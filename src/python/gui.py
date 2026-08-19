#!/usr/bin/env python3
"""
STRIDE-Lite Local Web GUI

Stdlib ThreadingHTTPServer wrapping model.py and scenario.py via subprocess.
Static assets live in src/gui/; jobs run in daemon threads and stream stdout
into an in-memory Job.log (last 500 lines on snapshot). I wrote this so I
can drive both pipelines from a browser without Flask or FastAPI.

Notes:
- Path traversal is gated by ensure_repo_file — anything that opens a
  user-supplied path must keep that check (/api/file, scenario JSON, CVE feed).
- Workspace paths are shown as ~/… so the status JSON does not leak a username.
- Jobs are subprocesses with cwd=BASE_DIR, same argv the CLI uses.

## Author Information
- **Author**: Nic Cravino
- **Email**: spidernic@me.com
- **LinkedIn**: https://www.linkedin.com/in/nic-cravino
- **Date**: August 2026

## License: Apache License 2.0
"""

from __future__ import annotations

import argparse
import json
import os
import subprocess
import sys
import threading
import time
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timezone
from http import HTTPStatus
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any
from urllib.parse import parse_qs, unquote, urlparse

from attack_stix import stix_status
from campaign_score import compare_scores, score_for
from killchains import build_catalog, compare_templates
from utils import (
    BASE_DIR,
    Provider,
    cve_feed_status,
    load_applications,
    parse_provider,
    resolve_mlx_api_key,
    resolve_mlx_base_url,
    resolve_mlx_model,
    resolve_provider_from_env,
)
from vault_index import build_vault, project_note

# Constants for file paths and POST size (1MB is plenty for a job request)
GUI_DIR = Path(BASE_DIR) / "src" / "gui"
OUTPUT_DIR = Path(BASE_DIR) / "output"
MAX_BODY_BYTES = 1_000_000


# In-memory subprocess job (snapshot is what the UI polls; log is tailed to 500)
@dataclass
class Job:
    id: str
    kind: str
    command: list[str]
    status: str = "running"
    returncode: int | None = None
    started_at: str = field(default_factory=lambda: now_iso())
    ended_at: str | None = None
    log: list[str] = field(default_factory=list)

    def snapshot(self) -> dict[str, Any]:
        # Last 500 lines so the poll payload stays small
        return {
            "id": self.id,
            "kind": self.kind,
            "command": self.command,
            "status": self.status,
            "returncode": self.returncode,
            "started_at": self.started_at,
            "ended_at": self.ended_at,
            "log": self.log[-500:],
        }


# Process-local job table (a restart wipes running state on purpose)
# TODO(nic): finished jobs never evict; a long GUI session keeps every snapshot
jobs: dict[str, Job] = {}
jobs_lock = threading.Lock()


# Function to stamp local ISO time to the second (started_at / ended_at)
def now_iso() -> str:
    return datetime.now(timezone.utc).astimezone().isoformat(timespec="seconds")


# Function to resolve a path under the repo root (cwd is the wrong tree)
def repo_path(*parts: str) -> Path:
    return Path(BASE_DIR, *parts).resolve()


# Function to show a path relative to BASE_DIR (absolute if it left the tree)
def rel_path(path: Path) -> str:
    try:
        return str(path.resolve().relative_to(Path(BASE_DIR).resolve()))
    except ValueError:
        return str(path)


def display_workspace(path: str | Path) -> str:
    """Mask $HOME as ~/… so /api/status does not leak a username."""
    text = str(path)
    home = os.path.expanduser("~")
    if home and (text == home or text.startswith(home + os.sep)):
        return "~" + text[len(home) :]
    return text


# Path-traversal gate — resolved path must stay inside BASE_DIR and be a real file
def ensure_repo_file(value: str) -> Path:
    path = Path(value)
    resolved = path.resolve() if path.is_absolute() else repo_path(value)
    base = Path(BASE_DIR).resolve()
    if base not in [resolved, *resolved.parents]:
        raise ValueError("Path must stay inside the project workspace")
    if not resolved.exists() or not resolved.is_file():
        raise ValueError(f"File not found: {value}")
    return resolved


# Fallback if the JSON is missing or unreadable
def load_json_file(path: Path, fallback: Any) -> Any:
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except Exception:
        return fallback


# Function to list *.json under output/<subdir> (newest mtime first, for the picker)
def list_json_outputs(subdir: str) -> list[dict[str, Any]]:
    directory = OUTPUT_DIR / subdir
    if not directory.exists():
        return []
    files = sorted(directory.glob("*.json"), key=lambda item: item.stat().st_mtime, reverse=True)
    salida: list[dict[str, Any]] = []
    for path in files:
        stat = path.stat()
        salida.append(
            {
                "name": path.name,
                "path": rel_path(path),
                "size": stat.st_size,
                "modified": datetime.fromtimestamp(stat.st_mtime).isoformat(timespec="seconds"),
            }
        )
    return salida


# Function to reshape applications.json rows for the CMDB picker
def load_cmdb_entries() -> list[dict[str, Any]]:
    return [
        {
            "cmdb_id": row["id"],
            "name": row["name"],
            "description": row["description"],
            "architecture": row["architecture"],
            "business_area": row["business_area"],
            "platform": row["platform"],
            "confidentiality": row["confidentiality"],
            "integrity": row["integrity"],
            "availability": row["availability"],
            "internet_facing": row["internet_facing"],
            "sourcing": row["sourcing"],
            "customer_data": row["customer_data"],
        }
        for row in load_applications()
    ]


# Function to load predefined_attack_templates.json (name → technique list)
def load_attack_templates() -> list[dict[str, Any]]:
    data = load_json_file(repo_path("data", "predefined_attack_templates.json"), {})
    if not isinstance(data, dict):
        return []
    return [
        {"name": name, "techniques": techniques if isinstance(techniques, list) else []}
        for name, techniques in sorted(data.items())
    ]


# Function to report provider readiness from env (I do not ping the endpoint)
def provider_status() -> dict[str, Any]:
    configured = resolve_provider_from_env(Provider.OPENAI).value
    return {
        "default": configured,
        "providers": [
            {
                "id": Provider.OPENAI.value,
                "label": "OpenAI",
                "ready": bool(os.getenv("OPENAI_API_KEY")),
                "model": os.getenv("OPENAI_MODEL") or os.getenv("LLM_MODEL", "gpt-4o"),
                "detail": "Hosted model endpoint",
            },
            {
                "id": Provider.MLX.value,
                "label": "oMLX",
                "ready": bool(resolve_mlx_api_key()),
                "model": resolve_mlx_model(),
                "base_url": resolve_mlx_base_url(),
                "detail": "Local OpenAI-compatible endpoint",
            },
        ],
    }


# Function to assemble the /api/status blob the UI boots from
def status_payload() -> dict[str, Any]:
    with jobs_lock:
        job_list = [job.snapshot() for job in sorted(jobs.values(), key=lambda item: item.started_at, reverse=True)]
    return {
        "workspace": display_workspace(BASE_DIR),
        "provider": provider_status(),
        "cmdb": load_cmdb_entries(),
        "cve_feed": cve_feed_status(),
        "attack_stix": stix_status(),
        "attack_templates": load_attack_templates(),
        "outputs": {
            "stride": list_json_outputs("stride"),
            "scenarios": list_json_outputs("scenarios"),
            "feedback": list_json_outputs("feedback"),
        },
        "jobs": job_list,
    }


# Function to parse a JSON POST body (capped; a runaway paste should not fill RAM)
def read_body(handler: BaseHTTPRequestHandler) -> dict[str, Any]:
    length = int(handler.headers.get("content-length") or "0")
    if length > MAX_BODY_BYTES:
        raise ValueError("Request body is too large")
    raw = handler.rfile.read(length) if length else b"{}"
    if not raw:
        return {}
    data = json.loads(raw.decode("utf-8"))
    if not isinstance(data, dict):
        raise ValueError("Expected a JSON object")
    return data


# Function to register a Job and spawn a daemon thread (server shutdown is not blocked)
def start_job(kind: str, command: list[str]) -> Job:
    job = Job(id=uuid.uuid4().hex[:12], kind=kind, command=command)
    with jobs_lock:
        jobs[job.id] = job
    thread = threading.Thread(target=run_job, args=(job,), daemon=True)
    thread.start()
    return job


# Function to run the job command with cwd=BASE_DIR (stderr folded into stdout)
def run_job(job: Job) -> None:
    env = os.environ.copy()
    # Force unbuffered child stdout so the log updates line by line
    env["PYTHONUNBUFFERED"] = "1"
    try:
        process = subprocess.Popen(
            job.command,
            cwd=BASE_DIR,
            env=env,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            bufsize=1,
        )
        assert process.stdout is not None
        for line in process.stdout:
            with jobs_lock:
                job.log.append(line.rstrip())
        returncode = process.wait()
        with jobs_lock:
            job.returncode = returncode
            job.status = "succeeded" if returncode == 0 else "failed"
            job.ended_at = now_iso()
    except Exception as exc:
        with jobs_lock:
            job.status = "failed"
            job.returncode = -1
            job.ended_at = now_iso()
            job.log.append(f"{type(exc).__name__}: {exc}")


# Function to launch model.py for one application id (same argv the CLI uses)
def build_model_job(data: dict[str, Any]) -> Job:
    cmdb_id = str(data.get("cmdb_id") or data.get("app_id") or "").strip()
    if not cmdb_id:
        raise ValueError("Application ID is required")
    provider = parse_provider(str(data.get("provider") or Provider.OPENAI.value)).value
    command = [sys.executable, "src/python/model.py", cmdb_id, "--provider", provider]
    return start_job("threat-model", command)


# Function to launch scenario.py (JSON and optional CVE feed stay in-repo)
def build_scenario_job(data: dict[str, Any]) -> Job:
    json_file = str(data.get("json_file") or "").strip()
    attack_template = str(data.get("attack_template") or "").strip()
    if not json_file:
        raise ValueError("Threat model JSON file is required")
    if not attack_template:
        raise ValueError("Attack template is required")
    model_file = ensure_repo_file(json_file)
    provider = parse_provider(str(data.get("provider") or Provider.OPENAI.value)).value
    min_cvss = str(data.get("min_cvss") or "8.5")
    command = [
        sys.executable,
        "src/python/scenario.py",
        "--json_file",
        str(model_file),
        "--provider",
        provider,
        "--attack_template",
        attack_template,
        "--min_cvss",
        min_cvss,
    ]
    cve_feed = str(data.get("cve_feed") or "").strip()
    if cve_feed:
        # Optional CVE feed; same containment check as the threat-model JSON
        command.extend(["--cve_feed", str(ensure_repo_file(cve_feed))])
    return start_job("scenario", command)


# Request handler for static files plus the /api/* job and vault endpoints
class GuiHandler(BaseHTTPRequestHandler):
    server_version = "STRIDELite/2.0"

    # HEAD of a static file (Content-Length only; same path check as serve_static)
    def do_HEAD(self) -> None:
        parsed = urlparse(self.path)
        relative = "index.html" if parsed.path in ("", "/") else parsed.path.lstrip("/")
        path = (GUI_DIR / relative).resolve()
        if GUI_DIR.resolve() not in [path, *path.parents] or not path.exists() or not path.is_file():
            self.send_error(HTTPStatus.NOT_FOUND)
            return
        content_type = _content_type(path)
        self.send_response(HTTPStatus.OK)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(path.stat().st_size))
        self.end_headers()

    # JSON API first; anything else is a static file under src/gui/
    def do_GET(self) -> None:
        parsed = urlparse(self.path)
        try:
            if parsed.path == "/api/status":
                self.send_json(status_payload())
            elif parsed.path == "/api/jobs":
                with jobs_lock:
                    self.send_json([job.snapshot() for job in jobs.values()])
            elif parsed.path.startswith("/api/jobs/"):
                # Job snapshot by id (404 if the process-local table never saw it)
                job_id = parsed.path.rsplit("/", 1)[-1]
                with jobs_lock:
                    job = jobs.get(job_id)
                    if not job:
                        self.send_error_json(HTTPStatus.NOT_FOUND, "Job not found")
                        return
                    self.send_json(job.snapshot())
            elif parsed.path == "/api/file":
                # /api/file?path=… — ensure_repo_file is the path-traversal gate
                query = parse_qs(parsed.query)
                raw_path = unquote((query.get("path") or [""])[0])
                path = ensure_repo_file(raw_path)
                self.send_json({"path": rel_path(path), "content": load_json_file(path, None)})
            elif parsed.path == "/api/vault":
                self.send_json(build_vault())
            elif parsed.path == "/api/killchains":
                self.send_json(build_catalog())
            elif parsed.path == "/api/killchains/score":
                # Score one kill-chain by id= (404 if the template file is gone)
                query = parse_qs(parsed.query)
                ident = unquote((query.get("id") or [""])[0]).strip()
                if not ident:
                    raise ValueError("Score requires id=")
                try:
                    self.send_json(score_for(ident))
                except FileNotFoundError as exc:
                    self.send_error_json(HTTPStatus.NOT_FOUND, str(exc))
                    return
            elif parsed.path == "/api/killchains/compare":
                # Side-by-side templates (a=, b=); normalize=1 folds names before Jaccard
                query = parse_qs(parsed.query)
                left = unquote((query.get("a") or [""])[0]).strip()
                right = unquote((query.get("b") or [""])[0]).strip()
                normalize = (query.get("normalize") or ["0"])[0] in {"1", "true", "yes"}
                if not left or not right:
                    raise ValueError("Compare requires a= and b=")
                try:
                    payload = compare_templates(left, right, normalize=normalize)
                    payload["scores"] = compare_scores(left, right)
                    self.send_json(payload)
                except FileNotFoundError as exc:
                    self.send_error_json(HTTPStatus.NOT_FOUND, str(exc))
                    return
            elif parsed.path == "/api/killchains/score-compare":
                # Scores only (no template Jaccard) for a= and b=
                query = parse_qs(parsed.query)
                left = unquote((query.get("a") or [""])[0]).strip()
                right = unquote((query.get("b") or [""])[0]).strip()
                if not left or not right:
                    raise ValueError("Score compare requires a= and b=")
                try:
                    self.send_json(compare_scores(left, right))
                except FileNotFoundError as exc:
                    self.send_error_json(HTTPStatus.NOT_FOUND, str(exc))
                    return
            elif parsed.path == "/api/vault/note":
                # Vault note body by id= (markdown on disk; 404 if the file is missing)
                query = parse_qs(parsed.query)
                note_id = unquote((query.get("id") or [""])[0]).strip()
                if not note_id:
                    raise ValueError("Note id is required")
                try:
                    self.send_json(project_note(note_id))
                except FileNotFoundError:
                    self.send_error_json(HTTPStatus.NOT_FOUND, f"Note not found: {note_id}")
                    return
            else:
                self.serve_static(parsed.path)
        except Exception as exc:
            self.send_error_json(HTTPStatus.BAD_REQUEST, str(exc))

    # Start a threat-model or scenario job (202 + snapshot; the UI then polls)
    def do_POST(self) -> None:
        parsed = urlparse(self.path)
        try:
            data = read_body(self)
            if parsed.path == "/api/jobs/model":
                self.send_json(build_model_job(data).snapshot(), HTTPStatus.ACCEPTED)
            elif parsed.path == "/api/jobs/scenario":
                self.send_json(build_scenario_job(data).snapshot(), HTTPStatus.ACCEPTED)
            else:
                self.send_error_json(HTTPStatus.NOT_FOUND, "Unknown endpoint")
        except Exception as exc:
            self.send_error_json(HTTPStatus.BAD_REQUEST, str(exc))

    # Function to serve a file from src/gui/ (index.html for /; reject escape)
    def serve_static(self, request_path: str) -> None:
        relative = "index.html" if request_path in ("", "/") else request_path.lstrip("/")
        path = (GUI_DIR / relative).resolve()
        if GUI_DIR.resolve() not in [path, *path.parents] or not path.exists() or not path.is_file():
            self.send_error(HTTPStatus.NOT_FOUND)
            return
        content_type = _content_type(path)
        self.send_response(HTTPStatus.OK)
        self.send_header("Content-Type", content_type)
        self.end_headers()
        self.wfile.write(path.read_bytes())

    # Function to write a JSON response (indent=2 so /api/file is readable in a tab)
    def send_json(self, payload: Any, status: HTTPStatus = HTTPStatus.OK) -> None:
        salida = json.dumps(payload, indent=2).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(salida)))
        self.end_headers()
        self.wfile.write(salida)

    # Function to wrap an error string as {"error": …}
    def send_error_json(self, status: HTTPStatus, message: str) -> None:
        self.send_json({"error": message}, status)

    # Function to prefix access lines with [gui] (the default format is noisier)
    def log_message(self, fmt: str, *args: Any) -> None:
        sys.stderr.write(f"[gui] {self.address_string()} {fmt % args}\n")


# Function to map a few suffixes to Content-Type (everything else is HTML)
def _content_type(path: Path) -> str:
    if path.suffix == ".css":
        return "text/css; charset=utf-8"
    if path.suffix == ".js":
        return "text/javascript; charset=utf-8"
    if path.suffix == ".svg":
        return "image/svg+xml"
    return "text/html; charset=utf-8"


# Function to parse command-line arguments (better than doing it inline, scalable)
def main() -> None:
    parser = argparse.ArgumentParser(description="Serve the STRIDE-Lite v2.0 local GUI")
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=8765)
    args = parser.parse_args()

    server = ThreadingHTTPServer((args.host, args.port), GuiHandler)
    print(f"STRIDE-Lite v2.0: http://{args.host}:{args.port}")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        # KeyboardInterrupt is the normal stop; finally closes the socket
        print("\nStopping GUI server")
    finally:
        server.server_close()


if __name__ == "__main__":
    main()
