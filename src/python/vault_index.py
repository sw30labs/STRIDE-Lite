"""
STRIDE-Lite Vault Index

Walks output/stride and output/scenarios and builds the graph the GUI
vault pane draws: models, threats, scenarios, kill chains, and the
CMDB apps they hang off. I wrote this so the browser never has to parse
the raw assessment JSON itself.

Notes:
- STRIDE files go through normalize_model (six categories, DREAD join by title).
- Scenario cards scrape CVE / SL- control / T-IDs from prose when the JSON is thin.
- project_note hydrates one node id (model:, scenario:, killchain:, app:, …).

## Author Information
- **Author**: Nic Cravino
- **Email**: spidernic@me.com
- **LinkedIn**: https://www.linkedin.com/in/nic-cravino
- **Date**: August 2026

## License: Apache License 2.0
"""

from __future__ import annotations

import json
import re
from datetime import datetime
from pathlib import Path
from typing import Any

from campaign_score import compile_score
from killchains import build_catalog, slugify
from utils import (
    BASE_DIR,
    application_aliases,
    canonical_app_id,
    get_application,
    load_applications,
    load_sample_cves_by_id,
    normalize_application,
)

# Constants for file paths and model configuration
OUTPUT = Path(BASE_DIR) / "output"


# Function to resolve the vault root (default: output/ next to the repo)
def _output_root(output_dir: Path | None = None) -> Path:
    return Path(output_dir) if output_dir is not None else OUTPUT
# Six STRIDE buckets + the JSON keys I have actually seen on disk
STRIDE_CATS = (
    "Spoofing",
    "Tampering",
    "Repudiation",
    "Information Disclosure",
    "Denial of Service",
    "Elevation of Privilege",
)
TITLE_KEYS = ("threat_name", "name", "threat", "title", "scenario")
DESC_KEYS = ("description", "desc", "details", "summary")
IMPACT_KEYS = ("impact", "business_impact", "effect")
MITIGATION_KEYS = ("mitigation", "mitigations", "control", "recommendation", "remediation")
# SL-NN / CVE / T-ID scrapers (prose is messier than the JSON)
CONTROL_RE = re.compile(r"\bSL-\d{2}\b")
CVE_RE = re.compile(r"\bCVE-\d{4}-\d+\b", re.I)
TECH_RE = re.compile(r"\bT\d{4}(?:\.\d{3})?\b", re.I)


# Function to pick the first non-empty string among alias keys
def _first(payload: dict, keys: tuple[str, ...]) -> str:
    for key in keys:
        value = payload.get(key)
        if isinstance(value, str) and value.strip():
            return value.strip()
    return ""


# Function to decode a JSON string (already-parsed dict/list pass through)
def _loads_maybe(value: Any) -> Any:
    if isinstance(value, (dict, list)):
        return value
    if isinstance(value, str) and value.strip():
        try:
            return json.loads(value)
        except json.JSONDecodeError:
            return value
    return value


# Function to stamp file mtime as ISO seconds (vault "modified" prop)
def _mtime_iso(path: Path) -> str:
    return datetime.fromtimestamp(path.stat().st_mtime).isoformat(timespec="seconds")


# Function to show a path relative to BASE_DIR (absolute if it left the tree)
def _rel(path: Path) -> str:
    try:
        return str(path.resolve().relative_to(Path(BASE_DIR).resolve()))
    except ValueError:
        return str(path)


# Function to pull the CMDB id out of system_metadata
def _cmdb_id_from_meta(meta: dict) -> str:
    app = normalize_application(meta)
    return app.get("id") or ""


# Function to average the five DREAD cells (any missing cell → unscored)
def _dread_avg(row: dict) -> float | None:
    keys = ("Damage Potential", "Reproducibility", "Exploitability", "Affected Users", "Discoverability")
    scores = []
    for key in keys:
        try:
            scores.append(float(row.get(key)))
        except (TypeError, ValueError):
            return None
    return round(sum(scores) / len(scores), 2) if scores else None


# Function to flatten a STRIDE JSON into threats + DREAD rows the vault can graph
def normalize_model(raw: dict, path: Path) -> dict[str, Any]:
    meta = raw.get("system_metadata") if isinstance(raw.get("system_metadata"), dict) else {}
    # TODO(nic): no-underscore stems ignore a good meta id (ternary binds tighter than or)
    cmdb_id = _cmdb_id_from_meta(meta) or path.stem.split("_")[2] if "_" in path.stem else path.stem
    dread_rows = raw.get("dread_assessment") or []
    if not isinstance(dread_rows, list):
        dread_rows = []
    threats = []
    warnings = []
    for category in STRIDE_CATS:
        items = raw.get(category) or []
        if not isinstance(items, list) or not items:
            warnings.append(f"empty:{category}")
            continue
        for item in items:
            if not isinstance(item, dict):
                continue
            title = _first(item, TITLE_KEYS)
            if not title:
                warnings.append(f"untitled:{category}")
                continue
            # Exact title first, then a 40-char prefix (the LLM often rewrites the Scenario line)
            match = next(
                (
                    row
                    for row in dread_rows
                    if isinstance(row, dict)
                    and str(row.get("Threat Type", "")).lower() == category.lower()
                    and str(row.get("Scenario", "")).strip().lower() in {title.lower(), _first(item, ("threat",)).lower()}
                ),
                None,
            )
            if match is None:
                match = next(
                    (
                        row
                        for row in dread_rows
                        if isinstance(row, dict)
                        and str(row.get("Threat Type", "")).lower() == category.lower()
                        and title.lower()[:40] in str(row.get("Scenario", "")).lower()
                    ),
                    None,
                )
            avg = _dread_avg(match) if match else None
            threats.append(
                {
                    "category": category,
                    "title": title,
                    "description": _first(item, DESC_KEYS),
                    "impact": _first(item, IMPACT_KEYS),
                    "mitigation": _first(item, MITIGATION_KEYS),
                    "dread": match,
                    "avg": avg,
                }
            )
    app = normalize_application(meta)
    cmdb_id = canonical_app_id(app.get("id") or cmdb_id)
    avgs = [item["avg"] for item in threats if item.get("avg") is not None]
    return {
        "cmdb_id": cmdb_id,
        "name": app.get("name") or meta.get("name") or cmdb_id,
        "meta": {**meta, **{k: v for k, v in app.items() if v not in (None, "", [])}},
        "threats": threats,
        "dread": dread_rows,
        "warnings": warnings,
        "threat_count": len(threats),
        "max_avg": max(avgs) if avgs else None,
    }


# Function to build a card-sized digest of a scenario JSON (full prose stays on disk)
def summarize_scenario(raw: dict, path: Path) -> dict[str, Any]:
    stride = _loads_maybe(raw.get("STRIDE_Threat_Model_Report"))
    dread = _loads_maybe(raw.get("DREAD_Assessment_Report"))
    threat_report = raw.get("Threat_Report") or ""
    cves = sorted({item.upper() for item in CVE_RE.findall(" ".join([
        str(raw.get("CVE_Report") or ""),
        str(threat_report),
    ]))})
    controls = sorted(set(CONTROL_RE.findall(str(threat_report))))
    techniques = raw.get("selected_techniques")
    # Fallback if selected_techniques is missing — scrape T-IDs out of the prose
    if not isinstance(techniques, list):
        techniques = sorted({item.upper() for item in TECH_RE.findall(str(threat_report))})
    return {
        "template": raw.get("Attack_Template") or "",
        "cmdb_id": canonical_app_id(raw.get("app_id") or raw.get("cmdb_id") or ""),
        "name": raw.get("app_name") or raw.get("name") or "",
        "provider": raw.get("Provider") or "",
        "source_model_path": raw.get("source_model_path") or "",
        "complete": bool(raw.get("Complete")),
        "cves": cves,
        "controls": controls,
        "technique_ids": [item for item in techniques if isinstance(item, str)],
        "word_count": len(str(threat_report).split()),
        "has_stride": isinstance(stride, dict),
        "has_dread": isinstance(dread, list),
        "outline": _outline(str(threat_report)),
    }


# Function to collect the first 40 markdown headings (vault outline pane)
def _outline(text: str) -> list[str]:
    headings = []
    for line in text.splitlines():
        match = re.match(r"#{1,3}\s+(.+)", line.strip())
        if match:
            headings.append(match.group(1).strip())
    return headings[:40]


# Function to load control_taxonomy.csv grouped by SL-id
def load_controls() -> dict[str, list[dict[str, str]]]:
    import csv

    path = Path(BASE_DIR) / "data" / "control_taxonomy.csv"
    grouped: dict[str, list[dict[str, str]]] = {}
    # utf-8-sig: Excel often saves the taxonomy with a BOM
    with path.open(encoding="utf-8-sig", newline="") as handle:
        for row in csv.DictReader(handle):
            control_id = (row.get("ID") or "").strip()
            if not control_id:
                continue
            grouped.setdefault(control_id, []).append(
                {
                    "id": control_id,
                    "topic": row.get("Topic") or "",
                    "title": row.get("Title") or "",
                    "description": row.get("Description") or "",
                }
            )
    return grouped


# Function to load the demo CVE catalog (stand-in for a live feed)
def load_demo_cves() -> dict[str, dict[str, Any]]:
    return load_sample_cves_by_id()


# Function to load applications.json through the shared helper
def load_cmdb() -> list[dict[str, Any]]:
    return load_applications()


# Function to walk output/stride and output/scenarios into a vis-network graph
def build_vault(output_dir: Path | None = None) -> dict[str, Any]:
    catalog = build_catalog()
    nodes: list[dict[str, Any]] = []
    edges: list[dict[str, Any]] = []
    models: list[dict[str, Any]] = []
    scenarios: list[dict[str, Any]] = []
    root = _output_root(output_dir)

    stride_dir = root / "stride"
    if stride_dir.exists():
        for path in sorted(stride_dir.glob("*.json"), key=lambda item: item.stat().st_mtime):
            # Skip partial writes from a crashed model.py
            try:
                raw = json.loads(path.read_text(encoding="utf-8"))
            except (OSError, json.JSONDecodeError):
                continue
            if not isinstance(raw, dict):
                continue
            salida = normalize_model(raw, path)
            node_id = f"model:{path.name}"
            models.append({**salida, "id": node_id, "path": _rel(path), "modified": _mtime_iso(path)})
            nodes.append(
                {
                    "id": node_id,
                    "type": "model",
                    "label": salida["name"],
                    "path": _rel(path),
                    "tags": ["model", salida["cmdb_id"]],
                    "props": {
                        "cmdb_id": salida["cmdb_id"],
                        "threats": salida["threat_count"],
                        "max_dread": salida["max_avg"] if salida["max_avg"] is not None else "—",
                        "modified": _mtime_iso(path),
                    },
                    "group": "model",
                }
            )
            if salida["cmdb_id"]:
                edges.append(
                    {
                        "id": f"{node_id}->app:{salida['cmdb_id']}",
                        "from": node_id,
                        "to": f"app:{salida['cmdb_id']}",
                        "rel": "about",
                    }
                )
            for index, threat in enumerate(salida["threats"]):
                threat_id = f"threat:{path.name}:{index}"
                nodes.append(
                    {
                        "id": threat_id,
                        "type": "threat",
                        "label": threat["title"][:72],
                        "tags": ["threat", threat["category"], salida["cmdb_id"]],
                        "props": {
                            "category": threat["category"],
                            "dread": threat["avg"] if threat["avg"] is not None else "unscored",
                            "model": path.name,
                        },
                        "group": "threat",
                        # Individual threats stay off the overview; open the model note
                        "hiddenInVault": True,
                    }
                )
                edges.append(
                    {
                        "id": f"{node_id}->{threat_id}",
                        "from": node_id,
                        "to": threat_id,
                        "rel": "has-threat",
                    }
                )

    scenario_dir = root / "scenarios"
    if scenario_dir.exists():
        for path in sorted(scenario_dir.glob("*.json"), key=lambda item: item.stat().st_mtime):
            try:
                raw = json.loads(path.read_text(encoding="utf-8"))
            except (OSError, json.JSONDecodeError):
                continue
            if not isinstance(raw, dict):
                continue
            summary = summarize_scenario(raw, path)
            node_id = f"scenario:{path.name}"
            scenarios.append({**summary, "id": node_id, "path": _rel(path), "modified": _mtime_iso(path)})
            nodes.append(
                {
                    "id": node_id,
                    "type": "scenario",
                    "label": f"{summary['template'] or 'Scenario'} · {summary['cmdb_id'] or summary['name']}",
                    "path": _rel(path),
                    "tags": ["scenario", summary["cmdb_id"], summary["template"]],
                    "props": {
                        "cmdb_id": summary["cmdb_id"],
                        "template": summary["template"],
                        "provider": summary["provider"],
                        "words": summary["word_count"],
                        "modified": _mtime_iso(path),
                    },
                    "group": "scenario",
                }
            )
            if summary["cmdb_id"]:
                edges.append(
                    {
                        "id": f"{node_id}->app:{summary['cmdb_id']}",
                        "from": node_id,
                        "to": f"app:{summary['cmdb_id']}",
                        "rel": "about",
                    }
                )
            if summary["template"]:
                # Link scenario → killchain via the same slugify the catalog uses
                edges.append(
                    {
                        "id": f"{node_id}->kc:{slugify(summary['template'])}",
                        "from": node_id,
                        "to": f"killchain:{slugify(summary['template'])}",
                        "rel": "uses-template",
                    }
                )
            # derived-from: explicit source_model_path, else newest prior model for that app
            source = summary["source_model_path"]
            if source:
                source_name = Path(source).name
                if any(item["id"] == f"model:{source_name}" for item in nodes):
                    edges.append(
                        {
                            "id": f"{node_id}->model:{source_name}",
                            "from": node_id,
                            "to": f"model:{source_name}",
                            "rel": "derived-from",
                        }
                    )
            elif summary["cmdb_id"]:
                candidates = [item for item in models if item["cmdb_id"] == summary["cmdb_id"] and item["modified"] <= _mtime_iso(path)]
                if candidates:
                    chosen = max(candidates, key=lambda item: item["modified"])
                    edges.append(
                        {
                            "id": f"{node_id}->{chosen['id']}",
                            "from": node_id,
                            "to": chosen["id"],
                            "rel": "derived-from",
                        }
                    )

    # Only materialize CMDB apps the graph actually referenced
    referenced_apps = {edge["to"][4:] for edge in edges if edge["to"].startswith("app:")}
    for row in load_cmdb():
        if not isinstance(row, dict):
            continue
        app_id = str(row.get("id") or "")
        aliases = application_aliases(row)
        if not app_id or not (aliases & referenced_apps or app_id in referenced_apps):
            continue
        nodes.append(
            {
                "id": f"app:{app_id}",
                "type": "app",
                "label": row.get("name") or app_id,
                "tags": ["app", app_id],
                "props": {
                    "cmdb_id": app_id,
                    "confidentiality": row.get("confidentiality") or "",
                    "availability": row.get("availability") or "",
                    "internet_facing": row.get("internet_facing"),
                    "sourcing": row.get("sourcing") or "",
                    "customer_data": row.get("customer_data"),
                    "business_area": row.get("business_area") or "",
                },
                "group": "app",
            }
        )

    # Kill-chain templates from the catalog (present even with an empty output/)
    for template in catalog["templates"]:
        nodes.append(
            {
                "id": template["id"],
                "type": "killchain",
                "label": template["name"],
                "tags": ["killchain", *template["families"]],
                "props": {
                    "steps": template["step_count"],
                    "families": ", ".join(template["families"]),
                    "order": template["order_quality"],
                },
                "group": "killchain",
            }
        )

    return {
        "nodes": nodes,
        "edges": edges,
        "generated_at": datetime.now().isoformat(timespec="seconds"),
        "counts": {
            "models": len(models),
            "scenarios": len(scenarios),
            "killchains": len(catalog["templates"]),
            "nodes": len(nodes),
            "edges": len(edges),
        },
        "disclaimer": catalog["disclaimer"],
    }


# Fail early — reject traversal in note ids before we touch the filesystem
def _safe_name(note_id: str) -> str:
    name = note_id.split(":", 1)[1]
    if not name or "/" in name or "\\" in name or ".." in name:
        raise FileNotFoundError(note_id)
    return name


# Function to hydrate one vault node (model / scenario / killchain / app / tech / control / cve / threat)
def project_note(note_id: str, output_dir: Path | None = None) -> dict[str, Any]:
    root = _output_root(output_dir)
    # model:<filename> — re-normalize from disk
    if note_id.startswith("model:"):
        path = root / "stride" / _safe_name(note_id)
        raw = json.loads(path.read_text(encoding="utf-8"))
        salida = normalize_model(raw, path)
        return {"id": note_id, "type": "model", "path": _rel(path), **salida}
    # scenario:<filename> — card fields plus the three reports the digest omitted
    if note_id.startswith("scenario:"):
        path = root / "scenarios" / _safe_name(note_id)
        raw = json.loads(path.read_text(encoding="utf-8"))
        summary = summarize_scenario(raw, path)
        return {
            "id": note_id,
            "type": "scenario",
            "path": _rel(path),
            **summary,
            "stride": _loads_maybe(raw.get("STRIDE_Threat_Model_Report")),
            "dread": _loads_maybe(raw.get("DREAD_Assessment_Report")),
            "Threat_Report": raw.get("Threat_Report") or "",
            "CTI_Report": raw.get("CTI_Report") or "",
            "CVE_Report": raw.get("CVE_Report") or "",
            "meta": {
                "app_id": raw.get("app_id"),
                "app_name": raw.get("app_name"),
                "Attack_Template": raw.get("Attack_Template"),
                "Provider": raw.get("Provider"),
                "Threat_Report_Date": raw.get("Threat_Report_Date"),
            },
        }
    # killchain:<slug> — catalog row plus compile_score
    if note_id.startswith("killchain:"):
        catalog = build_catalog()
        template = next((item for item in catalog["templates"] if item["id"] == note_id), None)
        if not template:
            raise FileNotFoundError(note_id)
        return {
            "id": note_id,
            "type": "killchain",
            **template,
            "score": compile_score(template),
            "disclaimer": catalog["disclaimer"],
        }
    if note_id.startswith("app:"):
        cmdb_id = note_id.split(":", 1)[1]
        row = get_application(cmdb_id)
        if not row:
            raise FileNotFoundError(note_id)
        return {"id": note_id, "type": "app", "meta": row, "name": row.get("name") or row.get("id") or cmdb_id}
    if note_id.startswith("tech:"):
        catalog = build_catalog()
        tech_id = note_id.split(":", 1)[1].upper()
        technique = next((item for item in catalog["techniques"] if item["id"] == tech_id), None)
        if not technique:
            raise FileNotFoundError(note_id)
        return {"id": note_id, "type": "technique", **technique}
    if note_id.startswith("control:"):
        control_id = note_id.split(":", 1)[1].upper()
        rows = load_controls().get(control_id)
        if not rows:
            raise FileNotFoundError(note_id)
        return {"id": note_id, "type": "control", "control_id": control_id, "rows": rows}
    if note_id.startswith("cve:"):
        cve_id = note_id.split(":", 1)[1].upper()
        known = load_demo_cves().get(cve_id)
        return {
            "id": note_id,
            "type": "cve",
            "cve_id": cve_id,
            "known": bool(known),
            "record": known,
            "note": None if known else "Cited in prose only; not in the demo CVE catalog.",
        }
    # threat:<filename>:<index> — index into the flattened STRIDE list
    if note_id.startswith("threat:"):
        _, filename, index_s = note_id.split(":", 2)
        path = root / "stride" / filename
        if "/" in filename or ".." in filename:
            raise FileNotFoundError(note_id)
        raw = json.loads(path.read_text(encoding="utf-8"))
        salida = normalize_model(raw, path)
        try:
            threat = salida["threats"][int(index_s)]
        except (ValueError, IndexError) as exc:
            raise FileNotFoundError(note_id) from exc
        return {"id": note_id, "type": "threat", "model": f"model:{filename}", **threat}
    raise FileNotFoundError(note_id)
