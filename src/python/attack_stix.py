"""
Local MITRE ATT&CK STIX 2.x Enrichment

Optional lookup against a STIX 2.x bundle on disk so technique IDs can
pick up official names, tactics, and platforms. I wrote this to stay
air-gapped: nothing is downloaded, and if the dump is missing the
callers just get empty enrichment and keep going.

Notes:
- Search order: explicit path, ATTACK_STIX / ATTACK_STIX_PATH, then
  data/enterprise-attack.json and a couple of filename aliases.
- Subtechniques (Txxxx.yyy) inherit the parent Txxxx when the child
  is not in the dump.
- Descriptions are clipped so the GUI does not drown in STIX prose.

## Author Information
- **Author**: Nic Cravino
- **Email**: spidernic@me.com
- **LinkedIn**: https://www.linkedin.com/in/nic-cravino
- **Date**: August 2026

## License: Apache License 2.0
"""

from __future__ import annotations

import json
import os
from pathlib import Path
from typing import Any

from utils import BASE_DIR

# Process-local STIX index (path-keyed so force=True actually reloads)
_CACHE: dict[str, dict[str, Any]] | None = None
_CACHE_PATH: str | None = None


# Function to list local STIX bundle candidates (never downloads)
def stix_candidate_paths(explicit: str | None = None) -> list[Path]:
    names = (
        explicit,
        os.getenv("ATTACK_STIX"),
        os.getenv("ATTACK_STIX_PATH"),
        str(Path(BASE_DIR) / "data" / "enterprise-attack.json"),
        str(Path(BASE_DIR) / "data" / "attack-stix.json"),
        str(Path(BASE_DIR) / "data" / "attack_stix.json"),
    )
    salida: list[Path] = []
    for raw in names:
        if not raw:
            continue
        path = Path(raw)
        # Relative paths resolve against the repo root, not cwd
        if not path.is_absolute():
            path = Path(BASE_DIR) / path
        if path.is_file() and path not in salida:
            salida.append(path)
    return salida


# Function to resolve the first existing STIX path (fallback if the bundle is missing)
def resolve_stix_path(explicit: str | None = None) -> Path | None:
    found = stix_candidate_paths(explicit)
    return found[0] if found else None


# Function to pull a MITRE T-id off external_references (enterprise / mobile / ICS)
def _external_id(obj: dict[str, Any]) -> str:
    for ref in obj.get("external_references") or []:
        if not isinstance(ref, dict):
            continue
        if ref.get("source_name") in {"mitre-attack", "mitre-mobile-attack", "mitre-ics-attack"}:
            ext = str(ref.get("external_id") or "").strip().upper()
            if ext.startswith("T"):
                return ext
    return ""


# Function to turn kill-chain phases into tactic names (ATT&CK uses hyphens; I space them)
def _tactics(obj: dict[str, Any]) -> list[str]:
    out: list[str] = []
    for phase in obj.get("kill_chain_phases") or []:
        if not isinstance(phase, dict):
            continue
        name = str(phase.get("phase_name") or "").replace("-", " ").strip().lower()
        if name and name not in out:
            out.append(name)
    return out


# Function to index attack-patterns by T-id (skip revoked/deprecated)
def load_stix_index(explicit: str | None = None, *, force: bool = False) -> dict[str, dict[str, Any]]:
    global _CACHE, _CACHE_PATH
    path = resolve_stix_path(explicit)
    key = str(path.resolve()) if path else ""
    if not force and _CACHE is not None and _CACHE_PATH == key:
        return _CACHE
    index: dict[str, dict[str, Any]] = {}
    if path:
        data = json.loads(path.read_text(encoding="utf-8"))
        objects = data.get("objects") if isinstance(data, dict) else data
        for obj in objects if isinstance(objects, list) else []:
            if not isinstance(obj, dict) or obj.get("type") != "attack-pattern":
                continue
            if obj.get("revoked") or obj.get("x_mitre_deprecated"):
                continue
            tech_id = _external_id(obj)
            if not tech_id:
                continue
            description = str(obj.get("description") or "").strip()
            if len(description) > 400:
                description = description[:397].rstrip() + "…"
            index[tech_id] = {
                "id": tech_id,
                "name": obj.get("name") or "",
                "tactics": _tactics(obj),
                "platforms": list(obj.get("x_mitre_platforms") or []),
                "description": description,
                "stix_id": obj.get("id") or "",
            }
    _CACHE = index
    _CACHE_PATH = key
    return index


# Function to stamp STIX fields onto a technique dict
def enrich_technique(tech: dict[str, Any], index: dict[str, dict[str, Any]] | None = None) -> dict[str, Any]:
    index = index if index is not None else load_stix_index()
    if not index:
        return tech
    tech_id = str(tech.get("suggested_id") or tech.get("id") or "").upper()
    rec = index.get(tech_id)
    # Subtechniques inherit parent when Txxxx.yyy is missing from the local dump
    if not rec and "." in tech_id:
        rec = index.get(tech_id.split(".", 1)[0])
    if not rec:
        return tech
    tech["stix"] = rec
    tech["stix_name"] = rec.get("name") or ""
    tech["stix_tactics"] = list(rec.get("tactics") or [])
    tech["stix_platforms"] = list(rec.get("platforms") or [])
    return tech


# Function to report whether the local bundle is present
def stix_status(explicit: str | None = None) -> dict[str, Any]:
    path = resolve_stix_path(explicit)
    index = load_stix_index(explicit)
    return {
        "present": bool(path),
        "path": str(path.relative_to(BASE_DIR)) if path else "",
        "count": len(index),
    }
