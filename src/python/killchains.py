"""
ATT&CK Kill-Chain Notes

Parses predefined_attack_templates.json into catalog records Vault can browse:
templates, techniques, and T-ID ambiguities.

I left the historical T-IDs on the records. Some of the JSON still has T1859
where T1059 belongs; TYPO_MAP flags those instead of rewriting the file.

Notes:
- A step line is optional tactic, a label, then a parenthetical blob of T-IDs / CVEs.
- Lines starting with Note: stay notes (ATLAS AML.T* ids live there).
- STIX names and tactics attach only if a local enterprise-attack.json is on disk.

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
from pathlib import Path
from typing import Any

from attack_stix import enrich_technique, load_stix_index, stix_status
from utils import BASE_DIR

# Constants for file paths and ATT&CK tactic names
TEMPLATES_PATH = Path(BASE_DIR) / "data" / "predefined_attack_templates.json"

ENTERPRISE_TACTICS = {
    "reconnaissance",
    "resource development",
    "initial access",
    "execution",
    "persistence",
    "privilege escalation",
    "defense evasion",
    "credential access",
    "discovery",
    "lateral movement",
    "collection",
    "command and control",
    "exfiltration",
    "impact",
}

# Historically mistyped T-IDs from predefined_attack_templates.json
# Vault flags them (id_status=typo + suggested_id) instead of silently rewriting the JSON
TYPO_MAP = {
    "T1859": "T1059",
    "T1859.006": "T1059.006",
    "T1868": "T1068",
    "T1827": "T1027",
    "T1821.002": "T1021.002",
    "T1847": "T1047",
    "T1841": "T1041",
    "T1848": "T1048",
    "T1816": "T1016",
    "T1283": "T1203",
    "T1218.811": "T1218.011",
    "T1078.004": "T1070.004",
    "T1499,001": "T1499.001",
    "T1110.084": "T1110.004",
    "T1874.881": "T1074.001",
    "T1883.001": "T1003.001",
    "T1083.881": "T1003.001",
}

# Step line: optional Tactic: label (blob). ID_RE also accepts a comma sub-id (T1499,001).
STEP_RE = re.compile(
    r"^(?:(?P<tactic>[A-Za-z][A-Za-z /&-]+):\s+)?(?P<label>.+?)\s+\((?P<blob>[^)]+)\)\s*$"
)
ID_RE = re.compile(r"T\d{4}(?:[.,]\d{3})?", re.I)
CVE_RE = re.compile(r"CVE-\d{4}-\d+", re.I)
ATLAS_RE = re.compile(r"AML\.T\d+", re.I)
# Due-diligence / gate notes (not kill-chain steps)
DUE_DILIGENCE_RE = re.compile(r"(due-diligence|gate G\d+|veto |EV-\d+|Domain [A-F]\b)", re.I)


# Function to turn a template title into a killchain: slug (names drift more than the steps)
def slugify(name: str) -> str:
    slug = re.sub(r"[^a-z0-9]+", "-", name.lower())
    return slug.strip("-") or "template"


# Function to tag a template from its title (no extra JSON field to maintain)
def family_tags(name: str) -> list[str]:
    lower = name.lower()
    tags: list[str] = []
    if any(token in lower for token in ("[ai saas", "[buy-side", "shadow ai", "shadow agent", "agentic", "prompt injection", "rag ", "vector store", "ai model", "mcp")):
        tags.append("ai-saas")
    if any(token in lower for token in ("ransomware", "lockbit", "ransomhub", "akira", "data extortion")):
        tags.append("ransomware")
    if name.startswith("[API]") or "api exposure" in lower or "api abuse" in lower:
        tags.append("api")
    if re.search(r"\bapt\b", lower) or "typhoon" in lower or "scattered spider" in lower or re.search(r"\bunc\d+", lower):
        tags.append("apt")
    if not tags:
        tags.append("other")
    return tags


# Function to normalize a T-ID (comma-as-dot shows up in the historical JSON)
def normalize_tech_id(raw: str) -> str:
    value = raw.strip().upper().replace(",", ".")
    return value


# Function to pull T-IDs and CVEs out of a parenthetical blob
def parse_ids(blob: str) -> list[dict[str, str]]:
    salida: list[dict[str, str]] = []
    for match in ID_RE.findall(blob):
        tech_id = normalize_tech_id(match)
        suggested = TYPO_MAP.get(tech_id)
        salida.append(
            {
                "id": tech_id,
                "suggested_id": suggested or tech_id,
                "id_status": "typo" if suggested else "ok",
            }
        )
    for match in CVE_RE.findall(blob):
        salida.append({"id": match.upper(), "suggested_id": match.upper(), "id_status": "ok", "kind": "cve"})
    # Fallback if the blob is slash-separated and no T-ID matched yet
    if "/" in blob and not salida:
        for part in blob.split("/"):
            salida.extend(parse_ids(part))
    return salida


# Function to parse one template line into a step or a note
def parse_step(raw: str, ordinal: int) -> dict[str, Any] | None:
    text = raw.strip()
    if not text:
        return None
    # ATLAS / free-text notes start with Note: (keep them off the step list)
    if text.lower().startswith("note:"):
        return {
            "ord": ordinal,
            "raw": text,
            "kind": "note",
            "ids": ATLAS_RE.findall(text),
            "atlas_ids": ATLAS_RE.findall(text),
            "flags": ["note"],
        }
    match = STEP_RE.match(text)
    tactic = ""
    label = text
    blob = ""
    if match:
        tactic = (match.group("tactic") or "").strip()
        label = (match.group("label") or "").strip()
        blob = (match.group("blob") or "").strip()
    ids = parse_ids(blob) if blob else parse_ids(text)
    # Drop tactic if it is not an enterprise name (junk prefixes stay off the catalog)
    if tactic and tactic.lower() not in ENTERPRISE_TACTICS:
        tactic = ""
    leaf = label.split(":")[-1].strip() if ":" in label else label
    return {
        "ord": ordinal,
        "raw": text,
        "kind": "step",
        "label": label,
        "name": leaf,
        "tactic": tactic,
        "ids": [item["id"] for item in ids],
        "id_meta": ids,
        "flags": [item["id_status"] for item in ids if item.get("id_status") not in (None, "ok")],
    }


# Function to load predefined_attack_templates.json (dict of name → step lines)
def load_templates() -> dict[str, list[str]]:
    data = json.loads(TEMPLATES_PATH.read_text(encoding="utf-8"))
    return data if isinstance(data, dict) else {}


# Function to build the vault catalog (templates, techniques, typo flags)
def build_catalog() -> dict[str, Any]:
    templates_raw = load_templates()
    techniques: dict[str, dict[str, Any]] = {}
    templates: list[dict[str, Any]] = []
    ambiguities: list[dict[str, str]] = []

    for name, steps in templates_raw.items():
        parsed_steps = []
        notes = []
        atlas_ids = []
        tactic_hits = 0
        for index, raw in enumerate(steps if isinstance(steps, list) else [], start=1):
            if not isinstance(raw, str):
                continue
            if DUE_DILIGENCE_RE.search(raw) and raw.lower().startswith("note:"):
                notes.append(re.sub(r"(?i)due-diligence.*$", "", raw).strip())
            step = parse_step(raw, index)
            if not step:
                continue
            if step["kind"] == "note":
                notes.append(step["raw"])
                atlas_ids.extend(step.get("atlas_ids") or [])
                continue
            if step.get("tactic"):
                tactic_hits += 1
            parsed_steps.append(step)
            for meta in step.get("id_meta") or []:
                tech_id = meta["id"]
                node = techniques.setdefault(
                    tech_id,
                    {
                        "id": tech_id,
                        "suggested_id": meta.get("suggested_id") or tech_id,
                        "id_status": meta.get("id_status") or "ok",
                        "kind": meta.get("kind") or ("subtechnique" if "." in tech_id else "technique"),
                        "name": step["name"],
                        "raw_labels": [],
                        "used_by": [],
                        "tactics_claimed": [],
                        "parent": tech_id.split(".")[0] if "." in tech_id else None,
                    },
                )
                if step["raw"] not in node["raw_labels"]:
                    node["raw_labels"].append(step["raw"])
                if name not in node["used_by"]:
                    node["used_by"].append(name)
                if step.get("tactic") and step["tactic"] not in node["tactics_claimed"]:
                    node["tactics_claimed"].append(step["tactic"])
                if meta.get("id_status") == "typo":
                    ambiguities.append({"template": name, "raw": tech_id, "suggested": meta["suggested_id"], "label": step["name"]})

        templates.append(
            {
                "id": f"killchain:{slugify(name)}",
                "name": name,
                "slug": slugify(name),
                "families": family_tags(name),
                # Tactic prefix on half+ of the steps → listed order is real
                "order_quality": "tactic-prefixed" if tactic_hits >= max(1, len(parsed_steps) // 2) else "list-order-assumed",
                "steps": parsed_steps,
                "notes": notes,
                "atlas_ids": sorted(set(atlas_ids)),
                "step_count": len(parsed_steps),
            }
        )

    # Fallback if the local STIX bundle is missing
    stix = load_stix_index()
    enriched = [enrich_technique(item, stix) for item in techniques.values()]
    status = stix_status()
    return {
        "templates": templates,
        "techniques": enriched,
        "ambiguities": ambiguities,
        "stix": status,
        "disclaimer": (
            "This product uses the MITRE ATT&CK® knowledge base but is not affiliated "
            "with or endorsed by The MITRE Corporation. Technique IDs are public identifiers used for structure."
        ),
    }


# Technique IDs on one template (optional typo-normalize for Jaccard)
def _template_ids(template: dict[str, Any], normalize: bool) -> set[str]:
    ids: set[str] = set()
    for step in template.get("steps") or []:
        metas = step.get("id_meta") or [{"id": item, "suggested_id": item} for item in step.get("ids") or []]
        for meta in metas:
            raw = meta.get("suggested_id") if normalize and meta.get("suggested_id") else meta.get("id")
            if raw:
                ids.add(raw)
    return ids


# Function to compare two templates by technique-ID overlap (name, slug, or killchain: id)
def compare_templates(name_or_id_a: str, name_or_id_b: str, normalize: bool = False) -> dict[str, Any]:
    catalog = build_catalog()
    # Resolve by id, name, or slug (killchain: prefix is optional)
    def find(key: str) -> dict[str, Any] | None:
        key_l = key.lower()
        for item in catalog["templates"]:
            if item["id"].lower() == key_l or item["name"].lower() == key_l or item["slug"] == key_l:
                return item
            if key_l.startswith("killchain:") and item["id"].lower() == key_l:
                return item
        return None

    left = find(name_or_id_a)
    right = find(name_or_id_b)
    if not left or not right:
        raise FileNotFoundError(f"Unknown template: {name_or_id_a if not left else name_or_id_b}")
    a_ids = _template_ids(left, normalize)
    b_ids = _template_ids(right, normalize)
    both = sorted(a_ids & b_ids)
    only_a = sorted(a_ids - b_ids)
    only_b = sorted(b_ids - a_ids)
    union = len(a_ids | b_ids)
    return {
        "a": {"id": left["id"], "name": left["name"], "count": len(a_ids)},
        "b": {"id": right["id"], "name": right["name"], "count": len(b_ids)},
        "normalize": normalize,
        "shared": both,
        "only_a": only_a,
        "only_b": only_b,
        "jaccard": round(len(both) / union, 3) if union else 0.0,
    }
