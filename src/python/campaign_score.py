"""
Campaign Score IR Compiler

Compile a kill-chain template into a Campaign Score IR.

The source lists are bags of ATT&CK techniques. This module does not pretend
every list index is a causal edge. It places glyphs on a phase × lane grid,
keeps one spine node per occupied phase, and parks the rest as toolbox chips.

Notes:
- Sequence and storyboard views are attached on the IR so score_export.py can stay a dumb renderer.
- Unmapped steps still occupy Persist so the exporter has a cell; the unmapped counter is the audit trail.

## Author Information
- **Author**: Nic Cravino
- **Email**: spidernic@me.com
- **LinkedIn**: https://www.linkedin.com/in/nic-cravino
- **Date**: August 2026

## License: Apache License 2.0
"""

from __future__ import annotations

from typing import Any

from attack_stix import load_stix_index
from killchains import build_catalog, normalize_tech_id, slugify

# Constants for Score columns (fourteen ATT&CK tactics collapse into these seven)
PHASES: tuple[tuple[str, str, tuple[str, ...]], ...] = (
    ("recon", "Recon", ("reconnaissance", "resource development")),
    ("access", "Access", ("initial access",)),
    ("execute", "Execute", ("execution",)),
    ("persist", "Persist", ("persistence", "privilege escalation", "defense evasion")),
    ("move", "Move", ("credential access", "discovery", "lateral movement")),
    ("exfil", "Exfil", ("collection", "command and control", "exfiltration")),
    ("impact", "Impact", ("impact",)),
)

# Constants for Score swimlanes (label keywords first, then tactic default)
LANES: tuple[tuple[str, str], ...] = (
    ("human", "Human"),
    ("endpoint", "Endpoint"),
    ("identity", "Identity"),
    ("network", "Network"),
    ("cloud", "Cloud"),
    ("data", "Data"),
)

# Primary visualization tactic for public enterprise T-IDs used in this repo.
# Subtechniques inherit the parent unless listed. Not a full ATT&CK dump.
_TID_TACTIC: dict[str, str] = {
    "T1003": "credential access",
    "T1005": "collection",
    "T1014": "defense evasion",
    "T1016": "discovery",
    "T1018": "discovery",
    "T1020": "exfiltration",
    "T1021": "lateral movement",
    "T1027": "defense evasion",
    "T1028": "lateral movement",
    "T1036": "defense evasion",
    "T1040": "credential access",
    "T1041": "exfiltration",
    "T1046": "discovery",
    "T1047": "execution",
    "T1048": "exfiltration",
    "T1049": "discovery",
    "T1053": "persistence",
    "T1055": "defense evasion",
    "T1056": "collection",
    "T1059": "execution",
    "T1068": "privilege escalation",
    "T1070": "defense evasion",
    "T1071": "command and control",
    "T1074": "collection",
    "T1078": "persistence",
    "T1082": "discovery",
    "T1083": "discovery",
    "T1087": "discovery",
    "T1090": "command and control",
    "T1098": "persistence",
    "T1105": "command and control",
    "T1110": "credential access",
    "T1114": "collection",
    "T1119": "collection",
    "T1133": "initial access",
    "T1134": "privilege escalation",
    "T1135": "discovery",
    "T1136": "persistence",
    "T1140": "defense evasion",
    "T1185": "collection",
    "T1189": "initial access",
    "T1190": "initial access",
    "T1193": "initial access",
    "T1195": "initial access",
    "T1198": "initial access",
    "T1199": "initial access",
    "T1201": "discovery",
    "T1203": "execution",
    "T1204": "execution",
    "T1213": "collection",
    "T1218": "defense evasion",
    "T1219": "command and control",
    "T1485": "impact",
    "T1486": "impact",
    "T1489": "impact",
    "T1490": "impact",
    "T1496": "impact",
    "T1498": "impact",
    "T1499": "impact",
    "T1505": "persistence",
    "T1519": "persistence",
    "T1526": "discovery",
    "T1528": "credential access",
    "T1530": "collection",
    "T1531": "impact",
    "T1534": "lateral movement",
    "T1537": "exfiltration",
    "T1539": "credential access",
    "T1542": "persistence",
    "T1543": "persistence",
    "T1546": "persistence",
    "T1547": "persistence",
    "T1550": "defense evasion",
    "T1552": "credential access",
    "T1554": "persistence",
    "T1555": "credential access",
    "T1556": "credential access",
    "T1557": "credential access",
    "T1562": "defense evasion",
    "T1564": "defense evasion",
    "T1565": "impact",
    "T1566": "initial access",
    "T1567": "exfiltration",
    "T1570": "lateral movement",
    "T1571": "command and control",
    "T1572": "command and control",
    "T1573": "command and control",
    "T1574": "persistence",
    "T1583": "resource development",
    "T1584": "resource development",
    "T1585": "resource development",
    "T1586": "resource development",
    "T1587": "resource development",
    "T1588": "resource development",
    "T1589": "reconnaissance",
    "T1590": "reconnaissance",
    "T1591": "reconnaissance",
    "T1592": "reconnaissance",
    "T1593": "reconnaissance",
    "T1595": "reconnaissance",
    "T1598": "reconnaissance",
    "T1601": "defense evasion",
    "T1606": "credential access",
    "T1619": "discovery",
    "T1621": "credential access",
    "T1656": "defense evasion",
    "T1657": "impact",
    "T1872": "initial access",
}

# Label-substring fallback when a step has no usable T-ID / tactic
_LABEL_TACTIC: tuple[tuple[str, str], ...] = (
    ("spearphish", "initial access"),
    ("phish", "initial access"),
    ("vishing", "initial access"),
    ("user execution", "execution"),
    ("public-facing", "initial access"),
    ("log4shell", "initial access"),
    ("prompt injection", "execution"),
    ("data encrypted", "impact"),
    ("encrypt for impact", "impact"),
    ("ransomware", "impact"),
    ("exfil", "exfiltration"),
    ("credential", "credential access"),
    ("lsass", "credential access"),
    ("valid account", "persistence"),
    ("lateral", "lateral movement"),
    ("scheduled task", "persistence"),
    ("powershell", "execution"),
    ("interpreter", "execution"),
)

# Lane from label keywords (first match wins; tactic defaults sit in lane_for_step)
_LANE_RULES: tuple[tuple[str, tuple[str, ...]], ...] = (
    ("human", ("phish", "spearphish", "vishing", "user execution", "help desk", "social", "impersonat")),
    ("identity", ("valid account", "credential", "lsass", "password", "mfa", "token", "saml", "oauth", "account")),
    ("data", ("data encrypted", "ransomware", "exfil", "stag", "repositor", "data from", "collection", "information repositor")),
    ("cloud", ("saas", "cloud", "mailbox", "azure", "aws", "m365", "sharepoint", "teams", "mcp", "llm", "rag", "vector")),
    ("network", ("public-facing", "remote service", "c2", "protocol", "smb", "rdp", "vpn", "proxy", "application layer")),
)

# Icon from label keywords (else the lane default in _LANE_ICON)
_ICON_RULES: tuple[tuple[str, str], ...] = (
    ("phish", "mail"),
    ("spearphish", "mail"),
    ("vishing", "mail"),
    ("mail", "mail"),
    ("data encrypted", "alert"),
    ("ransomware", "alert"),
    ("prompt injection", "robot"),
    ("llm", "robot"),
    ("mcp", "robot"),
    ("public-facing", "bug"),
    ("exploit", "bug"),
    ("log4shell", "bug"),
    ("credential", "key"),
    ("lsass", "key"),
    ("password", "key"),
    ("valid account", "lock"),
    ("user execution", "user"),
    ("powershell", "terminal"),
    ("interpreter", "terminal"),
    ("scheduled", "terminal"),
    ("exfil", "file"),
    ("saas", "cloud"),
    ("cloud", "cloud"),
)

# Default glyph per lane when no label rule fired
_LANE_ICON = {
    "human": "user",
    "endpoint": "terminal",
    "identity": "lock",
    "network": "globe",
    "cloud": "cloud",
    "data": "database",
}

# Tactic name → phase key (built from PHASES so the two cannot drift)
_TACTIC_PHASE = {
    tactic: key
    for key, _, tactics in PHASES
    for tactic in tactics
}


# Function to squash punctuation in labels (so "Public-Facing" matches "public facing")
def _norm(text: str) -> str:
    return " ".join((text or "").lower().replace("_", " ").replace("-", " ").split())


# Function to drop the subtechnique suffix (T1059.001 → T1059)
def _tid_parent(tech_id: str) -> str:
    value = normalize_tech_id(tech_id)
    return value.split(".")[0] if "." in value else value


# Function to map a T-ID to a visualization tactic (STIX first, then the local table)
def tactic_for_id(tech_id: str) -> str:
    value = normalize_tech_id(tech_id)
    if value.startswith("CVE-"):
        # CVEs sit on Access (public-facing exploit, not a tactic in ATT&CK)
        return "initial access"
    stix = load_stix_index()
    rec = stix.get(value) or stix.get(_tid_parent(value))
    if rec:
        for name in rec.get("tactics") or []:
            if name in _TACTIC_PHASE:
                return name
    # Fallback if the local STIX bundle is missing or has no tactic for this T-ID
    if value in _TID_TACTIC:
        return _TID_TACTIC[value]
    parent = _tid_parent(value)
    return _TID_TACTIC.get(parent, "")


# Function to pick a tactic for a catalog step (claimed tactic, then label, then T-IDs)
def tactic_for_step(step: dict[str, Any]) -> str:
    claimed = _norm(step.get("tactic") or "")
    if claimed in _TACTIC_PHASE:
        return claimed
    blob = _norm(f"{step.get('label') or ''} {step.get('name') or ''}")
    for needle, tactic in _LABEL_TACTIC:
        if needle in blob:
            return tactic
    for meta in step.get("id_meta") or []:
        tech_id = meta.get("suggested_id") or meta.get("id") or ""
        tactic = tactic_for_id(str(tech_id))
        if tactic:
            return tactic
    for tech_id in step.get("ids") or []:
        tactic = tactic_for_id(str(tech_id))
        if tactic:
            return tactic
    return ""


# Function to map an ATT&CK tactic onto a Score phase column
def phase_for_tactic(tactic: str) -> str:
    return _TACTIC_PHASE.get(_norm(tactic), "")


# Function to pick a swimlane for a step (label keywords first, then tactic default)
def lane_for_step(step: dict[str, Any], tactic: str) -> str:
    blob = _norm(f"{step.get('label') or ''} {step.get('name') or ''} {step.get('raw') or ''}")
    for lane, needles in _LANE_RULES:
        if any(needle in blob for needle in needles):
            return lane
    # Tactic defaults when the label has no lane keyword
    if tactic in {"reconnaissance", "resource development"}:
        return "network"
    if tactic == "initial access":
        return "network"
    if tactic == "execution":
        return "endpoint"
    if tactic in {"persistence", "privilege escalation", "defense evasion"}:
        return "endpoint"
    if tactic == "credential access":
        return "identity"
    if tactic in {"discovery", "lateral movement"}:
        return "network"
    if tactic in {"collection", "exfiltration"}:
        return "data"
    if tactic == "command and control":
        return "network"
    if tactic == "impact":
        return "data"
    return "endpoint"


# Function to pick a glyph icon (label keywords, else the lane default)
def icon_for_step(step: dict[str, Any], lane: str) -> str:
    blob = _norm(f"{step.get('label') or ''} {step.get('name') or ''}")
    for needle, icon in _ICON_RULES:
        if needle in blob:
            return icon
    return _LANE_ICON.get(lane, "terminal")


# Function to take the first T-ID off a step (suggested_id wins over the raw id)
def _primary_id(step: dict[str, Any]) -> str:
    for meta in step.get("id_meta") or []:
        value = meta.get("suggested_id") or meta.get("id")
        if value:
            return str(value)
    ids = step.get("ids") or []
    return str(ids[0]) if ids else ""


# Function to clip a step name for the board (ellipsis after 20 chars)
def _short_label(step: dict[str, Any]) -> str:
    name = (step.get("name") or step.get("label") or "").strip()
    if len(name) <= 22:
        return name
    return name[:20].rstrip() + "…"


# Function to resolve a killchain template by id, name, or slug
def _find_template(key: str, catalog: dict[str, Any] | None = None) -> dict[str, Any]:
    catalog = catalog or build_catalog()
    wanted = (key or "").strip().lower()
    # Accept killchain:slug, the raw slug, or the template name
    if wanted.startswith("killchain:"):
        wanted_id = wanted
        wanted_name = wanted.split(":", 1)[1]
    else:
        wanted_id = f"killchain:{slugify(key)}"
        wanted_name = wanted
    for item in catalog["templates"]:
        if item["id"].lower() == wanted_id or item["name"].lower() == wanted or item["slug"] == wanted_name:
            return item
    raise FileNotFoundError(f"Unknown template: {key}")


# Function to compile a template into Campaign Score IR (one spine node per occupied phase)
def compile_score(template: dict[str, Any]) -> dict[str, Any]:
    glyphs: list[dict[str, Any]] = []
    unmapped = 0
    for step in template.get("steps") or []:
        # Notes stay off the board (ATLAS lines live in template.notes)
        if step.get("kind") == "note":
            continue
        tactic = tactic_for_step(step)
        phase = phase_for_tactic(tactic)
        if not phase:
            unmapped += 1
            # Fallback if the tactic is unknown — Persist is the middle column, not a claim
            phase = "persist"
            tactic = tactic or "unmapped"
        lane = lane_for_step(step, tactic)
        tech_id = _primary_id(step)
        glyphs.append(
            {
                "id": f"g-{step.get('ord')}",
                "ord": step.get("ord"),
                "phase": phase,
                "lane": lane,
                "tactic": tactic,
                "tech_id": tech_id,
                "label": _short_label(step),
                "icon": icon_for_step(step, lane),
                "role": "toolbox",
            }
        )

    occupied_phases = [key for key, _, _ in PHASES if any(item["phase"] == key for item in glyphs)]
    climax_id = ""
    # Climax prefers Impact, then Exfil, then the last glyph (rightmost beat on the board)
    for preferred in ("impact", "exfil"):
        match = next((item for item in reversed(glyphs) if item["phase"] == preferred), None)
        if match:
            climax_id = match["id"]
            break
    if not climax_id and glyphs:
        climax_id = glyphs[-1]["id"]
    climax = next((item for item in glyphs if item["id"] == climax_id), None)

    spine_ids: list[str] = []
    for key, _, _ in PHASES:
        if key not in occupied_phases:
            continue
        if climax and climax["phase"] == key:
            pick = climax
        else:
            pick = next(item for item in glyphs if item["phase"] == key)
        # One spine node per occupied phase; leftover glyphs stay toolbox chips
        pick["role"] = "climax" if pick["id"] == climax_id else "spine"
        spine_ids.append(pick["id"])

    toolbox = [item["id"] for item in glyphs if item["role"] == "toolbox"]
    score = {
        "id": template.get("id"),
        "name": template.get("name"),
        "slug": template.get("slug"),
        "families": list(template.get("families") or []),
        "order_quality": template.get("order_quality") or "list-order-assumed",
        "inferred": (template.get("order_quality") or "") != "tactic-prefixed",
        "step_count": len(glyphs),
        "phases": [{"id": key, "label": label} for key, label, _ in PHASES if key in occupied_phases],
        "lanes": [{"id": key, "label": label} for key, label in LANES],
        "glyphs": glyphs,
        "spine": spine_ids,
        "toolbox": toolbox,
        "climax": climax_id,
        "notes": list(template.get("notes") or []),
        "unmapped": unmapped,
        "disclaimer": (
            "Phase columns are inferred from public ATT&CK tactic families. "
            "List order in the template is not a proven kill chain."
        ),
    }
    # Views ride on the IR so the HTML exporter stays a dumb renderer
    score["views"] = {
        "sequence": sequence_view(score),
        "storyboard": storyboard_view(score),
    }
    return score


# Lane id → display label (sequence actors and storyboard captions)
_LANE_LABEL = {key: label for key, label in LANES}


# Function to return spine glyphs in IR order (not append order)
def _spine_glyphs(score: dict[str, Any]) -> list[dict[str, Any]]:
    order = {glyph_id: index for index, glyph_id in enumerate(score.get("spine") or [])}
    return sorted(
        (item for item in score.get("glyphs") or [] if item["id"] in order),
        key=lambda item: order[item["id"]],
    )


# Function to build the sequence-diagram view (attacker plus up to four lanes)
def sequence_view(score: dict[str, Any]) -> dict[str, Any]:
    spine = _spine_glyphs(score)
    actors: list[dict[str, str]] = [{"id": "attacker", "label": "Attacker"}]
    seen = {"attacker"}
    for glyph in spine:
        lane = glyph.get("lane") or "endpoint"
        if lane not in seen:
            actors.append({"id": lane, "label": _LANE_LABEL.get(lane, lane.title())})
            seen.add(lane)
        if len(actors) >= 5:
            # Sequence diagrams get crowded past five actors
            break
    actor_ids = {item["id"] for item in actors}
    messages = []
    previous = "attacker"
    for glyph in spine:
        dest = glyph.get("lane") or "endpoint"
        if dest not in actor_ids:
            dest = actors[-1]["id"]
        # Self-lane hops bounce off Attacker so the arrow is still visible
        source = previous if previous != dest else "attacker"
        if source not in actor_ids:
            source = "attacker"
        messages.append(
            {
                "from": source,
                "to": dest,
                "tech_id": glyph.get("tech_id") or "",
                "label": glyph.get("label") or "",
                "icon": glyph.get("icon") or "terminal",
                "phase": glyph.get("phase") or "",
                "climax": glyph.get("role") == "climax",
            }
        )
        previous = dest
    return {
        "available": 1 <= len(messages) <= 7,
        "actors": actors,
        "messages": messages,
    }


# Function to subsample a spine into storyboard frames (evenly spaced, including first and last)
def _pick_frames(spine: list[dict[str, Any]], max_frames: int) -> list[dict[str, Any]]:
    if len(spine) <= max_frames:
        return spine
    if max_frames <= 1:
        return spine[-1:]
    # Evenly spaced indexes, always including first and last (climax is usually last)
    indexes = [round(i * (len(spine) - 1) / (max_frames - 1)) for i in range(max_frames)]
    seen: set[int] = set()
    salida: list[dict[str, Any]] = []
    for index in indexes:
        if index not in seen:
            seen.add(index)
            salida.append(spine[index])
    return salida


# Function to build the storyboard view (five frames unless the chain is already short)
def storyboard_view(score: dict[str, Any], max_frames: int = 5) -> dict[str, Any]:
    spine = _spine_glyphs(score)
    if not spine:
        return {"available": False, "frames": [], "collapsed": False}
    salida = _pick_frames(spine, max_frames)
    frames = [
        {
            "n": index + 1,
            "tech_id": glyph.get("tech_id") or "",
            "title": glyph.get("label") or "",
            "phase": glyph.get("phase") or "",
            "lane": glyph.get("lane") or "",
            "icon": glyph.get("icon") or "user",
            "climax": glyph.get("role") == "climax",
            "caption": f"{_LANE_LABEL.get(glyph.get('lane') or '', glyph.get('lane') or '')} · {glyph.get('phase') or ''}",
        }
        for index, glyph in enumerate(salida)
    ]
    # Short chains keep every spine node; longer ones set collapsed and subsample
    short = int(score.get("step_count") or 0) <= 6
    return {
        "available": short or 1 <= len(frames) <= max_frames,
        "collapsed": not short and len(spine) > max_frames,
        "frames": frames,
    }


# Function to collect technique IDs from a compiled score (empty ids stay out)
def _score_ids(score: dict[str, Any]) -> set[str]:
    return {str(item.get("tech_id")) for item in score.get("glyphs") or [] if item.get("tech_id")}


# Function to compare two scores by technique-ID overlap (Jaccard on the glyph ids)
def compare_scores(key_a: str, key_b: str, catalog: dict[str, Any] | None = None) -> dict[str, Any]:
    catalog = catalog or build_catalog()
    left = score_for(key_a, catalog)
    right = score_for(key_b, catalog)
    a_ids = _score_ids(left)
    b_ids = _score_ids(right)
    both = sorted(a_ids & b_ids)
    only_a = sorted(a_ids - b_ids)
    only_b = sorted(b_ids - a_ids)
    union = len(a_ids | b_ids)
    # Jaccard on technique IDs, not on phase layout (empty union is 0.0)
    return {
        "a": left,
        "b": right,
        "shared": both,
        "only_a": only_a,
        "only_b": only_b,
        "jaccard": round(len(both) / union, 3) if union else 0.0,
    }


# Function to compile one template from the catalog (name, slug, or killchain: id)
def score_for(key: str, catalog: dict[str, Any] | None = None) -> dict[str, Any]:
    catalog = catalog or build_catalog()
    return compile_score(_find_template(key, catalog))


# Function to compile every catalog template into Score IR
def compile_all() -> list[dict[str, Any]]:
    catalog = build_catalog()
    return [compile_score(item) for item in catalog["templates"]]
