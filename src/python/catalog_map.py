"""
Catalog Map IR Compiler

Turn compiled Campaign Scores into a polar / ternary catalog map.
The browser paints; it does not invent slices, radii, or coordinates.

Notes:
- Six slices, closed vocabulary. First-match on glyphs + families + name.
- Radius is the data/cloud share (compositional Data vertex).
- Polar θ is slice center plus a deterministic intra-slice spread.
- Ternary is Human / Infra / Data (shares sum to 1) — the 3-axis view, still 2D.

## Author Information
- **Author**: Nic Cravino
- **Email**: spidernic@me.com
- **LinkedIn**: https://www.linkedin.com/in/nic-cravino
- **Date**: August 2026

## License: Apache License 2.0
"""

from __future__ import annotations

import math
from collections import Counter, defaultdict
from typing import Any

from campaign_score import compile_score
from killchains import build_catalog

# Slice ring around the wheel (index 0 at 12 o'clock, clockwise)
SLICES: tuple[tuple[str, str, str], ...] = (
    ("identity", "Identity", "#fbbf24"),
    ("exploit", "Exploit", "#f87171"),
    ("espionage", "Espionage", "#22d3ee"),
    ("cloud-api", "Cloud / API", "#5eead4"),
    ("agent-ai", "Agent runtime", "#a78bfa"),
    ("ransomware", "Ransomware", "#fb923c"),
)

SLICE_IDS: tuple[str, ...] = tuple(item[0] for item in SLICES)
SLICE_META: dict[str, dict[str, Any]] = {
    key: {"id": key, "label": label, "color": color, "index": index}
    for index, (key, label, color) in enumerate(SLICES)
}

# Polar radii in unit-circle space (hole so the hub stays readable)
POLAR_INNER = 0.26
POLAR_OUTER = 0.90
SLICE_SPREAD = 0.72  # fraction of the wedge used for intra-slice spread
TERNARY_SQRT3_2 = 3**0.5 / 2.0

# Name needles for agent-runtime when family_tags has not caught up
_AGENT_NEEDLES = (
    "mcp",
    "rag",
    "llm",
    "prompt",
    "agentic",
    "copilot",
    "vector store",
    "ai saas",
    "buy-side",
    "shadow ai",
    "llmj",
)

# Social / MFA / cookie / vishing — identity before ransomware
_IDENTITY_PREFIXES = ("T1566", "T1539", "T1621", "T1550", "T1606", "T1656", "T1598")
_CLOUD_IDS = {"T1530", "T1526", "T1619"}


# Function to collect T-IDs plus their parent (T1566.001 also counts as T1566)
def _tech_ids(score: dict[str, Any]) -> set[str]:
    salida: set[str] = set()
    for glyph in score.get("glyphs") or []:
        tid = str(glyph.get("tech_id") or "").strip().upper()
        if not tid:
            continue
        salida.add(tid)
        salida.add(tid.split(".")[0])
    return salida


# Function to count glyphs per lane / phase (empty score → n=1 so shares stay defined)
def _counts(score: dict[str, Any]) -> tuple[int, Counter, Counter]:
    glyphs = [item for item in (score.get("glyphs") or []) if item.get("role") != "note"]
    n = max(len(glyphs), 1)
    lanes = Counter(str(item.get("lane") or "") for item in glyphs)
    phases = Counter(str(item.get("phase") or "") for item in glyphs)
    return n, lanes, phases


# Function to fold six lanes into Human / Infra / Data (compositional, sum=1)
def lane_composition(score: dict[str, Any]) -> dict[str, float]:
    n, lanes, _ = _counts(score)
    human = (lanes["human"] + lanes["identity"]) / n
    infra = (lanes["endpoint"] + lanes["network"]) / n
    data = (lanes["data"] + lanes["cloud"]) / n
    total = human + infra + data
    if total <= 0:
        return {"human": 0.0, "infra": 1.0, "data": 0.0}
    human_s = round(human / total, 4)
    data_s = round(data / total, 4)
    infra_s = round(1.0 - human_s - data_s, 4)
    return {"human": human_s, "infra": infra_s, "data": data_s}


# Function to pick one of six slices (first match; order is the product rule)
def classify_slice(score: dict[str, Any]) -> str:
    ids = _tech_ids(score)
    name = str(score.get("name") or "").lower()
    families = {str(item).lower() for item in (score.get("families") or [])}
    n, lanes, phases = _counts(score)
    humanish = (lanes["human"] + lanes["identity"]) / n
    dataish = (lanes["data"] + lanes["cloud"]) / n
    persist_move = (phases["persist"] + phases["move"]) / n

    # Agent runtime — buy-side / SaaS copilots stay together on purpose
    if "ai-saas" in families or any(needle in name for needle in _AGENT_NEEDLES):
        return "agent-ai"

    # Identity before ransomware so help-desk + T1486 (Scattered Spider) stays human-led
    identity_hit = any(
        tid == prefix or tid.startswith(prefix + ".")
        for tid in ids
        for prefix in _IDENTITY_PREFIXES
    )
    if humanish >= 0.28 and (identity_hit or lanes["human"] >= 2):
        return "identity"

    if "T1486" in ids or "ransomware" in families:
        return "ransomware"

    if "api" in families:
        return "cloud-api"
    if (ids & _CLOUD_IDS or "cloud" in name or "saas" in name or "snowflake" in name) and dataish >= 0.32:
        return "cloud-api"

    if "apt" in families:
        return "espionage"
    # LOTL / pre-position: persist+move without encrypt, and actual Move (discovery/lateral)
    if (
        persist_move >= 0.40
        and phases["impact"] == 0
        and phases["move"] > 0
        and (lanes["endpoint"] + lanes["network"]) / n >= 0.50
    ):
        return "espionage"

    return "exploit"


# Function to feature one score (no polar θ — that needs the rest of the slice)
def point_features(score: dict[str, Any]) -> dict[str, Any]:
    comp = lane_composition(score)
    slice_id = classify_slice(score)
    meta = SLICE_META[slice_id]
    step_count = int(score.get("step_count") or len(score.get("glyphs") or []))
    return {
        "id": score.get("id"),
        "name": score.get("name"),
        "slug": score.get("slug"),
        "families": list(score.get("families") or []),
        "slice": slice_id,
        "slice_label": meta["label"],
        "slice_index": meta["index"],
        "color": meta["color"],
        "human": comp["human"],
        "infra": comp["infra"],
        "data": comp["data"],
        "radius": comp["data"],
        "step_count": step_count,
    }


# Function to map data-share onto the polar ring (nothing sits on the hub or the rim)
def _polar_r(radius: float) -> float:
    clamped = min(1.0, max(0.0, float(radius)))
    return POLAR_INNER + (POLAR_OUTER - POLAR_INNER) * clamped


# Function to spread points inside a wedge (sort by radius, then name — stable)
def _layout_polar(points: list[dict[str, Any]]) -> None:
    width = 2.0 * math.pi / len(SLICES)
    by_slice: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for point in points:
        by_slice[point["slice"]].append(point)
    for slice_id, group in by_slice.items():
        group.sort(key=lambda item: (item["radius"], item["name"] or ""))
        n = len(group)
        center = SLICE_META[slice_id]["index"] * width - math.pi / 2.0 + width / 2.0
        last_r = -1.0
        for index, point in enumerate(group):
            offset = (index - (n - 1) / 2.0) / max(n, 1)
            theta = center + offset * width * SLICE_SPREAD
            visual_r = _polar_r(point["radius"])
            # Same-radius neighbors get a tiny outward nudge so dots do not stack
            if last_r >= 0 and abs(visual_r - last_r) < 0.035:
                visual_r = min(POLAR_OUTER, last_r + 0.04)
            last_r = visual_r
            point["theta"] = round(theta, 6)
            point["polar_r"] = round(visual_r, 6)
            point["polar_x"] = round(visual_r * math.cos(theta), 6)
            point["polar_y"] = round(visual_r * math.sin(theta), 6)


# Function to place Human/Infra/Data on an equilateral triangle (y-up, unit height √3/2)
def _layout_ternary(points: list[dict[str, Any]]) -> None:
    for point in points:
        human = point["human"]
        data = point["data"]
        # Infra is the leftover vertex; x = data + human/2, y = human * √3/2
        point["ternary_x"] = round(data + human / 2.0, 6)
        point["ternary_y"] = round(human * TERNARY_SQRT3_2, 6)


# Function to scale dot radius from step_count (unit-circle space, ~8–14px at 620px)
def _layout_dots(points: list[dict[str, Any]]) -> None:
    counts = [int(item["step_count"] or 1) for item in points] or [1]
    lo, hi = min(counts), max(counts)
    span = max(hi - lo, 1)
    for point in points:
        t = (int(point["step_count"] or 1) - lo) / span
        point["dot_r"] = round(0.045 + 0.028 * t, 6)


# Function to compile the catalog map IR (slices + one point per template)
def compile_catalog_map(catalog: dict[str, Any] | None = None) -> dict[str, Any]:
    catalog = catalog or build_catalog()
    points = [point_features(compile_score(template)) for template in catalog.get("templates") or []]
    _layout_polar(points)
    _layout_ternary(points)
    _layout_dots(points)
    return {
        "slices": [
            {
                "id": key,
                "label": label,
                "color": color,
                "index": index,
                "theta_start": round(index * 2.0 * math.pi / len(SLICES) - math.pi / 2.0, 6),
                "theta_end": round((index + 1) * 2.0 * math.pi / len(SLICES) - math.pi / 2.0, 6),
            }
            for index, (key, label, color) in enumerate(SLICES)
        ],
        "points": points,
        "rings": [
            {"t": 0.0, "r": _polar_r(0.0), "label": "infra"},
            {"t": 0.5, "r": _polar_r(0.5), "label": "mix"},
            {"t": 1.0, "r": _polar_r(1.0), "label": "data"},
        ],
        "polar": {"inner": POLAR_INNER, "outer": POLAR_OUTER},
        "ternary": {
            "human": {"x": 0.5, "y": TERNARY_SQRT3_2, "label": "Human"},
            "infra": {"x": 0.0, "y": 0.0, "label": "Infra"},
            "data": {"x": 1.0, "y": 0.0, "label": "Data"},
        },
        "disclaimer": (
            "Slices are compiled from Campaign Score lanes and ATT&CK IDs. "
            "Radius is data/cloud share. Ternary vertices are Human, Infra, Data."
        ),
    }


# Function to look up one laid-out point (full catalog layout, so θ matches the map)
def map_point_for(key: str, catalog: dict[str, Any] | None = None) -> dict[str, Any]:
    catalog = catalog or build_catalog()
    wanted = (key or "").strip().lower()
    payload = compile_catalog_map(catalog)
    for point in payload["points"]:
        if str(point.get("id") or "").lower() == wanted or str(point.get("name") or "").lower() == wanted:
            return point
        if wanted.startswith("killchain:") and str(point.get("id") or "").lower() == wanted:
            return point
    raise FileNotFoundError(f"Unknown template: {key}")
