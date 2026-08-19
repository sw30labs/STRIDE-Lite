#!/usr/bin/env python3
"""
Campaign Score HTML/SVG/JSON Export

Deterministic renderer for a Campaign Score intermediate representation.
I wrote this so the board never goes through an LLM: phase columns, lane
rows, spine, and toolbox overflow are laid out from the IR lists.
The same grid is painted as a self-contained HTML page, a matching SVG,
and/or the JSON IR.

Notes:
- Geometry comes from the IR, not an LLM. campaign_score.py is the source of truth.
- ICONS holds tiny path fragments keyed by glyph.icon; everything else is IR.
- Keep this file dumb so a second exporter cannot invent geometry.

## Author Information
- **Author**: Nic Cravino
- **Email**: spidernic@me.com
- **LinkedIn**: https://www.linkedin.com/in/nic-cravino
- **Date**: August 2026

## License: Apache License 2.0
"""

from __future__ import annotations

import argparse
import html
import json
from pathlib import Path
from typing import Any

from campaign_score import compile_all, score_for
from killchains import slugify
from utils import BASE_DIR

# Constants for file paths and grid layout (IR fills cells; sizes stay fixed)
OUT_DIR = Path(BASE_DIR) / "output" / "diagrams"

# Lane-label gutter and phase cell size. I sized these so a 7-phase score still fits a laptop.
LABEL_W = 56
COL_W = 92
ROW_H = 44
HEAD_H = 28

# Path `d` fragments keyed by glyph.icon the IR already chose
ICONS: dict[str, str] = {
    "user": "M8 7a4 4 0 1 0 8 0a4 4 0 0 0 -8 0 M6 21v-2a4 4 0 0 1 4 -4h4a4 4 0 0 1 4 4v2",
    "mail": "M3 7a2 2 0 0 1 2 -2h14a2 2 0 0 1 2 2v10a2 2 0 0 1 -2 2h-14a2 2 0 0 1 -2 -2v-10 M3 7l9 6l9 -6",
    "terminal": "M5 7l5 5l-5 5 M12 19h7",
    "lock": "M5 13a2 2 0 0 1 2 -2h10a2 2 0 0 1 2 2v6a2 2 0 0 1 -2 2h-10a2 2 0 0 1 -2 -2v-6 M8 11v-4a4 4 0 1 1 8 0v4",
    "key": "M8 15a4 4 0 1 0 8 0a4 4 0 1 0 -8 0 M16.5 9.5l3.5 -3.5l-2 -2 M18 7l2 2",
    "globe": "M3 12a9 9 0 1 0 18 0a9 9 0 0 0 -18 0 M3.6 9h16.8 M3.6 15h16.8 M11.5 3a17 17 0 0 0 0 18 M12.5 3a17 17 0 0 1 0 18",
    "cloud": "M6.7 18c-2.6 0 -4.7 -2 -4.7 -4.5s2.1 -4.5 4.7 -4.5c.4 -1.8 1.8 -3.2 3.7 -3.8c1.9 -.6 4 -.2 5.4 1c1.5 1.2 2.2 3 1.8 4.8h1c1.9 0 3.5 1.6 3.5 3.5s-1.6 3.5 -3.5 3.5h-11.9",
    "database": "M4 6a8 3 0 1 0 16 0a8 3 0 1 0 -16 0 M4 6v6a8 3 0 0 0 16 0v-6 M4 12v6a8 3 0 0 0 16 0v-6",
    "bug": "M9 9v-1a3 3 0 0 1 6 0v1 M8 9h8a6 6 0 0 1 1 3v3a5 5 0 0 1 -10 0v-3a6 6 0 0 1 1 -3 M3 13h4 M17 13h4 M12 20v-6",
    "alert": "M12 9v4 M10.4 3.6l-8.1 13.5a1.9 1.9 0 0 1 1.6 2.9h16.2a1.9 1.9 0 0 0 1.6 -2.9l-8.1 -13.5a1.9 1.9 0 0 0 -3.3 0 M12 16h.01",
    "robot": "M6 6a2 2 0 0 1 2 -2h8a2 2 0 0 1 2 2v4a2 2 0 0 1 -2 2h-8a2 2 0 0 1 -2 -2z M12 2v2 M9 12v9 M15 12v9 M10 8h.01 M14 8h.01",
    "file": "M14 3v4a1 1 0 0 0 1 1h4 M17 21h-10a2 2 0 0 1 -2 -2v-14a2 2 0 0 1 2 -2h7l5 5v11a2 2 0 0 1 -2 2",
    "server": "M3 7a3 3 0 0 1 3 -3h12a3 3 0 0 1 3 3v2a3 3 0 0 1 -3 3h-12a3 3 0 0 1 -3 -3 M3 15a3 3 0 0 1 3 -3h12a3 3 0 0 1 3 3v2a3 3 0 0 1 -3 3h-12a3 3 0 0 1 -3 -3",
}

# Ink and paper for the self-contained HTML (no extra stylesheet)
INK = "#d7e3f4"
MUTED = "#8493aa"
TEAL = "#5eead4"
AMBER = "#fbbf24"
LINE = "rgba(94,234,212,0.18)"
PAPER = "#04060c"


# Function to HTML-escape a value (quote=True covers aria ids on the svg)
def _esc(value: Any) -> str:
    return html.escape(str(value or ""), quote=True)


# SVG scoreboard from the IR grid (geometry from IR, not an LLM)
def render_svg(score: dict[str, Any]) -> str:
    phases = score.get("phases") or []
    lanes = score.get("lanes") or []
    glyphs = score.get("glyphs") or []
    # ViewBox from occupied phases × lanes (8px gutter so the last stroke is not clipped)
    width = LABEL_W + len(phases) * COL_W + 8
    height = HEAD_H + len(lanes) * ROW_H + 8
    slug = _esc(score.get("slug") or "score")
    parts = [
        f'<svg class="score-svg" viewBox="0 0 {width} {height}" role="img" '
        f'aria-labelledby="{slug}-title {slug}-desc" xmlns="http://www.w3.org/2000/svg">',
        f'<title id="{slug}-title">{_esc(score.get("name") or "Campaign score")}</title>',
        f'<desc id="{slug}-desc">Phase-by-lane campaign score with a short spine and toolbox overflow.</desc>',
        f'<rect width="{width}" height="{height}" fill="{PAPER}"/>',
    ]
    # Index glyphs by cell so a crowded (phase, lane) can show +N overflow
    by_cell: dict[tuple[str, str], list[dict[str, Any]]] = {}
    for glyph in glyphs:
        by_cell.setdefault((glyph["phase"], glyph["lane"]), []).append(glyph)

    for col, phase in enumerate(phases):
        x = LABEL_W + col * COL_W
        parts.append(f'<text fill="{MUTED}" font-family="ui-monospace,monospace" font-size="8" text-anchor="middle" x="{x + COL_W / 2}" y="16">{_esc(phase["label"])}</text>')
        for row, lane in enumerate(lanes):
            y = HEAD_H + row * ROW_H
            if col == 0:
                parts.append(f'<text fill="{MUTED}" font-family="ui-monospace,monospace" font-size="8" x="6" y="{y + 26}">{_esc(lane["label"])}</text>')
            here = by_cell.get((phase["id"], lane["id"])) or []
            # Prefer climax, then spine, then first glyph (one lead per occupied cell)
            lead = next((item for item in here if item["role"] == "climax"), None)
            lead = lead or next((item for item in here if item["role"] == "spine"), None)
            lead = lead or (here[0] if here else None)
            if not lead:
                continue
            extras = [item for item in here if item["id"] != lead["id"]]
            climax = lead["role"] == "climax"
            # Climax is amber; spine is teal; leftover glyphs stay muted
            color = AMBER if climax else TEAL if lead["role"] == "spine" else MUTED
            stroke = AMBER if climax else LINE
            icon = ICONS.get(lead.get("icon") or "", ICONS["terminal"])
            parts.append(
                f'<rect x="{x + 6}" y="{y + 4}" width="{COL_W - 12}" height="36" rx="4" '
                f'fill="#0d1422" stroke="{stroke}"/>'
            )
            parts.append(
                f'<g transform="translate({x + 10},{y + 10}) scale(0.55)" fill="none" '
                f'stroke="{color}" stroke-width="1.6" stroke-linecap="round" stroke-linejoin="round">'
                f'<path d="{icon}"/></g>'
            )
            parts.append(
                f'<text fill="{TEAL}" font-family="ui-monospace,monospace" font-size="7" x="{x + 28}" y="{y + 18}">{_esc(lead.get("tech_id") or "—")}</text>'
            )
            parts.append(
                f'<text fill="{INK}" font-family="system-ui,sans-serif" font-size="8" x="{x + 28}" y="{y + 30}">{_esc(lead.get("label"))}</text>'
            )
            if extras:
                # +N in the corner; the HTML toolbox list has the rest
                parts.append(
                    f'<text fill="{AMBER}" font-family="ui-monospace,monospace" font-size="8" x="{x + COL_W - 14}" y="{y + 14}">+{len(extras)}</text>'
                )
    parts.append("</svg>")
    return "\n".join(parts)


# Optional sequence / storyboard views (same IR, different lists)
def _view_lists(score: dict[str, Any]) -> str:
    seq = (score.get("views") or {}).get("sequence") or {}
    story = (score.get("views") or {}).get("storyboard") or {}
    parts: list[str] = []
    if seq.get("available"):
        actors = " · ".join(item.get("label") or "" for item in seq.get("actors") or [])
        msgs = "".join(
            f"<li><code>{_esc(item.get('from'))}</code> → <code>{_esc(item.get('to'))}</code> · {_esc(item.get('tech_id'))} {_esc(item.get('label'))}</li>"
            for item in seq.get("messages") or []
        )
        parts.append(f"<h2>Sequence</h2><p class=\"lede\">{_esc(actors)}</p><ol>{msgs}</ol>")
    if story.get("available"):
        frames = "".join(
            f"<li><strong>{_esc(item.get('n'))}.</strong> {_esc(item.get('tech_id'))} · {_esc(item.get('title'))} · {_esc(item.get('caption'))}</li>"
            for item in story.get("frames") or []
        )
        # Collapsed spine is a flag on the storyboard view, not missing data
        note = " Spine collapsed." if story.get("collapsed") else ""
        parts.append(f"<h2>Storyboard</h2><p class=\"lede\">{_esc(note)}</p><ol>{frames}</ol>")
    return "\n".join(parts)


# Self-contained HTML around the SVG (portable; no server, no CDN)
def render_html(score: dict[str, Any], caption: str = "") -> str:
    spine = [item for item in score.get("glyphs") or [] if item["id"] in set(score.get("spine") or [])]
    # Keep spine list order from the IR (not the order glyphs were appended)
    spine.sort(key=lambda item: (score.get("spine") or []).index(item["id"]))
    toolbox = [item for item in score.get("glyphs") or [] if item.get("role") == "toolbox"]
    banner = ""
    if score.get("inferred"):
        # Banner when phase order was inferred from T-IDs, not a proven chain
        banner = '<p class="banner">Phase order inferred from T-IDs, not a proven kill chain.</p>'
    caption_html = html.escape(caption) if caption else ""
    spine_items = "".join(
        f"<li><code>{_esc(item.get('tech_id'))}</code> · {_esc(item.get('label'))} · {_esc(item.get('phase'))}</li>"
        for item in spine
    )
    toolbox_items = "".join(
        f"<li><code>{_esc(item.get('tech_id'))}</code> · {_esc(item.get('label'))}</li>"
        for item in toolbox
    )
    return f"""<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="utf-8"/>
  <meta name="viewport" content="width=device-width, initial-scale=1"/>
  <title>{_esc(score.get("name") or "Campaign score")}</title>
  <style>
    :root {{ color-scheme: dark; }}
    body {{ margin: 24px; background: {PAPER}; color: {INK}; font-family: system-ui, sans-serif; }}
    .eyebrow {{ font: 11px ui-monospace, monospace; letter-spacing: 0.16em; text-transform: uppercase; color: {MUTED}; }}
    h1 {{ font-size: 22px; font-weight: 600; margin: 6px 0 12px; }}
    .banner {{ color: {AMBER}; border: 1px solid rgba(251,191,36,0.25); padding: 8px 10px; border-radius: 4px; font: 12px ui-monospace, monospace; }}
    .score-svg {{ width: 100%; height: auto; border: 1px solid {LINE}; border-radius: 6px; }}
    .caption[data-caption-slot] {{ min-height: 1.4em; color: {MUTED}; font-style: italic; }}
    h2 {{ font-size: 13px; letter-spacing: 0.08em; text-transform: uppercase; color: {MUTED}; margin: 20px 0 8px; }}
    li {{ font-size: 13px; line-height: 1.5; color: {MUTED}; }}
    code {{ color: {TEAL}; }}
    footer {{ margin-top: 28px; font: 11px ui-monospace, monospace; color: {MUTED}; border-top: 1px solid {LINE}; padding-top: 12px; }}
  </style>
</head>
<body>
  <p class="eyebrow">STRIDE-Lite · Campaign Score</p>
  <h1>{_esc(score.get("name"))}</h1>
  {banner}
  {render_svg(score)}
  <p class="caption" data-caption-slot="">{caption_html}</p>
  {_view_lists(score)}
  <h2>Spine</h2>
  <ol>{spine_items}</ol>
  <h2>Toolbox</h2>
  <ul>{toolbox_items or "<li>None</li>"}</ul>
  <footer>{_esc(score.get("disclaimer"))} MITRE ATT&amp;CK® IDs are public identifiers used for structure.</footer>
</body>
</html>
"""


# Write each requested format beside the others (html / svg / json)
def export_score(score: dict[str, Any], dest_dir: Path, formats: set[str]) -> list[Path]:
    dest_dir.mkdir(parents=True, exist_ok=True)
    slug = score.get("slug") or slugify(score.get("name") or "score")
    salida: list[Path] = []
    if "html" in formats:
        path = dest_dir / f"{slug}.html"
        path.write_text(render_html(score), encoding="utf-8")
        salida.append(path)
    if "svg" in formats:
        path = dest_dir / f"{slug}.svg"
        path.write_text(render_svg(score), encoding="utf-8")
        salida.append(path)
    if "json" in formats:
        path = dest_dir / f"{slug}.json"
        path.write_text(json.dumps(score, indent=2), encoding="utf-8")
        salida.append(path)
    return salida


# Function to parse command-line arguments and export (one template or --all)
def main() -> None:
    parser = argparse.ArgumentParser(description="Export a Campaign Score as self-contained HTML/SVG/JSON")
    parser.add_argument("template", nargs="?", help='Template name or killchain:slug')
    parser.add_argument("--all", action="store_true", help="Export every predefined template")
    parser.add_argument("--format", default="html", help="Comma list: html,svg,json (default html)")
    parser.add_argument("--out", default=str(OUT_DIR), help="Output directory")
    args = parser.parse_args()
    formats = {item.strip().lower() for item in args.format.split(",") if item.strip()}
    if args.all:
        scores = compile_all()
    elif args.template:
        scores = [score_for(args.template)]
    else:
        parser.error("Provide a template name or --all")
    dest = Path(args.out)
    written: list[Path] = []
    for score in scores:
        written.extend(export_score(score, dest, formats))
    for path in written:
        print(path)


if __name__ == "__main__":
    main()
