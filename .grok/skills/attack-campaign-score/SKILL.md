---
name: attack-campaign-score
description: Export a STRIDE-Lite Campaign Score (phase × lane kill-chain diagram) from a predefined attack template. Use when the user asks for a score, kill-chain diagram, attack-template visual, editorial still, or runs /attack-campaign-score. Geometry is compiled by Python from the template IR — never invent nodes or go through Mermaid.
---

# Attack Campaign Score

Export a **Campaign Score** for one or more entries in `data/predefined_attack_templates.json`.

The score is a phase × lane grid with a short spine, toolbox overflow, and one climax. It is **not** a 1→2→3 flowchart. Most templates are technique bags; list order is not a proven kill chain.

## Do this

From the repo root:

```bash
python src/python/score_export.py "Zero-Day Exploit [New]"
python src/python/score_export.py --all
python src/python/score_export.py "LockBit Ransomware Attack" --format html,svg,json
```

Writes gitignored files under `output/diagrams/<slug>.html` (plus `.svg` / `.json` if requested).

Open the HTML. Confirm the inferred-order banner is present when `inferred: true`. Sequence and storyboard lists are in the same file; they use the spine, not every technique.

Compare two templates in Vault (COMPARE) or:

```bash
# visual compare payload
# GET /api/killchains/score-compare?a=Zero-Day%20Exploit%20%5BNew%5D&b=LockBit%20Ransomware%20Attack
```

## Do not

- Do not draw Mermaid, then “translate” it. Mermaid is not a source.
- Do not add, drop, rename, or reposition glyphs. The IR in `campaign_score.score_for` is the geometry.
- Do not call an image model or diagram-design to invent a new layout unless the user **explicitly** asks for a redraw *after* the CLI file exists. If they do, feed `output/diagrams/<slug>.json` (the IR), keep spine length, and report every collapse.
- Do not claim MITRE affiliation.
- Do not download ATT&CK STIX.

## Optional caption

If the user wants a one-line editorial caption, write it only into the existing `<p class="caption" data-caption-slot="">`. One sentence. No extra boxes.

## Live viewer

The same IR already renders in the Vault kill-chain note (`GET /api/killchains/score?id=…`). Prefer that for interactive play. This skill is for stills.

## Bulk

`--all` exports every template. Review two stills (one ransomware, one short phishing/zero-day) before treating the batch as done.
