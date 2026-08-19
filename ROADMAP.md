# ROADMAP

Personal research project. Not a product commitment. Dates are not promises.

## v2.0 — shipped in this tree

- STRIDE → DREAD LangGraph workflow with parseable JSON (field aliases, all six categories).
- Scenario workflow (CVE / CTI / kill chain) that no longer crashes on `{braces}` in reports.
- Local GUI (command deck): generate, inspect jobs, read artifacts.
- Vault: models, scenarios, templates, and apps as notes; local graph; compare; quality flags; ⌘P.
- oMLX / OpenAI-compatible providers. Metrics off port 8000.
- Tests: `tests.test_stride_lite`, `tests.test_gui_http`, optional Chrome E2E.
- Demo control catalog uses project-native `SL-xx` IDs (not industry catalog IDs).
- Application inventory uses generic fields (`availability`, `internet_facing`, `customer_data`, `sourcing`) and `APP-*` IDs.
- Vault Campaign Score: phase × lane kill-chain grid with a playable spine. Sequence and storyboard views of the spine. Compare two scores (shared T-IDs). Deterministic HTML/SVG export via `score_export.py`.
- User CVE feed path (`--cve_feed` / `CVE_FEED`). Optional local ATT&CK STIX enrich. Scenario outline jumps to headings; markdown tables use a header row.

## Next (still Lite)

- Real scenario QA (the three QA nodes are rubber stamps).
- Persist `source_model_path` / `selected_techniques` on every new scenario (already written; keep it).

## Not in this repository

Contingency Atlas (ingest, signals, judged scenarios, radar) is a **separate** system. It is not public and is not shipped here. Visual kinship only.

Do not open issues asking for Atlas features against this repo.

## Publication notes

This repository’s git history starts at v2.0. Demo inventory is ACME (`APP-*`); controls are project-native `SL-xx`.

Keep `.env`, `output/`, and `logs/` untracked (gitignored).
