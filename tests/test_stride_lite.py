#!/usr/bin/env python3
"""
STRIDE-Lite Backend Unittests

Unittest suite for the v2.0 backend: STRIDE JSON parsing, the kill-chain
catalog, campaign scores (spine / lanes / HTML export), the vault graph,
and the public application schema. I run this from the repo root so
data/ and tests/fixtures resolve the same way the scripts do.

Notes:
- I wrote this since parse_threat_response silently drops anything that
  does not match the six-category schema — empty STRIDE output is usually
  a JSON shape bug, not LangGraph.
- Vault fixture notes are type:filename (MODEL_NOTE / SCENARIO_NOTE /
  THREAT_NOTE). A note id that walks out of the vault must raise.
- src/python is inserted on sys.path; the production scripts rely on that
  when invoked as python src/python/foo.py.

## Author Information
- **Author**: Nic Cravino
- **Email**: spidernic@me.com
- **LinkedIn**: https://www.linkedin.com/in/nic-cravino
- **Date**: August 2026

## License: Apache License 2.0
"""

from __future__ import annotations

import json
import sys
import unittest
from pathlib import Path

# Constants for repo root and vault fixture notes (type:filename)
ROOT = Path(__file__).resolve().parents[1]
VAULT_FIXTURES = ROOT / "tests" / "fixtures" / "vault"
MODEL_NOTE = "model:security_assessment_APP-778899_fixture.json"
SCENARIO_NOTE = "scenario:Zero-Day_Exploit_New__APP-778899_fixture.json"
THREAT_NOTE = "threat:security_assessment_APP-778899_fixture.json:0"
# src/python onto sys.path (same trick the scripts use when run as a file)
sys.path.insert(0, str(ROOT / "src" / "python"))

from attack_stix import enrich_technique, load_stix_index  # noqa: E402
from campaign_score import compare_scores, compile_all, score_for  # noqa: E402
from score_export import export_score, render_html  # noqa: E402
from killchains import (  # noqa: E402
    build_catalog,
    compare_templates,
    family_tags,
    parse_step,
    slugify,
)
from model import parse_threat_response  # noqa: E402
from utils import (  # noqa: E402
    APPLICATION_FIELDS,
    application_prompt_vars,
    canonical_app_id,
    get_application,
    load_applications,
    load_sample_cves,
    normalize_application,
    resolve_cve_feed_path,
)
from vault_index import (  # noqa: E402
    build_vault,
    normalize_model,
    project_note,
    summarize_scenario,
)


# STRIDE JSON parser — six-category schema, aliases, saved-file keys
class ParseThreatTests(unittest.TestCase):
    # Three well-formed threats per category (parser trims to ≥3 / ≤5)
    def test_exact_schema_is_kept(self):
        payload = {
            cat: [
                {"threat_name": f"{cat}-{i}", "description": "d", "impact": "i", "mitigation": "m"}
                for i in range(3)
            ]
            for cat in (
                "Spoofing",
                "Tampering",
                "Repudiation",
                "Information Disclosure",
                "Denial of Service",
                "Elevation of Privilege",
            )
        }
        salida = parse_threat_response(json.dumps(payload))
        self.assertTrue(all(len(salida[cat]) == 3 for cat in payload))

    # Markdown fence + snake_case alias folded onto Information Disclosure
    def test_aliases_and_fence(self):
        raw = """```json
        {"information_disclosure": [{"name": "Leak", "desc": "x", "control": "DLP"}]}
        ```"""
        salida = parse_threat_response(raw)
        self.assertEqual(salida["Information Disclosure"][0]["threat_name"], "Leak")

    def test_saved_threat_key_shape(self):
        raw = {
            "Spoofing": [{"threat": "Sender spoof", "mitigation": "SPF"}],
            "dread_assessment": [],
        }
        # LLM JSON vs a saved assessment — parse_threat_response is the former; vault normalize is the latter
        model = normalize_model(raw, Path("security_assessment_CMDB1_1.json"))
        self.assertEqual(model["threats"][0]["title"], "Sender spoof")


# Kill-chain catalog, slugs, note lines vs steps, template compare
class KillchainTests(unittest.TestCase):
    # 37 is the shipped template count; bump this if predefined_attack_templates.json grows
    def test_catalog_size(self):
        catalog = build_catalog()
        self.assertEqual(len(catalog["templates"]), 37)
        self.assertGreaterEqual(len(catalog["techniques"]), 50)
        self.assertGreater(len(catalog["ambiguities"]), 0)

    def test_slug_and_family(self):
        self.assertEqual(slugify("Zero-Day Exploit [New]"), "zero-day-exploit-new")
        self.assertIn("ai-saas", family_tags("Indirect Prompt Injection via Vendor AI Ingestion [AI SaaS 2026]"))
        self.assertIn("ai-saas", family_tags("Overprivileged Researcher MCP and Agentic Tool-Chain Abuse [Buy-Side 2026]"))
        self.assertIn("ai-saas", family_tags("Shadow Agentic Research and Coding Agents Outside SDLC [Buy-Side 2026]"))
        self.assertIn("ai-saas", family_tags("MNPI Exfil via Research RAG and Agent Tools [Buy-Side 2026]"))
        self.assertIn("ai-saas", family_tags("Integrity Incident via Poisoned RAG Copilot Output [Buy-Side 2026]"))
        self.assertIn("ransomware", family_tags("LockBit Ransomware Attack"))
        self.assertIn("api", family_tags("[API] Public APIs (External Exposure) API Abuse DDoS Attack"))
        self.assertIn("apt", family_tags("Salt Typhoon Telecom Edge Espionage [New 2025]"))

    # "Note:" lines are annotations, not kill-chain steps
    def test_note_lines_are_not_steps(self):
        step = parse_step("Note: Maps to MITRE ATLAS — LLM Prompt Injection (AML.T0051)", 1)
        self.assertEqual(step["kind"], "note")

    # T1859 is the T1059 typo we catch in id_meta
    def test_typo_flagged(self):
        step = parse_step("Command and Scripting Interpreter (T1859)", 1)
        self.assertEqual(step["id_meta"][0]["suggested_id"], "T1059")
        self.assertEqual(step["id_meta"][0]["id_status"], "typo")

    def test_compare(self):
        result = compare_templates("Zero-Day Exploit [New]", "LockBit Ransomware Attack")
        self.assertGreater(result["a"]["count"], 0)
        self.assertGreater(result["b"]["count"], 0)
        self.assertIn("shared", result)
        self.assertGreaterEqual(result["jaccard"], 0)
        self.assertLessEqual(result["jaccard"], 1)

    # Fail early — unknown template names raise, not a quiet empty compare
    def test_compare_unknown(self):
        with self.assertRaises(FileNotFoundError):
            compare_templates("Zero-Day Exploit [New]", "not-a-real-template")


# Campaign scores: spine/lanes, climax, HTML export, sequence views
class CampaignScoreTests(unittest.TestCase):
    # compile_all: one score per shipped template, six lanes, climax glyph
    def test_all_templates_compile(self):
        scores = compile_all()
        self.assertEqual(len(scores), 37)
        for score in scores:
            self.assertLessEqual(len(score["spine"]), 7)
            self.assertGreaterEqual(len(score["spine"]), 1)
            self.assertTrue(score["phases"])
            self.assertEqual(len(score["lanes"]), 6)
            self.assertTrue(score["climax"])
            roles = {item["id"]: item["role"] for item in score["glyphs"]}
            self.assertEqual(roles.get(score["climax"]), "climax")

    def test_lockbit_climax_is_impact(self):
        score = score_for("LockBit Ransomware Attack")
        climax = next(item for item in score["glyphs"] if item["id"] == score["climax"])
        self.assertEqual(climax["phase"], "impact")
        self.assertTrue(score["inferred"])

    def test_zero_day_has_access_and_execute(self):
        score = score_for("Zero-Day Exploit [New]")
        phases = {item["id"] for item in score["phases"]}
        self.assertIn("access", phases)
        self.assertIn("execute", phases)
        self.assertIn("exfil", phases)
        exfil = next(item for item in score["glyphs"] if item["tech_id"] == "T1048.002")
        self.assertEqual(exfil["phase"], "exfil")
        note = project_note("killchain:zero-day-exploit-new")
        self.assertEqual(note["score"]["slug"], score["slug"])

    def test_unknown_template(self):
        with self.assertRaises(FileNotFoundError):
            score_for("not-a-real-template")

    # Self-contained HTML (inline SVG, no mermaid runtime)
    def test_export_html_is_self_contained(self):
        import tempfile

        score = score_for("Zero-Day Exploit [New]")
        html = render_html(score)
        self.assertIn("<svg", html)
        self.assertIn("T1190", html)
        self.assertIn("data-caption-slot", html)
        self.assertIn("inferred from T-IDs", html)
        self.assertNotIn("mermaid", html.lower())
        with tempfile.TemporaryDirectory() as tmp:
            written = export_score(score, Path(tmp), {"html", "json"})
            names = {path.name for path in written}
            self.assertEqual(names, {"zero-day-exploit-new.html", "zero-day-exploit-new.json"})
            payload = json.loads((Path(tmp) / "zero-day-exploit-new.json").read_text())
            self.assertEqual(payload["climax"], score["climax"])

    # Short campaigns keep sequence+storyboard; long ones collapse storyboard
    def test_sequence_and_storyboard_views(self):
        short = score_for("Predictive Ransomware")
        self.assertTrue(short["views"]["sequence"]["available"])
        self.assertGreaterEqual(len(short["views"]["sequence"]["messages"]), 1)
        self.assertLessEqual(len(short["views"]["sequence"]["actors"]), 5)
        self.assertTrue(short["views"]["storyboard"]["available"])
        self.assertLessEqual(len(short["views"]["storyboard"]["frames"]), 5)
        long = score_for("LockBit Ransomware Attack")
        self.assertTrue(long["views"]["sequence"]["available"])
        self.assertTrue(long["views"]["storyboard"]["collapsed"])
        self.assertLessEqual(len(long["views"]["storyboard"]["frames"]), 5)

    def test_compare_scores_marks_shared(self):
        result = compare_scores("Zero-Day Exploit [New]", "LockBit Ransomware Attack")
        self.assertIn("T1190", result["shared"])
        self.assertEqual(result["a"]["slug"], "zero-day-exploit-new")
        self.assertGreaterEqual(result["jaccard"], 0)
        self.assertLessEqual(result["jaccard"], 1)


# Vault graph from fixtures — notes, traversal reject, empty-model warnings
class VaultTests(unittest.TestCase):
    # Fixture vault must wire model / scenario / killchain / app / threat
    def test_build_vault_connects_sample(self):
        vault = build_vault(output_dir=VAULT_FIXTURES)
        types = {node["type"] for node in vault["nodes"]}
        self.assertIn("model", types)
        self.assertIn("scenario", types)
        self.assertIn("killchain", types)
        self.assertIn("app", types)
        self.assertIn("threat", types)
        rels = {edge["rel"] for edge in vault["edges"]}
        self.assertIn("derived-from", rels)
        self.assertIn("uses-template", rels)
        self.assertIn("has-threat", rels)

    def test_project_notes(self):
        model = project_note(MODEL_NOTE, output_dir=VAULT_FIXTURES)
        self.assertEqual(model["type"], "model")
        self.assertEqual(model["threat_count"], 6)
        scenario = project_note(SCENARIO_NOTE, output_dir=VAULT_FIXTURES)
        self.assertEqual(scenario["template"], "Zero-Day Exploit [New]")
        self.assertTrue(scenario["outline"])
        chain = project_note("killchain:zero-day-exploit-new")
        self.assertEqual(chain["step_count"], 12)
        app = project_note("app:CMDB778899")
        self.assertEqual(app["type"], "app")
        self.assertEqual(app["meta"]["id"], "APP-778899")
        self.assertEqual(project_note("app:APP-778899")["meta"]["id"], "APP-778899")
        tech = project_note("tech:T1190")
        self.assertEqual(tech["type"], "technique")
        control = project_note("control:SL-05")
        self.assertTrue(control["rows"])
        cve = project_note("cve:CVE-2821-28550")
        self.assertTrue(cve["known"])
        unknown = project_note("cve:CVE-2099-0001")
        self.assertFalse(unknown["known"])
        threat = project_note(THREAT_NOTE, output_dir=VAULT_FIXTURES)
        self.assertEqual(threat["type"], "threat")

    # Fail early — note ids must not walk out of the vault
    def test_traversal_rejected(self):
        with self.assertRaises(FileNotFoundError):
            project_note("model:../etc/passwd")

    # Empty STRIDE buckets keep one warning per category (not a silent zero)
    def test_empty_model_keeps_warnings(self):
        empty = {cat: [] for cat in (
            "Spoofing", "Tampering", "Repudiation", "Information Disclosure",
            "Denial of Service", "Elevation of Privilege",
        )}
        empty["system_metadata"] = {"cmdb_id": "CMDB0", "name": "Empty"}
        salida = normalize_model(empty, Path("security_assessment_CMDB0_1.json"))
        self.assertEqual(salida["threat_count"], 0)
        self.assertEqual(len(salida["warnings"]), 6)
        self.assertEqual(salida["name"], "Empty")

    def test_summarize_scenario_parses_strings(self):
        raw = json.loads((VAULT_FIXTURES / "scenarios" / "Zero-Day_Exploit_New__APP-778899_fixture.json").read_text())
        summary = summarize_scenario(raw, Path("x.json"))
        self.assertTrue(summary["source_model_path"])
        self.assertTrue(summary["has_stride"])
        self.assertTrue(summary["has_dread"])
        self.assertEqual(summary["cmdb_id"], "APP-778899")


# Public application schema, CMDB* → APP-* mapping, CVE feed override
class InventoryTests(unittest.TestCase):
    # Inventory is APPLICATION_FIELDS (9 rows in data/applications.json)
    def test_applications_use_public_schema(self):
        apps = load_applications()
        self.assertEqual(len(apps), 9)
        allowed = set(APPLICATION_FIELDS)
        raw = json.loads((ROOT / "data" / "applications.json").read_text())
        for row in raw:
            self.assertTrue(set(row).issubset(allowed))
            self.assertTrue(str(row["id"]).startswith("APP-"))
            self.assertIsInstance(row["internet_facing"], bool)
            self.assertIsInstance(row["customer_data"], bool)
            self.assertIn(row["sourcing"], {"in-house", "COTS", "SAAS", "Hybrid"})
            self.assertRegex(row["availability"], r"^Level [123]$")

    def test_normalize_public_row(self):
        reminted = normalize_application(
            {
                "id": "APP-778899",
                "name": "ACME MAIL TRIAGE AGENT",
                "description": "old description",
                "architecture": "old architecture",
                "business_area": "Operations",
                "confidentiality": "Level 2",
                "integrity": "Level 2",
                "availability": "Level 2",
                "platform": ["Cloud"],
                "internet_facing": True,
                "sourcing": "COTS",
                "customer_data": True,
            }
        )
        self.assertEqual(reminted["id"], "APP-778899")
        self.assertEqual(reminted["availability"], "Level 2")
        self.assertEqual(reminted["confidentiality"], "Level 2")
        self.assertTrue(reminted["internet_facing"])
        self.assertTrue(reminted["customer_data"])
        self.assertEqual(reminted["sourcing"], "COTS")
        self.assertEqual(reminted["platform"], ["Cloud"])
        self.assertEqual(reminted["architecture"], "old architecture")
        self.assertEqual(reminted["business_area"], "Operations")

    # CMDB* keys and values still mint APP-* (old inventory)
    def test_cmdb_id_key_and_value_still_map(self):
        reminted = normalize_application({"cmdb_id": "CMDB778899", "name": "Mail"})
        self.assertEqual(reminted["id"], "APP-778899")
        self.assertEqual(reminted["name"], "Mail")

    def test_unknown_keys_are_ignored(self):
        reminted = normalize_application({"id": "APP-1", "name": "X", "mystery_field": "nope"})
        self.assertEqual(reminted["name"], "X")
        self.assertNotIn("mystery_field", reminted)

    # Prompt vars are all app_* (ChatPromptTemplate substitution stays namespaced)
    def test_prompt_vars_use_public_names(self):
        vars_ = application_prompt_vars({"id": "APP-1", "name": "N", "platform": ["Linux"]})
        self.assertEqual(vars_["app_id"], "APP-1")
        self.assertEqual(vars_["app_name"], "N")
        self.assertEqual(vars_["app_platform"], "Linux")
        self.assertTrue(all(key.startswith("app_") for key in vars_))

    def test_lookup_accepts_legacy_id(self):
        self.assertEqual(canonical_app_id("CMDB778899"), "APP-778899")
        self.assertEqual(get_application("CMDB778899")["id"], "APP-778899")
        self.assertEqual(get_application("APP-778899")["name"], "ACME MAIL TRIAGE AGENT")

    # Shipped sample_cves.json; demo_critical_vulnerability.json and cmdb.json must stay gone
    def test_sample_cves_exist_and_old_file_is_gone(self):
        cves = load_sample_cves()
        self.assertTrue(any(item.get("id") == "CVE-2821-28550" for item in cves))
        self.assertTrue((ROOT / "data" / "sample_cves.json").exists())
        self.assertFalse((ROOT / "data" / "demo_critical_vulnerability.json").exists())
        self.assertFalse((ROOT / "data" / "cmdb.json").exists())

    # CVE feed path override (temp file, not the shipped sample_cves.json)
    def test_user_cve_feed_override(self):
        import tempfile

        payload = [{"id": "CVE-1999-0001", "description": "fixture", "score": 9.0}]
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "feed.json"
            path.write_text(json.dumps(payload), encoding="utf-8")
            rows = load_sample_cves(str(path))
            self.assertEqual(rows[0]["id"], "CVE-1999-0001")
            self.assertEqual(resolve_cve_feed_path(str(path)).resolve(), path.resolve())

    # Mini STIX fixture; clear the process cache so later lookups don't inherit it
    def test_local_stix_enriches_technique(self):
        import attack_stix

        fixture = ROOT / "tests" / "fixtures" / "mini_attack_stix.json"
        index = load_stix_index(str(fixture), force=True)
        self.assertIn("T1190", index)
        self.assertEqual(index["T1566"]["name"], "Phishing")
        tech = enrich_technique({"id": "T1190", "name": "placeholder"}, index)
        self.assertEqual(tech["stix_name"], "Exploit Public-Facing Application")
        self.assertIn("initial access", tech["stix_tactics"])
        attack_stix._CACHE = None
        attack_stix._CACHE_PATH = None


if __name__ == "__main__":
    unittest.main(verbosity=2)
