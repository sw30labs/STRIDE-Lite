#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Script: Cyber Threat Scenario and CVE Report Generator
Author: Nic Cravino
Date: 12 May 2025
UPDate: August 19, 2026 - CVE feed path, brace-escape for ChatPromptTemplate
License: Apache 2.0
Description: CVE then CTI then a threat-scenario report on top of a model.py JSON. Vulnerability data is CVE_FEED or data/sample_cves.json (db_path is an unused SQLite leftover). YAML prompts/templates; curly braces in JSON are doubled before ChatPromptTemplate.format.
"""
import argparse
import json
import logging
import os
import yaml
import pandas as pd
from typing import Dict, Any, Optional
from datetime import datetime
from dotenv import load_dotenv
from langchain_core.messages import HumanMessage, SystemMessage
from langgraph.graph import StateGraph, END
from pydantic import BaseModel
from langchain_community.callbacks import get_openai_callback
from utils import (
    Provider,
    application_prompt_vars,
    get_application,
    get_llm,
    load_sample_cves,
    normalize_application,
    parse_provider,
    resolve_provider_from_env,
)

# Setup paths and directories (repo root is two parents above src/python)
SRC_DIR = os.path.dirname(os.path.abspath(__file__))
BASE_DIR = os.path.dirname(os.path.dirname(SRC_DIR))
ATTACK_TEMPLATES_FILE = 'data/predefined_attack_templates.json'
SAMPLE_CVE_FILE = 'data/sample_cves.json'
CONTROLS_TAXONOMY_FILE = 'data/control_taxonomy.csv'
SCENARIO_OUTPUT_DIR = os.path.join(BASE_DIR, "output/scenarios")
CVE_LIMIT = 1  # leftover cap; the feed loader does not apply it here

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s [%(levelname)s] %(message)s')
load_dotenv(override=True)

# Function to invoke an LLM and log tokens (callback first; usage_metadata is the MLX fallback)
def invoke_with_tracking(llm, messages):
    """Invoke an LLM and log token usage (callback first; usage_metadata is the MLX fallback)."""
    try:
        with get_openai_callback() as cb:
            response = llm.invoke(messages)
        usage = getattr(response, "usage_metadata", None)
        if cb.total_tokens:
            logging.info(
                f"Prompt Tokens: {cb.prompt_tokens}, Completion Tokens: {cb.completion_tokens}, Total Tokens: {cb.total_tokens}"
            )
        elif usage:
            # Fallback when the OpenAI callback returns zero (MLX / local endpoints)
            logging.info(
                f"Prompt Tokens: {usage.get('input_tokens')}, Completion Tokens: {usage.get('output_tokens')}, Total Tokens: {usage.get('total_tokens')}"
            )
        return response
    except Exception:
        raise

# Load YAML files (agent system messages + sample report templates)
with open(os.path.join(BASE_DIR, 'src/yaml/scenario_prompts.yml'), 'r', encoding='utf-8') as file:
    prompts = yaml.safe_load(file)
    scenario_menu_gen_system_message_cve_agent = prompts['scenario_prompts']['scenario_menu_gen_system_message_cve_agent']
    scenario_menu_gen_system_message_cti_agent = prompts['scenario_prompts']['scenario_menu_gen_system_message_cti_agent']
    scenario_menu_gen_system_message_reporting_agent_v2 = prompts['scenario_prompts']['scenario_menu_gen_system_message_reporting_agent_v2']

with open(os.path.join(BASE_DIR, 'src/yaml/scenario_templates.yml'), 'r', encoding='utf-8') as file:
    scenario_templates = yaml.safe_load(file)
    cve_report_template = scenario_templates.get('cve_report_template', 'Default CVE Report Template')
    sample_risk_report = scenario_templates['risk_report']['content']
    sample_cti_external_report = scenario_templates['cti_report']['content']
    sample_threat_scenario = scenario_templates['threat_scenario']['content']

# --- State Management --- (LangGraph merges the dict each node returns)
class WorkflowState(BaseModel):
    provider: Provider
    cmdb_info: Optional[Dict] = None
    selected_template: Optional[str] = None
    selected_techniques: Optional[list] = None
    stride_data: Optional[str] = None
    dread_data: Optional[str] = None
    controls_data: Optional[str] = None
    cve_report: Optional[str] = None
    cve_qa_feedback: Optional[Dict] = None
    cve_approved: bool = False
    cti_report: Optional[str] = None
    cti_qa_feedback: Optional[Dict] = None
    cti_approved: bool = False
    threat_scenario_report: Optional[str] = None
    threat_scenario_qa_feedback: Optional[Dict] = None
    threat_scenario_approved: bool = False
    final_output_path: Optional[str] = None
    error: Optional[str] = None
    complete: bool = False
    cvss_score: str = "9"
    cve_iterations: int = 0
    cti_iterations: int = 0
    threat_scenario_iterations: int = 0
    max_iterations: int = 3  # unused here; the qa_* nodes always approve
    json_file: str
    attack_template: Optional[str] = None
    db_path: str = "cve_database.db"  # unused SQLite leftover; prefer cve_feed
    cve_feed: Optional[str] = None

# Function to relativize a path against the repo root (for source_model_path in the JSON)
def _rel_workspace_path(path: str) -> str:
    try:
        return os.path.relpath(os.path.abspath(path), BASE_DIR)
    except Exception:
        return path  # Fallback if the path cannot be made relative


# Function to load the demo CVE list (JSON feed, not SQLite)
def load_demo_vulnerabilities(feed: str | None = None) -> list:
    return load_sample_cves(feed)

# Function to load MITRE techniques for a named attack template
def load_attack_techniques(attack_template: str) -> list:
    file_path = os.path.join(BASE_DIR, ATTACK_TEMPLATES_FILE)
    try:
        with open(file_path, 'r', encoding='utf-8') as file:
            attack_templates = json.load(file)
        return attack_templates.get(attack_template, [])
    except Exception as e:
        logging.error(f"Failed to load attack templates from {file_path}: {str(e)}")
        return []  # Fallback if the templates file is missing

# Function to load control_taxonomy.csv (ID as key, title+description as value)
def load_controls_taxonomy() -> dict:
    file_path = os.path.join(BASE_DIR, CONTROLS_TAXONOMY_FILE)
    try:
        controls_df = pd.read_csv(file_path, encoding='utf-8-sig')
        # ID → "ID - Title: Description" so the scenario prompt can cite controls by ID
        controls_dict = {
            row['ID']: f"{row['ID']} - {row['Title']}: {row['Description']}"
            for _, row in controls_df.iterrows()
        }
        logging.info(f"Loaded {len(controls_dict)} controls from {file_path}")
        return controls_dict
    except Exception as e:
        logging.error(f"Failed to load controls taxonomy from {file_path}: {str(e)}")
        return {}

# Function to pull STRIDE/DREAD out of the model.py JSON and pick the attack template
def select_cmdb_and_template(state: WorkflowState) -> Dict[str, Any]:
    logging.info(f"State in select_cmdb_and_template: {state.model_dump()}")
    try:
        with open(state.json_file, 'r') as f:
            data = json.load(f)
            if "system_metadata" not in data:
                return {"error": "JSON file missing 'system_metadata' section"}
    except Exception as e:
        return {"error": f"Failed to load JSON file: {str(e)}"}

    system_metadata = data.get("system_metadata", {})
    # Six STRIDE keys as stored in the threat-model JSON
    stride_threats = {key: data.get(key, []) for key in ["Tampering", "Repudiation", "Elevation of Privilege", "Spoofing", "Denial of Service", "Information Disclosure"]}
    dread_assessment = data.get("dread_assessment", [])
    
    cmdb_info = normalize_application(system_metadata)
    if not cmdb_info.get("name") or not cmdb_info.get("description"):
        # Fallback if the JSON metadata is thin — fill from applications.json
        inventory = get_application(cmdb_info.get("id") or system_metadata.get("cmdb_id") or "")
        if inventory:
            merged = {**inventory, **{k: v for k, v in cmdb_info.items() if v not in (None, "", [])}}
            cmdb_info = normalize_application(merged)
    # Load controls as a dictionary and convert to a string
    controls_dict = load_controls_taxonomy()
    controls_str = "\n".join([f"{k}: {v}" for k, v in controls_dict.items()])
    return {
        "cmdb_info": cmdb_info,
        "selected_template": state.attack_template or cve_report_template,
        "selected_techniques": load_attack_techniques(state.attack_template) if state.attack_template else [],
        "stride_data": json.dumps(stride_threats, indent=2),
        "dread_data": json.dumps(dread_assessment, indent=2),
        "controls_data": controls_str # Store as string
    }

# Function to generate the CVE report (feed JSON is brace-escaped for .format)
def generate_cve_report(state: WorkflowState) -> Dict[str, Any]:
    try:
        # leagrego is the demo CVE list; db_path is a leftover alias for the feed path
        leagrego = load_demo_vulnerabilities(getattr(state, "cve_feed", None) or getattr(state, "db_path", None))
        cve_json = json.dumps(leagrego)
        # Double braces so ChatPromptTemplate.format does not treat CVE JSON as fields
        cve_json_escaped = cve_json.replace("{", "{{").replace("}", "}}")
        logging.info(cve_json_escaped)
        logging.info("CVE JSON validated successfully")

        prompt_vars = application_prompt_vars(state.cmdb_info)
        system_message_template = scenario_menu_gen_system_message_cve_agent.replace("- {cveinfo}", "```json\n{cveinfo}\n```")
        system_message = system_message_template.format(
            cvss_score=state.cvss_score,
            selected_template=state.selected_template,
            app_platform=prompt_vars["app_platform"],
            cveinfo=cve_json_escaped
        )
        messages = [
            SystemMessage(content=system_message),
            HumanMessage(content="Generate the CVE report following the specified format."),
        ]
        llm = get_llm(state.provider)
        response = invoke_with_tracking(llm, messages)
        # Logging.debug(f"Full CVE list: {json.dumps(cve_list, indent=2)}")
        return {"cve_report": response.content, "cve_iterations": state.cve_iterations + 1}
    except Exception as e:
        logging.error(f"Error in generate_cve_report: {type(e).__name__}: {str(e)}", exc_info=True)
        return {"error": f"{type(e).__name__}: {str(e)}"}

# QA node for the CVE report — rubber-stamp (always approved)
# TODO(nic): real LLM QA before relying on this beyond demos
def qa_cve_report(state: WorkflowState) -> Dict[str, Any]:
    return {"cve_qa_feedback": {"approved": True, "feedback": "Approved"}, "cve_approved": True}

# Function to generate the CTI report from the approved CVE output
def generate_cti_report(state: WorkflowState) -> Dict[str, Any]:
    try:
        if not state.cve_approved:
            return {"error": "CVE report not approved yet"}
        # Brace-escape STRIDE/DREAD JSON and the sample reports so .format does not crash
        stride_escaped = state.stride_data.replace('{', '{{').replace('}', '}}') if state.stride_data else ""
        dread_escaped = state.dread_data.replace('{', '{{').replace('}', '}}') if state.dread_data else ""
        risk_report_escaped = sample_risk_report.replace('{', '{{').replace('}', '}}')
        cti_external_escaped = sample_cti_external_report.replace('{', '{{').replace('}', '}}')
        system_message = scenario_menu_gen_system_message_cti_agent.format(
            sample_risk_report=risk_report_escaped,
            sample_cti_external_report=cti_external_escaped,
            selected_template=state.selected_template,
            stride=stride_escaped,
            dread=dread_escaped
        )
        messages = [
            SystemMessage(content=system_message),
            HumanMessage(content=f"Generate the CTI report using the CVE report below: \n\n{state.cve_report}"),
        ]
        llm = get_llm(state.provider)
        response = invoke_with_tracking(llm, messages)
        return {"cti_report": response.content, "cti_iterations": state.cti_iterations + 1}
    except Exception as e:
        logging.error(f"Error in generate_cti_report: {type(e).__name__}: {str(e)}", exc_info=True)
        return {"error": f"{type(e).__name__}: {str(e)}"}

# QA node for the CTI report — rubber-stamp (always approved)
def qa_cti_report(state: WorkflowState) -> Dict[str, Any]:
    return {"cti_qa_feedback": {"approved": True, "feedback": "Approved"}, "cti_approved": True}

# Function to generate the threat-scenario report (CVE + CTI + controls taxonomy)
def generate_threat_scenario_report(state: WorkflowState) -> Dict[str, Any]:
    try:
        if not state.cti_approved:
            return {"error": "CTI report not approved yet"}

        stride_escaped = state.stride_data.replace('{', '{{').replace('}', '}}') if state.stride_data else ""
        dread_escaped = state.dread_data.replace('{', '{{').replace('}', '}}') if state.dread_data else ""
        # Use controls_data as a string directly (already formatted in select_cmdb_and_template)
        controls_escaped = state.controls_data.replace('{', '{{').replace('}', '}}') if state.controls_data else ""
        risk_report_escaped = sample_risk_report.replace('{', '{{').replace('}', '}}')
        threat_scenario_template_escaped = sample_threat_scenario.replace('{', '{{').replace('}', '}}')

        prompt_vars = application_prompt_vars(state.cmdb_info)
        # selected_techniques2 is the slot name in the YAML prompt
        system_message = scenario_menu_gen_system_message_reporting_agent_v2.format(
            selected_techniques2='\n'.join(state.selected_techniques) if state.selected_techniques else "No techniques provided",
            selected_template=state.selected_template,
            sample_threat_scenario=threat_scenario_template_escaped,
            sample_scenario_list="",
            cvss_score=state.cvss_score,
            sample_risk_report=risk_report_escaped,
            controls_string=controls_escaped,
            stride=stride_escaped,
            dread=dread_escaped,
            **prompt_vars,
        )

        messages = [
            SystemMessage(
                content=system_message
                + "\nFor the 'Control Failures' section, select specific control failures from the provided controls_string by their IDs (e.g., SL-05, SL-12) and include their full descriptions exactly as provided in the taxonomy without summarization."
            ),
            HumanMessage(
                content=(
                    "Generate the Cyber Threat Scenario report using the following inputs:\n\n"
                    f"CVE Report:\n{state.cve_report}\n\nCTI Report:\n{state.cti_report}"
                )
            ),
        ]
        llm = get_llm(state.provider)
        response = invoke_with_tracking(llm, messages)
        return {"threat_scenario_report": response.content, "threat_scenario_iterations": state.threat_scenario_iterations + 1}
    except Exception as e:
        logging.error(f"Error in generate_threat_scenario_report: {type(e).__name__}: {str(e)}", exc_info=True)
        return {"error": f"{type(e).__name__}: {str(e)}"}


# QA node for the threat-scenario report — rubber-stamp (always approved)
def qa_threat_scenario_report(state: WorkflowState) -> Dict[str, Any]:
    return {"threat_scenario_qa_feedback": {"approved": True, "feedback": "Approved"}, "threat_scenario_approved": True}


# Function to write the three reports plus metadata under output/scenarios/
def save_reports_to_json(state: WorkflowState) -> Dict[str, Any]:
    try:
        if not state.threat_scenario_approved:
            return {"error": "Threat Scenario report not approved yet"}
        now = datetime.now()
        fecha = now.strftime("%Y%m%d")
        current_datetime = now.strftime("%d %B %Y, %H:%M:%S")
        # Filename slug from the template name (spaces, brackets, commas → _)
        title_threat_scenario = state.attack_template.replace(' ', '_').replace(',', '_').replace('(', '_').replace(')', '_').replace('[', '_').replace(']', '_').replace('__', '_')
        app = state.cmdb_info or {}
        file_identifier = f"{title_threat_scenario}_{app.get('id') or 'APP'}_{fecha}"
        json_file_path = os.path.join(SCENARIO_OUTPUT_DIR, f"{file_identifier}.json")
        os.makedirs(SCENARIO_OUTPUT_DIR, exist_ok=True)
        salida = {
            "Attack_Template": state.attack_template,
            "titleThreatScenario": title_threat_scenario,
            "app_id": app.get("id"),
            "app_name": app.get("name"),
            "description": app.get("description"),
            "architecture": app.get("architecture"),
            "business_area": app.get("business_area"),
            "sourcing": app.get("sourcing"),
            "internet_facing": app.get("internet_facing"),
            "confidentiality": app.get("confidentiality"),
            "integrity": app.get("integrity"),
            "availability": app.get("availability"),
            "customer_data": app.get("customer_data"),
            "platform": app.get("platform"),
            "CVSS_Tshld": state.cvss_score,
            "Threat_Report_Date": current_datetime,
            "CVE_Report_Date": current_datetime,
            "CTI_Report_Date": current_datetime,
            "STRIDE_Threat_Model_Report": state.stride_data,
            "DREAD_Assessment_Report": state.dread_data,
            "Threat_Report": state.threat_scenario_report,
            "CTI_Report": state.cti_report,
            "CVE_Report": state.cve_report,
            "Provider": state.provider.value,
            "Complete": True,
            "source_model_path": _rel_workspace_path(state.json_file),
            "selected_techniques": state.selected_techniques or [],
            "platforms": app.get("platform") or [],
        }
        with open(json_file_path, 'w') as f:
            json.dump(salida, f, indent=4)
        logging.info(f"Reports saved to {json_file_path}")
        return {"final_output_path": json_file_path, "complete": True}
    except Exception as e:
        logging.error(f"Error in save_reports_to_json: {type(e).__name__}: {str(e)}", exc_info=True)
        return {"error": f"{type(e).__name__}: {str(e)}"}


# Function to gate the next node (end if state.error else continue)
def check_error(state: WorkflowState) -> str:
    return "end" if state.error else "continue"


# Set up the LangGraph workflow (linear CVE → CTI → scenario; each step gated by check_error)
workflow = StateGraph(WorkflowState)
workflow.add_node("select_cmdb_and_template", select_cmdb_and_template)
workflow.add_node("generate_cve_report", generate_cve_report)
workflow.add_node("qa_cve_report", qa_cve_report)
workflow.add_node("generate_cti_report", generate_cti_report)
workflow.add_node("qa_cti_report", qa_cti_report)
workflow.add_node("generate_threat_scenario_report", generate_threat_scenario_report)
workflow.add_node("qa_threat_scenario_report", qa_threat_scenario_report)
workflow.add_node("save_reports_to_json", save_reports_to_json)

workflow.set_entry_point("select_cmdb_and_template")
workflow.add_conditional_edges("select_cmdb_and_template", check_error, {"continue": "generate_cve_report", "end": END})
workflow.add_conditional_edges("generate_cve_report", check_error, {"continue": "qa_cve_report", "end": END})
workflow.add_conditional_edges("qa_cve_report", check_error, {"continue": "generate_cti_report", "end": END})
workflow.add_conditional_edges("generate_cti_report", check_error, {"continue": "qa_cti_report", "end": END})
workflow.add_conditional_edges("qa_cti_report", check_error, {"continue": "generate_threat_scenario_report", "end": END})
workflow.add_conditional_edges("generate_threat_scenario_report", check_error, {"continue": "qa_threat_scenario_report", "end": END})
workflow.add_conditional_edges("qa_threat_scenario_report", check_error, {"continue": "save_reports_to_json", "end": END})
workflow.add_edge("save_reports_to_json", END)

app = workflow.compile()


# Function to run the scenario pipeline from the CLI
def main():
    parser = argparse.ArgumentParser(description="Generate CVE, CTI, and Threat Scenario reports using OpenAI or local oMLX")
    parser.add_argument(
        '--provider',
        type=parse_provider,
        default=resolve_provider_from_env(Provider.OPENAI),
        metavar='{openai,mlx}',
        help='LLM provider to use; "omlx" is accepted as an alias for "mlx"',
    )
    parser.add_argument('--json_file', type=str, required=True, help='Path to the JSON file containing system data')
    parser.add_argument('--attack_template', type=str, default=None, help='Path to the MITRE ATT&CK template file')
    parser.add_argument('--db_path', type=str, default='cve_database.db', help='Unused SQLite placeholder; prefer --cve_feed')
    parser.add_argument('--cve_feed', type=str, default=None, help='JSON CVE feed path (list of {id, ...}). Defaults to CVE_FEED or data/sample_cves.json')
    parser.add_argument('--min_cvss', type=float, default=8.5, help='Minimum CVSS score for CVEs')
    args = parser.parse_args()

    logging.info(f"Selected provider: {args.provider.value}")

    initial_state = WorkflowState(
        provider=args.provider,
        json_file=args.json_file,
        attack_template=args.attack_template,
        db_path=args.db_path,
        cve_feed=args.cve_feed,
        cvss_score=str(args.min_cvss)
    )
    print(f"Initial state: {initial_state.model_dump()}")

    with get_openai_callback() as cb:
        final_state = app.invoke(initial_state)
    if cb.total_tokens:
        logging.info(
            f"Workflow Tokens - Prompt: {cb.prompt_tokens}, Completion: {cb.completion_tokens}, Total: {cb.total_tokens}"
        )

    if final_state.get('error'):
        logging.error(f"Workflow failed: {final_state['error']}")
    elif final_state.get('complete'):
        logging.info(f"Workflow completed successfully. Output saved to: {final_state.get('final_output_path')}")
    else:
        logging.info(f"CVE Report:\n" + (final_state.get('cve_report') or "No CVE report generated"))
        logging.info(f"CTI Report:\n" + (final_state.get('cti_report') or "No CTI report generated"))
        logging.info(f"Threat Scenario Report:\n" + (final_state.get('threat_scenario_report') or "No Threat Scenario report generated"))
        logging.warning("Workflow ended without completion or error.")


if __name__ == "__main__":
    main()
