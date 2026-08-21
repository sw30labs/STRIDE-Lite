#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Script: Threat Model and Workflow Generator
Author: Nic Cravino
Date: 12 May 2025
UPDate: August 21, 2026 - v2.1 public tree, metrics off 8000
License: Apache License 2.0
Description: STRIDE then DREAD for one APP-* id; LangGraph loops generate→QA until pass or 3 iterations.
"""
import os
import re
import json
import yaml
import asyncio
import logging
from datetime import datetime
from typing import Dict, Iterable, Optional, Any, Tuple
from argparse import ArgumentParser
from pydantic import BaseModel
from prometheus_client import Counter, start_http_server
from langsmith.run_helpers import traceable
from langchain_core.prompts import ChatPromptTemplate
from langchain_core.messages import HumanMessage
from langgraph.graph import StateGraph, END
from langchain_community.callbacks import get_openai_callback
from dotenv import load_dotenv
from utils import (
    Provider,
    application_context_block,
    get_application,
    get_llm,
    parse_provider,
    resolve_provider_from_env,
)

# Setup paths and directories (repo root is two parents above src/python)
SRC_DIR = os.path.dirname(os.path.abspath(__file__))
BASE_DIR = os.path.dirname(os.path.dirname(SRC_DIR))

# --- State Management --- (LangGraph merges the dict each node returns)
class WorkflowState(BaseModel):
    cmdb_id: str
    system_desc: str
    provider: Provider
    stride_data: Optional[Dict] = None
    dread_data: Optional[Dict] = None
    error: Optional[str] = None
    complete: bool = False
    saved_path: Optional[str] = None
    cmdb_info: Optional[Dict] = None
    stride_qa_feedback: Optional[Dict] = None
    dread_qa_feedback: Optional[Dict] = None
    final_qa_feedback: Optional[Dict] = None
    stride_iterations: int = 0
    dread_iterations: int = 0
    stride_qa_passed: bool = False
    dread_qa_passed: bool = False
    final_threat_model: Optional[Dict] = None # complete model after final_qa


load_dotenv()


# --- Monitoring Setup --- (Prometheus counters; HTTP bind is later, never on 8000)
REQUESTS = Counter('threat_requests', 'API requests', ['service'])
ERRORS = Counter('threat_errors', 'API errors', ['error_type'])


# Function to invoke an LLM and log tokens (callback first; usage_metadata is the MLX fallback)
def invoke_with_tracking(llm, messages):
    """Invoke an LLM and log token usage (callback first; usage_metadata is the MLX fallback)."""
    try:
        with get_openai_callback() as cb:
            response = llm.invoke(messages)
        usage = getattr(response, "usage_metadata", None)
        if cb.total_tokens:
            logging.info(
                f"Prompt Tokens: {cb.prompt_tokens}, "
                f"Completion Tokens: {cb.completion_tokens}, "
                f"Total Tokens: {cb.total_tokens}"
            )
        elif usage:
            # Fallback when the OpenAI callback returns zero (MLX / local endpoints)
            logging.info(
                f"Prompt Tokens: {usage.get('input_tokens')}, "
                f"Completion Tokens: {usage.get('output_tokens')}, "
                f"Total Tokens: {usage.get('total_tokens')}"
            )
        return response
    except Exception:
        raise


# Function to invoke a LangChain agent and log the underlying LLM tokens
def agent_invoke_with_tracking(agent, data):
    """Invoke an agent and log token usage for the underlying LLM calls."""
    with get_openai_callback() as cb:
        result = agent.invoke(data)
    if cb.total_tokens:
        logging.info(
            f"Prompt Tokens: {cb.prompt_tokens}, "
            f"Completion Tokens: {cb.completion_tokens}, "
            f"Total Tokens: {cb.total_tokens}"
        )
    return result


# --- Core Implementation --- (trips after 3 LLM failures in this process)
class CircuitBreaker:
    def __init__(self, max_failures=3):
        self.failures = 0
        self.max_failures = max_failures

    def check(self):
        # Fail early — further calls would just pile on the same error
        if self.failures >= self.max_failures:
            raise RuntimeError("API circuit breaker tripped")

# Process-local breaker; .failures is incremented on STRIDE/DREAD LLM errors
threat_cb = CircuitBreaker()

# --- Agent Tools -=- (callable classes the LangGraph nodes wrap)
class GenerateSTRIDEThreats:
    def __call__(self, system_desc: str, provider: Provider, cmdb_info: Optional[Dict] = None, qa_feedback: Optional[Dict] = None) -> Dict:
        try:
            threat_cb.check()
            llm = get_llm(provider)
            prompts = load_prompts()
            stride_template = prompts['stride_prompt']
            enhanced_desc = system_desc
            if cmdb_info:
                context = application_context_block(cmdb_info)
                if context:
                    enhanced_desc += "\n\nSystem Context:\n" + context
            if qa_feedback:
                enhanced_desc += "\n\nQA Feedback:\n" + json.dumps(qa_feedback, indent=2)
            # Concatenate rather than ChatPromptTemplate.format — JSON braces in the desc would blow up str.format
            formatted_prompt = stride_template + "\n\n" + enhanced_desc
            stride_response = invoke_with_tracking(
                llm, [HumanMessage(content=formatted_prompt)]
            ).content
            return parse_threat_response(stride_response)
        except Exception as e:
            threat_cb.failures += 1
            logging.error(f"STRIDE generation error: {str(e)}")
            raise

# DREAD scorer (flattens STRIDE into (name, category) pairs for the prompt)
class GenerateDREADAssessment:
    def __call__(self, stride_data: Dict, provider: Provider, cmdb_info: Optional[Dict] = None, qa_feedback: Optional[Dict] = None) -> Dict:
        try:
            threat_cb.check()
            llm = get_llm(provider)
            prompts = load_prompts()
            dread_template = prompts['dread_prompt']
            all_threats = [(t['threat_name'], cat) for cat, threats in stride_data.items() if isinstance(threats, list) for t in threats]
            # .replace, not .format — the template and the JSON both contain braces
            formatted_prompt = dread_template.replace("${threats}", json.dumps(all_threats, indent=2))
            if cmdb_info:
                context = application_context_block(cmdb_info)
                if context:
                    formatted_prompt += "\n\nSystem Context:\n" + context
            if qa_feedback:
                formatted_prompt += "\n\nQA Feedback:\n" + json.dumps(qa_feedback, indent=2)
            dread_response = invoke_with_tracking(
                llm, [HumanMessage(content=formatted_prompt)]
            ).content
            dread_data = parse_threat_response(dread_response)
            # Fallback if the model skipped the Risk Assessment key
            return dread_data if dread_data.get('Risk Assessment') else {"Risk Assessment": []}
        except Exception as e:
            threat_cb.failures += 1
            logging.error(f"DREAD assessment error: {str(e)}")
            raise

# Function to QA the STRIDE JSON (pass/score/improvement_needed; feeds the next generate loop)
class QAStrideModel:
    def __call__(self, stride_data: Dict, provider: Provider, cmdb_info: Optional[Dict] = None) -> Dict:
        try:
            llm = get_llm(provider)
            prompts = load_prompts()
            qa_prompt = prompts["qa_stride"]["human_template"]
            formatted_prompt = qa_prompt.replace("{{stride_output}}", json.dumps(stride_data, indent=2))
            qa_response = invoke_with_tracking(
                llm, [HumanMessage(content=formatted_prompt)]
            ).content
            # First JSON object in the reply; full-string load if the regex misses
            json_match = re.search(r'\{.*\}', qa_response, re.DOTALL)
            return json.loads(json_match.group(0)) if json_match else json.loads(qa_response)
        except Exception as e:
            logging.error(f"STRIDE QA failed: {str(e)}")
            return {"pass": False, "error": str(e)}

class QADreadAssessment:
    def __call__(self, dread_data: Dict, stride_data: Dict, provider: Provider, cmdb_info: Optional[Dict] = None) -> Dict:
        try:
            llm = get_llm(provider)
            prompts = load_prompts()
            qa_prompt = prompts["qa_dread"]["human_template"]
            formatted_prompt = qa_prompt.replace("{{dread_output}}", json.dumps(dread_data, indent=2))
            qa_response = invoke_with_tracking(
                llm, [HumanMessage(content=formatted_prompt)]
            ).content
            json_match = re.search(r'\{.*\}', qa_response, re.DOTALL)
            return json.loads(json_match.group(0)) if json_match else json.loads(qa_response)
        except Exception as e:
            logging.error(f"DREAD QA failed: {str(e)}")
            return {"pass": False, "error": str(e)}

# Final pass over the merged model (on LLM failure I return the model as-is so save still runs)
class FinalQA:
    def __call__(self, complete_model: Dict, provider: Provider) -> Dict:
        try:
            llm = get_llm(provider)
            prompts = load_prompts()
            qa_prompt = prompts["qa_final"]["human_template"]
            formatted_prompt = qa_prompt.replace("{{threat_model}}", json.dumps(complete_model, indent=2))
            qa_response = invoke_with_tracking(
                llm, [HumanMessage(content=formatted_prompt)]
            ).content
            json_match = re.search(r'\{.*\}', qa_response, re.DOTALL)
            return json.loads(json_match.group(0)) if json_match else json.loads(qa_response)
        except Exception as e:
            logging.error(f"Final QA failed: {str(e)}")
            return complete_model

# Function to write the assessment JSON under output/stride/
class SaveThreatModel:
    def __call__(self, data: Dict, cmdb_id: str) -> str:
        try:
            output_dir = os.path.join(BASE_DIR, "output/stride")
            os.makedirs(output_dir, exist_ok=True)
            filename = f"{output_dir}/security_assessment_{cmdb_id}_{datetime.now().strftime('%Y%m%d%H%M%S')}.json"
            if 'system_metadata' not in data or not data['system_metadata']:
                data['system_metadata'] = {'cmdb_id': cmdb_id}
            with open(filename, "w") as f:
                json.dump(data, f, indent=2)
            return filename
        except Exception as e:
            logging.error(f"Failed to save threat model: {str(e)}")
            raise


# Function to load stride_prompts.yml (keys: stride.human_template, dread.format_template, qa_*)
def load_prompts() -> Dict:
    try:
        with open(os.path.join(BASE_DIR, "src/yaml/stride_prompts.yml"), 'r') as f:
            prompts = yaml.safe_load(f)
        return {
            'stride_prompt': prompts['stride']['human_template'],
            'dread_prompt': prompts['dread']['format_template'],
            'qa_stride': prompts.get('qa_stride', {}),
            'qa_dread': prompts.get('qa_dread', {}),
            'qa_final': prompts.get('qa_final', {})
        }
    except Exception as e:
        logging.error(f"Failed to load prompts: {str(e)}")
        raise

# Canonical STRIDE labels the parser will emit (aliases map sloppy LLM keys onto these)
_STRIDE_CATEGORIES: Tuple[str, ...] = (
    "Spoofing",
    "Tampering",
    "Repudiation",
    "Information Disclosure",
    "Denial of Service",
    "Elevation of Privilege",
)

# LLM key aliases (underscores, "dos", "eop", "privilege escalation")
_CATEGORY_ALIASES = {
    "spoofing": "Spoofing",
    "tampering": "Tampering",
    "repudiation": "Repudiation",
    "information disclosure": "Information Disclosure",
    "information_disclosure": "Information Disclosure",
    "denial of service": "Denial of Service",
    "denial_of_service": "Denial of Service",
    "dos": "Denial of Service",
    "elevation of privilege": "Elevation of Privilege",
    "elevation_of_privilege": "Elevation of Privilege",
    "privilege escalation": "Elevation of Privilege",
    "eop": "Elevation of Privilege",
}

_THREAT_NAME_KEYS = ("threat_name", "name", "threat", "title", "scenario")
_DESC_KEYS = ("description", "desc", "details", "summary")
_IMPACT_KEYS = ("impact", "business_impact", "effect")
_MITIGATION_KEYS = ("mitigation", "mitigations", "control", "recommendation", "remediation")


# Function to normalize a category label for alias lookup
def _norm_label(value: str) -> str:
    return " ".join(value.replace("_", " ").replace("-", " ").lower().split())


# Function to take the first non-empty string among known keys
def _first_str(payload: Dict, keys: Iterable[str]) -> str:
    for key in keys:
        value = payload.get(key)
        if isinstance(value, str) and value.strip():
            return value.strip()
    return ""


# Function to map an LLM key onto a canonical STRIDE category
def _match_category(key: str) -> Optional[str]:
    return _CATEGORY_ALIASES.get(_norm_label(key))


# Function to pull JSON objects out of a noisy LLM reply (picks the one that looks most like STRIDE/DREAD)
def _extract_json_object(content: str) -> Dict:
    text = content.strip()
    decoder = json.JSONDecoder()
    candidates = []
    idx = 0
    # Walk every '{' and try raw_decode — models wrap JSON in prose
    while True:
        start = text.find("{", idx)
        if start < 0:
            break
        try:
            obj, end = decoder.raw_decode(text, start)
        except json.JSONDecodeError:
            idx = start + 1
            continue
        if isinstance(obj, dict):
            candidates.append(obj)
        idx = end
    if not candidates:
        raise ValueError("No JSON found in response")

    def score(obj: Dict) -> int:
        # Prefer objects with STRIDE keys; Risk Assessment wins for DREAD replies
        keys = {_norm_label(str(k)) for k in obj}
        hits = sum(1 for cat in _STRIDE_CATEGORIES if _norm_label(cat) in keys)
        if "risk assessment" in keys:
            hits += 10
        return hits

    return max(candidates, key=score)


# Function to coerce a threat dict onto threat_name/description/impact/mitigation
def _coerce_threat(threat: Dict) -> Optional[Dict]:
    name = _first_str(threat, _THREAT_NAME_KEYS)
    if not name:
        return None
    return {
        "threat_name": name,
        "description": _first_str(threat, _DESC_KEYS),
        "impact": _first_str(threat, _IMPACT_KEYS),
        "mitigation": _first_str(threat, _MITIGATION_KEYS),
    }


# Function to coerce LLM JSON into the six STRIDE buckets (schema mismatch is dropped, not raised)
def parse_threat_response(response) -> Dict:
    try:
        content = response.content if hasattr(response, "content") else response
        if not isinstance(content, str):
            content = str(content)
        data = _extract_json_object(content)

        # DREAD replies use a Risk Assessment list instead of the six categories
        risk_key = next((k for k in data if _norm_label(str(k)) == "risk assessment"), None)
        if risk_key is not None:
            return {"Risk Assessment": data[risk_key]} if risk_key != "Risk Assessment" else data

        # Nested wrapper: some models put STRIDE under a parent key
        if not any(_match_category(str(k)) for k in data):
            for value in data.values():
                if isinstance(value, dict) and any(_match_category(str(k)) for k in value):
                    data = value
                    break

        # Six STRIDE keys only; trim each category to 5 well-formed threats
        formatted_data = {cat: [] for cat in _STRIDE_CATEGORIES}
        for key, value in data.items():
            matched_key = _match_category(str(key))
            if not matched_key or not isinstance(value, list):
                continue
            threats = [
                coerced
                for item in value
                if isinstance(item, dict)
                for coerced in [_coerce_threat(item)]
                if coerced
            ]
            if threats:
                formatted_data[matched_key] = threats[:5]

        filled = {cat: len(items) for cat, items in formatted_data.items()}
        if not any(filled.values()):
            logging.warning("Parsed STRIDE JSON but kept 0 threats. Top-level keys: %s", list(data.keys()))
        else:
            logging.info("Parsed STRIDE categories: %s", filled)
        return formatted_data
    except Exception as e:
        logging.error(f"Error parsing response: {str(e)}")
        raise


# Function to start the Prometheus exporter (METRICS_PORT, default 9100; 0 disables)
def start_metrics_server() -> None:
    """Bind Prometheus somewhere that is not the oMLX default (8000)."""
    raw = os.getenv("METRICS_PORT", "9100")
    try:
        port = int(raw)
    except ValueError:
        logging.warning("Invalid METRICS_PORT=%r; skipping metrics server", raw)
        return
    if port <= 0:
        logging.info("Metrics server disabled (METRICS_PORT=%s)", port)
        return
    try:
        start_http_server(port)
        logging.info("Prometheus metrics listening on port %s", port)
    except OSError as exc:
        # Bind failed (port in use); continue without metrics
        logging.warning("Could not start metrics server on port %s: %s", port, exc)

#-=- Agent Functions -=- (each returns a partial WorkflowState update)
def generate_stride_agent(state: WorkflowState) -> Dict[str, Any]:
    try:
        stride_tool = GenerateSTRIDEThreats()
        # Skip stale QA text on the first pass
        qa_feedback = state.stride_qa_feedback if state.stride_iterations > 0 else None
        result = stride_tool(state.system_desc, state.provider, state.cmdb_info, qa_feedback)
        return {"stride_data": result}
    except Exception as e:
        return {"error": str(e)}

def generate_dread_agent(state: WorkflowState) -> Dict[str, Any]:
    if not state.stride_data:
        return {"error": "No STRIDE data available"}
    try:
        dread_tool = GenerateDREADAssessment()
        qa_feedback = state.dread_qa_feedback if state.dread_iterations > 0 else None
        result = dread_tool(state.stride_data, state.provider, state.cmdb_info, qa_feedback)
        return {"dread_data": result}
    except Exception as e:
        return {"error": str(e)}

def qa_stride_agent(state: WorkflowState) -> Dict[str, Any]:
    if not state.stride_data:
        # Increment iterations so a failed generate_stride cannot loop forever.
        return {
            "error": state.error or "No STRIDE data available",
            "stride_iterations": state.stride_iterations + 1,
            "stride_qa_passed": False,
        }
    if not any(isinstance(items, list) and items for items in state.stride_data.values()):
        # Parser kept zero threats — fail QA so the generate loop can retry
        return {
            "stride_qa_feedback": {
                "pass": False,
                "score": 1,
                "improvement_needed": "STRIDE output contained no usable threats after parsing.",
            },
            "stride_iterations": state.stride_iterations + 1,
            "stride_qa_passed": False,
        }
    try:
        qa_tool = QAStrideModel()
        feedback = qa_tool(state.stride_data, state.provider, state.cmdb_info)
        return {
            "stride_qa_feedback": feedback,
            "stride_iterations": state.stride_iterations + 1,
            "stride_qa_passed": feedback.get('pass', False)
        }
    except Exception as e:
        return {"error": str(e)}

def qa_dread_agent(state: WorkflowState) -> Dict[str, Any]:
    if not state.dread_data:
        return {"error": "No DREAD data available"}
    try:
        qa_tool = QADreadAssessment()
        feedback = qa_tool(state.dread_data, state.stride_data, state.provider, state.cmdb_info)
        return {
            "dread_qa_feedback": feedback,
            "dread_iterations": state.dread_iterations + 1,
            "dread_qa_passed": feedback.get('pass', False)
        }
    except Exception as e:
        return {"error": str(e)}


def final_qa_agent(state: WorkflowState) -> Dict[str, Any]:
    if not state.stride_data or not state.dread_data:
        return {"error": "Missing data for final QA"}
    try:
        system_metadata = {
            'cmdb_id': state.cmdb_id,
            **{k: v for k, v in (state.cmdb_info or {}).items() if v}
        }
        complete_model = {
            "system_metadata": system_metadata,
            **state.stride_data,
            "dread_assessment": state.dread_data.get('Risk Assessment', [])
        }
        qa_tool = FinalQA()
        improved_model = qa_tool(complete_model, state.provider)
        return {
            "final_threat_model": improved_model,
            "final_qa_feedback": {"pass": True, "message": "Final QA applied"}
        }
    except Exception as e:
        return {"error": str(e)}

def save_model_agent(state: WorkflowState) -> Dict[str, Any]:
    if not state.final_threat_model:
        return {"error": "No final threat model available"}
    try:
        save_tool = SaveThreatModel()
        feedback_dir = os.path.join(BASE_DIR, "output/feedback")
        os.makedirs(feedback_dir, exist_ok=True)
        timestamp = datetime.now().strftime('%Y%m%d%H%M%S')

        for feedback_type, feedback in [
            ("stride", state.stride_qa_feedback),
            ("dread", state.dread_qa_feedback),
            ("final", state.final_qa_feedback)
        ]:
            if feedback:
                filename = f"{feedback_dir}/{feedback_type}_feedback_{state.cmdb_id}_{timestamp}.json"
                with open(filename, 'w') as f:
                    json.dump(feedback, f, indent=2)
                logging.info(f"Saved {feedback_type} feedback to {filename}")

        result = save_tool(state.final_threat_model, state.cmdb_id)
        return {"complete": True, "saved_path": result}
    except Exception as e:
        return {"error": str(e)}


# Conditional edge: pass or 3 iterations → DREAD; else loop generate_stride
def should_qa_stride(state: WorkflowState) -> str:
    return "generate_dread" if state.stride_qa_passed or state.stride_iterations >= 3 else "generate_stride"

# Conditional edge: pass or 3 iterations → final_qa; else loop generate_dread
def should_qa_dread(state: WorkflowState) -> str:
    return "final_qa" if state.dread_qa_passed or state.dread_iterations >= 3 else "generate_dread"


# --- Main Workflow --- (entry generate_stride; save_model is the terminal node)
@traceable(name="threat_model_workflow")
async def main(cmdb_id: str, provider: Provider = Provider.OPENAI):
    start_metrics_server()
    try:
        cmdb_info = get_application(cmdb_id)
        if not cmdb_info:
            raise ValueError(f"No application entry for ID: {cmdb_id}")
        # Old CMDB* values still map to APP-* inside get_application
        cmdb_id = cmdb_info["id"]

        workflow = StateGraph(WorkflowState)
        workflow.add_node("generate_stride", generate_stride_agent)
        workflow.add_node("qa_stride", qa_stride_agent)
        workflow.add_node("generate_dread", generate_dread_agent)
        workflow.add_node("qa_dread", qa_dread_agent)
        workflow.add_node("final_qa", final_qa_agent)
        workflow.add_node("save_model", save_model_agent)

        workflow.set_entry_point("generate_stride")
        workflow.add_edge("generate_stride", "qa_stride")
        workflow.add_edge("generate_dread", "qa_dread")
        workflow.add_edge("final_qa", "save_model")
        # Linear until QA; the two should_qa_* edges are the only loops
        workflow.add_conditional_edges("qa_stride", should_qa_stride)
        workflow.add_conditional_edges("qa_dread", should_qa_dread)

        app = workflow.compile()
        # architecture text first; description is the fallback if the CMDB row is thin
        system_desc = cmdb_info.get("architecture") or cmdb_info.get("description") or ""
        config = WorkflowState(cmdb_id=cmdb_id, system_desc=system_desc, provider=provider, cmdb_info=cmdb_info)
        with get_openai_callback() as cb:
            final_state = await app.ainvoke(config)
        if cb.total_tokens:
            logging.info(
                f"Workflow Tokens - Prompt: {cb.prompt_tokens}, Completion: {cb.completion_tokens}, Total: {cb.total_tokens}"
            )

        # ainvoke returns a dict; wrap it so attribute access works
        final_state_obj = WorkflowState(**final_state)

        # Fail the run if QA/save never produced a path
        if final_state_obj.error:
            raise Exception(final_state_obj.error)
        if not final_state_obj.saved_path:
            raise Exception("No output file generated")

        print(f"✅ Generated threat model for {cmdb_id} using {provider}")
        print(f"📄 Output file: {final_state_obj.saved_path}")
    except Exception as e:
        logging.critical(f"Workflow failed: {str(e)}")
        raise


if __name__ == "__main__":
    # Function to parse command-line arguments (better than doing it in main, scalable)
    parser = ArgumentParser(description='Generate threat models using OpenAI or local oMLX')
    parser.add_argument('cmdb_id', help='Application ID to process (e.g. APP-123456)')
    parser.add_argument(
        '--provider',
        type=parse_provider,
        default=resolve_provider_from_env(Provider.OPENAI),
        metavar='{openai,mlx}',
        help='LLM provider to use; "omlx" is accepted as an alias for "mlx"',
    )
    args = parser.parse_args()

    logs_dir = os.path.join(BASE_DIR, "logs")
    os.makedirs(logs_dir, exist_ok=True)
    # File + stdout; filename carries a run stamp
    logging.basicConfig(
        level=logging.DEBUG,
        format='%(asctime)s [%(levelname)s] %(message)s',
        handlers=[logging.FileHandler(f"{logs_dir}/threat_model_{datetime.now().strftime('%Y%m%d%H%M%S')}.log"), logging.StreamHandler()]
    )
    asyncio.run(main(args.cmdb_id, args.provider))
