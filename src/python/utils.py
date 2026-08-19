"""
STRIDE-Lite Shared Utilities

Provider selection, ChatOpenAI factory, CMDB/APP inventory, and the local
CVE feed path. I wrote this so model.py, scenario.py, and the GUI all
resolve oMLX the same way, and so leftover CMDB* ids still map to APP-*.

Notes:
- CLI --provider wins; otherwise LLM_PROVIDER; omlx is an alias for mlx.
- OpenAI is forced to json_object; MLX is not (some local models reject it).
- Dashboard/root oMLX URLs are rewritten to /v1.
- CVE feed is a JSON file on disk. No download.

## Author Information
- **Author**: Nic Cravino
- **Email**: spidernic@me.com
- **LinkedIn**: https://www.linkedin.com/in/nic-cravino
- **Date**: August 2026

## License: Apache License 2.0
"""
import json
import os
import re
import logging
from enum import Enum
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional, Set, Tuple
from urllib.parse import urlsplit, urlunsplit
from dotenv import load_dotenv

# -- Paths --------------------------------------------------------- (repo root is two parents above src/python)
SRC_DIR = os.path.dirname(os.path.abspath(__file__))
BASE_DIR = os.path.dirname(os.path.dirname(SRC_DIR))
DEFAULT_MLX_BASE_URL = "http://127.0.0.1:8000/v1"

# -- Environment variables ---------------------------------------- (OMLX_* aliases; OPENAI_MODEL falls back to LLM_MODEL)
load_dotenv()
ENV_VARS = {
    "OPENAI_API_KEY": os.getenv("OPENAI_API_KEY"),
    "OPENAI_MODEL": os.getenv("OPENAI_MODEL") or os.getenv("LLM_MODEL", "gpt-4o"),
    "MLX_API_KEY": os.getenv("MLX_API_KEY") or os.getenv("OMLX_API_KEY"),
    "MLX_BASE_URL": os.getenv("MLX_BASE_URL") or os.getenv("OMLX_BASE_URL", DEFAULT_MLX_BASE_URL),
    "MLX_MODEL": os.getenv("MLX_MODEL") or os.getenv("OMLX_MODEL") or os.getenv("LLM_MODEL", "default"),
}

# -- Provider enum ------------------------------------------------- (CLI --provider wins; omlx is an alias for mlx)
class Provider(str, Enum):
    OPENAI = "openai"
    MLX = "mlx"

# -- Circuit breaker ---------------------------------------------- (trips after 3 LLM failures in-process)
class CircuitBreaker:
    """Simple failure counter to avoid hammering an LLM endpoint."""

    def __init__(self, max_failures: int = 3):
        self.failures = 0
        self.max_failures = max_failures

    def check(self):
        # Fail early — further calls would just pile on the same error
        if self.failures >= self.max_failures:
            raise RuntimeError("API circuit breaker tripped")

# Process-local breaker; model.py increments .failures on LLM errors
threat_cb = CircuitBreaker()


# Function to parse a float env var (blank or junk falls back to default)
def _parse_float_env(name: str, default: float) -> float:
    value = os.getenv(name)
    if value in (None, ""):
        return default
    try:
        return float(value)
    except (TypeError, ValueError):
        return default


# Function to parse an int env var (same fallback as float)
def _parse_int_env(name: str, default: int) -> int:
    value = os.getenv(name)
    if value in (None, ""):
        return default
    try:
        return int(value)
    except (TypeError, ValueError):
        return default


# Function to pick per-provider timeout and retries
def _resolve_timeout_and_retries(provider: Provider) -> Tuple[float, int]:
    # Local MLX generations regularly exceed 2 minutes; keep OpenAI at 120s.
    default_timeout = 300.0 if provider == Provider.MLX else 120.0
    global_timeout = _parse_float_env("LLM_TIMEOUT", default_timeout)
    global_retries = _parse_int_env("LLM_MAX_RETRIES", 5)
    provider_name = provider.value.upper()
    timeout = _parse_float_env(f"{provider_name}_TIMEOUT", global_timeout)
    retries = _parse_int_env(f"{provider_name}_MAX_RETRIES", global_retries)
    return timeout, retries


# Function to rewrite oMLX dashboard/root URLs to the OpenAI /v1 base
def _normalize_mlx_base_url(url: str) -> str:
    """Accept an oMLX dashboard/root URL and return the OpenAI API base URL."""
    parsed = urlsplit(url)
    # Empty, slash, or /admin is the dashboard; the chat API lives at /v1
    if parsed.path in ("", "/") or parsed.path.startswith("/admin"):
        return urlunsplit((parsed.scheme, parsed.netloc, "/v1", "", ""))
    return urlunsplit((parsed.scheme, parsed.netloc, parsed.path.rstrip("/"), "", ""))


# Function to read MLX_API_KEY (OMLX_API_KEY is the alias)
def resolve_mlx_api_key() -> str | None:
    return os.getenv("MLX_API_KEY") or os.getenv("OMLX_API_KEY")


# Function to resolve the MLX base URL (normalized to /v1)
def resolve_mlx_base_url() -> str:
    return _normalize_mlx_base_url(
        os.getenv("MLX_BASE_URL") or os.getenv("OMLX_BASE_URL") or DEFAULT_MLX_BASE_URL
    )


# Function to pick the local model name (MLX_MODEL, then OMLX_MODEL, then LLM_MODEL)
def resolve_mlx_model(default: str = "default") -> str:
    return os.getenv("MLX_MODEL") or os.getenv("OMLX_MODEL") or os.getenv("LLM_MODEL") or default


# Function to parse a provider string (omlx is accepted as mlx)
def parse_provider(value: str) -> Provider:
    normalized = value.strip().lower()
    if normalized == "omlx":
        normalized = Provider.MLX.value
    try:
        return Provider(normalized)
    except ValueError as exc:
        choices = ", ".join(provider.value for provider in Provider)
        raise ValueError(f"Unsupported provider '{value}'. Choose one of: {choices}") from exc


# Function to read LLM_PROVIDER from env (unknown values warn and fall back)
def resolve_provider_from_env(default: Provider = Provider.OPENAI) -> Provider:
    raw = os.getenv("LLM_PROVIDER")
    if not raw:
        return default
    try:
        return parse_provider(raw)
    except ValueError:
        logging.warning("Unknown LLM_PROVIDER=%r; falling back to %s", raw, default.value)
        return default


# -- LLM factory --------------------------------------------------- (both go through ChatOpenAI; MLX is a local base_url)

def get_llm(provider: Provider):
    """Return a LangChain ChatOpenAI instance for openai or local mlx."""
    try:
        # Imported here so inventory-only callers do not pull langchain
        from langchain_openai import ChatOpenAI

        timeout, max_retries = _resolve_timeout_and_retries(provider)

        # OpenAI is forced to json_object; MLX is not (some local models reject it)
        if provider == Provider.OPENAI:
            api_key = os.getenv("OPENAI_API_KEY")
            if not api_key:
                raise ValueError("OpenAI API key not found")
            return ChatOpenAI(
                model=os.getenv("OPENAI_MODEL") or os.getenv("LLM_MODEL", "gpt-4o"),
                api_key=api_key,
                max_retries=max_retries,
                timeout=timeout,
                model_kwargs={"response_format": {"type": "json_object"}},
            )

        if provider == Provider.MLX:
            api_key = resolve_mlx_api_key()
            if not api_key:
                raise ValueError("MLX_API_KEY or OMLX_API_KEY not found")
            return ChatOpenAI(
                model=resolve_mlx_model(),
                api_key=api_key,
                base_url=resolve_mlx_base_url(),
                max_retries=max_retries,
                timeout=timeout,
            )

        raise ValueError(f"Unsupported provider: {provider}")

    except Exception as exc:
        logging.error(f"Failed to initialise {provider} LLM: {exc}")
        raise


# -- Application inventory ---------------------------------------- (canonical schema; CMDB* values still map to APP-*)
# Canonical public schema. Saved JSON from this project may use `cmdb_id`
# or `app_id` as the id key; CMDB* id *values* still map to APP-*.

APPLICATION_FIELDS: Tuple[str, ...] = (
    "id",
    "name",
    "description",
    "architecture",
    "business_area",
    "confidentiality",
    "integrity",
    "availability",
    "platform",
    "internet_facing",
    "sourcing",
    "customer_data",
)

# Alternate keys on saved threat-model JSON (older files used cmdb_id)
_FIELD_ALIASES: Dict[str, Tuple[str, ...]] = {
    "id": ("id", "app_id", "cmdb_id"),
}

# Prompt labels in the order the STRIDE template expects
_PROMPT_LABELS: Tuple[Tuple[str, str], ...] = (
    ("id", "Application ID"),
    ("name", "Name"),
    ("description", "Description"),
    ("architecture", "Architecture"),
    ("business_area", "Business area"),
    ("confidentiality", "Confidentiality"),
    ("integrity", "Integrity"),
    ("availability", "Availability"),
    ("platform", "Platform"),
    ("internet_facing", "Internet facing"),
    ("sourcing", "Sourcing"),
    ("customer_data", "Customer data"),
)

# Regex → canonical OS token (order matters; cloud|saas is one bucket)
_PLATFORM_RULES: Tuple[Tuple[re.Pattern[str], str], ...] = (
    (re.compile(r"z/?os", re.I), "z/OS"),
    (re.compile(r"linux", re.I), "Linux"),
    (re.compile(r"windows", re.I), "Windows"),
    (re.compile(r"cloud|saas", re.I), "Cloud"),
)

# Allowed sourcing labels (inventory free text is mapped onto these)
_SOURCING_VALUES = ("in-house", "COTS", "SAAS", "Hybrid")


# Function to pick the first non-empty key from a row
def _first_present(row: Dict[str, Any], keys: Iterable[str]) -> Any:
    for key in keys:
        if key in row and row[key] not in (None, ""):
            return row[key]
    return None


def canonical_app_id(raw: Any) -> str:
    """APP-123456. Accepts CMDB123456 / APP123456 / APP-123456."""
    text = str(raw or "").strip()
    if not text:
        return ""
    match = re.fullmatch(r"(?:CMDB|APP[-_]?)(.+)", text, re.I)
    if match:
        return f"APP-{match.group(1)}"
    return text


# Function to normalise CIA to "Level N" when the source used tier/level
def _cia_level(value: Any) -> str:
    if value in (None, ""):
        return ""
    text = str(value).strip()
    match = re.search(r"(?:level|tier)\s*([123])", text, re.I)
    if match:
        return f"Level {match.group(1)}"
    if re.fullmatch(r"[123]", text):
        return f"Level {text}"
    return text


# Function to coerce yes/true/1 to bool (blank or junk is false)
def _as_bool(value: Any) -> bool:
    if isinstance(value, bool):
        return value
    if value in (None, ""):
        return False
    text = str(value).strip().lower()
    if text in {"true", "yes", "1", "y"}:
        return True
    if text in {"false", "no", "0", "n"}:
        return False
    return False


# Function to map sourcing free text onto in-house / COTS / SAAS / Hybrid
def _sourcing(value: Any) -> str:
    if value in (None, ""):
        return ""
    text = str(value).strip()
    low = text.lower()
    if "hybrid" in low:
        return "Hybrid"
    if "saas" in low:
        return "SAAS"
    if "in-house" in low or "in house" in low:
        return "in-house"
    if "cots" in low or "commercial" in low:
        return "COTS"
    return text


# Function to split platform strings and drop llama.cpp (runtime, not an OS)
def _platforms(value: Any) -> List[str]:
    if isinstance(value, str):
        items = [part.strip() for part in value.split(",") if part.strip()]
    elif isinstance(value, list):
        items = value
    else:
        items = []
    out: List[str] = []
    seen: Set[str] = set()
    for item in items:
        if not isinstance(item, str):
            continue
        # llama.cpp showed up in a few inventory dumps; it is not a host platform
        if item.lower() == "llama.cpp":
            continue
        mapped = item.strip()
        for pattern, name in _PLATFORM_RULES:
            if pattern.search(mapped):
                mapped = name
                break
        if mapped and mapped not in seen:
            seen.add(mapped)
            out.append(mapped)
    return out


def normalize_application(row: Optional[Dict[str, Any]]) -> Dict[str, Any]:
    """Map a raw inventory or saved-metadata row onto the public schema."""
    source = row if isinstance(row, dict) else {}
    picked = {
        field: _first_present(source, _FIELD_ALIASES.get(field, (field,)))
        for field in APPLICATION_FIELDS
    }
    app_id = canonical_app_id(picked["id"])
    return {
        "id": app_id,
        "name": str(picked["name"] or "").strip(),
        "description": str(picked["description"] or "").strip(),
        "architecture": str(picked["architecture"] or "").strip(),
        "business_area": str(picked["business_area"] or "").strip(),
        "confidentiality": _cia_level(picked["confidentiality"]),
        "integrity": _cia_level(picked["integrity"]),
        "availability": _cia_level(picked["availability"]),
        "platform": _platforms(picked["platform"]),
        "internet_facing": _as_bool(picked["internet_facing"]),
        "sourcing": _sourcing(picked["sourcing"]),
        "customer_data": _as_bool(picked["customer_data"]),
    }


# Function to build lookup aliases (APP-123456, APP123456, CMDB123456, bare token)
def application_aliases(app: Dict[str, Any]) -> Set[str]:
    aliases: Set[str] = set()
    raw_id = str(app.get("id") or "").strip()
    if not raw_id:
        return aliases
    aliases.add(raw_id)
    # Dashless form so APP-123456 also hits APP123456
    aliases.add(raw_id.replace("-", ""))
    canon = canonical_app_id(raw_id)
    if canon:
        aliases.add(canon)
        match = re.fullmatch(r"APP-(.+)", canon, re.I)
        if match:
            token = match.group(1)
            aliases.update({token, f"CMDB{token}", f"APP{token}", f"APP-{token}"})
    return {item for item in aliases if item}


# Function to locate data/applications.json under the repo root
def applications_path() -> Path:
    return Path(BASE_DIR) / "data" / "applications.json"


# Function to load and normalise the application inventory (missing file → empty list)
def load_applications() -> List[Dict[str, Any]]:
    path = applications_path()
    if not path.exists():
        return []
    data = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(data, list):
        return []
    return [normalize_application(row) for row in data if isinstance(row, dict)]


# Function to look up one application by APP-* or leftover CMDB* id
def get_application(app_id: str) -> Optional[Dict[str, Any]]:
    wanted = str(app_id or "").strip()
    if not wanted:
        return None
    wanted_canon = canonical_app_id(wanted)
    for app in load_applications():
        aliases = application_aliases(app)
        if wanted in aliases or wanted_canon in aliases:
            return app
    return None


# Function to format inventory values for prompts (bools as yes/no, platforms joined)
def format_application_value(key: str, value: Any) -> str:
    if key in {"internet_facing", "customer_data"}:
        if isinstance(value, bool):
            return "yes" if value else "no"
    if key == "platform" and isinstance(value, list):
        return ", ".join(str(item) for item in value)
    return str(value)


# Function to render a labelled context block for the STRIDE prompt
def application_context_block(app: Optional[Dict[str, Any]]) -> str:
    source = app if isinstance(app, dict) else {}
    lines = []
    for key, label in _PROMPT_LABELS:
        value = source.get(key)
        if value in (None, "", []):
            continue
        lines.append(f"{label}: {format_application_value(key, value)}")
    return "\n".join(lines)


# Function to flatten an application row into prompt template vars
def application_prompt_vars(app: Optional[Dict[str, Any]]) -> Dict[str, str]:
    source = app if isinstance(app, dict) else {}
    platform = format_application_value("platform", source.get("platform") or [])
    return {
        "app_id": source.get("id") or "",
        "app_name": source.get("name") or "",
        "app_description": source.get("description") or "",
        "app_architecture": source.get("architecture") or "",
        "app_sourcing": source.get("sourcing") or "",
        "app_internet_facing": format_application_value("internet_facing", source.get("internet_facing", False)),
        "app_confidentiality": source.get("confidentiality") or "",
        "app_integrity": source.get("integrity") or "",
        "app_availability": source.get("availability") or "",
        "app_customer_data": format_application_value("customer_data", source.get("customer_data", False)),
        "app_platform": platform,
        "app_business_area": source.get("business_area") or "",
    }


# -- CVE feed ------------------------------------------------------ (file on disk; never downloaded)

# Function to locate the bundled sample CVE JSON
def sample_cves_path() -> Path:
    return Path(BASE_DIR) / "data" / "sample_cves.json"


def resolve_cve_feed_path(explicit: str | None = None) -> Path:
    """User JSON list, else CVE_FEED / CVE_FEED_PATH, else the sample file. No download."""
    for raw in (explicit, os.getenv("CVE_FEED"), os.getenv("CVE_FEED_PATH")):
        if not raw:
            continue
        path = Path(raw)
        # Relative paths resolve against the repo root, not cwd
        if not path.is_absolute():
            path = Path(BASE_DIR) / path
        if path.is_file():
            return path
    return sample_cves_path()


# Function to flatten a CVE JSON list or NVD-shaped dict into records with an id
def _cve_records(data: Any) -> List[Dict[str, Any]]:
    if isinstance(data, list):
        rows = data
    elif isinstance(data, dict):
        rows = data.get("cves") or data.get("items") or data.get("vulnerabilities") or []
    else:
        rows = []
    salida: List[Dict[str, Any]] = []
    for item in rows:
        if not isinstance(item, dict):
            continue
        # NVD-shaped wrap: nested cve.id / descriptions, no top-level id
        if "cve" in item and isinstance(item["cve"], dict) and not item.get("id"):
            nested = item["cve"]
            cve_id = nested.get("id")
            descriptions = nested.get("descriptions") or []
            text = ""
            if isinstance(descriptions, list):
                english = next((row for row in descriptions if isinstance(row, dict) and row.get("lang") == "en"), None)
                text = (english or (descriptions[0] if descriptions else {})).get("value") or ""
            item = {"id": cve_id, "description": text, **{k: v for k, v in item.items() if k != "cve"}}
        if item.get("id"):
            salida.append(item)
    return salida


# Function to load CVE records from the resolved feed path
def load_sample_cves(explicit: str | None = None) -> List[Dict[str, Any]]:
    path = resolve_cve_feed_path(explicit)
    if not path.exists():
        return []
    data = json.loads(path.read_text(encoding="utf-8"))
    return _cve_records(data)


# Function to index CVE records by uppercase id (for scenario lookups)
def load_sample_cves_by_id(explicit: str | None = None) -> Dict[str, Dict[str, Any]]:
    salida: Dict[str, Dict[str, Any]] = {}
    for item in load_sample_cves(explicit):
        cve_id = item.get("id")
        if cve_id:
            salida[str(cve_id).upper()] = item
    return salida


# Function to report which CVE file is in use and whether it is the sample
def cve_feed_status(explicit: str | None = None) -> Dict[str, Any]:
    path = resolve_cve_feed_path(explicit)
    try:
        rel = str(path.resolve().relative_to(Path(BASE_DIR).resolve()))
    except ValueError:
        rel = str(path)
    return {
        "path": rel,
        "count": len(load_sample_cves(explicit)),
        "sample": path.resolve() == sample_cves_path().resolve(),
    }
