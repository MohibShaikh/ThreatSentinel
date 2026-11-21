"""
Agent tool environment: a self-describing set of read-only investigation tools.

The planner's deterministic pivoting and the optional LLM tool-use loop both
go through ``AgentEnvironment``, so the agent decides which indicators to
inspect from what it finds instead of following hardcoded field funnels.

Security boundary: every tool here is read-only. Mutating response actions
(firewall blocks, SIEM rules, paging) are never exposed as tool calls; they
stay behind deterministic risk scoring and human review in the planner.
"""

from __future__ import annotations

import asyncio
import copy
import ipaddress
import json
import logging
import re
import time
from dataclasses import asdict, dataclass, is_dataclass
from typing import Any, Awaitable, Callable, Dict, List, Optional

from .detectors import analyze_event, extract_iocs
from .guardrails import is_public_ip, redact_sensitive_data, scan_prompt_injection
from .llm import to_gemini_schema

logger = logging.getLogger(__name__)

DEFAULT_TOOL_TIMEOUT_SECONDS = 45.0
MAX_STRING_LENGTH = 4096
MAX_ARRAY_ITEMS = 50
_CVE_RE = re.compile(r"^CVE-\d{4}-\d{4,7}$", re.IGNORECASE)
# Local forensics judges hash validity itself; this only keeps the argument sane
_HASH_TEXT_RE = re.compile(r"^[A-Za-z0-9._\-]{1,256}$")

ToolHandler = Callable[..., Awaitable[Any]]


class ToolArgumentError(ValueError):
    """Arguments did not match the tool's JSON schema."""


@dataclass
class AgentTool:
    name: str
    description: str
    category: str
    parameters: Dict[str, Any]
    handler: ToolHandler
    read_only: bool = True

    def schema(self) -> Dict[str, Any]:
        return {
            "name": self.name,
            "description": self.description,
            "category": self.category,
            "read_only": self.read_only,
            "parameters": copy.deepcopy(self.parameters),
        }


@dataclass
class ToolCallRecord:
    step: int
    tool: str
    args: Dict[str, Any]
    ok: bool
    duration_ms: float
    summary: str = ""
    data: Any = None
    error: Optional[str] = None
    actor: str = "planner"

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


# ---------------------------------------------------------------------------
# Argument validation (the JSON Schema subset the tools use)
# ---------------------------------------------------------------------------

_JSON_TYPES = {
    "string": str, "integer": int, "number": (int, float), "boolean": bool, "object": dict, "array": list,
}


def _coerce(value: Any, schema: Dict[str, Any], path: str) -> Any:
    expected = schema.get("type")
    if expected is None:
        return value
    # Small local models often send nested JSON as a string
    if expected in ("object", "array") and isinstance(value, str):
        try:
            value = json.loads(value)
        except (json.JSONDecodeError, ValueError):
            raise ToolArgumentError(f"{path}: expected {expected}, got a non-JSON string") from None
    if expected == "integer" and isinstance(value, str) and value.strip().lstrip("-").isdigit():
        value = int(value.strip())
    if expected in ("integer", "number") and isinstance(value, bool):
        raise ToolArgumentError(f"{path}: expected {expected}, got boolean")
    if expected == "integer" and isinstance(value, float) and value.is_integer():
        value = int(value)
    if not isinstance(value, _JSON_TYPES[expected]):
        raise ToolArgumentError(f"{path}: expected {expected}, got {type(value).__name__}")

    if expected == "string":
        if len(value) > schema.get("maxLength", MAX_STRING_LENGTH):
            raise ToolArgumentError(f"{path}: string too long")
        if len(value) < schema.get("minLength", 0):
            raise ToolArgumentError(f"{path}: string too short")
    elif expected in ("integer", "number"):
        if "minimum" in schema and value < schema["minimum"]:
            raise ToolArgumentError(f"{path}: must be >= {schema['minimum']}")
        if "maximum" in schema and value > schema["maximum"]:
            raise ToolArgumentError(f"{path}: must be <= {schema['maximum']}")
    elif expected == "array":
        if len(value) > schema.get("maxItems", MAX_ARRAY_ITEMS):
            raise ToolArgumentError(f"{path}: too many items")
        if len(value) < schema.get("minItems", 0):
            raise ToolArgumentError(f"{path}: too few items")
        item_schema = schema.get("items") or {}
        value = [_coerce(v, item_schema, f"{path}[{i}]") for i, v in enumerate(value)]
    return value


def validate_arguments(arguments: Any, schema: Dict[str, Any]) -> Dict[str, Any]:
    """Validate and lightly coerce tool arguments. Unknown arguments are rejected."""
    if arguments is None:
        arguments = {}
    if isinstance(arguments, str):
        try:
            arguments = json.loads(arguments) if arguments.strip() else {}
        except (json.JSONDecodeError, ValueError):
            raise ToolArgumentError("arguments are not valid JSON") from None
    if not isinstance(arguments, dict):
        raise ToolArgumentError("arguments must be a JSON object")
    properties = schema.get("properties", {})
    unknown = sorted(set(arguments) - set(properties))
    if unknown:
        raise ToolArgumentError(f"unexpected argument(s): {', '.join(unknown)}")
    missing = [k for k in schema.get("required", []) if k not in arguments]
    if missing:
        raise ToolArgumentError(f"missing required argument(s): {', '.join(missing)}")
    clean: Dict[str, Any] = {}
    for key, value in arguments.items():
        clean[key] = _coerce(value, properties[key], key)
    for key, prop in properties.items():
        if key not in clean and "default" in prop:
            clean[key] = copy.deepcopy(prop["default"])
    return clean


def _jsonable(value: Any) -> Any:
    if is_dataclass(value) and not isinstance(value, type):
        return {k: _jsonable(v) for k, v in asdict(value).items()}
    if isinstance(value, dict):
        return {str(k): _jsonable(v) for k, v in value.items()}
    if isinstance(value, (list, tuple, set)):
        return [_jsonable(v) for v in value]
    if isinstance(value, (str, int, float, bool)) or value is None:
        return value
    return str(value)


def _object(properties: Dict[str, Any], required: Optional[List[str]] = None) -> Dict[str, Any]:
    return {"type": "object", "properties": properties, "required": required or [],
            "additionalProperties": False}


EVENT_DATA_SCHEMA = {
    "type": "object",
    "description": "Security event: event_type, source_ip, url, file_hash, payload, ...",
}


# ---------------------------------------------------------------------------
# Environment
# ---------------------------------------------------------------------------

class AgentEnvironment:
    """Registry of read-only tools built from whatever the planner actually has."""

    def __init__(self, tools: Any = None, memory: Any = None, integrations: Any = None,
                 *, tool_timeout: float = DEFAULT_TOOL_TIMEOUT_SECONDS):
        self.tools = tools
        self.memory = memory
        self.integrations = integrations
        self.tool_timeout = tool_timeout
        self._registry: Dict[str, AgentTool] = {}
        self._register_builtin_tools()

    # ------------------------------------------------------------------ registry

    def register(self, tool: AgentTool) -> None:
        """Add a tool. Only read-only tools can ever be registered."""
        if not tool.read_only:
            raise ValueError(f"Refusing to register mutating tool '{tool.name}': "
                             "response actions stay behind risk scoring and human review")
        if not re.fullmatch(r"[a-zA-Z_][a-zA-Z0-9_]{0,63}", tool.name):
            raise ValueError(f"Invalid tool name '{tool.name}'")
        if tool.parameters.get("type") != "object":
            raise ValueError("Tool parameters must be a JSON Schema object")
        self._registry[tool.name] = tool

    def get(self, name: str) -> Optional[AgentTool]:
        return self._registry.get(name)

    @property
    def tool_names(self) -> List[str]:
        return list(self._registry)

    def _intel_sources(self, capability: str) -> List[str]:
        registry = getattr(self.tools, "tools", None) or {}
        return [n for n, t in registry.items() if capability in getattr(t, "SUPPORTS", ())]

    def _register_builtin_tools(self) -> None:
        if self.tools is not None:
            for capability, name, arg, desc in (
                ("ip", "inspect_ip", "ip",
                 "Inspect an IP address: local forensics (bogon, metadata, reserved ranges) plus public "
                 "reputation/enrichment. External lookups are skipped automatically for non-public IPs."),
                ("url", "inspect_url", "url",
                 "Inspect a URL: local forensics (DGA-like domains, IDN homographs, SSRF targets, lure "
                 "paths) plus any reputation services configured."),
                ("file", "inspect_file_hash", "file_hash",
                 "Inspect a file hash (MD5/SHA1/SHA256): local known-hash checks (e.g. EICAR) plus any "
                 "file reputation services configured."),
            ):
                sources = self._intel_sources(capability)
                if not sources:
                    continue
                self.register(AgentTool(
                    name=name,
                    description=f"{desc} Sources available now: {', '.join(sources)}.",
                    category="threat_intel",
                    parameters=_object({arg: {"type": "string", "maxLength": 2048, "minLength": 1,
                                              "description": f"The {arg.replace('_', ' ')} to inspect"}}, [arg]),
                    handler=getattr(self, f"_{name}"),
                ))
            if self._intel_sources("cve"):
                self.register(AgentTool(
                    name="check_cve_kev",
                    description="Check CVE identifiers against the CISA Known Exploited Vulnerabilities "
                                "catalog. Returns which CVEs are actively exploited in the wild.",
                    category="threat_intel",
                    parameters=_object({"cves": {"type": "array", "items": {"type": "string", "maxLength": 32},
                                                 "minItems": 1, "maxItems": 50}}, ["cves"]),
                    handler=self._check_cve_kev,
                ))

        if self.memory is not None:
            self.register(AgentTool(
                name="search_memory",
                description="Find similar past investigations (TF-IDF cosine + IOC overlap), including "
                            "analyst-confirmed false positives.",
                category="memory",
                parameters=_object({"event_data": EVENT_DATA_SCHEMA,
                                    "limit": {"type": "integer", "minimum": 1, "maximum": 20, "default": 5}},
                                   ["event_data"]),
                handler=self._search_memory,
            ))
            self.register(AgentTool(
                name="get_pattern_insights",
                description="Learned temporal, IP-frequency and payload-keyword patterns for an event.",
                category="memory",
                parameters=_object({"event_data": EVENT_DATA_SCHEMA}, ["event_data"]),
                handler=self._get_pattern_insights,
            ))

        self.register(AgentTool(
            name="extract_iocs",
            description="Extract normalized IPs, URLs, domains, hashes, CVEs and emails from any JSON data.",
            category="analysis",
            parameters=_object({"data": {"type": "object", "description": "Any JSON object to mine"}}, ["data"]),
            handler=self._extract_iocs,
        ))
        self.register(AgentTool(
            name="run_detectors",
            description="Run the deterministic detection rules (classic attacks, OWASP LLM Top 10 2025, "
                        "agentic threats, MITRE ATT&CK and ATLAS mappings) on an event.",
            category="analysis",
            parameters=_object({"event_data": EVENT_DATA_SCHEMA}, ["event_data"]),
            handler=self._run_detectors,
        ))
        self.register(AgentTool(
            name="scan_prompt_injection",
            description="Scan text or JSON for direct or indirect prompt injection (including base64-encoded).",
            category="guardrails",
            parameters=_object({"data": {"description": "Text or any JSON value to scan"}}, ["data"]),
            handler=self._scan_prompt_injection,
        ))
        if self.integrations is not None:
            self.register(AgentTool(
                name="list_response_capabilities",
                description="List connected integrations and the response actions they support. Discovery "
                            "only: it never executes or changes anything.",
                category="discovery",
                parameters=_object({}),
                handler=self._list_response_capabilities,
            ))

    # ------------------------------------------------------------------ schema export

    def list_tool_schemas(self) -> List[Dict[str, Any]]:
        return [t.schema() for t in self._registry.values()]

    def to_openai_tools(self) -> List[Dict[str, Any]]:
        return [{"type": "function", "function": {"name": t.name, "description": t.description,
                                                  "parameters": copy.deepcopy(t.parameters)}}
                for t in self._registry.values()]

    def to_anthropic_tools(self) -> List[Dict[str, Any]]:
        return [{"name": t.name, "description": t.description, "input_schema": copy.deepcopy(t.parameters)}
                for t in self._registry.values()]

    def to_gemini_tools(self) -> List[Dict[str, Any]]:
        return [{"functionDeclarations": [
            {"name": t.name, "description": t.description, "parameters": to_gemini_schema(t.parameters)}
            for t in self._registry.values()]}]

    # ------------------------------------------------------------------ execution

    async def execute_tool(self, name: str, arguments: Optional[Dict[str, Any]] = None, *,
                           redact: bool = False, step: int = 0, actor: str = "planner") -> ToolCallRecord:
        started = time.perf_counter()

        def _record(ok: bool, args: Any, summary: str = "", data: Any = None,
                    error: Optional[str] = None) -> ToolCallRecord:
            record = ToolCallRecord(step=step, tool=str(name)[:64], args=_jsonable(args) if isinstance(args, dict) else {},
                                    ok=ok, duration_ms=round((time.perf_counter() - started) * 1000, 2),
                                    summary=summary, data=data, error=error, actor=actor)
            if redact:
                record.args = redact_sensitive_data(record.args)[0]
                record.data = redact_sensitive_data(record.data)[0]
                record.summary = redact_sensitive_data(record.summary)[0]
                if record.error:
                    record.error = redact_sensitive_data(record.error)[0]
            return record

        tool = self._registry.get(name) if isinstance(name, str) else None
        if tool is None:
            return _record(False, arguments, error=f"Unknown tool '{name}'. Available: {', '.join(self._registry)}")
        try:
            args = validate_arguments(arguments, tool.parameters)
        except ToolArgumentError as e:
            return _record(False, arguments, error=f"Invalid arguments: {e}")
        try:
            result = await asyncio.wait_for(tool.handler(**args), timeout=self.tool_timeout)
        except asyncio.TimeoutError:
            return _record(False, args, error=f"Tool timed out after {self.tool_timeout:g}s")
        except Exception as e:  # a tool failure is data for the agent, never a crash
            logger.warning(f"Tool {name} failed: {type(e).__name__}: {e}")
            return _record(False, args, error=f"{type(e).__name__}: {str(e)[:300]}")

        data = _jsonable(result)
        ok = not (isinstance(data, dict) and data.get("success") is False)
        error = data.get("error") if isinstance(data, dict) and not ok else None
        return _record(ok, args, summary=self._summarize(tool.name, data), data=data, error=error)

    # ------------------------------------------------------------------ handlers

    @staticmethod
    def _tool_result_dict(result: Any) -> Dict[str, Any]:
        data = dict(getattr(result, "data", {}) or {})
        return {"success": bool(getattr(result, "success", False)), "source": getattr(result, "source", "unknown"),
                **data, "error": getattr(result, "error", None)}

    async def _inspect_ip(self, ip: str) -> Dict[str, Any]:
        ip = ip.strip().strip("[]")
        try:
            ip = str(ipaddress.ip_address(ip))
        except ValueError:
            raise ToolArgumentError(f"'{ip[:64]}' is not an IP address") from None
        public = is_public_ip(ip)
        out = self._tool_result_dict(await self.tools.query_ip_reputation(ip))
        out.update({"indicator": ip, "public": public,
                    "scope": "external + local" if public else "local forensics only (non-public IP)"})
        return out

    async def _inspect_url(self, url: str) -> Dict[str, Any]:
        url = url.strip()
        if not url or any(ch.isspace() for ch in url):
            raise ToolArgumentError("url must be a single non-empty URL")
        out = self._tool_result_dict(await self.tools.query_url_reputation(url))
        out["indicator"] = url
        return out

    async def _inspect_file_hash(self, file_hash: str) -> Dict[str, Any]:
        file_hash = file_hash.strip()
        if not _HASH_TEXT_RE.match(file_hash):
            raise ToolArgumentError("file_hash must be 1-256 characters of [A-Za-z0-9._-]")
        out = self._tool_result_dict(await self.tools.query_file_reputation(file_hash))
        out["indicator"] = file_hash
        return out

    async def _check_cve_kev(self, cves: List[str]) -> Dict[str, Any]:
        normalized = sorted({c.strip().upper() for c in cves if _CVE_RE.match(c.strip())})
        if not normalized:
            raise ToolArgumentError("no valid CVE identifiers (format CVE-YYYY-NNNN)")
        out = self._tool_result_dict(await self.tools.query_cve_exploitation(normalized))
        out["cves_checked"] = normalized
        return out

    async def _search_memory(self, event_data: Dict[str, Any], limit: int = 5) -> Dict[str, Any]:
        matches = await self.memory.find_similar_events(event_data, limit=limit)
        return {"matches": [{
            "event_id": m.event_id, "event_type": m.event_type, "risk_score": m.risk_score,
            "risk_level": m.risk_level, "false_positive": m.false_positive,
            "similarity": round(float(getattr(m, "similarity", 0.0) or 0.0), 4),
        } for m in matches or []]}

    async def _get_pattern_insights(self, event_data: Dict[str, Any]) -> Dict[str, Any]:
        return {"insights": _jsonable(await self.memory.get_pattern_insights(event_data) or [])}

    async def _extract_iocs(self, data: Dict[str, Any]) -> Dict[str, Any]:
        return extract_iocs(data)

    async def _run_detectors(self, event_data: Dict[str, Any]) -> Dict[str, Any]:
        result = analyze_event(event_data).to_dict()
        result.pop("extracted_iocs", None)  # extract_iocs answers that question
        return result

    async def _scan_prompt_injection(self, data: Any) -> Dict[str, Any]:
        return scan_prompt_injection(data).to_dict()

    async def _list_response_capabilities(self) -> Dict[str, Any]:
        active = getattr(self.integrations, "active_integrations", {}) or {}
        capabilities: Dict[str, List[str]] = {}
        integrations = []
        for name, integration in active.items():
            try:
                actions = [getattr(a, "value", str(a)) for a in integration.get_supported_actions()]
            except Exception:
                actions = []
            itype = getattr(getattr(integration, "integration_type", None), "value", None)
            integrations.append({"name": name, "type": itype, "supported_actions": actions})
            for action in actions:
                capabilities.setdefault(action, []).append(name)
        configured = sorted((getattr(self.integrations, "integrations", {}) or {}).keys())
        return {
            "active_integrations": integrations,
            "configured_integrations": configured,
            "capabilities": capabilities,
            "autonomous_execution": "never via tools; gated by deterministic risk scoring and human review",
        }

    # ------------------------------------------------------------------ summaries

    @staticmethod
    def _summarize(name: str, data: Any) -> str:
        if not isinstance(data, dict):
            return ""
        if name.startswith("inspect_") or name == "check_cve_kev":
            if not data.get("success"):
                return f"{data.get('indicator', '')}: no source answered".strip(": ")
            parts = [f"reputation {float(data.get('reputation_score', 0) or 0):.2f}",
                     f"local risk {float(data.get('local_risk', 0) or 0):.2f}"]
            if data.get("reputation_sources"):
                parts.append("sources " + ",".join(data["reputation_sources"]))
            if data.get("cves"):
                parts.append(f"{len(data['cves'])} CVE(s)")
            kev = [m for r in data.get("individual_results", []) or [] for m in r.get("kev_matches", []) or []]
            if kev:
                parts.append(f"{len(kev)} KEV match(es)")
            prefix = data.get("indicator") or ",".join(data.get("cves_checked", [])[:3])
            return f"{prefix}: " + ", ".join(parts)
        if name == "search_memory":
            matches = data.get("matches", [])
            fps = sum(1 for m in matches if m.get("false_positive"))
            return f"{len(matches)} similar investigation(s), {fps} false positive(s)"
        if name == "get_pattern_insights":
            return f"{len(data.get('insights', []))} pattern insight(s)"
        if name == "extract_iocs":
            return ", ".join(f"{k}={len(v)}" for k, v in data.items() if v) or "no IOCs"
        if name == "run_detectors":
            return f"{len(data.get('findings', []))} finding(s), severity {data.get('severity_score', 0)}"
        if name == "scan_prompt_injection":
            return f"injection {'DETECTED' if data.get('detected') else 'not detected'} (score {data.get('score', 0)})"
        if name == "list_response_capabilities":
            return f"{len(data.get('active_integrations', []))} active integration(s)"
        return ""


__all__ = ["AgentEnvironment", "AgentTool", "ToolCallRecord", "ToolArgumentError", "validate_arguments"]
