"""
LLM-era guardrails: prompt injection detection, secret redaction, safe LLM
output parsing and outbound URL (SSRF) validation.

Everything here is deterministic and offline. It is used both to protect the
agent's own LLM calls and as a detection signal for hostile telemetry.
"""

from __future__ import annotations

import base64
import binascii
import ipaddress
import json
import math
import re
import secrets
from dataclasses import dataclass, field
from typing import Any, Dict, Iterable, List, Optional, Set, Tuple
from urllib.parse import urlsplit

from pydantic import BaseModel, Field, field_validator

# ---------------------------------------------------------------------------
# Recursive string extraction
# ---------------------------------------------------------------------------

_MAX_DEPTH = 12
_MAX_STRINGS = 5000


def iter_strings(data: Any, *, include_keys: bool = True, _depth: int = 0) -> Iterable[str]:
    """Yield every string (and optionally dict key) nested inside ``data``."""
    if _depth > _MAX_DEPTH:
        return
    if isinstance(data, str):
        yield data
    elif isinstance(data, dict):
        for key, value in data.items():
            if include_keys and isinstance(key, str):
                yield key
            yield from iter_strings(value, include_keys=include_keys, _depth=_depth + 1)
    elif isinstance(data, (list, tuple, set)):
        for item in data:
            yield from iter_strings(item, include_keys=include_keys, _depth=_depth + 1)


def _collect_strings(data: Any) -> List[str]:
    out: List[str] = []
    for s in iter_strings(data):
        out.append(s)
        if len(out) >= _MAX_STRINGS:
            break
    return out


# ---------------------------------------------------------------------------
# Prompt injection scanning
# ---------------------------------------------------------------------------

@dataclass
class PromptInjectionScanResult:
    detected: bool = False
    score: float = 0.0
    matched_rules: List[str] = field(default_factory=list)
    owasp_categories: List[str] = field(default_factory=list)
    mitre_atlas_ids: List[str] = field(default_factory=list)
    evidence: List[str] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "detected": self.detected,
            "score": self.score,
            "matched_rules": list(self.matched_rules),
            "owasp_categories": list(self.owasp_categories),
            "mitre_atlas_ids": list(self.mitre_atlas_ids),
            "evidence": list(self.evidence),
        }


# (rule_id, compiled pattern, weight, owasp, atlas)
_INJECTION_RULES: List[Tuple[str, re.Pattern, float, List[str], List[str]]] = [
    (
        "instruction_override",
        re.compile(
            r"\b(ignore|disregard|forget|override|bypass)\b[\s\w,]{0,30}?\b"
            r"(all\s+)?(previous|prior|above|earlier|preceding|system|your|the)\b[\s\w]{0,20}?"
            r"\b(instructions?|prompts?|rules?|directives?|guidelines?|context)\b",
            re.IGNORECASE,
        ),
        0.55, ["LLM01:2025"], ["AML.T0051"],
    ),
    (
        "system_prompt_extraction",
        re.compile(
            r"\b(reveal|print|show|repeat|output|leak|dump|display|tell\s+me)\b[\s\w]{0,30}?"
            r"\b(system|initial|hidden|original|developer)\s+(prompt|instructions?|message)",
            re.IGNORECASE,
        ),
        0.5, ["LLM01:2025", "LLM07:2025"], ["AML.T0051", "AML.T0054"],
    ),
    (
        "system_prompt_reference",
        re.compile(r"\bsystem\s*prompt\b", re.IGNORECASE),
        0.2, ["LLM07:2025"], ["AML.T0051"],
    ),
    (
        "role_hijack",
        re.compile(
            r"\b(you\s+are\s+now|from\s+now\s+on\s+you|act\s+as\s+(an?\s+)?(unrestricted|unfiltered|jailbroken)|"
            r"pretend\s+(to\s+be|you\s+are)|new\s+persona|developer\s+mode|DAN\s+mode|do\s+anything\s+now)\b",
            re.IGNORECASE,
        ),
        0.45, ["LLM01:2025"], ["AML.T0054"],
    ),
    (
        "jailbreak_keyword",
        re.compile(r"\b(jailbreak|jailbroken|no\s+restrictions|without\s+any\s+(filters|restrictions|limits))\b",
                   re.IGNORECASE),
        0.35, ["LLM01:2025"], ["AML.T0054"],
    ),
    (
        "risk_score_manipulation",
        re.compile(
            r"(risk_modifier|risk_score|risk\s+score|confidence|urgency|severity)\s*[\"']?\s*[:=]\s*[\"']?\s*"
            r"(0(\.0+)?(?![\d.])|-\d|low|benign|none)\b|"
            r"\b(classify|mark|report|label|rate|treat)\s+(this|the|it|all|these|every)\b[\s\w]{0,25}?\b(as\s+)?(benign|safe|harmless|false\s+positive|low\s+risk)\b",
            re.IGNORECASE,
        ),
        0.5, ["LLM01:2025"], ["AML.T0051"],
    ),
    (
        "delimiter_breakout",
        re.compile(r"</?\s*untrusted[_\w]*|</?\s*(system|assistant|user)\s*>|<\|im_(start|end)\|>|\[/?INST\]|"
                   r"<<\s*/?SYS\s*>>", re.IGNORECASE),
        0.5, ["LLM01:2025"], ["AML.T0051"],
    ),
    (
        "markdown_fence_breakout",
        re.compile(r"```[\s\S]{0,40}?(ignore|instruction|system|assistant|you\s+are)", re.IGNORECASE),
        0.35, ["LLM01:2025"], ["AML.T0051"],
    ),
    (
        "tool_call_smuggling",
        re.compile(
            r"(\"(tool_calls?|function_call)\"\s*:|<\s*(tool_call|function_call|invoke)\b|"
            r"\b(call|invoke|execute|run)\s+(the\s+)?(tool|function)\s+\w+|"
            r"\b(execute_action|block_ip|send_email|run_shell|exec_command)\s*\()",
            re.IGNORECASE,
        ),
        0.45, ["LLM01:2025", "LLM06:2025"], ["AML.T0051"],
    ),
    (
        "hidden_instruction_marker",
        re.compile(r"<\s*(IMPORTANT|SECRET|HIDDEN|ADMIN)\s*>|\bdo\s+not\s+(tell|inform|mention\s+(this\s+)?to)\s+the\s+user\b",
                   re.IGNORECASE),
        0.45, ["LLM01:2025"], ["AML.T0051"],
    ),
    (
        "exfiltration_instruction",
        re.compile(
            r"\b(send|post|upload|exfiltrate|forward|email)\b[\s\w]{0,30}?\b"
            r"(api[\s_-]?keys?|credentials?|secrets?|passwords?|tokens?|conversation|chat\s+history|"
            r"system\s+prompt|\.env|ssh\s+keys?)\b",
            re.IGNORECASE,
        ),
        0.4, ["LLM01:2025", "LLM02:2025"], ["AML.T0051", "AML.T0057"],
    ),
    (
        "invisible_unicode",
        re.compile("[\u200b-\u200f\u202a-\u202e\u2060-\u2064\ufeff\U000e0000-\U000e007f]"),
        0.3, ["LLM01:2025"], ["AML.T0051"],
    ),
]

_B64_TOKEN = re.compile(r"(?<![A-Za-z0-9+/=])[A-Za-z0-9+/]{24,}={0,2}(?![A-Za-z0-9+/=])")


def _decode_b64_candidates(text: str) -> List[str]:
    decoded: List[str] = []
    for match in _B64_TOKEN.finditer(text):
        token = match.group(0)
        padded = token + "=" * (-len(token) % 4)
        try:
            raw = base64.b64decode(padded, validate=True)
        except (binascii.Error, ValueError):
            continue
        try:
            candidate = raw.decode("utf-8")
        except UnicodeDecodeError:
            continue
        printable = sum(ch.isprintable() or ch.isspace() for ch in candidate)
        if candidate and printable / len(candidate) > 0.9:
            decoded.append(candidate)
        if len(decoded) >= 20:
            break
    return decoded


def _snippet(text: str, start: int, end: int, width: int = 60) -> str:
    lo = max(0, start - 20)
    hi = min(len(text), max(end, start + width))
    return text[lo:hi].replace("\n", " ").strip()[:160]


def scan_prompt_injection(data: Any) -> PromptInjectionScanResult:
    """Scan every string inside ``data`` for direct/indirect prompt injection."""
    result = PromptInjectionScanResult()
    matched: Dict[str, float] = {}
    owasp: Set[str] = set()
    atlas: Set[str] = set()

    def _scan(text: str, via: str = "") -> None:
        for rule_id, pattern, weight, rule_owasp, rule_atlas in _INJECTION_RULES:
            m = pattern.search(text)
            if not m:
                continue
            key = f"{rule_id}{via}"
            if key not in matched:
                matched[key] = weight
                owasp.update(rule_owasp)
                atlas.update(rule_atlas)
                if len(result.evidence) < 10:
                    result.evidence.append(f"{key}: {_snippet(text, m.start(), m.end())}")

    for text in _collect_strings(data):
        if not text or len(text) < 4:
            continue
        sample = text[:20000]
        _scan(sample)
        for decoded in _decode_b64_candidates(sample):
            before = len(matched)
            _scan(decoded, via="(base64)")
            if len(matched) > before:
                matched.setdefault("base64_encoded_instruction", 0.3)

    if matched:
        # Probabilistic OR so several weak signals add up but never exceed 1.0
        remaining = 1.0
        for weight in matched.values():
            remaining *= (1.0 - weight)
        score = round(1.0 - remaining, 3)
        # A lone generic reference ("system prompt") is not enough on its own
        result.detected = score >= 0.35
        result.score = score
        result.matched_rules = sorted(matched)
        result.owasp_categories = sorted(owasp)
        result.mitre_atlas_ids = sorted(atlas)
    return result


# ---------------------------------------------------------------------------
# Untrusted data isolation
# ---------------------------------------------------------------------------

_LABEL_RE = re.compile(r"[^a-z0-9_]")


def wrap_untrusted_data(label: str, data: Any) -> Tuple[str, str]:
    """Serialize ``data`` as JSON inside a nonce-tagged untrusted block.

    Every ``<`` and ``>`` in the JSON is emitted as a ``\\u003c``/``\\u003e``
    escape. JSON syntax never uses those characters outside strings, so the
    result is still valid JSON with identical meaning, but nothing inside it
    can form a closing tag (with or without the nonce).
    """
    safe_label = _LABEL_RE.sub("_", (label or "data").lower())[:40] or "data"
    nonce = secrets.token_hex(8)
    serialized = json.dumps(data, indent=2, default=str, ensure_ascii=False, sort_keys=True)
    serialized = serialized.replace("<", "\\u003c").replace(">", "\\u003e")
    tag = f"untrusted_{safe_label}"
    wrapped = f'<{tag} nonce="{nonce}">\n{serialized}\n</{tag} nonce="{nonce}">'
    return wrapped, nonce


# ---------------------------------------------------------------------------
# Secret / PII redaction
# ---------------------------------------------------------------------------

_SECRET_PATTERNS: List[Tuple[str, re.Pattern]] = [
    ("pem_private_key", re.compile(
        r"-----BEGIN [A-Z0-9 ]*PRIVATE KEY-----[\s\S]*?(-----END [A-Z0-9 ]*PRIVATE KEY-----|$)")),
    ("aws_access_key", re.compile(r"\b(AKIA|ASIA)[0-9A-Z]{16}\b")),
    ("github_token", re.compile(r"\b(gh[pousr]_[A-Za-z0-9_]{36,}|github_pat_[A-Za-z0-9_]{22,})\b")),
    ("anthropic_api_key", re.compile(r"\bsk-ant-[A-Za-z0-9_\-]{20,}")),
    ("openai_api_key", re.compile(r"\bsk-(proj-|svcacct-)?[A-Za-z0-9_\-]{20,}")),
    ("stripe_key", re.compile(r"\b(sk|rk|pk)_(live|test)_[A-Za-z0-9]{16,}\b")),
    ("slack_token", re.compile(r"\bxox[baprs]-[A-Za-z0-9\-]{10,}")),
    ("google_api_key", re.compile(r"\bAIza[0-9A-Za-z_\-]{35}\b")),
    ("jwt", re.compile(r"\beyJ[A-Za-z0-9_\-]{8,}\.eyJ[A-Za-z0-9_\-]{8,}\.[A-Za-z0-9_\-]{8,}")),
    ("bearer_token", re.compile(r"(?i)\bbearer\s+[A-Za-z0-9\-._~+/]{16,}=*")),
    ("password_assignment", re.compile(
        r"(?i)(?<![a-z])(password|passwd|pwd|secret[_-]?key|client[_-]?secret|secret|api[_-]?key|access[_-]?token|auth[_-]?token)\b\s*[\"']?\s*[:=]\s*[\"']?[^\s\"',;]{6,}")),
    ("us_ssn", re.compile(r"\b(?!000|666|9\d\d)\d{3}-(?!00)\d{2}-(?!0000)\d{4}\b")),
]

_CARD_CANDIDATE = re.compile(r"\b\d(?:[ -]?\d){12,18}\b")


def _luhn_valid(digits: str) -> bool:
    total = 0
    for i, ch in enumerate(reversed(digits)):
        n = int(ch)
        if i % 2 == 1:
            n *= 2
            if n > 9:
                n -= 9
        total += n
    return total % 10 == 0


def _redact_text(text: str, found: Set[str]) -> str:
    for name, pattern in _SECRET_PATTERNS:
        if pattern.search(text):
            found.add(name)
            text = pattern.sub(f"[REDACTED:{name}]", text)

    def _card(m: re.Match) -> str:
        digits = re.sub(r"\D", "", m.group(0))
        if 13 <= len(digits) <= 19 and _luhn_valid(digits) and len(set(digits)) > 1:
            found.add("credit_card")
            return "[REDACTED:credit_card]"
        return m.group(0)

    return _CARD_CANDIDATE.sub(_card, text)


def redact_sensitive_data(data: Any) -> Tuple[Any, List[str]]:
    """Return a deep copy of ``data`` with secrets/PII replaced, plus the types found."""
    found: Set[str] = set()

    def _walk(value: Any, depth: int) -> Any:
        if depth > _MAX_DEPTH:
            return value
        if isinstance(value, str):
            return _redact_text(value, found)
        if isinstance(value, dict):
            return {k: _walk(v, depth + 1) for k, v in value.items()}
        if isinstance(value, list):
            return [_walk(v, depth + 1) for v in value]
        if isinstance(value, tuple):
            return tuple(_walk(v, depth + 1) for v in value)
        return value

    return _walk(data, 0), sorted(found)


# ---------------------------------------------------------------------------
# LLM output parsing
# ---------------------------------------------------------------------------

_VALID_URGENCY = {"critical", "high", "medium", "low"}
_FENCE_RE = re.compile(r"```(?:json|JSON)?\s*(.*?)\s*```", re.DOTALL)


def _unit_float(value: Any, default: float = 0.0) -> float:
    if value is None or isinstance(value, bool):
        return default
    try:
        if isinstance(value, str):
            value = value.strip().rstrip("%")
        number = float(value)
    except (TypeError, ValueError):
        return default
    if math.isnan(number) or math.isinf(number):
        return default
    return max(0.0, min(1.0, number))


def _str_list(value: Any, limit: int = 50) -> List[str]:
    if value is None:
        return []
    if isinstance(value, (str, int, float)):
        value = [value]
    if not isinstance(value, (list, tuple)):
        return []
    return [str(v)[:500] for v in value if v is not None][:limit]


class LLMAnalysisResult(BaseModel):
    """Validated, clamped view of an LLM SOC analysis."""

    threat_assessment: str = ""
    risk_modifier: float = Field(default=0.0, ge=0.0, le=1.0)
    confidence: float = Field(default=0.0, ge=0.0, le=1.0)
    urgency: str = "medium"
    attack_classification: str = "unknown"
    key_findings: List[str] = Field(default_factory=list)
    recommended_actions: List[str] = Field(default_factory=list)
    mitre_tactics: List[str] = Field(default_factory=list)
    mitre_techniques: List[str] = Field(default_factory=list)
    mitre_atlas: List[str] = Field(default_factory=list)
    owasp_llm: List[str] = Field(default_factory=list)
    ioc_analysis: Dict[str, List[str]] = Field(default_factory=dict)

    @field_validator("risk_modifier", "confidence", mode="before")
    @classmethod
    def _clamp(cls, v: Any) -> float:
        return _unit_float(v)

    @field_validator("urgency", mode="before")
    @classmethod
    def _urgency(cls, v: Any) -> str:
        text = str(v or "").strip().lower()
        return text if text in _VALID_URGENCY else "medium"

    @field_validator("threat_assessment", "attack_classification", mode="before")
    @classmethod
    def _text(cls, v: Any) -> str:
        if v is None:
            return ""
        return str(v)[:4000]

    @field_validator("key_findings", "recommended_actions", "mitre_tactics",
                     "mitre_techniques", "mitre_atlas", "owasp_llm", mode="before")
    @classmethod
    def _lists(cls, v: Any) -> List[str]:
        return _str_list(v)

    @field_validator("ioc_analysis", mode="before")
    @classmethod
    def _iocs(cls, v: Any) -> Dict[str, List[str]]:
        if not isinstance(v, dict):
            return {}
        return {str(k)[:64]: _str_list(val, limit=100) for k, val in list(v.items())[:10]}


def _extract_json_object(text: str) -> Optional[Dict[str, Any]]:
    candidates: List[str] = []
    for m in _FENCE_RE.finditer(text):
        candidates.append(m.group(1))
    # Unterminated opening fence
    stripped = text.strip()
    if stripped.startswith("```"):
        candidates.append(re.sub(r"^```[A-Za-z]*\s*", "", stripped).rstrip("`").strip())
    candidates.append(text)

    decoder = json.JSONDecoder()
    for candidate in candidates:
        pos = candidate.find("{")
        while pos != -1:
            try:
                obj, _ = decoder.raw_decode(candidate, pos)
            except json.JSONDecodeError:
                pos = candidate.find("{", pos + 1)
                continue
            if isinstance(obj, dict):
                return obj
            pos = candidate.find("{", pos + 1)
    return None


def parse_llm_analysis(raw_content: Any) -> Dict[str, Any]:
    """Parse model output into a clamped analysis dict. Never raises."""
    text = raw_content if isinstance(raw_content, str) else str(raw_content or "")
    obj = _extract_json_object(text)
    if obj is None:
        result = LLMAnalysisResult(
            threat_assessment=text.strip()[:4000],
            risk_modifier=0.0,
            confidence=0.3,
        ).model_dump()
        result["parsed"] = False
        return result
    known = {k: v for k, v in obj.items() if k in LLMAnalysisResult.model_fields}
    try:
        result = LLMAnalysisResult(**known).model_dump()
    except Exception:  # pragma: no cover - validators are total, this is a backstop
        result = LLMAnalysisResult().model_dump()
    result["parsed"] = True
    return result


# ---------------------------------------------------------------------------
# Outbound URL / IP safety
# ---------------------------------------------------------------------------

_CLOUD_METADATA_HOSTS = {
    "169.254.169.254", "metadata.google.internal", "metadata", "100.100.100.200",
    "fd00:ec2::254", "instance-data", "instance-data.ec2.internal",
}
_BLOCKED_SUFFIXES = (".localhost", ".local", ".internal", ".localdomain", ".home.arpa", ".lan", ".corp")
_NUMERIC_HOST = re.compile(r"^(0x[0-9a-f]+|\d+)(\.(0x[0-9a-f]+|\d+))*$", re.IGNORECASE)


def is_public_ip(ip: str) -> bool:
    """True only for globally routable unicast addresses."""
    try:
        addr = ipaddress.ip_address(str(ip).strip().strip("[]"))
    except ValueError:
        return False
    if isinstance(addr, ipaddress.IPv6Address) and addr.ipv4_mapped is not None:
        addr = addr.ipv4_mapped
    return bool(
        addr.is_global
        and not addr.is_private
        and not addr.is_loopback
        and not addr.is_link_local
        and not addr.is_multicast
        and not addr.is_reserved
        and not addr.is_unspecified
    )


def _host_allowed(host: str, allowed_hosts: Set[str]) -> bool:
    for entry in allowed_hosts:
        entry = entry.lower().rstrip(".")
        if entry.startswith("."):
            if host.endswith(entry) and len(host) > len(entry):
                return True
        elif host == entry:
            return True
    return False


def validate_outbound_url(url: str, *, allowed_hosts: Optional[Set[str]] = None,
                          allow_http: bool = False) -> str:
    """Validate a URL the server is about to call. Raises ValueError if unsafe.

    This blocks literal private/metadata targets and internal hostnames. It
    does not resolve DNS, so callers that need protection against DNS
    rebinding should also pin ``allowed_hosts``.
    """
    if not isinstance(url, str) or not url.strip():
        raise ValueError("URL is empty")
    url = url.strip()
    if any(ch in url for ch in "\r\n\t\x00 "):
        raise ValueError("URL contains whitespace or control characters")
    parts = urlsplit(url)
    scheme = parts.scheme.lower()
    allowed_schemes = {"https", "http"} if allow_http else {"https"}
    if scheme not in allowed_schemes:
        raise ValueError(f"URL scheme '{scheme or 'none'}' not allowed")
    if parts.username is not None or parts.password is not None or "@" in parts.netloc:
        raise ValueError("Credentials in URL are not allowed")
    host = (parts.hostname or "").lower().rstrip(".")
    if not host:
        raise ValueError("URL has no host")
    try:
        _ = parts.port
    except ValueError as exc:
        raise ValueError("Invalid port in URL") from exc

    if host == "localhost" or host.endswith(_BLOCKED_SUFFIXES) or host in _CLOUD_METADATA_HOSTS:
        raise ValueError(f"Host '{host}' is internal and not allowed")

    try:
        ipaddress.ip_address(host)
        is_ip = True
    except ValueError:
        is_ip = False
    if is_ip:
        if not is_public_ip(host):
            raise ValueError(f"IP '{host}' is not a public address")
    elif _NUMERIC_HOST.match(host):
        raise ValueError(f"Obfuscated numeric host '{host}' is not allowed")
    elif "." not in host:
        raise ValueError(f"Single-label host '{host}' is not allowed")

    if allowed_hosts and not _host_allowed(host, set(allowed_hosts)):
        raise ValueError(f"Host '{host}' is not in the allowed host list")
    return url
