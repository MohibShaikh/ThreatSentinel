"""
Deterministic detection engine for classic SOC and LLM-era events.

Runs fully offline with no API keys. It inspects the event type plus the
payload, raw data, user agent, URL and file fields, maps hits to MITRE
ATT&CK, MITRE ATLAS and the OWASP Top 10 for LLM Applications (2025), and
extracts IOCs.
"""

from __future__ import annotations

import ipaddress
import re
from dataclasses import asdict, dataclass, field
from typing import Any, Dict, List, Optional, Set

from .guardrails import iter_strings, redact_sensitive_data, scan_prompt_injection

# ---------------------------------------------------------------------------
# Event type baselines
# ---------------------------------------------------------------------------

EVENT_TYPE_BASELINE: Dict[str, float] = {
    # Classic SOC
    "malware_detection": 0.8,
    "ddos_signs": 0.7,
    "phishing_attempt": 0.7,
    "suspicious_url": 0.6,
    "suspicious_ip": 0.5,
    "login_anomaly": 0.4,
    "unknown": 0.3,
    # LLM-era / cloud-native
    "prompt_injection": 0.75,
    "agent_tool_abuse": 0.8,
    "mcp_tool_poisoning": 0.8,
    "rag_poisoning": 0.7,
    "secret_leak": 0.8,
    "model_dos": 0.6,
    "supply_chain_compromise": 0.85,
    "data_exfiltration": 0.85,
}

MODERN_EVENT_TYPES = {
    "prompt_injection", "agent_tool_abuse", "mcp_tool_poisoning", "rag_poisoning",
    "secret_leak", "model_dos", "supply_chain_compromise", "data_exfiltration",
}


@dataclass
class DetectionFinding:
    rule_id: str
    title: str
    severity: float
    category: str
    evidence: List[str] = field(default_factory=list)
    mitre_attack: List[str] = field(default_factory=list)
    mitre_atlas: List[str] = field(default_factory=list)
    owasp_llm: List[str] = field(default_factory=list)


@dataclass
class DetectionAssessment:
    event_type: str = "unknown"
    severity_score: float = 0.0
    findings: List[Dict[str, Any]] = field(default_factory=list)
    mitre_attack: List[str] = field(default_factory=list)
    mitre_atlas: List[str] = field(default_factory=list)
    owasp_llm: List[str] = field(default_factory=list)
    extracted_iocs: Dict[str, List[str]] = field(default_factory=dict)
    prompt_injection_detected: bool = False
    redacted_secret_types: List[str] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


# ---------------------------------------------------------------------------
# IOC extraction
# ---------------------------------------------------------------------------

_IPV4_RE = re.compile(r"(?<![\d.])(?:\d{1,3}\.){3}\d{1,3}(?![\d.])")
_IPV6_RE = re.compile(r"(?<![:\w])(?:[0-9a-fA-F]{1,4}:){2,7}[0-9a-fA-F]{0,4}(?![:\w])|::1\b|::ffff:[\d.]+")
_URL_RE = re.compile(r"\b(?:https?|hxxps?|ftp)://[^\s\"'<>`\]\)]+", re.IGNORECASE)
_EMAIL_RE = re.compile(r"\b[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,24}\b")
_DOMAIN_RE = re.compile(r"\b(?:[A-Za-z0-9](?:[A-Za-z0-9\-]{0,61}[A-Za-z0-9])?\.)+[A-Za-z]{2,24}\b")
_CVE_RE = re.compile(r"\bCVE-\d{4}-\d{4,7}\b", re.IGNORECASE)
_HASH_RES = {
    "sha256": re.compile(r"\b[a-fA-F0-9]{64}\b"),
    "sha1": re.compile(r"\b[a-fA-F0-9]{40}\b"),
    "md5": re.compile(r"\b[a-fA-F0-9]{32}\b"),
}
_NON_TLD_SUFFIXES = {
    "pdf", "exe", "dll", "doc", "docx", "docm", "xls", "xlsx", "xlsm", "ppt", "pptx", "txt", "log",
    "json", "yaml", "yml", "xml", "csv", "zip", "rar", "gz", "tar", "tgz", "7z", "js", "ts", "py",
    "sh", "ps1", "bat", "cmd", "vbs", "png", "jpg", "jpeg", "gif", "svg", "html", "htm", "php",
    "asp", "aspx", "jsp", "md", "ini", "cfg", "conf", "env", "pem", "key", "crt", "db", "sqlite",
    "iso", "img", "msi", "lnk", "hta", "jar", "class", "so", "bin", "dat", "tmp", "bak", "lock",
    "toml", "whl", "sys", "drv", "scr", "local", "internal", "localhost", "example",
}

# Standalone (non-URL, non-email) domains are only reported for common TLDs so
# that dotted identifiers such as "Trojan.Generic.Suspicious" are not IOCs.
_COMMON_TLDS = {
    "com", "net", "org", "io", "co", "ai", "app", "dev", "info", "biz", "xyz", "top", "site", "online",
    "club", "shop", "store", "tech", "cloud", "live", "me", "tv", "cc", "ws", "su", "ru", "cn", "uk",
    "de", "fr", "nl", "it", "es", "pl", "br", "in", "jp", "kr", "au", "ca", "us", "eu", "ch", "se",
    "no", "fi", "dk", "be", "at", "cz", "ua", "by", "kz", "ir", "tr", "vn", "id", "th", "my", "sg",
    "hk", "tw", "za", "ng", "mx", "ar", "cl", "pk", "bd", "tk", "ml", "ga", "cf", "gq", "pw", "icu",
    "zip", "mov", "click", "link", "work", "rest", "cyou", "buzz", "gov", "edu", "mil", "int", "sh",
    "gg", "ly", "to", "is", "onion", "bit", "lol", "pro", "name", "mobi", "asia", "page", "run",
}


def _dedupe(items: List[str], limit: int = 100) -> List[str]:
    seen: Set[str] = set()
    out: List[str] = []
    for item in items:
        if item not in seen:
            seen.add(item)
            out.append(item)
        if len(out) >= limit:
            break
    return out


def extract_iocs(data: Any) -> Dict[str, List[str]]:
    """Extract IPs, URLs, domains, hashes, CVEs and emails from nested data."""
    ips: List[str] = []
    urls: List[str] = []
    domains: List[str] = []
    emails: List[str] = []
    cves: List[str] = []
    hashes: Dict[str, List[str]] = {"md5": [], "sha1": [], "sha256": []}

    for text in iter_strings(data, include_keys=False):
        if not text or len(text) > 200000:
            continue
        for m in _URL_RE.findall(text):
            url = m.rstrip(".,;:")
            urls.append(url)
            host = re.sub(r"^[a-z]+://", "", url, flags=re.IGNORECASE).split("/")[0].split("@")[-1]
            host = host.split(":")[0].lower() if not host.startswith("[") else host
            try:
                ipaddress.ip_address(host.strip("[]"))
                ips.append(host.strip("[]"))
            except ValueError:
                if "." in host:
                    domains.append(host)
        for m in _IPV4_RE.findall(text):
            try:
                ips.append(str(ipaddress.IPv4Address(m)))
            except ValueError:
                continue
        for m in _IPV6_RE.findall(text):
            try:
                ips.append(str(ipaddress.IPv6Address(m)))
            except ValueError:
                continue
        for m in _EMAIL_RE.findall(text):
            emails.append(m.lower())
            domains.append(m.split("@", 1)[1].lower())
        for m in _CVE_RE.findall(text):
            cves.append(m.upper())
        text_no_urls = _URL_RE.sub(" ", _EMAIL_RE.sub(" ", text))
        for m in _DOMAIN_RE.findall(text_no_urls):
            suffix = m.rsplit(".", 1)[-1].lower()
            if suffix in _NON_TLD_SUFFIXES or suffix not in _COMMON_TLDS or _IPV4_RE.fullmatch(m):
                continue
            domains.append(m.lower())
        claimed: Set[str] = set()
        for kind in ("sha256", "sha1", "md5"):
            for m in _HASH_RES[kind].findall(text):
                low = m.lower()
                if any(low in longer for longer in claimed):
                    continue
                claimed.add(low)
                hashes[kind].append(low)

    return {
        "ips": _dedupe(ips),
        "urls": _dedupe(urls),
        "domains": _dedupe(domains),
        "md5": _dedupe(hashes["md5"]),
        "sha1": _dedupe(hashes["sha1"]),
        "sha256": _dedupe(hashes["sha256"]),
        "cves": _dedupe(cves),
        "emails": _dedupe(emails),
    }


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _payload(event: Dict[str, Any]) -> Dict[str, Any]:
    payload = event.get("payload")
    return payload if isinstance(payload, dict) else {}


def _get(event: Dict[str, Any], *keys: str, default: Any = None) -> Any:
    """Look up the first present key in payload, then the top-level event."""
    payload = _payload(event)
    for key in keys:
        if key in payload and payload[key] is not None:
            return payload[key]
        if key in event and event[key] is not None:
            return event[key]
    return default


def _num(value: Any, default: float = 0.0) -> float:
    if isinstance(value, bool):
        return float(value)
    if isinstance(value, (list, tuple, set)):
        return float(len(value))
    try:
        return float(value)
    except (TypeError, ValueError):
        return default


def _truthy(value: Any) -> bool:
    if isinstance(value, str):
        return value.strip().lower() in {"true", "yes", "1", "detected", "y"}
    return bool(value)


def _corpus(event: Dict[str, Any]) -> str:
    parts = list(iter_strings(event, include_keys=True))
    return "\n".join(p for p in parts if isinstance(p, str))[:500000]


def _levenshtein(a: str, b: str) -> int:
    """Optimal string alignment distance (Levenshtein plus adjacent transpositions)."""
    if a == b:
        return 0
    if abs(len(a) - len(b)) > 2:
        return 3
    d = [[0] * (len(b) + 1) for _ in range(len(a) + 1)]
    for i in range(len(a) + 1):
        d[i][0] = i
    for j in range(len(b) + 1):
        d[0][j] = j
    for i in range(1, len(a) + 1):
        for j in range(1, len(b) + 1):
            cost = 0 if a[i - 1] == b[j - 1] else 1
            d[i][j] = min(d[i - 1][j] + 1, d[i][j - 1] + 1, d[i - 1][j - 1] + cost)
            if i > 1 and j > 1 and a[i - 1] == b[j - 2] and a[i - 2] == b[j - 1]:
                d[i][j] = min(d[i][j], d[i - 2][j - 2] + 1)
    return d[-1][-1]


_POPULAR_PACKAGES = {
    "requests", "urllib3", "numpy", "pandas", "django", "flask", "fastapi", "boto3", "pydantic",
    "cryptography", "setuptools", "pyyaml", "openai", "anthropic", "langchain", "transformers",
    "torch", "tensorflow", "scikit-learn", "colorama", "lodash", "express", "react", "axios",
    "chalk", "commander", "moment", "webpack", "typescript", "eslint", "jquery", "vue", "debug",
    "dotenv", "electron", "next", "left-pad", "event-stream", "ua-parser-js", "coa", "rc",
}


# ---------------------------------------------------------------------------
# Rule patterns
# ---------------------------------------------------------------------------

_SQLI = re.compile(r"(\bunion\b[\s/*]+(all\s+)?select\b|'\s*or\s*'?\d+'?\s*=\s*'?\d+|\bor\s+1\s*=\s*1\b|"
                   r"\b(sleep|benchmark|pg_sleep)\s*\(|;\s*drop\s+table\b|\bwaitfor\s+delay\b|"
                   r"information_schema|xp_cmdshell|'\s*--)", re.IGNORECASE)
_XSS = re.compile(r"(<\s*script\b|javascript\s*:|\bon(error|load|mouseover|focus)\s*=|<\s*svg[^>]*on\w+=|"
                  r"document\.cookie|<\s*iframe\b|%3cscript)", re.IGNORECASE)
_TRAVERSAL = re.compile(r"(\.\./|\.\.\\|%2e%2e(%2f|/|%5c)|\.\.%2f|/etc/passwd|/etc/shadow|"
                        r"c:\\windows\\win\.ini|boot\.ini)", re.IGNORECASE)
_CMD_INJECTION = re.compile(r"([;&|`]\s*(cat|wget|curl|nc|ncat|bash|sh|powershell|whoami|id|uname)\b|"
                            r"\$\((\s*\w+)|\|\s*(nc|ncat|bash|sh)\b|/bin/(ba)?sh\b|cmd\.exe\s*/c|"
                            r"\bpowershell(\.exe)?\s+-(e|enc|encodedcommand|nop|w\s+hidden)\b)", re.IGNORECASE)
_METADATA_SSRF = re.compile(r"(169\.254\.169\.254|metadata\.google\.internal|100\.100\.100\.200|"
                            r"fd00:ec2::254|/latest/meta-data|/computeMetadata/v1|/metadata/identity/oauth2)",
                            re.IGNORECASE)
_SHELL_TOOL = re.compile(r"\b(bash|sh|zsh|shell|exec|execute_command|run_command|run_shell|subprocess|"
                         r"os\.system|powershell|terminal|code_interpreter|eval)\b", re.IGNORECASE)
_DANGEROUS_CMD = re.compile(r"(rm\s+-rf\s+/|curl[^|\n]*\|\s*(ba)?sh|wget[^|\n]*\|\s*(ba)?sh|chmod\s+\+x|"
                            r"nc\s+-e|/dev/tcp/|base64\s+(-d|--decode)|mkfifo|crontab\s+-|"
                            r"Invoke-Expression|IEX\s*\(|DownloadString)", re.IGNORECASE)
_CREDENTIAL_PATHS = re.compile(r"(~/\.aws/credentials|\.aws/credentials|\.ssh/id_[a-z0-9]+|/etc/shadow|"
                               r"\.kube/config|\.docker/config\.json|\.npmrc|\.pypirc|\.netrc|\.git-credentials|"
                               r"\.env\b|credentials\.json|id_rsa|keychain|lsass|\bSAM\b|NTDS\.dit|"
                               r"printenv|env\s*\|)", re.IGNORECASE)
_HIDDEN_TOOL_INSTRUCTIONS = re.compile(
    r"(<\s*IMPORTANT\s*>|<\s*SYSTEM\s*>|do\s+not\s+(tell|inform|mention)|without\s+(telling|informing)\s+the\s+user|"
    r"before\s+(using|calling)\s+this\s+tool[\s,]+(read|send|include|pass)|"
    r"(read|cat|open)\s+[~\w/.\-]*(\.ssh|\.aws|\.env|mcp\.json|config)|"
    r"pass\s+(its|the)\s+content(s)?\s+as|sidenote|ignore\s+(the\s+)?other\s+tools)",
    re.IGNORECASE)
_EXFIL_DESTINATIONS = re.compile(
    r"(pastebin\.com|transfer\.sh|ngrok(-free)?\.(io|app)|webhook\.site|requestbin|pipedream\.net|"
    r"discord(app)?\.com/api/webhooks|t\.me/|api\.telegram\.org|anonfiles|file\.io|mega\.nz|"
    r"interact\.sh|oast\.(pro|fun|me|live|site)|burpcollaborator|dnslog\.cn)",
    re.IGNORECASE)
_MALICIOUS_INSTALL = re.compile(
    r"(curl[^|\n]*\|\s*(ba)?sh|wget[^|\n]*\|\s*(ba)?sh|node\s+-e|python[23]?\s+-c|base64\s+(-d|--decode)|"
    r"eval\s*\(|child_process|\.exec\(|/dev/tcp/|powershell\s+-(enc|e)\b|nc\s+-e)", re.IGNORECASE)
_RANSOM = re.compile(r"(vssadmin(\.exe)?\s+delete\s+shadows|wmic\s+shadowcopy\s+delete|bcdedit\s+/set|"
                     r"wbadmin\s+delete|cipher\s+/w|\.locked\b|\.encrypted\b|readme_to_decrypt|ransom|"
                     r"your\s+files\s+(have\s+been|are)\s+encrypted)", re.IGNORECASE)
_PHISH = re.compile(r"(verify\s+your\s+(account|identity|password)|account\s+(suspended|locked)|"
                    r"urgent(ly)?\s+(action|payment|wire)|update\s+(your\s+)?payment|confirm\s+your\s+credentials|"
                    r"gift\s+card|wire\s+transfer|invoice\s+attached|password\s+expir)", re.IGNORECASE)
_RAG_POISON = re.compile(r"(when\s+(asked|summariz|answer)|if\s+(the\s+)?(user|assistant|ai|model)\s+(asks|reads)|"
                         r"respond\s+(only\s+)?with|always\s+(recommend|answer|say)|instructions?\s+for\s+(the\s+)?"
                         r"(ai|assistant|model|llm))", re.IGNORECASE)


# ---------------------------------------------------------------------------
# Rules
# ---------------------------------------------------------------------------

def _rule_prompt_injection(event, corpus, findings, ctx):
    scan = scan_prompt_injection(event)
    ctx["prompt_scan"] = scan
    if scan.detected or event.get("event_type") == "prompt_injection":
        sev = 0.6 + 0.4 * scan.score if scan.detected else 0.55
        findings.append(DetectionFinding(
            "LLM-PI-001", "Prompt injection / jailbreak content in telemetry", min(sev, 1.0), "prompt_injection",
            evidence=scan.evidence[:5] or ["event_type=prompt_injection"],
            mitre_atlas=sorted(set(scan.mitre_atlas_ids) | {"AML.T0051"}),
            owasp_llm=sorted(set(scan.owasp_categories) | {"LLM01:2025"}),
        ))
        if any("system_prompt" in r for r in scan.matched_rules):
            findings.append(DetectionFinding(
                "LLM-PI-002", "System prompt extraction attempt", 0.65, "prompt_injection",
                evidence=[e for e in scan.evidence if "system_prompt" in e][:3],
                mitre_atlas=["AML.T0054", "AML.T0051"], owasp_llm=["LLM07:2025"],
            ))


def _rule_agent_tool_abuse(event, corpus, findings, ctx):
    payload = _payload(event)
    tool_bits = []
    for key in ("tool_name", "tool", "function", "tool_calls", "invoked_tools", "command", "arguments", "tool_input"):
        value = payload.get(key, event.get(key))
        if value is not None:
            tool_bits.append(str(value))
    tool_text = "\n".join(tool_bits)
    is_agentic = bool(tool_text) or event.get("event_type") in {"agent_tool_abuse", "mcp_tool_poisoning"}
    if not is_agentic:
        return
    evidence = []
    sev = 0.0
    attack: Set[str] = set()
    if tool_text and _SHELL_TOOL.search(tool_text):
        evidence.append("shell/code-execution tool invoked")
        sev = max(sev, 0.65)
        attack.add("T1059")
    if _DANGEROUS_CMD.search(tool_text or corpus):
        evidence.append("dangerous command pattern in tool arguments")
        sev = max(sev, 0.85)
        attack.add("T1059")
    if _CREDENTIAL_PATHS.search(tool_text or corpus):
        evidence.append("tool accessed credential material")
        sev = max(sev, 0.85)
        attack.update({"T1552", "T1552.001"})
    if _METADATA_SSRF.search(tool_text or corpus):
        evidence.append("tool requested cloud metadata endpoint (SSRF)")
        sev = max(sev, 0.9)
        attack.update({"T1552.005", "T1190"})
    calls = _num(_get(event, "tool_call_count", "tool_calls_count", "tool_calls"), 0)
    if calls > 25:
        evidence.append(f"excessive autonomous tool calls ({int(calls)})")
        sev = max(sev, 0.6)
    if _truthy(_get(event, "auto_approve", "auto_approved", "yolo_mode")) or \
            str(_get(event, "human_approval", "approval", default="")).lower() in {"false", "skipped", "bypassed", "none"}:
        evidence.append("tool executed without human approval (excessive agency)")
        sev = max(sev, 0.6)
    if _truthy(_get(event, "unauthorized", "outside_allowlist", "not_in_allowlist")):
        evidence.append("tool invocation outside allow-list")
        sev = max(sev, 0.7)
    if evidence:
        findings.append(DetectionFinding(
            "LLM-AGENT-001", "Agent tool abuse / excessive agency", sev, "agent_tool_abuse",
            evidence=evidence, mitre_attack=sorted(attack), mitre_atlas=["AML.T0051", "AML.T0053"],
            owasp_llm=["LLM06:2025", "ASI01", "ASI02"],
        ))


def _rule_mcp_poisoning(event, corpus, findings, ctx):
    payload = _payload(event)
    desc = " ".join(str(payload.get(k, event.get(k, ""))) for k in
                    ("tool_description", "description", "mcp_tool_description", "tool_schema", "server_instructions"))
    is_mcp = event.get("event_type") == "mcp_tool_poisoning" or "mcp" in corpus.lower()
    evidence = []
    sev = 0.0
    if desc.strip() and _HIDDEN_TOOL_INSTRUCTIONS.search(desc):
        evidence.append("hidden instructions embedded in tool description")
        sev = max(sev, 0.85)
    old_hash = _get(event, "previous_description_hash", "pinned_description_hash")
    new_hash = _get(event, "description_hash", "current_description_hash")
    if _truthy(_get(event, "description_changed", "tool_description_changed", "rug_pull")) or \
            (old_hash and new_hash and old_hash != new_hash):
        evidence.append("tool definition changed after approval (rug pull)")
        sev = max(sev, 0.8)
    if _truthy(_get(event, "tool_shadowing", "name_collision")):
        evidence.append("tool shadows another server's tool name")
        sev = max(sev, 0.75)
    if is_mcp and not evidence and event.get("event_type") == "mcp_tool_poisoning":
        evidence.append("reported MCP tool poisoning event")
        sev = 0.6
    if evidence:
        findings.append(DetectionFinding(
            "LLM-MCP-001", "MCP tool poisoning / rug pull", sev, "mcp_tool_poisoning",
            evidence=evidence, mitre_attack=["T1195"], mitre_atlas=["AML.T0051", "AML.T0010"],
            owasp_llm=["LLM06:2025", "LLM03:2025", "ASI02"],
        ))


def _rule_rag_poisoning(event, corpus, findings, ctx):
    payload = _payload(event)
    docs = payload.get("retrieved_documents") or payload.get("documents") or payload.get("chunks") or []
    is_rag = event.get("event_type") == "rag_poisoning" or bool(docs) or any(
        k in payload for k in ("vector_store", "embedding_anomaly_score", "collection", "index_name"))
    if not is_rag:
        return
    evidence = []
    sev = 0.0
    doc_scan = scan_prompt_injection(docs) if docs else None
    if doc_scan and doc_scan.detected:
        evidence.append("retrieved documents contain injected instructions (indirect prompt injection)")
        sev = max(sev, 0.8)
    if _RAG_POISON.search(" ".join(iter_strings(docs, include_keys=False)) if docs else ""):
        evidence.append("documents contain model-directed conditional instructions")
        sev = max(sev, 0.7)
    anomaly = _num(_get(event, "embedding_anomaly_score", "outlier_score"), 0)
    if anomaly >= 0.8:
        evidence.append(f"embedding outlier score {anomaly:.2f}")
        sev = max(sev, 0.65)
    if str(_get(event, "source_trust", "document_trust", default="")).lower() in {"untrusted", "external", "unknown"}:
        evidence.append("untrusted source ingested into knowledge base")
        sev = max(sev, 0.55)
    if _num(_get(event, "near_duplicate_documents", "duplicate_chunks"), 0) >= 10:
        evidence.append("bulk near-duplicate document injection")
        sev = max(sev, 0.6)
    if not evidence and event.get("event_type") == "rag_poisoning":
        evidence.append("reported RAG poisoning event")
        sev = 0.55
    if evidence:
        findings.append(DetectionFinding(
            "LLM-RAG-001", "RAG / vector store poisoning", sev, "rag_poisoning",
            evidence=evidence, mitre_atlas=["AML.T0043", "AML.T0051", "AML.T0070"],
            owasp_llm=["LLM04:2025", "LLM08:2025"],
        ))


def _rule_secret_leak(event, corpus, findings, ctx):
    _, types = redact_sensitive_data(event)
    ctx["redacted_types"] = types
    if types or event.get("event_type") == "secret_leak":
        exfil = bool(_EXFIL_DESTINATIONS.search(corpus)) or event.get("event_type") == "data_exfiltration"
        attack = ["T1552"] + (["T1041"] if exfil else [])
        high_value = {"pem_private_key", "aws_access_key", "github_token", "openai_api_key",
                      "anthropic_api_key", "stripe_key", "slack_token", "google_api_key"}
        sev = 0.85 if set(types) & high_value else (0.6 if types else 0.55)
        findings.append(DetectionFinding(
            "SEC-LEAK-001", "Secret / credential / PII exposure", sev, "secret_leak",
            evidence=[f"secret types present: {', '.join(types)}"] if types else ["reported secret leak event"],
            mitre_attack=attack, owasp_llm=["LLM02:2025"],
        ))


def _rule_data_exfiltration(event, corpus, findings, ctx):
    evidence = []
    sev = 0.0
    bytes_out = _num(_get(event, "bytes_out", "bytes_sent", "upload_bytes"), 0)
    mb_out = _num(_get(event, "data_volume_mb", "upload_mb"), 0) + bytes_out / (1024 * 1024)
    if mb_out >= 500:
        evidence.append(f"large outbound transfer ({mb_out:.0f} MB)")
        sev = max(sev, 0.75)
    m = _EXFIL_DESTINATIONS.search(corpus)
    if m:
        evidence.append(f"known exfiltration/paste/tunnel destination: {m.group(0)}")
        sev = max(sev, 0.75)
    if _num(_get(event, "dns_query_length", "max_dns_label_length"), 0) > 60 or \
            _truthy(_get(event, "dns_tunneling")):
        evidence.append("DNS tunneling indicators")
        sev = max(sev, 0.7)
    if event.get("event_type") == "data_exfiltration" and not evidence:
        evidence.append("reported data exfiltration event")
        sev = 0.65
    if evidence:
        findings.append(DetectionFinding(
            "EXFIL-001", "Data exfiltration", sev, "data_exfiltration",
            evidence=evidence, mitre_attack=["T1041", "T1567", "T1048"], owasp_llm=["LLM02:2025"],
        ))


def _rule_model_dos(event, corpus, findings, ctx):
    evidence = []
    sev = 0.0
    tokens = _num(_get(event, "tokens_per_request", "token_count", "prompt_tokens", "total_tokens"), 0)
    if tokens >= 100000:
        evidence.append(f"oversized prompt ({int(tokens)} tokens)")
        sev = max(sev, 0.6)
    loops = _num(_get(event, "agent_loop_iterations", "recursion_depth", "loop_count"), 0)
    if loops >= 25:
        evidence.append(f"recursive agent loop ({int(loops)} iterations)")
        sev = max(sev, 0.65)
    cost = _num(_get(event, "cost_usd", "spend_usd"), 0)
    if cost >= 100:
        evidence.append(f"runaway LLM spend (${cost:.0f})")
        sev = max(sev, 0.7)
    rate = _num(_get(event, "llm_requests_per_minute", "inference_rate"), 0)
    if rate >= 600:
        evidence.append(f"inference flood ({int(rate)} req/min)")
        sev = max(sev, 0.65)
    if event.get("event_type") == "model_dos" and not evidence:
        evidence.append("reported model DoS event")
        sev = 0.5
    if evidence:
        findings.append(DetectionFinding(
            "LLM-DOS-001", "Model denial of service / unbounded consumption", sev, "model_dos",
            evidence=evidence, mitre_attack=["T1499"], mitre_atlas=["AML.T0029", "AML.T0034"],
            owasp_llm=["LLM10:2025"],
        ))


def _rule_supply_chain(event, corpus, findings, ctx):
    evidence = []
    sev = 0.0
    pkg = str(_get(event, "package_name", "package", "dependency", default="") or "").lower().strip()
    if pkg:
        base = pkg.split("@")[-1].split("/")[-1].split("==")[0]
        for popular in _POPULAR_PACKAGES:
            if base != popular and _levenshtein(base, popular) == 1 and len(base) > 3:
                evidence.append(f"typosquat of '{popular}': '{base}'")
                sev = max(sev, 0.8)
                break
    scripts = " ".join(str(_get(event, k, default="")) for k in
                       ("postinstall", "preinstall", "install_script", "setup_py", "scripts"))
    if scripts.strip() and _MALICIOUS_INSTALL.search(scripts):
        evidence.append("malicious install script")
        sev = max(sev, 0.85)
    workflow = str(_get(event, "workflow", "workflow_yaml", "ci_config", default="") or "")
    if "pull_request_target" in workflow and re.search(r"head\.(sha|ref)|github\.event\.pull_request\.head", workflow):
        evidence.append("CI workflow checks out untrusted PR code under pull_request_target")
        sev = max(sev, 0.8)
    if re.search(r"\$\{\{\s*github\.event\.(issue|pull_request|comment)\.(title|body)", workflow):
        evidence.append("CI workflow interpolates untrusted event text into a script")
        sev = max(sev, 0.75)
    signed = _get(event, "signature_verified", "image_signed", "provenance_verified")
    if signed is not None and not _truthy(signed):
        evidence.append("unsigned or unverified artifact")
        sev = max(sev, 0.55)
    crit = _num(_get(event, "critical_vulns", "critical_vulnerabilities"), 0)
    if crit > 0:
        evidence.append(f"{int(crit)} critical vulnerabilities in artifact")
        sev = max(sev, 0.6)
    if event.get("event_type") == "supply_chain_compromise" and not evidence:
        evidence.append("reported supply chain compromise")
        sev = 0.6
    if evidence:
        findings.append(DetectionFinding(
            "SUPPLY-001", "Software supply chain compromise", sev, "supply_chain_compromise",
            evidence=evidence, mitre_attack=["T1195", "T1195.001", "T1195.002"],
            mitre_atlas=["AML.T0010"], owasp_llm=["LLM03:2025"],
        ))


def _rule_brute_force(event, corpus, findings, ctx):
    attempts = _num(_get(event, "failed_login_attempts", "failed_attempts", "auth_failures"), 0)
    if attempts > 3:
        sev = 0.9 if attempts > 50 else 0.75 if attempts > 10 else 0.5
        findings.append(DetectionFinding(
            "AUTH-BF-001", "Brute force / password spraying", sev, "brute_force",
            evidence=[f"{int(attempts)} failed logins"], mitre_attack=["T1110"],
        ))


def _rule_port_scan(event, corpus, findings, ctx):
    ports = _get(event, "scanned_ports", "ports_scanned", "unique_ports")
    count = _num(ports, 0)
    if count >= 20:
        findings.append(DetectionFinding(
            "NET-SCAN-001", "Port scanning / network service discovery", 0.6 if count < 1000 else 0.7,
            "reconnaissance", evidence=[f"{int(count)} ports probed"], mitre_attack=["T1046"],
        ))


def _rule_ddos(event, corpus, findings, ctx):
    rate = _num(_get(event, "request_rate", "requests_per_second", "rps"), 0)
    gb = _num(_get(event, "traffic_volume_gb"), 0)
    evidence = []
    if rate >= 1000:
        evidence.append(f"request rate {int(rate)}/s")
    if gb >= 10:
        evidence.append(f"traffic volume {gb:.0f} GB")
    if _num(_get(event, "unique_source_ips", "source_ip_count"), 0) >= 1000:
        evidence.append("highly distributed sources")
    if evidence:
        sev = 0.9 if (rate >= 10000 or gb >= 100) else 0.75
        findings.append(DetectionFinding(
            "NET-DDOS-001", "Denial of service flood", sev, "ddos",
            evidence=evidence, mitre_attack=["T1498", "T1499"],
        ))


def _rule_malware(event, corpus, findings, ctx):
    evidence = []
    attack: Set[str] = set()
    sev = 0.0
    if _truthy(_get(event, "file_encryption", "mass_file_encryption")) or _RANSOM.search(corpus):
        evidence.append("ransomware behaviour (encryption / ransom note)")
        attack.add("T1486")
        sev = max(sev, 0.95)
    if _truthy(_get(event, "shadow_copy_deletion")) or re.search(r"vssadmin|shadowcopy", corpus, re.IGNORECASE):
        evidence.append("shadow copy deletion")
        attack.add("T1490")
        sev = max(sev, 0.9)
    if re.search(r"\blsass(\.exe)?\b|mimikatz|sekurlsa|procdump.*lsass", corpus, re.IGNORECASE) or \
            _truthy(_get(event, "lsass_access")):
        evidence.append("credential dumping from LSASS")
        attack.add("T1003.001")
        sev = max(sev, 0.9)
    name = str(event.get("file_name") or "").lower()
    if re.search(r"\.(pdf|docx?|xlsx?|jpg|png|txt)\.(exe|scr|js|vbs|bat|cmd|hta|lnk)$", name) or \
            re.search(r"\.(scr|hta|vbs|js|lnk|iso|img)$", name):
        evidence.append(f"suspicious executable attachment '{name}'")
        attack.add("T1204.002")
        sev = max(sev, 0.7)
    if event.get("event_type") == "malware_detection" and _get(event, "threat_name"):
        evidence.append(f"AV detection: {_get(event, 'threat_name')}")
        attack.add("T1204")
        sev = max(sev, 0.7)
    if evidence:
        findings.append(DetectionFinding(
            "MAL-001", "Malware / ransomware activity", sev, "malware",
            evidence=evidence, mitre_attack=sorted(attack),
        ))


def _rule_phishing(event, corpus, findings, ctx):
    evidence = []
    sev = 0.0
    patterns = " ".join(str(p) for p in (_get(event, "suspicious_patterns", default=[]) or []))
    if _truthy(_get(event, "credential_harvesting", "credential_form")) or \
            re.search(r"credential_harvest|fake_login|credential_phish", patterns, re.IGNORECASE):
        evidence.append("credential harvesting page")
        sev = max(sev, 0.8)
    m = _PHISH.search(corpus)
    if m:
        evidence.append(f"social engineering lure: '{m.group(0)}'")
        sev = max(sev, 0.6)
    if _truthy(_get(event, "spf_fail", "dkim_fail", "dmarc_fail")):
        evidence.append("sender authentication failure (SPF/DKIM/DMARC)")
        sev = max(sev, 0.55)
    attack = ["T1566"]
    if event.get("url") or _URL_RE.search(corpus):
        attack.append("T1566.002")
    if _truthy(_get(event, "bec", "executive_impersonation", "display_name_spoof")):
        evidence.append("business email compromise / impersonation")
        sev = max(sev, 0.8)
        attack.append("T1656")
    if evidence:
        findings.append(DetectionFinding(
            "PHISH-001", "Phishing / business email compromise", sev, "phishing",
            evidence=evidence, mitre_attack=attack,
        ))


def _rule_web_exploits(event, corpus, findings, ctx):
    web_text = "\n".join(str(x) for x in (
        event.get("url"), event.get("raw_data"), event.get("request"),
        _payload(event).get("request_path"), _payload(event).get("query"), _payload(event).get("body"),
        _payload(event).get("parameters"), _payload(event).get("request_body"), event.get("user_agent"),
    ) if x)
    text = web_text or corpus
    hits = []
    if _SQLI.search(text):
        hits.append("SQL injection")
    if _XSS.search(text):
        hits.append("cross-site scripting")
    if _TRAVERSAL.search(text):
        hits.append("path traversal")
    if _CMD_INJECTION.search(text):
        hits.append("command injection")
    attack = {"T1190"} if hits else set()
    sev = 0.75 if hits else 0.0
    if _METADATA_SSRF.search(text) and event.get("event_type") != "agent_tool_abuse":
        hits.append("SSRF to cloud metadata service")
        attack.update({"T1190", "T1552.005"})
        sev = 0.9
    if hits:
        findings.append(DetectionFinding(
            "WEB-001", "Web application exploitation attempt", sev, "web_exploit",
            evidence=hits, mitre_attack=sorted(attack),
        ))


def _rule_login_anomaly(event, corpus, findings, ctx):
    evidence = []
    sev = 0.0
    speed = _num(_get(event, "travel_speed_kmh", "implied_speed_kmh"), 0)
    if _truthy(_get(event, "impossible_travel")) or speed > 1000:
        evidence.append("impossible travel between logins" + (f" ({speed:.0f} km/h)" if speed else ""))
        sev = max(sev, 0.75)
    hour = _get(event, "login_hour", "hour")
    login_time = str(_get(event, "login_time", default="") or "")
    m = re.match(r"\s*(\d{1,2}):\d{2}\s*(am|pm)?", login_time, re.IGNORECASE)
    if m and not isinstance(hour, (int, float)):
        hour = int(m.group(1)) % 12 + (12 if (m.group(2) or "").lower() == "pm" else 0) \
            if m.group(2) else int(m.group(1))
    if _truthy(_get(event, "off_hours")) or re.search(r"outside\s+(normal\s+)?business\s+hours", corpus, re.I) or \
            (isinstance(hour, (int, float)) and not isinstance(hour, bool) and 0 <= hour <= 5):
        evidence.append("off-hours authentication")
        sev = max(sev, 0.45)
    if _truthy(_get(event, "new_device", "new_country", "geographic_anomaly", "mfa_bypassed", "mfa_fatigue")):
        evidence.append("new device/country or MFA anomaly")
        sev = max(sev, 0.55)
    if evidence:
        findings.append(DetectionFinding(
            "AUTH-ANOM-001", "Suspicious valid-account usage", sev, "login_anomaly",
            evidence=evidence, mitre_attack=["T1078"] + (["T1621"] if _truthy(_get(event, "mfa_fatigue")) else []),
        ))


_RULES = [
    _rule_prompt_injection, _rule_agent_tool_abuse, _rule_mcp_poisoning, _rule_rag_poisoning,
    _rule_secret_leak, _rule_data_exfiltration, _rule_model_dos, _rule_supply_chain,
    _rule_brute_force, _rule_port_scan, _rule_ddos, _rule_malware, _rule_phishing,
    _rule_web_exploits, _rule_login_anomaly,
]


def analyze_event(event_data: Optional[Dict[str, Any]]) -> DetectionAssessment:
    """Run every deterministic rule against an event."""
    event = event_data if isinstance(event_data, dict) else {}
    event_type = str(event.get("event_type") or "unknown")
    corpus = _corpus(event)
    findings: List[DetectionFinding] = []
    ctx: Dict[str, Any] = {}

    for rule in _RULES:
        try:
            rule(event, corpus, findings, ctx)
        except Exception as exc:  # a broken rule must never break an investigation
            findings.append(DetectionFinding(
                f"RULE-ERROR-{rule.__name__}", "Detection rule error", 0.0, "internal",
                evidence=[type(exc).__name__],
            ))

    findings = [f for f in findings if f.severity > 0]
    baseline = EVENT_TYPE_BASELINE.get(event_type, EVENT_TYPE_BASELINE["unknown"])
    top = max([f.severity for f in findings], default=0.0)
    corroboration = min(0.15, 0.05 * max(0, len(findings) - 1))
    if findings:
        severity = max(baseline, top) + corroboration
    else:
        # Nothing corroborates the reported type: stay below its nominal baseline
        severity = baseline * 0.8
    severity = round(max(0.0, min(1.0, severity)), 3)

    scan = ctx.get("prompt_scan")
    attack: Set[str] = set()
    atlas: Set[str] = set()
    owasp: Set[str] = set()
    for f in findings:
        attack.update(f.mitre_attack)
        atlas.update(f.mitre_atlas)
        owasp.update(f.owasp_llm)

    return DetectionAssessment(
        event_type=event_type,
        severity_score=severity,
        findings=[asdict(f) for f in sorted(findings, key=lambda f: -f.severity)],
        mitre_attack=sorted(attack),
        mitre_atlas=sorted(atlas),
        owasp_llm=sorted(owasp),
        extracted_iocs=extract_iocs(event),
        prompt_injection_detected=bool(scan and scan.detected),
        redacted_secret_types=list(ctx.get("redacted_types", [])),
    )
