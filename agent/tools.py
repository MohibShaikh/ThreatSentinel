"""
SOC Agent Tools - threat intelligence sources and the tool registry.

Three kinds of tools:

* Local forensics: offline analysis of IPs, URLs and hashes. Always on, never
  claims external reputation.
* Keyless public intel: Shodan InternetDB, RDAP and the CISA KEV catalog.
  Free, no key. Enabled by default; only ever sent public IPs.
* Keyed intel: VirusTotal (v3), AbuseIPDB, URLVoid, Shodan. Used when a real
  key is configured.
"""

import asyncio
import base64
import copy
import ipaddress
import logging
import math
import re
import time
from collections import Counter
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Set, Union
from urllib.parse import quote, urlsplit

import aiohttp
import validators

from .guardrails import is_public_ip

try:  # Hardened XML parser (no DTDs, no entity expansion)
    from defusedxml import ElementTree as SafeET
    from defusedxml.common import DefusedXmlException
except ImportError:  # pragma: no cover - fallback when defusedxml is absent
    SafeET = None

    class DefusedXmlException(ValueError):
        pass

DEFAULT_TIMEOUT_SECONDS = 15
NON_PUBLIC_SKIP_ERROR = "Skipped external lookup for non-public IP"

_PLACEHOLDER_RE = re.compile(
    r"^(your[_\-].*|.*_here|changeme|change[_\-]me|placeholder|xxx+|none|null|todo|dummy|test|example|<.*>)$",
    re.IGNORECASE,
)


def is_configured_api_key(key: Optional[str]) -> bool:
    """True when ``key`` looks like a real credential rather than a template value."""
    if not key or not isinstance(key, str):
        return False
    key = key.strip()
    if not key or _PLACEHOLDER_RE.match(key):
        return False
    return "placeholder" not in key.lower()


def _parse_xml(body: str):
    """Parse untrusted XML without DTD/entity processing."""
    if SafeET is not None:
        return SafeET.fromstring(body, forbid_dtd=True, forbid_entities=True, forbid_external=True)
    if "<!DOCTYPE" in body.upper() or "<!ENTITY" in body.upper():  # pragma: no cover
        raise DefusedXmlException("DTD/entity declarations are not allowed")
    import xml.etree.ElementTree as ET  # noqa: S405 - DTDs rejected above  # pragma: no cover
    return ET.fromstring(body)  # noqa: S314  # pragma: no cover


@dataclass
class ToolResult:
    """Standardized result format for all tool operations"""
    success: bool
    source: str
    data: Dict[str, Any]
    error: Optional[str] = None
    timestamp: Optional[datetime] = None

    def __post_init__(self):
        if self.timestamp is None:
            self.timestamp = datetime.now(timezone.utc)


class _RateLimiter:
    """Shared, lock-protected minimum-interval limiter."""

    def __init__(self, per_minute: float):
        self.interval = 60.0 / per_minute if per_minute and per_minute > 0 else 0.0
        self._last = 0.0
        self._lock = asyncio.Lock()

    async def wait(self):
        if not self.interval:
            return
        async with self._lock:
            elapsed = time.monotonic() - self._last
            if elapsed < self.interval:
                await asyncio.sleep(self.interval - elapsed)
            self._last = time.monotonic()


class BaseTool:
    """Base class for all intelligence tools.

    A tool owns no network state shared between investigations. The registry
    calls :meth:`with_session` to get a per-query clone bound to a session it
    owns. ``async with tool:`` still works for standalone use.
    """

    TOOL_NAME = "base"
    REQUIRES_API_KEY = True
    IS_EXTERNAL = True            # sends data off-box
    PROVIDES_REPUTATION = True    # its score means "known bad", not just enrichment
    SUPPORTS: frozenset = frozenset()

    def __init__(self, api_key: str = "", config: Optional[Dict[str, Any]] = None):
        self.api_key = api_key or ""
        self.config = config or {}
        self.timeout = aiohttp.ClientTimeout(total=self.config.get("timeout", DEFAULT_TIMEOUT_SECONDS))
        self.logger = logging.getLogger(f"{__name__}.{self.__class__.__name__}")
        self._session: Optional[aiohttp.ClientSession] = None

    async def __aenter__(self):
        self._session = aiohttp.ClientSession(timeout=self.timeout)
        return self

    async def __aexit__(self, exc_type, exc_val, exc_tb):
        if self._session:
            await self._session.close()

    def with_session(self, session: Optional[aiohttp.ClientSession]) -> "BaseTool":
        clone = copy.copy(self)
        clone._session = session
        return clone

    def _result(self, success: bool, data: Optional[Dict[str, Any]] = None,
                error: Optional[str] = None) -> ToolResult:
        return ToolResult(success=success, source=self.TOOL_NAME, data=data or {}, error=error)

    def _not_supported(self, what: str) -> ToolResult:
        return self._result(False, error=f"{what} checking not supported by {self.TOOL_NAME}")

    def _missing_key(self) -> ToolResult:
        return self._result(False, error=f"{self.TOOL_NAME} API key not configured")

    def _require_session(self) -> aiohttp.ClientSession:
        if self._session is None or self._session.closed:
            raise RuntimeError("Tool used outside a session; use 'async with tool' or the registry")
        return self._session

    async def query_ip(self, ip: str) -> ToolResult:
        return self._not_supported("IP")

    async def query_url(self, url: str) -> ToolResult:
        return self._not_supported("URL")

    async def query_file_hash(self, file_hash: str) -> ToolResult:
        return self._not_supported("File hash")


# ---------------------------------------------------------------------------
# Local forensics (offline, always on)
# ---------------------------------------------------------------------------

_KNOWN_HASHES = {
    "44d88612fea8a8f36de82e1278abb02f": ("EICAR antivirus test file", 0.2),
    "3395856ce81f2b7382dee72602f798b642f14140": ("EICAR antivirus test file", 0.2),
    "275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f": ("EICAR antivirus test file", 0.2),
    "d41d8cd98f00b204e9800998ecf8427e": ("Empty file (zero bytes)", 0.0),
    "da39a3ee5e6b4b0d3255bfef95601890afd80709": ("Empty file (zero bytes)", 0.0),
    "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855": ("Empty file (zero bytes)", 0.0),
}
_HASH_TYPES = {32: "md5", 40: "sha1", 64: "sha256", 128: "sha512"}
_SUSPICIOUS_TLDS = {
    "tk", "ml", "ga", "cf", "gq", "xyz", "top", "zip", "mov", "click", "country", "kim", "work",
    "loan", "men", "gdn", "racing", "review", "stream", "download", "icu", "cyou", "rest", "buzz",
    "monster", "quest", "sbs", "cfd", "lol", "pw",
}
_SENSITIVE_PATHS = re.compile(
    r"(/\.env\b|/\.git(/|$)|/wp-admin|/wp-login|/admin\b|/phpmyadmin|/\.aws|/\.ssh|/server-status|"
    r"/actuator|/console|/etc/passwd|/cgi-bin|/xmlrpc\.php|/\.DS_Store|/backup|\.sql\b|\.bak\b)",
    re.IGNORECASE,
)
_BRANDS = ("paypal", "microsoft", "office365", "outlook", "apple", "icloud", "amazon", "google",
           "netflix", "facebook", "instagram", "linkedin", "dropbox", "docusign", "coinbase",
           "binance", "metamask", "chase", "wellsfargo", "bankofamerica", "okta")
_LURE_WORDS = ("login", "signin", "verify", "secure", "account", "update", "wallet", "support", "auth")
_METADATA_HOSTS = {"169.254.169.254", "metadata.google.internal", "100.100.100.200", "fd00:ec2::254"}
_DOC_NETS = [ipaddress.ip_network(n) for n in
             ("192.0.2.0/24", "198.51.100.0/24", "203.0.113.0/24", "2001:db8::/32")]
_CGNAT = ipaddress.ip_network("100.64.0.0/10")
_ULA = ipaddress.ip_network("fc00::/7")


def _shannon_entropy(text: str) -> float:
    if not text:
        return 0.0
    counts = Counter(text)
    n = len(text)
    return -sum((c / n) * math.log2(c / n) for c in counts.values())


class LocalForensicTool(BaseTool):
    """Offline forensic analysis. Reports facts about an indicator, never reputation."""

    TOOL_NAME = "local_forensics"
    REQUIRES_API_KEY = False
    IS_EXTERNAL = False
    PROVIDES_REPUTATION = False
    SUPPORTS = frozenset({"ip", "url", "file"})

    def classify_ip(self, ip: str) -> Dict[str, Any]:
        addr = ipaddress.ip_address(ip.strip().strip("[]"))
        info: Dict[str, Any] = {"ip": str(addr), "version": addr.version, "is_public": is_public_ip(str(addr))}
        indicators: List[str] = []
        risk = 0.0
        category = "public"

        mapped = addr.ipv4_mapped if isinstance(addr, ipaddress.IPv6Address) else None
        if mapped is not None:
            indicators.append(f"IPv4-mapped IPv6 address for {mapped} (filter-evasion form)")
            risk = max(risk, 0.2)
            addr = mapped

        if str(addr) in _METADATA_HOSTS:
            category = "cloud_metadata"
            indicators.append("Cloud instance metadata service address: SSRF / credential theft target")
            risk = max(risk, 0.8)
        elif addr.is_loopback:
            category = "loopback"
            indicators.append("Loopback address: spoofed source or local process")
            risk = max(risk, 0.3)
        elif addr.is_link_local:
            category = "link_local"
            indicators.append("Link-local address: unexpected outside the local segment")
            risk = max(risk, 0.3)
        elif addr.is_multicast:
            category = "multicast"
            indicators.append("Multicast address used as a host: spoofing or misconfiguration")
            risk = max(risk, 0.3)
        elif addr.is_unspecified:
            category = "unspecified"
            indicators.append("Unspecified address (0.0.0.0 / ::)")
            risk = max(risk, 0.3)
        elif any(addr in net for net in _DOC_NETS):
            category = "documentation"
            indicators.append("Documentation range (RFC 5737/3849): never routed, likely spoofed or test data")
            risk = max(risk, 0.2)
        elif isinstance(addr, ipaddress.IPv4Address) and addr in _CGNAT:
            category = "cgnat"
            indicators.append("Carrier-grade NAT range (RFC 6598): shared address, attribution is weak")
            risk = max(risk, 0.1)
        elif isinstance(addr, ipaddress.IPv6Address) and addr in _ULA:
            category = "ipv6_ula"
            indicators.append("IPv6 unique local address: internal source")
            risk = max(risk, 0.1)
        elif addr.is_private:
            category = "private"
            indicators.append("Private RFC 1918 address: internal host, consider lateral movement or insider activity")
            risk = max(risk, 0.1)
        elif addr.is_reserved:
            category = "reserved"
            indicators.append("Reserved address space: should never appear as a real source")
            risk = max(risk, 0.3)
        else:
            indicators.append("Publicly routable address")

        info.update({"category": category, "local_risk": risk, "indicators": indicators})
        return info

    async def query_ip(self, ip: str) -> ToolResult:
        try:
            info = self.classify_ip(ip)
        except ValueError:
            return self._result(False, error=f"Invalid IP address: {ip!r}")
        return self._result(True, {
            "reputation_score": 0.0,
            "local_risk": info["local_risk"],
            "indicators": info["indicators"],
            "classification": info,
        })

    async def query_url(self, url: str) -> ToolResult:
        if not isinstance(url, str) or not url.strip():
            return self._result(False, error="Invalid URL format")
        candidate = url.strip()
        if "://" not in candidate:
            candidate = "http://" + candidate
        parts = urlsplit(candidate)
        host = (parts.hostname or "").lower().rstrip(".")
        if not host:
            return self._result(False, error="Invalid URL format")

        indicators: List[str] = []
        risk = 0.0

        if parts.scheme not in ("http", "https"):
            indicators.append(f"Non-web scheme '{parts.scheme}'")
            risk = max(risk, 0.3)
        elif parts.scheme == "http":
            indicators.append("Plain HTTP (no TLS)")
            risk = max(risk, 0.05)
        if "@" in parts.netloc:
            indicators.append("Credentials/'@' in authority: classic URL obfuscation trick")
            risk = max(risk, 0.6)
        if parts.port and parts.port not in (80, 443, 8080, 8443):
            indicators.append(f"Unusual port {parts.port}")
            risk = max(risk, 0.2)

        try:
            ipaddress.ip_address(host)
            ip_host = True
        except ValueError:
            ip_host = False

        if host in _METADATA_HOSTS or (parts.path or "").startswith(("/latest/meta-data", "/computeMetadata")):
            indicators.append("Cloud metadata endpoint: SSRF / credential theft target")
            risk = max(risk, 0.9)
        if ip_host:
            indicators.append("Raw IP address instead of a domain name")
            risk = max(risk, 0.4)
            if not is_public_ip(host):
                indicators.append("URL targets a non-public address (SSRF / internal pivot)")
                risk = max(risk, 0.6)
        elif host == "localhost" or host.endswith((".local", ".internal", ".localhost")):
            indicators.append("URL targets an internal hostname (SSRF / internal pivot)")
            risk = max(risk, 0.6)
        else:
            labels = host.split(".")
            tld = labels[-1]
            registered = labels[-2] if len(labels) >= 2 else labels[0]
            if any(label.startswith("xn--") for label in labels):
                indicators.append("Punycode/IDN domain: possible homograph attack")
                risk = max(risk, 0.5)
            if tld in _SUSPICIOUS_TLDS:
                indicators.append(f"Abuse-heavy TLD '.{tld}'")
                risk = max(risk, 0.35)
            entropy = _shannon_entropy(registered)
            if len(registered) >= 10 and entropy >= 3.5 and sum(c.isdigit() for c in registered) >= 2:
                indicators.append(f"High-entropy domain label (entropy {entropy:.2f}): possible DGA")
                risk = max(risk, 0.5)
            elif len(registered) >= 16 and entropy >= 3.8:
                indicators.append(f"High-entropy domain label (entropy {entropy:.2f}): possible DGA")
                risk = max(risk, 0.4)
            if len(labels) > 4:
                indicators.append(f"Excessive subdomains ({len(labels) - 2})")
                risk = max(risk, 0.3)
            if registered.count("-") >= 3:
                indicators.append("Many hyphens in domain (typical of phishing kits)")
                risk = max(risk, 0.3)
            for brand in _BRANDS:
                if brand in host and registered != brand:
                    indicators.append(f"Brand '{brand}' used outside its own domain: possible phishing")
                    risk = max(risk, 0.6)
                    break
            if any(word in host for word in _LURE_WORDS) and risk >= 0.3:
                indicators.append("Credential lure keyword in hostname")
                risk = min(1.0, risk + 0.1)

        if _SENSITIVE_PATHS.search(parts.path or ""):
            indicators.append(f"Sensitive path probed: {parts.path[:80]}")
            risk = max(risk, 0.4)
        if len(url) > 200:
            indicators.append(f"Very long URL ({len(url)} chars)")
            risk = max(risk, 0.2)
        if not indicators:
            indicators.append("No structural URL anomalies")

        return self._result(True, {
            "reputation_score": 0.0,
            "local_risk": round(risk, 3),
            "indicators": indicators,
            "host": host,
            "domain_entropy": round(_shannon_entropy(host.split(".")[-2] if "." in host else host), 3),
        })

    async def query_file_hash(self, file_hash: str) -> ToolResult:
        value = (file_hash or "").strip().lower()
        if not re.fullmatch(r"[0-9a-f]+", value) or len(value) not in _HASH_TYPES:
            return self._result(False, error="Invalid hash format (expected MD5/SHA1/SHA256/SHA512 hex)")
        hash_type = _HASH_TYPES[len(value)]
        indicators = [f"Valid {hash_type.upper()} hash"]
        risk = 0.0
        known = _KNOWN_HASHES.get(value)
        if known:
            label, risk = known
            indicators.append(f"Known hash: {label}")
            if "Empty" in label:
                indicators.append("Detection of an empty file is very likely a false positive")
            if "EICAR" in label:
                indicators.append("EICAR is a harmless AV test string: verify the detection pipeline, not an infection")
        if hash_type == "md5":
            indicators.append("MD5 is collision-prone; prefer SHA256 for blocking decisions")
        return self._result(True, {
            "reputation_score": 0.0,
            "local_risk": risk,
            "indicators": indicators,
            "hash_type": hash_type,
            "known_label": known[0] if known else None,
        })


# ---------------------------------------------------------------------------
# Keyless public intel
# ---------------------------------------------------------------------------

class ShodanInternetDBTool(BaseTool):
    """Shodan InternetDB (https://internetdb.shodan.io), free and keyless."""

    TOOL_NAME = "internetdb"
    REQUIRES_API_KEY = False
    SUPPORTS = frozenset({"ip"})
    BASE_URL = "https://internetdb.shodan.io"

    def _parse(self, data: Dict[str, Any]) -> ToolResult:
        ports = data.get("ports") or []
        vulns = data.get("vulns") or []
        tags = [str(t).lower() for t in (data.get("tags") or [])]
        hostnames = data.get("hostnames") or []
        cpes = data.get("cpes") or []

        score = 0.0
        indicators: List[str] = []
        if {"compromised", "malware", "c2"} & set(tags):
            score = max(score, 0.8)
        if "tor" in tags:
            score = max(score, 0.4)
        if {"vpn", "proxy"} & set(tags):
            score = max(score, 0.2)
        if "honeypot" in tags:
            indicators.append("Host is a known honeypot (likely research/scanner infrastructure)")
        if "scanner" in tags:
            score = max(score, 0.3)
        if vulns:
            score = min(1.0, score + min(0.05 * len(vulns), 0.4))
            indicators.append(f"Known vulnerabilities: {', '.join(vulns[:5])}"
                              + (f" (+{len(vulns) - 5} more)" if len(vulns) > 5 else ""))
        if len(ports) > 20:
            score = min(1.0, score + 0.1)
        if ports:
            indicators.append(f"Open ports: {len(ports)} ({', '.join(str(p) for p in ports[:10])})")
        if tags:
            indicators.append(f"Tags: {', '.join(tags)}")
        if hostnames:
            indicators.append(f"Hostnames: {', '.join(hostnames[:3])}")
        return self._result(True, {
            "reputation_score": round(score, 3),
            "indicators": indicators,
            "ports": ports, "cves": vulns, "tags": tags, "hostnames": hostnames, "cpes": cpes,
            "raw_response": data,
        })

    async def query_ip(self, ip: str) -> ToolResult:
        try:
            ip = str(ipaddress.ip_address(ip.strip()))
        except ValueError:
            return self._result(False, error=f"Invalid IP address: {ip!r}")
        if not is_public_ip(ip):
            return self._result(False, error=NON_PUBLIC_SKIP_ERROR)
        try:
            async with self._require_session().get(f"{self.BASE_URL}/{ip}", timeout=self.timeout) as response:
                if response.status == 404:
                    return self._result(False, error="No InternetDB data for this IP")
                if response.status != 200:
                    return self._result(False, error=f"HTTP {response.status}")
                data = await response.json(content_type=None)
                if not isinstance(data, dict):
                    return self._result(False, error="Unexpected InternetDB response")
                return self._parse(data)
        except Exception as e:
            return self._result(False, error=f"{type(e).__name__}: {e}")


class RDAPTool(BaseTool):
    """RDAP network registration lookup via https://rdap.org (keyless)."""

    TOOL_NAME = "rdap"
    REQUIRES_API_KEY = False
    PROVIDES_REPUTATION = False
    SUPPORTS = frozenset({"ip"})
    BASE_URL = "https://rdap.org/ip"

    def _parse(self, data: Dict[str, Any]) -> ToolResult:
        cidrs = []
        for c in data.get("cidr0_cidrs") or []:
            prefix = c.get("v4prefix") or c.get("v6prefix")
            if prefix is not None:
                cidrs.append(f"{prefix}/{c.get('length')}")
        orgs = []
        for entity in data.get("entities") or []:
            vcard = entity.get("vcardArray")
            if isinstance(vcard, list) and len(vcard) > 1:
                for field in vcard[1]:
                    if isinstance(field, list) and field and field[0] == "fn":
                        orgs.append(str(field[-1]))
            elif entity.get("handle"):
                orgs.append(str(entity["handle"]))
        info = {
            "network_name": data.get("name"),
            "handle": data.get("handle"),
            "country": data.get("country"),
            "start_address": data.get("startAddress"),
            "end_address": data.get("endAddress"),
            "cidrs": cidrs,
            "organizations": orgs[:5],
            "type": data.get("type"),
        }
        indicators = []
        if info["network_name"]:
            indicators.append(f"Network: {info['network_name']}")
        if orgs:
            indicators.append(f"Registrant: {orgs[0]}")
        if info["country"]:
            indicators.append(f"Country: {info['country']}")
        if cidrs:
            indicators.append(f"CIDR: {', '.join(cidrs[:3])}")
        return self._result(True, {"reputation_score": 0.0, "indicators": indicators, "registration": info})

    async def query_ip(self, ip: str) -> ToolResult:
        try:
            ip = str(ipaddress.ip_address(ip.strip()))
        except ValueError:
            return self._result(False, error=f"Invalid IP address: {ip!r}")
        if not is_public_ip(ip):
            return self._result(False, error=NON_PUBLIC_SKIP_ERROR)
        try:
            async with self._require_session().get(
                f"{self.BASE_URL}/{ip}", timeout=self.timeout,
                headers={"Accept": "application/rdap+json, application/json"},
            ) as response:
                if response.status != 200:
                    return self._result(False, error=f"HTTP {response.status}")
                data = await response.json(content_type=None)
                if not isinstance(data, dict):
                    return self._result(False, error="Unexpected RDAP response")
                return self._parse(data)
        except Exception as e:
            return self._result(False, error=f"{type(e).__name__}: {e}")


class CISAKEVTool(BaseTool):
    """CISA Known Exploited Vulnerabilities catalog (keyless, cached in memory)."""

    TOOL_NAME = "cisa_kev"
    REQUIRES_API_KEY = False
    SUPPORTS = frozenset({"cve"})
    FEED_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
    CACHE_TTL_SECONDS = 6 * 3600

    _cache: Dict[str, Any] = {"fetched_at": 0.0, "entries": None}
    _lock: Optional[asyncio.Lock] = None

    @classmethod
    def _get_lock(cls) -> asyncio.Lock:
        if cls._lock is None:
            cls._lock = asyncio.Lock()
        return cls._lock

    @classmethod
    def load_catalog(cls, catalog: Dict[str, Any]) -> int:
        """Load a catalog dict (e.g. from an offline mirror). Returns entry count."""
        entries = {
            str(v.get("cveID", "")).upper(): v
            for v in catalog.get("vulnerabilities", []) if isinstance(v, dict) and v.get("cveID")
        }
        cls._cache = {"fetched_at": time.monotonic(), "entries": entries}
        return len(entries)

    async def _catalog(self) -> Optional[Dict[str, Any]]:
        cache = type(self)._cache
        if cache["entries"] is not None and time.monotonic() - cache["fetched_at"] < self.CACHE_TTL_SECONDS:
            return cache["entries"]
        async with self._get_lock():
            cache = type(self)._cache
            if cache["entries"] is not None and time.monotonic() - cache["fetched_at"] < self.CACHE_TTL_SECONDS:
                return cache["entries"]
            try:
                async with self._require_session().get(
                    self.FEED_URL, timeout=aiohttp.ClientTimeout(total=30)
                ) as response:
                    if response.status != 200:
                        raise RuntimeError(f"HTTP {response.status}")
                    data = await response.json(content_type=None)
                type(self).load_catalog(data)
            except Exception as e:
                # Degrade gracefully: keep serving a stale catalog if there is one
                self.logger.warning(f"CISA KEV feed unavailable: {type(e).__name__}: {e}")
            return type(self)._cache["entries"]

    async def query_cves(self, cves: List[str]) -> ToolResult:
        wanted = sorted({c.strip().upper() for c in cves if re.fullmatch(r"(?i)CVE-\d{4}-\d{4,7}", c.strip())})
        if not wanted:
            return self._result(False, error="No valid CVE identifiers supplied")
        catalog = await self._catalog()
        if catalog is None:
            return self._result(False, error="CISA KEV catalog unavailable (offline)")
        hits = []
        for cve in wanted:
            entry = catalog.get(cve)
            if entry:
                hits.append({
                    "cve": cve,
                    "vendor": entry.get("vendorProject"),
                    "product": entry.get("product"),
                    "name": entry.get("vulnerabilityName"),
                    "date_added": entry.get("dateAdded"),
                    "due_date": entry.get("dueDate"),
                    "known_ransomware_use": entry.get("knownRansomwareCampaignUse"),
                })
        indicators = [f"{h['cve']} is actively exploited (CISA KEV): {h['name'] or h['product']}" for h in hits]
        ransomware = [h for h in hits if str(h.get("known_ransomware_use", "")).lower() == "known"]
        if ransomware:
            indicators.append(f"{len(ransomware)} CVE(s) used in ransomware campaigns")
        score = 0.0
        if hits:
            score = 0.9 if ransomware else 0.7
        return self._result(True, {
            "reputation_score": score,
            "indicators": indicators,
            "kev_matches": hits,
            "cves_checked": wanted,
        })


# ---------------------------------------------------------------------------
# Keyed intel
# ---------------------------------------------------------------------------

class VirusTotalTool(BaseTool):
    """VirusTotal API v3."""

    TOOL_NAME = "virustotal"
    SUPPORTS = frozenset({"ip", "url", "file"})

    def __init__(self, api_key: str, config: Optional[Dict[str, Any]] = None):
        super().__init__(api_key, config)
        self.base_url = "https://www.virustotal.com/api/v3"
        self.rate_limit = self.config.get("rate_limit", 4)
        self._limiter = _RateLimiter(self.rate_limit)

    @property
    def _headers(self) -> Dict[str, str]:
        return {"x-apikey": self.api_key, "Accept": "application/json"}

    @staticmethod
    def _stats_score(attrs: Dict[str, Any]) -> tuple:
        stats = attrs.get("last_analysis_stats") or {}
        malicious = int(stats.get("malicious", 0) or 0)
        suspicious = int(stats.get("suspicious", 0) or 0)
        total = sum(int(v or 0) for v in stats.values() if isinstance(v, (int, float)))
        score = (malicious + 0.5 * suspicious) / total if total else 0.0
        return min(score, 1.0), malicious, suspicious, total

    def _parse_ip_response(self, data: Dict[str, Any]) -> ToolResult:
        """Parse an IP report. Accepts the v3 shape and the legacy v2 shape."""
        indicators: List[str] = []
        score = 0.0
        attrs = (data.get("data") or {}).get("attributes") if isinstance(data.get("data"), dict) else None
        if attrs is not None:
            score, malicious, suspicious, total = self._stats_score(attrs)
            if malicious or suspicious:
                indicators.append(f"Flagged by {malicious} malicious / {suspicious} suspicious of {total} engines")
            reputation = attrs.get("reputation")
            if isinstance(reputation, (int, float)) and reputation < 0:
                indicators.append(f"Community reputation {reputation}")
                score = min(1.0, max(score, min(abs(reputation) / 100.0, 0.5)))
            if attrs.get("as_owner"):
                indicators.append(f"ASN: {attrs['as_owner']}")
            if attrs.get("country"):
                indicators.append(f"Country: {attrs['country']}")
        elif data.get("response_code") == 1:
            detected_urls = data.get("detected_urls", [])
            detected_samples = data.get("detected_communicating_samples", []) or data.get("detected_samples", [])
            score = min(len(detected_urls) * 0.1 + len(detected_samples) * 0.2, 1.0)
            if detected_urls:
                indicators.append(f"Associated with {len(detected_urls)} malicious URLs")
            if detected_samples:
                indicators.append(f"Associated with {len(detected_samples)} malicious files")
            if data.get("as_owner"):
                indicators.append(f"ASN: {data['as_owner']}")
            if data.get("country"):
                indicators.append(f"Country: {data['country']}")
        return self._result(True, {"reputation_score": score, "indicators": indicators, "raw_response": data})

    def _parse_object_response(self, data: Dict[str, Any], noun: str) -> ToolResult:
        attrs = (data.get("data") or {}).get("attributes") or {}
        score, malicious, suspicious, total = self._stats_score(attrs)
        indicators: List[str] = []
        if malicious or suspicious:
            indicators.append(f"Detected as malicious by {malicious}/{total} engines"
                              + (f" ({suspicious} suspicious)" if suspicious else ""))
        label = (attrs.get("popular_threat_classification") or {}).get("suggested_threat_label")
        if label:
            indicators.append(f"Threat label: {label}")
        if attrs.get("last_analysis_date"):
            ts = datetime.fromtimestamp(int(attrs["last_analysis_date"]), tz=timezone.utc)
            indicators.append(f"Last analyzed: {ts.isoformat()}")
        if attrs.get("meaningful_name"):
            indicators.append(f"{noun} name: {attrs['meaningful_name']}")
        return self._result(True, {"reputation_score": score, "indicators": indicators, "raw_response": data})

    async def query_ip(self, ip: str) -> ToolResult:
        try:
            ip = str(ipaddress.ip_address(ip.strip()))
        except ValueError:
            return self._result(False, error=f"Invalid IP address: {ip!r}")
        if not self.api_key:
            return self._missing_key()
        try:
            await self._limiter.wait()
            async with self._require_session().get(
                f"{self.base_url}/ip_addresses/{ip}", headers=self._headers, timeout=self.timeout
            ) as response:
                if response.status != 200:
                    return self._result(False, error=f"HTTP {response.status}")
                return self._parse_ip_response(await response.json(content_type=None))
        except Exception as e:
            return self._result(False, error=f"{type(e).__name__}: {e}")

    async def query_url(self, url: str) -> ToolResult:
        if not isinstance(url, str) or not validators.url(url):
            return self._result(False, error="Invalid URL format")
        if not self.api_key:
            return self._missing_key()
        url_id = base64.urlsafe_b64encode(url.encode()).decode().rstrip("=")
        try:
            await self._limiter.wait()
            session = self._require_session()
            async with session.get(f"{self.base_url}/urls/{url_id}", headers=self._headers,
                                   timeout=self.timeout) as response:
                if response.status == 200:
                    return self._parse_object_response(await response.json(content_type=None), "URL")
                if response.status != 404:
                    return self._result(False, error=f"HTTP {response.status}")
            # Unknown URL: submit it so the next investigation gets a verdict
            await self._limiter.wait()
            async with session.post(f"{self.base_url}/urls", headers=self._headers,
                                    data={"url": url}, timeout=self.timeout) as submit:
                if submit.status != 200:
                    return self._result(False, error=f"URL not in VirusTotal; submission HTTP {submit.status}")
                body = await submit.json(content_type=None)
                analysis_id = (body.get("data") or {}).get("id")
            return self._result(False, {"analysis_id": analysis_id},
                                error="URL not yet analyzed by VirusTotal; submitted for scanning")
        except Exception as e:
            return self._result(False, error=f"{type(e).__name__}: {e}")

    async def query_file_hash(self, file_hash: str) -> ToolResult:
        value = (file_hash or "").strip().lower()
        if not re.fullmatch(r"[0-9a-f]{32}|[0-9a-f]{40}|[0-9a-f]{64}", value):
            return self._result(False, error="Invalid hash format (expected MD5/SHA1/SHA256 hex)")
        if not self.api_key:
            return self._missing_key()
        try:
            await self._limiter.wait()
            async with self._require_session().get(
                f"{self.base_url}/files/{value}", headers=self._headers, timeout=self.timeout
            ) as response:
                if response.status == 404:
                    return self._result(False, error="Hash not found in VirusTotal")
                if response.status != 200:
                    return self._result(False, error=f"HTTP {response.status}")
                return self._parse_object_response(await response.json(content_type=None), "File")
        except Exception as e:
            return self._result(False, error=f"{type(e).__name__}: {e}")


class AbuseIPDBTool(BaseTool):
    """AbuseIPDB v2 IP reputation."""

    TOOL_NAME = "abuseipdb"
    SUPPORTS = frozenset({"ip"})

    def __init__(self, api_key: str, config: Optional[Dict[str, Any]] = None):
        super().__init__(api_key, config)
        self.base_url = "https://api.abuseipdb.com/api/v2"

    def _parse_ip_response(self, data: Dict[str, Any]) -> ToolResult:
        ip_data = data.get("data") or {}
        abuse_confidence = ip_data.get("abuseConfidencePercentage", 0) or 0
        total_reports = ip_data.get("totalReports", 0) or 0
        indicators = []
        if abuse_confidence > 0:
            indicators.append(f"Abuse confidence: {abuse_confidence}%")
        if total_reports > 0:
            indicators.append(f"Total reports: {total_reports}")
        for key, label in (("usageType", "Usage type"), ("isp", "ISP"), ("countryCode", "Country")):
            if ip_data.get(key):
                indicators.append(f"{label}: {ip_data[key]}")
        if ip_data.get("isTor"):
            indicators.append("Tor exit node")
        return self._result(True, {
            "reputation_score": min(abuse_confidence / 100.0, 1.0),
            "indicators": indicators,
            "raw_response": data,
        })

    async def query_ip(self, ip: str) -> ToolResult:
        try:
            ip = str(ipaddress.ip_address(ip.strip()))
        except ValueError:
            return self._result(False, error=f"Invalid IP address: {ip!r}")
        if not self.api_key:
            return self._missing_key()
        try:
            async with self._require_session().get(
                f"{self.base_url}/check",
                headers={"Key": self.api_key, "Accept": "application/json"},
                params={"ipAddress": ip, "maxAgeInDays": "90", "verbose": ""},
                timeout=self.timeout,
            ) as response:
                if response.status != 200:
                    return self._result(False, error=f"HTTP {response.status}")
                return self._parse_ip_response(await response.json(content_type=None))
        except Exception as e:
            return self._result(False, error=f"{type(e).__name__}: {e}")


class URLVoidTool(BaseTool):
    """URLVoid host reputation (XML API)."""

    TOOL_NAME = "urlvoid"
    SUPPORTS = frozenset({"url"})

    def __init__(self, api_key: str, config: Optional[Dict[str, Any]] = None):
        super().__init__(api_key, config)
        self.base_url = "https://api.urlvoid.com/1000"

    async def query_url(self, url: str) -> ToolResult:
        if not isinstance(url, str) or not validators.url(url):
            return self._result(False, error="Invalid URL format")
        if not self.api_key:
            return self._missing_key()
        host = urlsplit(url).hostname
        if not host:
            return self._result(False, error="URL has no host")
        try:
            api_url = f"{self.base_url}/{quote(self.api_key, safe='')}/host/{quote(host, safe='.-')}"
            async with self._require_session().get(api_url, timeout=self.timeout) as response:
                if response.status != 200:
                    return self._result(False, error=f"HTTP {response.status}")
                body = await response.text()
        except Exception as e:
            return self._result(False, error=f"{type(e).__name__}: {e}")

        indicators: List[str] = []
        score = 0.0
        try:
            root = _parse_xml(body)
        except Exception as e:  # includes DefusedXmlException and ParseError
            return self._result(False, error=f"Unparseable URLVoid response: {type(e).__name__}")
        detections = root.findtext(".//detections")
        engines_count = root.findtext(".//engines/count")
        resolved_ip = root.findtext(".//ip")
        country = root.findtext(".//country_name")
        if detections and engines_count:
            try:
                det, eng = int(detections), int(engines_count)
            except ValueError:
                det, eng = 0, 0
            score = det / eng if eng > 0 else 0.0
            if det > 0:
                indicators.append(f"Detected by {det}/{eng} engines")
        if resolved_ip:
            indicators.append(f"Resolves to {resolved_ip}")
        if country:
            indicators.append(f"Hosted in {country}")
        return self._result(True, {
            "reputation_score": score,
            "indicators": indicators,
            "raw_response": {"status": "checked", "host": host, "body_length": len(body)},
        })


class ShodanTool(BaseTool):
    """Shodan host API (keyed)."""

    TOOL_NAME = "shodan"
    SUPPORTS = frozenset({"ip"})

    def __init__(self, api_key: str, config: Optional[Dict[str, Any]] = None):
        super().__init__(api_key, config)
        self.base_url = "https://api.shodan.io"

    def _parse_ip_response(self, data: Dict[str, Any]) -> ToolResult:
        ports = data.get("ports") or []
        vulns = data.get("vulns") or []
        if isinstance(vulns, dict):
            vulns = list(vulns)
        org = data.get("org")
        score = 0.0
        if len(ports) > 10:
            score += 0.3
        if vulns:
            score += min(len(vulns) * 0.15, 0.6)
        indicators = []
        if ports:
            indicators.append(f"Open ports: {len(ports)} ({', '.join(str(p) for p in ports[:8])})")
        if vulns:
            indicators.append(f"Known vulnerabilities: {', '.join(vulns[:5])}")
        if org:
            indicators.append(f"Organization: {org}")
        if data.get("os"):
            indicators.append(f"OS: {data['os']}")
        if data.get("city"):
            indicators.append(f"Location: {data['city']}, {data.get('country_code', '')}")
        return self._result(True, {
            "reputation_score": min(score, 1.0), "indicators": indicators,
            "cves": vulns, "raw_response": data,
        })

    async def query_ip(self, ip: str) -> ToolResult:
        try:
            ip = str(ipaddress.ip_address(ip.strip()))
        except ValueError:
            return self._result(False, error=f"Invalid IP address: {ip!r}")
        if not self.api_key:
            return self._missing_key()
        try:
            async with self._require_session().get(
                f"{self.base_url}/shodan/host/{ip}", params={"key": self.api_key}, timeout=self.timeout
            ) as response:
                if response.status != 200:
                    return self._result(False, error=f"HTTP {response.status}")
                return self._parse_ip_response(await response.json(content_type=None))
        except Exception as e:
            return self._result(False, error=f"{type(e).__name__}: {e}")


# ---------------------------------------------------------------------------
# Registry
# ---------------------------------------------------------------------------

KEYED_TOOLS = {
    "virustotal": VirusTotalTool,
    "abuseipdb": AbuseIPDBTool,
    "shodan": ShodanTool,
    "urlvoid": URLVoidTool,
}
KEYLESS_TOOLS = {
    "internetdb": ShodanInternetDBTool,
    "rdap": RDAPTool,
    "cisa_kev": CISAKEVTool,
}


class ToolRegistry:
    """Owns every intel tool, fans queries out concurrently, aggregates results."""

    def __init__(self, api_keys: Optional[Dict[str, Optional[str]]] = None,
                 config: Optional[Dict[str, Any]] = None):
        self.api_keys = api_keys or {}
        self.config = config or {}
        self.logger = logging.getLogger(__name__)
        self.enable_keyless_intel = bool(self.config.get("enable_keyless_intel", True))
        self.timeout_seconds = self.config.get("timeout", DEFAULT_TIMEOUT_SECONDS)
        self.tools: Dict[str, BaseTool] = {}
        self.api_call_counts: Dict[str, int] = {}
        self._initialize_tools()

    def _initialize_tools(self):
        self.tools["local_forensics"] = LocalForensicTool("", self.config.get("local_forensics", {}))
        if self.enable_keyless_intel:
            for name, cls in KEYLESS_TOOLS.items():
                self.tools[name] = cls("", self.config.get(name, {}))
        for name, cls in KEYED_TOOLS.items():
            key = self.api_keys.get(name)
            if is_configured_api_key(key):
                self.tools[name] = cls(key.strip(), self.config.get(name, {}))

        keyed = [n for n in KEYED_TOOLS if n in self.tools]
        self.logger.info(
            f"Initialized {len(self.tools)} intel tools (keyed: {keyed or 'none'}, "
            f"keyless public intel: {'on' if self.enable_keyless_intel else 'off'})"
        )

    def _sources_for(self, capability: str, sources: Optional[List[str]]) -> List[str]:
        if sources is None:
            return [n for n, t in self.tools.items() if capability in t.SUPPORTS]
        return [s for s in sources if s in self.tools]

    async def _query_with_sessions(self, available_sources: List[str], method_name: str,
                                   *args) -> List[Union[ToolResult, Exception]]:
        """Run one query across tools with a session owned by this call only."""
        timeout = aiohttp.ClientTimeout(total=self.timeout_seconds)
        async with aiohttp.ClientSession(timeout=timeout) as session:
            calls = []
            for name in available_sources:
                tool = self.tools[name]
                if tool.IS_EXTERNAL:
                    self.api_call_counts[name] = self.api_call_counts.get(name, 0) + 1
                calls.append(getattr(tool.with_session(session), method_name)(*args))
            return await asyncio.gather(*calls, return_exceptions=True)

    def _skip_result(self, name: str) -> ToolResult:
        return ToolResult(False, name, {}, error=NON_PUBLIC_SKIP_ERROR)

    async def query_ip_reputation(self, ip: str, sources: Optional[List[str]] = None) -> ToolResult:
        available = self._sources_for("ip", sources)
        if not available:
            return ToolResult(False, "registry", {}, error="No tools available for IP reputation checking")
        public = is_public_ip(ip)
        to_query = [s for s in available if public or not self.tools[s].IS_EXTERNAL]
        skipped = [self._skip_result(s) for s in available if s not in to_query]
        results = await self._query_with_sessions(to_query, "query_ip", ip) if to_query else []
        return self._aggregate_results(list(results), "ip_reputation", skipped=skipped)

    async def query_url_reputation(self, url: str, sources: Optional[List[str]] = None) -> ToolResult:
        available = self._sources_for("url", sources)
        if not available:
            return ToolResult(False, "registry", {}, error="No tools available for URL reputation checking")
        results = await self._query_with_sessions(available, "query_url", url)
        return self._aggregate_results(list(results), "url_reputation")

    async def query_file_reputation(self, file_hash: str, sources: Optional[List[str]] = None) -> ToolResult:
        available = self._sources_for("file", sources)
        if not available:
            return ToolResult(False, "registry", {}, error="No tools available for file reputation checking")
        results = await self._query_with_sessions(available, "query_file_hash", file_hash)
        return self._aggregate_results(list(results), "file_reputation")

    async def query_cve_exploitation(self, cves: List[str]) -> ToolResult:
        available = self._sources_for("cve", None)
        if not available or not cves:
            return ToolResult(False, "registry", {}, error="No tools available for CVE exploitation checking")
        results = await self._query_with_sessions(available, "query_cves", list(cves))
        return self._aggregate_results(list(results), "cve_exploitation")

    def _aggregate_results(self, results: List[Union[ToolResult, Exception]], query_type: str,
                           skipped: Optional[List[ToolResult]] = None) -> ToolResult:
        skipped = skipped or []
        successful = [r for r in results if isinstance(r, ToolResult) and r.success]
        errors: Dict[str, str] = {}
        for r in results:
            if isinstance(r, Exception):
                errors[f"error_{len(errors)}"] = f"{type(r).__name__}: {r}"
            elif isinstance(r, ToolResult) and not r.success:
                errors[r.source] = r.error or "failed"
        for r in skipped:
            errors[r.source] = r.error or NON_PUBLIC_SKIP_ERROR

        if not successful:
            return ToolResult(False, "registry", {"errors": errors, "query_type": query_type},
                              error=f"All {query_type} queries failed")

        reputation = [r for r in successful
                      if getattr(self.tools.get(r.source), "PROVIDES_REPUTATION", True)
                      and getattr(self.tools.get(r.source), "IS_EXTERNAL", True)]
        local = [r for r in successful if not getattr(self.tools.get(r.source), "IS_EXTERNAL", True)]
        max_reputation = max((r.data.get("reputation_score", 0.0) or 0.0 for r in reputation), default=0.0)
        local_risk = max((r.data.get("local_risk", 0.0) or 0.0 for r in local), default=0.0)

        all_indicators = []
        cves: Set[str] = set()
        for r in successful:
            for indicator in r.data.get("indicators", []):
                all_indicators.append(f"[{r.source}] {indicator}")
            cves.update(str(c).upper() for c in (r.data.get("cves") or []))

        attempted = len(results)
        return ToolResult(True, "registry", {
            "reputation_score": max_reputation,
            "local_risk": local_risk,
            "indicators": all_indicators,
            "confidence": len(successful) / attempted if attempted else 0.0,
            "sources_queried": [r.source for r in successful],
            "reputation_sources": [r.source for r in reputation],
            "local_sources": [r.source for r in local],
            "cves": sorted(cves),
            "errors": errors,
            "query_type": query_type,
            "individual_results": [{"source": r.source, **r.data} for r in successful],
        })

    def get_available_tools(self) -> List[str]:
        return list(self.tools.keys())

    def get_tool_capabilities(self) -> Dict[str, List[str]]:
        names = {"ip": "ip_reputation", "url": "url_reputation", "file": "file_reputation",
                 "cve": "cve_exploitation"}
        return {
            name: [names[c] for c in ("ip", "url", "file", "cve") if c in tool.SUPPORTS]
            for name, tool in self.tools.items()
        }

    def get_status(self) -> Dict[str, Any]:
        return {
            name: {
                "external": tool.IS_EXTERNAL,
                "requires_api_key": tool.REQUIRES_API_KEY,
                "provides_reputation": tool.PROVIDES_REPUTATION,
                "capabilities": sorted(tool.SUPPORTS),
                "api_calls": self.api_call_counts.get(name, 0),
            }
            for name, tool in self.tools.items()
        }
