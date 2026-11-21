"""
Unit tests for agent/tools.py

All network calls are mocked; conftest.py refuses any real request.
"""

import asyncio
import base64
from datetime import datetime
from unittest.mock import AsyncMock, MagicMock, patch

import aiohttp
import pytest

from agent.tools import (
    NON_PUBLIC_SKIP_ERROR, AbuseIPDBTool, CISAKEVTool, LocalForensicTool, RDAPTool, ShodanInternetDBTool,
    ShodanTool, ToolRegistry, ToolResult, URLVoidTool, VirusTotalTool, is_configured_api_key,
)


def mock_response(status=200, json_data=None, text=None):
    resp = MagicMock()
    resp.status = status
    resp.json = AsyncMock(return_value=json_data)
    resp.text = AsyncMock(return_value=text if text is not None else "")
    ctx = MagicMock()
    ctx.__aenter__ = AsyncMock(return_value=resp)
    ctx.__aexit__ = AsyncMock(return_value=False)
    return ctx


class TestToolResult:
    def test_tool_result_creation(self):
        result = ToolResult(success=True, source="test", data={"key": "value"})
        assert result.success is True
        assert result.error is None
        assert isinstance(result.timestamp, datetime)
        assert result.timestamp.tzinfo is not None

    def test_tool_result_with_error(self):
        result = ToolResult(success=False, source="test", data={}, error="Test error")
        assert result.error == "Test error"


class TestConfiguredKeys:
    @pytest.mark.parametrize("key", [None, "", "   ", "your_virustotal_api_key_here", "changeme",
                                     "placeholder", "your-key", "<api-key>", "xxxx"])
    def test_placeholders_rejected(self, key):
        assert is_configured_api_key(key) is False

    def test_real_looking_key_accepted(self):
        assert is_configured_api_key("4f2a9c1b7e5d4c3a2b1f0e9d8c7b6a59") is True


class TestVirusTotalTool:
    @pytest.fixture
    def vt_tool(self):
        return VirusTotalTool("test_api_key", {"rate_limit": 0})

    async def test_query_ip_v3(self, vt_tool):
        body = {"data": {"attributes": {
            "last_analysis_stats": {"malicious": 8, "suspicious": 2, "harmless": 60, "undetected": 10},
            "as_owner": "Example AS", "country": "NL", "reputation": -12}}}
        with patch("aiohttp.ClientSession.get", return_value=mock_response(200, body)) as mock_get:
            async with vt_tool:
                result = await vt_tool.query_ip("8.8.8.8")
        assert result.success is True
        assert result.source == "virustotal"
        # Engine ratio is 9/80; negative community reputation (-12) lifts it to 0.12
        assert result.data["reputation_score"] == pytest.approx(0.12)
        assert any("8 malicious" in i for i in result.data["indicators"])
        url = mock_get.call_args.args[0]
        assert url.endswith("/api/v3/ip_addresses/8.8.8.8")
        assert mock_get.call_args.kwargs["headers"]["x-apikey"] == "test_api_key"

    def test_parse_legacy_v2_shape(self, vt_tool):
        result = vt_tool._parse_ip_response({"response_code": 1, "detected_urls": [{}], "detected_samples": [{}]})
        assert result.success is True
        assert result.data["reputation_score"] == pytest.approx(0.3)

    async def test_query_ip_invalid(self, vt_tool):
        async with vt_tool:
            result = await vt_tool.query_ip("invalid_ip")
        assert result.success is False
        assert "invalid" in result.error.lower()

    @pytest.mark.parametrize("status", [401, 403, 429, 500])
    async def test_non_200_never_returns_none(self, vt_tool, status):
        with patch("aiohttp.ClientSession.get", return_value=mock_response(status, {})):
            async with vt_tool:
                result = await vt_tool.query_ip("8.8.8.8")
        assert isinstance(result, ToolResult)
        assert result.success is False
        assert result.error == f"HTTP {status}"

    async def test_query_url_v3_uses_b64_id(self, vt_tool):
        url = "http://example.com/login"
        body = {"data": {"attributes": {"last_analysis_stats": {"malicious": 5, "harmless": 5}}}}
        with patch("aiohttp.ClientSession.get", return_value=mock_response(200, body)) as mock_get:
            async with vt_tool:
                result = await vt_tool.query_url(url)
        expected_id = base64.urlsafe_b64encode(url.encode()).decode().rstrip("=")
        assert mock_get.call_args.args[0].endswith(f"/api/v3/urls/{expected_id}")
        assert result.success is True
        assert result.data["reputation_score"] == 0.5

    async def test_query_url_unknown_is_submitted(self, vt_tool):
        with patch("aiohttp.ClientSession.get", return_value=mock_response(404, {})), \
             patch("aiohttp.ClientSession.post",
                   return_value=mock_response(200, {"data": {"id": "u-abc"}})) as mock_post:
            async with vt_tool:
                result = await vt_tool.query_url("http://example.com/new")
        assert result.success is False
        assert "submitted" in result.error
        assert result.data["analysis_id"] == "u-abc"
        assert mock_post.called

    async def test_query_file_hash_v3(self, vt_tool):
        body = {"data": {"attributes": {"last_analysis_stats": {"malicious": 3, "undetected": 7},
                                        "popular_threat_classification": {"suggested_threat_label": "trojan.x"}}}}
        with patch("aiohttp.ClientSession.get", return_value=mock_response(200, body)):
            async with vt_tool:
                result = await vt_tool.query_file_hash("a" * 64)
        assert result.success is True
        assert result.data["reputation_score"] == pytest.approx(0.3)
        assert any("trojan.x" in i for i in result.data["indicators"])

    async def test_query_file_hash_not_found(self, vt_tool):
        with patch("aiohttp.ClientSession.get", return_value=mock_response(404, {})):
            async with vt_tool:
                result = await vt_tool.query_file_hash("b" * 32)
        assert result.success is False
        assert "not found" in result.error.lower()


class TestAbuseIPDBTool:
    async def test_query_ip_success(self):
        tool = AbuseIPDBTool("test_api_key")
        body = {"data": {"abuseConfidencePercentage": 75, "usageType": "isp", "countryCode": "US"}}
        with patch("aiohttp.ClientSession.get", return_value=mock_response(200, body)):
            async with tool:
                result = await tool.query_ip("1.1.1.1")
        assert result.success is True
        assert result.data["reputation_score"] == 0.75
        assert "Abuse confidence: 75%" in result.data["indicators"]

    async def test_non_200_returns_failure(self):
        tool = AbuseIPDBTool("test_api_key")
        with patch("aiohttp.ClientSession.get", return_value=mock_response(429, {})):
            async with tool:
                result = await tool.query_ip("1.1.1.1")
        assert result is not None
        assert result.success is False
        assert result.error == "HTTP 429"

    async def test_url_and_hash_not_supported(self):
        tool = AbuseIPDBTool("k")
        assert "not supported" in (await tool.query_url("http://example.com")).error
        assert "not supported" in (await tool.query_file_hash("abc")).error


class TestURLVoidTool:
    async def test_query_url_success_uses_hostname(self):
        tool = URLVoidTool("test_api_key")
        assert tool.TOOL_NAME == "urlvoid"
        xml_body = ("<?xml version='1.0'?><response><detections>3</detections><engines><count>40</count>"
                    "</engines><ip>93.184.216.34</ip><country_name>United States</country_name></response>")
        with patch("aiohttp.ClientSession.get", return_value=mock_response(200, text=xml_body)) as mock_get:
            async with tool:
                result = await tool.query_url("http://user@example.com:8080/path")
        assert result.success is True
        assert result.data["reputation_score"] == 3 / 40
        assert mock_get.call_args.args[0].endswith("/host/example.com")

    async def test_xxe_payload_rejected(self):
        tool = URLVoidTool("test_api_key")
        xxe = ('<?xml version="1.0"?><!DOCTYPE r [<!ENTITY x SYSTEM "file:///etc/passwd">]>'
               "<response><detections>&x;</detections></response>")
        with patch("aiohttp.ClientSession.get", return_value=mock_response(200, text=xxe)):
            async with tool:
                result = await tool.query_url("http://example.com")
        assert result.success is False
        assert "root:" not in str(result.data)

    async def test_missing_key(self):
        result = await URLVoidTool("").query_url("http://example.com")
        assert result.success is False
        assert "not configured" in result.error

    async def test_query_ip_not_supported(self):
        assert "not supported" in (await URLVoidTool("k").query_ip("1.1.1.1")).error


class TestShodanTool:
    async def test_query_ip_success(self):
        tool = ShodanTool("test_api_key")
        body = {"ports": [22, 80, 443, 8080], "vulns": ["CVE-2021-1234"], "org": "Example ISP"}
        with patch("aiohttp.ClientSession.get", return_value=mock_response(200, body)):
            async with tool:
                result = await tool.query_ip("1.1.1.1")
        assert result.success is True
        assert any("Open ports: 4" in i for i in result.data["indicators"])
        assert result.data["cves"] == ["CVE-2021-1234"]

    async def test_non_200_returns_failure(self):
        tool = ShodanTool("test_api_key")
        with patch("aiohttp.ClientSession.get", return_value=mock_response(404, {})):
            async with tool:
                result = await tool.query_ip("1.1.1.1")
        assert result is not None and result.success is False and result.error == "HTTP 404"


class TestLocalForensicTool:
    @pytest.fixture
    def tool(self):
        return LocalForensicTool()

    @pytest.mark.parametrize("ip,category", [
        ("169.254.169.254", "cloud_metadata"),
        ("10.1.2.3", "private"),
        ("127.0.0.1", "loopback"),
        ("100.64.1.1", "cgnat"),
        ("203.0.113.9", "documentation"),
        ("224.0.0.1", "multicast"),
        ("fd12:3456::1", "ipv6_ula"),
        ("8.8.8.8", "public"),
    ])
    async def test_ip_classification(self, tool, ip, category):
        result = await tool.query_ip(ip)
        assert result.success is True
        assert result.data["classification"]["category"] == category
        assert result.data["reputation_score"] == 0.0  # never fakes external reputation

    async def test_metadata_ip_high_local_risk(self, tool):
        result = await tool.query_ip("169.254.169.254")
        assert result.data["local_risk"] >= 0.8

    async def test_ipv4_mapped_ipv6(self, tool):
        result = await tool.query_ip("::ffff:10.0.0.1")
        assert result.data["classification"]["category"] == "private"
        assert any("IPv4-mapped" in i for i in result.data["indicators"])

    async def test_url_heuristics(self, tool):
        result = await tool.query_url("http://paypal-login-secure.xn--80ak6aa92e.xyz/wp-admin/.env")
        text = " ".join(result.data["indicators"])
        assert "Punycode" in text
        assert ".xyz" in text
        assert "Sensitive path" in text
        assert result.data["local_risk"] >= 0.5

    async def test_url_credential_trick_and_metadata(self, tool):
        r1 = await tool.query_url("http://google.com@evil.example/")
        assert any("'@'" in i for i in r1.data["indicators"])
        r2 = await tool.query_url("http://169.254.169.254/latest/meta-data/")
        assert r2.data["local_risk"] >= 0.9

    async def test_dga_entropy(self, tool):
        result = await tool.query_url("https://x7k2q9zr4w8pl3m.com/")
        assert any("entropy" in i for i in result.data["indicators"])

    @pytest.mark.parametrize("value,label", [
        ("44d88612fea8a8f36de82e1278abb02f", "EICAR"),
        ("275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f", "EICAR"),
        ("d41d8cd98f00b204e9800998ecf8427e", "Empty file"),
    ])
    async def test_known_hashes(self, tool, value, label):
        result = await tool.query_file_hash(value)
        assert label in result.data["known_label"]

    async def test_invalid_hash(self, tool):
        assert (await tool.query_file_hash("not-a-hash")).success is False


class TestKeylessIntel:
    async def test_internetdb_parses_tags_and_vulns(self):
        tool = ShodanInternetDBTool()
        body = {"ip": "1.2.3.4", "ports": [22, 445], "vulns": ["CVE-2017-0144"], "tags": ["compromised"],
                "hostnames": ["h.example"], "cpes": []}
        with patch("aiohttp.ClientSession.get", return_value=mock_response(200, body)) as mock_get:
            async with tool:
                result = await tool.query_ip("1.2.3.4")
        assert mock_get.call_args.args[0] == "https://internetdb.shodan.io/1.2.3.4"
        assert result.success is True
        assert result.data["reputation_score"] >= 0.8
        assert result.data["cves"] == ["CVE-2017-0144"]

    @pytest.mark.parametrize("status", [404, 500])
    async def test_internetdb_errors(self, status):
        tool = ShodanInternetDBTool()
        with patch("aiohttp.ClientSession.get", return_value=mock_response(status, {})):
            async with tool:
                result = await tool.query_ip("1.2.3.4")
        assert result.success is False

    async def test_internetdb_never_sends_private_ip(self):
        tool = ShodanInternetDBTool()
        with patch("aiohttp.ClientSession.get") as mock_get:
            async with tool:
                result = await tool.query_ip("192.168.1.10")
        assert result.error == NON_PUBLIC_SKIP_ERROR
        mock_get.assert_not_called()

    async def test_internetdb_timeout(self):
        tool = ShodanInternetDBTool()
        with patch("aiohttp.ClientSession.get", side_effect=asyncio.TimeoutError()):
            async with tool:
                result = await tool.query_ip("1.2.3.4")
        assert result.success is False
        assert "TimeoutError" in result.error

    async def test_rdap(self):
        tool = RDAPTool()
        body = {"name": "EXAMPLE-NET", "handle": "NET-1", "country": "US",
                "cidr0_cidrs": [{"v4prefix": "1.2.3.0", "length": 24}],
                "entities": [{"handle": "ORG-1", "vcardArray": ["vcard", [["fn", {}, "text", "Example Org"]]]}]}
        with patch("aiohttp.ClientSession.get", return_value=mock_response(200, body)) as mock_get:
            async with tool:
                result = await tool.query_ip("1.2.3.4")
        assert mock_get.call_args.args[0] == "https://rdap.org/ip/1.2.3.4"
        reg = result.data["registration"]
        assert reg["network_name"] == "EXAMPLE-NET" and reg["cidrs"] == ["1.2.3.0/24"]
        assert reg["organizations"] == ["Example Org"]
        assert tool.PROVIDES_REPUTATION is False

    async def test_cisa_kev_match_and_offline(self):
        CISAKEVTool._cache = {"fetched_at": 0.0, "entries": None}
        tool = CISAKEVTool()
        catalog = {"vulnerabilities": [{"cveID": "CVE-2017-0144", "vendorProject": "Microsoft",
                                        "product": "SMBv1", "vulnerabilityName": "EternalBlue",
                                        "knownRansomwareCampaignUse": "Known"}]}
        with patch("aiohttp.ClientSession.get", return_value=mock_response(200, catalog)):
            async with tool:
                hit = await tool.query_cves(["cve-2017-0144", "CVE-2099-0001"])
        assert hit.success is True
        assert hit.data["kev_matches"][0]["cve"] == "CVE-2017-0144"
        assert hit.data["reputation_score"] >= 0.9

        # Cached: a second lookup works with the network gone
        with patch("aiohttp.ClientSession.get", side_effect=aiohttp.ClientConnectionError()):
            async with tool:
                cached = await tool.query_cves(["CVE-2017-0144"])
        assert cached.success is True

        CISAKEVTool._cache = {"fetched_at": 0.0, "entries": None}
        async with tool:
            offline = await tool.query_cves(["CVE-2017-0144"])
        assert offline.success is False
        assert "unavailable" in offline.error


class TestToolRegistry:
    @pytest.fixture
    def registry(self):
        return ToolRegistry({"virustotal": "vt_test_key", "abuseipdb": "abuse_test_key", "shodan": "shodan_test_key"},
                            {"enable_keyless_intel": False})

    def test_tool_initialization(self, registry):
        assert set(registry.tools) == {"local_forensics", "virustotal", "abuseipdb", "shodan"}

    def test_keyless_defaults_with_zero_keys(self):
        registry = ToolRegistry({})
        assert set(registry.tools) == {"local_forensics", "internetdb", "rdap", "cisa_kev"}

    def test_placeholder_keys_not_registered(self):
        registry = ToolRegistry({"virustotal": "your_virustotal_api_key_here", "shodan": ""},
                                {"enable_keyless_intel": False})
        assert set(registry.tools) == {"local_forensics"}

    def test_get_tool_capabilities(self, registry):
        caps = registry.get_tool_capabilities()
        assert set(caps["virustotal"]) == {"ip_reputation", "url_reputation", "file_reputation"}
        assert caps["abuseipdb"] == ["ip_reputation"]
        assert "url_reputation" not in caps["shodan"]

    async def test_query_ip_reputation_aggregation(self, registry):
        results = {
            "virustotal": ToolResult(True, "virustotal", {"reputation_score": 0.8, "indicators": ["VT"]}),
            "abuseipdb": ToolResult(True, "abuseipdb", {"reputation_score": 0.6, "indicators": ["Abuse"]}),
            "shodan": ToolResult(True, "shodan", {"reputation_score": 0.4, "indicators": ["Shodan"]}),
        }
        with patch.object(registry.tools["virustotal"], "query_ip", return_value=results["virustotal"]), \
             patch.object(registry.tools["abuseipdb"], "query_ip", return_value=results["abuseipdb"]), \
             patch.object(registry.tools["shodan"], "query_ip", return_value=results["shodan"]):
            result = await registry.query_ip_reputation("1.1.1.1")
        assert result.success is True
        assert result.data["reputation_score"] == 0.8
        assert set(result.data["reputation_sources"]) == {"virustotal", "abuseipdb", "shodan"}
        assert result.data["local_sources"] == ["local_forensics"]
        assert result.data["confidence"] == 1.0
        assert registry.api_call_counts == {"virustotal": 1, "abuseipdb": 1, "shodan": 1}

    async def test_private_ip_skips_external_tools(self, registry):
        mocks = {n: AsyncMock() for n in ("virustotal", "abuseipdb", "shodan")}
        with patch.object(registry.tools["virustotal"], "query_ip", mocks["virustotal"]), \
             patch.object(registry.tools["abuseipdb"], "query_ip", mocks["abuseipdb"]), \
             patch.object(registry.tools["shodan"], "query_ip", mocks["shodan"]):
            result = await registry.query_ip_reputation("10.0.0.5")
        for mock in mocks.values():
            mock.assert_not_called()
        assert result.success is True
        assert result.data["reputation_sources"] == []
        assert result.data["errors"]["virustotal"] == NON_PUBLIC_SKIP_ERROR
        assert registry.api_call_counts == {}

    async def test_query_with_no_available_tools(self):
        result = await ToolRegistry({}).query_ip_reputation("1.1.1.1", sources=["nonexistent_tool"])
        assert result.success is False
        assert "No tools available" in result.error

    async def test_partial_failure_handling(self, registry):
        with patch.object(registry.tools["virustotal"], "query_ip",
                          return_value=ToolResult(True, "virustotal", {"reputation_score": 0.8, "indicators": []})), \
             patch.object(registry.tools["abuseipdb"], "query_ip",
                          return_value=ToolResult(False, "abuseipdb", {}, error="API error")), \
             patch.object(registry.tools["shodan"], "query_ip", side_effect=Exception("Network error")):
            result = await registry.query_ip_reputation("1.1.1.1", sources=["virustotal", "abuseipdb", "shodan"])
        assert result.success is True
        assert result.data["confidence"] < 1.0
        assert result.data["sources_queried"] == ["virustotal"]

    async def test_all_failures_report_errors(self, registry):
        with patch.object(registry.tools["virustotal"], "query_ip",
                          return_value=ToolResult(False, "virustotal", {}, error="HTTP 500")):
            result = await registry.query_ip_reputation("1.1.1.1", sources=["virustotal"])
        assert result.success is False
        assert result.data["errors"]["virustotal"] == "HTTP 500"


class TestSessionSafety:
    async def test_tool_context_manager(self):
        tool = VirusTotalTool("test_key")
        async with tool:
            assert isinstance(tool._session, aiohttp.ClientSession)
        assert tool._session.closed is True

    async def test_registry_never_mutates_shared_tool_session(self):
        registry = ToolRegistry({"virustotal": "real_key_123456"}, {"enable_keyless_intel": False})
        vt = registry.tools["virustotal"]
        seen_sessions = []

        async def fake_query(self_clone, ip):
            seen_sessions.append(self_clone._session)
            await asyncio.sleep(0.01)
            assert not self_clone._session.closed
            return ToolResult(True, "virustotal", {"reputation_score": 0.1, "indicators": []})

        with patch.object(VirusTotalTool, "query_ip", fake_query):
            results = await asyncio.gather(*[registry.query_ip_reputation("1.1.1.1") for _ in range(5)])

        assert all(r.success for r in results)
        assert vt._session is None  # the shared instance is never bound to a session
        assert len({id(s) for s in seen_sessions}) == 5  # one isolated session per query
        assert all(s.closed for s in seen_sessions)
        assert registry.api_call_counts["virustotal"] == 5
