"""
Unit tests for agent/reporter.py
"""

import pytest
import tempfile
import os
from datetime import datetime, timezone
from types import SimpleNamespace

from agent.reporter import IncidentReporter, ReportSection


class TestReportSection:
    def test_creation(self):
        section = ReportSection(
            title="Executive Summary",
            content="Summary content here.",
            severity="warning",
            data={"key": "val"},
        )
        assert section.title == "Executive Summary"
        assert section.severity == "warning"

    def test_defaults(self):
        section = ReportSection(title="Test", content="Body")
        assert section.severity == "info"
        assert section.data is None


def make_sample_context():
    return SimpleNamespace(
        event_id="evt_rpt_001",
        event_data={
            "event_type": "suspicious_ip",
            "source_ip": "192.168.1.100",
            "user_agent": "python-requests/2.28",
            "payload": {"failed_login_attempts": 25},
        },
        risk_assessment={
            "risk_score": 0.75,
            "risk_level": "high",
            "base_risk": 0.6,
            "intel_risk": 0.8,
            "pattern_risk": 0.3,
            "confidence": 0.85,
        },
        intelligence_data={
            "sources": ["virustotal"],
            "reputation_score": 0.8,
            "confidence": 0.7,
            "threat_indicators": ["known_malicious"],
        },
        recommended_actions=[
            {"action_type": "BLOCK", "priority": 1, "description": "Block IP", "estimated_effort": "5 min"},
        ],
        reasoning_log=["Assessment done", "Intel gathered"],
        start_time=datetime.now(timezone.utc),
    )


class TestIncidentReporter:
    @pytest.fixture
    def temp_dir(self):
        with tempfile.TemporaryDirectory() as d:
            yield d

    @pytest.fixture
    def reporter(self, temp_dir):
        return IncidentReporter({
            "reports_dir": temp_dir,
            "auto_save": False,
        })

    @pytest.fixture
    def sample_context(self):
        return make_sample_context()

    def test_initialization(self, reporter, temp_dir):
        assert reporter.reports_dir == os.path.realpath(temp_dir) or str(reporter.reports_dir) == temp_dir

    @pytest.mark.asyncio
    async def test_generate_report(self, reporter, sample_context):
        report = await reporter.generate_report(sample_context)
        assert "metadata" in report
        assert "executive_summary" in report
        assert "risk_assessment" in report
        assert "recommended_actions" in report
        assert report["metadata"]["event_id"] == "evt_rpt_001"

    @pytest.mark.asyncio
    async def test_generate_report_formats(self, reporter, sample_context):
        report = await reporter.generate_report(sample_context)
        assert "formats" in report
        assert "markdown" in report["formats"]
        assert "json" in report["formats"]
        assert "Investigation Report" in report["formats"]["markdown"]

    @pytest.mark.asyncio
    async def test_generate_report_with_auto_save(self, temp_dir):
        reporter = IncidentReporter({"reports_dir": temp_dir, "auto_save": True})
        ctx = SimpleNamespace(
            event_id="evt_save_001",
            event_data={"event_type": "suspicious_ip", "source_ip": "10.0.0.1"},
            risk_assessment={"risk_score": 0.5, "risk_level": "medium", "confidence": 0.6},
            intelligence_data={"sources": [], "reputation_score": 0, "confidence": 0},
            recommended_actions=[],
            reasoning_log=[],
            start_time=datetime.now(timezone.utc),
        )
        await reporter.generate_report(ctx)

        files = os.listdir(temp_dir)
        md_files = [f for f in files if f.endswith(".md")]
        json_files = [f for f in files if f.endswith(".json")]
        assert len(md_files) >= 1
        assert len(json_files) >= 1

    def test_generate_executive_summary(self, reporter, sample_context):
        summary = reporter._generate_executive_summary(sample_context)
        assert "suspicious_ip" in summary
        assert "HIGH" in summary
        assert "192.168.1.100" in summary

    def test_generate_event_analysis(self, reporter, sample_context):
        analysis = reporter._generate_event_analysis(sample_context)
        assert analysis["event_type"] == "suspicious_ip"
        assert analysis["source_ip"] == "192.168.1.100"

    def test_generate_risk_assessment_section(self, reporter, sample_context):
        section = reporter._generate_risk_assessment_section(sample_context)
        assert section["overall_score"] == 0.75
        assert section["risk_level"] == "high"

    def test_generate_actions_section(self, reporter, sample_context):
        actions = reporter._generate_actions_section(sample_context)
        assert len(actions) == 1
        assert actions[0]["action_type"] == "BLOCK"

    def test_extract_indicators(self, reporter, sample_context):
        indicators = reporter._extract_indicators(sample_context)
        ip_indicators = [i for i in indicators if i["type"] == "ip"]
        assert len(ip_indicators) >= 1
        assert ip_indicators[0]["value"] == "192.168.1.100"

    def test_identify_risk_factors(self, reporter, sample_context):
        factors = reporter._identify_risk_factors(sample_context)
        assert len(factors) > 0

    def test_determine_action_urgency(self, reporter):
        assert reporter._determine_action_urgency({"priority": 1}) == "IMMEDIATE"
        assert reporter._determine_action_urgency({"priority": 2}) == "HIGH"
        assert reporter._determine_action_urgency({"priority": 3}) == "MEDIUM"
        assert reporter._determine_action_urgency({"priority": 5}) == "LOW"

    @pytest.mark.asyncio
    async def test_error_report(self, reporter):
        ctx = SimpleNamespace(event_id="evt_err")
        report = reporter._generate_error_report(ctx, Exception("test failure"))
        assert report["metadata"]["status"] == "ERROR"
        assert "test failure" in report["metadata"]["error"]


class TestReporterHardening:
    @pytest.fixture
    def reporter(self, tmp_path):
        return IncidentReporter({"reports_dir": str(tmp_path), "auto_save": False})

    @pytest.fixture
    def sample_context(self):
        return make_sample_context()

    @pytest.fixture
    def hostile_context(self):
        return SimpleNamespace(
            event_id="evt_xss",
            event_data={
                "event_type": "prompt_injection",
                "source_ip": "8.8.8.8",
                "url": "http://evil.example.com/a'b",
                "user_agent": "<script>alert('ua')</script>",
                "payload": {"note": "<img src=x onerror=alert(1)>"},
            },
            risk_assessment={"risk_score": 0.82, "risk_level": "critical", "base_risk": 0.9, "intel_risk": None,
                             "pattern_risk": 0.0, "confidence": 0.6,
                             "llm_analysis": {"threat_assessment": "<b>bold</b><script>x()</script>",
                                              "confidence": 0.7, "urgency": "high", "risk_modifier": 0.8,
                                              "key_findings": ["<iframe src=//evil>"]},
                             "llm_risk": 0.8},
            intelligence_data={"sources": [], "local_sources": ["local_forensics"], "reputation_score": 0.0,
                               "confidence": 1.0, "threat_indicators": ["[local_forensics] <svg onload=1>"]},
            detection_assessment={"findings": [{"rule_id": "LLM-PI-001", "title": "<script>t</script>",
                                                "severity": 0.9, "evidence": ["<b>e</b>"]}],
                                  "mitre_attack": ["T1190"], "mitre_atlas": ["AML.T0051"],
                                  "owasp_llm": ["LLM01:2025"],
                                  "extracted_iocs": {"ips": ["8.8.8.8", "10.0.0.1"], "domains": ["evil.example.com"],
                                                     "sha256": ["a" * 64]},
                                  "redacted_secret_types": ["aws_access_key"]},
            prompt_injection_scan={"detected": True, "score": 0.8, "matched_rules": ["instruction_override"]},
            pattern_insights=[{"pattern_type": "ip_frequency", "description": "<u>seen</u>", "confidence": 0.5}],
            recommended_actions=[{"action_type": "ESCALATE", "priority": 1, "description": "<script>a</script>",
                                  "estimated_effort": "1m"}],
            reasoning_log=["<script>log</script>"],
            start_time=datetime.now(timezone.utc),
            status="pending_human_review",
        )

    async def test_intel_none_does_not_crash(self, reporter, sample_context):
        sample_context.risk_assessment["intel_risk"] = None
        report = await reporter.generate_report(sample_context)
        assert report["metadata"]["status"] != "ERROR"
        md = report["formats"]["markdown"]
        assert "| Intelligence Risk | N/A |" in md
        assert "Uncertainty Floor (+0.25)" in md
        assert "| Base Risk (event evidence) | 0.60 | 70% | 0.420 |" in md
        assert report["risk_assessment"]["component_scores"]["intelligence_risk"] is None

    async def test_weights_with_intel_and_llm(self, reporter, sample_context):
        sample_context.risk_assessment["llm_analysis"] = {"confidence": 0.5}
        sample_context.risk_assessment["llm_risk"] = 0.5
        md = (await reporter.generate_report(sample_context))["formats"]["markdown"]
        assert "| Intelligence Risk | 0.80 | 35% | 0.280 |" in md
        assert "| LLM Modifier | 0.50 | 30% | 0.150 |" in md
        assert "Uncertainty Floor" not in md

    async def test_html_is_xss_safe(self, reporter, hostile_context):
        html = (await reporter.generate_report(hostile_context))["formats"]["html"]
        for raw in ("<script>", "<img src=x", "<iframe", "<svg onload", "<b>bold</b>", "<u>seen</u>"):
            assert raw not in html
        assert "&lt;script&gt;" in html
        assert "Content-Security-Policy" in html and "default-src 'none'" in html

    async def test_markdown_sections_and_defang(self, reporter, hostile_context):
        md = (await reporter.generate_report(hostile_context))["formats"]["markdown"]
        for section in ("MITRE ATT&CK | T1190", "MITRE ATLAS | AML.T0051", "OWASP LLM Top 10 (2025) | LLM01:2025",
                        "Prompt injection in telemetry:** DETECTED", "aws_access_key", "## LLM Analysis",
                        "## Pattern Insights"):
            assert section in md
        assert "`8[.]8[.]8[.]8`" in md and "`8.8.8.8`" in md
        assert "hxxp://evil[.]example[.]com" in md

    async def test_stix_bundle(self, reporter, hostile_context):
        import json as _json
        bundle = _json.loads((await reporter.generate_report(hostile_context))["formats"]["stix"])
        assert bundle["type"] == "bundle" and bundle["id"].startswith("bundle--")
        by_type = {}
        for obj in bundle["objects"]:
            by_type.setdefault(obj["type"], []).append(obj)
            if obj["type"] != "bundle":
                assert obj.get("spec_version") == "2.1"
        patterns = [i["pattern"] for i in by_type["indicator"]]
        assert "[ipv4-addr:value = '8.8.8.8']" in patterns
        assert "[url:value = 'http://evil.example.com/a\\'b']" in patterns  # quote escaped
        assert "[file:hashes.'SHA-256' = '" + "a" * 64 + "']" in patterns
        assert not any("10.0.0.1" in p for p in patterns)  # private IPs are not shared as indicators
        assert any(o["value"] == "10.0.0.1" for o in by_type["ipv4-addr"])
        report = by_type["report"][0]
        ids = {o["id"] for o in bundle["objects"]}
        assert set(report["object_refs"]) <= ids
        assert by_type["observed-data"][0]["number_observed"] == 1
        assert {"T1190", "AML.T0051"} <= {a["name"] for a in by_type["attack-pattern"]}

    async def test_auto_save_consistent_names(self, tmp_path, sample_context):
        reporter = IncidentReporter({"reports_dir": str(tmp_path), "auto_save": True})
        sample_context.event_id = "inv_abc123"
        await reporter.generate_report(sample_context)
        names = sorted(p.name for p in tmp_path.iterdir())
        assert len(names) == 3
        assert all(n.startswith("rpt_") and "_inv_abc123." in n for n in names)
        assert {n.rsplit(".", 1)[1] for n in names} == {"json", "md", "html"}
