"""
Unit tests for agent/reporter.py
"""

import pytest
import tempfile
import os
import json
from datetime import datetime
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
            start_time=datetime.utcnow(),
        )

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
            start_time=datetime.utcnow(),
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
