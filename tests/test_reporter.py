"""
Unit tests for agent/reporter.py

Tests the incident report generation system including Markdown/JSON
report creation, templating, and file operations.
"""

import pytest
import asyncio
import tempfile
import os
import json
from datetime import datetime
from unittest.mock import patch, MagicMock
from typing import Dict, Any

from agent.reporter import (
    IncidentReporter, ReportSection, InvestigationReport
)
from agent.planner import (
    InvestigationContext, SecurityEvent, ThreatIntelligence, 
    RiskAssessment, ActionRecommendation
)


class TestReportSection:
    """Test ReportSection dataclass"""
    
    def test_report_section_creation(self):
        """Test basic ReportSection creation"""
        section = ReportSection(
            title="Executive Summary",
            content="This is a summary of the investigation.",
            level=1,
            metadata={"section_type": "summary"}
        )
        
        assert section.title == "Executive Summary"
        assert "summary" in section.content
        assert section.level == 1
        assert section.metadata["section_type"] == "summary"


class TestInvestigationReport:
    """Test InvestigationReport dataclass"""
    
    def test_investigation_report_creation(self):
        """Test basic InvestigationReport creation"""
        report = InvestigationReport(
            investigation_id="rpt_001",
            event_summary="Suspicious IP investigation",
            findings=["Malicious IP detected", "High risk score"],
            recommended_actions=["Block IP", "Monitor network"],
            report_format="markdown",
            content="# Investigation Report\n\nDetailed findings..."
        )
        
        assert report.investigation_id == "rpt_001"
        assert "suspicious" in report.event_summary.lower()
        assert len(report.findings) == 2
        assert len(report.recommended_actions) == 2
        assert report.report_format == "markdown"
        assert "Investigation Report" in report.content


class TestIncidentReporter:
    """Test IncidentReporter functionality"""
    
    @pytest.fixture
    def temp_reports_dir(self):
        """Create temporary directory for test reports"""
        with tempfile.TemporaryDirectory() as temp_dir:
            yield temp_dir
    
    @pytest.fixture
    def reporter(self, temp_reports_dir):
        """Create IncidentReporter instance for testing"""
        return IncidentReporter(reports_dir=temp_reports_dir)
    
    @pytest.fixture
    def sample_investigation_context(self):
        """Create comprehensive investigation context for testing"""
        # Create security event
        event = SecurityEvent(
            event_id="evt_report_001",
            event_type="suspicious_ip",
            source_ip="192.168.1.100",
            timestamp=datetime.now(),
            severity="high",
            description="Multiple failed login attempts from suspicious IP address"
        )
        
        # Create threat intelligence
        threat_intel = [
            ThreatIntelligence(
                source="virustotal",
                reputation_score=0.85,
                indicators=["Known malicious IP", "Associated with malware distribution"],
                raw_data={"vt_response": {"positives": 15, "total": 20}}
            ),
            ThreatIntelligence(
                source="abuseipdb",
                reputation_score=0.72,
                indicators=["Abuse confidence: 72%", "Usage type: datacenter"],
                raw_data={"abuse_data": {"confidence": 72, "country": "US"}}
            )
        ]
        
        # Create risk assessment
        risk_assessment = RiskAssessment(
            risk_level="high",
            risk_score=0.87,
            factors=[
                "High reputation score from multiple sources",
                "Recent malicious activity indicators",
                "Failed authentication attempts"
            ],
            confidence=0.92
        )
        
        # Create action recommendations
        action_recommendations = [
            ActionRecommendation(
                action_type="BLOCK_IP",
                target="192.168.1.100",
                priority="critical",
                reason="Confirmed malicious IP with active threat indicators",
                implementation_details={"rule_name": "auto_block_malicious_ip"}
            ),
            ActionRecommendation(
                action_type="SEND_ALERT",
                target="#security-team",
                priority="high",
                reason="High-risk security event requiring immediate attention",
                implementation_details={"channel": "slack", "urgency": "high"}
            ),
            ActionRecommendation(
                action_type="CREATE_INCIDENT",
                target="security-incidents",
                priority="medium",
                reason="Document security event for compliance and tracking",
                implementation_details={"incident_type": "security_breach", "severity": "high"}
            )
        ]
        
        # Create investigation context
        context = InvestigationContext(
            event=event,
            threat_intelligence=threat_intel,
            risk_assessment=risk_assessment,
            action_recommendations=action_recommendations
        )
        
        context.investigation_id = "inv_report_001"
        context.status = "completed"
        context.start_time = datetime.now()
        context.end_time = datetime.now()
        
        return context
    
    def test_reporter_initialization(self, reporter, temp_reports_dir):
        """Test reporter initialization"""
        assert reporter.reports_dir == temp_reports_dir
        assert os.path.exists(temp_reports_dir)
        assert hasattr(reporter, 'template_env')
    
    @pytest.mark.asyncio
    async def test_generate_report_markdown(self, reporter, sample_investigation_context):
        """Test generating markdown report"""
        report = await reporter.generate_report(
            sample_investigation_context,
            report_format="markdown"
        )
        
        assert isinstance(report, InvestigationReport)
        assert report.investigation_id == "inv_report_001"
        assert report.report_format == "markdown"
        assert "# Investigation Report" in report.content
        assert "192.168.1.100" in report.content
        assert "Executive Summary" in report.content
    
    @pytest.mark.asyncio
    async def test_generate_report_json(self, reporter, sample_investigation_context):
        """Test generating JSON report"""
        report = await reporter.generate_report(
            sample_investigation_context,
            report_format="json"
        )
        
        assert report.report_format == "json"
        
        # Verify JSON content is valid
        json_data = json.loads(report.content)
        assert json_data["investigation_id"] == "inv_report_001"
        assert "event" in json_data
        assert "threat_intelligence" in json_data
        assert "risk_assessment" in json_data
        assert "action_recommendations" in json_data
    
    @pytest.mark.asyncio
    async def test_generate_report_with_auto_save(self, reporter, sample_investigation_context):
        """Test generating report with automatic file saving"""
        report = await reporter.generate_report(
            sample_investigation_context,
            report_format="markdown",
            auto_save=True
        )
        
        # Check that files were saved
        md_file = os.path.join(reporter.reports_dir, f"{report.investigation_id}.md")
        json_file = os.path.join(reporter.reports_dir, f"{report.investigation_id}.json")
        
        assert os.path.exists(md_file)
        assert os.path.exists(json_file)
        
        # Verify file contents
        with open(md_file, 'r') as f:
            md_content = f.read()
            assert "# Investigation Report" in md_content
        
        with open(json_file, 'r') as f:
            json_content = json.load(f)
            assert json_content["investigation_id"] == "inv_report_001"
    
    def test_extract_metadata_section(self, reporter, sample_investigation_context):
        """Test extracting metadata section"""
        section = reporter._extract_metadata_section(sample_investigation_context)
        
        assert section.title == "Investigation Metadata"
        assert sample_investigation_context.investigation_id in section.content
        assert "evt_report_001" in section.content
        assert "suspicious_ip" in section.content
    
    def test_extract_executive_summary_section(self, reporter, sample_investigation_context):
        """Test extracting executive summary section"""
        section = reporter._extract_executive_summary_section(sample_investigation_context)
        
        assert section.title == "Executive Summary"
        assert "high-risk" in section.content.lower()
        assert "192.168.1.100" in section.content
        assert "malicious" in section.content.lower()
    
    def test_extract_event_analysis_section(self, reporter, sample_investigation_context):
        """Test extracting event analysis section"""
        section = reporter._extract_event_analysis_section(sample_investigation_context)
        
        assert section.title == "Event Analysis"
        assert "failed login attempts" in section.content.lower()
        assert "192.168.1.100" in section.content
        assert "high" in section.content.lower()
    
    def test_extract_threat_intelligence_section(self, reporter, sample_investigation_context):
        """Test extracting threat intelligence section"""
        section = reporter._extract_threat_intelligence_section(sample_investigation_context)
        
        assert section.title == "Threat Intelligence Analysis"
        assert "virustotal" in section.content.lower()
        assert "abuseipdb" in section.content.lower()
        assert "0.85" in section.content  # VirusTotal score
        assert "0.72" in section.content  # AbuseIPDB score
    
    def test_extract_risk_assessment_section(self, reporter, sample_investigation_context):
        """Test extracting risk assessment section"""
        section = reporter._extract_risk_assessment_section(sample_investigation_context)
        
        assert section.title == "Risk Assessment"
        assert "high" in section.content.lower()
        assert "0.87" in section.content  # Risk score
        assert "0.92" in section.content  # Confidence
        assert "reputation score" in section.content.lower()
    
    def test_extract_actions_section(self, reporter, sample_investigation_context):
        """Test extracting recommended actions section"""
        section = reporter._extract_actions_section(sample_investigation_context)
        
        assert section.title == "Recommended Actions"
        assert "BLOCK_IP" in section.content
        assert "SEND_ALERT" in section.content
        assert "CREATE_INCIDENT" in section.content
        assert "critical" in section.content.lower()
    
    def test_extract_timeline_section(self, reporter, sample_investigation_context):
        """Test extracting investigation timeline section"""
        section = reporter._extract_timeline_section(sample_investigation_context)
        
        assert section.title == "Investigation Timeline"
        assert "started" in section.content.lower()
        assert "completed" in section.content.lower()
    
    def test_extract_technical_details_section(self, reporter, sample_investigation_context):
        """Test extracting technical details section"""
        section = reporter._extract_technical_details_section(sample_investigation_context)
        
        assert section.title == "Technical Details"
        assert "Event Type" in section.content
        assert "Risk Score" in section.content
        assert "suspicious_ip" in section.content
    
    def test_extract_iocs_section(self, reporter, sample_investigation_context):
        """Test extracting indicators of compromise section"""
        section = reporter._extract_iocs_section(sample_investigation_context)
        
        assert section.title == "Indicators of Compromise (IoCs)"
        assert "192.168.1.100" in section.content
        assert "IP Address" in section.content
    
    def test_render_markdown_report(self, reporter, sample_investigation_context):
        """Test rendering markdown report from sections"""
        sections = [
            ReportSection("Test Section 1", "Content 1", 1),
            ReportSection("Test Section 2", "Content 2", 2),
            ReportSection("Test Subsection", "Content 3", 3)
        ]
        
        markdown_content = reporter._render_markdown_report(sections, sample_investigation_context)
        
        assert "# Test Section 1" in markdown_content
        assert "## Test Section 2" in markdown_content
        assert "### Test Subsection" in markdown_content
        assert "Content 1" in markdown_content
    
    def test_render_json_report(self, reporter, sample_investigation_context):
        """Test rendering JSON report from context"""
        json_content = reporter._render_json_report(sample_investigation_context)
        
        json_data = json.loads(json_content)
        
        assert json_data["investigation_id"] == "inv_report_001"
        assert json_data["event"]["event_id"] == "evt_report_001"
        assert json_data["event"]["source_ip"] == "192.168.1.100"
        assert len(json_data["threat_intelligence"]) == 2
        assert json_data["risk_assessment"]["risk_level"] == "high"
        assert len(json_data["action_recommendations"]) == 3
    
    @pytest.mark.asyncio
    async def test_save_report_files(self, reporter, sample_investigation_context):
        """Test saving report files to disk"""
        markdown_content = "# Test Report\n\nTest content"
        json_content = '{"test": "data"}'
        
        await reporter._save_report_files(
            "test_investigation",
            markdown_content,
            json_content
        )
        
        # Verify files were created
        md_file = os.path.join(reporter.reports_dir, "test_investigation.md")
        json_file = os.path.join(reporter.reports_dir, "test_investigation.json")
        
        assert os.path.exists(md_file)
        assert os.path.exists(json_file)
        
        # Verify file contents
        with open(md_file, 'r') as f:
            assert f.read() == markdown_content
        
        with open(json_file, 'r') as f:
            assert json.load(f) == {"test": "data"}
    
    @pytest.mark.asyncio
    async def test_error_handling_invalid_format(self, reporter, sample_investigation_context):
        """Test error handling for invalid report format"""
        with pytest.raises(ValueError, match="Unsupported report format"):
            await reporter.generate_report(
                sample_investigation_context,
                report_format="invalid_format"
            )
    
    @pytest.mark.asyncio
    async def test_report_with_minimal_context(self, reporter):
        """Test generating report with minimal investigation context"""
        # Create minimal context
        event = SecurityEvent(
            event_id="minimal_evt",
            event_type="unknown",
            source_ip="unknown",
            timestamp=datetime.now(),
            severity="low",
            description="Minimal event for testing"
        )
        
        context = InvestigationContext(event=event)
        context.investigation_id = "minimal_inv"
        context.status = "completed"
        
        report = await reporter.generate_report(context, report_format="markdown")
        
        assert report.investigation_id == "minimal_inv"
        assert "minimal_evt" in report.content
        assert "No threat intelligence" in report.content
        assert "No specific risk assessment" in report.content
    
    @pytest.mark.asyncio
    async def test_concurrent_report_generation(self, reporter):
        """Test concurrent report generation"""
        contexts = []
        for i in range(3):
            event = SecurityEvent(
                f"concurrent_evt_{i}",
                "test_event",
                f"192.168.1.{i}",
                datetime.now(),
                "medium",
                f"Test event {i}"
            )
            context = InvestigationContext(event=event)
            context.investigation_id = f"concurrent_inv_{i}"
            contexts.append(context)
        
        # Generate reports concurrently
        tasks = [
            reporter.generate_report(context, report_format="markdown")
            for context in contexts
        ]
        reports = await asyncio.gather(*tasks)
        
        assert len(reports) == 3
        assert all(isinstance(report, InvestigationReport) for report in reports)
        assert len(set(report.investigation_id for report in reports)) == 3  # Unique IDs
    
    def test_template_customization(self, reporter):
        """Test template customization and rendering"""
        # Test that template environment is properly configured
        assert hasattr(reporter.template_env, 'get_template')
        
        # Test template loading
        template_str = "Investigation: {{ investigation_id }}\nRisk: {{ risk_level }}"
        template = reporter.template_env.from_string(template_str)
        
        rendered = template.render(
            investigation_id="test_001",
            risk_level="high"
        )
        
        assert "Investigation: test_001" in rendered
        assert "Risk: high" in rendered


class TestReporterIntegration:
    """Integration tests for reporter system"""
    
    @pytest.mark.asyncio
    async def test_full_reporting_workflow(self, temp_reports_dir):
        """Test complete reporting workflow"""
        reporter = IncidentReporter(reports_dir=temp_reports_dir)
        
        # Create comprehensive investigation context
        event = SecurityEvent(
            "integration_evt",
            "malware_detection",
            "203.0.113.45",
            datetime.now(),
            "critical",
            "Malware detected on critical server"
        )
        
        threat_intel = [
            ThreatIntelligence(
                "virustotal",
                0.95,
                ["Known malware signature", "Active C&C communication"],
                {"detection_ratio": "45/47"}
            )
        ]
        
        risk_assessment = RiskAssessment(
            "critical",
            0.95,
            ["Critical infrastructure", "Active malware", "High confidence"],
            0.98
        )
        
        actions = [
            ActionRecommendation(
                "QUARANTINE_HOST",
                "203.0.113.45",
                "critical",
                "Immediate isolation required",
                {"isolation_method": "network_segment"}
            )
        ]
        
        context = InvestigationContext(
            event=event,
            threat_intelligence=threat_intel,
            risk_assessment=risk_assessment,
            action_recommendations=actions
        )
        context.investigation_id = "integration_test_inv"
        context.status = "completed"
        
        # Generate and save report
        report = await reporter.generate_report(
            context,
            report_format="markdown",
            auto_save=True
        )
        
        # Verify report quality
        assert report.investigation_id == "integration_test_inv"
        assert "critical" in report.content.lower()
        assert "malware" in report.content.lower()
        assert "QUARANTINE_HOST" in report.content
        
        # Verify files exist
        md_file = os.path.join(temp_reports_dir, "integration_test_inv.md")
        json_file = os.path.join(temp_reports_dir, "integration_test_inv.json")
        
        assert os.path.exists(md_file)
        assert os.path.exists(json_file)
        
        # Verify file size (should be substantial)
        assert os.path.getsize(md_file) > 1000  # At least 1KB
        assert os.path.getsize(json_file) > 500   # At least 500B


# CLI Mock Demonstrations
class TestReporterCLIMockInteractions:
    """Mock CLI interactions for reporter testing"""
    
    @pytest.mark.mock
    def test_generate_report_cli_mock(self):
        """Mock CLI interaction for report generation"""
        print("\n=== Report Generation CLI Mock Demo ===")
        print("Command: python -m agent.reporter generate --investigation-id inv_2024_5678 --format markdown --save")
        print("Response:")
        print(json.dumps({
            "report_generation": {
                "investigation_id": "inv_2024_5678",
                "report_format": "markdown",
                "generation_timestamp": datetime.now().isoformat(),
                "processing_time_ms": 567
            },
            "report_metadata": {
                "title": "Security Investigation Report - Suspicious IP Activity",
                "sections_generated": 8,
                "total_content_length": 4523,
                "threat_intel_sources": 3,
                "recommended_actions": 4,
                "risk_level": "high"
            },
            "file_operations": {
                "markdown_file": "reports/inv_2024_5678.md",
                "json_file": "reports/inv_2024_5678.json",
                "file_sizes": {
                    "markdown_bytes": 4523,
                    "json_bytes": 2156
                },
                "auto_saved": True
            },
            "content_summary": {
                "executive_summary": "High-risk IP address 192.168.1.100 identified with multiple threat indicators",
                "key_findings": [
                    "VirusTotal reputation score: 0.87",
                    "Associated with known malware distribution",
                    "Recent failed authentication attempts detected"
                ],
                "primary_recommendations": [
                    "Immediate IP blocking required",
                    "Network monitoring enhancement",
                    "Incident documentation for compliance"
                ]
            }
        }, indent=2))
    
    @pytest.mark.mock
    def test_list_reports_cli_mock(self):
        """Mock CLI interaction for listing reports"""
        print("\n=== List Reports CLI Mock Demo ===")
        print("Command: python -m agent.reporter list --recent 10 --format table")
        print("Response:")
        print(json.dumps({
            "report_listing": {
                "total_reports": 156,
                "reports_shown": 10,
                "reports": [
                    {
                        "investigation_id": "inv_2024_5678",
                        "event_type": "suspicious_ip",
                        "risk_level": "high",
                        "generated_at": "2024-07-27T14:43:03Z",
                        "file_size_kb": 4.4,
                        "status": "completed"
                    },
                    {
                        "investigation_id": "inv_2024_5677",
                        "event_type": "malware_detection",
                        "risk_level": "critical",
                        "generated_at": "2024-07-27T13:28:15Z",
                        "file_size_kb": 6.7,
                        "status": "completed"
                    },
                    {
                        "investigation_id": "inv_2024_5676",
                        "event_type": "phishing_attempt",
                        "risk_level": "medium",
                        "generated_at": "2024-07-27T12:15:42Z",
                        "file_size_kb": 3.2,
                        "status": "completed"
                    },
                    {
                        "investigation_id": "inv_2024_5675",
                        "event_type": "data_exfiltration",
                        "risk_level": "critical",
                        "generated_at": "2024-07-27T11:05:28Z",
                        "file_size_kb": 8.1,
                        "status": "completed"
                    },
                    {
                        "investigation_id": "inv_2024_5674",
                        "event_type": "brute_force",
                        "risk_level": "medium",
                        "generated_at": "2024-07-27T09:45:17Z",
                        "file_size_kb": 2.9,
                        "status": "completed"
                    }
                ]
            },
            "storage_summary": {
                "total_storage_mb": 89.4,
                "reports_directory": "reports/",
                "oldest_report": "2024-01-15T08:30:00Z",
                "newest_report": "2024-07-27T14:43:03Z"
            }
        }, indent=2))
    
    @pytest.mark.mock
    def test_export_report_cli_mock(self):
        """Mock CLI interaction for report export"""
        print("\n=== Export Report CLI Mock Demo ===")
        print("Command: python -m agent.reporter export --investigation-id inv_2024_5678 --format pdf --output-dir /exports")
        print("Response:")
        print(json.dumps({
            "export_operation": {
                "investigation_id": "inv_2024_5678",
                "source_format": "markdown",
                "target_format": "pdf",
                "export_timestamp": datetime.now().isoformat(),
                "processing_time_ms": 1234
            },
            "export_results": {
                "output_file": "/exports/inv_2024_5678_report.pdf",
                "file_size_mb": 2.3,
                "pages_generated": 7,
                "export_quality": "high",
                "includes_charts": True,
                "includes_iocs": True
            },
            "document_metadata": {
                "title": "ThreatSentinel Investigation Report",
                "subject": "Security Investigation - Suspicious IP Activity",
                "author": "ThreatSentinel Autonomous Agent",
                "creation_date": datetime.now().isoformat(),
                "security_classification": "confidential",
                "document_version": "1.0"
            },
            "export_options_applied": {
                "watermark": True,
                "page_numbering": True,
                "table_of_contents": True,
                "executive_summary_highlight": True,
                "color_coding_by_risk": True
            }
        }, indent=2)) 