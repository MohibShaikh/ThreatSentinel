"""
Unit tests for agent/planner.py

Tests the main SOC agent orchestration engine including investigation
workflow, human review integration, and component coordination.
"""

import pytest
import asyncio
import tempfile
import json
from datetime import datetime
from unittest.mock import AsyncMock, MagicMock, patch
from typing import Dict, Any

from agent.planner import (
    SOCAgentPlanner, InvestigationContext, SecurityEvent, 
    ThreatIntelligence, RiskAssessment, ActionRecommendation,
    InvestigationReport
)


class TestSecurityEvent:
    """Test SecurityEvent dataclass"""
    
    def test_security_event_creation(self):
        """Test basic SecurityEvent creation"""
        event = SecurityEvent(
            event_id="evt_001",
            event_type="suspicious_ip",
            source_ip="192.168.1.100",
            timestamp=datetime.now(),
            severity="medium",
            description="Repeated failed login attempts"
        )
        
        assert event.event_id == "evt_001"
        assert event.event_type == "suspicious_ip"
        assert event.source_ip == "192.168.1.100"
        assert event.severity == "medium"
        assert "login" in event.description


class TestThreatIntelligence:
    """Test ThreatIntelligence dataclass"""
    
    def test_threat_intelligence_creation(self):
        """Test basic ThreatIntelligence creation"""
        threat_intel = ThreatIntelligence(
            source="virustotal",
            reputation_score=0.85,
            indicators=["Known malicious IP", "Associated with malware"],
            raw_data={"vt_response": "test_data"}
        )
        
        assert threat_intel.source == "virustotal"
        assert threat_intel.reputation_score == 0.85
        assert len(threat_intel.indicators) == 2
        assert "vt_response" in threat_intel.raw_data


class TestRiskAssessment:
    """Test RiskAssessment dataclass"""
    
    def test_risk_assessment_creation(self):
        """Test basic RiskAssessment creation"""
        risk = RiskAssessment(
            risk_level="high",
            risk_score=0.87,
            factors=["High reputation score", "Multiple threat indicators"],
            confidence=0.92
        )
        
        assert risk.risk_level == "high"
        assert risk.risk_score == 0.87
        assert len(risk.factors) == 2
        assert risk.confidence == 0.92


class TestActionRecommendation:
    """Test ActionRecommendation dataclass"""
    
    def test_action_recommendation_creation(self):
        """Test basic ActionRecommendation creation"""
        action = ActionRecommendation(
            action_type="BLOCK_IP",
            target="192.168.1.100",
            priority="high",
            reason="Malicious activity detected",
            implementation_details={"rule_name": "auto_block_rule"}
        )
        
        assert action.action_type == "BLOCK_IP"
        assert action.target == "192.168.1.100"
        assert action.priority == "high"
        assert "malicious" in action.reason.lower()


class TestInvestigationContext:
    """Test InvestigationContext dataclass"""
    
    @pytest.fixture
    def sample_context(self):
        """Create sample investigation context"""
        event = SecurityEvent(
            event_id="evt_001",
            event_type="suspicious_ip",
            source_ip="192.168.1.100",
            timestamp=datetime.now(),
            severity="medium",
            description="Suspicious IP activity"
        )
        
        return InvestigationContext(event=event)
    
    def test_investigation_context_creation(self, sample_context):
        """Test InvestigationContext creation"""
        assert sample_context.event.event_id == "evt_001"
        assert sample_context.threat_intelligence == []
        assert sample_context.risk_assessment is None
        assert sample_context.action_recommendations == []
        assert sample_context.requires_human_review is False


class TestSOCAgentPlanner:
    """Test SOCAgentPlanner functionality"""
    
    @pytest.fixture
    def temp_storage_dir(self):
        """Create temporary directory for test storage"""
        with tempfile.TemporaryDirectory() as temp_dir:
            yield temp_dir
    
    @pytest.fixture
    def mock_config(self):
        """Mock configuration for SOC agent"""
        return {
            "confidence_threshold": 0.8,
            "review_threshold": 0.75,
            "emergency_mode": False,
            "api_keys": {
                "virustotal": "test_vt_key",
                "abuseipdb": "test_abuse_key"
            }
        }
    
    @pytest.fixture
    def soc_agent(self, temp_storage_dir, mock_config):
        """Create SOCAgentPlanner instance for testing"""
        return SOCAgentPlanner(
            storage_path=temp_storage_dir,
            config=mock_config
        )
    
    @pytest.fixture
    def sample_event(self):
        """Create sample security event"""
        return SecurityEvent(
            event_id="test_evt_001",
            event_type="suspicious_ip",
            source_ip="192.168.1.100",
            timestamp=datetime.now(),
            severity="medium",
            description="Multiple failed login attempts from suspicious IP"
        )
    
    def test_soc_agent_initialization(self, soc_agent):
        """Test SOC agent initialization"""
        assert soc_agent.confidence_threshold == 0.8
        assert soc_agent.review_threshold == 0.75
        assert soc_agent.emergency_mode is False
        assert hasattr(soc_agent, 'tool_registry')
        assert hasattr(soc_agent, 'memory')
        assert hasattr(soc_agent, 'reporter')
    
    @pytest.mark.asyncio
    async def test_investigate_incident_basic_flow(self, soc_agent, sample_event):
        """Test basic investigation workflow"""
        # Mock tool registry responses
        mock_threat_intel = ThreatIntelligence(
            source="virustotal",
            reputation_score=0.7,
            indicators=["Associated with 2 malicious URLs"],
            raw_data={"vt_data": "test"}
        )
        
        soc_agent.tool_registry.query_ip_reputation = AsyncMock(return_value=mock_threat_intel)
        
        # Mock memory operations
        soc_agent.memory.find_similar_events = AsyncMock(return_value=[])
        soc_agent.memory.get_pattern_insights = AsyncMock(return_value=[])
        soc_agent.memory.store_investigation = AsyncMock()
        
        # Mock reporter
        soc_agent.reporter.generate_report = AsyncMock(return_value=InvestigationReport(
            investigation_id="test_inv_001",
            event_summary="Test investigation",
            findings=["Test finding"],
            recommended_actions=["Test action"],
            report_format="markdown",
            content="Test report content"
        ))
        
        # Run investigation
        result = await soc_agent.investigate_incident(sample_event)
        
        # Verify results
        assert result.investigation_id is not None
        assert result.event.event_id == "test_evt_001"
        assert result.risk_assessment is not None
        assert len(result.action_recommendations) > 0
        assert result.status == "completed"
    
    @pytest.mark.asyncio
    async def test_investigate_incident_with_human_review(self, soc_agent, sample_event):
        """Test investigation with human review trigger"""
        # Set up high-risk scenario that triggers human review
        mock_threat_intel = ThreatIntelligence(
            source="virustotal",
            reputation_score=0.95,  # Very high risk
            indicators=["Known malware distribution", "Command & Control server"],
            raw_data={"confidence": 0.6}  # Low confidence - triggers review
        )
        
        soc_agent.tool_registry.query_ip_reputation = AsyncMock(return_value=mock_threat_intel)
        soc_agent.memory.find_similar_events = AsyncMock(return_value=[])
        soc_agent.memory.get_pattern_insights = AsyncMock(return_value=[])
        soc_agent.memory.store_investigation = AsyncMock()
        
        # Run investigation
        result = await soc_agent.investigate_incident(sample_event)
        
        # Should trigger human review
        assert result.requires_human_review is True
        assert result.status == "pending_human_review"
        assert "escalation_details" in result.__dict__
        assert len(result.audit_trail) > 0
    
    @pytest.mark.asyncio
    async def test_investigate_incident_emergency_mode(self, soc_agent, sample_event):
        """Test investigation in emergency mode (bypasses human review)"""
        # Enable emergency mode
        soc_agent.emergency_mode = True
        
        # High-risk scenario that would normally trigger review
        mock_threat_intel = ThreatIntelligence(
            source="virustotal",
            reputation_score=0.95,
            indicators=["Critical threat"],
            raw_data={"confidence": 0.5}
        )
        
        soc_agent.tool_registry.query_ip_reputation = AsyncMock(return_value=mock_threat_intel)
        soc_agent.memory.find_similar_events = AsyncMock(return_value=[])
        soc_agent.memory.get_pattern_insights = AsyncMock(return_value=[])
        soc_agent.memory.store_investigation = AsyncMock()
        soc_agent.reporter.generate_report = AsyncMock(return_value=InvestigationReport(
            investigation_id="emergency_inv_001",
            event_summary="Emergency investigation",
            findings=["Critical finding"],
            recommended_actions=["Immediate action"],
            report_format="markdown",
            content="Emergency report"
        ))
        
        result = await soc_agent.investigate_incident(sample_event)
        
        # Should complete without human review even with high risk/low confidence
        assert result.requires_human_review is False
        assert result.status == "completed"
    
    def test_calculate_risk_score(self, soc_agent):
        """Test risk score calculation"""
        # Test with threat intelligence
        threat_intel = [
            ThreatIntelligence("virustotal", 0.8, ["indicator1"], {}),
            ThreatIntelligence("abuseipdb", 0.6, ["indicator2"], {})
        ]
        
        risk_score = soc_agent._calculate_risk_score(threat_intel, [])
        
        assert 0.0 <= risk_score <= 1.0
        assert risk_score > 0.6  # Should be influenced by threat intel scores
    
    def test_generate_action_recommendations(self, soc_agent, sample_event):
        """Test action recommendation generation"""
        # Mock risk assessment
        risk_assessment = RiskAssessment(
            risk_level="high",
            risk_score=0.85,
            factors=["High threat score"],
            confidence=0.9
        )
        
        # Mock threat intelligence
        threat_intel = [
            ThreatIntelligence("virustotal", 0.8, ["malicious"], {})
        ]
        
        actions = soc_agent._generate_action_recommendations(
            sample_event, risk_assessment, threat_intel
        )
        
        assert len(actions) > 0
        assert any(action.action_type == "BLOCK_IP" for action in actions)
        assert all(action.priority in ["low", "medium", "high", "critical"] for action in actions)
    
    def test_check_escalation_triggers(self, soc_agent):
        """Test escalation trigger checking"""
        # High risk + low confidence should trigger escalation
        context = InvestigationContext(
            event=SecurityEvent("test", "suspicious_ip", "1.1.1.1", datetime.now(), "high", "test")
        )
        
        risk_assessment = RiskAssessment(
            risk_level="high",
            risk_score=0.9,
            factors=["Critical threat"],
            confidence=0.5  # Low confidence
        )
        
        escalation_details = soc_agent._check_escalation_triggers(context, risk_assessment)
        
        assert escalation_details is not None
        assert "high_risk_low_confidence" in escalation_details["triggered_rules"]
    
    def test_create_audit_entry(self, soc_agent):
        """Test audit entry creation"""
        audit_entry = soc_agent._create_audit_entry(
            "investigation_started",
            "system",
            {"event_id": "test_001"}
        )
        
        assert audit_entry["event"] == "investigation_started"
        assert audit_entry["actor"] == "system"
        assert audit_entry["details"]["event_id"] == "test_001"
        assert "timestamp" in audit_entry
    
    @pytest.mark.asyncio
    async def test_process_analyst_feedback(self, soc_agent):
        """Test processing analyst feedback"""
        investigation_id = "test_inv_feedback"
        
        # Mock memory operations
        soc_agent.memory.update_investigation_outcome = AsyncMock()
        
        feedback = {
            "investigation_id": investigation_id,
            "analyst_id": "analyst_001",
            "outcome": "false_positive",
            "confidence": 0.95,
            "feedback": "This was a legitimate system scan",
            "missed_indicators": [],
            "accuracy_rating": 0.8
        }
        
        result = await soc_agent.process_analyst_feedback(feedback)
        
        assert result["status"] == "feedback_processed"
        assert result["confidence_adjustment"] is not None
        
        # Verify memory was updated
        soc_agent.memory.update_investigation_outcome.assert_called_once()
    
    @pytest.mark.asyncio
    async def test_error_handling_in_investigation(self, soc_agent, sample_event):
        """Test error handling during investigation"""
        # Mock a failure in threat intelligence gathering
        soc_agent.tool_registry.query_ip_reputation = AsyncMock(
            side_effect=Exception("API failure")
        )
        
        soc_agent.memory.find_similar_events = AsyncMock(return_value=[])
        soc_agent.memory.get_pattern_insights = AsyncMock(return_value=[])
        soc_agent.memory.store_investigation = AsyncMock()
        
        # Investigation should handle the error gracefully
        result = await soc_agent.investigate_incident(sample_event)
        
        # Should complete with reduced confidence due to missing threat intel
        assert result.status == "completed"
        assert result.risk_assessment.confidence < 0.8  # Reduced confidence
    
    @pytest.mark.asyncio
    async def test_concurrent_investigations(self, soc_agent):
        """Test handling concurrent investigations"""
        events = [
            SecurityEvent(f"evt_{i}", "suspicious_ip", f"192.168.1.{i}", 
                         datetime.now(), "medium", f"Event {i}")
            for i in range(3)
        ]
        
        # Mock all dependencies
        soc_agent.tool_registry.query_ip_reputation = AsyncMock(return_value=ThreatIntelligence(
            "virustotal", 0.5, ["test"], {}
        ))
        soc_agent.memory.find_similar_events = AsyncMock(return_value=[])
        soc_agent.memory.get_pattern_insights = AsyncMock(return_value=[])
        soc_agent.memory.store_investigation = AsyncMock()
        soc_agent.reporter.generate_report = AsyncMock(return_value=InvestigationReport(
            "test_inv", "test", ["finding"], ["action"], "markdown", "content"
        ))
        
        # Run concurrent investigations
        tasks = [soc_agent.investigate_incident(event) for event in events]
        results = await asyncio.gather(*tasks)
        
        assert len(results) == 3
        assert all(result.status == "completed" for result in results)
        assert len(set(result.investigation_id for result in results)) == 3  # Unique IDs
    
    def test_load_escalation_rules(self, soc_agent):
        """Test loading of escalation rules"""
        rules = soc_agent._load_escalation_rules()
        
        assert len(rules) > 0
        assert any(rule["name"] == "high_risk_low_confidence" for rule in rules)
        assert any(rule["name"] == "critical_infrastructure" for rule in rules)
        assert all("condition" in rule for rule in rules)
        assert all("description" in rule for rule in rules)
    
    @pytest.mark.asyncio
    async def test_memory_integration(self, soc_agent, sample_event):
        """Test integration with memory system"""
        # Mock similar events found in memory
        similar_event = type('MockMemory', (), {
            'investigation_id': 'prev_001',
            'event_type': 'suspicious_ip',
            'outcome': 'malicious',
            'confidence': 0.9
        })()
        
        soc_agent.memory.find_similar_events = AsyncMock(return_value=[similar_event])
        soc_agent.memory.get_pattern_insights = AsyncMock(return_value=[])
        soc_agent.memory.store_investigation = AsyncMock()
        
        # Mock threat intel
        soc_agent.tool_registry.query_ip_reputation = AsyncMock(return_value=ThreatIntelligence(
            "virustotal", 0.6, ["test"], {}
        ))
        
        soc_agent.reporter.generate_report = AsyncMock(return_value=InvestigationReport(
            "test_inv", "test", ["finding"], ["action"], "markdown", "content"
        ))
        
        result = await soc_agent.investigate_incident(sample_event)
        
        # Risk score should be influenced by similar events
        assert result.risk_assessment.risk_score > 0.6  # Boosted by similar malicious event
        
        # Memory should be updated with new investigation
        soc_agent.memory.store_investigation.assert_called_once()


class TestSOCAgentIntegration:
    """Integration tests for SOC agent workflow"""
    
    @pytest.mark.asyncio
    async def test_full_investigation_workflow(self, temp_storage_dir):
        """Test complete investigation workflow from start to finish"""
        config = {
            "confidence_threshold": 0.7,
            "api_keys": {"virustotal": "test_key"}
        }
        
        agent = SOCAgentPlanner(storage_path=temp_storage_dir, config=config)
        
        # Mock all external dependencies
        agent.tool_registry.query_ip_reputation = AsyncMock(return_value=ThreatIntelligence(
            "virustotal", 0.8, ["Known malicious IP"], {"vt_data": "test"}
        ))
        
        agent.memory.find_similar_events = AsyncMock(return_value=[])
        agent.memory.get_pattern_insights = AsyncMock(return_value=[])
        agent.memory.store_investigation = AsyncMock()
        
        agent.reporter.generate_report = AsyncMock(return_value=InvestigationReport(
            "full_workflow_inv",
            "Suspicious IP Investigation",
            ["High reputation score from VirusTotal"],
            ["Block IP address", "Monitor for additional activity"],
            "markdown",
            "# Investigation Report\n\nMalicious IP detected."
        ))
        
        # Create test event
        event = SecurityEvent(
            event_id="full_workflow_evt",
            event_type="suspicious_ip",
            source_ip="198.51.100.10",
            timestamp=datetime.now(),
            severity="high",
            description="Detected command & control communication"
        )
        
        # Run full investigation
        result = await agent.investigate_incident(event)
        
        # Verify all phases completed
        assert result.investigation_id is not None
        assert result.status == "completed"
        assert result.threat_intelligence is not None
        assert result.risk_assessment is not None
        assert len(result.action_recommendations) > 0
        assert result.report is not None
        assert len(result.audit_trail) > 0
        
        # Verify high-risk event generated appropriate responses
        assert result.risk_assessment.risk_level in ["high", "critical"]
        assert any(action.action_type == "BLOCK_IP" for action in result.action_recommendations)


# CLI Mock Demonstrations
class TestPlannerCLIMockInteractions:
    """Mock CLI interactions for planner testing"""
    
    @pytest.mark.mock
    def test_investigation_cli_mock(self):
        """Mock CLI interaction for starting investigation"""
        print("\n=== SOC Agent Investigation CLI Mock Demo ===")
        print("Command: python -m agent.planner investigate --event-file data/sample_events.json --event-id evt_001")
        print("Response:")
        print(json.dumps({
            "investigation_initiated": {
                "investigation_id": "inv_2024_5678",
                "event_id": "evt_001",
                "event_type": "suspicious_ip",
                "source_ip": "192.168.1.100",
                "severity": "high",
                "priority": "high",
                "estimated_completion_time": "2024-07-27T14:45:00Z"
            },
            "investigation_phases": {
                "phase_1_threat_intelligence": "in_progress",
                "phase_2_memory_analysis": "pending",
                "phase_3_risk_assessment": "pending",
                "phase_4_action_planning": "pending",
                "phase_5_report_generation": "pending"
            },
            "progress_tracking": {
                "current_phase": "threat_intelligence_gathering",
                "completion_percentage": 15,
                "estimated_time_remaining_seconds": 180
            },
            "real_time_updates": {
                "threat_intel_sources_queried": ["virustotal", "abuseipdb"],
                "preliminary_reputation_score": 0.75,
                "similar_events_found": 3
            },
            "investigation_timestamp": datetime.now().isoformat()
        }, indent=2))
    
    @pytest.mark.mock
    def test_investigation_status_cli_mock(self):
        """Mock CLI interaction for investigation status"""
        print("\n=== Investigation Status CLI Mock Demo ===")
        print("Command: python -m agent.planner status --investigation-id inv_2024_5678")
        print("Response:")
        print(json.dumps({
            "investigation_status": {
                "investigation_id": "inv_2024_5678",
                "current_status": "completed",
                "completion_percentage": 100,
                "total_execution_time_seconds": 42.7,
                "started_at": "2024-07-27T14:42:15Z",
                "completed_at": "2024-07-27T14:43:03Z"
            },
            "investigation_results": {
                "risk_assessment": {
                    "risk_level": "high",
                    "risk_score": 0.87,
                    "confidence": 0.92,
                    "primary_factors": [
                        "High reputation score from multiple threat intel sources",
                        "Associated with known malware distribution",
                        "Recent burst of failed login attempts"
                    ]
                },
                "threat_intelligence_summary": {
                    "sources_consulted": 4,
                    "total_indicators": 8,
                    "highest_reputation_score": 0.94,
                    "consensus_malicious": True
                },
                "recommended_actions": [
                    {
                        "action_type": "BLOCK_IP",
                        "target": "192.168.1.100",
                        "priority": "critical",
                        "reason": "Confirmed malicious IP with active threat indicators",
                        "estimated_impact": "high"
                    },
                    {
                        "action_type": "SEND_ALERT",
                        "target": "#security-team",
                        "priority": "high",
                        "reason": "Critical threat detected requiring immediate attention"
                    },
                    {
                        "action_type": "CREATE_INCIDENT",
                        "target": "security-incidents",
                        "priority": "high",
                        "reason": "Document security event for compliance and tracking"
                    }
                ]
            },
            "human_review": {
                "required": False,
                "reason": "High confidence automated assessment",
                "escalation_triggers": "none"
            },
            "execution_metrics": {
                "threat_intel_query_time_ms": 1247,
                "risk_assessment_time_ms": 89,
                "action_planning_time_ms": 156,
                "report_generation_time_ms": 234
            }
        }, indent=2))
    
    @pytest.mark.mock
    def test_human_review_cli_mock(self):
        """Mock CLI interaction for human review workflow"""
        print("\n=== Human Review Workflow CLI Mock Demo ===")
        print("Command: python -m agent.planner review --investigation-id inv_2024_5679 --analyst-feedback '{\"outcome\":\"confirmed_malicious\",\"confidence\":0.95}'")
        print("Response:")
        print(json.dumps({
            "review_processing": {
                "investigation_id": "inv_2024_5679",
                "analyst_id": "analyst_john_doe",
                "review_timestamp": datetime.now().isoformat(),
                "feedback_received": {
                    "outcome": "confirmed_malicious",
                    "analyst_confidence": 0.95,
                    "additional_indicators": [
                        "IP appears in recent threat feed update",
                        "Associated with APT group indicators"
                    ],
                    "false_positive": False,
                    "accuracy_rating": 0.88
                }
            },
            "agent_learning_update": {
                "confidence_threshold_adjustment": 0.02,
                "new_confidence_threshold": 0.82,
                "pattern_learning": {
                    "similar_event_pattern_updated": True,
                    "threat_signature_refined": True
                },
                "memory_updates": [
                    "Investigation outcome updated to 'confirmed_malicious'",
                    "Analyst feedback incorporated into pattern database"
                ]
            },
            "investigation_completion": {
                "final_status": "completed_with_human_validation",
                "actions_approved_for_execution": [
                    "BLOCK_IP: 192.168.1.100",
                    "CREATE_INCIDENT: SEC-2024-0567",
                    "NOTIFY: security-team"
                ],
                "compliance_documentation": "audit_trail_exported",
                "case_closed_timestamp": datetime.now().isoformat()
            }
        }, indent=2)) 