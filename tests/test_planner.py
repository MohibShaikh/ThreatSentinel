"""
Unit tests for agent/planner.py
"""

import pytest
from datetime import datetime
from unittest.mock import AsyncMock

from agent.planner import SOCAgentPlanner, InvestigationContext, InvestigationPhase


@pytest.fixture
def planner_config():
    return {
        "api_keys": {},
        "memory": {"db_path": ":memory:"},
        "reporting": {"output_dir": "/tmp/ts_test_reports"},
        "confidence_threshold": 0.7,
        "emergency_threshold": 0.8,
    }


@pytest.fixture
def planner(planner_config):
    return SOCAgentPlanner(planner_config)


class TestInvestigationContext:
    def test_creation(self):
        ctx = InvestigationContext(
            event_id="evt_001",
            event_data={"event_type": "suspicious_ip"},
            phase=InvestigationPhase.INITIAL_ASSESSMENT,
            intelligence_data={},
        )
        assert ctx.event_id == "evt_001"
        assert ctx.phase == InvestigationPhase.INITIAL_ASSESSMENT
        assert ctx.reasoning_log == []
        assert isinstance(ctx.start_time, datetime)


class TestSOCAgentPlanner:
    def test_initialization(self, planner):
        assert planner.confidence_threshold == 0.7
        assert planner.emergency_threshold == 0.8
        assert hasattr(planner, "tools")
        assert hasattr(planner, "memory")
        assert hasattr(planner, "reporter")

    def test_classify_event_severity(self, planner):
        assert planner._classify_event_severity({"event_type": "malware_detection"}) >= 0.7
        assert planner._classify_event_severity({"event_type": "suspicious_ip"}) >= 0.4
        assert planner._classify_event_severity({"event_type": "unknown"}) >= 0.2

    def test_classify_event_severity_with_failed_logins(self, planner):
        event = {
            "event_type": "suspicious_ip",
            "payload": {"failed_login_attempts": 20},
        }
        severity = planner._classify_event_severity(event)
        assert severity > planner._classify_event_severity({"event_type": "suspicious_ip"})

    def test_determine_risk_level(self, planner):
        assert planner._determine_risk_level(0.9) == "critical"
        assert planner._determine_risk_level(0.7) == "high"
        assert planner._determine_risk_level(0.4) == "medium"
        assert planner._determine_risk_level(0.1) == "low"

    def test_calculate_confidence(self, planner):
        ctx = InvestigationContext(
            event_id="evt_conf",
            event_data={},
            phase=InvestigationPhase.RISK_ANALYSIS,
            intelligence_data={"sources": ["vt", "abuse"], "confidence": 0.8},
        )
        confidence = planner._calculate_confidence(ctx)
        assert 0.0 <= confidence <= 1.0
        assert confidence > 0.5

    def test_generate_response_actions_critical(self, planner):
        ctx = InvestigationContext(
            event_id="evt_act",
            event_data={"event_type": "malware_detection"},
            phase=InvestigationPhase.ACTION_PLANNING,
            intelligence_data={},
        )
        actions = planner._generate_response_actions("critical", "malware_detection", ctx)
        assert len(actions) >= 2
        assert any(a["action_type"] == "BLOCK" for a in actions)
        assert any(a["action_type"] == "ESCALATE" for a in actions)

    def test_generate_response_actions_low(self, planner):
        ctx = InvestigationContext(
            event_id="evt_low",
            event_data={"event_type": "unknown"},
            phase=InvestigationPhase.ACTION_PLANNING,
            intelligence_data={},
        )
        actions = planner._generate_response_actions("low", "unknown", ctx)
        assert len(actions) >= 1
        assert actions[0]["action_type"] == "ALERT"

    def test_prioritize_actions_emergency(self, planner):
        actions = [
            {"action_type": "BLOCK", "priority": 1},
            {"action_type": "MONITOR", "priority": 3},
            {"action_type": "ESCALATE", "priority": 1},
        ]
        result = planner._prioritize_actions(actions, emergency_mode=True)
        assert all(a["priority"] <= 2 for a in result)

    def test_prioritize_actions_normal(self, planner):
        actions = [
            {"action_type": "MONITOR", "priority": 3},
            {"action_type": "BLOCK", "priority": 1},
        ]
        result = planner._prioritize_actions(actions, emergency_mode=False)
        assert result[0]["priority"] <= result[-1]["priority"]

    def test_load_escalation_rules(self, planner):
        rules = planner._load_escalation_rules()
        assert len(rules) > 0
        assert all("name" in r for r in rules)
        assert all("condition" in r for r in rules)

    def test_process_intelligence_results(self, planner):
        results = [
            {"success": True, "source": "vt", "reputation_score": 0.8, "indicators": ["mal"]},
            Exception("timeout"),
            {"success": True, "source": "abuse", "reputation_score": 0.6},
        ]
        processed = planner._process_intelligence_results(results)
        assert len(processed["sources"]) == 2
        assert processed["reputation_score"] == 0.8

    @pytest.mark.asyncio
    async def test_investigate_incident_basic(self, planner):
        planner.memory.find_similar_events = AsyncMock(return_value=[])
        planner.memory.store_investigation = AsyncMock(return_value=True)
        planner.reporter.generate_report = AsyncMock(return_value={})

        result = await planner.investigate_incident(
            {"event_type": "suspicious_ip", "source_ip": "10.0.0.1"}
        )

        assert result["status"] in ("completed", "pending_human_review")
        assert "risk_assessment" in result or "review_request" in result

    @pytest.mark.asyncio
    async def test_investigate_incident_emergency(self, planner):
        planner.memory.find_similar_events = AsyncMock(return_value=[])
        planner.memory.store_investigation = AsyncMock(return_value=True)
        planner.reporter.generate_report = AsyncMock(return_value={})

        result = await planner.investigate_incident(
            {"event_type": "malware_detection", "source_ip": "10.0.0.55"},
            emergency_mode=True,
        )

        assert result["status"] in ("completed", "failed")

    @pytest.mark.asyncio
    async def test_investigate_incident_failure_handling(self, planner):
        planner.memory.find_similar_events = AsyncMock(side_effect=Exception("db error"))

        result = await planner.investigate_incident(
            {"event_type": "suspicious_ip", "source_ip": "1.2.3.4"}
        )

        assert result["status"] == "failed"
        assert "error" in result

    @pytest.mark.asyncio
    async def test_process_analyst_feedback(self, planner):
        planner.memory.mark_false_positive = AsyncMock(return_value=True)
        planner.memory.add_missed_indicators = AsyncMock(return_value=True)

        feedback = {
            "analyst_id": "analyst_1",
            "review_status": "approved",
            "accuracy_rating": 4,
            "false_positive": False,
        }
        result = await planner.process_analyst_feedback("inv_001", feedback)
        assert result["status"] == "feedback_processed"

    @pytest.mark.asyncio
    async def test_process_analyst_feedback_false_positive(self, planner):
        planner.memory.mark_false_positive = AsyncMock(return_value=True)

        feedback = {
            "analyst_id": "analyst_2",
            "review_status": "rejected",
            "accuracy_rating": 1,
            "false_positive": True,
            "learning_notes": "benign scanner",
        }
        old_threshold = planner.confidence_threshold
        result = await planner.process_analyst_feedback("inv_002", feedback)
        assert result["status"] == "feedback_processed"
        assert planner.confidence_threshold >= old_threshold
