"""
Unit tests for agent/action_logger.py
"""

import pytest
import tempfile
import os
import sqlite3
import json
from datetime import datetime, timedelta

from agent.action_logger import (
    ActionLogger, ActionLog, ActionType, ActionStatus, LogLevel
)


class TestActionType:
    def test_action_type_values(self):
        assert ActionType.INVESTIGATION_STARTED.value == "investigation_started"
        assert ActionType.THREAT_INTEL_QUERY.value == "threat_intel_query"
        assert ActionType.RISK_ASSESSMENT.value == "risk_assessment"
        assert ActionType.INTEGRATION_EXECUTION.value == "integration_execution"
        assert ActionType.HUMAN_ESCALATION.value == "human_escalation"
        assert ActionType.PATTERN_DETECTION.value == "pattern_detection"
        assert ActionType.ERROR_OCCURRED.value == "error_occurred"
        assert ActionType.SYSTEM_EVENT.value == "system_event"


class TestActionStatus:
    def test_action_status_values(self):
        assert ActionStatus.SUCCESS.value == "success"
        assert ActionStatus.FAILED.value == "failed"
        assert ActionStatus.IN_PROGRESS.value == "in_progress"
        assert ActionStatus.CANCELLED.value == "cancelled"
        assert ActionStatus.PARTIAL.value == "partial"


class TestLogLevel:
    def test_log_level_values(self):
        assert LogLevel.DEBUG.value == "debug"
        assert LogLevel.INFO.value == "info"
        assert LogLevel.WARNING.value == "warning"
        assert LogLevel.ERROR.value == "error"
        assert LogLevel.CRITICAL.value == "critical"


class TestActionLog:
    def test_action_log_creation(self):
        log = ActionLog(
            id="log_001",
            timestamp=datetime.now(),
            investigation_id="inv_001",
            action_type=ActionType.THREAT_INTEL_QUERY,
            status=ActionStatus.SUCCESS,
            level=LogLevel.INFO,
            component="virustotal",
            description="Queried VT for IP",
            details={"ip": "192.168.1.1"},
        )
        assert log.id == "log_001"
        assert log.investigation_id == "inv_001"
        assert log.action_type == ActionType.THREAT_INTEL_QUERY
        assert log.status == ActionStatus.SUCCESS

    def test_action_log_to_dict(self):
        now = datetime.now()
        log = ActionLog(
            id="log_002",
            timestamp=now,
            investigation_id="inv_002",
            action_type=ActionType.INTEGRATION_EXECUTION,
            status=ActionStatus.SUCCESS,
            level=LogLevel.INFO,
            component="palo_alto",
            description="Blocked IP",
            details={"action": "BLOCK_IP", "target": "10.0.0.1"},
            duration_ms=250,
        )
        d = log.to_dict()
        assert d["id"] == "log_002"
        assert d["action_type"] == "integration_execution"
        assert d["status"] == "success"
        assert d["duration_ms"] == 250

    def test_action_log_from_dict(self):
        data = {
            "id": "log_003",
            "timestamp": datetime.now().isoformat(),
            "investigation_id": "inv_003",
            "action_type": "risk_assessment",
            "status": "success",
            "level": "info",
            "component": "risk_analyzer",
            "description": "Assessed risk",
            "details": json.dumps({"risk_score": 0.85}),
            "duration_ms": 120,
            "error_message": None,
            "correlation_id": None,
        }
        log = ActionLog.from_dict(data)
        assert log.id == "log_003"
        assert log.action_type == ActionType.RISK_ASSESSMENT
        assert log.status == ActionStatus.SUCCESS
        assert log.details["risk_score"] == 0.85


class TestActionLogger:
    @pytest.fixture
    def temp_logger_dir(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            yield temp_dir

    @pytest.fixture
    def action_logger(self, temp_logger_dir):
        return ActionLogger(db_path=os.path.join(temp_logger_dir, "test_action_logs.db"))

    def test_logger_initialization(self, action_logger):
        assert os.path.exists(action_logger.db_path)
        conn = sqlite3.connect(action_logger.db_path)
        cursor = conn.cursor()
        cursor.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='action_logs'")
        result = cursor.fetchone()
        conn.close()
        assert result is not None

    def test_log_action(self, action_logger):
        log_id = action_logger.log_action(
            action_type=ActionType.THREAT_INTEL_QUERY,
            component="virustotal",
            description="Queried VT for 192.168.1.100",
            investigation_id="inv_001",
            status=ActionStatus.SUCCESS,
            level=LogLevel.INFO,
            details={"ip": "192.168.1.100"},
            duration_ms=150,
        )
        assert log_id is not None

        conn = sqlite3.connect(action_logger.db_path)
        cursor = conn.cursor()
        cursor.execute("SELECT * FROM action_logs WHERE id = ?", (log_id,))
        result = cursor.fetchone()
        conn.close()
        assert result is not None

    def test_log_investigation_started(self, action_logger):
        action_logger.log_investigation_started("inv_start_001", {
            "event_type": "suspicious_ip",
            "source_ip": "192.168.1.100",
        })
        logs = action_logger.get_investigation_logs("inv_start_001")
        assert len(logs) == 1
        assert logs[0].action_type == ActionType.INVESTIGATION_STARTED

    def test_log_threat_intel_query(self, action_logger):
        action_logger.log_threat_intel_query(
            investigation_id="inv_ti_001",
            provider="virustotal",
            target="192.168.1.100",
            result={"score": 0.8, "malicious": True},
            duration_ms=150,
        )
        logs = action_logger.get_investigation_logs("inv_ti_001")
        assert len(logs) == 1
        assert logs[0].action_type == ActionType.THREAT_INTEL_QUERY

    def test_log_risk_assessment(self, action_logger):
        action_logger.log_risk_assessment(
            investigation_id="inv_ra_001",
            risk_score=0.85,
            risk_level="high",
            factors={"base_risk": 0.7, "confidence": 0.9},
        )
        logs = action_logger.get_investigation_logs("inv_ra_001")
        assert len(logs) == 1
        assert logs[0].action_type == ActionType.RISK_ASSESSMENT

    def test_log_error(self, action_logger):
        action_logger.log_error(
            component="threat_analyzer",
            error_message="Invalid input format",
            investigation_id="inv_err_001",
            details={"operation": "analysis"},
        )
        logs = action_logger.get_investigation_logs("inv_err_001")
        assert len(logs) == 1
        assert logs[0].action_type == ActionType.ERROR_OCCURRED
        assert logs[0].status == ActionStatus.FAILED
        assert logs[0].level == LogLevel.ERROR

    def test_get_investigation_logs(self, action_logger):
        inv_id = "inv_multi_001"
        action_logger.log_investigation_started(inv_id, {"event_type": "suspicious_ip"})
        action_logger.log_threat_intel_query(inv_id, "virustotal", "1.2.3.4", {"score": 0.5}, 100)
        action_logger.log_risk_assessment(inv_id, 0.6, "medium", {"base_risk": 0.5})

        logs = action_logger.get_investigation_logs(inv_id)
        assert len(logs) == 3
        assert logs[0].action_type == ActionType.INVESTIGATION_STARTED

    def test_get_component_performance(self, action_logger):
        for i in range(5):
            action_logger.log_threat_intel_query(
                f"inv_perf_{i}", "virustotal", f"1.2.3.{i}",
                {"score": 0.5}, duration_ms=100 + i * 50,
            )
        perf = action_logger.get_component_performance("ThreatIntel.virustotal", hours=1)
        assert perf["total_actions"] == 5
        assert perf["successful_actions"] == 5

    def test_get_system_health(self, action_logger):
        action_logger.log_investigation_started("inv_h1", {"event_type": "suspicious_ip"})
        action_logger.log_error("analyzer", "test error", investigation_id="inv_h1")
        action_logger.log_risk_assessment("inv_h1", 0.5, "medium", {})

        health = action_logger.get_system_health(hours=1)
        assert health["total_actions"] >= 3
        assert "health_status" in health

    def test_get_investigation_timeline(self, action_logger):
        inv_id = "inv_tl_001"
        action_logger.log_investigation_started(inv_id, {"event_type": "malware_detection"})
        action_logger.log_threat_intel_query(inv_id, "virustotal", "hash123", {"score": 0.9}, 200)

        timeline = action_logger.get_investigation_timeline(inv_id)
        assert len(timeline) == 2
        assert timeline[0]["action"] == "investigation_started"

    def test_export_audit_trail(self, action_logger):
        inv_id = "inv_audit_001"
        action_logger.log_investigation_started(inv_id, {"event_type": "suspicious_ip"})
        action_logger.log_risk_assessment(inv_id, 0.8, "high", {"base_risk": 0.7})

        trail = action_logger.export_audit_trail(inv_id)
        assert trail["investigation_id"] == inv_id
        assert trail["total_actions"] == 2

    def test_cleanup_old_logs(self, action_logger):
        inv_id = "inv_cleanup_001"
        log_id = action_logger.log_action(
            action_type=ActionType.THREAT_INTEL_QUERY,
            component="virustotal",
            description="old query",
            investigation_id=inv_id,
        )

        old_ts = (datetime.now() - timedelta(days=100)).isoformat()
        with sqlite3.connect(action_logger.db_path) as conn:
            conn.execute("UPDATE action_logs SET timestamp = ? WHERE id = ?", (old_ts, log_id))

        action_logger.log_action(
            action_type=ActionType.THREAT_INTEL_QUERY,
            component="abuseipdb",
            description="recent query",
            investigation_id=inv_id,
        )

        deleted = action_logger.cleanup_old_logs(days=90)
        assert deleted >= 1

        remaining = action_logger.get_investigation_logs(inv_id)
        ids = [entry.id for entry in remaining]
        assert log_id not in ids
