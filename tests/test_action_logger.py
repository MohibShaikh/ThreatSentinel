"""
Unit tests for agent/action_logger.py

Tests the comprehensive action logging system for detailed audit trails,
compliance monitoring, and performance analytics.
"""

import pytest
import asyncio
import tempfile
import os
import sqlite3
import json
from datetime import datetime, timedelta
from unittest.mock import patch, MagicMock

from agent.action_logger import (
    ActionLogger, ActionLog, ActionType, ActionStatus, LogLevel
)


class TestActionType:
    """Test ActionType enum"""
    
    def test_action_type_values(self):
        """Test ActionType enum values"""
        assert ActionType.INVESTIGATION_START.value == "investigation_start"
        assert ActionType.THREAT_INTEL_QUERY.value == "threat_intel_query"
        assert ActionType.RISK_ASSESSMENT.value == "risk_assessment"
        assert ActionType.INTEGRATION_EXECUTION.value == "integration_execution"
        assert ActionType.HUMAN_ESCALATION.value == "human_escalation"
        assert ActionType.PATTERN_DETECTION.value == "pattern_detection"
        assert ActionType.ERROR.value == "error"


class TestActionStatus:
    """Test ActionStatus enum"""
    
    def test_action_status_values(self):
        """Test ActionStatus enum values"""
        assert ActionStatus.STARTED.value == "started"
        assert ActionStatus.COMPLETED.value == "completed"
        assert ActionStatus.FAILED.value == "failed"
        assert ActionStatus.CANCELLED.value == "cancelled"


class TestLogLevel:
    """Test LogLevel enum"""
    
    def test_log_level_values(self):
        """Test LogLevel enum values"""
        assert LogLevel.DEBUG.value == "debug"
        assert LogLevel.INFO.value == "info"
        assert LogLevel.WARNING.value == "warning"
        assert LogLevel.ERROR.value == "error"
        assert LogLevel.CRITICAL.value == "critical"


class TestActionLog:
    """Test ActionLog dataclass"""
    
    def test_action_log_creation(self):
        """Test basic ActionLog creation"""
        log = ActionLog(
            log_id="log_001",
            investigation_id="inv_001",
            action_type=ActionType.THREAT_INTEL_QUERY,
            component="virustotal",
            action_data={"ip": "192.168.1.1"},
            status=ActionStatus.COMPLETED,
            level=LogLevel.INFO
        )
        
        assert log.log_id == "log_001"
        assert log.investigation_id == "inv_001"
        assert log.action_type == ActionType.THREAT_INTEL_QUERY
        assert log.component == "virustotal"
        assert log.status == ActionStatus.COMPLETED
        assert log.level == LogLevel.INFO
        assert isinstance(log.timestamp, datetime)
    
    def test_action_log_to_dict(self):
        """Test ActionLog serialization to dictionary"""
        log = ActionLog(
            log_id="log_002",
            investigation_id="inv_002",
            action_type=ActionType.INTEGRATION_EXECUTION,
            component="palo_alto",
            action_data={"action": "BLOCK_IP", "target": "10.0.0.1"},
            status=ActionStatus.COMPLETED,
            level=LogLevel.INFO,
            result={"success": True, "rule_id": "rule_123"},
            execution_time_ms=250
        )
        
        log_dict = log.to_dict()
        
        assert log_dict["log_id"] == "log_002"
        assert log_dict["action_type"] == ActionType.INTEGRATION_EXECUTION.value
        assert log_dict["status"] == ActionStatus.COMPLETED.value
        assert log_dict["level"] == LogLevel.INFO.value
        assert log_dict["execution_time_ms"] == 250
    
    def test_action_log_from_dict(self):
        """Test ActionLog deserialization from dictionary"""
        log_data = {
            "log_id": "log_003",
            "investigation_id": "inv_003",
            "action_type": ActionType.RISK_ASSESSMENT.value,
            "component": "risk_analyzer",
            "action_data": {"event_type": "suspicious_ip"},
            "status": ActionStatus.COMPLETED.value,
            "level": LogLevel.INFO.value,
            "result": {"risk_score": 0.85},
            "execution_time_ms": 120,
            "error_message": None,
            "timestamp": datetime.now().isoformat()
        }
        
        log = ActionLog.from_dict(log_data)
        
        assert log.log_id == "log_003"
        assert log.action_type == ActionType.RISK_ASSESSMENT
        assert log.status == ActionStatus.COMPLETED
        assert log.level == LogLevel.INFO
        assert log.result["risk_score"] == 0.85


class TestActionLogger:
    """Test ActionLogger functionality"""
    
    @pytest.fixture
    def temp_logger_dir(self):
        """Create temporary directory for test database"""
        with tempfile.TemporaryDirectory() as temp_dir:
            yield temp_dir
    
    @pytest.fixture
    def action_logger(self, temp_logger_dir):
        """Create ActionLogger instance with temporary storage"""
        return ActionLogger(db_path=os.path.join(temp_logger_dir, "test_action_logs.db"))
    
    @pytest.fixture
    def sample_log(self):
        """Create sample action log for testing"""
        return ActionLog(
            log_id="sample_log_001",
            investigation_id="inv_sample_001",
            action_type=ActionType.THREAT_INTEL_QUERY,
            component="virustotal",
            action_data={
                "query_type": "ip_reputation",
                "target": "192.168.1.100"
            },
            status=ActionStatus.COMPLETED,
            level=LogLevel.INFO,
            result={
                "reputation_score": 0.75,
                "indicators": ["malicious_urls", "malware_samples"]
            },
            execution_time_ms=234
        )
    
    def test_logger_initialization(self, action_logger):
        """Test action logger initialization"""
        assert os.path.exists(action_logger.db_path)
        
        # Verify database schema
        conn = sqlite3.connect(action_logger.db_path)
        cursor = conn.cursor()
        cursor.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='action_logs'")
        result = cursor.fetchone()
        conn.close()
        
        assert result is not None
    
    @pytest.mark.asyncio
    async def test_log_action(self, action_logger, sample_log):
        """Test logging an action"""
        await action_logger.log_action(sample_log)
        
        # Verify log was stored
        conn = sqlite3.connect(action_logger.db_path)
        cursor = conn.cursor()
        cursor.execute("SELECT * FROM action_logs WHERE log_id = ?", (sample_log.log_id,))
        result = cursor.fetchone()
        conn.close()
        
        assert result is not None
        assert result[1] == sample_log.log_id  # log_id column
        assert result[2] == sample_log.investigation_id  # investigation_id column
    
    @pytest.mark.asyncio
    async def test_log_investigation_start(self, action_logger):
        """Test logging investigation start"""
        investigation_id = "inv_start_001"
        event_data = {
            "event_id": "evt_001",
            "event_type": "suspicious_ip",
            "source_ip": "192.168.1.100"
        }
        
        await action_logger.log_investigation_start(investigation_id, event_data)
        
        # Verify log entry
        logs = await action_logger.get_investigation_logs(investigation_id)
        assert len(logs) == 1
        assert logs[0].action_type == ActionType.INVESTIGATION_START
        assert logs[0].status == ActionStatus.STARTED
    
    @pytest.mark.asyncio
    async def test_log_threat_intel_query(self, action_logger):
        """Test logging threat intelligence query"""
        investigation_id = "inv_threat_001"
        source = "virustotal"
        query_data = {"target": "192.168.1.100", "query_type": "ip_reputation"}
        result = {"reputation_score": 0.8, "confidence": 0.9}
        
        await action_logger.log_threat_intel_query(
            investigation_id, source, query_data, result, 150
        )
        
        # Verify log entry
        logs = await action_logger.get_investigation_logs(investigation_id)
        assert len(logs) == 1
        assert logs[0].action_type == ActionType.THREAT_INTEL_QUERY
        assert logs[0].component == source
        assert logs[0].execution_time_ms == 150
    
    @pytest.mark.asyncio
    async def test_log_integration_execution(self, action_logger):
        """Test logging integration execution"""
        investigation_id = "inv_integration_001"
        integration_name = "palo_alto"
        action_data = {"action": "BLOCK_IP", "target": "10.0.0.1"}
        result = {"success": True, "rule_id": "rule_456"}
        
        await action_logger.log_integration_execution(
            investigation_id, integration_name, action_data, result, 300
        )
        
        # Verify log entry
        logs = await action_logger.get_investigation_logs(investigation_id)
        assert len(logs) == 1
        assert logs[0].action_type == ActionType.INTEGRATION_EXECUTION
        assert logs[0].component == integration_name
        assert logs[0].result["rule_id"] == "rule_456"
    
    @pytest.mark.asyncio
    async def test_log_error(self, action_logger):
        """Test logging error"""
        investigation_id = "inv_error_001"
        component = "threat_analyzer"
        error_data = {"operation": "analysis", "input": "malformed_data"}
        error_message = "Invalid input format"
        
        await action_logger.log_error(
            investigation_id, component, error_data, error_message
        )
        
        # Verify log entry
        logs = await action_logger.get_investigation_logs(investigation_id)
        assert len(logs) == 1
        assert logs[0].action_type == ActionType.ERROR
        assert logs[0].status == ActionStatus.FAILED
        assert logs[0].level == LogLevel.ERROR
        assert logs[0].error_message == error_message
    
    @pytest.mark.asyncio
    async def test_get_investigation_logs(self, action_logger):
        """Test retrieving logs for specific investigation"""
        investigation_id = "inv_multi_001"
        
        # Add multiple logs for same investigation
        logs_to_add = [
            ActionLog("log1", investigation_id, ActionType.INVESTIGATION_START, 
                     "planner", {}, ActionStatus.STARTED, LogLevel.INFO),
            ActionLog("log2", investigation_id, ActionType.THREAT_INTEL_QUERY, 
                     "virustotal", {}, ActionStatus.COMPLETED, LogLevel.INFO),
            ActionLog("log3", investigation_id, ActionType.RISK_ASSESSMENT, 
                     "risk_analyzer", {}, ActionStatus.COMPLETED, LogLevel.INFO)
        ]
        
        for log in logs_to_add:
            await action_logger.log_action(log)
        
        # Retrieve logs
        retrieved_logs = await action_logger.get_investigation_logs(investigation_id)
        
        assert len(retrieved_logs) == 3
        # Should be ordered by timestamp
        assert retrieved_logs[0].action_type == ActionType.INVESTIGATION_START
    
    @pytest.mark.asyncio
    async def test_get_component_performance(self, action_logger):
        """Test getting component performance metrics"""
        component = "virustotal"
        investigation_id = "inv_perf_001"
        
        # Add multiple logs for same component with different execution times
        execution_times = [100, 150, 200, 250, 300]
        for i, exec_time in enumerate(execution_times):
            log = ActionLog(
                f"log_perf_{i}",
                investigation_id,
                ActionType.THREAT_INTEL_QUERY,
                component,
                {},
                ActionStatus.COMPLETED,
                LogLevel.INFO,
                execution_time_ms=exec_time
            )
            await action_logger.log_action(log)
        
        # Get performance metrics
        perf_data = await action_logger.get_component_performance(component)
        
        assert perf_data["component"] == component
        assert perf_data["total_actions"] == 5
        assert perf_data["avg_execution_time_ms"] == 200.0  # Average of execution times
        assert perf_data["min_execution_time_ms"] == 100
        assert perf_data["max_execution_time_ms"] == 300
    
    @pytest.mark.asyncio
    async def test_get_system_health(self, action_logger):
        """Test getting overall system health metrics"""
        investigation_id = "inv_health_001"
        
        # Add logs with different statuses
        logs_to_add = [
            ActionLog("health1", investigation_id, ActionType.THREAT_INTEL_QUERY, 
                     "virustotal", {}, ActionStatus.COMPLETED, LogLevel.INFO),
            ActionLog("health2", investigation_id, ActionType.THREAT_INTEL_QUERY, 
                     "abuseipdb", {}, ActionStatus.COMPLETED, LogLevel.INFO),
            ActionLog("health3", investigation_id, ActionType.INTEGRATION_EXECUTION, 
                     "palo_alto", {}, ActionStatus.FAILED, LogLevel.ERROR),
            ActionLog("health4", investigation_id, ActionType.RISK_ASSESSMENT, 
                     "analyzer", {}, ActionStatus.COMPLETED, LogLevel.INFO)
        ]
        
        for log in logs_to_add:
            await action_logger.log_action(log)
        
        # Get system health
        health_data = await action_logger.get_system_health()
        
        assert health_data["total_actions"] >= 4
        assert health_data["success_rate"] == 0.75  # 3 out of 4 successful
        assert "component_health" in health_data
    
    @pytest.mark.asyncio
    async def test_get_investigation_timeline(self, action_logger):
        """Test getting investigation timeline"""
        investigation_id = "inv_timeline_001"
        
        # Add logs with specific timestamps
        base_time = datetime.now()
        timeline_logs = [
            ActionLog("timeline1", investigation_id, ActionType.INVESTIGATION_START, 
                     "planner", {}, ActionStatus.STARTED, LogLevel.INFO, 
                     timestamp=base_time),
            ActionLog("timeline2", investigation_id, ActionType.THREAT_INTEL_QUERY, 
                     "virustotal", {}, ActionStatus.COMPLETED, LogLevel.INFO,
                     timestamp=base_time + timedelta(seconds=30)),
            ActionLog("timeline3", investigation_id, ActionType.RISK_ASSESSMENT, 
                     "analyzer", {}, ActionStatus.COMPLETED, LogLevel.INFO,
                     timestamp=base_time + timedelta(seconds=60))
        ]
        
        for log in timeline_logs:
            await action_logger.log_action(log)
        
        # Get timeline
        timeline = await action_logger.get_investigation_timeline(investigation_id)
        
        assert len(timeline["events"]) == 3
        assert timeline["total_duration_seconds"] >= 60
        assert timeline["events"][0]["action_type"] == ActionType.INVESTIGATION_START.value
    
    @pytest.mark.asyncio
    async def test_export_audit_trail(self, action_logger):
        """Test exporting complete audit trail"""
        investigation_id = "inv_audit_001"
        
        # Add comprehensive logs
        audit_logs = [
            ActionLog("audit1", investigation_id, ActionType.INVESTIGATION_START, 
                     "planner", {"event_id": "evt_001"}, ActionStatus.STARTED, LogLevel.INFO),
            ActionLog("audit2", investigation_id, ActionType.THREAT_INTEL_QUERY, 
                     "virustotal", {"target": "192.168.1.1"}, ActionStatus.COMPLETED, LogLevel.INFO,
                     result={"reputation_score": 0.8}),
            ActionLog("audit3", investigation_id, ActionType.HUMAN_ESCALATION, 
                     "reviewer", {"reason": "high_risk"}, ActionStatus.COMPLETED, LogLevel.WARNING)
        ]
        
        for log in audit_logs:
            await action_logger.log_action(log)
        
        # Export audit trail
        audit_trail = await action_logger.export_audit_trail(investigation_id)
        
        assert audit_trail["investigation_id"] == investigation_id
        assert len(audit_trail["action_logs"]) == 3
        assert "metadata" in audit_trail
        assert "summary" in audit_trail
    
    @pytest.mark.asyncio
    async def test_cleanup_old_logs(self, action_logger):
        """Test cleanup of old action logs"""
        investigation_id = "inv_cleanup_001"
        
        # Add old log
        old_log = ActionLog(
            "old_log", investigation_id, ActionType.THREAT_INTEL_QUERY,
            "virustotal", {}, ActionStatus.COMPLETED, LogLevel.INFO
        )
        await action_logger.log_action(old_log)
        
        # Manually update timestamp to be old
        old_timestamp = datetime.now() - timedelta(days=100)
        conn = sqlite3.connect(action_logger.db_path)
        cursor = conn.cursor()
        cursor.execute(
            "UPDATE action_logs SET timestamp = ? WHERE log_id = ?",
            (old_timestamp.isoformat(), old_log.log_id)
        )
        conn.commit()
        conn.close()
        
        # Add recent log
        recent_log = ActionLog(
            "recent_log", investigation_id, ActionType.THREAT_INTEL_QUERY,
            "abuseipdb", {}, ActionStatus.COMPLETED, LogLevel.INFO
        )
        await action_logger.log_action(recent_log)
        
        # Cleanup old logs (older than 90 days)
        deleted_count = await action_logger.cleanup_old_logs(days=90)
        
        assert deleted_count >= 1
        
        # Verify old log was deleted
        remaining_logs = await action_logger.get_investigation_logs(investigation_id)
        log_ids = [log.log_id for log in remaining_logs]
        assert "old_log" not in log_ids
        assert "recent_log" in log_ids
    
    @pytest.mark.asyncio
    async def test_concurrent_logging(self, action_logger):
        """Test concurrent logging operations"""
        investigation_id = "inv_concurrent_001"
        
        # Create multiple concurrent logging operations
        async def log_action_async(i):
            log = ActionLog(
                f"concurrent_log_{i}",
                investigation_id,
                ActionType.THREAT_INTEL_QUERY,
                f"tool_{i}",
                {"index": i},
                ActionStatus.COMPLETED,
                LogLevel.INFO
            )
            await action_logger.log_action(log)
        
        # Execute concurrent logs
        await asyncio.gather(*[log_action_async(i) for i in range(10)])
        
        # Verify all logs were stored
        logs = await action_logger.get_investigation_logs(investigation_id)
        assert len(logs) == 10


class TestActionLoggerIntegration:
    """Integration tests for action logger system"""
    
    @pytest.mark.asyncio
    async def test_real_investigation_logging_workflow(self, temp_logger_dir):
        """Test action logger with realistic investigation workflow"""
        logger = ActionLogger(db_path=os.path.join(temp_logger_dir, "workflow_test.db"))
        investigation_id = "inv_workflow_001"
        
        # Simulate complete investigation workflow
        
        # 1. Start investigation
        await logger.log_investigation_start(investigation_id, {
            "event_id": "evt_001",
            "event_type": "suspicious_ip",
            "source_ip": "192.168.1.100"
        })
        
        # 2. Threat intelligence queries
        await logger.log_threat_intel_query(
            investigation_id, "virustotal", 
            {"target": "192.168.1.100"}, 
            {"reputation_score": 0.75}, 150
        )
        
        await logger.log_threat_intel_query(
            investigation_id, "abuseipdb",
            {"target": "192.168.1.100"},
            {"abuse_confidence": 67}, 120
        )
        
        # 3. Risk assessment
        await logger.log_action(ActionLog(
            "risk_001", investigation_id, ActionType.RISK_ASSESSMENT,
            "risk_analyzer", {"event_data": "analyzed"},
            ActionStatus.COMPLETED, LogLevel.INFO,
            result={"risk_score": 0.8, "risk_level": "high"}
        ))
        
        # 4. Integration execution
        await logger.log_integration_execution(
            investigation_id, "palo_alto",
            {"action": "BLOCK_IP", "target": "192.168.1.100"},
            {"success": True, "rule_id": "rule_789"}, 250
        )
        
        # 5. Human escalation (high risk)
        await logger.log_action(ActionLog(
            "escalation_001", investigation_id, ActionType.HUMAN_ESCALATION,
            "human_reviewer", {"reason": "high_risk_score"},
            ActionStatus.COMPLETED, LogLevel.WARNING
        ))
        
        # Verify complete workflow was logged
        logs = await logger.get_investigation_logs(investigation_id)
        assert len(logs) == 5
        
        # Verify timeline
        timeline = await logger.get_investigation_timeline(investigation_id)
        assert len(timeline["events"]) == 5
        assert timeline["total_duration_seconds"] > 0
        
        # Verify audit trail
        audit_trail = await logger.export_audit_trail(investigation_id)
        assert len(audit_trail["action_logs"]) == 5
        assert audit_trail["summary"]["total_actions"] == 5
    
    @pytest.mark.asyncio
    async def test_logger_persistence_across_instances(self, temp_logger_dir):
        """Test that logs persist across different ActionLogger instances"""
        db_path = os.path.join(temp_logger_dir, "persistence_test.db")
        
        # Create first logger instance and add logs
        logger1 = ActionLogger(db_path=db_path)
        investigation_id = "inv_persist_001"
        
        await logger1.log_investigation_start(investigation_id, {"test": "data"})
        
        # Create second logger instance (simulating restart)
        logger2 = ActionLogger(db_path=db_path)
        
        # Verify logs persist
        logs = await logger2.get_investigation_logs(investigation_id)
        assert len(logs) >= 1
        assert logs[0].investigation_id == investigation_id


# CLI Mock Demonstrations
class TestActionLoggerCLIMockInteractions:
    """Mock CLI interactions for action logger testing"""
    
    @pytest.mark.mock
    def test_audit_logs_cli_mock(self):
        """Mock CLI interaction for audit logs"""
        print("\n=== Action Logger Audit CLI Mock Demo ===")
        print("Command: python -m agent.action_logger audit --investigation-id inv_2024_1234")
        print("Response:")
        print(json.dumps({
            "investigation_id": "inv_2024_1234",
            "audit_trail": {
                "total_actions": 12,
                "action_logs": [
                    {
                        "log_id": "log_2024_5678",
                        "timestamp": "2024-07-27T14:30:15Z",
                        "action_type": "investigation_start",
                        "component": "planner",
                        "status": "started",
                        "level": "info",
                        "action_data": {"event_id": "evt_001", "source_ip": "192.168.1.100"}
                    },
                    {
                        "log_id": "log_2024_5679",
                        "timestamp": "2024-07-27T14:30:45Z",
                        "action_type": "threat_intel_query",
                        "component": "virustotal",
                        "status": "completed",
                        "level": "info",
                        "execution_time_ms": 234,
                        "result": {"reputation_score": 0.85}
                    },
                    {
                        "log_id": "log_2024_5680",
                        "timestamp": "2024-07-27T14:31:30Z",
                        "action_type": "integration_execution",
                        "component": "palo_alto",
                        "status": "completed",
                        "level": "info",
                        "execution_time_ms": 567,
                        "result": {"success": True, "rule_id": "rule_4521"}
                    }
                ],
                "summary": {
                    "total_duration_seconds": 125.7,
                    "success_rate": 0.92,
                    "error_count": 1,
                    "escalation_count": 1
                }
            },
            "export_timestamp": datetime.now().isoformat()
        }, indent=2))
    
    @pytest.mark.mock
    def test_performance_metrics_cli_mock(self):
        """Mock CLI interaction for performance metrics"""
        print("\n=== Performance Metrics CLI Mock Demo ===")
        print("Command: python -m agent.action_logger performance --component virustotal --days 30")
        print("Response:")
        print(json.dumps({
            "component_performance": {
                "component": "virustotal",
                "analysis_period_days": 30,
                "metrics": {
                    "total_actions": 1456,
                    "successful_actions": 1398,
                    "failed_actions": 58,
                    "success_rate": 0.96,
                    "avg_execution_time_ms": 187.3,
                    "min_execution_time_ms": 89,
                    "max_execution_time_ms": 2340,
                    "p95_execution_time_ms": 456,
                    "p99_execution_time_ms": 789
                },
                "trend_analysis": {
                    "success_rate_trend": "stable",
                    "performance_trend": "improving",
                    "error_rate_change": -0.02
                },
                "recommendations": [
                    "Performance is within acceptable limits",
                    "Consider implementing caching for frequently queried IPs"
                ]
            },
            "analysis_timestamp": datetime.now().isoformat()
        }, indent=2))
    
    @pytest.mark.mock
    def test_system_health_cli_mock(self):
        """Mock CLI interaction for system health"""
        print("\n=== System Health CLI Mock Demo ===")
        print("Command: python -m agent.action_logger health --detailed")
        print("Response:")
        print(json.dumps({
            "system_health": {
                "overall_status": "healthy",
                "metrics": {
                    "total_actions_24h": 2847,
                    "success_rate_24h": 0.94,
                    "avg_response_time_ms": 234.7,
                    "error_rate_24h": 0.06,
                    "active_investigations": 23
                },
                "component_health": {
                    "virustotal": {"status": "healthy", "success_rate": 0.96, "avg_time_ms": 187},
                    "abuseipdb": {"status": "healthy", "success_rate": 0.98, "avg_time_ms": 145},
                    "shodan": {"status": "degraded", "success_rate": 0.87, "avg_time_ms": 567},
                    "palo_alto": {"status": "healthy", "success_rate": 0.99, "avg_time_ms": 234},
                    "splunk": {"status": "healthy", "success_rate": 1.0, "avg_time_ms": 98}
                },
                "alerts": [
                    {
                        "severity": "warning",
                        "component": "shodan",
                        "message": "Success rate below threshold (87% < 90%)",
                        "recommendation": "Check API key limits and network connectivity"
                    }
                ],
                "uptime_hours": 168.5
            },
            "health_check_timestamp": datetime.now().isoformat()
        }, indent=2)) 