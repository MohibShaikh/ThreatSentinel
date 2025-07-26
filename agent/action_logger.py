"""
ThreatSentinel SOC Agent - Comprehensive Action Logging

Provides detailed logging of all agent actions, decisions, integrations,
and outcomes for audit trails, compliance, and continuous learning.
"""

import json
import sqlite3
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from enum import Enum
from pathlib import Path
from typing import Any, Dict, List, Optional, Union
import logging

logger = logging.getLogger(__name__)

class ActionType(Enum):
    INVESTIGATION_STARTED = "investigation_started"
    THREAT_INTEL_QUERY = "threat_intel_query"
    RISK_ASSESSMENT = "risk_assessment"
    ACTION_RECOMMENDATION = "action_recommendation"
    INTEGRATION_EXECUTION = "integration_execution"
    HUMAN_ESCALATION = "human_escalation"
    MEMORY_STORAGE = "memory_storage"
    PATTERN_DETECTION = "pattern_detection"
    INVESTIGATION_COMPLETED = "investigation_completed"
    ERROR_OCCURRED = "error_occurred"
    SYSTEM_EVENT = "system_event"

class ActionStatus(Enum):
    SUCCESS = "success"
    FAILED = "failed"
    IN_PROGRESS = "in_progress"
    CANCELLED = "cancelled"
    PARTIAL = "partial"

class LogLevel(Enum):
    DEBUG = "debug"
    INFO = "info"
    WARNING = "warning"
    ERROR = "error"
    CRITICAL = "critical"

@dataclass
class ActionLog:
    id: str
    timestamp: datetime
    investigation_id: Optional[str]
    action_type: ActionType
    status: ActionStatus
    level: LogLevel
    component: str  # Which component performed the action
    description: str
    details: Dict[str, Any] = field(default_factory=dict)
    duration_ms: Optional[int] = None
    error_message: Optional[str] = None
    correlation_id: Optional[str] = None  # Link related actions
    
    def to_dict(self) -> Dict[str, Any]:
        return {
            'id': self.id,
            'timestamp': self.timestamp.isoformat(),
            'investigation_id': self.investigation_id,
            'action_type': self.action_type.value,
            'status': self.status.value,
            'level': self.level.value,
            'component': self.component,
            'description': self.description,
            'details': json.dumps(self.details),
            'duration_ms': self.duration_ms,
            'error_message': self.error_message,
            'correlation_id': self.correlation_id
        }
    
    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> 'ActionLog':
        return cls(
            id=data['id'],
            timestamp=datetime.fromisoformat(data['timestamp']),
            investigation_id=data['investigation_id'],
            action_type=ActionType(data['action_type']),
            status=ActionStatus(data['status']),
            level=LogLevel(data['level']),
            component=data['component'],
            description=data['description'],
            details=json.loads(data['details']) if data['details'] else {},
            duration_ms=data['duration_ms'],
            error_message=data['error_message'],
            correlation_id=data['correlation_id']
        )

class ActionLogger:
    """
    Comprehensive action logging system for ThreatSentinel SOC Agent.
    
    Features:
    - Detailed action tracking with metadata
    - Performance metrics (duration, success rates)
    - Error tracking and analysis
    - Investigation correlation
    - Component-level logging
    - Audit trail for compliance
    - Learning insights from patterns
    """
    
    def __init__(self, db_path: str = "data/action_logs.db"):
        self.db_path = Path(db_path)
        self.db_path.parent.mkdir(exist_ok=True)
        self._init_database()
        
    def _init_database(self):
        """Initialize SQLite database for action logs."""
        with sqlite3.connect(self.db_path) as conn:
            conn.execute("""
                CREATE TABLE IF NOT EXISTS action_logs (
                    id TEXT PRIMARY KEY,
                    timestamp TEXT NOT NULL,
                    investigation_id TEXT,
                    action_type TEXT NOT NULL,
                    status TEXT NOT NULL,
                    level TEXT NOT NULL,
                    component TEXT NOT NULL,
                    description TEXT NOT NULL,
                    details TEXT,
                    duration_ms INTEGER,
                    error_message TEXT,
                    correlation_id TEXT
                )
            """)
            
            # Indexes for efficient querying
            conn.execute("""
                CREATE INDEX IF NOT EXISTS idx_timestamp 
                ON action_logs(timestamp DESC)
            """)
            
            conn.execute("""
                CREATE INDEX IF NOT EXISTS idx_investigation_id 
                ON action_logs(investigation_id, timestamp DESC)
            """)
            
            conn.execute("""
                CREATE INDEX IF NOT EXISTS idx_action_type_status 
                ON action_logs(action_type, status, timestamp DESC)
            """)
            
            conn.execute("""
                CREATE INDEX IF NOT EXISTS idx_component_level 
                ON action_logs(component, level, timestamp DESC)
            """)
    
    def log_action(self,
                   action_type: ActionType,
                   component: str,
                   description: str,
                   investigation_id: Optional[str] = None,
                   status: ActionStatus = ActionStatus.SUCCESS,
                   level: LogLevel = LogLevel.INFO,
                   details: Optional[Dict[str, Any]] = None,
                   duration_ms: Optional[int] = None,
                   error_message: Optional[str] = None,
                   correlation_id: Optional[str] = None) -> str:
        """Log a single action with all metadata."""
        
        action_log = ActionLog(
            id=str(uuid.uuid4()),
            timestamp=datetime.now(),
            investigation_id=investigation_id,
            action_type=action_type,
            status=status,
            level=level,
            component=component,
            description=description,
            details=details or {},
            duration_ms=duration_ms,
            error_message=error_message,
            correlation_id=correlation_id
        )
        
        # Store in database
        with sqlite3.connect(self.db_path) as conn:
            conn.execute("""
                INSERT INTO action_logs VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """, (
                action_log.id, action_log.timestamp.isoformat(),
                action_log.investigation_id, action_log.action_type.value,
                action_log.status.value, action_log.level.value,
                action_log.component, action_log.description,
                json.dumps(action_log.details),
                action_log.duration_ms, action_log.error_message,
                action_log.correlation_id
            ))
        
        # Also log to Python logger for real-time monitoring
        log_msg = f"[{component}] {description}"
        if investigation_id:
            log_msg = f"[{investigation_id}] {log_msg}"
        
        if level == LogLevel.DEBUG:
            logger.debug(log_msg)
        elif level == LogLevel.INFO:
            logger.info(log_msg)
        elif level == LogLevel.WARNING:
            logger.warning(log_msg)
        elif level == LogLevel.ERROR:
            logger.error(log_msg)
        elif level == LogLevel.CRITICAL:
            logger.critical(log_msg)
        
        return action_log.id
    
    def log_investigation_started(self, investigation_id: str, event_data: Dict[str, Any]):
        """Log the start of a new investigation."""
        return self.log_action(
            action_type=ActionType.INVESTIGATION_STARTED,
            component="SOCAgentPlanner",
            description=f"Investigation started for {event_data.get('event_type', 'unknown')} event",
            investigation_id=investigation_id,
            details={
                'event_type': event_data.get('event_type'),
                'source_ip': event_data.get('source_ip'),
                'emergency_mode': event_data.get('emergency_mode', False),
                'payload_keys': list(event_data.get('payload', {}).keys()) if 'payload' in event_data else []
            }
        )
    
    def log_threat_intel_query(self, investigation_id: str, provider: str, 
                              target: str, result: Dict[str, Any], duration_ms: int):
        """Log a threat intelligence API query."""
        return self.log_action(
            action_type=ActionType.THREAT_INTEL_QUERY,
            component=f"ThreatIntel.{provider}",
            description=f"Queried {provider} for {target}",
            investigation_id=investigation_id,
            duration_ms=duration_ms,
            details={
                'provider': provider,
                'target': target,
                'score': result.get('score'),
                'malicious': result.get('malicious'),
                'categories': result.get('categories', []),
                'confidence': result.get('confidence')
            }
        )
    
    def log_risk_assessment(self, investigation_id: str, risk_score: float, 
                           risk_level: str, factors: Dict[str, Any]):
        """Log risk assessment results."""
        return self.log_action(
            action_type=ActionType.RISK_ASSESSMENT,
            component="RiskAnalyzer",
            description=f"Risk assessed as {risk_level} (score: {risk_score:.2f})",
            investigation_id=investigation_id,
            details={
                'risk_score': risk_score,
                'risk_level': risk_level,
                'base_risk': factors.get('base_risk'),
                'threat_intel_weight': factors.get('threat_intel_weight'),
                'context_weight': factors.get('context_weight'),
                'confidence': factors.get('confidence')
            }
        )
    
    def log_action_recommendation(self, investigation_id: str, actions: List[Dict[str, Any]]):
        """Log recommended actions."""
        return self.log_action(
            action_type=ActionType.ACTION_RECOMMENDATION,
            component="ActionPlanner",
            description=f"Generated {len(actions)} recommended actions",
            investigation_id=investigation_id,
            details={
                'action_count': len(actions),
                'action_types': [action.get('action_type') for action in actions],
                'priorities': [action.get('priority') for action in actions],
                'targets': [action.get('target') for action in actions]
            }
        )
    
    def log_integration_execution(self, investigation_id: str, integration_name: str,
                                 action_type: str, target: str, success: bool,
                                 duration_ms: int, error_message: Optional[str] = None):
        """Log integration action execution."""
        return self.log_action(
            action_type=ActionType.INTEGRATION_EXECUTION,
            component=f"Integration.{integration_name}",
            description=f"Executed {action_type} on {integration_name} for {target}",
            investigation_id=investigation_id,
            status=ActionStatus.SUCCESS if success else ActionStatus.FAILED,
            level=LogLevel.INFO if success else LogLevel.ERROR,
            duration_ms=duration_ms,
            error_message=error_message,
            details={
                'integration_name': integration_name,
                'action_type': action_type,
                'target': target,
                'success': success
            }
        )
    
    def log_human_escalation(self, investigation_id: str, reason: str, 
                           priority: str, escalation_details: Dict[str, Any]):
        """Log human escalation events."""
        return self.log_action(
            action_type=ActionType.HUMAN_ESCALATION,
            component="HumanOversight",
            description=f"Escalated to human review: {reason}",
            investigation_id=investigation_id,
            level=LogLevel.WARNING,
            details={
                'reason': reason,
                'priority': priority,
                'escalation_trigger': escalation_details.get('trigger'),
                'risk_score': escalation_details.get('risk_score'),
                'confidence_score': escalation_details.get('confidence_score')
            }
        )
    
    def log_pattern_detection(self, investigation_id: str, pattern_type: str, 
                            details: Dict[str, Any]):
        """Log detected patterns in behavior or threats."""
        return self.log_action(
            action_type=ActionType.PATTERN_DETECTION,
            component="PatternAnalyzer",
            description=f"Detected {pattern_type} pattern",
            investigation_id=investigation_id,
            details={
                'pattern_type': pattern_type,
                'frequency': details.get('frequency'),
                'time_window': details.get('time_window'),
                'similarity_score': details.get('similarity_score'),
                'related_investigations': details.get('related_investigations', [])
            }
        )
    
    def log_error(self, component: str, error_message: str, 
                  investigation_id: Optional[str] = None, 
                  details: Optional[Dict[str, Any]] = None):
        """Log error events."""
        return self.log_action(
            action_type=ActionType.ERROR_OCCURRED,
            component=component,
            description=f"Error in {component}",
            investigation_id=investigation_id,
            status=ActionStatus.FAILED,
            level=LogLevel.ERROR,
            error_message=error_message,
            details=details or {}
        )
    
    def get_investigation_logs(self, investigation_id: str) -> List[ActionLog]:
        """Get all logs for a specific investigation."""
        with sqlite3.connect(self.db_path) as conn:
            cursor = conn.execute("""
                SELECT * FROM action_logs 
                WHERE investigation_id = ?
                ORDER BY timestamp ASC
            """, (investigation_id,))
            
            logs = []
            for row in cursor.fetchall():
                columns = [desc[0] for desc in cursor.description]
                log_data = dict(zip(columns, row))
                logs.append(ActionLog.from_dict(log_data))
            
            return logs
    
    def get_component_performance(self, component: str, 
                                 hours: int = 24) -> Dict[str, Any]:
        """Get performance metrics for a specific component."""
        since = datetime.now() - timedelta(hours=hours)
        
        with sqlite3.connect(self.db_path) as conn:
            # Total actions
            cursor = conn.execute("""
                SELECT COUNT(*) FROM action_logs 
                WHERE component = ? AND timestamp > ?
            """, (component, since.isoformat()))
            total_actions = cursor.fetchone()[0]
            
            # Success rate
            cursor = conn.execute("""
                SELECT COUNT(*) FROM action_logs 
                WHERE component = ? AND timestamp > ? AND status = 'success'
            """, (component, since.isoformat()))
            successful_actions = cursor.fetchone()[0]
            
            # Average duration
            cursor = conn.execute("""
                SELECT AVG(duration_ms) FROM action_logs 
                WHERE component = ? AND timestamp > ? AND duration_ms IS NOT NULL
            """, (component, since.isoformat()))
            avg_duration = cursor.fetchone()[0] or 0
            
            # Error count
            cursor = conn.execute("""
                SELECT COUNT(*) FROM action_logs 
                WHERE component = ? AND timestamp > ? AND level = 'error'
            """, (component, since.isoformat()))
            error_count = cursor.fetchone()[0]
            
            # Recent errors
            cursor = conn.execute("""
                SELECT error_message, COUNT(*) as count FROM action_logs 
                WHERE component = ? AND timestamp > ? AND error_message IS NOT NULL
                GROUP BY error_message
                ORDER BY count DESC
                LIMIT 5
            """, (component, since.isoformat()))
            recent_errors = dict(cursor.fetchall())
        
        success_rate = (successful_actions / total_actions * 100) if total_actions > 0 else 0
        
        return {
            'component': component,
            'time_window_hours': hours,
            'total_actions': total_actions,
            'successful_actions': successful_actions,
            'success_rate': round(success_rate, 2),
            'average_duration_ms': round(avg_duration, 2),
            'error_count': error_count,
            'recent_errors': recent_errors
        }
    
    def get_system_health(self, hours: int = 1) -> Dict[str, Any]:
        """Get overall system health metrics."""
        since = datetime.now() - timedelta(hours=hours)
        
        with sqlite3.connect(self.db_path) as conn:
            # Overall stats
            cursor = conn.execute("""
                SELECT 
                    COUNT(*) as total_actions,
                    SUM(CASE WHEN status = 'success' THEN 1 ELSE 0 END) as successful,
                    SUM(CASE WHEN level = 'error' THEN 1 ELSE 0 END) as errors,
                    AVG(duration_ms) as avg_duration
                FROM action_logs 
                WHERE timestamp > ?
            """, (since.isoformat(),))
            
            row = cursor.fetchone()
            total_actions, successful, errors, avg_duration = row
            
            # Component breakdown
            cursor = conn.execute("""
                SELECT component, COUNT(*) as count 
                FROM action_logs 
                WHERE timestamp > ?
                GROUP BY component
                ORDER BY count DESC
            """, (since.isoformat(),))
            component_activity = dict(cursor.fetchall())
            
            # Recent investigation count
            cursor = conn.execute("""
                SELECT COUNT(DISTINCT investigation_id) 
                FROM action_logs 
                WHERE timestamp > ? AND investigation_id IS NOT NULL
            """, (since.isoformat(),))
            investigation_count = cursor.fetchone()[0]
            
            # Error trends
            cursor = conn.execute("""
                SELECT error_message, COUNT(*) as count 
                FROM action_logs 
                WHERE timestamp > ? AND error_message IS NOT NULL
                GROUP BY error_message
                ORDER BY count DESC
                LIMIT 3
            """, (since.isoformat(),))
            top_errors = dict(cursor.fetchall())
        
        success_rate = (successful / total_actions * 100) if total_actions > 0 else 0
        error_rate = (errors / total_actions * 100) if total_actions > 0 else 0
        
        return {
            'time_window_hours': hours,
            'total_actions': total_actions,
            'success_rate': round(success_rate, 2),
            'error_rate': round(error_rate, 2),
            'average_duration_ms': round(avg_duration or 0, 2),
            'investigations_processed': investigation_count,
            'component_activity': component_activity,
            'top_errors': top_errors,
            'health_status': 'healthy' if error_rate < 5 else 'degraded' if error_rate < 20 else 'unhealthy'
        }
    
    def get_investigation_timeline(self, investigation_id: str) -> List[Dict[str, Any]]:
        """Get a timeline view of an investigation."""
        logs = self.get_investigation_logs(investigation_id)
        
        timeline = []
        for log in logs:
            timeline.append({
                'timestamp': log.timestamp.isoformat(),
                'component': log.component,
                'action': log.action_type.value,
                'description': log.description,
                'status': log.status.value,
                'duration_ms': log.duration_ms,
                'details': log.details
            })
        
        return timeline
    
    def cleanup_old_logs(self, days: int = 90) -> int:
        """Clean up old action logs."""
        cutoff_date = datetime.now() - timedelta(days=days)
        
        with sqlite3.connect(self.db_path) as conn:
            cursor = conn.execute("""
                DELETE FROM action_logs 
                WHERE timestamp < ?
            """, (cutoff_date.isoformat(),))
            
            deleted_count = cursor.rowcount
        
        logger.info(f"Cleaned up {deleted_count} old action logs")
        return deleted_count
    
    def export_audit_trail(self, investigation_id: str) -> Dict[str, Any]:
        """Export complete audit trail for an investigation."""
        logs = self.get_investigation_logs(investigation_id)
        timeline = self.get_investigation_timeline(investigation_id)
        
        if not logs:
            return {}
        
        start_time = logs[0].timestamp
        end_time = logs[-1].timestamp
        duration = (end_time - start_time).total_seconds()
        
        # Count actions by type
        action_counts = {}
        error_count = 0
        for log in logs:
            action_counts[log.action_type.value] = action_counts.get(log.action_type.value, 0) + 1
            if log.level == LogLevel.ERROR:
                error_count += 1
        
        return {
            'investigation_id': investigation_id,
            'start_time': start_time.isoformat(),
            'end_time': end_time.isoformat(),
            'total_duration_seconds': round(duration, 2),
            'total_actions': len(logs),
            'error_count': error_count,
            'action_breakdown': action_counts,
            'timeline': timeline,
            'export_timestamp': datetime.now().isoformat()
        } 