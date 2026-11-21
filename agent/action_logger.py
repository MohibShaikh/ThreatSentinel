"""
ThreatSentinel SOC Agent action logging

Provides detailed logging of all agent actions, decisions, integrations,
and outcomes for audit trails, compliance, and continuous learning.
"""

import hashlib
import json
import logging
import sqlite3
import threading
import uuid
from contextlib import contextmanager
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from enum import Enum
from pathlib import Path
from typing import Any, Dict, Iterator, List, Optional

logger = logging.getLogger(__name__)

GENESIS_HASH = "0" * 64


def _utcnow() -> datetime:
    return datetime.now(timezone.utc)


def _parse_ts(value: str) -> datetime:
    ts = datetime.fromisoformat(value)
    return ts if ts.tzinfo else ts.replace(tzinfo=timezone.utc)


def compute_entry_hash(prev_hash: str, entry_id: str, timestamp: str, investigation_id: Optional[str],
                       action_type: str, status: str, level: str, component: str, description: str,
                       details_json: Optional[str], error_message: Optional[str]) -> str:
    """SHA-256 over the previous link and every audited field of an entry."""
    material = "|".join([
        prev_hash or GENESIS_HASH, entry_id, timestamp, investigation_id or "", action_type, status,
        level, component, description, details_json or "", error_message or "",
    ])
    return hashlib.sha256(material.encode("utf-8")).hexdigest()

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
            timestamp=_parse_ts(data['timestamp']),
            investigation_id=data['investigation_id'],
            action_type=ActionType(data['action_type']),
            status=ActionStatus(data['status']),
            level=LogLevel(data['level']),
            component=data['component'],
            description=data['description'],
            details=json.loads(data['details']) if data.get('details') else {},
            duration_ms=data.get('duration_ms'),
            error_message=data.get('error_message'),
            correlation_id=data.get('correlation_id')
        )

class ActionLogger:
    """
    Action logging system for ThreatSentinel SOC Agent.

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
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        self._write_lock = threading.Lock()
        self._init_database()

    @contextmanager
    def _db(self) -> Iterator[sqlite3.Connection]:
        conn = sqlite3.connect(self.db_path, timeout=30)
        try:
            with conn:
                yield conn
        finally:
            conn.close()

    def _init_database(self):
        """Create the table, enable WAL and migrate older schemas in place."""
        with self._db() as conn:
            conn.execute("PRAGMA journal_mode=WAL")
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
                    correlation_id TEXT,
                    prev_hash TEXT,
                    entry_hash TEXT
                )
            """)
            columns = {row[1] for row in conn.execute("PRAGMA table_info(action_logs)")}
            for column in ("prev_hash", "entry_hash"):
                if column not in columns:
                    conn.execute(f"ALTER TABLE action_logs ADD COLUMN {column} TEXT")  # noqa: S608 - fixed names
            conn.execute("CREATE INDEX IF NOT EXISTS idx_timestamp ON action_logs(timestamp DESC)")
            conn.execute("CREATE INDEX IF NOT EXISTS idx_investigation_id "
                         "ON action_logs(investigation_id, timestamp DESC)")
            conn.execute("CREATE INDEX IF NOT EXISTS idx_action_type_status "
                         "ON action_logs(action_type, status, timestamp DESC)")
            conn.execute("CREATE INDEX IF NOT EXISTS idx_component_level "
                         "ON action_logs(component, level, timestamp DESC)")

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
            timestamp=_utcnow(),
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

        timestamp = action_log.timestamp.isoformat()
        details_json = json.dumps(action_log.details, default=str, sort_keys=True)
        with self._write_lock, self._db() as conn:
            # BEGIN IMMEDIATE serializes writers across processes so the chain stays linear
            conn.execute("BEGIN IMMEDIATE")
            row = conn.execute(
                "SELECT entry_hash FROM action_logs WHERE entry_hash IS NOT NULL ORDER BY rowid DESC LIMIT 1"
            ).fetchone()
            prev_hash = row[0] if row else GENESIS_HASH
            entry_hash = compute_entry_hash(
                prev_hash, action_log.id, timestamp, action_log.investigation_id,
                action_log.action_type.value, action_log.status.value, action_log.level.value,
                action_log.component, action_log.description, details_json, action_log.error_message,
            )
            conn.execute("""
                INSERT INTO action_logs
                (id, timestamp, investigation_id, action_type, status, level, component, description,
                 details, duration_ms, error_message, correlation_id, prev_hash, entry_hash)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """, (
                action_log.id, timestamp, action_log.investigation_id, action_log.action_type.value,
                action_log.status.value, action_log.level.value, action_log.component,
                action_log.description, details_json, action_log.duration_ms,
                action_log.error_message, action_log.correlation_id, prev_hash, entry_hash,
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
        with self._db() as conn:
            cursor = conn.execute("""
                SELECT * FROM action_logs
                WHERE investigation_id = ?
                ORDER BY timestamp ASC, rowid ASC
            """, (investigation_id,))

            logs = []
            for row in cursor.fetchall():
                columns = [desc[0] for desc in cursor.description]
                log_data = dict(zip(columns, row, strict=True))
                logs.append(ActionLog.from_dict(log_data))

            return logs

    def get_component_performance(self, component: str,
                                 hours: int = 24) -> Dict[str, Any]:
        """Get performance metrics for a specific component."""
        since = _utcnow() - timedelta(hours=hours)

        with self._db() as conn:
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
        since = _utcnow() - timedelta(hours=hours)

        with self._db() as conn:
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
        """Delete old logs and record the pruning anchor so the chain stays verifiable."""
        cutoff_date = (_utcnow() - timedelta(days=days)).isoformat()
        with self._write_lock, self._db() as conn:
            conn.execute("BEGIN IMMEDIATE")
            row = conn.execute(
                "SELECT entry_hash FROM action_logs WHERE timestamp < ? ORDER BY rowid DESC LIMIT 1",
                (cutoff_date,),
            ).fetchone()
            deleted_count = conn.execute(
                "DELETE FROM action_logs WHERE timestamp < ?", (cutoff_date,)
            ).rowcount
        if deleted_count:
            self.log_action(
                action_type=ActionType.SYSTEM_EVENT,
                component="AuditLog",
                description=f"Pruned {deleted_count} action logs older than {days} days",
                level=LogLevel.WARNING,
                details={"pruned_count": deleted_count, "anchor_hash": row[0] if row else None,
                         "cutoff": cutoff_date},
            )
        logger.info(f"Cleaned up {deleted_count} old action logs")
        return deleted_count

    def verify_integrity(self) -> Dict[str, Any]:
        """Walk the hash chain and report any entry that was altered, removed or reordered."""
        broken: List[Dict[str, Any]] = []
        legacy = 0
        total = 0
        expected_prev: Optional[str] = None
        anchors = {GENESIS_HASH}
        with self._db() as conn:
            conn.row_factory = sqlite3.Row
            rows = conn.execute("SELECT rowid, * FROM action_logs ORDER BY rowid ASC").fetchall()
        for row in rows:
            if row["component"] == "AuditLog" and row["details"]:
                try:
                    anchor = json.loads(row["details"]).get("anchor_hash")
                except (ValueError, AttributeError):
                    anchor = None
                if anchor:
                    anchors.add(anchor)

        for row in rows:
            total += 1
            if not row["entry_hash"]:
                legacy += 1
                continue
            recomputed = compute_entry_hash(
                row["prev_hash"], row["id"], row["timestamp"], row["investigation_id"], row["action_type"],
                row["status"], row["level"], row["component"], row["description"], row["details"],
                row["error_message"],
            )
            if recomputed != row["entry_hash"]:
                broken.append({"id": row["id"], "rowid": row["rowid"], "reason": "entry_hash mismatch (content altered)"})
            if expected_prev is None:
                if row["prev_hash"] not in anchors:
                    broken.append({"id": row["id"], "rowid": row["rowid"],
                                   "reason": "chain start does not match genesis or a recorded prune anchor"})
            elif row["prev_hash"] != expected_prev:
                broken.append({"id": row["id"], "rowid": row["rowid"],
                               "reason": "prev_hash does not match previous entry (deleted or reordered)"})
            expected_prev = row["entry_hash"]

        return {
            "valid": not broken,
            "total_entries": total,
            "chained_entries": total - legacy,
            "legacy_unchained_entries": legacy,
            "broken_links": broken[:100],
            "head_hash": expected_prev,
            "verified_at": _utcnow().isoformat(),
        }

    def search_logs(self, investigation_id: Optional[str] = None, component: Optional[str] = None,
                    action_type: Optional[str] = None, level: Optional[str] = None,
                    since_hours: int = 24, limit: int = 100) -> List[ActionLog]:
        """Filtered log query with parameter binding only."""
        clauses = ["timestamp > ?"]
        params: List[Any] = [(_utcnow() - timedelta(hours=since_hours)).isoformat()]
        for column, value in (("investigation_id", investigation_id), ("component", component),
                              ("action_type", action_type), ("level", level)):
            if value:
                clauses.append(f"{column} = ?")
                params.append(value)
        params.append(max(1, min(int(limit), 1000)))
        query = (f"SELECT * FROM action_logs WHERE {' AND '.join(clauses)} "  # noqa: S608 - fixed column names
                 "ORDER BY timestamp DESC, rowid DESC LIMIT ?")
        with self._db() as conn:
            conn.row_factory = sqlite3.Row
            rows = conn.execute(query, params).fetchall()
        return [ActionLog.from_dict(dict(r)) for r in rows]

    def get_active_components(self, hours: int = 24) -> List[Dict[str, Any]]:
        since = (_utcnow() - timedelta(hours=hours)).isoformat()
        with self._db() as conn:
            rows = conn.execute("""
                SELECT component, COUNT(*), MAX(timestamp),
                       SUM(CASE WHEN level = 'error' THEN 1 ELSE 0 END)
                FROM action_logs WHERE timestamp > ?
                GROUP BY component ORDER BY COUNT(*) DESC
            """, (since,)).fetchall()
        return [{"component": r[0], "action_count": r[1], "last_activity": r[2], "error_count": r[3] or 0}
                for r in rows]

    def get_overview(self, hours: int = 24) -> Dict[str, Any]:
        since = (_utcnow() - timedelta(hours=hours)).isoformat()
        with self._db() as conn:
            total_investigations = conn.execute(
                "SELECT COUNT(DISTINCT investigation_id) FROM action_logs WHERE investigation_id IS NOT NULL"
            ).fetchone()[0]
            total_actions = conn.execute("SELECT COUNT(*) FROM action_logs").fetchone()[0]
            recent_actions = conn.execute(
                "SELECT COUNT(*) FROM action_logs WHERE timestamp > ?", (since,)).fetchone()[0]
            recent_errors = conn.execute(
                "SELECT COUNT(*) FROM action_logs WHERE timestamp > ? AND level = 'error'", (since,)
            ).fetchone()[0]
            top_components = dict(conn.execute("""
                SELECT component, COUNT(*) AS count FROM action_logs WHERE timestamp > ?
                GROUP BY component ORDER BY count DESC LIMIT 5
            """, (since,)).fetchall())
        error_rate = (recent_errors / recent_actions * 100) if recent_actions else 0.0
        return {
            "total_investigations_tracked": total_investigations,
            "total_actions_logged": total_actions,
            f"recent_actions_{hours}h": recent_actions,
            f"recent_errors_{hours}h": recent_errors,
            f"error_rate_{hours}h": round(error_rate, 2),
            f"top_components_{hours}h": top_components,
            "audit_health": "healthy" if error_rate < 5 else "degraded" if error_rate < 20 else "unhealthy",
        }

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
            'export_timestamp': _utcnow().isoformat()
        }
