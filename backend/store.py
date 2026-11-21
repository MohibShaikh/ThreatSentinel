"""
Persistent investigation store (SQLite, WAL).

Single source of truth for investigation state across the API: the
investigations routes, the task queue handler, monitoring, reports and
stats all read and write here, so there is no split-brain in-memory copy and
state survives restarts.
"""

import json
import sqlite3
import threading
from contextlib import contextmanager
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Dict, Iterator, List, Optional, Tuple

ACTIVE_STATUSES = ("pending", "queued", "running")
FINISHED_STATUSES = ("completed", "failed", "cancelled", "pending_human_review")

_COLUMNS = {
    "id": "TEXT PRIMARY KEY",
    "status": "TEXT NOT NULL",
    "created_at": "TEXT NOT NULL",
    "started_at": "TEXT",
    "completed_at": "TEXT",
    "request_json": "TEXT NOT NULL",
    "result_json": "TEXT",
    "risk_level": "TEXT",
    "risk_score": "REAL",
    "event_type": "TEXT",
    "source_ip": "TEXT",
    "title": "TEXT",
    "current_phase": "TEXT",
    "progress": "INTEGER DEFAULT 0",
    "batch_id": "TEXT",
    "error": "TEXT",
    "review_status": "TEXT",
    "feedback_json": "TEXT",
    "owasp_categories_json": "TEXT",
    "mitre_techniques_json": "TEXT",
    "prompt_injection_detected": "INTEGER DEFAULT 0",
    "emergency_mode": "INTEGER DEFAULT 0",
}
_JSON_FIELDS = {
    "request_json": "request", "result_json": "result", "feedback_json": "feedback",
    "owasp_categories_json": "owasp_categories", "mitre_techniques_json": "mitre_techniques",
}


def utcnow() -> datetime:
    return datetime.now(timezone.utc)


def _iso(value: Any) -> Optional[str]:
    if value is None:
        return None
    if isinstance(value, datetime):
        if value.tzinfo is None:
            value = value.replace(tzinfo=timezone.utc)
        return value.isoformat()
    return str(value)


def _parse(value: Optional[str]) -> Optional[datetime]:
    if not value:
        return None
    dt = datetime.fromisoformat(value)
    return dt if dt.tzinfo else dt.replace(tzinfo=timezone.utc)


def _strip_large(result: Dict[str, Any]) -> Dict[str, Any]:
    """Drop duplicated rendered report formats before persisting the result."""
    result = dict(result)
    report = result.get("report")
    if isinstance(report, dict) and isinstance(report.get("formats"), dict):
        report = dict(report)
        report["formats"] = {k: v for k, v in report["formats"].items() if k in ("markdown", "html", "stix")}
        result["report"] = report
    return result


class InvestigationStore:
    def __init__(self, db_path: str = "data/investigations.db"):
        self.db_path = Path(db_path)
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        self._lock = threading.Lock()
        self._init_db()

    @contextmanager
    def _db(self) -> Iterator[sqlite3.Connection]:
        conn = sqlite3.connect(self.db_path, timeout=30)
        conn.row_factory = sqlite3.Row
        try:
            with conn:
                yield conn
        finally:
            conn.close()

    def _init_db(self) -> None:
        with self._db() as conn:
            conn.execute("PRAGMA journal_mode=WAL")
            columns_sql = ", ".join(f"{name} {ddl}" for name, ddl in _COLUMNS.items())
            conn.execute(f"CREATE TABLE IF NOT EXISTS investigations ({columns_sql})")  # noqa: S608 - static DDL
            existing = {row[1] for row in conn.execute("PRAGMA table_info(investigations)")}
            for name, ddl in _COLUMNS.items():
                if name not in existing:
                    conn.execute(f"ALTER TABLE investigations ADD COLUMN {name} {ddl}")  # noqa: S608 - static DDL
            conn.execute("CREATE INDEX IF NOT EXISTS idx_inv_created ON investigations(created_at DESC)")
            conn.execute("CREATE INDEX IF NOT EXISTS idx_inv_status ON investigations(status)")
            conn.execute("CREATE INDEX IF NOT EXISTS idx_inv_batch ON investigations(batch_id)")

    # ------------------------------------------------------------------ writes

    def create(self, investigation_id: str, request: Dict[str, Any], *, status: str = "pending",
               batch_id: Optional[str] = None, title: Optional[str] = None) -> Dict[str, Any]:
        event = request.get("event_data", {}) or {}
        record = {
            "id": investigation_id,
            "status": status,
            "created_at": _iso(utcnow()),
            "request_json": json.dumps(request, default=str),
            "event_type": event.get("event_type"),
            "source_ip": event.get("source_ip"),
            "title": title or f"{event.get('event_type', 'event')} from {event.get('source_ip') or 'unknown source'}",
            "current_phase": "queued",
            "progress": 0,
            "batch_id": batch_id,
            "emergency_mode": int(bool(request.get("emergency_mode"))),
        }
        with self._lock, self._db() as conn:
            conn.execute(
                f"INSERT INTO investigations ({', '.join(record)}) VALUES ({', '.join('?' for _ in record)})",  # noqa: S608
                list(record.values()),
            )
        return self.get(investigation_id)  # type: ignore[return-value]

    def update(self, investigation_id: str, **fields: Any) -> None:
        if not fields:
            return
        values: Dict[str, Any] = {}
        for key, value in fields.items():
            if key in ("request", "result", "feedback", "owasp_categories", "mitre_techniques"):
                column = f"{key}_json"
                if key == "result" and isinstance(value, dict):
                    value = _strip_large(value)
                values[column] = None if value is None else json.dumps(value, default=str)
            elif key in ("created_at", "started_at", "completed_at"):
                values[key] = _iso(value)
            elif key in ("prompt_injection_detected", "emergency_mode"):
                values[key] = int(bool(value))
            elif key in _COLUMNS:
                values[key] = value
            else:
                raise KeyError(f"Unknown investigation field: {key}")
        assignments = ", ".join(f"{column} = ?" for column in values)
        with self._lock, self._db() as conn:
            conn.execute(f"UPDATE investigations SET {assignments} WHERE id = ?",  # noqa: S608 - whitelisted columns
                         [*values.values(), investigation_id])

    def update_if_status(self, investigation_id: str, allowed_statuses: Tuple[str, ...], **fields: Any) -> bool:
        """Atomic compare-and-set on status, so a cancelled run cannot be overwritten."""
        with self._lock:
            with self._db() as conn:
                row = conn.execute("SELECT status FROM investigations WHERE id = ?", (investigation_id,)).fetchone()
            if not row or row["status"] not in allowed_statuses:
                return False
        self.update(investigation_id, **fields)
        return True

    def record_result(self, investigation_id: str, result: Dict[str, Any]) -> str:
        """Store a planner result, preserving pending_human_review. Returns the stored status."""
        risk = result.get("risk_assessment") or {}
        detection = result.get("detection_assessment") or {}
        scan = result.get("prompt_injection_scan") or {}
        status = result.get("status") or "completed"
        if status not in ("completed", "failed", "pending_human_review"):
            status = "completed"
        updated = self.update_if_status(
            investigation_id, ("pending", "queued", "running"),
            status=status,
            completed_at=utcnow(),
            result=result,
            current_phase=status,
            progress=100 if status != "failed" else 0,
            risk_level=risk.get("risk_level"),
            risk_score=risk.get("risk_score"),
            error=result.get("error") if status == "failed" else None,
            review_status="pending_review" if status == "pending_human_review" else None,
            owasp_categories=detection.get("owasp_llm", []),
            mitre_techniques=sorted(set(detection.get("mitre_attack", [])) | set(detection.get("mitre_atlas", []))),
            prompt_injection_detected=bool(scan.get("detected") or detection.get("prompt_injection_detected")),
        )
        current = self.get(investigation_id)
        return current["status"] if current else status if updated else "unknown"

    def delete(self, investigation_id: str) -> bool:
        with self._lock, self._db() as conn:
            return conn.execute("DELETE FROM investigations WHERE id = ?", (investigation_id,)).rowcount > 0

    # ------------------------------------------------------------------ reads

    @staticmethod
    def _row(row: sqlite3.Row) -> Dict[str, Any]:
        record = dict(row)
        for column, key in _JSON_FIELDS.items():
            raw = record.pop(column, None)
            try:
                record[key] = json.loads(raw) if raw else ({} if key in ("request", "result") else None)
            except ValueError:
                record[key] = None
        for key in ("created_at", "started_at", "completed_at"):
            record[key] = _parse(record.get(key))
        record["prompt_injection_detected"] = bool(record.get("prompt_injection_detected"))
        record["emergency_mode"] = bool(record.get("emergency_mode"))
        record["owasp_categories"] = record.get("owasp_categories") or []
        record["mitre_techniques"] = record.get("mitre_techniques") or []
        return record

    def get(self, investigation_id: str) -> Optional[Dict[str, Any]]:
        with self._db() as conn:
            row = conn.execute("SELECT * FROM investigations WHERE id = ?", (investigation_id,)).fetchone()
        return self._row(row) if row else None

    def list(self, *, status: Optional[str] = None, statuses: Optional[List[str]] = None,
             event_types: Optional[List[str]] = None, risk_levels: Optional[List[str]] = None,
             source_ip: Optional[str] = None, batch_id: Optional[str] = None,
             date_from: Optional[datetime] = None, date_to: Optional[datetime] = None,
             query: Optional[str] = None, limit: int = 50, offset: int = 0,
             include_result: bool = False) -> Tuple[List[Dict[str, Any]], int]:
        clauses: List[str] = []
        params: List[Any] = []

        def _in(column: str, values: Optional[List[str]]):
            if values:
                clauses.append(f"{column} IN ({', '.join('?' for _ in values)})")
                params.extend(values)

        if status:
            clauses.append("status = ?")
            params.append(status)
        _in("status", statuses)
        _in("event_type", event_types)
        _in("risk_level", risk_levels)
        if source_ip:
            clauses.append("source_ip = ?")
            params.append(source_ip)
        if batch_id:
            clauses.append("batch_id = ?")
            params.append(batch_id)
        if date_from:
            clauses.append("created_at >= ?")
            params.append(_iso(date_from))
        if date_to:
            clauses.append("created_at <= ?")
            params.append(_iso(date_to))
        if query:
            like = f"%{query.lower()}%"
            clauses.append("(LOWER(id) LIKE ? OR LOWER(COALESCE(title,'')) LIKE ? OR "
                           "LOWER(COALESCE(event_type,'')) LIKE ? OR LOWER(COALESCE(source_ip,'')) LIKE ? OR "
                           "LOWER(request_json) LIKE ?)")
            params.extend([like] * 5)
        where = f"WHERE {' AND '.join(clauses)}" if clauses else ""
        columns = "*" if include_result else ", ".join(c for c in _COLUMNS if c != "result_json")
        limit = max(1, min(int(limit), 1000))
        offset = max(0, int(offset))
        with self._db() as conn:
            total = conn.execute(f"SELECT COUNT(*) FROM investigations {where}", params).fetchone()[0]  # noqa: S608
            rows = conn.execute(
                f"SELECT {columns} FROM investigations {where} ORDER BY created_at DESC LIMIT ? OFFSET ?",  # noqa: S608
                [*params, limit, offset],
            ).fetchall()
        return [self._row(r) for r in rows], total

    def pending_reviews(self, limit: int = 100) -> List[Dict[str, Any]]:
        items, _ = self.list(status="pending_human_review", limit=limit, include_result=True)
        return [i for i in items if i.get("review_status") in (None, "pending_review", "under_review")]

    def count_by_status(self) -> Dict[str, int]:
        with self._db() as conn:
            return {r[0]: r[1] for r in conn.execute("SELECT status, COUNT(*) FROM investigations GROUP BY status")}

    def active_count(self) -> int:
        with self._db() as conn:
            return conn.execute(
                f"SELECT COUNT(*) FROM investigations WHERE status IN ({', '.join('?' for _ in ACTIVE_STATUSES)})",  # noqa: S608
                ACTIVE_STATUSES).fetchone()[0]

    def metrics(self, since: Optional[datetime] = None) -> Dict[str, Any]:
        since = since or (utcnow() - timedelta(hours=24))
        with self._db() as conn:
            rows = conn.execute(
                "SELECT status, risk_level, created_at, completed_at, prompt_injection_detected "
                "FROM investigations WHERE created_at >= ?", (_iso(since),)).fetchall()
        completed = [r for r in rows if r["status"] in ("completed", "pending_human_review")]
        failed = [r for r in rows if r["status"] == "failed"]
        durations = []
        for r in completed:
            start, end = _parse(r["created_at"]), _parse(r["completed_at"])
            if start and end:
                durations.append((end - start).total_seconds())
        finished = len(completed) + len(failed)
        risk: Dict[str, int] = {}
        for r in rows:
            if r["risk_level"]:
                risk[r["risk_level"]] = risk.get(r["risk_level"], 0) + 1
        return {
            "total": len(rows),
            "completed": len(completed),
            "failed": len(failed),
            "high_risk": len([r for r in rows if r["risk_level"] in ("high", "critical")]),
            "prompt_injection": len([r for r in rows if r["prompt_injection_detected"]]),
            "average_duration_seconds": round(sum(durations) / len(durations), 3) if durations else 0.0,
            "error_rate": round(len(failed) / finished * 100, 2) if finished else 0.0,
            "risk_distribution": risk,
        }

    def mark_interrupted(self) -> int:
        """On startup, runs that were in flight when the process died cannot resume."""
        with self._lock, self._db() as conn:
            return conn.execute(
                "UPDATE investigations SET status = 'failed', error = 'Interrupted by server restart', "
                "current_phase = 'failed' WHERE status IN ('pending', 'queued', 'running')"
            ).rowcount
