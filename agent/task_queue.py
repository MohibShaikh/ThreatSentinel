"""
ThreatSentinel SOC Agent - Task Queue Management

Provides priority-based task queuing, retry logic, and status tracking
for investigation tasks to ensure reliable processing under load.
"""

import asyncio
import json
import logging
import sqlite3
import uuid
from contextlib import contextmanager
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from enum import Enum
from pathlib import Path
from typing import Any, Callable, Dict, Iterator, List, Optional

logger = logging.getLogger(__name__)

IDLE_POLL_SECONDS = 1.0
ERROR_BACKOFF_SECONDS = 5.0


def _utcnow() -> datetime:
    return datetime.now(timezone.utc)


def _parse_ts(value: Optional[str]) -> Optional[datetime]:
    if not value:
        return None
    ts = datetime.fromisoformat(value)
    return ts if ts.tzinfo else ts.replace(tzinfo=timezone.utc)

class TaskStatus(Enum):
    PENDING = "pending"
    IN_PROGRESS = "in_progress"
    COMPLETED = "completed"
    FAILED = "failed"
    RETRYING = "retrying"
    CANCELLED = "cancelled"

class TaskPriority(Enum):
    LOW = 1
    MEDIUM = 2
    HIGH = 3
    CRITICAL = 4
    EMERGENCY = 5

@dataclass
class Task:
    id: str
    task_type: str
    priority: TaskPriority
    payload: Dict[str, Any]
    status: TaskStatus = TaskStatus.PENDING
    created_at: datetime = field(default_factory=_utcnow)
    started_at: Optional[datetime] = None
    completed_at: Optional[datetime] = None
    retry_count: int = 0
    max_retries: int = 3
    error_message: Optional[str] = None
    result: Optional[Any] = None
    timeout_seconds: int = 300  # 5 minutes default
    next_retry_at: Optional[datetime] = None

    def to_dict(self) -> Dict[str, Any]:
        return {
            'id': self.id,
            'task_type': self.task_type,
            'priority': self.priority.value,
            'payload': json.dumps(self.payload, default=str),
            'status': self.status.value,
            'created_at': self.created_at.isoformat(),
            'started_at': self.started_at.isoformat() if self.started_at else None,
            'completed_at': self.completed_at.isoformat() if self.completed_at else None,
            'retry_count': self.retry_count,
            'max_retries': self.max_retries,
            'error_message': self.error_message,
            'result': json.dumps(self.result, default=str) if self.result is not None else None,
            'timeout_seconds': self.timeout_seconds,
            'next_retry_at': self.next_retry_at.isoformat() if self.next_retry_at else None,
        }

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> 'Task':
        task = cls(
            id=data['id'],
            task_type=data['task_type'],
            priority=TaskPriority(data['priority']),
            payload=json.loads(data['payload']),
            status=TaskStatus(data['status']),
            created_at=_parse_ts(data['created_at']),
            retry_count=data['retry_count'],
            max_retries=data['max_retries'],
            error_message=data['error_message'],
            timeout_seconds=data['timeout_seconds']
        )

        task.started_at = _parse_ts(data.get('started_at'))
        task.completed_at = _parse_ts(data.get('completed_at'))
        task.next_retry_at = _parse_ts(data.get('next_retry_at'))
        if data.get('result'):
            task.result = json.loads(data['result'])

        return task

class TaskQueue:
    """
    Priority-based task queue with persistence, retry logic, and status tracking.

    Features:
    - Priority-based task scheduling (Emergency > Critical > High > Medium > Low)
    - Persistent storage with SQLite
    - Automatic retry with exponential backoff
    - Task timeout handling
    - Concurrent task processing
    - Status tracking and monitoring
    """

    def __init__(self, db_path: str = "data/tasks.db", max_workers: int = 5):
        self.db_path = Path(db_path)
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        self.max_workers = max_workers
        self.active_tasks: Dict[str, Task] = {}
        self.task_handlers: Dict[str, Callable] = {}
        self.workers: List[asyncio.Task] = []
        self.shutdown_event = asyncio.Event()

        self._init_database()

    @contextmanager
    def _db(self) -> Iterator[sqlite3.Connection]:
        conn = sqlite3.connect(self.db_path, timeout=30)
        try:
            with conn:
                yield conn
        finally:
            conn.close()

    @property
    def is_running(self) -> bool:
        return any(not w.done() for w in self.workers)

    def _init_database(self):
        """Initialize SQLite storage, enable WAL and migrate older schemas."""
        with self._db() as conn:
            conn.execute("PRAGMA journal_mode=WAL")
            conn.execute("""
                CREATE TABLE IF NOT EXISTS tasks (
                    id TEXT PRIMARY KEY,
                    task_type TEXT NOT NULL,
                    priority INTEGER NOT NULL,
                    payload TEXT NOT NULL,
                    status TEXT NOT NULL,
                    created_at TEXT NOT NULL,
                    started_at TEXT,
                    completed_at TEXT,
                    retry_count INTEGER DEFAULT 0,
                    max_retries INTEGER DEFAULT 3,
                    error_message TEXT,
                    result TEXT,
                    timeout_seconds INTEGER DEFAULT 300,
                    next_retry_at TEXT
                )
            """)
            columns = {row[1] for row in conn.execute("PRAGMA table_info(tasks)")}
            if "next_retry_at" not in columns:
                conn.execute("ALTER TABLE tasks ADD COLUMN next_retry_at TEXT")
            conn.execute("""
                CREATE INDEX IF NOT EXISTS idx_status_priority
                ON tasks(status, priority DESC, created_at ASC)
            """)

    def register_handler(self, task_type: str, handler: Callable):
        """Register a handler function for a specific task type."""
        self.task_handlers[task_type] = handler
        logger.info(f"Registered handler for task type: {task_type}")

    async def add_task(self,
                      task_type: str,
                      payload: Dict[str, Any],
                      priority: TaskPriority = TaskPriority.MEDIUM,
                      max_retries: int = 3,
                      timeout_seconds: int = 300) -> str:
        """Add a new task to the queue."""
        task = Task(
            id=str(uuid.uuid4()),
            task_type=task_type,
            priority=priority,
            payload=payload,
            max_retries=max_retries,
            timeout_seconds=timeout_seconds
        )

        with self._db() as conn:
            conn.execute("""
                INSERT INTO tasks (id, task_type, priority, payload, status, created_at, started_at,
                                   completed_at, retry_count, max_retries, error_message, result,
                                   timeout_seconds, next_retry_at)
                VALUES (?, ?, ?, ?, ?, ?, NULL, NULL, ?, ?, NULL, NULL, ?, NULL)
            """, (
                task.id, task.task_type, task.priority.value,
                json.dumps(task.payload, default=str), task.status.value,
                task.created_at.isoformat(), task.retry_count, task.max_retries,
                task.timeout_seconds
            ))

        logger.info(f"Added task {task.id} ({task.task_type}) with priority {priority.name}")
        return task.id

    def _claim_next_task(self) -> Optional[Task]:
        now = _utcnow().isoformat()
        conn = sqlite3.connect(self.db_path, timeout=30, isolation_level=None)
        try:
            conn.row_factory = sqlite3.Row
            # BEGIN IMMEDIATE takes the write lock up front, so two workers (or two
            # processes) can never select and claim the same row.
            conn.execute("BEGIN IMMEDIATE")
            try:
                row = conn.execute("""
                    SELECT * FROM tasks
                    WHERE status = 'pending'
                       OR (status = 'retrying' AND (next_retry_at IS NULL OR next_retry_at <= ?))
                    ORDER BY priority DESC, created_at ASC
                    LIMIT 1
                """, (now,)).fetchone()
                if not row:
                    conn.execute("COMMIT")
                    return None
                task = Task.from_dict(dict(row))
                task.status = TaskStatus.IN_PROGRESS
                task.started_at = _utcnow()
                task.next_retry_at = None
                conn.execute(
                    "UPDATE tasks SET status = ?, started_at = ?, next_retry_at = NULL WHERE id = ?",
                    (task.status.value, task.started_at.isoformat(), task.id),
                )
                conn.execute("COMMIT")
                return task
            except Exception:
                conn.execute("ROLLBACK")
                raise
        finally:
            conn.close()

    async def get_next_task(self) -> Optional[Task]:
        """Atomically claim the highest-priority task that is due."""
        return self._claim_next_task()

    async def complete_task(self, task_id: str, result: Any = None):
        """Mark a task as completed with optional result."""
        task = self.active_tasks.get(task_id)
        if task:
            task.status = TaskStatus.COMPLETED
            task.completed_at = _utcnow()
            task.result = result
            del self.active_tasks[task_id]

        with self._db() as conn:
            conn.execute("""
                UPDATE tasks
                SET status = ?, completed_at = ?, result = ?
                WHERE id = ?
            """, (TaskStatus.COMPLETED.value,
                  _utcnow().isoformat(),
                  json.dumps(result, default=str) if result is not None else None,
                  task_id))

        logger.info(f"Task {task_id} completed successfully")

    async def fail_task(self, task_id: str, error_message: str):
        """Mark a task as failed or schedule retry."""
        task = self.active_tasks.get(task_id)
        if not task:
            with self._db() as conn:
                cursor = conn.execute("SELECT * FROM tasks WHERE id = ?", (task_id,))
                row = cursor.fetchone()
                if row:
                    columns = [desc[0] for desc in cursor.description]
                    task_data = dict(zip(columns, row, strict=True))
                    task = Task.from_dict(task_data)

        if not task:
            logger.error(f"Task {task_id} not found for failure handling")
            return

        task.retry_count += 1
        task.error_message = error_message

        if task.retry_count >= task.max_retries:
            # Maximum retries reached, mark as failed
            task.status = TaskStatus.FAILED
            task.completed_at = _utcnow()
            task.next_retry_at = None
            logger.error(f"Task {task_id} failed permanently after {task.retry_count} retries: {error_message}")
        else:
            # Schedule retry with exponential backoff
            task.status = TaskStatus.RETRYING
            retry_delay = min(2 ** task.retry_count, 300)  # Max 5 minutes
            task.next_retry_at = _utcnow() + timedelta(seconds=retry_delay)
            logger.warning(f"Task {task_id} failed, retrying in {retry_delay}s (attempt {task.retry_count}/{task.max_retries}): {error_message}")

        # Remove from active tasks
        if task_id in self.active_tasks:
            del self.active_tasks[task_id]

        with self._db() as conn:
            conn.execute("""
                UPDATE tasks
                SET status = ?, retry_count = ?, error_message = ?, completed_at = ?, next_retry_at = ?
                WHERE id = ?
            """, (task.status.value, task.retry_count, task.error_message,
                  task.completed_at.isoformat() if task.completed_at else None,
                  task.next_retry_at.isoformat() if task.next_retry_at else None,
                  task_id))

    async def cancel_task(self, task_id: str) -> bool:
        """Cancel a pending or in-progress task."""
        # Remove from active tasks if present
        if task_id in self.active_tasks:
            del self.active_tasks[task_id]

        with self._db() as conn:
            cursor = conn.execute("""
                UPDATE tasks
                SET status = ?, completed_at = ?, next_retry_at = NULL
                WHERE id = ? AND status IN ('pending', 'in_progress', 'retrying')
            """, (TaskStatus.CANCELLED.value, _utcnow().isoformat(), task_id))
            return cursor.rowcount > 0

    async def get_task_status(self, task_id: str) -> Optional[Task]:
        """Get current status of a task."""
        # Check active tasks first
        if task_id in self.active_tasks:
            return self.active_tasks[task_id]

        with self._db() as conn:
            cursor = conn.execute("SELECT * FROM tasks WHERE id = ?", (task_id,))
            row = cursor.fetchone()

            if row:
                columns = [desc[0] for desc in cursor.description]
                task_data = dict(zip(columns, row, strict=True))
                return Task.from_dict(task_data)

        return None

    async def list_tasks(self, status: Optional[str] = None, limit: int = 50) -> List[Task]:
        """Most recent tasks first, optionally filtered by status."""
        limit = max(1, min(int(limit), 1000))
        query = "SELECT * FROM tasks"
        params: List[Any] = []
        if status:
            query += " WHERE status = ?"
            params.append(status)
        query += " ORDER BY created_at DESC LIMIT ?"
        params.append(limit)
        with self._db() as conn:
            cursor = conn.execute(query, params)
            columns = [desc[0] for desc in cursor.description]
            tasks = [Task.from_dict(dict(zip(columns, row, strict=True))) for row in cursor.fetchall()]
        # In-flight tasks carry fresher state than their stored row
        return [self.active_tasks.get(t.id, t) for t in tasks]

    async def count_tasks(self, status: Optional[str] = None) -> int:
        with self._db() as conn:
            if status:
                return conn.execute("SELECT COUNT(*) FROM tasks WHERE status = ?", (status,)).fetchone()[0]
            return conn.execute("SELECT COUNT(*) FROM tasks").fetchone()[0]

    async def get_queue_stats(self) -> Dict[str, Any]:
        """Get current queue statistics."""
        with self._db() as conn:
            cursor = conn.execute("""
                SELECT status, COUNT(*) as count
                FROM tasks
                GROUP BY status
            """)
            status_counts = dict(cursor.fetchall())

            cursor = conn.execute("""
                SELECT COUNT(*) FROM tasks
                WHERE status = 'pending' OR status = 'retrying'
            """)
            pending_count = cursor.fetchone()[0]

            cursor = conn.execute("""
                SELECT task_type, COUNT(*) as count
                FROM tasks
                WHERE status IN ('pending', 'in_progress', 'retrying')
                GROUP BY task_type
            """)
            type_counts = dict(cursor.fetchall())

        return {
            'status_counts': status_counts,
            'pending_tasks': pending_count,
            'active_tasks': len(self.active_tasks),
            'task_type_counts': type_counts,
            'max_workers': self.max_workers,
            'workers_running': len([w for w in self.workers if not w.done()])
        }

    async def process_task(self, task: Task) -> Any:
        """Process a single task using the registered handler."""
        if task.task_type not in self.task_handlers:
            raise ValueError(f"No handler registered for task type: {task.task_type}")

        handler = self.task_handlers[task.task_type]

        try:
            # Execute with timeout
            result = await asyncio.wait_for(
                handler(task.payload),
                timeout=task.timeout_seconds
            )
            return result
        except asyncio.TimeoutError:
            raise ValueError(f"Task timed out after {task.timeout_seconds} seconds") from None
        except Exception as e:
            raise ValueError(f"Task handler failed: {str(e)}") from e

    async def worker(self):
        """Worker coroutine that processes tasks from the queue."""
        while not self.shutdown_event.is_set():
            try:
                task = await self.get_next_task()
                if not task:
                    await self._idle(IDLE_POLL_SECONDS)
                    continue

                self.active_tasks[task.id] = task
                logger.info(f"Processing task {task.id} ({task.task_type})")
                try:
                    result = await self.process_task(task)
                    await self.complete_task(task.id, result)
                except asyncio.CancelledError:
                    await self.fail_task(task.id, "Worker cancelled during shutdown")
                    raise
                except Exception as e:
                    await self.fail_task(task.id, str(e))

            except asyncio.CancelledError:
                break
            except Exception as e:
                logger.error(f"Worker error: {e}")
                await self._idle(ERROR_BACKOFF_SECONDS)

    async def _idle(self, seconds: float):
        """Sleep that wakes immediately on shutdown."""
        try:
            await asyncio.wait_for(self.shutdown_event.wait(), timeout=seconds)
        except asyncio.TimeoutError:
            pass

    async def start(self):
        """Start workers. Calling start() on a running queue is a no-op."""
        if self.is_running:
            logger.info("Task queue already running")
            return
        self.shutdown_event.clear()
        self.workers = [asyncio.create_task(self.worker()) for _ in range(self.max_workers)]
        logger.info(f"Task queue started with {self.max_workers} workers")

    async def stop(self, timeout: float = 10.0):
        """Signal shutdown, let in-flight tasks finish, then cancel stragglers."""
        logger.info("Stopping task queue...")
        self.shutdown_event.set()
        if self.workers:
            _, pending = await asyncio.wait(self.workers, timeout=timeout)
            for worker in pending:
                worker.cancel()
            await asyncio.gather(*self.workers, return_exceptions=True)
        self.workers = []
        logger.info("Task queue stopped")

    async def cleanup_old_tasks(self, days: int = 30):
        """Clean up completed/failed tasks older than specified days."""
        cutoff_date = _utcnow() - timedelta(days=days)

        with self._db() as conn:
            cursor = conn.execute("""
                DELETE FROM tasks
                WHERE status IN ('completed', 'failed', 'cancelled')
                AND created_at < ?
            """, (cutoff_date.isoformat(),))

            deleted_count = cursor.rowcount

        logger.info(f"Cleaned up {deleted_count} old tasks")
        return deleted_count
