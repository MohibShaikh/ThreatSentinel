"""
Unit tests for agent/task_queue.py

Tests the priority-based task queue system with persistence,
retry logic, and concurrent processing capabilities.
"""

import pytest
import asyncio
import tempfile
import os
import sqlite3
import json
from datetime import datetime, timedelta, timezone

from agent.task_queue import (
    TaskQueue, Task, TaskStatus, TaskPriority
)


class TestTaskStatus:
    """Test TaskStatus enum"""

    def test_task_status_values(self):
        """Test TaskStatus enum values"""
        assert TaskStatus.PENDING.value == "pending"
        assert TaskStatus.IN_PROGRESS.value == "in_progress"
        assert TaskStatus.COMPLETED.value == "completed"
        assert TaskStatus.FAILED.value == "failed"
        assert TaskStatus.RETRYING.value == "retrying"
        assert TaskStatus.CANCELLED.value == "cancelled"


class TestTaskPriority:
    """Test TaskPriority enum"""

    def test_task_priority_values(self):
        """Test TaskPriority enum values"""
        assert TaskPriority.LOW.value == 1
        assert TaskPriority.MEDIUM.value == 2
        assert TaskPriority.HIGH.value == 3
        assert TaskPriority.CRITICAL.value == 4
        assert TaskPriority.EMERGENCY.value == 5

    def test_priority_ordering(self):
        """Test that priority numeric values are ordered correctly"""
        assert TaskPriority.CRITICAL.value > TaskPriority.HIGH.value
        assert TaskPriority.HIGH.value > TaskPriority.MEDIUM.value
        assert TaskPriority.MEDIUM.value > TaskPriority.LOW.value
        assert TaskPriority.EMERGENCY.value > TaskPriority.CRITICAL.value


class TestTask:
    """Test Task dataclass"""

    def test_task_creation(self):
        """Test basic Task creation"""
        task = Task(
            id="test_task_001",
            task_type="investigation",
            priority=TaskPriority.HIGH,
            payload={"event_id": "evt_001", "source_ip": "192.168.1.1"}
        )

        assert task.id == "test_task_001"
        assert task.task_type == "investigation"
        assert task.priority == TaskPriority.HIGH
        assert task.status == TaskStatus.PENDING
        assert task.retry_count == 0
        assert task.max_retries == 3
        assert task.timeout_seconds == 300
        assert task.payload["event_id"] == "evt_001"
        assert isinstance(task.created_at, datetime)

    def test_task_to_dict(self):
        """Test Task serialization to dictionary"""
        task = Task(
            id="test_task_002",
            task_type="analysis",
            priority=TaskPriority.MEDIUM,
            payload={"data": "test"}
        )

        task_dict = task.to_dict()

        assert task_dict["id"] == "test_task_002"
        assert task_dict["task_type"] == "analysis"
        assert task_dict["priority"] == TaskPriority.MEDIUM.value
        assert task_dict["status"] == TaskStatus.PENDING.value
        assert task_dict["payload"] == json.dumps({"data": "test"})
        assert task_dict["retry_count"] == 0
        assert task_dict["max_retries"] == 3
        assert task_dict["timeout_seconds"] == 300

    def test_task_from_dict(self):
        """Test Task deserialization from dictionary"""
        now = datetime.now()
        task_data = {
            "id": "test_task_003",
            "task_type": "report",
            "priority": TaskPriority.LOW.value,
            "status": TaskStatus.IN_PROGRESS.value,
            "payload": json.dumps({"report_id": "rpt_001"}),
            "retry_count": 2,
            "max_retries": 3,
            "created_at": now.isoformat(),
            "started_at": now.isoformat(),
            "completed_at": None,
            "error_message": None,
            "result": None,
            "timeout_seconds": 300
        }

        task = Task.from_dict(task_data)

        assert task.id == "test_task_003"
        assert task.task_type == "report"
        assert task.priority == TaskPriority.LOW
        assert task.status == TaskStatus.IN_PROGRESS
        assert task.retry_count == 2
        assert task.payload == {"report_id": "rpt_001"}
        assert task.started_at is not None

    def test_task_roundtrip(self):
        """Test Task serialization roundtrip via to_dict/from_dict"""
        original = Task(
            id="roundtrip_001",
            task_type="scan",
            priority=TaskPriority.CRITICAL,
            payload={"target": "10.0.0.1"},
            max_retries=5,
            timeout_seconds=600
        )

        task_dict = original.to_dict()
        restored = Task.from_dict(task_dict)

        assert restored.id == original.id
        assert restored.task_type == original.task_type
        assert restored.priority == original.priority
        assert restored.payload == original.payload
        assert restored.max_retries == original.max_retries
        assert restored.timeout_seconds == original.timeout_seconds


class TestTaskQueue:
    """Test TaskQueue functionality"""

    @pytest.fixture
    def temp_queue_dir(self):
        """Create temporary directory for test database"""
        with tempfile.TemporaryDirectory() as temp_dir:
            yield temp_dir

    @pytest.fixture
    def task_queue(self, temp_queue_dir):
        """Create TaskQueue instance with temporary storage"""
        return TaskQueue(db_path=os.path.join(temp_queue_dir, "test_tasks.db"))

    def test_queue_initialization(self, task_queue):
        """Test task queue initialization"""
        assert os.path.exists(task_queue.db_path)
        assert task_queue.workers == []
        assert len(task_queue.task_handlers) == 0
        assert task_queue.max_workers == 5

    def test_register_handler(self, task_queue):
        """Test registering task handlers"""
        async def test_handler(payload):
            return {"result": "success"}

        task_queue.register_handler("investigation", test_handler)

        assert "investigation" in task_queue.task_handlers
        assert task_queue.task_handlers["investigation"] == test_handler

    @pytest.mark.asyncio
    async def test_add_task(self, task_queue):
        """Test adding task to queue"""
        task_id = await task_queue.add_task(
            task_type="investigation",
            payload={"event_id": "evt_001", "source_ip": "192.168.1.100"},
            priority=TaskPriority.HIGH
        )

        assert isinstance(task_id, str)

        conn = sqlite3.connect(task_queue.db_path)
        cursor = conn.cursor()
        cursor.execute("SELECT * FROM tasks WHERE id = ?", (task_id,))
        result = cursor.fetchone()
        conn.close()

        assert result is not None

    @pytest.mark.asyncio
    async def test_get_next_task(self, task_queue):
        """Test retrieving next task by priority"""
        await task_queue.add_task("test", {}, TaskPriority.LOW)
        high_id = await task_queue.add_task("test", {}, TaskPriority.HIGH)
        critical_id = await task_queue.add_task("test", {}, TaskPriority.CRITICAL)

        next_task = await task_queue.get_next_task()
        assert next_task is not None
        assert next_task.id == critical_id
        assert next_task.priority == TaskPriority.CRITICAL
        assert next_task.status == TaskStatus.IN_PROGRESS

        next_task = await task_queue.get_next_task()
        assert next_task is not None
        assert next_task.id == high_id
        assert next_task.priority == TaskPriority.HIGH

    @pytest.mark.asyncio
    async def test_complete_task(self, task_queue):
        """Test completing a task"""
        task_id = await task_queue.add_task(
            task_type="investigation",
            payload={"event_id": "evt_001"},
            priority=TaskPriority.HIGH
        )

        result = {"status": "success", "findings": ["test"]}
        await task_queue.complete_task(task_id, result)

        conn = sqlite3.connect(task_queue.db_path)
        cursor = conn.cursor()
        cursor.execute("SELECT status, result FROM tasks WHERE id = ?", (task_id,))
        row = cursor.fetchone()
        conn.close()

        assert row[0] == TaskStatus.COMPLETED.value
        assert json.loads(row[1]) == result

    @pytest.mark.asyncio
    async def test_fail_task_with_retry(self, task_queue):
        """Test failing task with retry logic"""
        task_id = await task_queue.add_task(
            task_type="investigation",
            payload={"event_id": "evt_001"},
            priority=TaskPriority.HIGH,
            max_retries=3
        )

        await task_queue.fail_task(task_id, "Test error")

        conn = sqlite3.connect(task_queue.db_path)
        cursor = conn.cursor()
        cursor.execute("SELECT status, retry_count FROM tasks WHERE id = ?", (task_id,))
        row = cursor.fetchone()
        conn.close()

        assert row[0] == TaskStatus.RETRYING.value
        assert row[1] == 1

    @pytest.mark.asyncio
    async def test_fail_task_max_retries(self, task_queue):
        """Test failing task that exceeds max retries"""
        task_id = await task_queue.add_task(
            task_type="investigation",
            payload={"event_id": "evt_001"},
            priority=TaskPriority.HIGH,
            max_retries=1
        )

        await task_queue.fail_task(task_id, "Error 1")

        conn = sqlite3.connect(task_queue.db_path)
        cursor = conn.cursor()
        cursor.execute("SELECT status, retry_count FROM tasks WHERE id = ?", (task_id,))
        row = cursor.fetchone()
        conn.close()

        assert row[0] == TaskStatus.FAILED.value

    @pytest.mark.asyncio
    async def test_cancel_task(self, task_queue):
        """Test cancelling a task"""
        task_id = await task_queue.add_task(
            task_type="investigation",
            payload={"event_id": "evt_001"},
            priority=TaskPriority.HIGH
        )

        result = await task_queue.cancel_task(task_id)
        assert result is True

        conn = sqlite3.connect(task_queue.db_path)
        cursor = conn.cursor()
        cursor.execute("SELECT status FROM tasks WHERE id = ?", (task_id,))
        row = cursor.fetchone()
        conn.close()

        assert row[0] == TaskStatus.CANCELLED.value

    @pytest.mark.asyncio
    async def test_cancel_nonexistent_task(self, task_queue):
        """Test cancelling a task that doesn't exist returns False"""
        result = await task_queue.cancel_task("nonexistent_id")
        assert result is False

    @pytest.mark.asyncio
    async def test_get_task_status(self, task_queue):
        """Test retrieving task status"""
        task_id = await task_queue.add_task(
            task_type="investigation",
            payload={"event_id": "evt_001"},
            priority=TaskPriority.HIGH
        )

        task_info = await task_queue.get_task_status(task_id)

        assert task_info is not None
        assert task_info.id == task_id
        assert task_info.status == TaskStatus.PENDING

    @pytest.mark.asyncio
    async def test_get_task_status_nonexistent(self, task_queue):
        """Test retrieving status for a task that doesn't exist"""
        task_info = await task_queue.get_task_status("nonexistent_id")
        assert task_info is None

    @pytest.mark.asyncio
    async def test_get_queue_stats(self, task_queue):
        """Test getting queue statistics"""
        await task_queue.add_task("test", {}, TaskPriority.LOW)
        await task_queue.add_task("test", {}, TaskPriority.HIGH)
        task_id_3 = await task_queue.add_task("test", {}, TaskPriority.MEDIUM)

        await task_queue.complete_task(task_id_3, {"result": "done"})

        stats = await task_queue.get_queue_stats()

        assert "status_counts" in stats
        assert "pending_tasks" in stats
        assert "active_tasks" in stats
        assert "task_type_counts" in stats
        assert "max_workers" in stats
        assert stats["pending_tasks"] >= 2
        assert stats["max_workers"] == 5

    @pytest.mark.asyncio
    async def test_cleanup_old_tasks(self, task_queue):
        """Test cleanup of old completed tasks"""
        task_id_old = await task_queue.add_task("test", {}, TaskPriority.LOW)
        await task_queue.complete_task(task_id_old, {"result": "done"})

        old_timestamp = (datetime.now() - timedelta(days=40)).isoformat()
        conn = sqlite3.connect(task_queue.db_path)
        cursor = conn.cursor()
        cursor.execute(
            "UPDATE tasks SET created_at = ? WHERE id = ?",
            (old_timestamp, task_id_old)
        )
        conn.commit()
        conn.close()

        task_id_recent = await task_queue.add_task("test", {}, TaskPriority.LOW)
        await task_queue.complete_task(task_id_recent, {"result": "done"})

        deleted_count = await task_queue.cleanup_old_tasks(days=30)

        assert deleted_count >= 1

        conn = sqlite3.connect(task_queue.db_path)
        cursor = conn.cursor()
        cursor.execute("SELECT COUNT(*) FROM tasks WHERE id = ?", (task_id_old,))
        count = cursor.fetchone()[0]
        conn.close()

        assert count == 0

    @pytest.mark.asyncio
    async def test_worker_processing(self, task_queue):
        """Test worker task processing"""
        async def test_handler(payload):
            await asyncio.sleep(0.1)
            return {"processed": True}

        task_queue.register_handler("investigation", test_handler)

        task_id = await task_queue.add_task(
            task_type="investigation",
            payload={"data": "test"},
            priority=TaskPriority.HIGH
        )

        await task_queue.start()

        await asyncio.sleep(1.0)

        task_info = await task_queue.get_task_status(task_id)
        assert task_info.status == TaskStatus.COMPLETED

        await task_queue.stop()

    @pytest.mark.asyncio
    async def test_worker_error_handling(self, task_queue):
        """Test worker error handling"""
        async def failing_handler(payload):
            raise Exception("Handler failed")

        task_queue.register_handler("failing_task", failing_handler)

        task_id = await task_queue.add_task(
            task_type="failing_task",
            payload={},
            priority=TaskPriority.HIGH,
            max_retries=1
        )

        await task_queue.start()

        await asyncio.sleep(2.0)

        task_info = await task_queue.get_task_status(task_id)
        assert task_info.status in [TaskStatus.FAILED, TaskStatus.RETRYING]

        await task_queue.stop()

    @pytest.mark.asyncio
    async def test_concurrent_task_processing(self, task_queue):
        """Test concurrent processing of multiple tasks"""
        async def concurrent_handler(payload):
            await asyncio.sleep(0.1)
            return {"processed": True}

        task_queue.register_handler("concurrent", concurrent_handler)

        task_ids = []
        for i in range(5):
            tid = await task_queue.add_task("concurrent", {"id": i}, TaskPriority.MEDIUM)
            task_ids.append(tid)

        await task_queue.start()

        await asyncio.sleep(3.0)

        completed_count = 0
        for tid in task_ids:
            info = await task_queue.get_task_status(tid)
            if info.status == TaskStatus.COMPLETED:
                completed_count += 1

        assert completed_count == 5

        await task_queue.stop()

    @pytest.mark.asyncio
    async def test_process_task_no_handler(self, task_queue):
        """Test that processing a task with no registered handler raises"""
        task = Task(
            id="no_handler_001",
            task_type="unknown_type",
            priority=TaskPriority.LOW,
            payload={}
        )
        with pytest.raises(ValueError, match="No handler registered"):
            await task_queue.process_task(task)


class TestTaskQueueIntegration:
    """Integration tests for task queue system"""

    @pytest.fixture
    def temp_queue_dir(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            yield temp_dir

    @pytest.mark.asyncio
    async def test_real_investigation_workflow(self, temp_queue_dir):
        """Test task queue with realistic investigation workflow"""
        queue = TaskQueue(db_path=os.path.join(temp_queue_dir, "workflow_test.db"))

        async def investigation_handler(payload):
            event_id = payload.get("event_id")
            source_ip = payload.get("source_ip")
            await asyncio.sleep(0.1)
            return {
                "event_id": event_id,
                "source_ip": source_ip,
                "investigation_result": "completed",
                "risk_score": 0.75,
                "indicators": ["malicious_activity"]
            }

        queue.register_handler("investigation", investigation_handler)

        critical_id = await queue.add_task(
            task_type="investigation",
            payload={
                "event_id": "evt_001",
                "source_ip": "192.168.1.100",
                "event_type": "suspicious_ip",
                "severity": "critical"
            },
            priority=TaskPriority.CRITICAL
        )

        normal_id = await queue.add_task(
            task_type="investigation",
            payload={
                "event_id": "evt_002",
                "source_ip": "10.0.0.50",
                "event_type": "port_scan",
                "severity": "medium"
            },
            priority=TaskPriority.MEDIUM
        )

        await queue.start()

        await asyncio.sleep(2.0)

        critical_result = await queue.get_task_status(critical_id)
        normal_result = await queue.get_task_status(normal_id)

        assert critical_result.status == TaskStatus.COMPLETED
        assert normal_result.status == TaskStatus.COMPLETED

        assert critical_result.result["risk_score"] == 0.75

        await queue.stop()

    @pytest.mark.asyncio
    async def test_queue_persistence_across_restarts(self, temp_queue_dir):
        """Test that tasks persist across queue restarts"""
        db_path = os.path.join(temp_queue_dir, "persistence_test.db")

        queue1 = TaskQueue(db_path=db_path)

        task_id = await queue1.add_task(
            task_type="test",
            payload={"data": "persistent"},
            priority=TaskPriority.HIGH
        )

        queue2 = TaskQueue(db_path=db_path)

        task_info = await queue2.get_task_status(task_id)
        assert task_info is not None
        assert task_info.id == task_id
        assert task_info.priority == TaskPriority.HIGH


# CLI Mock Demonstrations
class TestTaskQueueCLIMockInteractions:
    """Mock CLI interactions for task queue testing"""

    @pytest.mark.mock
    def test_queue_stats_cli_mock(self):
        """Mock CLI interaction for queue statistics"""
        print("\n=== Task Queue Stats CLI Mock Demo ===")
        print("Command: python -m agent.task_queue stats")
        print("Response:")
        print(json.dumps({
            "queue_statistics": {
                "total_tasks": 1247,
                "pending": 23,
                "in_progress": 5,
                "completed": 1195,
                "failed": 18,
                "cancelled": 6
            },
            "priority_breakdown": {
                "critical": 3,
                "high": 8,
                "medium": 12,
                "low": 5
            },
            "task_types": {
                "investigation": 892,
                "report_generation": 234,
                "pattern_analysis": 121
            },
            "performance_metrics": {
                "avg_processing_time_seconds": 45.6,
                "successful_completion_rate": 0.96,
                "active_workers": 4,
                "max_workers": 8
            },
            "last_updated": "2024-07-27T14:35:00Z"
        }, indent=2))

    @pytest.mark.mock
    def test_queue_add_task_cli_mock(self):
        """Mock CLI interaction for adding task"""
        print("\n=== Add Task CLI Mock Demo ===")
        print("Command: python -m agent.task_queue add --type investigation --priority high --payload '{\"event_id\":\"evt_001\",\"source_ip\":\"192.168.1.100\"}'")
        print("Response:")
        print(json.dumps({
            "task_created": {
                "task_id": "task_2024_0789",
                "task_type": "investigation",
                "priority": "high",
                "status": "pending",
                "payload": {
                    "event_id": "evt_001",
                    "source_ip": "192.168.1.100"
                },
                "created_at": "2024-07-27T14:36:15Z",
                "queue_position": 3
            },
            "message": "Task successfully added to queue",
            "estimated_start_time": "2024-07-27T14:38:30Z"
        }, indent=2))

    @pytest.mark.mock
    def test_queue_worker_management_cli_mock(self):
        """Mock CLI interaction for worker management"""
        print("\n=== Worker Management CLI Mock Demo ===")
        print("Command: python -m agent.task_queue workers --action start --count 6")
        print("Response:")
        print(json.dumps({
            "worker_status": {
                "action": "start",
                "workers_started": 6,
                "total_active_workers": 6,
                "max_workers": 8,
                "worker_ids": [
                    "worker_001", "worker_002", "worker_003",
                    "worker_004", "worker_005", "worker_006"
                ]
            },
            "queue_impact": {
                "estimated_throughput_increase": "300%",
                "avg_wait_time_reduction": "65%"
            },
            "system_resources": {
                "cpu_usage_percent": 45,
                "memory_usage_mb": 256,
                "available_capacity": "good"
            },
            "timestamp": "2024-07-27T14:37:00Z"
        }, indent=2))


class TestTaskQueueHardening:
    @pytest.fixture
    def queue(self, tmp_path):
        return TaskQueue(db_path=str(tmp_path / "q.db"), max_workers=2)

    async def test_backoff_is_enforced(self, queue):
        task_id = await queue.add_task("t", {}, TaskPriority.HIGH, max_retries=3)
        claimed = await queue.get_next_task()
        assert claimed.id == task_id
        await queue.fail_task(task_id, "boom")
        status = await queue.get_task_status(task_id)
        assert status.status == TaskStatus.RETRYING
        assert status.next_retry_at > datetime.now(timezone.utc)
        assert await queue.get_next_task() is None  # not due yet

        with sqlite3.connect(queue.db_path) as conn:
            past = (datetime.now(timezone.utc) - timedelta(seconds=1)).isoformat()
            conn.execute("UPDATE tasks SET next_retry_at = ? WHERE id = ?", (past, task_id))
        due = await queue.get_next_task()
        assert due is not None and due.id == task_id

    async def test_atomic_claim_no_duplicates(self, queue):
        for i in range(20):
            await queue.add_task("t", {"i": i}, TaskPriority.MEDIUM)
        claimed = await asyncio.gather(*[asyncio.to_thread(queue._claim_next_task) for _ in range(30)])
        ids = [t.id for t in claimed if t]
        assert len(ids) == 20 and len(set(ids)) == 20

    async def test_start_stop_restart_lifecycle(self, queue):
        processed = []

        async def handler(payload):
            processed.append(payload["n"])
            return {"ok": True}

        queue.register_handler("work", handler)
        await queue.start()
        workers = list(queue.workers)
        await queue.start()  # second start is a no-op
        assert queue.workers == workers and len(workers) == 2

        stop_started = asyncio.get_running_loop().time()
        await queue.stop()
        assert asyncio.get_running_loop().time() - stop_started < 2.0  # idle workers wake on shutdown
        assert queue.workers == [] and not queue.is_running

        await queue.add_task("work", {"n": 1}, TaskPriority.HIGH)
        await queue.start()  # restart clears the shutdown flag
        for _ in range(50):
            if processed:
                break
            await asyncio.sleep(0.05)
        await queue.stop()
        assert processed == [1]

    async def test_timestamps_are_utc(self, queue):
        task_id = await queue.add_task("t", {}, TaskPriority.LOW)
        task = await queue.get_task_status(task_id)
        assert task.created_at.tzinfo is not None

    async def test_legacy_schema_migrated(self, tmp_path):
        path = tmp_path / "legacy.db"
        with sqlite3.connect(path) as conn:
            conn.execute("""CREATE TABLE tasks (id TEXT PRIMARY KEY, task_type TEXT NOT NULL,
                priority INTEGER NOT NULL, payload TEXT NOT NULL, status TEXT NOT NULL, created_at TEXT NOT NULL,
                started_at TEXT, completed_at TEXT, retry_count INTEGER DEFAULT 0, max_retries INTEGER DEFAULT 3,
                error_message TEXT, result TEXT, timeout_seconds INTEGER DEFAULT 300)""")
            conn.execute("INSERT INTO tasks VALUES ('old', 't', 2, '{}', 'retrying', '2024-01-01T00:00:00', "
                         "NULL, NULL, 1, 3, 'x', NULL, 300)")
        queue = TaskQueue(db_path=str(path))
        claimed = await queue.get_next_task()
        assert claimed.id == "old"  # NULL next_retry_at means due immediately
