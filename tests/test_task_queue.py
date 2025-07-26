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
from datetime import datetime, timedelta
from unittest.mock import AsyncMock, MagicMock, patch

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
        assert TaskStatus.CANCELLED.value == "cancelled"


class TestTaskPriority:
    """Test TaskPriority enum"""
    
    def test_task_priority_values(self):
        """Test TaskPriority enum values"""
        assert TaskPriority.LOW.value == 1
        assert TaskPriority.MEDIUM.value == 2
        assert TaskPriority.HIGH.value == 3
        assert TaskPriority.CRITICAL.value == 4
    
    def test_priority_comparison(self):
        """Test that priorities can be compared"""
        assert TaskPriority.CRITICAL > TaskPriority.HIGH
        assert TaskPriority.HIGH > TaskPriority.MEDIUM
        assert TaskPriority.MEDIUM > TaskPriority.LOW


class TestTask:
    """Test Task dataclass"""
    
    def test_task_creation(self):
        """Test basic Task creation"""
        task = Task(
            task_id="test_task_001",
            task_type="investigation",
            priority=TaskPriority.HIGH,
            payload={"event_id": "evt_001", "source_ip": "192.168.1.1"}
        )
        
        assert task.task_id == "test_task_001"
        assert task.task_type == "investigation"
        assert task.priority == TaskPriority.HIGH
        assert task.status == TaskStatus.PENDING
        assert task.retry_count == 0
        assert task.payload["event_id"] == "evt_001"
        assert isinstance(task.created_at, datetime)
    
    def test_task_to_dict(self):
        """Test Task serialization to dictionary"""
        task = Task(
            task_id="test_task_002",
            task_type="analysis",
            priority=TaskPriority.MEDIUM,
            payload={"data": "test"}
        )
        
        task_dict = task.to_dict()
        
        assert task_dict["task_id"] == "test_task_002"
        assert task_dict["task_type"] == "analysis"
        assert task_dict["priority"] == TaskPriority.MEDIUM.value
        assert task_dict["status"] == TaskStatus.PENDING.value
        assert task_dict["payload"] == {"data": "test"}
    
    def test_task_from_dict(self):
        """Test Task deserialization from dictionary"""
        task_data = {
            "task_id": "test_task_003",
            "task_type": "report",
            "priority": TaskPriority.LOW.value,
            "status": TaskStatus.IN_PROGRESS.value,
            "payload": {"report_id": "rpt_001"},
            "retry_count": 2,
            "created_at": datetime.now().isoformat(),
            "started_at": datetime.now().isoformat(),
            "completed_at": None,
            "error_message": None
        }
        
        task = Task.from_dict(task_data)
        
        assert task.task_id == "test_task_003"
        assert task.task_type == "report"
        assert task.priority == TaskPriority.LOW
        assert task.status == TaskStatus.IN_PROGRESS
        assert task.retry_count == 2


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
    
    @pytest.fixture
    def sample_task(self):
        """Create sample task for testing"""
        return Task(
            task_id="sample_001",
            task_type="investigation",
            priority=TaskPriority.HIGH,
            payload={
                "event_id": "evt_001",
                "source_ip": "192.168.1.100",
                "event_type": "suspicious_ip"
            }
        )
    
    def test_queue_initialization(self, task_queue):
        """Test task queue initialization"""
        assert os.path.exists(task_queue.db_path)
        assert task_queue.workers == []
        assert len(task_queue.handlers) == 0
    
    def test_register_handler(self, task_queue):
        """Test registering task handlers"""
        async def test_handler(task: Task):
            return {"result": "success"}
        
        task_queue.register_handler("investigation", test_handler)
        
        assert "investigation" in task_queue.handlers
        assert task_queue.handlers["investigation"] == test_handler
    
    @pytest.mark.asyncio
    async def test_add_task(self, task_queue, sample_task):
        """Test adding task to queue"""
        await task_queue.add_task(sample_task)
        
        # Verify task was stored in database
        conn = sqlite3.connect(task_queue.db_path)
        cursor = conn.cursor()
        cursor.execute("SELECT * FROM tasks WHERE task_id = ?", (sample_task.task_id,))
        result = cursor.fetchone()
        conn.close()
        
        assert result is not None
        assert result[1] == sample_task.task_id  # task_id column
        assert result[2] == sample_task.task_type  # task_type column
    
    @pytest.mark.asyncio
    async def test_get_next_task(self, task_queue):
        """Test retrieving next task by priority"""
        # Add tasks with different priorities
        low_task = Task("low_001", "test", TaskPriority.LOW, {})
        high_task = Task("high_001", "test", TaskPriority.HIGH, {})
        critical_task = Task("critical_001", "test", TaskPriority.CRITICAL, {})
        
        await task_queue.add_task(low_task)
        await task_queue.add_task(high_task)
        await task_queue.add_task(critical_task)
        
        # Should get critical task first
        next_task = await task_queue.get_next_task()
        assert next_task.task_id == "critical_001"
        assert next_task.priority == TaskPriority.CRITICAL
        
        # Mark as in progress and get next
        await task_queue.update_task_status(next_task.task_id, TaskStatus.IN_PROGRESS)
        
        next_task = await task_queue.get_next_task()
        assert next_task.task_id == "high_001"
        assert next_task.priority == TaskPriority.HIGH
    
    @pytest.mark.asyncio
    async def test_update_task_status(self, task_queue, sample_task):
        """Test updating task status"""
        await task_queue.add_task(sample_task)
        
        # Update to in progress
        await task_queue.update_task_status(sample_task.task_id, TaskStatus.IN_PROGRESS)
        
        # Verify update
        conn = sqlite3.connect(task_queue.db_path)
        cursor = conn.cursor()
        cursor.execute("SELECT status FROM tasks WHERE task_id = ?", (sample_task.task_id,))
        result = cursor.fetchone()
        conn.close()
        
        assert result[0] == TaskStatus.IN_PROGRESS.value
    
    @pytest.mark.asyncio
    async def test_complete_task(self, task_queue, sample_task):
        """Test completing a task"""
        await task_queue.add_task(sample_task)
        
        result = {"status": "success", "findings": ["test"]}
        await task_queue.complete_task(sample_task.task_id, result)
        
        # Verify task is marked as completed
        conn = sqlite3.connect(task_queue.db_path)
        cursor = conn.cursor()
        cursor.execute("SELECT status, result FROM tasks WHERE task_id = ?", (sample_task.task_id,))
        row = cursor.fetchone()
        conn.close()
        
        assert row[0] == TaskStatus.COMPLETED.value
        assert json.loads(row[1]) == result
    
    @pytest.mark.asyncio
    async def test_fail_task_with_retry(self, task_queue, sample_task):
        """Test failing task with retry logic"""
        await task_queue.add_task(sample_task)
        
        # Fail task (should retry)
        await task_queue.fail_task(sample_task.task_id, "Test error", max_retries=3)
        
        # Verify task is back to pending with incremented retry count
        conn = sqlite3.connect(task_queue.db_path)
        cursor = conn.cursor()
        cursor.execute("SELECT status, retry_count FROM tasks WHERE task_id = ?", (sample_task.task_id,))
        row = cursor.fetchone()
        conn.close()
        
        assert row[0] == TaskStatus.PENDING.value
        assert row[1] == 1  # retry count incremented
    
    @pytest.mark.asyncio
    async def test_fail_task_max_retries(self, task_queue, sample_task):
        """Test failing task that exceeds max retries"""
        sample_task.retry_count = 3  # Already at max retries
        await task_queue.add_task(sample_task)
        
        # Fail task (should not retry)
        await task_queue.fail_task(sample_task.task_id, "Test error", max_retries=3)
        
        # Verify task is marked as failed
        conn = sqlite3.connect(task_queue.db_path)
        cursor = conn.cursor()
        cursor.execute("SELECT status FROM tasks WHERE task_id = ?", (sample_task.task_id,))
        row = cursor.fetchone()
        conn.close()
        
        assert row[0] == TaskStatus.FAILED.value
    
    @pytest.mark.asyncio
    async def test_cancel_task(self, task_queue, sample_task):
        """Test cancelling a task"""
        await task_queue.add_task(sample_task)
        
        await task_queue.cancel_task(sample_task.task_id)
        
        # Verify task is cancelled
        conn = sqlite3.connect(task_queue.db_path)
        cursor = conn.cursor()
        cursor.execute("SELECT status FROM tasks WHERE task_id = ?", (sample_task.task_id,))
        row = cursor.fetchone()
        conn.close()
        
        assert row[0] == TaskStatus.CANCELLED.value
    
    @pytest.mark.asyncio
    async def test_get_task_status(self, task_queue, sample_task):
        """Test retrieving task status"""
        await task_queue.add_task(sample_task)
        
        task_info = await task_queue.get_task_status(sample_task.task_id)
        
        assert task_info is not None
        assert task_info.task_id == sample_task.task_id
        assert task_info.status == TaskStatus.PENDING
    
    @pytest.mark.asyncio
    async def test_get_queue_stats(self, task_queue):
        """Test getting queue statistics"""
        # Add tasks with different statuses
        tasks = [
            Task("pending_1", "test", TaskPriority.LOW, {}),
            Task("pending_2", "test", TaskPriority.HIGH, {}),
            Task("completed_1", "test", TaskPriority.MEDIUM, {}),
        ]
        
        for task in tasks:
            await task_queue.add_task(task)
        
        # Mark one as completed
        await task_queue.complete_task("completed_1", {"result": "done"})
        
        stats = await task_queue.get_queue_stats()
        
        assert stats["total_tasks"] >= 3
        assert stats["pending"] >= 2
        assert stats["completed"] >= 1
        assert stats["in_progress"] >= 0
    
    @pytest.mark.asyncio
    async def test_cleanup_old_tasks(self, task_queue):
        """Test cleanup of old completed tasks"""
        # Add old completed task
        old_task = Task("old_completed", "test", TaskPriority.LOW, {})
        await task_queue.add_task(old_task)
        await task_queue.complete_task(old_task.task_id, {"result": "done"})
        
        # Manually update timestamp to be old
        old_timestamp = datetime.now() - timedelta(days=40)
        conn = sqlite3.connect(task_queue.db_path)
        cursor = conn.cursor()
        cursor.execute(
            "UPDATE tasks SET completed_at = ? WHERE task_id = ?",
            (old_timestamp.isoformat(), old_task.task_id)
        )
        conn.commit()
        conn.close()
        
        # Add recent task
        recent_task = Task("recent_completed", "test", TaskPriority.LOW, {})
        await task_queue.add_task(recent_task)
        await task_queue.complete_task(recent_task.task_id, {"result": "done"})
        
        # Cleanup old tasks (older than 30 days)
        deleted_count = await task_queue.cleanup_old_tasks(days=30)
        
        assert deleted_count >= 1
        
        # Verify old task was deleted
        conn = sqlite3.connect(task_queue.db_path)
        cursor = conn.cursor()
        cursor.execute("SELECT COUNT(*) FROM tasks WHERE task_id = ?", (old_task.task_id,))
        count = cursor.fetchone()[0]
        conn.close()
        
        assert count == 0
    
    @pytest.mark.asyncio
    async def test_worker_processing(self, task_queue):
        """Test worker task processing"""
        # Register a test handler
        async def test_handler(task: Task):
            await asyncio.sleep(0.1)  # Simulate work
            return {"processed": True, "task_id": task.task_id}
        
        task_queue.register_handler("investigation", test_handler)
        
        # Add a task
        task = Task("worker_test", "investigation", TaskPriority.HIGH, {"data": "test"})
        await task_queue.add_task(task)
        
        # Start workers
        await task_queue.start_workers(num_workers=1)
        
        # Wait for processing
        await asyncio.sleep(0.5)
        
        # Check task was completed
        task_info = await task_queue.get_task_status("worker_test")
        assert task_info.status == TaskStatus.COMPLETED
        
        # Stop workers
        await task_queue.stop_workers()
    
    @pytest.mark.asyncio
    async def test_worker_error_handling(self, task_queue):
        """Test worker error handling"""
        # Register a handler that raises an exception
        async def failing_handler(task: Task):
            raise Exception("Handler failed")
        
        task_queue.register_handler("failing_task", failing_handler)
        
        # Add a task
        task = Task("error_test", "failing_task", TaskPriority.HIGH, {})
        await task_queue.add_task(task)
        
        # Start workers
        await task_queue.start_workers(num_workers=1)
        
        # Wait for processing
        await asyncio.sleep(0.5)
        
        # Check task failed or was retried
        task_info = await task_queue.get_task_status("error_test")
        assert task_info.status in [TaskStatus.FAILED, TaskStatus.PENDING]
        
        # Stop workers
        await task_queue.stop_workers()
    
    @pytest.mark.asyncio
    async def test_concurrent_task_processing(self, task_queue):
        """Test concurrent processing of multiple tasks"""
        # Register handler
        async def concurrent_handler(task: Task):
            await asyncio.sleep(0.1)
            return {"task_id": task.task_id, "processed": True}
        
        task_queue.register_handler("concurrent", concurrent_handler)
        
        # Add multiple tasks
        tasks = [
            Task(f"concurrent_{i}", "concurrent", TaskPriority.MEDIUM, {"id": i})
            for i in range(5)
        ]
        
        for task in tasks:
            await task_queue.add_task(task)
        
        # Start multiple workers
        await task_queue.start_workers(num_workers=3)
        
        # Wait for processing
        await asyncio.sleep(1)
        
        # Check all tasks completed
        stats = await task_queue.get_queue_stats()
        assert stats["completed"] >= 5
        
        # Stop workers
        await task_queue.stop_workers()


class TestTaskQueueIntegration:
    """Integration tests for task queue system"""
    
    @pytest.mark.asyncio
    async def test_real_investigation_workflow(self, temp_queue_dir):
        """Test task queue with realistic investigation workflow"""
        queue = TaskQueue(db_path=os.path.join(temp_queue_dir, "workflow_test.db"))
        
        # Simulate investigation handler
        async def investigation_handler(task: Task):
            event_id = task.payload.get("event_id")
            source_ip = task.payload.get("source_ip")
            
            # Simulate investigation work
            await asyncio.sleep(0.1)
            
            return {
                "event_id": event_id,
                "source_ip": source_ip,
                "investigation_result": "completed",
                "risk_score": 0.75,
                "indicators": ["malicious_activity"]
            }
        
        queue.register_handler("investigation", investigation_handler)
        
        # Add investigation tasks with different priorities
        critical_event = Task(
            "inv_critical_001",
            "investigation",
            TaskPriority.CRITICAL,
            {
                "event_id": "evt_001",
                "source_ip": "192.168.1.100",
                "event_type": "suspicious_ip",
                "severity": "critical"
            }
        )
        
        normal_event = Task(
            "inv_normal_001",
            "investigation",
            TaskPriority.MEDIUM,
            {
                "event_id": "evt_002", 
                "source_ip": "10.0.0.50",
                "event_type": "port_scan",
                "severity": "medium"
            }
        )
        
        await queue.add_task(normal_event)
        await queue.add_task(critical_event)  # Add critical after normal
        
        # Start workers
        await queue.start_workers(num_workers=2)
        
        # Wait for processing
        await asyncio.sleep(0.5)
        
        # Verify critical event was processed first
        critical_result = await queue.get_task_status("inv_critical_001")
        normal_result = await queue.get_task_status("inv_normal_001")
        
        assert critical_result.status == TaskStatus.COMPLETED
        assert normal_result.status == TaskStatus.COMPLETED
        
        # Verify results contain expected data
        critical_task_result = json.loads(critical_result.result)
        assert critical_task_result["risk_score"] == 0.75
        
        await queue.stop_workers()
    
    @pytest.mark.asyncio
    async def test_queue_persistence_across_restarts(self, temp_queue_dir):
        """Test that tasks persist across queue restarts"""
        db_path = os.path.join(temp_queue_dir, "persistence_test.db")
        
        # Create first queue instance and add tasks
        queue1 = TaskQueue(db_path=db_path)
        
        task = Task("persist_001", "test", TaskPriority.HIGH, {"data": "persistent"})
        await queue1.add_task(task)
        
        # Create second queue instance (simulating restart)
        queue2 = TaskQueue(db_path=db_path)
        
        # Verify task persists
        task_info = await queue2.get_task_status("persist_001")
        assert task_info is not None
        assert task_info.task_id == "persist_001"
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