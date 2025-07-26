"""
FastAPI routes for task queue management and monitoring.

Provides endpoints for:
- Task creation and management
- Queue monitoring and statistics
- Task status tracking
- Worker health monitoring
"""

from datetime import datetime
from typing import Dict, List, Optional

from fastapi import APIRouter, HTTPException, Depends
from pydantic import BaseModel

from ..main import get_soc_agent
from agent.task_queue import TaskQueue, TaskPriority, TaskStatus
from agent.planner import SOCAgentPlanner

router = APIRouter(prefix="/tasks", tags=["tasks"])

# Pydantic models for request/response
class TaskCreateRequest(BaseModel):
    task_type: str
    payload: Dict
    priority: str = "medium"  # low, medium, high, critical, emergency
    max_retries: int = 3
    timeout_seconds: int = 300

class TaskResponse(BaseModel):
    id: str
    task_type: str
    priority: str
    status: str
    created_at: str
    started_at: Optional[str] = None
    completed_at: Optional[str] = None
    retry_count: int
    max_retries: int
    error_message: Optional[str] = None
    result: Optional[Dict] = None
    timeout_seconds: int

class QueueStatsResponse(BaseModel):
    status_counts: Dict[str, int]
    pending_tasks: int
    active_tasks: int
    task_type_counts: Dict[str, int]
    max_workers: int
    workers_running: int

# Global task queue instance
task_queue: Optional[TaskQueue] = None

def get_task_queue() -> TaskQueue:
    """Get or create the global task queue instance."""
    global task_queue
    if task_queue is None:
        task_queue = TaskQueue(max_workers=5)
        
        # Register investigation handler
        async def investigation_handler(payload: Dict):
            from backend.routes.investigations import run_investigation_task
            return await run_investigation_task(payload)
        
        task_queue.register_handler("investigation", investigation_handler)
        
        # Start the workers (this should be done in app startup)
        import asyncio
        try:
            loop = asyncio.get_running_loop()
            loop.create_task(task_queue.start())
        except:
            pass  # Workers will be started manually
    
    return task_queue

@router.post("/", response_model=TaskResponse)
async def create_task(request: TaskCreateRequest):
    """Create a new task in the queue."""
    queue = get_task_queue()
    
    # Convert priority string to enum
    priority_map = {
        "low": TaskPriority.LOW,
        "medium": TaskPriority.MEDIUM, 
        "high": TaskPriority.HIGH,
        "critical": TaskPriority.CRITICAL,
        "emergency": TaskPriority.EMERGENCY
    }
    
    if request.priority.lower() not in priority_map:
        raise HTTPException(status_code=400, detail="Invalid priority level")
    
    priority = priority_map[request.priority.lower()]
    
    try:
        task_id = await queue.add_task(
            task_type=request.task_type,
            payload=request.payload,
            priority=priority,
            max_retries=request.max_retries,
            timeout_seconds=request.timeout_seconds
        )
        
        # Get the created task details
        task = await queue.get_task_status(task_id)
        if not task:
            raise HTTPException(status_code=500, detail="Failed to retrieve created task")
        
        return TaskResponse(
            id=task.id,
            task_type=task.task_type,
            priority=task.priority.name.lower(),
            status=task.status.value,
            created_at=task.created_at.isoformat(),
            started_at=task.started_at.isoformat() if task.started_at else None,
            completed_at=task.completed_at.isoformat() if task.completed_at else None,
            retry_count=task.retry_count,
            max_retries=task.max_retries,
            error_message=task.error_message,
            result=task.result,
            timeout_seconds=task.timeout_seconds
        )
        
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to create task: {str(e)}")

@router.get("/{task_id}", response_model=TaskResponse)
async def get_task_status(task_id: str):
    """Get the status of a specific task."""
    queue = get_task_queue()
    
    task = await queue.get_task_status(task_id)
    if not task:
        raise HTTPException(status_code=404, detail="Task not found")
    
    return TaskResponse(
        id=task.id,
        task_type=task.task_type,
        priority=task.priority.name.lower(),
        status=task.status.value,
        created_at=task.created_at.isoformat(),
        started_at=task.started_at.isoformat() if task.started_at else None,
        completed_at=task.completed_at.isoformat() if task.completed_at else None,
        retry_count=task.retry_count,
        max_retries=task.max_retries,
        error_message=task.error_message,
        result=task.result,
        timeout_seconds=task.timeout_seconds
    )

@router.delete("/{task_id}")
async def cancel_task(task_id: str):
    """Cancel a pending or in-progress task."""
    queue = get_task_queue()
    
    success = await queue.cancel_task(task_id)
    if not success:
        raise HTTPException(status_code=404, detail="Task not found or cannot be cancelled")
    
    return {"message": f"Task {task_id} cancelled successfully"}

@router.get("/", response_model=QueueStatsResponse)
async def get_queue_stats():
    """Get current queue statistics and status."""
    queue = get_task_queue()
    
    stats = await queue.get_queue_stats()
    
    return QueueStatsResponse(
        status_counts=stats['status_counts'],
        pending_tasks=stats['pending_tasks'],
        active_tasks=stats['active_tasks'],
        task_type_counts=stats['task_type_counts'],
        max_workers=stats['max_workers'],
        workers_running=stats['workers_running']
    )

@router.post("/queue/start")
async def start_queue():
    """Start the task queue workers."""
    queue = get_task_queue()
    
    try:
        await queue.start()
        return {"message": "Task queue workers started successfully"}
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to start queue: {str(e)}")

@router.post("/queue/stop")
async def stop_queue():
    """Stop the task queue workers gracefully."""
    queue = get_task_queue()
    
    try:
        await queue.stop()
        return {"message": "Task queue workers stopped successfully"}
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to stop queue: {str(e)}")

@router.post("/queue/cleanup")
async def cleanup_old_tasks(days: int = 30):
    """Clean up completed/failed tasks older than specified days."""
    queue = get_task_queue()
    
    try:
        deleted_count = await queue.cleanup_old_tasks(days)
        return {"message": f"Cleaned up {deleted_count} old tasks"}
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to cleanup tasks: {str(e)}")

@router.post("/investigations/", response_model=TaskResponse)
async def create_investigation_task(
    request: TaskCreateRequest,
    agent: SOCAgentPlanner = Depends(get_soc_agent)
):
    """Create a new investigation task (convenience endpoint)."""
    # Override task type for investigations
    request.task_type = "investigation"
    return await create_task(request) 