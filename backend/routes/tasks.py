"""
Task queue management routes. The queue itself is created, started and
stopped by the application lifespan (see backend.main).
"""

from typing import Any, Dict, List, Optional

from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel, Field

from agent.task_queue import Task, TaskPriority, TaskQueue, TaskStatus

from ..deps import get_current_user, get_task_queue

router = APIRouter(dependencies=[Depends(get_current_user)], prefix="/tasks", tags=["tasks"])

PRIORITY_MAP = {
    "low": TaskPriority.LOW,
    "medium": TaskPriority.MEDIUM,
    "high": TaskPriority.HIGH,
    "critical": TaskPriority.CRITICAL,
    "emergency": TaskPriority.EMERGENCY,
}


class TaskCreateRequest(BaseModel):
    task_type: str = Field(default="investigation", pattern=r"^[a-z_]{1,64}$")
    payload: Dict[str, Any]
    priority: str = "medium"
    max_retries: int = Field(default=3, ge=1, le=10)
    timeout_seconds: int = Field(default=300, ge=1, le=3600)


class TaskResponse(BaseModel):
    id: str
    task_type: str
    priority: str
    status: str
    created_at: str
    started_at: Optional[str] = None
    completed_at: Optional[str] = None
    next_retry_at: Optional[str] = None
    retry_count: int
    max_retries: int
    error_message: Optional[str] = None
    result: Optional[Any] = None
    timeout_seconds: int


class QueueStatsResponse(BaseModel):
    status_counts: Dict[str, int]
    pending_tasks: int
    active_tasks: int
    task_type_counts: Dict[str, int]
    max_workers: int
    workers_running: int


def _to_response(task: Task) -> TaskResponse:
    return TaskResponse(
        id=task.id,
        task_type=task.task_type,
        priority=task.priority.name.lower(),
        status=task.status.value,
        created_at=task.created_at.isoformat(),
        started_at=task.started_at.isoformat() if task.started_at else None,
        completed_at=task.completed_at.isoformat() if task.completed_at else None,
        next_retry_at=task.next_retry_at.isoformat() if task.next_retry_at else None,
        retry_count=task.retry_count,
        max_retries=task.max_retries,
        error_message=task.error_message,
        result=task.result,
        timeout_seconds=task.timeout_seconds,
    )


async def _enqueue(request: TaskCreateRequest, queue: TaskQueue) -> TaskResponse:
    priority = PRIORITY_MAP.get(request.priority.lower())
    if priority is None:
        raise HTTPException(status_code=400, detail="Invalid priority level")
    if request.task_type not in queue.task_handlers:
        raise HTTPException(status_code=400, detail=f"No handler registered for task type '{request.task_type}'")
    if request.task_type == "investigation":
        event = request.payload.get("event_data")
        if not isinstance(event, dict) or "event_type" not in event:
            raise HTTPException(status_code=422, detail="investigation payload needs event_data.event_type")
    task_id = await queue.add_task(task_type=request.task_type, payload=request.payload, priority=priority,
                                   max_retries=request.max_retries, timeout_seconds=request.timeout_seconds)
    task = await queue.get_task_status(task_id)
    if not task:
        raise HTTPException(status_code=500, detail="Failed to retrieve created task")
    return _to_response(task)


@router.post("/", response_model=TaskResponse)
async def create_task(request: TaskCreateRequest, queue: TaskQueue = Depends(get_task_queue)):
    return await _enqueue(request, queue)


@router.get("/", response_model=QueueStatsResponse)
async def get_queue_stats(queue: TaskQueue = Depends(get_task_queue)):
    return QueueStatsResponse(**(await queue.get_queue_stats()))


@router.post("/investigations/", response_model=TaskResponse)
async def create_investigation_task(request: TaskCreateRequest, queue: TaskQueue = Depends(get_task_queue)):
    """Convenience endpoint: enqueue an investigation."""
    return await _enqueue(request.model_copy(update={"task_type": "investigation"}), queue)


@router.post("/queue/start")
async def start_queue(queue: TaskQueue = Depends(get_task_queue)):
    await queue.start()
    return {"message": "Task queue workers running", "workers_running": len(queue.workers)}


@router.post("/queue/stop")
async def stop_queue(queue: TaskQueue = Depends(get_task_queue)):
    await queue.stop()
    return {"message": "Task queue workers stopped"}


@router.post("/queue/cleanup")
async def cleanup_old_tasks(days: int = Query(30, ge=1, le=3650), queue: TaskQueue = Depends(get_task_queue)):
    deleted = await queue.cleanup_old_tasks(days)
    return {"message": f"Cleaned up {deleted} old tasks"}


class TaskListResponse(BaseModel):
    tasks: List[TaskResponse]
    total_count: int


# Registered before /{task_id} so "items" is never read as a task id
@router.get("/items", response_model=TaskListResponse)
async def list_tasks(status: Optional[str] = Query(None), limit: int = Query(50, ge=1, le=200),
                     queue: TaskQueue = Depends(get_task_queue)):
    if status is not None and status not in {s.value for s in TaskStatus}:
        raise HTTPException(status_code=400, detail="Invalid task status")
    tasks = await queue.list_tasks(status=status, limit=limit)
    return TaskListResponse(tasks=[_to_response(t) for t in tasks], total_count=await queue.count_tasks(status))


@router.get("/{task_id}", response_model=TaskResponse)
async def get_task_status(task_id: str, queue: TaskQueue = Depends(get_task_queue)):
    task = await queue.get_task_status(task_id)
    if not task:
        raise HTTPException(status_code=404, detail="Task not found")
    return _to_response(task)


@router.delete("/{task_id}")
async def cancel_task(task_id: str, queue: TaskQueue = Depends(get_task_queue)):
    if not await queue.cancel_task(task_id):
        raise HTTPException(status_code=404, detail="Task not found or cannot be cancelled")
    return {"message": f"Task {task_id} cancelled successfully"}
