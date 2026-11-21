"""
Audit trail routes: investigation logs, timelines, exports, health metrics,
search and hash-chain integrity verification. All queries go through
ActionLogger methods; no raw SQL here.
"""

from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel

from agent import SOCAgentPlanner
from agent.action_logger import ActionLog, ActionLogger

from ..deps import get_current_user, get_soc_agent

router = APIRouter(dependencies=[Depends(get_current_user)], prefix="/audit", tags=["audit"])


class ActionLogResponse(BaseModel):
    id: str
    timestamp: str
    investigation_id: Optional[str]
    action_type: str
    status: str
    level: str
    component: str
    description: str
    details: Dict[str, Any]
    duration_ms: Optional[int]
    error_message: Optional[str]
    correlation_id: Optional[str]


class ComponentPerformanceResponse(BaseModel):
    component: str
    time_window_hours: int
    total_actions: int
    successful_actions: int
    success_rate: float
    average_duration_ms: float
    error_count: int
    recent_errors: Dict[str, int]


class SystemHealthResponse(BaseModel):
    time_window_hours: int
    total_actions: int
    success_rate: float
    error_rate: float
    average_duration_ms: float
    investigations_processed: int
    component_activity: Dict[str, int]
    top_errors: Dict[str, int]
    health_status: str


class InvestigationTimelineResponse(BaseModel):
    investigation_id: str
    timeline: List[Dict[str, Any]]
    total_actions: int
    duration_seconds: float
    start_time: str
    end_time: str


class AuditTrailResponse(BaseModel):
    investigation_id: str
    start_time: str
    end_time: str
    total_duration_seconds: float
    total_actions: int
    error_count: int
    action_breakdown: Dict[str, int]
    timeline: List[Dict[str, Any]]
    export_timestamp: str


def get_action_logger(agent: SOCAgentPlanner = Depends(get_soc_agent)) -> ActionLogger:
    return agent.action_logger


def _to_response(log: ActionLog) -> ActionLogResponse:
    return ActionLogResponse(
        id=log.id, timestamp=log.timestamp.isoformat(), investigation_id=log.investigation_id,
        action_type=log.action_type.value, status=log.status.value, level=log.level.value,
        component=log.component, description=log.description, details=log.details,
        duration_ms=log.duration_ms, error_message=log.error_message, correlation_id=log.correlation_id,
    )


@router.get("/integrity")
async def verify_audit_integrity(logger: ActionLogger = Depends(get_action_logger)):
    """Recompute the SHA-256 hash chain over every audit entry."""
    return logger.verify_integrity()


@router.get("/investigations/{investigation_id}/logs", response_model=List[ActionLogResponse])
async def get_investigation_logs(investigation_id: str, logger: ActionLogger = Depends(get_action_logger)):
    logs = logger.get_investigation_logs(investigation_id)
    if not logs:
        raise HTTPException(status_code=404, detail="No logs found for this investigation")
    return [_to_response(log) for log in logs]


@router.get("/investigations/{investigation_id}/timeline", response_model=InvestigationTimelineResponse)
async def get_investigation_timeline(investigation_id: str, logger: ActionLogger = Depends(get_action_logger)):
    logs = logger.get_investigation_logs(investigation_id)
    if not logs:
        raise HTTPException(status_code=404, detail="No timeline found for this investigation")
    timeline = logger.get_investigation_timeline(investigation_id)
    start, end = logs[0].timestamp, logs[-1].timestamp
    return InvestigationTimelineResponse(
        investigation_id=investigation_id, timeline=timeline, total_actions=len(timeline),
        duration_seconds=(end - start).total_seconds(), start_time=start.isoformat(), end_time=end.isoformat(),
    )


@router.get("/investigations/{investigation_id}/export", response_model=AuditTrailResponse)
async def export_investigation_audit_trail(investigation_id: str, logger: ActionLogger = Depends(get_action_logger)):
    audit_trail = logger.export_audit_trail(investigation_id)
    if not audit_trail:
        raise HTTPException(status_code=404, detail="No audit trail found for this investigation")
    return AuditTrailResponse(**audit_trail)


@router.get("/components/{component}/performance", response_model=ComponentPerformanceResponse)
async def get_component_performance(component: str, hours: int = Query(24, ge=1, le=168),
                                    logger: ActionLogger = Depends(get_action_logger)):
    return ComponentPerformanceResponse(**logger.get_component_performance(component, hours))


@router.get("/system/health", response_model=SystemHealthResponse)
async def get_system_health(hours: int = Query(1, ge=1, le=168), logger: ActionLogger = Depends(get_action_logger)):
    return SystemHealthResponse(**logger.get_system_health(hours))


@router.get("/logs/search", response_model=List[ActionLogResponse])
async def search_action_logs(
    investigation_id: Optional[str] = Query(None),
    component: Optional[str] = Query(None),
    action_type: Optional[str] = Query(None),
    level: Optional[str] = Query(None),
    since_hours: int = Query(24, ge=1, le=168),
    limit: int = Query(100, ge=1, le=1000),
    logger: ActionLogger = Depends(get_action_logger),
):
    logs = logger.search_logs(investigation_id=investigation_id, component=component, action_type=action_type,
                              level=level, since_hours=since_hours, limit=limit)
    return [_to_response(log) for log in logs]


@router.delete("/logs/cleanup")
async def cleanup_old_logs(days: int = Query(90, ge=7, le=365), logger: ActionLogger = Depends(get_action_logger)):
    deleted = logger.cleanup_old_logs(days)
    return {"message": f"Cleaned up {deleted} old action logs", "integrity": logger.verify_integrity()["valid"]}


@router.get("/components/", response_model=List[Dict[str, Any]])
async def list_active_components(hours: int = Query(24, ge=1, le=168),
                                 logger: ActionLogger = Depends(get_action_logger)):
    return logger.get_active_components(hours)


@router.get("/statistics/overview")
async def get_audit_overview(logger: ActionLogger = Depends(get_action_logger)):
    overview = logger.get_overview(24)
    integrity = logger.verify_integrity()
    overview["integrity"] = {"valid": integrity["valid"], "total_entries": integrity["total_entries"],
                             "broken_links": len(integrity["broken_links"])}
    overview["generated_at"] = datetime.now(timezone.utc).isoformat()
    return overview
