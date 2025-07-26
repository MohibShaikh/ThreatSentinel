"""
FastAPI routes for action logging and audit trail management.

Provides endpoints for:
- Retrieving investigation audit trails
- System health and performance monitoring
- Component performance analysis
- Action log querying and filtering
"""

from datetime import datetime, timedelta
from typing import Dict, List, Optional

from fastapi import APIRouter, HTTPException, Query
from pydantic import BaseModel

from agent.action_logger import ActionLogger, ActionType, LogLevel

router = APIRouter(prefix="/audit", tags=["audit"])

# Pydantic models for responses
class ActionLogResponse(BaseModel):
    id: str
    timestamp: str
    investigation_id: Optional[str]
    action_type: str
    status: str
    level: str
    component: str
    description: str
    details: Dict
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
    timeline: List[Dict]
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
    timeline: List[Dict]
    export_timestamp: str

# Global action logger instance
action_logger: Optional[ActionLogger] = None

def get_action_logger() -> ActionLogger:
    """Get or create the global action logger instance."""
    global action_logger
    if action_logger is None:
        action_logger = ActionLogger()
    return action_logger

@router.get("/investigations/{investigation_id}/logs", response_model=List[ActionLogResponse])
async def get_investigation_logs(investigation_id: str):
    """Get all action logs for a specific investigation."""
    logger = get_action_logger()
    
    logs = logger.get_investigation_logs(investigation_id)
    
    if not logs:
        raise HTTPException(status_code=404, detail="No logs found for this investigation")
    
    return [
        ActionLogResponse(
            id=log.id,
            timestamp=log.timestamp.isoformat(),
            investigation_id=log.investigation_id,
            action_type=log.action_type.value,
            status=log.status.value,
            level=log.level.value,
            component=log.component,
            description=log.description,
            details=log.details,
            duration_ms=log.duration_ms,
            error_message=log.error_message,
            correlation_id=log.correlation_id
        )
        for log in logs
    ]

@router.get("/investigations/{investigation_id}/timeline", response_model=InvestigationTimelineResponse)
async def get_investigation_timeline(investigation_id: str):
    """Get a timeline view of an investigation."""
    logger = get_action_logger()
    
    timeline = logger.get_investigation_timeline(investigation_id)
    logs = logger.get_investigation_logs(investigation_id)
    
    if not timeline:
        raise HTTPException(status_code=404, detail="No timeline found for this investigation")
    
    start_time = logs[0].timestamp if logs else datetime.now()
    end_time = logs[-1].timestamp if logs else datetime.now()
    duration = (end_time - start_time).total_seconds()
    
    return InvestigationTimelineResponse(
        investigation_id=investigation_id,
        timeline=timeline,
        total_actions=len(timeline),
        duration_seconds=duration,
        start_time=start_time.isoformat(),
        end_time=end_time.isoformat()
    )

@router.get("/investigations/{investigation_id}/export", response_model=AuditTrailResponse)
async def export_investigation_audit_trail(investigation_id: str):
    """Export complete audit trail for an investigation."""
    logger = get_action_logger()
    
    audit_trail = logger.export_audit_trail(investigation_id)
    
    if not audit_trail:
        raise HTTPException(status_code=404, detail="No audit trail found for this investigation")
    
    return AuditTrailResponse(**audit_trail)

@router.get("/components/{component}/performance", response_model=ComponentPerformanceResponse)
async def get_component_performance(
    component: str,
    hours: int = Query(24, description="Time window in hours", ge=1, le=168)
):
    """Get performance metrics for a specific component."""
    logger = get_action_logger()
    
    performance = logger.get_component_performance(component, hours)
    
    return ComponentPerformanceResponse(**performance)

@router.get("/system/health", response_model=SystemHealthResponse)
async def get_system_health(
    hours: int = Query(1, description="Time window in hours", ge=1, le=168)
):
    """Get overall system health metrics."""
    logger = get_action_logger()
    
    health = logger.get_system_health(hours)
    
    return SystemHealthResponse(**health)

@router.get("/logs/search", response_model=List[ActionLogResponse])
async def search_action_logs(
    investigation_id: Optional[str] = Query(None, description="Filter by investigation ID"),
    component: Optional[str] = Query(None, description="Filter by component name"),
    action_type: Optional[str] = Query(None, description="Filter by action type"),
    level: Optional[str] = Query(None, description="Filter by log level"),
    since_hours: int = Query(24, description="Look back this many hours", ge=1, le=168),
    limit: int = Query(100, description="Maximum number of results", ge=1, le=1000)
):
    """Search and filter action logs with various criteria."""
    logger = get_action_logger()
    
    # Build query - this is a simplified version
    # In a real implementation, you'd add proper filtering to the ActionLogger class
    since = datetime.now() - timedelta(hours=since_hours)
    
    # For now, get recent logs and filter in Python (not efficient for large datasets)
    import sqlite3
    
    query = """
        SELECT * FROM action_logs 
        WHERE timestamp > ?
    """
    params = [since.isoformat()]
    
    if investigation_id:
        query += " AND investigation_id = ?"
        params.append(investigation_id)
    
    if component:
        query += " AND component = ?"
        params.append(component)
    
    if action_type:
        query += " AND action_type = ?"
        params.append(action_type)
    
    if level:
        query += " AND level = ?"
        params.append(level)
    
    query += " ORDER BY timestamp DESC LIMIT ?"
    params.append(limit)
    
    results = []
    try:
        with sqlite3.connect(logger.db_path) as conn:
            cursor = conn.execute(query, params)
            
            for row in cursor.fetchall():
                columns = [desc[0] for desc in cursor.description]
                log_data = dict(zip(columns, row))
                
                # Convert to ActionLog and then to response
                action_log = logger.__class__.ActionLog.from_dict(log_data)
                results.append(ActionLogResponse(
                    id=action_log.id,
                    timestamp=action_log.timestamp.isoformat(),
                    investigation_id=action_log.investigation_id,
                    action_type=action_log.action_type.value,
                    status=action_log.status.value,
                    level=action_log.level.value,
                    component=action_log.component,
                    description=action_log.description,
                    details=action_log.details,
                    duration_ms=action_log.duration_ms,
                    error_message=action_log.error_message,
                    correlation_id=action_log.correlation_id
                ))
                
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to search logs: {str(e)}")
    
    return results

@router.delete("/logs/cleanup")
async def cleanup_old_logs(
    days: int = Query(90, description="Delete logs older than this many days", ge=7, le=365)
):
    """Clean up old action logs."""
    logger = get_action_logger()
    
    try:
        deleted_count = logger.cleanup_old_logs(days)
        return {"message": f"Cleaned up {deleted_count} old action logs"}
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to cleanup logs: {str(e)}")

@router.get("/components/", response_model=List[Dict])
async def list_active_components():
    """List all components that have logged actions recently."""
    logger = get_action_logger()
    
    since = datetime.now() - timedelta(hours=24)
    
    try:
        with sqlite3.connect(logger.db_path) as conn:
            cursor = conn.execute("""
                SELECT 
                    component,
                    COUNT(*) as action_count,
                    MAX(timestamp) as last_activity,
                    SUM(CASE WHEN level = 'error' THEN 1 ELSE 0 END) as error_count
                FROM action_logs 
                WHERE timestamp > ?
                GROUP BY component
                ORDER BY action_count DESC
            """, (since.isoformat(),))
            
            components = []
            for row in cursor.fetchall():
                components.append({
                    'component': row[0],
                    'action_count': row[1],
                    'last_activity': row[2],
                    'error_count': row[3]
                })
            
            return components
            
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to list components: {str(e)}")

@router.get("/statistics/overview")
async def get_audit_overview():
    """Get high-level audit and logging statistics."""
    logger = get_action_logger()
    
    try:
        with sqlite3.connect(logger.db_path) as conn:
            # Total investigations
            cursor = conn.execute("""
                SELECT COUNT(DISTINCT investigation_id) 
                FROM action_logs 
                WHERE investigation_id IS NOT NULL
            """)
            total_investigations = cursor.fetchone()[0]
            
            # Total actions
            cursor = conn.execute("SELECT COUNT(*) FROM action_logs")
            total_actions = cursor.fetchone()[0]
            
            # Recent activity (last 24 hours)
            since = datetime.now() - timedelta(hours=24)
            cursor = conn.execute("""
                SELECT COUNT(*) FROM action_logs 
                WHERE timestamp > ?
            """, (since.isoformat(),))
            recent_actions = cursor.fetchone()[0]
            
            # Error rate (last 24 hours)
            cursor = conn.execute("""
                SELECT COUNT(*) FROM action_logs 
                WHERE timestamp > ? AND level = 'error'
            """, (since.isoformat(),))
            recent_errors = cursor.fetchone()[0]
            
            # Most active components
            cursor = conn.execute("""
                SELECT component, COUNT(*) as count 
                FROM action_logs 
                WHERE timestamp > ?
                GROUP BY component
                ORDER BY count DESC
                LIMIT 5
            """, (since.isoformat(),))
            top_components = dict(cursor.fetchall())
            
            error_rate = (recent_errors / recent_actions * 100) if recent_actions > 0 else 0
            
            return {
                'total_investigations_tracked': total_investigations,
                'total_actions_logged': total_actions,
                'recent_actions_24h': recent_actions,
                'recent_errors_24h': recent_errors,
                'error_rate_24h': round(error_rate, 2),
                'top_components_24h': top_components,
                'audit_health': 'healthy' if error_rate < 5 else 'degraded' if error_rate < 20 else 'unhealthy'
            }
            
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to get audit overview: {str(e)}") 