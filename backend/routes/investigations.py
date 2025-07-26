"""
ThreatSentinel SOC Agent - Investigation Routes

API routes for managing security incident investigations.
"""

import asyncio
import logging
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Any

from fastapi import APIRouter, HTTPException, Depends, Query, BackgroundTasks, status
from fastapi.responses import JSONResponse

from ..models import (
    InvestigationRequest,
    InvestigationResponse, 
    InvestigationStatus,
    BulkInvestigationRequest,
    BulkInvestigationResponse,
    SearchRequest,
    SearchResponse,
    ErrorResponse
)
from ..config import get_settings
from ...agent import SOCAgentPlanner


# Create router
router = APIRouter()

# Global storage for investigations (in production, use proper database)
active_investigations: Dict[str, Any] = {}
investigation_history: List[Dict[str, Any]] = []

logger = logging.getLogger(__name__)


def get_soc_agent() -> SOCAgentPlanner:
    """Dependency to get SOC agent instance"""
    # This would be injected from main.py in practice
    from ..main import soc_agent
    if soc_agent is None:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="SOC Agent not initialized"
        )
    return soc_agent


@router.post("/", response_model=InvestigationResponse, status_code=status.HTTP_201_CREATED)
async def create_investigation(
    request: InvestigationRequest,
    background_tasks: BackgroundTasks,
    agent: SOCAgentPlanner = Depends(get_soc_agent)
):
    """
    Create a new security incident investigation
    
    Submits a security event for autonomous investigation by the SOC Agent.
    The investigation runs asynchronously and results can be retrieved using
    the returned investigation ID.
    """
    try:
        # Generate unique investigation ID
        investigation_id = f"inv_{datetime.utcnow().strftime('%Y%m%d_%H%M%S')}_{hash(str(request.event_data)) % 10000}"
        
        # Estimate completion time based on emergency mode
        completion_minutes = 2 if request.emergency_mode else 5
        estimated_completion = datetime.utcnow() + timedelta(minutes=completion_minutes)
        
        # Store investigation request
        investigation_record = {
            'id': investigation_id,
            'status': 'pending',
            'created_at': datetime.utcnow(),
            'request': request.dict(),
            'estimated_completion': estimated_completion,
            'progress': 0,
            'current_phase': 'queued'
        }
        
        active_investigations[investigation_id] = investigation_record
        
        # Start investigation in background
        background_tasks.add_task(
            run_investigation_task,
            investigation_id,
            request.event_data,
            request.emergency_mode
        )
        
        logger.info(f"Created investigation {investigation_id}")
        
        return InvestigationResponse(
            investigation_id=investigation_id,
            status="created",
            message="Investigation created and queued for processing",
            estimated_completion_time=estimated_completion,
            priority="emergency" if request.emergency_mode else "normal"
        )
        
    except Exception as e:
        logger.error(f"Failed to create investigation: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to create investigation: {str(e)}"
        )


@router.get("/{investigation_id}", response_model=InvestigationStatus)
async def get_investigation_status(investigation_id: str):
    """
    Get the current status of an investigation
    
    Returns detailed status information including current phase,
    progress percentage, and preliminary findings.
    """
    if investigation_id not in active_investigations:
        # Check if it's in history
        historical = next(
            (inv for inv in investigation_history if inv['id'] == investigation_id),
            None
        )
        if historical:
            return InvestigationStatus(
                investigation_id=investigation_id,
                status=historical['status'],
                start_time=historical['created_at'],
                current_phase='completed',
                progress_percentage=100,
                estimated_time_remaining=0,
                preliminary_risk_level=historical.get('risk_level', 'unknown')
            )
        
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Investigation {investigation_id} not found"
        )
    
    investigation = active_investigations[investigation_id]
    
    # Calculate estimated time remaining
    if investigation['status'] in ['completed', 'failed']:
        time_remaining = 0
    else:
        elapsed = (datetime.utcnow() - investigation['created_at']).total_seconds()
        estimated_total = 300 if not investigation['request'].get('emergency_mode') else 120
        time_remaining = max(0, estimated_total - elapsed)
    
    return InvestigationStatus(
        investigation_id=investigation_id,
        status=investigation['status'],
        start_time=investigation['created_at'],
        current_phase=investigation.get('current_phase', 'unknown'),
        progress_percentage=investigation.get('progress', 0),
        estimated_time_remaining=int(time_remaining),
        preliminary_risk_level=investigation.get('preliminary_risk_level', 'unknown')
    )


@router.get("/{investigation_id}/result")
async def get_investigation_result(investigation_id: str):
    """
    Get the complete result of a finished investigation
    
    Returns the full investigation report including risk assessment,
    threat intelligence findings, and recommended actions.
    """
    # Check active investigations first
    if investigation_id in active_investigations:
        investigation = active_investigations[investigation_id]
        if investigation['status'] != 'completed':
            raise HTTPException(
                status_code=status.HTTP_409_CONFLICT,
                detail=f"Investigation not completed. Current status: {investigation['status']}"
            )
        return investigation.get('result', {})
    
    # Check historical investigations
    historical = next(
        (inv for inv in investigation_history if inv['id'] == investigation_id),
        None
    )
    if historical:
        return historical.get('result', {})
    
    raise HTTPException(
        status_code=status.HTTP_404_NOT_FOUND,
        detail=f"Investigation {investigation_id} not found"
    )


@router.delete("/{investigation_id}")
async def cancel_investigation(investigation_id: str):
    """
    Cancel an ongoing investigation
    
    Cancels an investigation that is currently running or queued.
    Completed investigations cannot be cancelled.
    """
    if investigation_id not in active_investigations:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Investigation {investigation_id} not found"
        )
    
    investigation = active_investigations[investigation_id]
    
    if investigation['status'] in ['completed', 'failed']:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail=f"Cannot cancel investigation with status: {investigation['status']}"
        )
    
    # Mark as cancelled
    investigation['status'] = 'cancelled'
    investigation['cancelled_at'] = datetime.utcnow()
    investigation['current_phase'] = 'cancelled'
    
    logger.info(f"Cancelled investigation {investigation_id}")
    
    return {"message": f"Investigation {investigation_id} cancelled successfully"}


@router.post("/bulk", response_model=BulkInvestigationResponse)
async def create_bulk_investigations(
    request: BulkInvestigationRequest,
    background_tasks: BackgroundTasks,
    agent: SOCAgentPlanner = Depends(get_soc_agent)
):
    """
    Create multiple investigations from a batch of events
    
    Efficiently processes multiple security events in parallel,
    with optional batch tracking and emergency mode support.
    """
    try:
        # Generate batch ID if not provided
        batch_id = request.batch_id or f"batch_{datetime.utcnow().strftime('%Y%m%d_%H%M%S')}"
        
        investigation_ids = []
        
        # Create investigations for each event
        for i, event_data in enumerate(request.events):
            investigation_id = f"inv_{datetime.utcnow().strftime('%Y%m%d_%H%M%S')}_{i:03d}"
            
            # Create investigation record
            investigation_record = {
                'id': investigation_id,
                'status': 'pending',
                'created_at': datetime.utcnow(),
                'request': {
                    'event_data': event_data,
                    'emergency_mode': request.emergency_mode,
                    'batch_id': batch_id
                },
                'progress': 0,
                'current_phase': 'queued',
                'batch_id': batch_id
            }
            
            active_investigations[investigation_id] = investigation_record
            investigation_ids.append(investigation_id)
            
            # Start investigation in background
            background_tasks.add_task(
                run_investigation_task,
                investigation_id,
                event_data,
                request.emergency_mode
            )
        
        # Estimate completion time for the batch
        completion_minutes = 3 if request.emergency_mode else 7
        estimated_completion = datetime.utcnow() + timedelta(minutes=completion_minutes)
        
        logger.info(f"Created bulk investigation batch {batch_id} with {len(investigation_ids)} investigations")
        
        return BulkInvestigationResponse(
            batch_id=batch_id,
            total_events=len(request.events),
            investigation_ids=investigation_ids,
            estimated_completion_time=estimated_completion,
            status="created"
        )
        
    except Exception as e:
        logger.error(f"Failed to create bulk investigations: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to create bulk investigations: {str(e)}"
        )


@router.get("/batch/{batch_id}")
async def get_batch_status(batch_id: str):
    """
    Get the status of a batch investigation
    
    Returns aggregated status information for all investigations
    in the specified batch.
    """
    # Find all investigations for this batch
    batch_investigations = {
        inv_id: inv for inv_id, inv in active_investigations.items()
        if inv.get('batch_id') == batch_id
    }
    
    # Also check historical investigations
    historical_batch = [
        inv for inv in investigation_history
        if inv.get('batch_id') == batch_id
    ]
    
    if not batch_investigations and not historical_batch:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Batch {batch_id} not found"
        )
    
    # Calculate batch statistics
    all_investigations = list(batch_investigations.values()) + historical_batch
    total_count = len(all_investigations)
    
    status_counts = {}
    for inv in all_investigations:
        status = inv['status']
        status_counts[status] = status_counts.get(status, 0) + 1
    
    # Calculate overall progress
    completed = status_counts.get('completed', 0)
    failed = status_counts.get('failed', 0)
    cancelled = status_counts.get('cancelled', 0)
    finished = completed + failed + cancelled
    
    overall_progress = (finished / total_count * 100) if total_count > 0 else 0
    
    # Determine batch status
    if finished == total_count:
        batch_status = 'completed'
    elif failed > 0 or cancelled > 0:
        batch_status = 'partial'
    else:
        batch_status = 'running'
    
    return {
        'batch_id': batch_id,
        'total_investigations': total_count,
        'status_counts': status_counts,
        'overall_progress': round(overall_progress, 1),
        'batch_status': batch_status,
        'investigation_ids': [inv['id'] for inv in all_investigations]
    }


@router.post("/search", response_model=SearchResponse)
async def search_investigations(request: SearchRequest):
    """
    Search through historical investigations
    
    Provides flexible search capabilities across investigation history
    with filtering by event type, risk level, dates, and free text.
    """
    try:
        # Combine active and historical investigations
        all_investigations = list(active_investigations.values()) + investigation_history
        
        # Apply filters
        filtered_results = []
        
        for inv in all_investigations:
            # Skip if doesn't match filters
            if request.event_types:
                event_type = inv.get('request', {}).get('event_data', {}).get('event_type')
                if event_type not in [et.value for et in request.event_types]:
                    continue
            
            if request.risk_levels:
                risk_level = inv.get('risk_level', 'unknown')
                if risk_level not in [rl.value for rl in request.risk_levels]:
                    continue
            
            if request.date_from:
                if inv.get('created_at', datetime.min) < request.date_from:
                    continue
            
            if request.date_to:
                if inv.get('created_at', datetime.max) > request.date_to:
                    continue
            
            if request.source_ip:
                source_ip = inv.get('request', {}).get('event_data', {}).get('source_ip')
                if source_ip != request.source_ip:
                    continue
            
            # Free text search (simple implementation)
            if request.query:
                search_text = f"{inv.get('id', '')} {inv.get('status', '')} {inv.get('request', {})}"
                if request.query.lower() not in search_text.lower():
                    continue
            
            filtered_results.append(inv)
        
        # Sort by creation time (newest first)
        filtered_results.sort(key=lambda x: x.get('created_at', datetime.min), reverse=True)
        
        # Apply pagination
        total_results = len(filtered_results)
        start_idx = request.offset
        end_idx = start_idx + request.limit
        paginated_results = filtered_results[start_idx:end_idx]
        
        # Format results for response
        formatted_results = []
        for inv in paginated_results:
            formatted_results.append({
                'investigation_id': inv['id'],
                'status': inv['status'],
                'created_at': inv['created_at'],
                'event_type': inv.get('request', {}).get('event_data', {}).get('event_type'),
                'risk_level': inv.get('risk_level', 'unknown'),
                'source_ip': inv.get('request', {}).get('event_data', {}).get('source_ip')
            })
        
        return SearchResponse(
            total_results=total_results,
            results=formatted_results,
            query_time_ms=50.0,  # Mock query time
            has_more=end_idx < total_results
        )
        
    except Exception as e:
        logger.error(f"Search failed: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Search failed: {str(e)}"
        )


@router.get("/")
async def list_investigations(
    status: Optional[str] = Query(None, description="Filter by status"),
    limit: int = Query(50, le=200, description="Maximum results to return"),
    offset: int = Query(0, description="Results offset")
):
    """
    List recent investigations with optional filtering
    
    Returns a paginated list of investigations with basic information.
    """
    # Combine active and historical investigations
    all_investigations = list(active_investigations.values()) + investigation_history
    
    # Apply status filter if provided
    if status:
        all_investigations = [inv for inv in all_investigations if inv.get('status') == status]
    
    # Sort by creation time (newest first)
    all_investigations.sort(key=lambda x: x.get('created_at', datetime.min), reverse=True)
    
    # Apply pagination
    total_count = len(all_investigations)
    paginated = all_investigations[offset:offset + limit]
    
    # Format for response
    formatted_investigations = []
    for inv in paginated:
        formatted_investigations.append({
            'investigation_id': inv['id'],
            'status': inv['status'],
            'created_at': inv['created_at'],
            'event_type': inv.get('request', {}).get('event_data', {}).get('event_type'),
            'emergency_mode': inv.get('request', {}).get('emergency_mode', False),
            'progress': inv.get('progress', 0),
            'current_phase': inv.get('current_phase', 'unknown')
        })
    
    return {
        'investigations': formatted_investigations,
        'total_count': total_count,
        'limit': limit,
        'offset': offset,
        'has_more': offset + limit < total_count
    }


async def run_investigation_task(investigation_id: str, event_data: Dict[str, Any], emergency_mode: bool = False):
    """
    Background task to run the actual investigation
    
    This function executes the SOC Agent investigation pipeline
    and updates the investigation status throughout the process.
    """
    try:
        if investigation_id not in active_investigations:
            logger.error(f"Investigation {investigation_id} not found in active investigations")
            return
        
        investigation = active_investigations[investigation_id]
        
        # Update status to running
        investigation.update({
            'status': 'running',
            'started_at': datetime.utcnow(),
            'current_phase': 'initial_assessment',
            'progress': 10
        })
        
        logger.info(f"Starting investigation {investigation_id}")
        
        # Get SOC agent
        from ..main import soc_agent
        if soc_agent is None:
            raise Exception("SOC Agent not available")
        
        # Run the investigation
        result = await soc_agent.investigate_incident(event_data, emergency_mode)
        
        # Update with results
        investigation.update({
            'status': 'completed',
            'completed_at': datetime.utcnow(),
            'result': result,
            'current_phase': 'completed',
            'progress': 100,
            'risk_level': result.get('risk_assessment', {}).get('risk_level', 'unknown'),
            'preliminary_risk_level': result.get('risk_assessment', {}).get('risk_level', 'unknown')
        })
        
        # Move to history and clean up active investigations
        investigation_history.append(investigation.copy())
        
        # Keep active investigations list manageable
        if len(active_investigations) > 100:
            # Move oldest completed investigations to history
            completed_ids = [
                inv_id for inv_id, inv in active_investigations.items()
                if inv['status'] in ['completed', 'failed', 'cancelled']
            ]
            completed_ids.sort(key=lambda x: active_investigations[x].get('completed_at', datetime.min))
            
            for inv_id in completed_ids[:50]:  # Move oldest 50
                if inv_id in active_investigations:
                    del active_investigations[inv_id]
        
        logger.info(f"Investigation {investigation_id} completed successfully")
        
    except Exception as e:
        logger.error(f"Investigation {investigation_id} failed: {e}")
        
        if investigation_id in active_investigations:
            active_investigations[investigation_id].update({
                'status': 'failed',
                'failed_at': datetime.utcnow(),
                'error': str(e),
                'current_phase': 'failed',
                'progress': 0
            }) 