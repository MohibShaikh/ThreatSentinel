"""
ThreatSentinel SOC Agent - Investigation Routes

All state lives in the persistent InvestigationStore. Static paths
(/bulk, /search, /reviews/pending, /batch/...) are declared before
/{investigation_id} so they are never captured by it.
"""

import logging
import time
from datetime import timedelta
from typing import Any, Dict, Optional

from fastapi import APIRouter, Depends, HTTPException, Query, status

from agent import SOCAgentPlanner

from ..deps import get_current_user, get_soc_agent, get_store, running_investigations
from ..models import (AnalystFeedback, BulkInvestigationRequest, BulkInvestigationResponse, InvestigationRequest,
                      InvestigationResponse, InvestigationStatus, ReviewStatus, SearchRequest, SearchResponse)
from ..runner import new_investigation_id, start_investigation
from ..store import ACTIVE_STATUSES, utcnow

router = APIRouter(dependencies=[Depends(get_current_user)])
logger = logging.getLogger(__name__)


def _summary(inv: Dict[str, Any]) -> Dict[str, Any]:
    return {
        "investigation_id": inv["id"],
        "id": inv["id"],
        "title": inv.get("title"),
        "status": inv["status"],
        "created_at": inv["created_at"],
        "completed_at": inv.get("completed_at"),
        "event_type": inv.get("event_type"),
        "source_ip": inv.get("source_ip"),
        "risk_level": inv.get("risk_level"),
        "risk_score": inv.get("risk_score"),
        "emergency_mode": inv.get("emergency_mode", False),
        "progress": inv.get("progress", 0),
        "current_phase": inv.get("current_phase") or "unknown",
        "batch_id": inv.get("batch_id"),
        "review_status": inv.get("review_status"),
        "owasp_categories": inv.get("owasp_categories", []),
        "mitre_techniques": inv.get("mitre_techniques", []),
        "prompt_injection_detected": inv.get("prompt_injection_detected", False),
    }


def _get_or_404(investigation_id: str) -> Dict[str, Any]:
    record = get_store().get(investigation_id)
    if not record:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND,
                            detail=f"Investigation {investigation_id} not found")
    return record


@router.post("/", response_model=InvestigationResponse, status_code=status.HTTP_201_CREATED)
async def create_investigation(request: InvestigationRequest, agent: SOCAgentPlanner = Depends(get_soc_agent)):
    """Submit a security event for asynchronous investigation."""
    store = get_store()
    investigation_id = new_investigation_id()
    store.create(investigation_id, request.model_dump())
    start_investigation(investigation_id, request.event_data, request.emergency_mode)
    logger.info(f"Created investigation {investigation_id}")
    return InvestigationResponse(
        investigation_id=investigation_id,
        status="created",
        message="Investigation created and queued for processing",
        estimated_completion_time=utcnow() + timedelta(minutes=2 if request.emergency_mode else 5),
        priority="emergency" if request.emergency_mode else "normal",
    )


@router.post("/bulk", response_model=BulkInvestigationResponse)
async def create_bulk_investigations(request: BulkInvestigationRequest,
                                     agent: SOCAgentPlanner = Depends(get_soc_agent)):
    store = get_store()
    batch_id = request.batch_id or f"batch_{new_investigation_id()[4:]}"
    ids = []
    for event_data in request.events:
        investigation_id = new_investigation_id()
        store.create(investigation_id, {"event_data": event_data, "emergency_mode": request.emergency_mode,
                                        "batch_id": batch_id}, batch_id=batch_id)
        start_investigation(investigation_id, event_data, request.emergency_mode)
        ids.append(investigation_id)
    return BulkInvestigationResponse(
        batch_id=batch_id,
        total_events=len(request.events),
        investigation_ids=ids,
        estimated_completion_time=utcnow() + timedelta(minutes=3 if request.emergency_mode else 7),
        status="created",
    )


@router.post("/search", response_model=SearchResponse)
async def search_investigations(request: SearchRequest):
    started = time.perf_counter()
    items, total = get_store().list(
        event_types=[e.value for e in request.event_types] if request.event_types else None,
        risk_levels=[r.value for r in request.risk_levels] if request.risk_levels else None,
        date_from=request.date_from, date_to=request.date_to, source_ip=request.source_ip,
        query=request.query, limit=request.limit, offset=request.offset,
    )
    return SearchResponse(
        total_results=total,
        results=[_summary(i) for i in items],
        query_time_ms=round((time.perf_counter() - started) * 1000, 3),
        has_more=request.offset + len(items) < total,
    )


@router.get("/reviews/pending")
async def list_pending_reviews(limit: int = Query(100, ge=1, le=500)):
    """Escalated investigations waiting for an analyst decision."""
    items = get_store().pending_reviews(limit=limit)
    reviews = []
    for inv in items:
        result = inv.get("result") or {}
        review = result.get("review_request") or {}
        reviews.append({
            **_summary(inv),
            "priority": review.get("priority", "medium"),
            "triggers": review.get("triggers", []),
            "reason": review.get("reason"),
            "confidence_score": review.get("confidence_score"),
            "proposed_actions": result.get("proposed_actions", []),
        })
    rank = {"critical": 0, "high": 1, "medium": 2, "low": 3}
    reviews.sort(key=lambda r: (rank.get(r["priority"], 9), -(r.get("risk_score") or 0)))
    return {"reviews": reviews, "total_count": len(reviews)}


@router.get("/batch/{batch_id}")
async def get_batch_status(batch_id: str):
    items, total = get_store().list(batch_id=batch_id, limit=1000)
    if not total:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=f"Batch {batch_id} not found")
    counts: Dict[str, int] = {}
    for inv in items:
        counts[inv["status"]] = counts.get(inv["status"], 0) + 1
    finished = sum(v for k, v in counts.items() if k not in ACTIVE_STATUSES)
    if finished == total:
        batch_status = "completed"
    elif counts.get("failed") or counts.get("cancelled"):
        batch_status = "partial"
    else:
        batch_status = "running"
    return {
        "batch_id": batch_id,
        "total_investigations": total,
        "status_counts": counts,
        "overall_progress": round(finished / total * 100, 1),
        "batch_status": batch_status,
        "investigation_ids": [i["id"] for i in items],
    }


@router.get("/")
async def list_investigations(
    status_filter: Optional[str] = Query(None, alias="status", description="Filter by status"),
    limit: int = Query(50, ge=1, le=200),
    offset: int = Query(0, ge=0),
):
    items, total = get_store().list(status=status_filter, limit=limit, offset=offset)
    return {
        "investigations": [_summary(i) for i in items],
        "total_count": total,
        "limit": limit,
        "offset": offset,
        "has_more": offset + len(items) < total,
    }


@router.get("/{investigation_id}", response_model=InvestigationStatus)
async def get_investigation_status(investigation_id: str):
    inv = _get_or_404(investigation_id)
    if inv["status"] in ACTIVE_STATUSES:
        elapsed = (utcnow() - inv["created_at"]).total_seconds()
        remaining = max(0, int((120 if inv.get("emergency_mode") else 300) - elapsed))
    else:
        remaining = 0
    return InvestigationStatus(
        investigation_id=investigation_id,
        status=inv["status"],
        start_time=inv["created_at"],
        current_phase=inv.get("current_phase") or "unknown",
        progress_percentage=int(inv.get("progress") or 0),
        estimated_time_remaining=remaining,
        preliminary_risk_level=inv.get("risk_level") or "unknown",
    )


@router.get("/{investigation_id}/result")
async def get_investigation_result(investigation_id: str):
    inv = _get_or_404(investigation_id)
    if inv["status"] not in ("completed", "pending_human_review"):
        raise HTTPException(status_code=status.HTTP_409_CONFLICT,
                            detail=f"Investigation not completed. Current status: {inv['status']}")
    return {**(inv.get("result") or {}), "status": inv["status"], "review_status": inv.get("review_status"),
            "feedback": inv.get("feedback")}


@router.post("/{investigation_id}/feedback")
async def submit_feedback(investigation_id: str, feedback: AnalystFeedback,
                          agent: SOCAgentPlanner = Depends(get_soc_agent),
                          user: Dict[str, Any] = Depends(get_current_user)):
    """Record an analyst decision; on approval optionally execute the proposed actions."""
    store = get_store()
    inv = _get_or_404(investigation_id)
    if inv["status"] in ACTIVE_STATUSES:
        raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail="Investigation is still running")

    payload = feedback.model_dump(mode="json")
    payload["investigation_id"] = investigation_id
    learning = await agent.process_analyst_feedback(investigation_id, payload)

    execution = None
    if feedback.review_status == ReviewStatus.APPROVED and feedback.execute_actions and not feedback.false_positive:
        execution = await agent.execute_approved_actions(inv.get("result") or {})

    new_status = inv["status"]
    if inv["status"] == "pending_human_review" and feedback.review_status in (
            ReviewStatus.APPROVED, ReviewStatus.REJECTED):
        new_status = "completed"
    store.update(investigation_id, review_status=feedback.review_status.value,
                 feedback={**payload, "submitted_by": user.get("user_id"), "execution": execution},
                 status=new_status)
    return {
        "investigation_id": investigation_id,
        "status": new_status,
        "review_status": feedback.review_status.value,
        "learning": learning,
        "execution": execution,
    }


@router.delete("/{investigation_id}")
async def cancel_investigation(investigation_id: str):
    store = get_store()
    inv = _get_or_404(investigation_id)
    if inv["status"] not in ACTIVE_STATUSES:
        raise HTTPException(status_code=status.HTTP_409_CONFLICT,
                            detail=f"Cannot cancel investigation with status: {inv['status']}")
    store.update_if_status(investigation_id, ACTIVE_STATUSES, status="cancelled",
                           completed_at=utcnow(), current_phase="cancelled")
    task = running_investigations.get(investigation_id)
    if task is not None and not task.done():
        task.cancel()
    logger.info(f"Cancelled investigation {investigation_id}")
    return {"message": f"Investigation {investigation_id} cancelled successfully", "status": "cancelled"}
