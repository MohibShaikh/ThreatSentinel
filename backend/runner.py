"""
Investigation execution shared by the REST routes and the task queue.

Runs are real asyncio tasks tracked in ``deps.running_investigations`` so a
DELETE can cancel them, and every state change goes through the
InvestigationStore with compare-and-set on status so a cancelled run is never
overwritten by a late result.
"""

import asyncio
import logging
import uuid
from typing import Any, Dict, Optional

from . import deps
from .config import get_settings
from .store import ACTIVE_STATUSES, utcnow

logger = logging.getLogger(__name__)
_semaphore: Optional[asyncio.Semaphore] = None


def new_investigation_id() -> str:
    return f"inv_{uuid.uuid4().hex[:12]}"


def _limiter() -> asyncio.Semaphore:
    global _semaphore
    if _semaphore is None:
        _semaphore = asyncio.Semaphore(max(1, get_settings().max_concurrent_investigations))
    return _semaphore


def reset_limiter() -> None:
    """Drop the semaphore (it is bound to the event loop that created it)."""
    global _semaphore
    _semaphore = None


async def run_investigation(investigation_id: str, event_data: Dict[str, Any],
                            emergency_mode: bool = False) -> Optional[Dict[str, Any]]:
    store = deps.get_store()
    agent = deps.get_soc_agent()
    try:
        async with _limiter():
            if not store.update_if_status(investigation_id, ("pending", "queued"), status="running",
                                          started_at=utcnow(), current_phase="initial_assessment", progress=10):
                logger.info(f"Investigation {investigation_id} no longer pending; not starting")
                return None
            result = await agent.investigate_incident(event_data, emergency_mode,
                                                      investigation_id=investigation_id)
            status = store.record_result(investigation_id, result)
            logger.info(f"Investigation {investigation_id} finished with status {status}")
            return result
    except asyncio.CancelledError:
        store.update_if_status(investigation_id, ACTIVE_STATUSES, status="cancelled",
                               completed_at=utcnow(), current_phase="cancelled")
        raise
    except Exception as e:
        logger.exception(f"Investigation {investigation_id} crashed")
        store.update_if_status(investigation_id, ACTIVE_STATUSES, status="failed", completed_at=utcnow(),
                               current_phase="failed", progress=0, error=f"{type(e).__name__}")
        return None
    finally:
        deps.running_investigations.pop(investigation_id, None)


def start_investigation(investigation_id: str, event_data: Dict[str, Any],
                        emergency_mode: bool = False) -> asyncio.Task:
    task = asyncio.create_task(run_investigation(investigation_id, event_data, emergency_mode),
                               name=f"investigation:{investigation_id}")
    deps.running_investigations[investigation_id] = task
    return task


async def investigation_task_handler(payload: Dict[str, Any]) -> Dict[str, Any]:
    """TaskQueue handler: investigate and return a compact result summary."""
    store = deps.get_store()
    event_data = payload.get("event_data") or {}
    if not isinstance(event_data, dict) or "event_type" not in event_data:
        raise ValueError("investigation task payload needs event_data with an event_type")
    emergency = bool(payload.get("emergency_mode", False))
    investigation_id = payload.get("investigation_id") or new_investigation_id()
    if store.get(investigation_id) is None:
        store.create(investigation_id, {"event_data": event_data, "emergency_mode": emergency},
                     batch_id=payload.get("batch_id"))
    task = start_investigation(investigation_id, event_data, emergency)
    await task
    record = store.get(investigation_id) or {}
    if record.get("status") not in ("completed", "pending_human_review"):
        raise RuntimeError(record.get("error") or f"Investigation ended with status {record.get('status')}")
    return {
        "investigation_id": investigation_id,
        "status": record.get("status"),
        "risk_level": record.get("risk_level"),
        "risk_score": record.get("risk_score"),
    }
