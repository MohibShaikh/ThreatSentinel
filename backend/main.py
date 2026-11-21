"""
ThreatSentinel SOC Agent Backend - FastAPI Main Application

REST API providing investigation, reporting, monitoring, integrations, task
queue and audit endpoints over the SOC agent.
"""

import json
import logging
import os
from contextlib import asynccontextmanager
from datetime import datetime, timedelta, timezone
from typing import Any, Dict

from fastapi import Depends, FastAPI, HTTPException, Request, status
from fastapi.exceptions import RequestValidationError
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from starlette.exceptions import HTTPException as StarletteHTTPException

from agent import SOCAgentPlanner, TaskQueue

from . import deps
from .config import Settings, get_settings
from .deps import get_current_user, get_soc_agent, get_store
from .middleware import RateLimitMiddleware, RequestTimingMiddleware, SecurityHeadersMiddleware
from .models import (AgentStatsResponse, HealthResponse, InvestigationRequest, InvestigationResponse,
                     InvestigationStatus)
from .routes import audit, integrations, investigations, monitoring, reports, tasks
from .runner import investigation_task_handler, new_investigation_id, reset_limiter, start_investigation
from .store import InvestigationStore

logger = logging.getLogger(__name__)
API_VERSION = "2.1.0"


def _utcnow() -> datetime:
    return datetime.now(timezone.utc)


def build_agent_config(settings: Settings) -> Dict[str, Any]:
    try:
        integrations_config = json.loads(settings.integrations_config or "{}")
    except json.JSONDecodeError as e:
        raise ValueError(f"Invalid INTEGRATIONS_CONFIG JSON: {e}") from e

    llm_config: Dict[str, Any] = {}
    if settings.llm_provider:
        llm_config = {
            "provider": settings.llm_provider,
            "api_key": settings.llm_api_key,
            "model": settings.llm_model,
            "base_url": settings.llm_base_url,
            "temperature": settings.llm_temperature,
            "max_tokens": settings.llm_max_tokens,
            "redact_secrets": settings.llm_redact_secrets,
        }
        llm_config = {k: v for k, v in llm_config.items() if v is not None}

    return {
        "api_keys": {
            "virustotal": settings.virustotal_api_key,
            "abuseipdb": settings.abuseipdb_api_key,
            "urlvoid": settings.urlvoid_api_key,
            "shodan": settings.shodan_api_key,
        },
        "enable_keyless_intel": settings.enable_keyless_intel,
        "memory": {"memory_dir": settings.memory_dir},
        "reporting": {"reports_dir": settings.reports_dir, "auto_save": settings.auto_save_reports},
        "llm": llm_config,
        "integrations_config": integrations_config,
        "audit": {"db_path": os.path.join(settings.data_dir, "action_logs.db")},
        "confidence_threshold": settings.confidence_threshold,
        "emergency_threshold": settings.emergency_threshold,
        "max_investigation_time": settings.max_investigation_time,
        "llm_max_tool_steps": settings.llm_max_tool_steps,
    }


@asynccontextmanager
async def lifespan(app: FastAPI):
    settings = get_settings()
    settings.validate_security_posture()
    if settings.debug:
        for problem in settings.security_posture_errors():
            logger.warning(f"DEBUG mode with insecure setting: {problem}")

    deps.soc_agent = SOCAgentPlanner(build_agent_config(settings))
    deps.investigation_store = InvestigationStore(os.path.join(settings.data_dir, "investigations.db"))
    interrupted = deps.investigation_store.mark_interrupted()
    if interrupted:
        logger.warning(f"Marked {interrupted} interrupted investigations as failed")
    reset_limiter()

    if deps.soc_agent.integrations.integrations:
        try:
            results = await deps.soc_agent.integrations.connect_all()
            logger.info(f"Integrations connected: {results}")
        except Exception as e:  # an unreachable integration must not stop the API
            logger.error(f"Integration startup failed: {type(e).__name__}: {e}")

    queue = TaskQueue(db_path=os.path.join(settings.data_dir, "tasks.db"),
                      max_workers=max(1, settings.task_queue_workers))
    queue.register_handler("investigation", investigation_task_handler)
    deps.task_queue = queue
    await queue.start()
    logger.info("SOC Agent backend started")

    try:
        yield
    finally:
        logger.info("Shutting down SOC Agent backend")
        await queue.stop()
        for task in list(deps.running_investigations.values()):
            task.cancel()
        try:
            await deps.soc_agent.integrations.disconnect_all()
        except Exception as e:
            logger.error(f"Integration shutdown failed: {type(e).__name__}")
        deps.task_queue = None


def _cors_origins(settings: Settings):
    # A wildcard with credentials would let any site act as the user
    return [o for o in settings.cors_origins if o != "*"]


app = FastAPI(
    title="ThreatSentinel SOC Agent API",
    description="Autonomous Security Operations Center Agent API",
    version=API_VERSION,
    docs_url="/docs",
    redoc_url="/redoc",
    lifespan=lifespan,
)

# Order: last added runs first. Timing wraps everything, then security headers,
# then rate limiting, then CORS closest to the routes.
app.add_middleware(
    CORSMiddleware,
    allow_origins=_cors_origins(get_settings()),
    allow_credentials=True,
    allow_methods=["GET", "POST", "PUT", "DELETE", "OPTIONS"],
    allow_headers=["Authorization", "Content-Type"],
)
app.add_middleware(RateLimitMiddleware, settings_provider=get_settings)
app.add_middleware(SecurityHeadersMiddleware)
app.add_middleware(RequestTimingMiddleware)

app.include_router(investigations.router, prefix="/api/v1/investigations", tags=["Investigations"])
app.include_router(reports.router, prefix="/api/v1/reports", tags=["Reports"])
app.include_router(monitoring.router, prefix="/api/v1/monitoring", tags=["Monitoring"])
app.include_router(monitoring.ws_router, prefix="/api/v1/monitoring")
app.include_router(integrations.router, prefix="/api/v1/integrations", tags=["Integrations"])
app.include_router(tasks.router, prefix="/api/v1", tags=["Tasks"])
app.include_router(audit.router, prefix="/api/v1", tags=["Audit"])


@app.get("/", response_model=Dict[str, str])
async def root():
    return {"message": "ThreatSentinel SOC Agent API", "version": API_VERSION,
            "documentation": "/docs", "health": "/health"}


@app.get("/health", response_model=HealthResponse)
async def health_check():
    """Unauthenticated liveness probe. Reveals no configuration or error detail."""
    healthy = deps.soc_agent is not None and deps.investigation_store is not None
    return HealthResponse(
        status="healthy" if healthy else "unhealthy",
        timestamp=_utcnow(),
        version=API_VERSION,
        agent_status="ready" if healthy else "unavailable",
    )


@app.get("/api/v1/stats", response_model=AgentStatsResponse, dependencies=[Depends(get_current_user)])
async def get_agent_stats(agent: SOCAgentPlanner = Depends(get_soc_agent)):
    store = get_store()
    try:
        memory_stats = await agent.memory.get_memory_stats()
        pending_tasks = 0
        if deps.task_queue is not None:
            pending_tasks = (await deps.task_queue.get_queue_stats()).get("pending_tasks", 0)
        return AgentStatsResponse(
            memory_stats=memory_stats,
            tool_capabilities=agent.tools.get_tool_capabilities(),
            active_investigations=store.active_count(),
            investigation_history=memory_stats.get("by_event_type", {}),
            risk_distribution=memory_stats.get("by_risk_level", {}),
            avg_investigation_time=memory_stats.get("avg_investigation_duration_seconds", 0.0),
            pending_tasks=pending_tasks,
            pending_reviews=len(store.pending_reviews()),
            llm_provider=f"{agent.llm.provider_name}/{agent.llm.model}" if agent.llm else None,
            intel_sources=agent.tools.get_available_tools(),
        )
    except Exception:
        logger.exception("Failed to build agent stats")
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                            detail="Failed to get agent stats") from None


@app.get("/api/v1/tools", dependencies=[Depends(get_current_user)])
async def list_agent_tools(agent: SOCAgentPlanner = Depends(get_soc_agent)) -> Dict[str, Any]:
    """The read-only tools the agent can choose from, with their JSON schemas."""
    return {
        "mode": "flexible_tool_environment",
        "llm_enabled": agent.llm is not None,
        "llm_provider": f"{agent.llm.provider_name}/{agent.llm.model}" if agent.llm else None,
        "max_tool_steps": agent.llm_max_tool_steps,
        "tools": agent.environment.list_tool_schemas(),
    }


# Legacy single-event endpoints, kept for existing clients; backed by the same store.

@app.post("/api/v1/investigate", response_model=InvestigationResponse,
          dependencies=[Depends(get_current_user)])
async def investigate_event(request: InvestigationRequest, agent: SOCAgentPlanner = Depends(get_soc_agent)):
    store = get_store()
    investigation_id = new_investigation_id()
    store.create(investigation_id, request.model_dump())
    start_investigation(investigation_id, request.event_data, request.emergency_mode)
    return InvestigationResponse(
        investigation_id=investigation_id,
        status="started",
        message="Investigation started successfully",
        estimated_completion_time=_utcnow() + timedelta(minutes=2 if request.emergency_mode else 5),
        priority="emergency" if request.emergency_mode else "normal",
    )


@app.get("/api/v1/investigate/{investigation_id}/status", response_model=InvestigationStatus,
         dependencies=[Depends(get_current_user)])
async def get_investigation_status(investigation_id: str):
    record = get_store().get(investigation_id)
    if not record:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Investigation not found")
    return InvestigationStatus(
        investigation_id=investigation_id,
        status=record["status"],
        start_time=record["created_at"],
        current_phase=record.get("current_phase") or "unknown",
        progress_percentage=int(record.get("progress") or 0),
        estimated_time_remaining=0,
        preliminary_risk_level=record.get("risk_level") or "unknown",
    )


@app.get("/api/v1/investigate/{investigation_id}/result", dependencies=[Depends(get_current_user)])
async def get_investigation_result(investigation_id: str):
    record = get_store().get(investigation_id)
    if not record:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Investigation not found")
    if record["status"] not in ("completed", "pending_human_review"):
        raise HTTPException(status_code=status.HTTP_409_CONFLICT,
                            detail=f"Investigation not completed. Current status: {record['status']}")
    return record.get("result") or {}


@app.exception_handler(StarletteHTTPException)
async def http_exception_handler(request: Request, exc: StarletteHTTPException):
    return JSONResponse(
        status_code=exc.status_code,
        content={"error": exc.detail, "status_code": exc.status_code, "timestamp": _utcnow().isoformat()},
        headers=getattr(exc, "headers", None),
    )


@app.exception_handler(RequestValidationError)
async def validation_exception_handler(request: Request, exc: RequestValidationError):
    errors = [{"loc": list(e.get("loc", [])), "msg": e.get("msg"), "type": e.get("type")} for e in exc.errors()]
    return JSONResponse(
        status_code=422,
        content={"error": "Validation error", "status_code": 422, "timestamp": _utcnow().isoformat(),
                 "validation_errors": errors},
    )


@app.exception_handler(Exception)
async def general_exception_handler(request: Request, exc: Exception):
    logger.error(f"Unhandled exception on {request.url.path}: {type(exc).__name__}")
    return JSONResponse(
        status_code=500,
        content={"error": "Internal server error", "status_code": 500, "timestamp": _utcnow().isoformat()},
    )
