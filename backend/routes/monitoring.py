"""
ThreatSentinel SOC Agent - Monitoring Routes

Real-time metrics, alerts, subscriptions and system status. Investigation
metrics come from the InvestigationStore; API latency comes from
RequestTimingMiddleware; intel call counts come from the tool registry.
"""

import asyncio
import json
import logging
import uuid
from collections import deque
from datetime import datetime, timedelta, timezone
from typing import Any, Deque, Dict, List, Optional

import psutil
from fastapi import APIRouter, Depends, HTTPException, Query, WebSocket, WebSocketDisconnect, status

from agent import SOCAgentPlanner

from .. import deps
from ..config import get_settings
from ..deps import get_current_user, get_soc_agent, get_store, verify_token
from ..middleware import response_times
from ..models import AlertConfiguration, EventSubscription, MonitoringMetrics

router = APIRouter(dependencies=[Depends(get_current_user)])
logger = logging.getLogger(__name__)

metrics_history: Deque[Dict[str, Any]] = deque(maxlen=1000)
active_websockets: List[WebSocket] = []
alert_config = AlertConfiguration()
subscriptions: Dict[str, EventSubscription] = {}
WS_AUTH_TIMEOUT_SECONDS = 5
WS_PUSH_INTERVAL_SECONDS = 5


def _utcnow() -> datetime:
    return datetime.now(timezone.utc)


def _avg(values: List[Optional[float]]) -> Optional[float]:
    clean = [v for v in values if isinstance(v, (int, float))]
    return round(sum(clean) / len(clean), 2) if clean else None


def _process_memory_mb() -> float:
    return round(psutil.Process().memory_info().rss / (1024 * 1024), 2)


def build_metrics(agent: SOCAgentPlanner) -> MonitoringMetrics:
    store = get_store()
    midnight = _utcnow().replace(hour=0, minute=0, second=0, microsecond=0)
    today = store.metrics(since=midnight)
    return MonitoringMetrics(
        timestamp=_utcnow(),
        active_investigations=store.active_count(),
        completed_investigations_today=today["completed"],
        average_investigation_time=today["average_duration_seconds"],
        high_risk_events_today=today["high_risk"],
        api_response_time=response_times.average_ms(last_n=200),
        memory_usage_mb=_process_memory_mb(),
        threat_intel_api_calls=dict(agent.tools.api_call_counts),
        error_rate=today["error_rate"],
    )


@router.get("/metrics", response_model=MonitoringMetrics)
async def get_current_metrics(agent: SOCAgentPlanner = Depends(get_soc_agent)):
    metrics = build_metrics(agent)
    metrics_history.append(metrics.model_dump(mode="json"))
    return metrics


@router.get("/metrics/history")
async def get_metrics_history(
    hours: int = Query(24, ge=1, le=168),
    resolution: str = Query("hour", pattern="^(minute|hour|day)$"),
):
    cutoff = _utcnow() - timedelta(hours=hours)
    points = [m for m in metrics_history if datetime.fromisoformat(m["timestamp"]) >= cutoff]

    if resolution in ("hour", "day") and len(points) > 100:
        buckets: Dict[datetime, List[Dict[str, Any]]] = {}
        for m in points:
            ts = datetime.fromisoformat(m["timestamp"])
            key = ts.replace(minute=0, second=0, microsecond=0)
            if resolution == "day":
                key = key.replace(hour=0)
            buckets.setdefault(key, []).append(m)
        points = [{
            "timestamp": key.isoformat(),
            "active_investigations": _avg([m["active_investigations"] for m in group]),
            "average_investigation_time": _avg([m["average_investigation_time"] for m in group]),
            "api_response_time": _avg([m.get("api_response_time") for m in group]),
            "memory_usage_mb": _avg([m["memory_usage_mb"] for m in group]),
            "error_rate": _avg([m["error_rate"] for m in group]),
            "data_points": len(group),
        } for key, group in sorted(buckets.items())]

    return {
        "metrics": points,
        "total_points": len(points),
        "time_range_hours": hours,
        "resolution": resolution,
        "start_time": cutoff.isoformat(),
        "end_time": _utcnow().isoformat(),
    }


# Separate router for websockets: HTTP auth dependencies cannot run during a
# websocket handshake, so this endpoint authenticates itself.
ws_router = APIRouter()


async def _authenticate_websocket(websocket: WebSocket) -> bool:
    """Accept bearer.<token> subprotocol, ?token= query, or a first {"type":"auth"} message."""
    subprotocol = None
    for proto in websocket.scope.get("subprotocols", []) or []:
        if proto.startswith("bearer."):
            subprotocol = proto
            if verify_token(proto[len("bearer."):]):
                await websocket.accept(subprotocol=proto)
                return True
    query_token = websocket.query_params.get("token")
    if query_token:
        if verify_token(query_token):
            await websocket.accept()
            return True
        await websocket.close(code=4401)
        return False
    if subprotocol:
        await websocket.close(code=4401)
        return False

    await websocket.accept()
    try:
        raw = await asyncio.wait_for(websocket.receive_text(), timeout=WS_AUTH_TIMEOUT_SECONDS)
        message = json.loads(raw)
    except (asyncio.TimeoutError, ValueError, WebSocketDisconnect):
        await websocket.close(code=4401)
        return False
    if isinstance(message, dict) and message.get("type") == "auth":
        token = message.get("token")
        if verify_token(token) or (not token and get_settings().debug):
            await websocket.send_json({"type": "auth_ok"})
            return True
    await websocket.close(code=4401)
    return False


@ws_router.websocket("/metrics/stream")
async def metrics_websocket(websocket: WebSocket):
    """Live metrics every few seconds. Authenticate before any data is sent."""
    if not await _authenticate_websocket(websocket):
        return
    active_websockets.append(websocket)
    try:
        while True:
            soc_agent = deps.soc_agent
            if soc_agent is None:
                await websocket.send_json({"type": "error", "error": "agent unavailable"})
            else:
                payload = build_metrics(soc_agent).model_dump(mode="json")
                payload.update({"type": "metrics", "websocket_connections": len(active_websockets)})
                await websocket.send_json(payload)
            await asyncio.sleep(WS_PUSH_INTERVAL_SECONDS)
    except WebSocketDisconnect:
        pass
    except Exception as e:
        logger.error(f"Metrics websocket error: {type(e).__name__}")
    finally:
        if websocket in active_websockets:
            active_websockets.remove(websocket)


@router.get("/alerts/config", response_model=AlertConfiguration)
async def get_alert_config():
    return alert_config


@router.put("/alerts/config", response_model=AlertConfiguration)
async def update_alert_config(config: AlertConfiguration):
    global alert_config
    alert_config = config
    logger.info(f"Updated alert configuration: {config.model_dump(mode='json')}")
    return alert_config


@router.get("/alerts/recent")
async def get_recent_alerts(hours: int = Query(24, ge=1, le=168), limit: int = Query(50, ge=1, le=200)):
    items, _ = get_store().list(risk_levels=["high", "critical"], date_from=_utcnow() - timedelta(hours=hours),
                                limit=limit)
    alerts = [{
        "alert_id": f"alert_{inv['id']}",
        "investigation_id": inv["id"],
        "alert_type": "prompt_injection" if inv.get("prompt_injection_detected") else "high_risk_investigation",
        "risk_level": inv.get("risk_level"),
        "risk_score": inv.get("risk_score"),
        "event_type": inv.get("event_type"),
        "source_ip": inv.get("source_ip"),
        "triggered_at": inv.get("completed_at") or inv.get("created_at"),
        "status": inv["status"],
        "owasp_categories": inv.get("owasp_categories", []),
        "message": f"{str(inv.get('risk_level')).upper()} risk {inv.get('event_type') or 'unknown'} investigation",
    } for inv in items]
    return {"alerts": alerts, "total_count": len(alerts), "time_range_hours": hours,
            "alert_config": alert_config.model_dump(mode="json")}


@router.post("/subscriptions", response_model=EventSubscription)
async def create_subscription(subscription: EventSubscription):
    if not subscription.subscription_id:
        subscription.subscription_id = f"sub_{uuid.uuid4().hex[:12]}"
    subscriptions[subscription.subscription_id] = subscription
    return subscription


@router.get("/subscriptions")
async def list_subscriptions():
    return {"subscriptions": [s.model_dump(mode="json") for s in subscriptions.values()],
            "total_count": len(subscriptions)}


@router.get("/subscriptions/{subscription_id}", response_model=EventSubscription)
async def get_subscription(subscription_id: str):
    if subscription_id not in subscriptions:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=f"Subscription {subscription_id} not found")
    return subscriptions[subscription_id]


@router.delete("/subscriptions/{subscription_id}")
async def delete_subscription(subscription_id: str):
    if subscription_id not in subscriptions:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=f"Subscription {subscription_id} not found")
    del subscriptions[subscription_id]
    return {"message": f"Subscription {subscription_id} deleted successfully"}


@router.get("/system/status")
async def get_system_status(agent: SOCAgentPlanner = Depends(get_soc_agent)):
    cpu_percent = await asyncio.to_thread(psutil.cpu_percent, 1)
    memory = psutil.virtual_memory()
    disk = psutil.disk_usage("/")
    memory_stats = await agent.memory.get_memory_stats()
    store = get_store()
    counts = store.count_by_status()
    return {
        "system": {
            "cpu_percent": cpu_percent,
            "memory_percent": memory.percent,
            "memory_used_gb": round(memory.used / (1024 ** 3), 2),
            "memory_total_gb": round(memory.total / (1024 ** 3), 2),
            "process_memory_mb": _process_memory_mb(),
            "disk_used_gb": round(disk.used / (1024 ** 3), 2),
            "disk_total_gb": round(disk.total / (1024 ** 3), 2),
            "disk_percent": round(disk.used / disk.total * 100, 1),
        },
        "agent": {
            "status": "healthy",
            "available_tools": len(agent.tools.get_available_tools()),
            "tool_capabilities": agent.tools.get_tool_capabilities(),
            "intel_tools": agent.tools.get_status(),
            "llm": f"{agent.llm.provider_name}/{agent.llm.model}" if agent.llm else None,
            "memory_investigations": memory_stats.get("total_investigations", 0),
            "patterns_learned": memory_stats.get("patterns_learned", 0),
        },
        "investigations": {
            "active_count": store.active_count(),
            "status_counts": counts,
            "historical_count": sum(counts.values()),
            "recent_24h": store.metrics()["total"],
        },
        "monitoring": {
            "websocket_connections": len(active_websockets),
            "subscriptions_count": len(subscriptions),
            "alerts_enabled": alert_config.enabled,
            "metrics_history_points": len(metrics_history),
            "api_latency": response_times.snapshot(),
        },
        "timestamp": _utcnow(),
    }


@router.post("/system/restart")
async def restart_agent(agent: SOCAgentPlanner = Depends(get_soc_agent)):
    """Reconnect integrations. A process restart is left to the supervisor."""
    results = await agent.integrations.connect_all() if agent.integrations.integrations else {}
    return {"message": "Integrations reconnected; restart the process to reload configuration",
            "integrations": results, "timestamp": _utcnow(), "status": "success"}


@router.get("/performance/stats")
async def get_performance_stats(agent: SOCAgentPlanner = Depends(get_soc_agent)):
    """Performance averages and trends. Works before any /metrics sample exists."""
    if not metrics_history:
        metrics_history.append(build_metrics(agent).model_dump(mode="json"))
    recent = list(metrics_history)[-100:]

    def trend(values: List[Optional[float]]) -> float:
        clean = [v for v in values if isinstance(v, (int, float))]
        return round((clean[-1] - clean[0]) / len(clean), 4) if len(clean) >= 2 else 0.0

    first_ts = datetime.fromisoformat(recent[0]["timestamp"])
    return {
        "averages": {
            "investigation_time_seconds": _avg([m["average_investigation_time"] for m in recent]),
            "api_response_time_ms": _avg([m.get("api_response_time") for m in recent]),
            "memory_usage_mb": _avg([m["memory_usage_mb"] for m in recent]),
            "error_rate_percent": _avg([m["error_rate"] for m in recent]),
        },
        "trends": {
            "investigation_time_trend": trend([m["average_investigation_time"] for m in recent]),
            "memory_usage_trend": trend([m["memory_usage_mb"] for m in recent]),
        },
        "api_latency": response_times.snapshot(),
        "threat_intel_api_calls": dict(agent.tools.api_call_counts),
        "metrics": {
            "sample_size": len(recent),
            "time_range_minutes": round((_utcnow() - first_ts).total_seconds() / 60, 2),
        },
        "thresholds": {"max_investigation_time": 300, "max_memory_usage_mb": 1024, "max_error_rate": 5.0},
    }
