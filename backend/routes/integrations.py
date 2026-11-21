"""
Integration Management API Routes

Static paths are registered before ``/{integration_name}`` so that
``/health``, ``/types``, ``/actions`` etc. are never captured as names.
"""

import logging
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, Field

from agent import SOCAgentPlanner
from agent.integrations.base import ActionType, stable_reference
from agent.integrations.registry import IntegrationRegistry

from ..deps import get_current_user, get_soc_agent

logger = logging.getLogger(__name__)
router = APIRouter(dependencies=[Depends(get_current_user)])


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _registry(agent: SOCAgentPlanner = Depends(get_soc_agent)) -> IntegrationRegistry:
    return agent.integrations


class ActionExecutionRequest(BaseModel):
    action_type: ActionType
    target: str = Field(..., min_length=1, max_length=2048)
    context: Dict[str, Any] = Field(default_factory=dict)
    preferred_integrations: Optional[List[str]] = None


class BulkActionRequest(BaseModel):
    actions: List[Dict[str, Any]] = Field(..., min_length=1, max_length=100)
    context: Dict[str, Any] = Field(default_factory=dict)


@router.get("/", response_model=Dict[str, Any], summary="List All Integrations")
async def list_integrations(registry: IntegrationRegistry = Depends(_registry)):
    status = registry.get_registry_status()
    return {
        "integrations": status["integration_status"],
        "summary": {
            "total_configured": status["total_configured"],
            "total_active": status["total_active"],
            "capabilities": status["capabilities"],
        },
    }


@router.get("/health", response_model=Dict[str, Any], summary="Health Check All Integrations")
async def health_check_integrations(registry: IntegrationRegistry = Depends(_registry)):
    results = await registry.health_check()
    healthy = len([r for r in results.values() if r])
    return {
        "health_check_completed": True,
        "total_integrations": len(results),
        "healthy_integrations": healthy,
        "unhealthy_integrations": len(results) - healthy,
        "health_results": results,
        "checked_at": _now(),
    }


@router.get("/types", response_model=Dict[str, str], summary="Get Available Integration Types")
async def get_integration_types():
    return IntegrationRegistry.get_available_integration_types()


@router.get("/actions", response_model=List[str], summary="Get Available Action Types")
async def get_action_types():
    return [action.value for action in ActionType]


@router.post("/connect", response_model=Dict[str, Any], summary="Connect All Integrations")
async def connect_integrations(registry: IntegrationRegistry = Depends(_registry)):
    results = await registry.connect_all()
    ok = len([r for r in results.values() if r])
    return {
        "message": "Connection process completed",
        "summary": {"total_integrations": len(results), "successful_connections": ok,
                    "failed_connections": len(results) - ok},
        "connection_results": results,
        "connected_at": _now(),
    }


@router.post("/disconnect", response_model=Dict[str, Any], summary="Disconnect All Integrations")
async def disconnect_integrations(registry: IntegrationRegistry = Depends(_registry)):
    results = await registry.disconnect_all()
    return {"message": "Disconnection process completed", "disconnection_results": results,
            "disconnected_at": _now()}


@router.get("/capabilities/{action_type}", response_model=Dict[str, Any], summary="Get Action Capabilities")
async def get_action_capabilities(action_type: ActionType, registry: IntegrationRegistry = Depends(_registry)):
    capabilities = [{
        "name": integration.name,
        "type": integration.integration_type.value,
        "connected": integration.is_connected,
        "status": integration.get_status(),
    } for integration in registry.get_integrations_by_action(action_type)]
    return {"action_type": action_type.value, "supporting_integrations": len(capabilities),
            "capabilities": capabilities}


@router.post("/actions/execute", response_model=Dict[str, Any], summary="Execute Single Action")
async def execute_action(request: ActionExecutionRequest, registry: IntegrationRegistry = Depends(_registry),
                         user: Dict[str, Any] = Depends(get_current_user)):
    context = {**request.context, "executed_by": user.get("user_id"), "executed_at": _now()}
    response = await registry.execute_action(
        action_type=request.action_type, target=request.target, context=context,
        preferred_integrations=request.preferred_integrations,
    )
    return {
        "action_type": request.action_type.value,
        "target": request.target,
        "execution_result": {
            "success": response.success,
            "actions_executed": len(response.actions_executed),
            "successful_actions": len([a for a in response.actions_executed if a.success]),
            "total_execution_time": response.total_execution_time,
            "metadata": response.metadata,
            "error_details": response.error_details,
        },
        "details": [{
            "success": a.success, "action_type": a.action_type.value, "target": a.target,
            "execution_time": a.execution_time, "reference_id": a.reference_id, "error_message": a.error_message,
        } for a in response.actions_executed],
    }


@router.post("/actions/bulk", response_model=Dict[str, Any], summary="Execute Multiple Actions")
async def execute_bulk_actions(request: BulkActionRequest, registry: IntegrationRegistry = Depends(_registry),
                               user: Dict[str, Any] = Depends(get_current_user)):
    valid_types = {a.value for a in ActionType}
    for action in request.actions:
        if action.get("action_type") not in valid_types:
            raise HTTPException(status_code=422, detail=f"Unknown action_type: {action.get('action_type')!r}")
    context = {**request.context, "executed_by": user.get("user_id"), "executed_at": _now(), "bulk_execution": True}
    responses = await registry.execute_response_actions(recommended_actions=request.actions, context=context)
    ok = len([r for r in responses if r.success])
    return {
        "bulk_execution_id": f"bulk_{stable_reference(request.actions, _now())}",
        "summary": {"total_actions": len(responses), "successful_actions": ok,
                    "failed_actions": len(responses) - ok,
                    "total_execution_time": sum(r.total_execution_time for r in responses)},
        "results": [{
            "success": r.success, "integration_name": r.integration_name,
            "actions_count": len(r.actions_executed), "execution_time": r.total_execution_time,
            "metadata": r.metadata, "error_details": r.error_details,
        } for r in responses],
    }


@router.get("/{integration_name}", response_model=Dict[str, Any], summary="Get Integration Details")
async def get_integration(integration_name: str, registry: IntegrationRegistry = Depends(_registry)):
    integration = registry.integrations.get(integration_name)
    if not integration:
        raise HTTPException(status_code=404, detail=f"Integration {integration_name} not found")
    return {
        "name": integration_name,
        "type": integration.integration_type.value,
        "connected": integration_name in registry.active_integrations,
        "status": integration.get_status(),
        "supported_actions": [a.value for a in integration.get_supported_actions()],
    }


@router.post("/{integration_name}/test", response_model=Dict[str, Any], summary="Test Integration")
async def test_integration(integration_name: str, registry: IntegrationRegistry = Depends(_registry)):
    if integration_name not in registry.integrations:
        raise HTTPException(status_code=404, detail=f"Integration {integration_name} not found")
    return {"integration_name": integration_name, "test_result": await registry.test_integration(integration_name),
            "tested_at": _now()}
