"""
Integration Management API Routes
"""

import logging
from typing import Dict, Any, List, Optional
from fastapi import APIRouter, HTTPException, Depends, BackgroundTasks
from pydantic import BaseModel
from datetime import datetime

from backend.main import get_soc_agent, get_current_user
from agent.integrations.base import ActionType, IntegrationType

logger = logging.getLogger(__name__)
router = APIRouter()

# Global integration registry (in production, this would be persistent)
integration_registry = None


class IntegrationConfigRequest(BaseModel):
    """Request model for configuring integrations"""
    integration_type: str
    config: Dict[str, Any]
    enabled: bool = True


class ActionExecutionRequest(BaseModel):
    """Request model for executing actions"""
    action_type: ActionType
    target: str
    context: Dict[str, Any] = {}
    preferred_integrations: Optional[List[str]] = None


class BulkActionRequest(BaseModel):
    """Request model for bulk action execution"""
    actions: List[Dict[str, Any]]
    context: Dict[str, Any] = {}


class IntegrationTestRequest(BaseModel):
    """Request model for testing integrations"""
    integration_name: str
    test_connection: bool = True
    test_action: Optional[ActionType] = None


@router.get("/", response_model=Dict[str, Any], summary="List All Integrations")
async def list_integrations(
    current_user: str = Depends(get_current_user)
):
    """
    Get list of all configured integrations and their status
    """
    try:
        global integration_registry
        if not integration_registry:
            # Initialize integration registry from SOC agent
            from agent.integrations.registry import IntegrationRegistry
            integration_registry = IntegrationRegistry({})
        
        status = integration_registry.get_registry_status()
        
        return {
            "integrations": status["integration_status"],
            "summary": {
                "total_configured": status["total_configured"],
                "total_active": status["total_active"],
                "capabilities": status["capabilities"]
            }
        }
        
    except Exception as e:
        logger.error(f"Error listing integrations: {str(e)}")
        raise HTTPException(status_code=500, detail=f"Failed to list integrations: {str(e)}")


@router.get("/types", response_model=Dict[str, str], summary="Get Available Integration Types")
async def get_integration_types(
    current_user: str = Depends(get_current_user)
):
    """
    Get all available integration types that can be configured
    """
    try:
        from agent.integrations.registry import IntegrationRegistry
        return IntegrationRegistry.get_available_integration_types()
        
    except Exception as e:
        logger.error(f"Error getting integration types: {str(e)}")
        raise HTTPException(status_code=500, detail=f"Failed to get integration types: {str(e)}")


@router.get("/actions", response_model=List[str], summary="Get Available Action Types")
async def get_action_types(
    current_user: str = Depends(get_current_user)
):
    """
    Get all available action types that can be executed
    """
    try:
        return [action.value for action in ActionType]
        
    except Exception as e:
        logger.error(f"Error getting action types: {str(e)}")
        raise HTTPException(status_code=500, detail=f"Failed to get action types: {str(e)}")


@router.get("/{integration_name}", response_model=Dict[str, Any], summary="Get Integration Details")
async def get_integration(
    integration_name: str,
    current_user: str = Depends(get_current_user)
):
    """
    Get detailed information about a specific integration
    """
    try:
        global integration_registry
        if not integration_registry:
            raise HTTPException(status_code=404, detail="Integration registry not initialized")
        
        integration = integration_registry.get_integration(integration_name)
        if not integration:
            raise HTTPException(status_code=404, detail=f"Integration {integration_name} not found")
        
        return {
            "name": integration_name,
            "type": integration.integration_type.value,
            "status": integration.get_status(),
            "supported_actions": [action.value for action in integration.get_supported_actions()]
        }
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error getting integration {integration_name}: {str(e)}")
        raise HTTPException(status_code=500, detail=f"Failed to get integration: {str(e)}")


@router.post("/{integration_name}/test", response_model=Dict[str, Any], summary="Test Integration")
async def test_integration(
    integration_name: str,
    current_user: str = Depends(get_current_user)
):
    """
    Test connection and functionality of a specific integration
    """
    try:
        global integration_registry
        if not integration_registry:
            raise HTTPException(status_code=404, detail="Integration registry not initialized")
        
        test_result = await integration_registry.test_integration(integration_name)
        
        return {
            "integration_name": integration_name,
            "test_result": test_result,
            "tested_at": datetime.utcnow().isoformat()
        }
        
    except Exception as e:
        logger.error(f"Error testing integration {integration_name}: {str(e)}")
        raise HTTPException(status_code=500, detail=f"Failed to test integration: {str(e)}")


@router.post("/actions/execute", response_model=Dict[str, Any], summary="Execute Single Action")
async def execute_action(
    request: ActionExecutionRequest,
    background_tasks: BackgroundTasks,
    current_user: str = Depends(get_current_user)
):
    """
    Execute a single action across relevant integrations
    """
    try:
        global integration_registry
        if not integration_registry:
            raise HTTPException(status_code=404, detail="Integration registry not initialized")
        
        # Add audit context
        audit_context = {
            **request.context,
            "executed_by": current_user,
            "executed_at": datetime.utcnow().isoformat()
        }
        
        response = await integration_registry.execute_action(
            action_type=request.action_type,
            target=request.target,
            context=audit_context,
            preferred_integrations=request.preferred_integrations
        )
        
        return {
            "action_type": request.action_type.value,
            "target": request.target,
            "execution_result": {
                "success": response.success,
                "actions_executed": len(response.actions_executed),
                "successful_actions": len([a for a in response.actions_executed if a.success]),
                "total_execution_time": response.total_execution_time,
                "metadata": response.metadata
            },
            "details": [
                {
                    "success": action.success,
                    "action_type": action.action_type.value,
                    "target": action.target,
                    "execution_time": action.execution_time,
                    "reference_id": action.reference_id,
                    "error_message": action.error_message
                }
                for action in response.actions_executed
            ]
        }
        
    except Exception as e:
        logger.error(f"Error executing action: {str(e)}")
        raise HTTPException(status_code=500, detail=f"Failed to execute action: {str(e)}")


@router.post("/actions/bulk", response_model=Dict[str, Any], summary="Execute Multiple Actions")
async def execute_bulk_actions(
    request: BulkActionRequest,
    background_tasks: BackgroundTasks,
    current_user: str = Depends(get_current_user)
):
    """
    Execute multiple actions in bulk across integrations
    """
    try:
        global integration_registry
        if not integration_registry:
            raise HTTPException(status_code=404, detail="Integration registry not initialized")
        
        # Add audit context
        audit_context = {
            **request.context,
            "executed_by": current_user,
            "executed_at": datetime.utcnow().isoformat(),
            "bulk_execution": True
        }
        
        responses = await integration_registry.execute_response_actions(
            recommended_actions=request.actions,
            context=audit_context
        )
        
        # Aggregate results
        total_actions = len(responses)
        successful_actions = len([r for r in responses if r.success])
        total_execution_time = sum(r.total_execution_time for r in responses)
        
        return {
            "bulk_execution_id": f"bulk_{hash(str(request.actions)) % 100000}",
            "summary": {
                "total_actions": total_actions,
                "successful_actions": successful_actions,
                "failed_actions": total_actions - successful_actions,
                "total_execution_time": total_execution_time
            },
            "results": [
                {
                    "success": response.success,
                    "integration_name": response.integration_name,
                    "actions_count": len(response.actions_executed),
                    "execution_time": response.total_execution_time,
                    "metadata": response.metadata,
                    "error_details": response.error_details
                }
                for response in responses
            ]
        }
        
    except Exception as e:
        logger.error(f"Error executing bulk actions: {str(e)}")
        raise HTTPException(status_code=500, detail=f"Failed to execute bulk actions: {str(e)}")


@router.get("/capabilities/{action_type}", response_model=Dict[str, Any], summary="Get Action Capabilities")
async def get_action_capabilities(
    action_type: ActionType,
    current_user: str = Depends(get_current_user)
):
    """
    Get which integrations support a specific action type
    """
    try:
        global integration_registry
        if not integration_registry:
            raise HTTPException(status_code=404, detail="Integration registry not initialized")
        
        supporting_integrations = integration_registry.get_integrations_by_action(action_type)
        
        capabilities = []
        for integration in supporting_integrations:
            capabilities.append({
                "name": integration.name,
                "type": integration.integration_type.value,
                "connected": integration.is_connected,
                "status": integration.get_status()
            })
        
        return {
            "action_type": action_type.value,
            "supporting_integrations": len(capabilities),
            "capabilities": capabilities
        }
        
    except Exception as e:
        logger.error(f"Error getting capabilities for {action_type}: {str(e)}")
        raise HTTPException(status_code=500, detail=f"Failed to get capabilities: {str(e)}")


@router.post("/connect", response_model=Dict[str, Any], summary="Connect All Integrations")
async def connect_integrations(
    background_tasks: BackgroundTasks,
    current_user: str = Depends(get_current_user)
):
    """
    Connect to all configured integrations
    """
    try:
        global integration_registry
        if not integration_registry:
            from agent.integrations.registry import IntegrationRegistry
            integration_registry = IntegrationRegistry({})
        
        connection_results = await integration_registry.connect_all()
        
        successful_connections = len([r for r in connection_results.values() if r])
        total_integrations = len(connection_results)
        
        return {
            "message": "Connection process completed",
            "summary": {
                "total_integrations": total_integrations,
                "successful_connections": successful_connections,
                "failed_connections": total_integrations - successful_connections
            },
            "connection_results": connection_results,
            "connected_at": datetime.utcnow().isoformat()
        }
        
    except Exception as e:
        logger.error(f"Error connecting integrations: {str(e)}")
        raise HTTPException(status_code=500, detail=f"Failed to connect integrations: {str(e)}")


@router.post("/disconnect", response_model=Dict[str, Any], summary="Disconnect All Integrations")
async def disconnect_integrations(
    current_user: str = Depends(get_current_user)
):
    """
    Disconnect from all active integrations
    """
    try:
        global integration_registry
        if not integration_registry:
            return {"message": "No active integrations to disconnect"}
        
        disconnection_results = await integration_registry.disconnect_all()
        
        return {
            "message": "Disconnection process completed",
            "disconnection_results": disconnection_results,
            "disconnected_at": datetime.utcnow().isoformat()
        }
        
    except Exception as e:
        logger.error(f"Error disconnecting integrations: {str(e)}")
        raise HTTPException(status_code=500, detail=f"Failed to disconnect integrations: {str(e)}")


@router.get("/health", response_model=Dict[str, Any], summary="Health Check All Integrations")
async def health_check_integrations(
    current_user: str = Depends(get_current_user)
):
    """
    Perform health check on all active integrations
    """
    try:
        global integration_registry
        if not integration_registry:
            return {"message": "Integration registry not initialized", "healthy_integrations": 0}
        
        health_results = await integration_registry._health_check()
        healthy_count = len([r for r in health_results.values() if r])
        
        return {
            "health_check_completed": True,
            "total_integrations": len(health_results),
            "healthy_integrations": healthy_count,
            "unhealthy_integrations": len(health_results) - healthy_count,
            "health_results": health_results,
            "checked_at": datetime.utcnow().isoformat()
        }
        
    except Exception as e:
        logger.error(f"Error performing health check: {str(e)}")
        raise HTTPException(status_code=500, detail=f"Failed to perform health check: {str(e)}")


@router.get("/logs/{integration_name}", response_model=Dict[str, Any], summary="Get Integration Logs")
async def get_integration_logs(
    integration_name: str,
    limit: int = 100,
    current_user: str = Depends(get_current_user)
):
    """
    Get recent logs for a specific integration (mock implementation)
    """
    try:
        # This is a mock implementation
        # In production, this would fetch actual logs from logging system
        
        mock_logs = [
            {
                "timestamp": datetime.utcnow().isoformat(),
                "level": "INFO",
                "message": f"Integration {integration_name} is operational",
                "details": {"action": "status_check", "result": "success"}
            },
            {
                "timestamp": datetime.utcnow().isoformat(),
                "level": "DEBUG",
                "message": f"Connection test successful for {integration_name}",
                "details": {"response_time": "0.25s"}
            }
        ]
        
        return {
            "integration_name": integration_name,
            "logs": mock_logs[:limit],
            "total_logs": len(mock_logs),
            "fetched_at": datetime.utcnow().isoformat()
        }
        
    except Exception as e:
        logger.error(f"Error getting logs for {integration_name}: {str(e)}")
        raise HTTPException(status_code=500, detail=f"Failed to get logs: {str(e)}")


@router.get("/metrics", response_model=Dict[str, Any], summary="Get Integration Metrics")
async def get_integration_metrics(
    timeframe: str = "24h",
    current_user: str = Depends(get_current_user)
):
    """
    Get metrics for all integrations (mock implementation)
    """
    try:
        # Mock metrics implementation
        # In production, this would fetch actual metrics from monitoring system
        
        mock_metrics = {
            "timeframe": timeframe,
            "total_actions_executed": 156,
            "successful_actions": 148,
            "failed_actions": 8,
            "average_response_time": 1.2,
            "integration_usage": {
                "slack": {"actions": 45, "success_rate": 0.98},
                "email": {"actions": 32, "success_rate": 1.0},
                "palo_alto": {"actions": 28, "success_rate": 0.89},
                "splunk": {"actions": 51, "success_rate": 0.96}
            },
            "action_breakdown": {
                "send_alert": 67,
                "block_ip": 28,
                "create_incident": 35,
                "notify": 26
            }
        }
        
        return {
            "metrics": mock_metrics,
            "collected_at": datetime.utcnow().isoformat()
        }
        
    except Exception as e:
        logger.error(f"Error getting integration metrics: {str(e)}")
        raise HTTPException(status_code=500, detail=f"Failed to get metrics: {str(e)}") 