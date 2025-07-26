"""
AITIA SOC Agent - Monitoring Routes

API routes for real-time monitoring, metrics, and system health.
"""

import asyncio
import logging
import psutil
import time
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Any

from fastapi import APIRouter, HTTPException, Depends, WebSocket, WebSocketDisconnect, Query, status
from fastapi.responses import JSONResponse

from ..models import (
    MonitoringMetrics,
    AlertConfiguration,
    EventSubscription,
    HealthResponse,
    ErrorResponse
)
from ..config import get_settings
from ...agent import SOCAgentPlanner


# Create router
router = APIRouter()

logger = logging.getLogger(__name__)

# Global monitoring state
metrics_history: List[Dict[str, Any]] = []
active_websockets: List[WebSocket] = []
alert_config = AlertConfiguration()
subscriptions: Dict[str, EventSubscription] = {}


def get_soc_agent() -> SOCAgentPlanner:
    """Dependency to get SOC agent instance"""
    from ..main import soc_agent
    if soc_agent is None:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="SOC Agent not initialized"
        )
    return soc_agent


@router.get("/metrics", response_model=MonitoringMetrics)
async def get_current_metrics(agent: SOCAgentPlanner = Depends(get_soc_agent)):
    """
    Get current system metrics
    
    Returns real-time metrics including active investigations,
    performance statistics, and resource usage.
    """
    try:
        # Get investigation data
        from ..routes.investigations import active_investigations, investigation_history
        
        # Calculate today's metrics
        today = datetime.utcnow().date()
        today_investigations = [
            inv for inv in investigation_history
            if inv.get('created_at', datetime.min).date() == today
        ]
        
        completed_today = len([
            inv for inv in today_investigations
            if inv.get('status') == 'completed'
        ])
        
        high_risk_today = len([
            inv for inv in today_investigations
            if inv.get('risk_level') in ['high', 'critical']
        ])
        
        # Calculate average investigation time for today
        completed_today_with_times = [
            inv for inv in today_investigations
            if inv.get('status') == 'completed' and 'completed_at' in inv and 'created_at' in inv
        ]
        
        if completed_today_with_times:
            total_time = sum([
                (inv['completed_at'] - inv['created_at']).total_seconds()
                for inv in completed_today_with_times
            ])
            avg_time = total_time / len(completed_today_with_times)
        else:
            avg_time = 0.0
        
        # Get memory stats
        memory_stats = await agent.memory.get_memory_stats()
        
        # Get API call statistics (mock for now)
        threat_intel_calls = {
            'virustotal': 45,
            'abuseipdb': 32,
            'urlvoid': 18,
            'shodan': 12
        }
        
        # System metrics
        memory_usage = psutil.virtual_memory().used / (1024 * 1024)  # MB
        
        # Mock error rate (would be calculated from actual errors)
        error_rate = 2.1  # percentage
        
        metrics = MonitoringMetrics(
            timestamp=datetime.utcnow(),
            active_investigations=len(active_investigations),
            completed_investigations_today=completed_today,
            average_investigation_time=avg_time,
            high_risk_events_today=high_risk_today,
            api_response_time=150.0,  # Mock value
            memory_usage_mb=memory_usage,
            threat_intel_api_calls=threat_intel_calls,
            error_rate=error_rate
        )
        
        # Store in history (keep last 1000 entries)
        metrics_history.append(metrics.dict())
        if len(metrics_history) > 1000:
            metrics_history.pop(0)
        
        return metrics
        
    except Exception as e:
        logger.error(f"Failed to get metrics: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to get metrics: {str(e)}"
        )


@router.get("/metrics/history")
async def get_metrics_history(
    hours: int = Query(24, ge=1, le=168, description="Hours of history to retrieve"),
    resolution: str = Query("hour", description="Data resolution (minute, hour, day)")
):
    """
    Get historical metrics data
    
    Returns time-series data for charting and trend analysis.
    """
    try:
        # Filter metrics by time range
        cutoff_time = datetime.utcnow() - timedelta(hours=hours)
        
        filtered_metrics = [
            m for m in metrics_history
            if datetime.fromisoformat(m['timestamp']) >= cutoff_time
        ]
        
        # Aggregate by resolution if needed
        if resolution == "hour" and len(filtered_metrics) > 100:
            # Group by hour and average
            hourly_data = {}
            for metric in filtered_metrics:
                hour_key = datetime.fromisoformat(metric['timestamp']).replace(minute=0, second=0, microsecond=0)
                if hour_key not in hourly_data:
                    hourly_data[hour_key] = []
                hourly_data[hour_key].append(metric)
            
            aggregated_metrics = []
            for hour, hour_metrics in hourly_data.items():
                avg_metric = {
                    'timestamp': hour.isoformat(),
                    'active_investigations': sum(m['active_investigations'] for m in hour_metrics) / len(hour_metrics),
                    'average_investigation_time': sum(m['average_investigation_time'] for m in hour_metrics) / len(hour_metrics),
                    'api_response_time': sum(m['api_response_time'] for m in hour_metrics) / len(hour_metrics),
                    'memory_usage_mb': sum(m['memory_usage_mb'] for m in hour_metrics) / len(hour_metrics),
                    'error_rate': sum(m['error_rate'] for m in hour_metrics) / len(hour_metrics),
                    'data_points': len(hour_metrics)
                }
                aggregated_metrics.append(avg_metric)
            
            filtered_metrics = aggregated_metrics
        
        return {
            'metrics': filtered_metrics,
            'total_points': len(filtered_metrics),
            'time_range_hours': hours,
            'resolution': resolution,
            'start_time': cutoff_time.isoformat(),
            'end_time': datetime.utcnow().isoformat()
        }
        
    except Exception as e:
        logger.error(f"Failed to get metrics history: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to get metrics history: {str(e)}"
        )


@router.websocket("/metrics/stream")
async def metrics_websocket(websocket: WebSocket):
    """
    WebSocket endpoint for real-time metrics streaming
    
    Provides live updates of system metrics for dashboards.
    """
    await websocket.accept()
    active_websockets.append(websocket)
    
    try:
        while True:
            # Send current metrics every 5 seconds
            try:
                # Get current metrics (simplified version)
                from ..routes.investigations import active_investigations, investigation_history
                
                current_metrics = {
                    'timestamp': datetime.utcnow().isoformat(),
                    'active_investigations': len(active_investigations),
                    'memory_usage_mb': psutil.virtual_memory().used / (1024 * 1024),
                    'recent_investigations': len([
                        inv for inv in investigation_history
                        if (datetime.utcnow() - inv.get('created_at', datetime.min)).total_seconds() < 3600
                    ]),
                    'websocket_connections': len(active_websockets)
                }
                
                await websocket.send_json(current_metrics)
                await asyncio.sleep(5)
                
            except WebSocketDisconnect:
                break
            except Exception as e:
                logger.error(f"Error in metrics websocket: {e}")
                break
                
    except WebSocketDisconnect:
        pass
    finally:
        if websocket in active_websockets:
            active_websockets.remove(websocket)


@router.get("/alerts/config", response_model=AlertConfiguration)
async def get_alert_config():
    """Get current alert configuration"""
    return alert_config


@router.put("/alerts/config", response_model=AlertConfiguration)
async def update_alert_config(config: AlertConfiguration):
    """Update alert configuration"""
    global alert_config
    alert_config = config
    logger.info(f"Updated alert configuration: {config.dict()}")
    return alert_config


@router.get("/alerts/recent")
async def get_recent_alerts(
    hours: int = Query(24, ge=1, le=168, description="Hours of history to retrieve"),
    limit: int = Query(50, le=200, description="Maximum alerts to return")
):
    """
    Get recent alerts triggered by the system
    
    Returns alerts based on current configuration and investigation results.
    """
    try:
        # Get recent high-risk investigations that would trigger alerts
        from ..routes.investigations import investigation_history
        
        cutoff_time = datetime.utcnow() - timedelta(hours=hours)
        
        recent_alerts = []
        for inv in investigation_history:
            if inv.get('created_at', datetime.min) < cutoff_time:
                continue
            
            risk_level = inv.get('risk_level', 'low')
            if risk_level in ['high', 'critical']:
                alert = {
                    'alert_id': f"alert_{inv['id']}",
                    'investigation_id': inv['id'],
                    'alert_type': 'high_risk_investigation',
                    'risk_level': risk_level,
                    'event_type': inv.get('request', {}).get('event_data', {}).get('event_type'),
                    'source_ip': inv.get('request', {}).get('event_data', {}).get('source_ip'),
                    'triggered_at': inv.get('completed_at', inv.get('created_at')),
                    'status': 'triggered',
                    'message': f"High risk {risk_level} investigation completed for {inv.get('request', {}).get('event_data', {}).get('event_type', 'unknown')} event"
                }
                recent_alerts.append(alert)
        
        # Sort by trigger time (newest first)
        recent_alerts.sort(key=lambda x: x['triggered_at'], reverse=True)
        
        # Apply limit
        recent_alerts = recent_alerts[:limit]
        
        return {
            'alerts': recent_alerts,
            'total_count': len(recent_alerts),
            'time_range_hours': hours,
            'alert_config': alert_config.dict()
        }
        
    except Exception as e:
        logger.error(f"Failed to get recent alerts: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to get recent alerts: {str(e)}"
        )


@router.post("/subscriptions", response_model=EventSubscription)
async def create_subscription(subscription: EventSubscription):
    """
    Create a new event subscription
    
    Subscribe to real-time notifications for specific event types or risk levels.
    """
    try:
        # Generate subscription ID if not provided
        if not hasattr(subscription, 'subscription_id') or not subscription.subscription_id:
            subscription.subscription_id = f"sub_{datetime.utcnow().strftime('%Y%m%d_%H%M%S')}"
        
        subscriptions[subscription.subscription_id] = subscription
        
        logger.info(f"Created subscription {subscription.subscription_id}")
        
        return subscription
        
    except Exception as e:
        logger.error(f"Failed to create subscription: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to create subscription: {str(e)}"
        )


@router.get("/subscriptions")
async def list_subscriptions():
    """List all active event subscriptions"""
    return {
        'subscriptions': list(subscriptions.values()),
        'total_count': len(subscriptions)
    }


@router.get("/subscriptions/{subscription_id}", response_model=EventSubscription)
async def get_subscription(subscription_id: str):
    """Get a specific subscription by ID"""
    if subscription_id not in subscriptions:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Subscription {subscription_id} not found"
        )
    
    return subscriptions[subscription_id]


@router.delete("/subscriptions/{subscription_id}")
async def delete_subscription(subscription_id: str):
    """Delete a subscription"""
    if subscription_id not in subscriptions:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Subscription {subscription_id} not found"
        )
    
    del subscriptions[subscription_id]
    logger.info(f"Deleted subscription {subscription_id}")
    
    return {"message": f"Subscription {subscription_id} deleted successfully"}


@router.get("/system/status")
async def get_system_status(agent: SOCAgentPlanner = Depends(get_soc_agent)):
    """
    Get detailed system status information
    
    Returns comprehensive system health and performance data.
    """
    try:
        # System resource information
        cpu_percent = psutil.cpu_percent(interval=1)
        memory = psutil.virtual_memory()
        disk = psutil.disk_usage('/')
        
        # Agent-specific status
        memory_stats = await agent.memory.get_memory_stats()
        tool_capabilities = agent.tools.get_tool_capabilities()
        
        # Investigation statistics
        from ..routes.investigations import active_investigations, investigation_history
        
        status_info = {
            'system': {
                'cpu_percent': cpu_percent,
                'memory_percent': memory.percent,
                'memory_used_gb': round(memory.used / (1024**3), 2),
                'memory_total_gb': round(memory.total / (1024**3), 2),
                'disk_used_gb': round(disk.used / (1024**3), 2),
                'disk_total_gb': round(disk.total / (1024**3), 2),
                'disk_percent': round((disk.used / disk.total) * 100, 1)
            },
            'agent': {
                'status': 'healthy',
                'available_tools': len(agent.tools.get_available_tools()),
                'tool_capabilities': tool_capabilities,
                'memory_investigations': memory_stats.get('total_investigations', 0),
                'patterns_learned': memory_stats.get('patterns_learned', 0)
            },
            'investigations': {
                'active_count': len(active_investigations),
                'historical_count': len(investigation_history),
                'recent_24h': len([
                    inv for inv in investigation_history
                    if (datetime.utcnow() - inv.get('created_at', datetime.min)).total_seconds() < 86400
                ])
            },
            'monitoring': {
                'websocket_connections': len(active_websockets),
                'subscriptions_count': len(subscriptions),
                'alerts_enabled': alert_config.enabled,
                'metrics_history_points': len(metrics_history)
            },
            'timestamp': datetime.utcnow()
        }
        
        return status_info
        
    except Exception as e:
        logger.error(f"Failed to get system status: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to get system status: {str(e)}"
        )


@router.post("/system/restart")
async def restart_agent(agent: SOCAgentPlanner = Depends(get_soc_agent)):
    """
    Restart the SOC Agent
    
    Reinitializes the agent with current configuration.
    """
    try:
        # In a real implementation, this would restart the agent process
        logger.info("Agent restart requested")
        
        # For now, just return a success message
        return {
            'message': 'Agent restart initiated',
            'timestamp': datetime.utcnow(),
            'status': 'success'
        }
        
    except Exception as e:
        logger.error(f"Failed to restart agent: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to restart agent: {str(e)}"
        )


@router.get("/performance/stats")
async def get_performance_stats():
    """
    Get performance statistics and benchmarks
    
    Returns detailed performance metrics and trend analysis.
    """
    try:
        # Calculate performance statistics from metrics history
        if not metrics_history:
            return {
                'message': 'No performance data available yet',
                'stats': {}
            }
        
        # Get last 100 metrics for statistics
        recent_metrics = metrics_history[-100:]
        
        # Calculate averages and trends
        avg_investigation_time = sum(m['average_investigation_time'] for m in recent_metrics) / len(recent_metrics)
        avg_api_response_time = sum(m['api_response_time'] for m in recent_metrics) / len(recent_metrics)
        avg_memory_usage = sum(m['memory_usage_mb'] for m in recent_metrics) / len(recent_metrics)
        avg_error_rate = sum(m['error_rate'] for m in recent_metrics) / len(recent_metrics)
        
        # Calculate trends (simple slope)
        def calculate_trend(values):
            if len(values) < 2:
                return 0
            return (values[-1] - values[0]) / len(values)
        
        investigation_times = [m['average_investigation_time'] for m in recent_metrics]
        memory_values = [m['memory_usage_mb'] for m in recent_metrics]
        
        performance_stats = {
            'averages': {
                'investigation_time_seconds': round(avg_investigation_time, 2),
                'api_response_time_ms': round(avg_api_response_time, 2),
                'memory_usage_mb': round(avg_memory_usage, 2),
                'error_rate_percent': round(avg_error_rate, 2)
            },
            'trends': {
                'investigation_time_trend': round(calculate_trend(investigation_times), 4),
                'memory_usage_trend': round(calculate_trend(memory_values), 4)
            },
            'metrics': {
                'sample_size': len(recent_metrics),
                'time_range_minutes': (datetime.utcnow() - datetime.fromisoformat(recent_metrics[0]['timestamp'])).total_seconds() / 60 if recent_metrics else 0
            },
            'thresholds': {
                'max_investigation_time': 300,  # 5 minutes
                'max_memory_usage_mb': 1024,    # 1GB
                'max_error_rate': 5.0           # 5%
            }
        }
        
        return performance_stats
        
    except Exception as e:
        logger.error(f"Failed to get performance stats: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to get performance stats: {str(e)}"
        ) 