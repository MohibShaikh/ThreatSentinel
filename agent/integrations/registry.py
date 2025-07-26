"""
Integration Registry for Managing SOC Tool Integrations
"""

import asyncio
import logging
from typing import Dict, Any, List, Optional, Type
from .base import BaseIntegration, IntegrationResponse, IntegrationType, ActionType, ActionResult
from .firewall import PaloAltoIntegration, FortinetIntegration, PfSenseIntegration
from .siem import SplunkIntegration, QRadarIntegration, SentinelIntegration
from .communication import SlackIntegration, TeamsIntegration, EmailIntegration
from .incident import ServiceNowIntegration, JiraIntegration, PagerDutyIntegration


class IntegrationRegistry:
    """
    Central registry for managing all SOC tool integrations
    
    Provides unified interface for discovering, configuring, and executing
    actions across multiple security tools and platforms.
    """
    
    # Available integration classes
    AVAILABLE_INTEGRATIONS = {
        # Firewall integrations
        "palo_alto": PaloAltoIntegration,
        "fortinet": FortinetIntegration,
        "pfsense": PfSenseIntegration,
        
        # SIEM integrations
        "splunk": SplunkIntegration,
        "qradar": QRadarIntegration,
        "azure_sentinel": SentinelIntegration,
        
        # Communication integrations
        "slack": SlackIntegration,
        "teams": TeamsIntegration,
        "email": EmailIntegration,
        
        # Incident Response integrations
        "servicenow": ServiceNowIntegration,
        "jira": JiraIntegration,
        "pagerduty": PagerDutyIntegration
    }
    
    def __init__(self, config: Dict[str, Any]):
        self.config = config
        self.logger = logging.getLogger(__name__)
        self.integrations: Dict[str, BaseIntegration] = {}
        self.active_integrations: Dict[str, BaseIntegration] = {}
        
        # Initialize configured integrations
        self._initialize_integrations()
    
    def _initialize_integrations(self):
        """Initialize all configured integrations"""
        integrations_config = self.config.get("integrations", {})
        
        for integration_name, integration_config in integrations_config.items():
            if integration_name in self.AVAILABLE_INTEGRATIONS:
                try:
                    integration_class = self.AVAILABLE_INTEGRATIONS[integration_name]
                    integration = integration_class(integration_config)
                    self.integrations[integration_name] = integration
                    self.logger.info(f"Registered integration: {integration_name}")
                except Exception as e:
                    self.logger.error(f"Failed to initialize {integration_name}: {e}")
            else:
                self.logger.warning(f"Unknown integration type: {integration_name}")
        
        self.logger.info(f"Initialized {len(self.integrations)} integrations")
    
    async def connect_all(self) -> Dict[str, bool]:
        """Connect to all configured integrations"""
        connection_results = {}
        
        for name, integration in self.integrations.items():
            try:
                connected = await integration.connect()
                connection_results[name] = connected
                
                if connected:
                    self.active_integrations[name] = integration
                    self.logger.info(f"Connected to {name}")
                else:
                    self.logger.warning(f"Failed to connect to {name}")
                    
            except Exception as e:
                self.logger.error(f"Error connecting to {name}: {e}")
                connection_results[name] = False
        
        self.logger.info(f"Connected to {len(self.active_integrations)}/{len(self.integrations)} integrations")
        return connection_results
    
    async def disconnect_all(self) -> Dict[str, bool]:
        """Disconnect from all active integrations"""
        disconnection_results = {}
        
        for name, integration in self.active_integrations.items():
            try:
                disconnected = await integration.disconnect()
                disconnection_results[name] = disconnected
                self.logger.info(f"Disconnected from {name}")
            except Exception as e:
                self.logger.error(f"Error disconnecting from {name}: {e}")
                disconnection_results[name] = False
        
        self.active_integrations.clear()
        return disconnection_results
    
    def get_integrations_by_type(self, integration_type: IntegrationType) -> List[BaseIntegration]:
        """Get all active integrations of a specific type"""
        return [
            integration for integration in self.active_integrations.values()
            if integration.integration_type == integration_type
        ]
    
    def get_integrations_by_action(self, action_type: ActionType) -> List[BaseIntegration]:
        """Get all active integrations that support a specific action"""
        return [
            integration for integration in self.active_integrations.values()
            if integration.is_action_supported(action_type)
        ]
    
    def get_integration(self, name: str) -> Optional[BaseIntegration]:
        """Get a specific integration by name"""
        return self.active_integrations.get(name)
    
    async def execute_action(self, action_type: ActionType, target: str, 
                           context: Dict[str, Any],
                           preferred_integrations: Optional[List[str]] = None) -> IntegrationResponse:
        """
        Execute an action across relevant integrations
        
        Args:
            action_type: Type of action to execute
            target: Target for the action (IP, URL, etc.)
            context: Additional context for the action
            preferred_integrations: List of preferred integration names to use
            
        Returns:
            IntegrationResponse: Aggregated response from all integrations
        """
        start_time = asyncio.get_event_loop().time()
        
        # Get relevant integrations
        if preferred_integrations:
            relevant_integrations = [
                self.active_integrations[name] for name in preferred_integrations
                if name in self.active_integrations and 
                self.active_integrations[name].is_action_supported(action_type)
            ]
        else:
            relevant_integrations = self.get_integrations_by_action(action_type)
        
        if not relevant_integrations:
            return IntegrationResponse(
                integration_name="registry",
                integration_type=IntegrationType.SOAR,
                success=False,
                actions_executed=[],
                total_execution_time=0.0,
                error_details={"error": f"No integrations available for action {action_type.value}"}
            )
        
        # Execute action across all relevant integrations
        tasks = []
        for integration in relevant_integrations:
            task = integration.execute_action(action_type, target, context)
            tasks.append(task)
        
        results = await asyncio.gather(*tasks, return_exceptions=True)
        
        # Process results
        successful_results = []
        failed_results = []
        
        for i, result in enumerate(results):
            integration_name = relevant_integrations[i].name
            
            if isinstance(result, Exception):
                self.logger.error(f"Integration {integration_name} failed: {result}")
                failed_results.append(ActionResult(
                    success=False,
                    action_type=action_type,
                    target=target,
                    details={"integration": integration_name},
                    execution_time=0.0,
                    error_message=str(result)
                ))
            else:
                if result.success:
                    successful_results.append(result)
                    self.logger.info(f"Integration {integration_name} succeeded: {action_type.value}")
                else:
                    failed_results.append(result)
                    self.logger.warning(f"Integration {integration_name} failed: {result.error_message}")
        
        total_execution_time = asyncio.get_event_loop().time() - start_time
        
        return IntegrationResponse(
            integration_name="registry",
            integration_type=IntegrationType.SOAR,
            success=len(successful_results) > 0,
            actions_executed=successful_results + failed_results,
            total_execution_time=total_execution_time,
            metadata={
                "total_integrations": len(relevant_integrations),
                "successful_integrations": len(successful_results),
                "failed_integrations": len(failed_results),
                "integration_names": [i.name for i in relevant_integrations]
            }
        )
    
    async def execute_response_actions(self, recommended_actions: List[Dict[str, Any]], 
                                     context: Dict[str, Any]) -> List[IntegrationResponse]:
        """
        Execute a list of recommended actions from SOC analysis
        
        Args:
            recommended_actions: List of action dictionaries with type, target, and details
            context: Investigation context
            
        Returns:
            List[IntegrationResponse]: Results from all action executions
        """
        responses = []
        
        for action in recommended_actions:
            action_type = ActionType(action.get("action_type"))
            target = action.get("target", "")
            action_context = {**context, **action.get("context", {})}
            
            try:
                response = await self.execute_action(
                    action_type=action_type,
                    target=target,
                    context=action_context,
                    preferred_integrations=action.get("preferred_integrations")
                )
                responses.append(response)
                
                self.logger.info(f"Executed action {action_type.value} on {target}: {response.success}")
                
            except Exception as e:
                self.logger.error(f"Failed to execute action {action_type.value}: {e}")
                
                # Create error response
                error_response = IntegrationResponse(
                    integration_name="registry",
                    integration_type=IntegrationType.SOAR,
                    success=False,
                    actions_executed=[],
                    total_execution_time=0.0,
                    error_details={"error": str(e), "action": action}
                )
                responses.append(error_response)
        
        return responses
    
    def get_registry_status(self) -> Dict[str, Any]:
        """Get comprehensive status of all integrations"""
        status = {
            "total_configured": len(self.integrations),
            "total_active": len(self.active_integrations),
            "integration_status": {},
            "capabilities": self._get_capabilities_summary(),
            "health_check": asyncio.create_task(self._health_check())
        }
        
        for name, integration in self.integrations.items():
            status["integration_status"][name] = {
                "type": integration.integration_type.value,
                "connected": name in self.active_integrations,
                "supported_actions": [action.value for action in integration.get_supported_actions()],
                "status": integration.get_status()
            }
        
        return status
    
    def _get_capabilities_summary(self) -> Dict[str, List[str]]:
        """Get summary of capabilities by action type"""
        capabilities = {}
        
        for action_type in ActionType:
            supporting_integrations = [
                integration.name for integration in self.active_integrations.values()
                if integration.is_action_supported(action_type)
            ]
            if supporting_integrations:
                capabilities[action_type.value] = supporting_integrations
        
        return capabilities
    
    async def _health_check(self) -> Dict[str, bool]:
        """Perform health check on all active integrations"""
        health_results = {}
        
        for name, integration in self.active_integrations.items():
            try:
                health_results[name] = await integration.test_connection()
            except Exception as e:
                self.logger.error(f"Health check failed for {name}: {e}")
                health_results[name] = False
        
        return health_results
    
    async def test_integration(self, integration_name: str) -> Dict[str, Any]:
        """Test a specific integration"""
        if integration_name not in self.integrations:
            return {
                "success": False,
                "error": f"Integration {integration_name} not found"
            }
        
        integration = self.integrations[integration_name]
        
        try:
            # Test connection
            connection_test = await integration.test_connection()
            
            # Get supported actions
            supported_actions = integration.get_supported_actions()
            
            # Get current status
            status = integration.get_status()
            
            return {
                "success": connection_test,
                "integration_name": integration_name,
                "type": integration.integration_type.value,
                "connection_test": connection_test,
                "supported_actions": [action.value for action in supported_actions],
                "status": status
            }
            
        except Exception as e:
            return {
                "success": False,
                "integration_name": integration_name,
                "error": str(e)
            }
    
    def add_integration(self, name: str, integration_class: Type[BaseIntegration], 
                       config: Dict[str, Any]) -> bool:
        """Dynamically add a new integration"""
        try:
            integration = integration_class(config)
            self.integrations[name] = integration
            self.logger.info(f"Added integration: {name}")
            return True
        except Exception as e:
            self.logger.error(f"Failed to add integration {name}: {e}")
            return False
    
    def remove_integration(self, name: str) -> bool:
        """Remove an integration"""
        try:
            if name in self.active_integrations:
                # Disconnect first
                asyncio.create_task(self.active_integrations[name].disconnect())
                del self.active_integrations[name]
            
            if name in self.integrations:
                del self.integrations[name]
                self.logger.info(f"Removed integration: {name}")
                return True
            
            return False
        except Exception as e:
            self.logger.error(f"Failed to remove integration {name}: {e}")
            return False
    
    @classmethod
    def get_available_integration_types(cls) -> Dict[str, str]:
        """Get all available integration types and their classes"""
        return {
            name: integration_class.__name__ 
            for name, integration_class in cls.AVAILABLE_INTEGRATIONS.items()
        } 