"""
Base Integration Framework for SOC Tool Adapters
"""

from abc import ABC, abstractmethod
from typing import Dict, Any, List, Optional, Union
from enum import Enum
from dataclasses import dataclass
from datetime import datetime
import logging
import asyncio
import aiohttp
from pydantic import BaseModel


class IntegrationType(str, Enum):
    """Types of SOC tool integrations"""
    SIEM = "siem"
    FIREWALL = "firewall"
    INCIDENT_RESPONSE = "incident_response"
    COMMUNICATION = "communication"
    SOAR = "soar"
    ENDPOINT_PROTECTION = "endpoint_protection"
    THREAT_INTELLIGENCE = "threat_intelligence"


class ActionType(str, Enum):
    """Types of actions that can be executed"""
    BLOCK_IP = "block_ip"
    BLOCK_URL = "block_url"
    BLOCK_DOMAIN = "block_domain"
    CREATE_INCIDENT = "create_incident"
    UPDATE_INCIDENT = "update_incident"
    SEND_ALERT = "send_alert"
    QUARANTINE_ENDPOINT = "quarantine_endpoint"
    ADD_TO_WATCHLIST = "add_to_watchlist"
    CREATE_RULE = "create_rule"
    ESCALATE = "escalate"
    NOTIFY = "notify"


@dataclass
class ActionResult:
    """Result of an integration action"""
    success: bool
    action_type: ActionType
    target: str
    details: Dict[str, Any]
    execution_time: float
    error_message: Optional[str] = None
    reference_id: Optional[str] = None
    timestamp: datetime = None
    
    def __post_init__(self):
        if self.timestamp is None:
            self.timestamp = datetime.utcnow()


class IntegrationResponse(BaseModel):
    """Standardized response from integrations"""
    integration_name: str
    integration_type: IntegrationType
    success: bool
    actions_executed: List[ActionResult]
    total_execution_time: float
    error_details: Optional[Dict[str, Any]] = None
    metadata: Dict[str, Any] = {}


class BaseIntegration(ABC):
    """
    Abstract base class for all SOC tool integrations
    
    Provides standardized interface for connecting to and executing
    actions on various security tools.
    """
    
    def __init__(self, name: str, integration_type: IntegrationType, config: Dict[str, Any]):
        self.name = name
        self.integration_type = integration_type
        self.config = config
        self.logger = logging.getLogger(f"integration.{name}")
        self.session: Optional[aiohttp.ClientSession] = None
        self.is_connected = False
        self.rate_limiter = None
        
    async def __aenter__(self):
        """Async context manager entry"""
        await self.connect()
        return self
        
    async def __aexit__(self, exc_type, exc_val, exc_tb):
        """Async context manager exit"""
        await self.disconnect()
    
    @abstractmethod
    async def connect(self) -> bool:
        """
        Establish connection to the integration
        
        Returns:
            bool: True if connection successful
        """
        pass
    
    @abstractmethod
    async def disconnect(self) -> bool:
        """
        Close connection to the integration
        
        Returns:
            bool: True if disconnection successful
        """
        pass
    
    @abstractmethod
    async def test_connection(self) -> bool:
        """
        Test if the integration is accessible and configured correctly
        
        Returns:
            bool: True if connection test passes
        """
        pass
    
    @abstractmethod
    async def execute_action(self, action_type: ActionType, target: str, 
                           context: Dict[str, Any]) -> ActionResult:
        """
        Execute a specific action through this integration
        
        Args:
            action_type: Type of action to execute
            target: Target of the action (IP, URL, etc.)
            context: Additional context for the action
            
        Returns:
            ActionResult: Result of the action execution
        """
        pass
    
    @abstractmethod
    def get_supported_actions(self) -> List[ActionType]:
        """
        Get list of actions supported by this integration
        
        Returns:
            List[ActionType]: Supported action types
        """
        pass
    
    async def batch_execute(self, actions: List[Dict[str, Any]]) -> List[ActionResult]:
        """
        Execute multiple actions in batch
        
        Args:
            actions: List of action dictionaries with action_type, target, context
            
        Returns:
            List[ActionResult]: Results of all actions
        """
        results = []
        
        for action in actions:
            try:
                result = await self.execute_action(
                    action["action_type"],
                    action["target"],
                    action.get("context", {})
                )
                results.append(result)
            except Exception as e:
                self.logger.error(f"Batch action failed: {e}")
                results.append(ActionResult(
                    success=False,
                    action_type=action["action_type"],
                    target=action["target"],
                    details={},
                    execution_time=0.0,
                    error_message=str(e)
                ))
        
        return results
    
    def _create_session(self) -> aiohttp.ClientSession:
        """Create aiohttp session with common configuration"""
        timeout = aiohttp.ClientTimeout(total=30)
        headers = {
            'User-Agent': f'AITIA-SOC-Agent/{self.name}',
            'Content-Type': 'application/json'
        }
        
        return aiohttp.ClientSession(
            timeout=timeout,
            headers=headers
        )
    
    async def _make_request(self, method: str, url: str, **kwargs) -> Dict[str, Any]:
        """
        Make HTTP request with error handling and logging
        
        Args:
            method: HTTP method
            url: Request URL
            **kwargs: Additional request parameters
            
        Returns:
            Dict[str, Any]: Response data
        """
        start_time = asyncio.get_event_loop().time()
        
        try:
            async with self.session.request(method, url, **kwargs) as response:
                execution_time = asyncio.get_event_loop().time() - start_time
                
                if response.status >= 400:
                    error_text = await response.text()
                    self.logger.error(f"HTTP {response.status}: {error_text}")
                    raise Exception(f"HTTP {response.status}: {error_text}")
                
                data = await response.json()
                self.logger.debug(f"Request to {url} completed in {execution_time:.2f}s")
                
                return data
                
        except Exception as e:
            execution_time = asyncio.get_event_loop().time() - start_time
            self.logger.error(f"Request to {url} failed after {execution_time:.2f}s: {e}")
            raise
    
    def get_config_value(self, key: str, default: Any = None) -> Any:
        """Get configuration value with optional default"""
        return self.config.get(key, default)
    
    def is_action_supported(self, action_type: ActionType) -> bool:
        """Check if action type is supported by this integration"""
        return action_type in self.get_supported_actions()
    
    def get_status(self) -> Dict[str, Any]:
        """Get current status of the integration"""
        return {
            "name": self.name,
            "type": self.integration_type.value,
            "connected": self.is_connected,
            "supported_actions": [action.value for action in self.get_supported_actions()],
            "config_keys": list(self.config.keys())
        } 