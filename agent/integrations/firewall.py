"""
Firewall Integration Adapters
"""

import asyncio
from typing import Dict, Any, List
from .base import BaseIntegration, ActionResult, ActionType, IntegrationType
import xml.etree.ElementTree as ET


class PaloAltoIntegration(BaseIntegration):
    """
    Palo Alto Networks Firewall Integration
    
    Supports blocking IPs, URLs, and domains through PAN-OS API
    """
    
    def __init__(self, config: Dict[str, Any]):
        super().__init__("PaloAlto", IntegrationType.FIREWALL, config)
        self.api_key = config.get("api_key")
        self.hostname = config.get("hostname")
        self.port = config.get("port", 443)
        self.vsys = config.get("vsys", "vsys1")
        
    async def connect(self) -> bool:
        """Connect to PAN-OS API"""
        try:
            self.session = self._create_session()
            
            # Test connection with API key
            url = f"https://{self.hostname}:{self.port}/api/"
            params = {
                "type": "op",
                "cmd": "<show><system><info></info></system></show>",
                "key": self.api_key
            }
            
            await self._make_request("GET", url, params=params)
            self.is_connected = True
            self.logger.info("Connected to Palo Alto firewall")
            return True
            
        except Exception as e:
            self.logger.error(f"Failed to connect to Palo Alto: {e}")
            self.is_connected = False
            return False
    
    async def disconnect(self) -> bool:
        """Disconnect from PAN-OS API"""
        if self.session:
            await self.session.close()
            self.session = None
        self.is_connected = False
        return True
    
    async def test_connection(self) -> bool:
        """Test PAN-OS API connection"""
        return await self.connect()
    
    def get_supported_actions(self) -> List[ActionType]:
        """Get supported actions for Palo Alto"""
        return [
            ActionType.BLOCK_IP,
            ActionType.BLOCK_URL,
            ActionType.BLOCK_DOMAIN,
            ActionType.CREATE_RULE,
            ActionType.ADD_TO_WATCHLIST
        ]
    
    async def execute_action(self, action_type: ActionType, target: str, 
                           context: Dict[str, Any]) -> ActionResult:
        """Execute action on Palo Alto firewall"""
        start_time = asyncio.get_event_loop().time()
        
        try:
            if action_type == ActionType.BLOCK_IP:
                result = await self._block_ip(target, context)
            elif action_type == ActionType.BLOCK_URL:
                result = await self._block_url(target, context)
            elif action_type == ActionType.BLOCK_DOMAIN:
                result = await self._block_domain(target, context)
            elif action_type == ActionType.CREATE_RULE:
                result = await self._create_security_rule(target, context)
            else:
                raise ValueError(f"Unsupported action: {action_type}")
            
            execution_time = asyncio.get_event_loop().time() - start_time
            
            return ActionResult(
                success=True,
                action_type=action_type,
                target=target,
                details=result,
                execution_time=execution_time,
                reference_id=result.get("reference_id")
            )
            
        except Exception as e:
            execution_time = asyncio.get_event_loop().time() - start_time
            self.logger.error(f"Action {action_type} failed for {target}: {e}")
            
            return ActionResult(
                success=False,
                action_type=action_type,
                target=target,
                details={},
                execution_time=execution_time,
                error_message=str(e)
            )
    
    async def _block_ip(self, ip: str, context: Dict[str, Any]) -> Dict[str, Any]:
        """Block IP address by adding to address group"""
        url = f"https://{self.hostname}:{self.port}/api/"
        
        # Create address object
        address_name = f"blocked_ip_{ip.replace('.', '_')}"
        cmd = f"""
        <set>
            <address>
                <entry name="{address_name}">
                    <ip-netmask>{ip}</ip-netmask>
                    <description>Blocked by ThreatSentinel SOC Agent - {context.get('reason', 'Security threat')}</description>
                </entry>
            </address>
        </set>
        """
        
        params = {
            "type": "config",
            "action": "set",
            "xpath": f"/config/devices/entry[@name='localhost.localdomain']/vsys/entry[@name='{self.vsys}']/address",
            "element": f"<entry name='{address_name}'><ip-netmask>{ip}</ip-netmask></entry>",
            "key": self.api_key
        }
        
        response = await self._make_request("POST", url, params=params)
        
        # Add to blocked group
        await self._add_to_address_group(address_name, "ThreatSentinel_Blocked_IPs")
        
        return {
            "address_object": address_name,
            "action": "blocked",
            "reference_id": response.get("msg", {}).get("line", ""),
            "reason": context.get("reason", "Security threat")
        }
    
    async def _block_url(self, url: str, context: Dict[str, Any]) -> Dict[str, Any]:
        """Block URL by adding to URL filtering category"""
        # Add URL to custom category
        api_url = f"https://{self.hostname}:{self.port}/api/"
        
        params = {
            "type": "config",
            "action": "set",
            "xpath": f"/config/devices/entry[@name='localhost.localdomain']/vsys/entry[@name='{self.vsys}']/profiles/custom-url-category/entry[@name='ThreatSentinel_Blocked_URLs']/list",
            "element": f"<member>{url}</member>",
            "key": self.api_key
        }
        
        response = await self._make_request("POST", api_url, params=params)
        
        return {
            "url": url,
            "category": "ThreatSentinel_Blocked_URLs",
            "action": "blocked",
            "reference_id": response.get("msg", {}).get("line", "")
        }
    
    async def _block_domain(self, domain: str, context: Dict[str, Any]) -> Dict[str, Any]:
        """Block domain using DNS security or URL filtering"""
        return await self._block_url(f"*.{domain}", context)
    
    async def _create_security_rule(self, rule_name: str, context: Dict[str, Any]) -> Dict[str, Any]:
        """Create security rule to block traffic"""
        url = f"https://{self.hostname}:{self.port}/api/"
        
        source = context.get("source", "any")
        destination = context.get("destination", "any")
        action = context.get("action", "deny")
        
        rule_xml = f"""
        <entry name="{rule_name}">
            <from><member>any</member></from>
            <to><member>any</member></to>
            <source><member>{source}</member></source>
            <destination><member>{destination}</member></destination>
            <service><member>any</member></service>
            <application><member>any</member></application>
            <action>{action}</action>
            <description>Created by ThreatSentinel SOC Agent</description>
        </entry>
        """
        
        params = {
            "type": "config",
            "action": "set",
            "xpath": f"/config/devices/entry[@name='localhost.localdomain']/vsys/entry[@name='{self.vsys}']/rulebase/security/rules",
            "element": rule_xml,
            "key": self.api_key
        }
        
        response = await self._make_request("POST", url, params=params)
        
        return {
            "rule_name": rule_name,
            "action": action,
            "source": source,
            "destination": destination,
            "reference_id": response.get("msg", {}).get("line", "")
        }
    
    async def _add_to_address_group(self, address_name: str, group_name: str):
        """Add address object to address group"""
        url = f"https://{self.hostname}:{self.port}/api/"
        
        params = {
            "type": "config",
            "action": "set",
            "xpath": f"/config/devices/entry[@name='localhost.localdomain']/vsys/entry[@name='{self.vsys}']/address-group/entry[@name='{group_name}']/static",
            "element": f"<member>{address_name}</member>",
            "key": self.api_key
        }
        
        return await self._make_request("POST", url, params=params)


class FortinetIntegration(BaseIntegration):
    """
    Fortinet FortiGate Firewall Integration
    
    Supports blocking through FortiOS REST API
    """
    
    def __init__(self, config: Dict[str, Any]):
        super().__init__("Fortinet", IntegrationType.FIREWALL, config)
        self.api_key = config.get("api_key")
        self.hostname = config.get("hostname")
        self.port = config.get("port", 443)
        self.vdom = config.get("vdom", "root")
        
    async def connect(self) -> bool:
        """Connect to FortiOS API"""
        try:
            self.session = self._create_session()
            self.session.headers.update({"Authorization": f"Bearer {self.api_key}"})
            
            # Test connection
            url = f"https://{self.hostname}:{self.port}/api/v2/cmdb/system/status"
            await self._make_request("GET", url)
            
            self.is_connected = True
            self.logger.info("Connected to Fortinet firewall")
            return True
            
        except Exception as e:
            self.logger.error(f"Failed to connect to Fortinet: {e}")
            self.is_connected = False
            return False
    
    async def disconnect(self) -> bool:
        """Disconnect from FortiOS API"""
        if self.session:
            await self.session.close()
            self.session = None
        self.is_connected = False
        return True
    
    async def test_connection(self) -> bool:
        """Test FortiOS API connection"""
        return await self.connect()
    
    def get_supported_actions(self) -> List[ActionType]:
        """Get supported actions for Fortinet"""
        return [
            ActionType.BLOCK_IP,
            ActionType.BLOCK_URL,
            ActionType.BLOCK_DOMAIN,
            ActionType.CREATE_RULE
        ]
    
    async def execute_action(self, action_type: ActionType, target: str, 
                           context: Dict[str, Any]) -> ActionResult:
        """Execute action on Fortinet firewall"""
        start_time = asyncio.get_event_loop().time()
        
        try:
            if action_type == ActionType.BLOCK_IP:
                result = await self._block_ip(target, context)
            elif action_type == ActionType.BLOCK_URL:
                result = await self._block_url(target, context)
            elif action_type == ActionType.CREATE_RULE:
                result = await self._create_firewall_policy(target, context)
            else:
                raise ValueError(f"Unsupported action: {action_type}")
            
            execution_time = asyncio.get_event_loop().time() - start_time
            
            return ActionResult(
                success=True,
                action_type=action_type,
                target=target,
                details=result,
                execution_time=execution_time,
                reference_id=result.get("reference_id")
            )
            
        except Exception as e:
            execution_time = asyncio.get_event_loop().time() - start_time
            self.logger.error(f"Action {action_type} failed for {target}: {e}")
            
            return ActionResult(
                success=False,
                action_type=action_type,
                target=target,
                details={},
                execution_time=execution_time,
                error_message=str(e)
            )
    
    async def _block_ip(self, ip: str, context: Dict[str, Any]) -> Dict[str, Any]:
        """Block IP by adding to address object and policy"""
        # Create address object
        address_name = f"ThreatSentinel_Blocked_{ip.replace('.', '_')}"
        url = f"https://{self.hostname}:{self.port}/api/v2/cmdb/firewall/address"
        
        address_data = {
            "name": address_name,
            "type": "ipmask",
            "subnet": f"{ip}/32",
            "comment": f"Blocked by ThreatSentinel SOC Agent - {context.get('reason', 'Security threat')}"
        }
        
        response = await self._make_request("POST", url, json=address_data)
        
        return {
            "address_object": address_name,
            "ip": ip,
            "action": "blocked",
            "reference_id": response.get("mkey"),
            "reason": context.get("reason")
        }
    
    async def _block_url(self, url_path: str, context: Dict[str, Any]) -> Dict[str, Any]:
        """Block URL using web filter"""
        # Add to blocked URLs in web filter profile
        api_url = f"https://{self.hostname}:{self.port}/api/v2/cmdb/webfilter/urlfilter"
        
        url_data = {
            "name": f"ThreatSentinel_Blocked_URL_{hash(url_path) % 10000}",
            "entries": [
                {
                    "url": url_path,
                    "type": "simple",
                    "action": "block"
                }
            ],
            "comment": f"Blocked by ThreatSentinel SOC Agent - {context.get('reason', 'Security threat')}"
        }
        
        response = await self._make_request("POST", api_url, json=url_data)
        
        return {
            "url": url_path,
            "filter_name": url_data["name"],
            "action": "blocked",
            "reference_id": response.get("mkey")
        }
    
    async def _create_firewall_policy(self, policy_name: str, context: Dict[str, Any]) -> Dict[str, Any]:
        """Create firewall policy"""
        url = f"https://{self.hostname}:{self.port}/api/v2/cmdb/firewall/policy"
        
        policy_data = {
            "name": policy_name,
            "srcintf": [{"name": context.get("source_interface", "any")}],
            "dstintf": [{"name": context.get("dest_interface", "any")}],
            "srcaddr": [{"name": context.get("source", "all")}],
            "dstaddr": [{"name": context.get("destination", "all")}],
            "service": [{"name": "ALL"}],
            "action": context.get("action", "deny"),
            "status": "enable",
            "comments": "Created by ThreatSentinel SOC Agent"
        }
        
        response = await self._make_request("POST", url, json=policy_data)
        
        return {
            "policy_name": policy_name,
            "action": policy_data["action"],
            "reference_id": response.get("mkey")
        }


class PfSenseIntegration(BaseIntegration):
    """
    pfSense Firewall Integration
    
    Supports blocking through pfSense API (requires pfSense API package)
    """
    
    def __init__(self, config: Dict[str, Any]):
        super().__init__("pfSense", IntegrationType.FIREWALL, config)
        self.api_key = config.get("api_key")
        self.api_secret = config.get("api_secret")
        self.hostname = config.get("hostname")
        self.port = config.get("port", 443)
        
    async def connect(self) -> bool:
        """Connect to pfSense API"""
        try:
            self.session = self._create_session()
            
            # Set up API authentication
            auth_header = f"Bearer {self.api_key}:{self.api_secret}"
            self.session.headers.update({"Authorization": auth_header})
            
            # Test connection
            url = f"https://{self.hostname}:{self.port}/api/v1/system/info"
            await self._make_request("GET", url)
            
            self.is_connected = True
            self.logger.info("Connected to pfSense firewall")
            return True
            
        except Exception as e:
            self.logger.error(f"Failed to connect to pfSense: {e}")
            self.is_connected = False
            return False
    
    async def disconnect(self) -> bool:
        """Disconnect from pfSense API"""
        if self.session:
            await self.session.close()
            self.session = None
        self.is_connected = False
        return True
    
    async def test_connection(self) -> bool:
        """Test pfSense API connection"""
        return await self.connect()
    
    def get_supported_actions(self) -> List[ActionType]:
        """Get supported actions for pfSense"""
        return [
            ActionType.BLOCK_IP,
            ActionType.CREATE_RULE,
            ActionType.ADD_TO_WATCHLIST
        ]
    
    async def execute_action(self, action_type: ActionType, target: str, 
                           context: Dict[str, Any]) -> ActionResult:
        """Execute action on pfSense firewall"""
        start_time = asyncio.get_event_loop().time()
        
        try:
            if action_type == ActionType.BLOCK_IP:
                result = await self._block_ip(target, context)
            elif action_type == ActionType.CREATE_RULE:
                result = await self._create_firewall_rule(target, context)
            else:
                raise ValueError(f"Unsupported action: {action_type}")
            
            execution_time = asyncio.get_event_loop().time() - start_time
            
            return ActionResult(
                success=True,
                action_type=action_type,
                target=target,
                details=result,
                execution_time=execution_time,
                reference_id=result.get("reference_id")
            )
            
        except Exception as e:
            execution_time = asyncio.get_event_loop().time() - start_time
            self.logger.error(f"Action {action_type} failed for {target}: {e}")
            
            return ActionResult(
                success=False,
                action_type=action_type,
                target=target,
                details={},
                execution_time=execution_time,
                error_message=str(e)
            )
    
    async def _block_ip(self, ip: str, context: Dict[str, Any]) -> Dict[str, Any]:
        """Block IP by creating firewall rule"""
        url = f"https://{self.hostname}:{self.port}/api/v1/firewall/rule"
        
        rule_data = {
            "type": "block",
            "interface": context.get("interface", "wan"),
            "source": {"address": ip},
            "destination": {"address": "any"},
            "descr": f"ThreatSentinel SOC Agent Block - {context.get('reason', 'Security threat')}"
        }
        
        response = await self._make_request("POST", url, json=rule_data)
        
        return {
            "ip": ip,
            "rule_id": response.get("id"),
            "action": "blocked",
            "interface": rule_data["interface"],
            "reference_id": response.get("id")
        }
    
    async def _create_firewall_rule(self, rule_description: str, context: Dict[str, Any]) -> Dict[str, Any]:
        """Create custom firewall rule"""
        url = f"https://{self.hostname}:{self.port}/api/v1/firewall/rule"
        
        rule_data = {
            "type": context.get("action", "block"),
            "interface": context.get("interface", "wan"),
            "source": {"address": context.get("source", "any")},
            "destination": {"address": context.get("destination", "any")},
            "protocol": context.get("protocol", "any"),
            "descr": f"ThreatSentinel SOC Agent - {rule_description}"
        }
        
        response = await self._make_request("POST", url, json=rule_data)
        
        return {
            "rule_description": rule_description,
            "rule_id": response.get("id"),
            "action": rule_data["type"],
            "reference_id": response.get("id")
        } 