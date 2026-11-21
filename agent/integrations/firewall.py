"""
Firewall Integration Adapters
"""

import time
import ipaddress
import re
from typing import Dict, Any, List
from xml.sax.saxutils import escape, quoteattr
from .base import BaseIntegration, ActionResult, ActionType, IntegrationType, stable_reference

_DOMAIN_RE = re.compile(
    r'^[A-Za-z0-9]([A-Za-z0-9\-]*[A-Za-z0-9])?'
    r'(\.[A-Za-z0-9]([A-Za-z0-9\-]*[A-Za-z0-9])?)+$'
)
_URL_ENTRY_RE = re.compile(r'^[A-Za-z0-9.\-*/:?=&]+$')
_RULE_NAME_RE = re.compile(r'^[\w\- ]+$')
_OBJECT_NAME_RE = re.compile(r'^[\w\-]{1,63}$')
_FORTI_NAME_RE = re.compile(r'^[\w\-. ]{1,79}$')
_ALLOWED_RULE_ACTIONS = {'deny', 'allow', 'drop', 'reset'}
_PFSENSE_ACTIONS = {'block', 'reject', 'pass'}
_PFSENSE_PROTOCOLS = {'any', 'tcp', 'udp', 'tcp/udp', 'icmp'}


def _validate_object_name(value: str, what: str) -> str:
    """Names interpolated into PAN-OS xpaths must be plain identifiers"""
    value = str(value or '').strip()
    if not _OBJECT_NAME_RE.fullmatch(value):
        raise ValueError(f"Unsafe {what}: {value!r}")
    return value


def _validate_forti_name(value: str, what: str) -> str:
    value = str(value or '').strip()
    if not _FORTI_NAME_RE.fullmatch(value):
        raise ValueError(f"Unsafe {what}: {value!r}")
    return value


def _validate_address_or_any(value: str) -> str:
    """'any' or a single IP / CIDR network"""
    value = str(value or 'any').strip()
    if value.lower() == 'any':
        return 'any'
    return str(ipaddress.ip_network(value, strict=False))


def _validate_ip(value: str) -> str:
    """Reject anything that is not a plain IP before it reaches firewall config"""
    return str(ipaddress.ip_address(value.strip()))


def _validate_domain(value: str) -> str:
    value = value.strip().lower()
    if not _DOMAIN_RE.fullmatch(value):
        raise ValueError(f"Unsafe domain for firewall rule: {value!r}")
    return value


def _validate_url_entry(value: str) -> str:
    value = re.sub(r'^https?://', '', value.strip(), flags=re.IGNORECASE)
    if not _URL_ENTRY_RE.fullmatch(value):
        raise ValueError(f"Unsafe URL entry for firewall rule: {value!r}")
    return value


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
        self.vsys = _validate_object_name(config.get("vsys", "vsys1"), "vsys")

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
        start_time = time.monotonic()

        try:
            if action_type == ActionType.BLOCK_IP:
                result = await self._block_ip(target, context)
            elif action_type == ActionType.BLOCK_URL:
                result = await self._block_url(target, context)
            elif action_type == ActionType.BLOCK_DOMAIN:
                result = await self._block_domain(target, context)
            elif action_type == ActionType.CREATE_RULE:
                result = await self._create_security_rule(target, context)
            elif action_type == ActionType.ADD_TO_WATCHLIST:
                result = await self._add_ip_to_group(target, "ThreatSentinel_Watchlist", "watchlisted", context)
            else:
                raise ValueError(f"Unsupported action: {action_type}")

            execution_time = time.monotonic() - start_time

            return ActionResult(
                success=True,
                action_type=action_type,
                target=target,
                details=result,
                execution_time=execution_time,
                reference_id=result.get("reference_id")
            )

        except Exception as e:
            execution_time = time.monotonic() - start_time
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
        """Block IP address by adding it to the blocked address group"""
        return await self._add_ip_to_group(ip, "ThreatSentinel_Blocked_IPs", "blocked", context)

    async def _add_ip_to_group(self, ip: str, group_name: str, verb: str,
                               context: Dict[str, Any]) -> Dict[str, Any]:
        """Create an address object for the IP and add it to a static address group"""
        url = f"https://{self.hostname}:{self.port}/api/"

        ip = _validate_ip(ip)
        address_name = f"blocked_ip_{ip.replace('.', '_').replace(':', '_')}"

        params = {
            "type": "config",
            "action": "set",
            "xpath": f"/config/devices/entry[@name='localhost.localdomain']/vsys/entry[@name='{self.vsys}']/address",
            "element": f"<entry name={quoteattr(address_name)}><ip-netmask>{escape(ip)}</ip-netmask></entry>",
            "key": self.api_key
        }

        response = await self._make_request("POST", url, params=params)
        await self._add_to_address_group(address_name, group_name)

        return {
            "address_object": address_name,
            "address_group": group_name,
            "action": verb,
            "reference_id": response.get("msg", {}).get("line", ""),
            "reason": context.get("reason", "Security threat")
        }

    async def _block_url(self, url: str, context: Dict[str, Any]) -> Dict[str, Any]:
        """Block URL by adding to URL filtering category"""
        # Add URL to custom category
        api_url = f"https://{self.hostname}:{self.port}/api/"

        url = _validate_url_entry(url)

        params = {
            "type": "config",
            "action": "set",
            "xpath": f"/config/devices/entry[@name='localhost.localdomain']/vsys/entry[@name='{self.vsys}']/profiles/custom-url-category/entry[@name='ThreatSentinel_Blocked_URLs']/list",
            "element": f"<member>{escape(url)}</member>",
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
        return await self._block_url(f"*.{_validate_domain(domain)}", context)

    async def _create_security_rule(self, rule_name: str, context: Dict[str, Any]) -> Dict[str, Any]:
        """Create security rule to block traffic"""
        url = f"https://{self.hostname}:{self.port}/api/"

        rule_name = rule_name.strip()
        if not _RULE_NAME_RE.fullmatch(rule_name):
            raise ValueError(f"Unsafe rule name: {rule_name!r}")

        source = context.get("source", "any")
        destination = context.get("destination", "any")
        action = context.get("action", "deny")

        if action not in _ALLOWED_RULE_ACTIONS:
            raise ValueError(f"Unsupported rule action: {action!r}")
        if source != "any":
            source = _validate_ip(source)
        if destination != "any":
            destination = _validate_ip(destination)

        rule_xml = f"""
        <entry name={quoteattr(rule_name)}>
            <from><member>any</member></from>
            <to><member>any</member></to>
            <source><member>{escape(source)}</member></source>
            <destination><member>{escape(destination)}</member></destination>
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
        group_name = _validate_object_name(group_name, "address group name")
        address_name = _validate_object_name(address_name, "address object name")
        vsys = _validate_object_name(self.vsys, "vsys")

        params = {
            "type": "config",
            "action": "set",
            "xpath": f"/config/devices/entry[@name='localhost.localdomain']/vsys/entry[@name='{vsys}']/address-group/entry[@name='{group_name}']/static",
            "element": f"<member>{escape(address_name)}</member>",
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
        start_time = time.monotonic()

        try:
            if action_type == ActionType.BLOCK_IP:
                result = await self._block_ip(target, context)
            elif action_type == ActionType.BLOCK_URL:
                result = await self._block_url(target, context)
            elif action_type == ActionType.BLOCK_DOMAIN:
                result = await self._block_domain(target, context)
            elif action_type == ActionType.CREATE_RULE:
                result = await self._create_firewall_policy(target, context)
            else:
                raise ValueError(f"Unsupported action: {action_type}")

            execution_time = time.monotonic() - start_time

            return ActionResult(
                success=True,
                action_type=action_type,
                target=target,
                details=result,
                execution_time=execution_time,
                reference_id=result.get("reference_id")
            )

        except Exception as e:
            execution_time = time.monotonic() - start_time
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
        ip = _validate_ip(ip)
        address_name = f"ThreatSentinel_Blocked_{ip.replace('.', '_').replace(':', '_')}"
        comment = f"Blocked by ThreatSentinel SOC Agent - {str(context.get('reason', 'Security threat'))[:200]}"
        if ipaddress.ip_address(ip).version == 6:
            url = f"https://{self.hostname}:{self.port}/api/v2/cmdb/firewall/address6"
            address_data = {"name": address_name, "type": "ipprefix", "ip6": f"{ip}/128", "comment": comment}
        else:
            url = f"https://{self.hostname}:{self.port}/api/v2/cmdb/firewall/address"
            address_data = {"name": address_name, "type": "ipmask", "subnet": f"{ip}/32", "comment": comment}

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

        url_path = _validate_url_entry(url_path)

        url_data = {
            "name": f"ThreatSentinel_Blocked_URL_{stable_reference(url_path)}",
            "entries": [
                {
                    "url": url_path,
                    "type": "simple",
                    "action": "block"
                }
            ],
            "comment": f"Blocked by ThreatSentinel SOC Agent - {str(context.get('reason', 'Security threat'))[:200]}"
        }

        response = await self._make_request("POST", api_url, json=url_data)

        return {
            "url": url_path,
            "filter_name": url_data["name"],
            "action": "blocked",
            "reference_id": response.get("mkey")
        }

    async def _block_domain(self, domain: str, context: Dict[str, Any]) -> Dict[str, Any]:
        """Block a domain and all its subdomains with a wildcard web filter entry"""
        domain = _validate_domain(domain)
        api_url = f"https://{self.hostname}:{self.port}/api/v2/cmdb/webfilter/urlfilter"
        filter_data = {
            "name": f"ThreatSentinel_Blocked_Domain_{stable_reference(domain)}",
            "entries": [
                {"url": domain, "type": "simple", "action": "block"},
                {"url": f"*.{domain}", "type": "wildcard", "action": "block"},
            ],
            "comment": f"Blocked by ThreatSentinel SOC Agent - {str(context.get('reason', 'Security threat'))[:200]}"
        }
        response = await self._make_request("POST", api_url, json=filter_data)
        return {
            "domain": domain,
            "filter_name": filter_data["name"],
            "action": "blocked",
            "reference_id": response.get("mkey")
        }

    async def _create_firewall_policy(self, policy_name: str, context: Dict[str, Any]) -> Dict[str, Any]:
        """Create firewall policy"""
        url = f"https://{self.hostname}:{self.port}/api/v2/cmdb/firewall/policy"

        policy_name = policy_name.strip()
        if not _RULE_NAME_RE.fullmatch(policy_name):
            raise ValueError(f"Unsafe policy name: {policy_name!r}")
        action = context.get("action", "deny")
        if action not in _ALLOWED_RULE_ACTIONS:
            raise ValueError(f"Unsupported policy action: {action!r}")

        policy_data = {
            "name": policy_name,
            "srcintf": [{"name": _validate_forti_name(context.get("source_interface", "any"), "source interface")}],
            "dstintf": [{"name": _validate_forti_name(context.get("dest_interface", "any"), "destination interface")}],
            "srcaddr": [{"name": _validate_forti_name(context.get("source", "all"), "source address")}],
            "dstaddr": [{"name": _validate_forti_name(context.get("destination", "all"), "destination address")}],
            "service": [{"name": "ALL"}],
            "action": action,
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
        start_time = time.monotonic()

        try:
            if action_type == ActionType.BLOCK_IP:
                result = await self._block_ip(target, context)
            elif action_type == ActionType.CREATE_RULE:
                result = await self._create_firewall_rule(target, context)
            elif action_type == ActionType.ADD_TO_WATCHLIST:
                result = await self._add_to_watchlist_alias(target, context)
            else:
                raise ValueError(f"Unsupported action: {action_type}")

            execution_time = time.monotonic() - start_time

            return ActionResult(
                success=True,
                action_type=action_type,
                target=target,
                details=result,
                execution_time=execution_time,
                reference_id=result.get("reference_id")
            )

        except Exception as e:
            execution_time = time.monotonic() - start_time
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
        ip = _validate_ip(ip)

        rule_data = {
            "type": "block",
            "interface": _validate_object_name(context.get("interface", "wan"), "interface"),
            "source": {"address": ip},
            "destination": {"address": "any"},
            "descr": f"ThreatSentinel SOC Agent Block - {_sanitize_descr(context.get('reason', 'Security threat'))}"
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

        action = str(context.get("action", "block")).lower()
        if action not in _PFSENSE_ACTIONS:
            raise ValueError(f"Unsupported rule action: {action!r}")
        protocol = str(context.get("protocol", "any")).lower()
        if protocol not in _PFSENSE_PROTOCOLS:
            raise ValueError(f"Unsupported protocol: {protocol!r}")

        rule_data = {
            "type": action,
            "interface": _validate_object_name(context.get("interface", "wan"), "interface"),
            "source": {"address": _validate_address_or_any(context.get("source", "any"))},
            "destination": {"address": _validate_address_or_any(context.get("destination", "any"))},
            "protocol": protocol,
            "descr": f"ThreatSentinel SOC Agent - {_sanitize_descr(rule_description)}"
        }

        response = await self._make_request("POST", url, json=rule_data)

        return {
            "rule_description": rule_description,
            "rule_id": response.get("id"),
            "action": rule_data["type"],
            "reference_id": response.get("id")
        }

    async def _add_to_watchlist_alias(self, ip: str, context: Dict[str, Any]) -> Dict[str, Any]:
        """Add an IP to the ThreatSentinel_Watchlist firewall alias"""
        url = f"https://{self.hostname}:{self.port}/api/v1/firewall/alias/entry"
        ip = _validate_ip(ip)
        data = {
            "name": "ThreatSentinel_Watchlist",
            "address": [ip],
            "detail": [f"ThreatSentinel {_sanitize_descr(context.get('investigation_id', ''))}"],
        }
        response = await self._make_request("POST", url, json=data)
        return {"ip": ip, "alias": "ThreatSentinel_Watchlist", "action": "watchlisted",
                "reference_id": response.get("id") or stable_reference(ip)}


def _sanitize_descr(value: Any, limit: int = 200) -> str:
    """Firewall descriptions: printable text only, no control characters"""
    return re.sub(r"[^\w\s.,:;()/@#+\-]", "", str(value or ""))[:limit]
