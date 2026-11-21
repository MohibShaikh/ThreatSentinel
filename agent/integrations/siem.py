"""
SIEM Integration Adapters
"""

import base64
import csv
import io
import re
import time
from typing import Any, Dict, List

import aiohttp

from .base import (ActionResult, ActionType, BaseIntegration, IntegrationType, safe_path_segment,
                   stable_reference)

_SAFE_INDICATOR = re.compile(r'^[A-Za-z0-9.\-_:]+$')
_RAW_QUERY_KEYS = ("search_query", "kql_query", "rule_logic")


def _sanitize_indicator(value: str) -> str:
    """Allow only plain indicators so nothing can break out of SPL/KQL/AQL strings"""
    value = str(value or "").strip()
    if not _SAFE_INDICATOR.fullmatch(value):
        raise ValueError(f"Unsafe indicator for SIEM query: {value!r}")
    return value


def _reject_raw_query(context: Dict[str, Any]) -> None:
    """Raw query overrides are code execution in the SIEM; queries are built from indicators only"""
    for key in _RAW_QUERY_KEYS:
        if context.get(key):
            raise ValueError(f"Raw query override '{key}' is not accepted; pass 'target' instead")


def _csv_cell(value: Any) -> str:
    """CSV cell with spreadsheet formula injection neutralized"""
    text = "" if value is None else str(value)
    text = text.replace("\r", " ").replace("\n", " ")
    if text[:1] in ("=", "+", "-", "@", "\t"):
        text = "'" + text
    return text


def _csv_line(values: List[Any]) -> str:
    buffer = io.StringIO()
    csv.writer(buffer, quoting=csv.QUOTE_MINIMAL, lineterminator="\n").writerow([_csv_cell(v) for v in values])
    return buffer.getvalue()


class SplunkIntegration(BaseIntegration):
    """
    Splunk SIEM Integration

    Supports creating incidents, sending alerts, and updating search queries
    """

    def __init__(self, config: Dict[str, Any]):
        super().__init__("Splunk", IntegrationType.SIEM, config)
        self.hostname = config.get("hostname")
        self.port = config.get("port", 8089)
        self.username = config.get("username")
        self.password = config.get("password")
        self.token = config.get("token")
        self.index = config.get("index", "main")

    async def connect(self) -> bool:
        """Connect to Splunk REST API"""
        try:
            self.session = self._create_session()

            if self.token:
                self.session.headers.update({"Authorization": f"Bearer {self.token}"})
            else:
                # Use basic auth
                auth_string = base64.b64encode(f"{self.username}:{self.password}".encode()).decode()
                self.session.headers.update({"Authorization": f"Basic {auth_string}"})

            # Test connection
            url = f"https://{self.hostname}:{self.port}/services/server/info"
            await self._make_request("GET", url)

            self.is_connected = True
            self.logger.info("Connected to Splunk")
            return True

        except Exception as e:
            self.logger.error(f"Failed to connect to Splunk: {e}")
            self.is_connected = False
            return False

    async def disconnect(self) -> bool:
        """Disconnect from Splunk API"""
        if self.session:
            await self.session.close()
            self.session = None
        self.is_connected = False
        return True

    async def test_connection(self) -> bool:
        """Test Splunk API connection"""
        return await self.connect()

    def get_supported_actions(self) -> List[ActionType]:
        """Get supported actions for Splunk"""
        return [
            ActionType.CREATE_INCIDENT,
            ActionType.SEND_ALERT,
            ActionType.ADD_TO_WATCHLIST,
            ActionType.CREATE_RULE
        ]

    async def execute_action(self, action_type: ActionType, target: str,
                           context: Dict[str, Any]) -> ActionResult:
        """Execute action in Splunk"""
        start_time = time.monotonic()

        try:
            if action_type == ActionType.CREATE_INCIDENT:
                result = await self._create_incident(target, context)
            elif action_type == ActionType.SEND_ALERT:
                result = await self._send_alert(target, context)
            elif action_type == ActionType.ADD_TO_WATCHLIST:
                result = await self._add_to_watchlist(target, context)
            elif action_type == ActionType.CREATE_RULE:
                result = await self._create_saved_search(target, context)
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

    async def _create_incident(self, title: str, context: Dict[str, Any]) -> Dict[str, Any]:
        """Create incident in Splunk (using notable events)"""
        url = f"https://{self.hostname}:{self.port}/services/receivers/simple"

        event_data = {
            "source": "ThreatSentinel SOC Agent",
            "sourcetype": "ThreatSentinel:incident",
            "index": self.index,
            "event": {
                "title": title,
                "severity": context.get("severity", "medium"),
                "description": context.get("description", ""),
                "investigation_id": context.get("investigation_id"),
                "risk_score": context.get("risk_score"),
                "indicators": context.get("indicators", []),
                "recommended_actions": context.get("actions", []),
                "timestamp": context.get("timestamp"),
                "event_type": "ThreatSentinel_incident"
            }
        }

        response = await self._make_request("POST", url, json=event_data)

        return {
            "incident_title": title,
            "event_id": response.get("event_id"),
            "index": self.index,
            "reference_id": response.get("event_id")
        }

    async def _send_alert(self, message: str, context: Dict[str, Any]) -> Dict[str, Any]:
        """Send alert event to Splunk"""
        url = f"https://{self.hostname}:{self.port}/services/receivers/simple"

        alert_data = {
            "source": "ThreatSentinel SOC Agent",
            "sourcetype": "ThreatSentinel:alert",
            "index": self.index,
            "event": {
                "message": message,
                "alert_type": context.get("alert_type", "security"),
                "severity": context.get("severity", "medium"),
                "investigation_id": context.get("investigation_id"),
                "indicators": context.get("indicators", []),
                "timestamp": context.get("timestamp"),
                "event_type": "ThreatSentinel_alert"
            }
        }

        response = await self._make_request("POST", url, json=alert_data)

        return {
            "alert_message": message,
            "event_id": response.get("event_id"),
            "severity": context.get("severity"),
            "reference_id": response.get("event_id")
        }

    async def _add_to_watchlist(self, indicator: str, context: Dict[str, Any]) -> Dict[str, Any]:
        """Add indicator to Splunk watchlist (lookup table)"""
        # Create/update lookup table for threat indicators
        url = f"https://{self.hostname}:{self.port}/services/data/lookup-table-files/ThreatSentinel_watchlist.csv"

        watchlist_entry = {
            "indicator": _sanitize_indicator(indicator),
            "indicator_type": context.get("indicator_type") or "unknown",
            "threat_level": context.get("threat_level") or "medium",
            "added_by": "ThreatSentinel SOC Agent",
            "added_date": context.get("timestamp") or "",
            "investigation_id": context.get("investigation_id") or "",
            "description": context.get("description") or ""
        }

        csv_line = _csv_line([
            watchlist_entry["indicator"],
            watchlist_entry["indicator_type"],
            watchlist_entry["threat_level"],
            watchlist_entry["added_by"],
            watchlist_entry["added_date"],
            watchlist_entry["investigation_id"],
            watchlist_entry["description"],
        ])

        try:
            await self._make_request("POST", url, data=csv_line)
        except Exception as e:
            self.logger.info(f"Watchlist lookup append failed ({type(e).__name__}); creating lookup first")
            await self._create_watchlist_lookup()
            await self._make_request("POST", url, data=csv_line)

        return {
            "indicator": indicator,
            "watchlist": "ThreatSentinel_watchlist",
            "action": "added",
            "reference_id": f"watchlist_{stable_reference(indicator)}"
        }

    async def _create_saved_search(self, search_name: str, context: Dict[str, Any]) -> Dict[str, Any]:
        """Create saved search/alert in Splunk"""
        url = f"https://{self.hostname}:{self.port}/services/saved/searches"
        _reject_raw_query(context)
        if not re.fullmatch(r"[\w\- ]{1,100}", search_name or ""):
            raise ValueError(f"Unsafe saved search name: {search_name!r}")
        index = safe_path_segment(self.index, "index name")

        search_data = {
            "name": search_name,
            "search": f'search index={index} "{_sanitize_indicator(context.get("target", ""))}"',
            "description": f"Created by ThreatSentinel SOC Agent - {context.get('description', '')}",
            "is_scheduled": context.get("schedule", False),
            "cron_schedule": context.get("cron", "0 */1 * * *"),  # Every hour by default
            "actions": "email" if context.get("email_alert") else ""
        }

        await self._make_request("POST", url, data=search_data)

        return {
            "search_name": search_name,
            "search_query": search_data["search"],
            "scheduled": search_data["is_scheduled"],
            "reference_id": search_name
        }

    async def _create_watchlist_lookup(self):
        """Create the watchlist lookup table if it doesn't exist"""
        url = f"https://{self.hostname}:{self.port}/services/data/lookup-table-files"

        csv_header = "indicator,indicator_type,threat_level,added_by,added_date,investigation_id,description\n"

        lookup_data = {
            "filename": "ThreatSentinel_watchlist.csv",
            "contents": csv_header
        }

        return await self._make_request("POST", url, data=lookup_data)


class QRadarIntegration(BaseIntegration):
    """
    IBM QRadar SIEM Integration

    Supports creating offenses and custom rules
    """

    def __init__(self, config: Dict[str, Any]):
        super().__init__("QRadar", IntegrationType.SIEM, config)
        self.hostname = config.get("hostname")
        self.sec_token = config.get("sec_token")
        self.version = config.get("version", "16.0")

    async def connect(self) -> bool:
        """Connect to QRadar API"""
        try:
            self.session = self._create_session()
            self.session.headers.update({
                "SEC": self.sec_token,
                "Version": self.version,
                "Accept": "application/json"
            })

            # Test connection
            url = f"https://{self.hostname}/api/system/about"
            await self._make_request("GET", url)

            self.is_connected = True
            self.logger.info("Connected to QRadar")
            return True

        except Exception as e:
            self.logger.error(f"Failed to connect to QRadar: {e}")
            self.is_connected = False
            return False

    async def disconnect(self) -> bool:
        """Disconnect from QRadar API"""
        if self.session:
            await self.session.close()
            self.session = None
        self.is_connected = False
        return True

    async def test_connection(self) -> bool:
        """Test QRadar API connection"""
        return await self.connect()

    def get_supported_actions(self) -> List[ActionType]:
        """Get supported actions for QRadar"""
        return [
            ActionType.CREATE_INCIDENT,
            ActionType.ADD_TO_WATCHLIST,
            ActionType.CREATE_RULE
        ]

    async def execute_action(self, action_type: ActionType, target: str,
                           context: Dict[str, Any]) -> ActionResult:
        """Execute action in QRadar"""
        start_time = time.monotonic()

        try:
            if action_type == ActionType.CREATE_INCIDENT:
                result = await self._create_offense(target, context)
            elif action_type == ActionType.ADD_TO_WATCHLIST:
                result = await self._add_to_reference_set(target, context)
            elif action_type == ActionType.CREATE_RULE:
                result = await self._create_custom_rule(target, context)
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

    async def _create_offense(self, title: str, context: Dict[str, Any]) -> Dict[str, Any]:
        """Create offense in QRadar"""
        # QRadar offenses are typically created automatically by rules
        # We can create a custom event that triggers an offense
        url = f"https://{self.hostname}/api/siem/offenses"

        offense_data = {
            "description": title,
            "magnitude": context.get("magnitude", 5),
            "severity": context.get("severity", 5),
            "credibility": context.get("credibility", 5),
            "relevance": context.get("relevance", 5)
        }

        response = await self._make_request("POST", url, json=offense_data)

        return {
            "offense_title": title,
            "offense_id": response.get("id"),
            "severity": offense_data["severity"],
            "reference_id": response.get("id")
        }

    async def _add_to_reference_set(self, indicator: str, context: Dict[str, Any]) -> Dict[str, Any]:
        """Add indicator to QRadar reference set"""
        reference_set_name = context.get("reference_set", "ThreatSentinel_Threat_Indicators")
        encoded_name = safe_path_segment(reference_set_name, "reference set name")
        indicator = _sanitize_indicator(indicator)

        try:
            await self._create_reference_set(reference_set_name)
        except Exception as e:
            self.logger.debug(f"Reference set create skipped ({type(e).__name__}); it may already exist")

        url = f"https://{self.hostname}/api/reference_data/sets/{encoded_name}"
        # QRadar takes the value as a query parameter on this endpoint
        await self._make_request("POST", url, params={"value": indicator})

        return {
            "indicator": indicator,
            "reference_set": reference_set_name,
            "action": "added",
            "reference_id": f"ref_{stable_reference(reference_set_name, indicator)}"
        }

    async def _create_custom_rule(self, rule_name: str, context: Dict[str, Any]) -> Dict[str, Any]:
        """Create custom rule in QRadar"""
        url = f"https://{self.hostname}/api/analytics/rules"
        _reject_raw_query(context)
        if not re.fullmatch(r"[\w\- ]{1,100}", rule_name or ""):
            raise ValueError(f"Unsafe rule name: {rule_name!r}")
        indicator = _sanitize_indicator(context.get("target", ""))

        rule_data = {
            "name": rule_name,
            "type": "EVENT",
            "enabled": True,
            "owner": "ThreatSentinel SOC Agent",
            "tests": [
                {
                    "text": f"when the event matches sourceip = '{indicator}'",
                    "uid": 1
                }
            ]
        }

        response = await self._make_request("POST", url, json=rule_data)

        return {
            "rule_name": rule_name,
            "rule_id": response.get("id"),
            "enabled": True,
            "reference_id": response.get("id")
        }

    async def _create_reference_set(self, name: str):
        """Create reference set if it doesn't exist"""
        url = f"https://{self.hostname}/api/reference_data/sets"

        ref_set_data = {
            "name": name,
            "element_type": "ALN",
            "timeout_type": "UNKNOWN"
        }

        return await self._make_request("POST", url, params=ref_set_data)


class SentinelIntegration(BaseIntegration):
    """
    Microsoft Azure Sentinel Integration

    Supports creating incidents and custom analytics rules
    """

    def __init__(self, config: Dict[str, Any]):
        super().__init__("Sentinel", IntegrationType.SIEM, config)
        self.tenant_id = config.get("tenant_id")
        self.client_id = config.get("client_id")
        self.client_secret = config.get("client_secret")
        self.subscription_id = config.get("subscription_id")
        self.resource_group = config.get("resource_group")
        self.workspace_name = config.get("workspace_name")
        self.access_token = None

    async def connect(self) -> bool:
        """Connect to Azure Sentinel API"""
        try:
            # Get Azure AD access token
            self.access_token = await self._get_access_token()

            self.session = self._create_session()
            self.session.headers.update({
                "Authorization": f"Bearer {self.access_token}",
                "Content-Type": "application/json"
            })

            # Test connection
            await self._make_request("GET", self._workspace_url(), params={"api-version": "2020-08-01"})

            self.is_connected = True
            self.logger.info("Connected to Azure Sentinel")
            return True

        except Exception as e:
            self.logger.error(f"Failed to connect to Azure Sentinel: {e}")
            self.is_connected = False
            return False

    async def disconnect(self) -> bool:
        """Disconnect from Azure Sentinel API"""
        if self.session:
            await self.session.close()
            self.session = None
        self.is_connected = False
        return True

    async def test_connection(self) -> bool:
        """Test Azure Sentinel API connection"""
        return await self.connect()

    def get_supported_actions(self) -> List[ActionType]:
        """Get supported actions for Azure Sentinel"""
        return [
            ActionType.CREATE_INCIDENT,
            ActionType.CREATE_RULE,
            ActionType.ADD_TO_WATCHLIST
        ]

    async def execute_action(self, action_type: ActionType, target: str,
                           context: Dict[str, Any]) -> ActionResult:
        """Execute action in Azure Sentinel"""
        start_time = time.monotonic()

        try:
            if action_type == ActionType.CREATE_INCIDENT:
                result = await self._create_incident(target, context)
            elif action_type == ActionType.CREATE_RULE:
                result = await self._create_analytics_rule(target, context)
            elif action_type == ActionType.ADD_TO_WATCHLIST:
                result = await self._add_to_watchlist(target, context)
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

    async def _get_access_token(self) -> str:
        """Get Azure AD access token"""
        url = f"https://login.microsoftonline.com/{safe_path_segment(self.tenant_id, 'tenant id')}/oauth2/v2.0/token"

        data = {
            "client_id": self.client_id,
            "client_secret": self.client_secret,
            "scope": "https://management.azure.com/.default",
            "grant_type": "client_credentials"
        }

        async with aiohttp.ClientSession(timeout=aiohttp.ClientTimeout(total=30)) as session:
            async with session.post(url, data=data) as response:
                if response.status != 200:
                    raise Exception(f"Azure AD token request failed: HTTP {response.status}")
                token_data = await response.json(content_type=None)
                return token_data["access_token"]

    def _workspace_url(self) -> str:
        return (f"https://management.azure.com/subscriptions/{safe_path_segment(self.subscription_id, 'subscription id')}"
                f"/resourceGroups/{safe_path_segment(self.resource_group, 'resource group')}"
                f"/providers/Microsoft.OperationalInsights/workspaces/"
                f"{safe_path_segment(self.workspace_name, 'workspace name')}")

    async def _create_incident(self, title: str, context: Dict[str, Any]) -> Dict[str, Any]:
        """Create incident in Azure Sentinel"""
        incident_id = f"threatsentinel-{stable_reference(title, context.get('investigation_id', ''), length=16)}"
        url = f"{self._workspace_url()}/providers/Microsoft.SecurityInsights/incidents/{incident_id}"

        incident_data = {
            "properties": {
                "title": title,
                "description": context.get("description", "Created by ThreatSentinel SOC Agent"),
                "severity": context.get("severity", "Medium"),
                "status": "New",
                "classification": "Undetermined",
                "owner": {
                    "assignedTo": "ThreatSentinel SOC Agent"
                }
            }
        }

        response = await self._make_request(
            "PUT", url,
            json=incident_data,
            params={"api-version": "2021-10-01"}
        )

        return {
            "incident_title": title,
            "incident_id": response.get("name"),
            "severity": incident_data["properties"]["severity"],
            "reference_id": response.get("name")
        }

    async def _create_analytics_rule(self, rule_name: str, context: Dict[str, Any]) -> Dict[str, Any]:
        """Create analytics rule in Azure Sentinel"""
        _reject_raw_query(context)
        rule_id = safe_path_segment(re.sub(r"\s+", "_", str(rule_name or "").strip()), "rule name")
        url = f"{self._workspace_url()}/providers/Microsoft.SecurityInsights/alertRules/{rule_id}"

        rule_data = {
            "kind": "Scheduled",
            "properties": {
                "displayName": rule_name,
                "description": f"Created by ThreatSentinel SOC Agent - {context.get('description', '')}",
                "severity": context.get("severity", "Medium"),
                "enabled": True,
                "query": f"SecurityEvent | where Computer contains '{_sanitize_indicator(context.get('target', ''))}'",
                "queryFrequency": "PT1H",
                "queryPeriod": "PT1H",
                "triggerOperator": "GreaterThan",
                "triggerThreshold": 0,
                "suppressionDuration": "PT5H",
                "suppressionEnabled": False
            }
        }

        response = await self._make_request(
            "PUT", url,
            json=rule_data,
            params={"api-version": "2021-10-01"}
        )

        return {
            "rule_name": rule_name,
            "rule_id": response.get("name"),
            "enabled": True,
            "reference_id": response.get("name")
        }

    async def _add_to_watchlist(self, indicator: str, context: Dict[str, Any]) -> Dict[str, Any]:
        """Add indicator to Azure Sentinel watchlist"""
        watchlist_alias = context.get("watchlist", "ThreatSentinel_Threat_Indicators")
        alias = safe_path_segment(watchlist_alias, "watchlist alias")
        indicator = _sanitize_indicator(indicator)

        try:
            await self._create_watchlist(watchlist_alias)
        except Exception as e:
            self.logger.debug(f"Watchlist create skipped ({type(e).__name__}); it may already exist")

        item_id = stable_reference(alias, indicator, length=32)
        item_uuid = f"{item_id[:8]}-{item_id[8:12]}-{item_id[12:16]}-{item_id[16:20]}-{item_id[20:32]}"
        url = (f"{self._workspace_url()}/providers/Microsoft.SecurityInsights/watchlists/{alias}"
               f"/watchlistItems/{item_uuid}")

        item_data = {
            "properties": {
                "itemsKeyValue": {
                    "indicator": indicator,
                    "indicator_type": context.get("indicator_type", "unknown"),
                    "threat_level": context.get("threat_level", "medium"),
                    "added_by": "ThreatSentinel SOC Agent",
                    "investigation_id": context.get("investigation_id", "")
                }
            }
        }

        response = await self._make_request(
            "PUT", url,
            json=item_data,
            params={"api-version": "2021-10-01"}
        )

        return {
            "indicator": indicator,
            "watchlist": watchlist_alias,
            "action": "added",
            "reference_id": response.get("name")
        }

    async def _create_watchlist(self, alias: str):
        """Create watchlist if it doesn't exist"""
        url = (f"{self._workspace_url()}/providers/Microsoft.SecurityInsights/watchlists/"
               f"{safe_path_segment(alias, 'watchlist alias')}")

        watchlist_data = {
            "properties": {
                "displayName": "ThreatSentinel Threat Indicators",
                "description": "Threat indicators managed by ThreatSentinel SOC Agent",
                "provider": "ThreatSentinel SOC Agent",
                "source": "Local file",
                "itemsSearchKey": "indicator"
            }
        }

        return await self._make_request(
            "PUT", url,
            json=watchlist_data,
            params={"api-version": "2021-10-01"}
        )
