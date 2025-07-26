"""
Incident Response Platform Integration Adapters
"""

import asyncio
import base64
from typing import Dict, Any, List
from .base import BaseIntegration, ActionResult, ActionType, IntegrationType


class ServiceNowIntegration(BaseIntegration):
    """
    ServiceNow Integration for incident management
    
    Supports creating and updating incidents, and managing the incident lifecycle
    """
    
    def __init__(self, config: Dict[str, Any]):
        super().__init__("ServiceNow", IntegrationType.INCIDENT_RESPONSE, config)
        self.instance_url = config.get("instance_url")
        self.username = config.get("username")
        self.password = config.get("password")
        self.api_version = config.get("api_version", "v1")
        
    async def connect(self) -> bool:
        """Connect to ServiceNow API"""
        try:
            self.session = self._create_session()
            
            # Set up basic authentication
            auth_string = base64.b64encode(f"{self.username}:{self.password}".encode()).decode()
            self.session.headers.update({
                "Authorization": f"Basic {auth_string}",
                "Content-Type": "application/json",
                "Accept": "application/json"
            })
            
            # Test connection
            url = f"{self.instance_url}/api/now/table/sys_user"
            params = {"sysparm_limit": 1}
            await self._make_request("GET", url, params=params)
            
            self.is_connected = True
            self.logger.info("Connected to ServiceNow")
            return True
            
        except Exception as e:
            self.logger.error(f"Failed to connect to ServiceNow: {e}")
            self.is_connected = False
            return False
    
    async def disconnect(self) -> bool:
        """Disconnect from ServiceNow API"""
        if self.session:
            await self.session.close()
            self.session = None
        self.is_connected = False
        return True
    
    async def test_connection(self) -> bool:
        """Test ServiceNow API connection"""
        return await self.connect()
    
    def get_supported_actions(self) -> List[ActionType]:
        """Get supported actions for ServiceNow"""
        return [
            ActionType.CREATE_INCIDENT,
            ActionType.UPDATE_INCIDENT,
            ActionType.ESCALATE
        ]
    
    async def execute_action(self, action_type: ActionType, target: str, 
                           context: Dict[str, Any]) -> ActionResult:
        """Execute action in ServiceNow"""
        start_time = asyncio.get_event_loop().time()
        
        try:
            if action_type == ActionType.CREATE_INCIDENT:
                result = await self._create_incident(target, context)
            elif action_type == ActionType.UPDATE_INCIDENT:
                result = await self._update_incident(target, context)
            elif action_type == ActionType.ESCALATE:
                result = await self._escalate_incident(target, context)
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
    
    async def _create_incident(self, title: str, context: Dict[str, Any]) -> Dict[str, Any]:
        """Create incident in ServiceNow"""
        url = f"{self.instance_url}/api/now/table/incident"
        
        # Map severity levels
        severity_map = {
            "critical": "1",
            "high": "2",
            "medium": "3",
            "low": "4"
        }
        
        urgency_map = {
            "critical": "1",
            "high": "2", 
            "medium": "3",
            "low": "4"
        }
        
        severity = context.get("severity", "medium").lower()
        
        incident_data = {
            "short_description": title,
            "description": self._format_description(context),
            "category": "Security",
            "subcategory": "Security Event",
            "severity": severity_map.get(severity, "3"),
            "urgency": urgency_map.get(severity, "3"),
            "impact": severity_map.get(severity, "3"),
            "caller_id": context.get("caller_id", ""),
            "assignment_group": context.get("assignment_group", "Security Team"),
            "work_notes": f"Created by ThreatSentinel SOC Agent - Investigation ID: {context.get('investigation_id', '')}"
        }
        
        response = await self._make_request("POST", url, json=incident_data)
        
        return {
            "incident_number": response["result"]["number"],
            "sys_id": response["result"]["sys_id"],
            "state": response["result"]["state"],
            "severity": severity,
            "reference_id": response["result"]["sys_id"]
        }
    
    async def _update_incident(self, incident_id: str, context: Dict[str, Any]) -> Dict[str, Any]:
        """Update existing incident in ServiceNow"""
        url = f"{self.instance_url}/api/now/table/incident/{incident_id}"
        
        update_data = {}
        
        if context.get("status"):
            # Map status to ServiceNow states
            status_map = {
                "new": "1",
                "in_progress": "2", 
                "on_hold": "3",
                "resolved": "6",
                "closed": "7",
                "cancelled": "8"
            }
            update_data["state"] = status_map.get(context["status"], "2")
        
        if context.get("work_notes"):
            update_data["work_notes"] = context["work_notes"]
        
        if context.get("resolution_notes"):
            update_data["close_notes"] = context["resolution_notes"]
        
        if context.get("assigned_to"):
            update_data["assigned_to"] = context["assigned_to"]
        
        response = await self._make_request("PUT", url, json=update_data)
        
        return {
            "incident_id": incident_id,
            "updated_fields": list(update_data.keys()),
            "state": response["result"]["state"],
            "reference_id": incident_id
        }
    
    async def _escalate_incident(self, incident_id: str, context: Dict[str, Any]) -> Dict[str, Any]:
        """Escalate incident in ServiceNow"""
        escalation_data = {
            "escalation": "1",
            "urgency": "1",  # Set to high urgency
            "impact": "1",   # Set to high impact
            "work_notes": f"Escalated by ThreatSentinel SOC Agent: {context.get('reason', 'Automatic escalation due to risk threshold')}"
        }
        
        if context.get("escalation_group"):
            escalation_data["assignment_group"] = context["escalation_group"]
        
        url = f"{self.instance_url}/api/now/table/incident/{incident_id}"
        response = await self._make_request("PUT", url, json=escalation_data)
        
        return {
            "incident_id": incident_id,
            "escalated": True,
            "urgency": "1",
            "escalation_reason": context.get("reason"),
            "reference_id": incident_id
        }
    
    def _format_description(self, context: Dict[str, Any]) -> str:
        """Format incident description"""
        description = f"""
Security incident detected by ThreatSentinel SOC Agent

Investigation ID: {context.get('investigation_id', 'N/A')}
Event Type: {context.get('event_type', 'N/A')}
Risk Score: {context.get('risk_score', 'N/A')}
Source IP: {context.get('source_ip', 'N/A')}

Description: {context.get('description', 'Automated security incident')}

Threat Intelligence Summary:
{context.get('threat_summary', 'Analysis in progress')}

Recommended Actions:
"""
        
        actions = context.get('actions', [])
        for i, action in enumerate(actions[:5], 1):
            description += f"{i}. {action}\n"
        
        return description


class JiraIntegration(BaseIntegration):
    """
    Jira Integration for issue tracking and incident management
    
    Supports creating issues, updating status, and managing security incidents as Jira tickets
    """
    
    def __init__(self, config: Dict[str, Any]):
        super().__init__("Jira", IntegrationType.INCIDENT_RESPONSE, config)
        self.server_url = config.get("server_url")
        self.username = config.get("username")
        self.api_token = config.get("api_token")
        self.project_key = config.get("project_key")
        
    async def connect(self) -> bool:
        """Connect to Jira API"""
        try:
            self.session = self._create_session()
            
            # Set up basic authentication
            auth_string = base64.b64encode(f"{self.username}:{self.api_token}".encode()).decode()
            self.session.headers.update({
                "Authorization": f"Basic {auth_string}",
                "Content-Type": "application/json",
                "Accept": "application/json"
            })
            
            # Test connection
            url = f"{self.server_url}/rest/api/3/myself"
            await self._make_request("GET", url)
            
            self.is_connected = True
            self.logger.info("Connected to Jira")
            return True
            
        except Exception as e:
            self.logger.error(f"Failed to connect to Jira: {e}")
            self.is_connected = False
            return False
    
    async def disconnect(self) -> bool:
        """Disconnect from Jira API"""
        if self.session:
            await self.session.close()
            self.session = None
        self.is_connected = False
        return True
    
    async def test_connection(self) -> bool:
        """Test Jira API connection"""
        return await self.connect()
    
    def get_supported_actions(self) -> List[ActionType]:
        """Get supported actions for Jira"""
        return [
            ActionType.CREATE_INCIDENT,
            ActionType.UPDATE_INCIDENT,
            ActionType.ESCALATE
        ]
    
    async def execute_action(self, action_type: ActionType, target: str, 
                           context: Dict[str, Any]) -> ActionResult:
        """Execute action in Jira"""
        start_time = asyncio.get_event_loop().time()
        
        try:
            if action_type == ActionType.CREATE_INCIDENT:
                result = await self._create_issue(target, context)
            elif action_type == ActionType.UPDATE_INCIDENT:
                result = await self._update_issue(target, context)
            elif action_type == ActionType.ESCALATE:
                result = await self._escalate_issue(target, context)
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
    
    async def _create_issue(self, title: str, context: Dict[str, Any]) -> Dict[str, Any]:
        """Create issue in Jira"""
        url = f"{self.server_url}/rest/api/3/issue"
        
        # Map severity to priority
        priority_map = {
            "critical": "Highest",
            "high": "High",
            "medium": "Medium", 
            "low": "Low"
        }
        
        severity = context.get("severity", "medium").lower()
        
        issue_data = {
            "fields": {
                "project": {"key": self.project_key},
                "summary": title,
                "description": {
                    "type": "doc",
                    "version": 1,
                    "content": [
                        {
                            "type": "paragraph",
                            "content": [
                                {
                                    "type": "text",
                                    "text": self._format_description(context)
                                }
                            ]
                        }
                    ]
                },
                "issuetype": {"name": context.get("issue_type", "Bug")},
                "priority": {"name": priority_map.get(severity, "Medium")},
                "labels": ["security", "ThreatSentinel-soc-agent", f"severity-{severity}"]
            }
        }
        
        # Add assignee if specified
        if context.get("assignee"):
            issue_data["fields"]["assignee"] = {"accountId": context["assignee"]}
        
        response = await self._make_request("POST", url, json=issue_data)
        
        return {
            "issue_key": response["key"],
            "issue_id": response["id"],
            "issue_url": f"{self.server_url}/browse/{response['key']}",
            "priority": priority_map.get(severity, "Medium"),
            "reference_id": response["key"]
        }
    
    async def _update_issue(self, issue_key: str, context: Dict[str, Any]) -> Dict[str, Any]:
        """Update existing issue in Jira"""
        url = f"{self.server_url}/rest/api/3/issue/{issue_key}"
        
        update_data = {"fields": {}}
        
        if context.get("status"):
            # Transition the issue to new status
            await self._transition_issue(issue_key, context["status"])
        
        if context.get("assignee"):
            update_data["fields"]["assignee"] = {"accountId": context["assignee"]}
        
        if context.get("comment"):
            # Add comment
            await self._add_comment(issue_key, context["comment"])
        
        if update_data["fields"]:
            await self._make_request("PUT", url, json=update_data)
        
        return {
            "issue_key": issue_key,
            "updated": True,
            "reference_id": issue_key
        }
    
    async def _escalate_issue(self, issue_key: str, context: Dict[str, Any]) -> Dict[str, Any]:
        """Escalate issue in Jira"""
        # Update priority to highest
        url = f"{self.server_url}/rest/api/3/issue/{issue_key}"
        
        escalation_data = {
            "fields": {
                "priority": {"name": "Highest"}
            }
        }
        
        await self._make_request("PUT", url, json=escalation_data)
        
        # Add escalation comment
        escalation_comment = f"Issue escalated by ThreatSentinel SOC Agent: {context.get('reason', 'Automatic escalation due to risk threshold')}"
        await self._add_comment(issue_key, escalation_comment)
        
        # Assign to escalation team if specified
        if context.get("escalation_assignee"):
            escalation_data = {
                "fields": {
                    "assignee": {"accountId": context["escalation_assignee"]}
                }
            }
            await self._make_request("PUT", url, json=escalation_data)
        
        return {
            "issue_key": issue_key,
            "escalated": True,
            "priority": "Highest",
            "escalation_reason": context.get("reason"),
            "reference_id": issue_key
        }
    
    async def _transition_issue(self, issue_key: str, status: str):
        """Transition issue to new status"""
        # Get available transitions
        transitions_url = f"{self.server_url}/rest/api/3/issue/{issue_key}/transitions"
        transitions_response = await self._make_request("GET", transitions_url)
        
        # Find transition ID for the desired status
        transition_id = None
        for transition in transitions_response["transitions"]:
            if transition["to"]["name"].lower() == status.lower():
                transition_id = transition["id"]
                break
        
        if transition_id:
            transition_data = {
                "transition": {"id": transition_id}
            }
            await self._make_request("POST", transitions_url, json=transition_data)
    
    async def _add_comment(self, issue_key: str, comment: str):
        """Add comment to issue"""
        url = f"{self.server_url}/rest/api/3/issue/{issue_key}/comment"
        
        comment_data = {
            "body": {
                "type": "doc",
                "version": 1,
                "content": [
                    {
                        "type": "paragraph",
                        "content": [
                            {
                                "type": "text",
                                "text": comment
                            }
                        ]
                    }
                ]
            }
        }
        
        await self._make_request("POST", url, json=comment_data)
    
    def _format_description(self, context: Dict[str, Any]) -> str:
        """Format issue description"""
        description = f"""Security incident detected by ThreatSentinel SOC Agent

Investigation Details:
- Investigation ID: {context.get('investigation_id', 'N/A')}
- Event Type: {context.get('event_type', 'N/A')}
- Risk Score: {context.get('risk_score', 'N/A')}
- Source IP: {context.get('source_ip', 'N/A')}

Incident Description:
{context.get('description', 'Automated security incident detected')}

Threat Intelligence Summary:
{context.get('threat_summary', 'Analysis in progress')}

Recommended Actions:
"""
        
        actions = context.get('actions', [])
        for i, action in enumerate(actions[:5], 1):
            description += f"{i}. {action}\n"
        
        description += "\nThis incident was automatically created by ThreatSentinel SOC Agent."
        
        return description


class PagerDutyIntegration(BaseIntegration):
    """
    PagerDuty Integration for incident alerting and escalation
    
    Supports triggering alerts, creating incidents, and managing on-call escalations
    """
    
    def __init__(self, config: Dict[str, Any]):
        super().__init__("PagerDuty", IntegrationType.INCIDENT_RESPONSE, config)
        self.api_token = config.get("api_token")
        self.service_key = config.get("service_key")
        self.routing_key = config.get("routing_key")
        self.api_url = "https://api.pagerduty.com"
        self.events_api_url = "https://events.pagerduty.com"
        
    async def connect(self) -> bool:
        """Connect to PagerDuty API"""
        try:
            self.session = self._create_session()
            self.session.headers.update({
                "Authorization": f"Token token={self.api_token}",
                "Accept": "application/vnd.pagerduty+json;version=2",
                "Content-Type": "application/json"
            })
            
            # Test connection
            url = f"{self.api_url}/users/me"
            await self._make_request("GET", url)
            
            self.is_connected = True
            self.logger.info("Connected to PagerDuty")
            return True
            
        except Exception as e:
            self.logger.error(f"Failed to connect to PagerDuty: {e}")
            self.is_connected = False
            return False
    
    async def disconnect(self) -> bool:
        """Disconnect from PagerDuty API"""
        if self.session:
            await self.session.close()
            self.session = None
        self.is_connected = False
        return True
    
    async def test_connection(self) -> bool:
        """Test PagerDuty API connection"""
        return await self.connect()
    
    def get_supported_actions(self) -> List[ActionType]:
        """Get supported actions for PagerDuty"""
        return [
            ActionType.CREATE_INCIDENT,
            ActionType.SEND_ALERT,
            ActionType.ESCALATE
        ]
    
    async def execute_action(self, action_type: ActionType, target: str, 
                           context: Dict[str, Any]) -> ActionResult:
        """Execute action in PagerDuty"""
        start_time = asyncio.get_event_loop().time()
        
        try:
            if action_type == ActionType.CREATE_INCIDENT:
                result = await self._create_incident(target, context)
            elif action_type == ActionType.SEND_ALERT:
                result = await self._send_alert(target, context)
            elif action_type == ActionType.ESCALATE:
                result = await self._escalate_incident(target, context)
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
    
    async def _create_incident(self, title: str, context: Dict[str, Any]) -> Dict[str, Any]:
        """Create incident in PagerDuty"""
        url = f"{self.api_url}/incidents"
        
        # Map severity to urgency
        urgency_map = {
            "critical": "high",
            "high": "high",
            "medium": "low",
            "low": "low"
        }
        
        severity = context.get("severity", "medium").lower()
        
        incident_data = {
            "incident": {
                "type": "incident",
                "title": title,
                "service": {
                    "id": self.service_key,
                    "type": "service_reference"
                },
                "urgency": urgency_map.get(severity, "low"),
                "body": {
                    "type": "incident_body",
                    "details": self._format_description(context)
                }
            }
        }
        
        # Add assignee if specified
        if context.get("assignee"):
            incident_data["incident"]["assignments"] = [
                {
                    "assignee": {
                        "id": context["assignee"],
                        "type": "user_reference"
                    }
                }
            ]
        
        response = await self._make_request("POST", url, json=incident_data)
        
        return {
            "incident_id": response["incident"]["id"],
            "incident_number": response["incident"]["incident_number"],
            "status": response["incident"]["status"],
            "urgency": response["incident"]["urgency"],
            "html_url": response["incident"]["html_url"],
            "reference_id": response["incident"]["id"]
        }
    
    async def _send_alert(self, message: str, context: Dict[str, Any]) -> Dict[str, Any]:
        """Send alert via PagerDuty Events API"""
        url = f"{self.events_api_url}/v2/enqueue"
        
        # Map severity to PagerDuty severity
        severity_map = {
            "critical": "critical",
            "high": "error",
            "medium": "warning",
            "low": "info"
        }
        
        severity = context.get("severity", "medium").lower()
        
        event_data = {
            "routing_key": self.routing_key,
            "event_action": "trigger",
            "dedup_key": context.get("investigation_id", f"ThreatSentinel_{hash(message) % 10000}"),
            "payload": {
                "summary": message,
                "source": "ThreatSentinel SOC Agent",
                "severity": severity_map.get(severity, "warning"),
                "component": "Security",
                "group": "SOC",
                "class": "Security Event",
                "custom_details": {
                    "investigation_id": context.get("investigation_id"),
                    "event_type": context.get("event_type"),
                    "risk_score": context.get("risk_score"),
                    "source_ip": context.get("source_ip"),
                    "threat_summary": context.get("threat_summary", "")
                }
            }
        }
        
        # Create separate session for Events API (no auth header needed)
        async with self._create_session() as events_session:
            async with events_session.post(url, json=event_data) as response:
                if response.status >= 400:
                    error_text = await response.text()
                    raise Exception(f"PagerDuty Events API error {response.status}: {error_text}")
                
                response_data = await response.json()
        
        return {
            "dedup_key": event_data["dedup_key"],
            "status": response_data["status"],
            "message": "Event triggered",
            "severity": severity,
            "reference_id": event_data["dedup_key"]
        }
    
    async def _escalate_incident(self, incident_id: str, context: Dict[str, Any]) -> Dict[str, Any]:
        """Escalate incident in PagerDuty"""
        url = f"{self.api_url}/incidents/{incident_id}"
        
        # Update incident urgency to high
        escalation_data = {
            "incident": {
                "type": "incident",
                "urgency": "high"
            }
        }
        
        response = await self._make_request("PUT", url, json=escalation_data)
        
        # Add note about escalation
        note_url = f"{self.api_url}/incidents/{incident_id}/notes"
        note_data = {
            "note": {
                "content": f"Escalated by ThreatSentinel SOC Agent: {context.get('reason', 'Automatic escalation due to risk threshold')}"
            }
        }
        
        await self._make_request("POST", note_url, json=note_data)
        
        return {
            "incident_id": incident_id,
            "escalated": True,
            "urgency": "high",
            "escalation_reason": context.get("reason"),
            "reference_id": incident_id
        }
    
    def _format_description(self, context: Dict[str, Any]) -> str:
        """Format incident description"""
        description = f"""Security incident detected by ThreatSentinel SOC Agent

Investigation ID: {context.get('investigation_id', 'N/A')}
Event Type: {context.get('event_type', 'N/A')}
Risk Score: {context.get('risk_score', 'N/A')}
Source IP: {context.get('source_ip', 'N/A')}

Description: {context.get('description', 'Automated security incident')}

Threat Intelligence Summary:
{context.get('threat_summary', 'Analysis in progress')}

Recommended Actions:
"""
        
        actions = context.get('actions', [])
        for i, action in enumerate(actions[:3], 1):  # Limit for PagerDuty
            description += f"{i}. {action}\n"
        
        return description 