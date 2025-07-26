"""
Communication Integration Adapters
"""

import asyncio
import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from typing import Dict, Any, List
from .base import BaseIntegration, ActionResult, ActionType, IntegrationType


class SlackIntegration(BaseIntegration):
    """
    Slack Integration for notifications and alerts
    
    Supports sending messages, alerts, and incident notifications to Slack channels
    """
    
    def __init__(self, config: Dict[str, Any]):
        super().__init__("Slack", IntegrationType.COMMUNICATION, config)
        self.webhook_url = config.get("webhook_url")
        self.bot_token = config.get("bot_token")
        self.default_channel = config.get("default_channel", "#security-alerts")
        
    async def connect(self) -> bool:
        """Connect to Slack API"""
        try:
            self.session = self._create_session()
            
            if self.bot_token:
                self.session.headers.update({"Authorization": f"Bearer {self.bot_token}"})
            
            # Test connection with a simple API call
            if self.bot_token:
                url = "https://slack.com/api/auth.test"
                await self._make_request("GET", url)
            
            self.is_connected = True
            self.logger.info("Connected to Slack")
            return True
            
        except Exception as e:
            self.logger.error(f"Failed to connect to Slack: {e}")
            self.is_connected = False
            return False
    
    async def disconnect(self) -> bool:
        """Disconnect from Slack API"""
        if self.session:
            await self.session.close()
            self.session = None
        self.is_connected = False
        return True
    
    async def test_connection(self) -> bool:
        """Test Slack API connection"""
        return await self.connect()
    
    def get_supported_actions(self) -> List[ActionType]:
        """Get supported actions for Slack"""
        return [
            ActionType.SEND_ALERT,
            ActionType.NOTIFY,
            ActionType.ESCALATE
        ]
    
    async def execute_action(self, action_type: ActionType, target: str, 
                           context: Dict[str, Any]) -> ActionResult:
        """Execute action in Slack"""
        start_time = asyncio.get_event_loop().time()
        
        try:
            if action_type == ActionType.SEND_ALERT:
                result = await self._send_alert(target, context)
            elif action_type == ActionType.NOTIFY:
                result = await self._send_notification(target, context)
            elif action_type == ActionType.ESCALATE:
                result = await self._send_escalation(target, context)
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
    
    async def _send_alert(self, message: str, context: Dict[str, Any]) -> Dict[str, Any]:
        """Send security alert to Slack"""
        channel = context.get("channel", self.default_channel)
        severity = context.get("severity", "medium").upper()
        
        # Create rich message with blocks
        blocks = [
            {
                "type": "header",
                "text": {
                    "type": "plain_text",
                    "text": f"🚨 SECURITY ALERT - {severity} 🚨"
                }
            },
            {
                "type": "section",
                "text": {
                    "type": "mrkdwn",
                    "text": f"*Message:* {message}"
                }
            },
            {
                "type": "section",
                "fields": [
                    {
                        "type": "mrkdwn",
                        "text": f"*Investigation ID:*\n{context.get('investigation_id', 'N/A')}"
                    },
                    {
                        "type": "mrkdwn",
                        "text": f"*Risk Score:*\n{context.get('risk_score', 'N/A')}"
                    },
                    {
                        "type": "mrkdwn",
                        "text": f"*Event Type:*\n{context.get('event_type', 'N/A')}"
                    },
                    {
                        "type": "mrkdwn",
                        "text": f"*Source:*\n{context.get('source_ip', 'N/A')}"
                    }
                ]
            }
        ]
        
        if context.get("actions"):
            actions_text = "\n".join([f"• {action}" for action in context["actions"][:3]])
            blocks.append({
                "type": "section",
                "text": {
                    "type": "mrkdwn",
                    "text": f"*Recommended Actions:*\n{actions_text}"
                }
            })
        
        payload = {
            "channel": channel,
            "blocks": blocks,
            "username": "ThreatSentinel SOC Agent",
            "icon_emoji": ":shield:"
        }
        
        if self.webhook_url:
            response = await self._send_webhook(payload)
        else:
            response = await self._send_via_api(payload)
        
        return {
            "message": message,
            "channel": channel,
            "severity": severity,
            "reference_id": response.get("ts") or response.get("timestamp")
        }
    
    async def _send_notification(self, message: str, context: Dict[str, Any]) -> Dict[str, Any]:
        """Send general notification to Slack"""
        channel = context.get("channel", self.default_channel)
        
        payload = {
            "channel": channel,
            "text": f"ℹ️ *ThreatSentinel SOC Agent Notification*\n{message}",
            "username": "ThreatSentinel SOC Agent",
            "icon_emoji": ":information_source:"
        }
        
        if self.webhook_url:
            response = await self._send_webhook(payload)
        else:
            response = await self._send_via_api(payload)
        
        return {
            "message": message,
            "channel": channel,
            "reference_id": response.get("ts") or response.get("timestamp")
        }
    
    async def _send_escalation(self, message: str, context: Dict[str, Any]) -> Dict[str, Any]:
        """Send escalation notification to Slack"""
        channel = context.get("channel", self.default_channel)
        analyst = context.get("analyst", "@channel")
        
        escalation_message = f"🔥 *ESCALATION REQUIRED* 🔥\n\n{analyst}\n\n{message}\n\n*Investigation ID:* {context.get('investigation_id', 'N/A')}\n*Requires immediate attention*"
        
        payload = {
            "channel": channel,
            "text": escalation_message,
            "username": "ThreatSentinel SOC Agent",
            "icon_emoji": ":fire:"
        }
        
        if self.webhook_url:
            response = await self._send_webhook(payload)
        else:
            response = await self._send_via_api(payload)
        
        return {
            "message": message,
            "channel": channel,
            "escalated_to": analyst,
            "reference_id": response.get("ts") or response.get("timestamp")
        }
    
    async def _send_webhook(self, payload: Dict[str, Any]) -> Dict[str, Any]:
        """Send message via webhook"""
        response = await self._make_request("POST", self.webhook_url, json=payload)
        return {"timestamp": asyncio.get_event_loop().time()}
    
    async def _send_via_api(self, payload: Dict[str, Any]) -> Dict[str, Any]:
        """Send message via Slack API"""
        url = "https://slack.com/api/chat.postMessage"
        response = await self._make_request("POST", url, json=payload)
        return response


class TeamsIntegration(BaseIntegration):
    """
    Microsoft Teams Integration for notifications and alerts
    
    Supports sending messages and alerts to Teams channels via webhook
    """
    
    def __init__(self, config: Dict[str, Any]):
        super().__init__("Teams", IntegrationType.COMMUNICATION, config)
        self.webhook_url = config.get("webhook_url")
        self.tenant_id = config.get("tenant_id")
        
    async def connect(self) -> bool:
        """Connect to Teams webhook"""
        try:
            self.session = self._create_session()
            
            # Test webhook with a simple message
            test_payload = {
                "@type": "MessageCard",
                "@context": "http://schema.org/extensions",
                "text": "ThreatSentinel SOC Agent connection test"
            }
            
            # Don't actually send test message, just validate webhook URL format
            if not self.webhook_url or "webhook.office.com" not in self.webhook_url:
                raise ValueError("Invalid Teams webhook URL")
            
            self.is_connected = True
            self.logger.info("Connected to Microsoft Teams")
            return True
            
        except Exception as e:
            self.logger.error(f"Failed to connect to Teams: {e}")
            self.is_connected = False
            return False
    
    async def disconnect(self) -> bool:
        """Disconnect from Teams webhook"""
        if self.session:
            await self.session.close()
            self.session = None
        self.is_connected = False
        return True
    
    async def test_connection(self) -> bool:
        """Test Teams webhook connection"""
        return await self.connect()
    
    def get_supported_actions(self) -> List[ActionType]:
        """Get supported actions for Teams"""
        return [
            ActionType.SEND_ALERT,
            ActionType.NOTIFY,
            ActionType.ESCALATE
        ]
    
    async def execute_action(self, action_type: ActionType, target: str, 
                           context: Dict[str, Any]) -> ActionResult:
        """Execute action in Teams"""
        start_time = asyncio.get_event_loop().time()
        
        try:
            if action_type == ActionType.SEND_ALERT:
                result = await self._send_alert(target, context)
            elif action_type == ActionType.NOTIFY:
                result = await self._send_notification(target, context)
            elif action_type == ActionType.ESCALATE:
                result = await self._send_escalation(target, context)
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
    
    async def _send_alert(self, message: str, context: Dict[str, Any]) -> Dict[str, Any]:
        """Send security alert to Teams"""
        severity = context.get("severity", "medium").upper()
        color = self._get_severity_color(severity)
        
        card = {
            "@type": "MessageCard",
            "@context": "http://schema.org/extensions",
            "themeColor": color,
            "summary": f"Security Alert - {severity}",
            "sections": [
                {
                    "activityTitle": f"🚨 SECURITY ALERT - {severity}",
                    "activitySubtitle": "ThreatSentinel SOC Agent",
                    "activityImage": "https://img.icons8.com/color/48/000000/security-checked.png",
                    "text": message,
                    "facts": [
                        {
                            "name": "Investigation ID:",
                            "value": context.get("investigation_id", "N/A")
                        },
                        {
                            "name": "Risk Score:",
                            "value": str(context.get("risk_score", "N/A"))
                        },
                        {
                            "name": "Event Type:",
                            "value": context.get("event_type", "N/A")
                        },
                        {
                            "name": "Source IP:",
                            "value": context.get("source_ip", "N/A")
                        }
                    ]
                }
            ]
        }
        
        if context.get("actions"):
            actions_text = "\\n".join([f"• {action}" for action in context["actions"][:3]])
            card["sections"].append({
                "activityTitle": "Recommended Actions",
                "text": actions_text
            })
        
        response = await self._make_request("POST", self.webhook_url, json=card)
        
        return {
            "message": message,
            "severity": severity,
            "card_sent": True,
            "reference_id": f"teams_{hash(message) % 10000}"
        }
    
    async def _send_notification(self, message: str, context: Dict[str, Any]) -> Dict[str, Any]:
        """Send general notification to Teams"""
        card = {
            "@type": "MessageCard",
            "@context": "http://schema.org/extensions",
            "themeColor": "0078D4",
            "summary": "ThreatSentinel SOC Agent Notification",
            "sections": [
                {
                    "activityTitle": "ℹ️ ThreatSentinel SOC Agent Notification",
                    "text": message
                }
            ]
        }
        
        response = await self._make_request("POST", self.webhook_url, json=card)
        
        return {
            "message": message,
            "card_sent": True,
            "reference_id": f"teams_{hash(message) % 10000}"
        }
    
    async def _send_escalation(self, message: str, context: Dict[str, Any]) -> Dict[str, Any]:
        """Send escalation notification to Teams"""
        card = {
            "@type": "MessageCard",
            "@context": "http://schema.org/extensions",
            "themeColor": "FF0000",
            "summary": "ESCALATION REQUIRED",
            "sections": [
                {
                    "activityTitle": "🔥 ESCALATION REQUIRED",
                    "activitySubtitle": "Immediate attention needed",
                    "text": message,
                    "facts": [
                        {
                            "name": "Investigation ID:",
                            "value": context.get("investigation_id", "N/A")
                        },
                        {
                            "name": "Escalated to:",
                            "value": context.get("analyst", "Security Team")
                        }
                    ]
                }
            ]
        }
        
        response = await self._make_request("POST", self.webhook_url, json=card)
        
        return {
            "message": message,
            "escalated_to": context.get("analyst", "Security Team"),
            "card_sent": True,
            "reference_id": f"teams_{hash(message) % 10000}"
        }
    
    def _get_severity_color(self, severity: str) -> str:
        """Get color based on severity level"""
        colors = {
            "LOW": "00FF00",      # Green
            "MEDIUM": "FFA500",   # Orange
            "HIGH": "FF4500",     # Red Orange
            "CRITICAL": "FF0000"  # Red
        }
        return colors.get(severity, "FFA500")


class EmailIntegration(BaseIntegration):
    """
    Email Integration for notifications and alerts
    
    Supports sending email notifications via SMTP
    """
    
    def __init__(self, config: Dict[str, Any]):
        super().__init__("Email", IntegrationType.COMMUNICATION, config)
        self.smtp_server = config.get("smtp_server")
        self.smtp_port = config.get("smtp_port", 587)
        self.username = config.get("username")
        self.password = config.get("password")
        self.from_email = config.get("from_email")
        self.use_tls = config.get("use_tls", True)
        self.default_recipients = config.get("default_recipients", [])
        
    async def connect(self) -> bool:
        """Test SMTP connection"""
        try:
            # Test SMTP connection in a separate thread to avoid blocking
            await asyncio.get_event_loop().run_in_executor(
                None, self._test_smtp_connection
            )
            
            self.is_connected = True
            self.logger.info("Connected to SMTP server")
            return True
            
        except Exception as e:
            self.logger.error(f"Failed to connect to SMTP: {e}")
            self.is_connected = False
            return False
    
    def _test_smtp_connection(self):
        """Test SMTP connection synchronously"""
        server = smtplib.SMTP(self.smtp_server, self.smtp_port)
        if self.use_tls:
            server.starttls()
        server.login(self.username, self.password)
        server.quit()
    
    async def disconnect(self) -> bool:
        """Disconnect (no persistent connection for email)"""
        self.is_connected = False
        return True
    
    async def test_connection(self) -> bool:
        """Test SMTP connection"""
        return await self.connect()
    
    def get_supported_actions(self) -> List[ActionType]:
        """Get supported actions for Email"""
        return [
            ActionType.SEND_ALERT,
            ActionType.NOTIFY,
            ActionType.ESCALATE
        ]
    
    async def execute_action(self, action_type: ActionType, target: str, 
                           context: Dict[str, Any]) -> ActionResult:
        """Execute action via Email"""
        start_time = asyncio.get_event_loop().time()
        
        try:
            if action_type == ActionType.SEND_ALERT:
                result = await self._send_alert(target, context)
            elif action_type == ActionType.NOTIFY:
                result = await self._send_notification(target, context)
            elif action_type == ActionType.ESCALATE:
                result = await self._send_escalation(target, context)
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
    
    async def _send_alert(self, message: str, context: Dict[str, Any]) -> Dict[str, Any]:
        """Send security alert via email"""
        recipients = context.get("recipients", self.default_recipients)
        severity = context.get("severity", "medium").upper()
        
        subject = f"🚨 SECURITY ALERT - {severity} - ThreatSentinel SOC Agent"
        
        # Create HTML email body
        html_body = f"""
        <html>
        <body>
            <h2 style="color: red;">🚨 SECURITY ALERT - {severity}</h2>
            <p><strong>Message:</strong> {message}</p>
            
            <table border="1" style="border-collapse: collapse;">
                <tr><td><strong>Investigation ID</strong></td><td>{context.get('investigation_id', 'N/A')}</td></tr>
                <tr><td><strong>Risk Score</strong></td><td>{context.get('risk_score', 'N/A')}</td></tr>
                <tr><td><strong>Event Type</strong></td><td>{context.get('event_type', 'N/A')}</td></tr>
                <tr><td><strong>Source IP</strong></td><td>{context.get('source_ip', 'N/A')}</td></tr>
            </table>
            
            {self._format_actions_html(context.get('actions', []))}
            
            <p><em>Generated by ThreatSentinel SOC Agent</em></p>
        </body>
        </html>
        """
        
        message_id = await self._send_email(recipients, subject, html_body)
        
        return {
            "message": message,
            "severity": severity,
            "recipients": recipients,
            "reference_id": message_id
        }
    
    async def _send_notification(self, message: str, context: Dict[str, Any]) -> Dict[str, Any]:
        """Send general notification via email"""
        recipients = context.get("recipients", self.default_recipients)
        subject = "ℹ️ ThreatSentinel SOC Agent Notification"
        
        html_body = f"""
        <html>
        <body>
            <h2>ℹ️ ThreatSentinel SOC Agent Notification</h2>
            <p>{message}</p>
            <p><em>Generated by ThreatSentinel SOC Agent</em></p>
        </body>
        </html>
        """
        
        message_id = await self._send_email(recipients, subject, html_body)
        
        return {
            "message": message,
            "recipients": recipients,
            "reference_id": message_id
        }
    
    async def _send_escalation(self, message: str, context: Dict[str, Any]) -> Dict[str, Any]:
        """Send escalation notification via email"""
        recipients = context.get("recipients", self.default_recipients)
        subject = "🔥 ESCALATION REQUIRED - ThreatSentinel SOC Agent"
        
        html_body = f"""
        <html>
        <body>
            <h2 style="color: red;">🔥 ESCALATION REQUIRED</h2>
            <p><strong>Immediate attention needed</strong></p>
            <p>{message}</p>
            
            <table border="1" style="border-collapse: collapse;">
                <tr><td><strong>Investigation ID</strong></td><td>{context.get('investigation_id', 'N/A')}</td></tr>
                <tr><td><strong>Escalated to</strong></td><td>{context.get('analyst', 'Security Team')}</td></tr>
            </table>
            
            <p><em>Generated by ThreatSentinel SOC Agent</em></p>
        </body>
        </html>
        """
        
        message_id = await self._send_email(recipients, subject, html_body)
        
        return {
            "message": message,
            "escalated_to": context.get("analyst", "Security Team"),
            "recipients": recipients,
            "reference_id": message_id
        }
    
    async def _send_email(self, recipients: List[str], subject: str, html_body: str) -> str:
        """Send email using SMTP"""
        message_id = f"email_{hash(subject + html_body) % 100000}"
        
        # Send email in executor to avoid blocking
        await asyncio.get_event_loop().run_in_executor(
            None, self._send_email_sync, recipients, subject, html_body
        )
        
        return message_id
    
    def _send_email_sync(self, recipients: List[str], subject: str, html_body: str):
        """Send email synchronously"""
        msg = MIMEMultipart('alternative')
        msg['Subject'] = subject
        msg['From'] = self.from_email
        msg['To'] = ', '.join(recipients)
        
        # Add HTML part
        html_part = MIMEText(html_body, 'html')
        msg.attach(html_part)
        
        # Send email
        server = smtplib.SMTP(self.smtp_server, self.smtp_port)
        if self.use_tls:
            server.starttls()
        server.login(self.username, self.password)
        server.send_message(msg)
        server.quit()
    
    def _format_actions_html(self, actions: List[str]) -> str:
        """Format recommended actions as HTML"""
        if not actions:
            return ""
        
        actions_html = "<h3>Recommended Actions:</h3><ul>"
        for action in actions[:5]:  # Limit to 5 actions
            actions_html += f"<li>{action}</li>"
        actions_html += "</ul>"
        
        return actions_html 