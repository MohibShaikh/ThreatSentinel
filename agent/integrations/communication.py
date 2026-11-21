"""
Communication Integration Adapters (Slack, Microsoft Teams, Email)
"""

import asyncio
import html
import re
import smtplib
import ssl
import time
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from email.utils import make_msgid
from typing import Any, Dict, List, Optional

from ..guardrails import validate_outbound_url
from .base import ActionResult, ActionType, BaseIntegration, IntegrationType, stable_reference

SLACK_WEBHOOK_HOSTS = {"hooks.slack.com"}
# Legacy O365 connectors, Power Automate (Logic Apps) and Power Platform workflow URLs
TEAMS_WEBHOOK_HOSTS = {".webhook.office.com", ".logic.azure.com", ".api.powerplatform.com"}
_EMAIL_RE = re.compile(r"^[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,24}$")
SMTP_TIMEOUT_SECONDS = 15


def _slack_escape(value: Any) -> str:
    """Slack mrkdwn control characters; stops forged links and @channel pings."""
    return str(value if value is not None else "N/A").replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")


def _no_header_injection(value: str, what: str) -> str:
    if "\r" in value or "\n" in value:
        raise ValueError(f"Line breaks are not allowed in email {what}")
    return value


def _validate_email(address: str, what: str) -> str:
    address = _no_header_injection(str(address or "").strip(), what)
    if not _EMAIL_RE.fullmatch(address):
        raise ValueError(f"Invalid email address in {what}: {address!r}")
    return address


class _ActionDispatchMixin:
    """Shared execute_action for alert / notify / escalate integrations."""

    async def execute_action(self, action_type: ActionType, target: str,
                             context: Dict[str, Any]) -> ActionResult:
        start_time = time.monotonic()
        try:
            if action_type == ActionType.SEND_ALERT:
                result = await self._send_alert(target, context)
            elif action_type == ActionType.NOTIFY:
                result = await self._send_notification(target, context)
            elif action_type == ActionType.ESCALATE:
                result = await self._send_escalation(target, context)
            else:
                raise ValueError(f"Unsupported action: {action_type}")
            return ActionResult(
                success=True, action_type=action_type, target=target, details=result,
                execution_time=time.monotonic() - start_time, reference_id=result.get("reference_id"),
            )
        except Exception as e:
            self.logger.error(f"Action {action_type} failed: {type(e).__name__}: {e}")
            return ActionResult(
                success=False, action_type=action_type, target=target, details={},
                execution_time=time.monotonic() - start_time, error_message=str(e),
            )

    def get_supported_actions(self) -> List[ActionType]:
        return [ActionType.SEND_ALERT, ActionType.NOTIFY, ActionType.ESCALATE]


class SlackIntegration(_ActionDispatchMixin, BaseIntegration):
    """Slack notifications via incoming webhook or bot token."""

    def __init__(self, config: Dict[str, Any]):
        super().__init__("Slack", IntegrationType.COMMUNICATION, config)
        self.webhook_url = config.get("webhook_url")
        self.bot_token = config.get("bot_token")
        self.default_channel = config.get("default_channel", "#security-alerts")

    def _checked_webhook(self) -> str:
        return validate_outbound_url(self.webhook_url, allowed_hosts=SLACK_WEBHOOK_HOSTS)

    async def connect(self) -> bool:
        try:
            if self.webhook_url:
                self._checked_webhook()
            self.session = self._create_session()
            if self.bot_token:
                self.session.headers.update({"Authorization": f"Bearer {self.bot_token}"})
                await self._make_request("GET", "https://slack.com/api/auth.test")
            self.is_connected = True
            self.logger.info("Connected to Slack")
            return True
        except Exception as e:
            self.logger.error(f"Failed to connect to Slack: {e}")
            self.is_connected = False
            return False

    async def disconnect(self) -> bool:
        if self.session:
            await self.session.close()
            self.session = None
        self.is_connected = False
        return True

    async def test_connection(self) -> bool:
        return await self.connect()

    async def _send_alert(self, message: str, context: Dict[str, Any]) -> Dict[str, Any]:
        channel = context.get("channel", self.default_channel)
        severity = str(context.get("severity", "medium")).upper()
        blocks = [
            {"type": "header", "text": {"type": "plain_text", "text": f"SECURITY ALERT - {severity}"[:150]}},
            {"type": "section", "text": {"type": "mrkdwn", "text": f"*Message:* {_slack_escape(message)}"[:3000]}},
            {"type": "section", "fields": [
                {"type": "mrkdwn", "text": f"*Investigation ID:*\n{_slack_escape(context.get('investigation_id'))}"},
                {"type": "mrkdwn", "text": f"*Risk Score:*\n{_slack_escape(context.get('risk_score'))}"},
                {"type": "mrkdwn", "text": f"*Event Type:*\n{_slack_escape(context.get('event_type'))}"},
                {"type": "mrkdwn", "text": f"*Source:*\n{_slack_escape(context.get('source_ip'))}"},
            ]},
        ]
        if context.get("actions"):
            actions_text = "\n".join(f"• {_slack_escape(a)}" for a in context["actions"][:3])
            blocks.append({"type": "section", "text": {"type": "mrkdwn",
                                                       "text": f"*Recommended Actions:*\n{actions_text}"[:3000]}})
        payload = {"channel": channel, "blocks": blocks, "text": f"Security alert ({severity})",
                   "username": "ThreatSentinel SOC Agent", "icon_emoji": ":shield:"}
        response = await (self._send_webhook(payload) if self.webhook_url else self._send_via_api(payload))
        return {"message": message, "channel": channel, "severity": severity,
                "reference_id": response.get("ts") or response.get("timestamp")}

    async def _send_notification(self, message: str, context: Dict[str, Any]) -> Dict[str, Any]:
        channel = context.get("channel", self.default_channel)
        payload = {"channel": channel,
                   "text": f"*ThreatSentinel SOC Agent Notification*\n{_slack_escape(message)}"[:3000],
                   "username": "ThreatSentinel SOC Agent", "icon_emoji": ":information_source:"}
        response = await (self._send_webhook(payload) if self.webhook_url else self._send_via_api(payload))
        return {"message": message, "channel": channel,
                "reference_id": response.get("ts") or response.get("timestamp")}

    async def _send_escalation(self, message: str, context: Dict[str, Any]) -> Dict[str, Any]:
        channel = context.get("channel", self.default_channel)
        analyst = str(context.get("analyst", "<!channel>"))
        # Only Slack mention syntax is allowed through unescaped, never free text
        if not re.fullmatch(r"<!(channel|here)>|<@[A-Z0-9]+>|<!subteam\^[A-Z0-9]+>", analyst):
            analyst = _slack_escape(analyst)
        text = (f"*ESCALATION REQUIRED*\n\n{analyst}\n\n{_slack_escape(message)}\n\n"
                f"*Investigation ID:* {_slack_escape(context.get('investigation_id'))}\n*Requires immediate attention*")
        payload = {"channel": channel, "text": text[:3000],
                   "username": "ThreatSentinel SOC Agent", "icon_emoji": ":fire:"}
        response = await (self._send_webhook(payload) if self.webhook_url else self._send_via_api(payload))
        return {"message": message, "channel": channel, "escalated_to": analyst,
                "reference_id": response.get("ts") or response.get("timestamp")}

    async def _send_webhook(self, payload: Dict[str, Any]) -> Dict[str, Any]:
        await self._make_request("POST", self._checked_webhook(), json=payload)
        return {"timestamp": time.time()}

    async def _send_via_api(self, payload: Dict[str, Any]) -> Dict[str, Any]:
        response = await self._make_request("POST", "https://slack.com/api/chat.postMessage", json=payload)
        if isinstance(response, dict) and response.get("ok") is False:
            raise Exception(f"Slack API error: {response.get('error', 'unknown')}")
        return response


class TeamsIntegration(_ActionDispatchMixin, BaseIntegration):
    """Microsoft Teams via Workflows (Adaptive Card) or legacy connector (MessageCard)."""

    def __init__(self, config: Dict[str, Any]):
        super().__init__("Teams", IntegrationType.COMMUNICATION, config)
        self.webhook_url = config.get("webhook_url")
        self.tenant_id = config.get("tenant_id")

    def _checked_webhook(self) -> str:
        return validate_outbound_url(self.webhook_url, allowed_hosts=TEAMS_WEBHOOK_HOSTS)

    @property
    def uses_workflows(self) -> bool:
        """Power Automate / Workflows endpoints expect Adaptive Cards."""
        url = (self.webhook_url or "").lower()
        return (".logic.azure.com" in url or ".powerplatform.com" in url
                or self.config.get("card_format") == "adaptive")

    async def connect(self) -> bool:
        try:
            self._checked_webhook()
            self.session = self._create_session()
            self.is_connected = True
            self.logger.info("Connected to Microsoft Teams")
            return True
        except Exception as e:
            self.logger.error(f"Failed to connect to Teams: {e}")
            self.is_connected = False
            return False

    async def disconnect(self) -> bool:
        if self.session:
            await self.session.close()
            self.session = None
        self.is_connected = False
        return True

    async def test_connection(self) -> bool:
        return await self.connect()

    def _build_card(self, title: str, subtitle: str, text: str, facts: List[Dict[str, str]],
                    color: str, extra: Optional[List[str]] = None) -> Dict[str, Any]:
        if self.uses_workflows:
            body: List[Dict[str, Any]] = [
                {"type": "TextBlock", "text": title, "weight": "Bolder", "size": "Large", "wrap": True,
                 "color": "Attention" if color in ("FF0000", "FF4500") else "Default"},
            ]
            if subtitle:
                body.append({"type": "TextBlock", "text": subtitle, "isSubtle": True, "wrap": True})
            body.append({"type": "TextBlock", "text": text, "wrap": True})
            if facts:
                body.append({"type": "FactSet", "facts": [{"title": f["name"], "value": f["value"]} for f in facts]})
            for line in extra or []:
                body.append({"type": "TextBlock", "text": f"- {line}", "wrap": True})
            return {
                "type": "message",
                "attachments": [{
                    "contentType": "application/vnd.microsoft.card.adaptive",
                    "contentUrl": None,
                    "content": {
                        "$schema": "http://adaptivecards.io/schemas/adaptive-card.json",
                        "type": "AdaptiveCard", "version": "1.4", "body": body,
                    },
                }],
            }
        card: Dict[str, Any] = {
            "@type": "MessageCard", "@context": "http://schema.org/extensions",
            "themeColor": color, "summary": title,
            "sections": [{"activityTitle": title, "activitySubtitle": subtitle, "text": text, "facts": facts}],
        }
        if extra:
            card["sections"].append({"activityTitle": "Recommended Actions",
                                     "text": "\n".join(f"- {e}" for e in extra)})
        return card

    async def _post(self, card: Dict[str, Any]) -> None:
        await self._make_request("POST", self._checked_webhook(), json=card)

    async def _send_alert(self, message: str, context: Dict[str, Any]) -> Dict[str, Any]:
        severity = str(context.get("severity", "medium")).upper()
        facts = [
            {"name": "Investigation ID", "value": str(context.get("investigation_id", "N/A"))},
            {"name": "Risk Score", "value": str(context.get("risk_score", "N/A"))},
            {"name": "Event Type", "value": str(context.get("event_type", "N/A"))},
            {"name": "Source IP", "value": str(context.get("source_ip", "N/A"))},
        ]
        actions = [str(a) for a in (context.get("actions") or [])[:3]]
        await self._post(self._build_card(f"SECURITY ALERT - {severity}", "ThreatSentinel SOC Agent",
                                          str(message), facts, self._get_severity_color(severity), actions))
        return {"message": message, "severity": severity, "card_sent": True,
                "reference_id": f"teams_{stable_reference(message, context.get('investigation_id'))}"}

    async def _send_notification(self, message: str, context: Dict[str, Any]) -> Dict[str, Any]:
        await self._post(self._build_card("ThreatSentinel SOC Agent Notification", "", str(message), [], "0078D4"))
        return {"message": message, "card_sent": True, "reference_id": f"teams_{stable_reference(message)}"}

    async def _send_escalation(self, message: str, context: Dict[str, Any]) -> Dict[str, Any]:
        facts = [
            {"name": "Investigation ID", "value": str(context.get("investigation_id", "N/A"))},
            {"name": "Escalated to", "value": str(context.get("analyst", "Security Team"))},
        ]
        await self._post(self._build_card("ESCALATION REQUIRED", "Immediate attention needed",
                                          str(message), facts, "FF0000"))
        return {"message": message, "escalated_to": context.get("analyst", "Security Team"), "card_sent": True,
                "reference_id": f"teams_{stable_reference(message, context.get('investigation_id'))}"}

    def _get_severity_color(self, severity: str) -> str:
        return {"LOW": "00FF00", "MEDIUM": "FFA500", "HIGH": "FF4500", "CRITICAL": "FF0000"}.get(severity, "FFA500")


class EmailIntegration(_ActionDispatchMixin, BaseIntegration):
    """Email notifications over SMTP with verified STARTTLS."""

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
        try:
            await asyncio.get_running_loop().run_in_executor(None, self._test_smtp_connection)
            self.is_connected = True
            self.logger.info("Connected to SMTP server")
            return True
        except Exception as e:
            self.logger.error(f"Failed to connect to SMTP: {e}")
            self.is_connected = False
            return False

    def _smtp(self) -> smtplib.SMTP:
        server = smtplib.SMTP(self.smtp_server, self.smtp_port, timeout=SMTP_TIMEOUT_SECONDS)
        try:
            if self.use_tls:
                server.starttls(context=ssl.create_default_context())
            if self.username:
                server.login(self.username, self.password)
        except Exception:
            server.close()
            raise
        return server

    def _test_smtp_connection(self):
        with self._smtp() as server:
            server.noop()

    async def disconnect(self) -> bool:
        self.is_connected = False
        return True

    async def test_connection(self) -> bool:
        return await self.connect()

    def _recipients(self, context: Dict[str, Any]) -> List[str]:
        recipients = context.get("recipients") or self.default_recipients
        if isinstance(recipients, str):
            recipients = [recipients]
        validated = [_validate_email(r, "recipients") for r in recipients]
        if not validated:
            raise ValueError("No email recipients configured")
        return validated

    @staticmethod
    def _e(value: Any, default: str = "N/A") -> str:
        return html.escape(str(value if value is not None else default))

    async def _send_alert(self, message: str, context: Dict[str, Any]) -> Dict[str, Any]:
        recipients = self._recipients(context)
        severity = str(context.get("severity", "medium")).upper()
        subject = f"SECURITY ALERT - {severity} - ThreatSentinel SOC Agent"
        html_body = f"""<html><body>
<h2 style="color: red;">SECURITY ALERT - {self._e(severity)}</h2>
<p><strong>Message:</strong> {self._e(message)}</p>
<table border="1" style="border-collapse: collapse;">
<tr><td><strong>Investigation ID</strong></td><td>{self._e(context.get('investigation_id'))}</td></tr>
<tr><td><strong>Risk Score</strong></td><td>{self._e(context.get('risk_score'))}</td></tr>
<tr><td><strong>Event Type</strong></td><td>{self._e(context.get('event_type'))}</td></tr>
<tr><td><strong>Source IP</strong></td><td>{self._e(context.get('source_ip'))}</td></tr>
</table>
{self._format_actions_html(context.get('actions', []))}
<p><em>Generated by ThreatSentinel SOC Agent</em></p>
</body></html>"""
        message_id = await self._send_email(recipients, subject, html_body)
        return {"message": message, "severity": severity, "recipients": recipients, "reference_id": message_id}

    async def _send_notification(self, message: str, context: Dict[str, Any]) -> Dict[str, Any]:
        recipients = self._recipients(context)
        subject = "ThreatSentinel SOC Agent Notification"
        html_body = f"""<html><body>
<h2>ThreatSentinel SOC Agent Notification</h2>
<p>{self._e(message)}</p>
<p><em>Generated by ThreatSentinel SOC Agent</em></p>
</body></html>"""
        message_id = await self._send_email(recipients, subject, html_body)
        return {"message": message, "recipients": recipients, "reference_id": message_id}

    async def _send_escalation(self, message: str, context: Dict[str, Any]) -> Dict[str, Any]:
        recipients = self._recipients(context)
        subject = "ESCALATION REQUIRED - ThreatSentinel SOC Agent"
        html_body = f"""<html><body>
<h2 style="color: red;">ESCALATION REQUIRED</h2>
<p><strong>Immediate attention needed</strong></p>
<p>{self._e(message)}</p>
<table border="1" style="border-collapse: collapse;">
<tr><td><strong>Investigation ID</strong></td><td>{self._e(context.get('investigation_id'))}</td></tr>
<tr><td><strong>Escalated to</strong></td><td>{self._e(context.get('analyst'), 'Security Team')}</td></tr>
</table>
<p><em>Generated by ThreatSentinel SOC Agent</em></p>
</body></html>"""
        message_id = await self._send_email(recipients, subject, html_body)
        return {"message": message, "escalated_to": context.get("analyst", "Security Team"),
                "recipients": recipients, "reference_id": message_id}

    async def _send_email(self, recipients: List[str], subject: str, html_body: str) -> str:
        _no_header_injection(subject, "subject")
        _validate_email(self.from_email, "from address")
        for r in recipients:
            _validate_email(r, "recipients")
        domain = self.from_email.split("@", 1)[1]
        message_id = make_msgid(idstring=stable_reference(subject, html_body), domain=domain)
        await asyncio.get_running_loop().run_in_executor(
            None, self._send_email_sync, recipients, subject, html_body, message_id)
        return message_id

    def _send_email_sync(self, recipients: List[str], subject: str, html_body: str,
                         message_id: Optional[str] = None):
        msg = MIMEMultipart("alternative")
        msg["Subject"] = subject
        msg["From"] = self.from_email
        msg["To"] = ", ".join(recipients)
        if message_id:
            msg["Message-ID"] = message_id
        msg.attach(MIMEText(html_body, "html", "utf-8"))
        with self._smtp() as server:
            server.send_message(msg)

    def _format_actions_html(self, actions: List[Any]) -> str:
        if not actions:
            return ""
        items = "".join(f"<li>{html.escape(str(a))}</li>" for a in actions[:5])
        return f"<h3>Recommended Actions:</h3><ul>{items}</ul>"
