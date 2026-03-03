"""
Unit tests for agent/integrations/

Tests the modular integration framework for SOC tools including
firewalls, SIEMs, communication tools, and incident response platforms.
"""

import pytest
import asyncio
import json
from datetime import datetime
from unittest.mock import AsyncMock, MagicMock, patch
from typing import Dict, Any

from agent.integrations.base import (
    BaseIntegration, IntegrationType, ActionType, ActionResult, IntegrationResponse
)
from agent.integrations.firewall import (
    PaloAltoIntegration, FortinetIntegration, PfSenseIntegration
)
from agent.integrations.siem import (
    SplunkIntegration, QRadarIntegration, SentinelIntegration
)
from agent.integrations.communication import (
    SlackIntegration, TeamsIntegration, EmailIntegration
)
from agent.integrations.incident import (
    ServiceNowIntegration, JiraIntegration, PagerDutyIntegration
)
from agent.integrations.registry import IntegrationRegistry


class TestIntegrationType:
    """Test IntegrationType enum"""

    def test_integration_type_values(self):
        """Test IntegrationType enum values"""
        assert IntegrationType.FIREWALL.value == "firewall"
        assert IntegrationType.SIEM.value == "siem"
        assert IntegrationType.COMMUNICATION.value == "communication"
        assert IntegrationType.INCIDENT_RESPONSE.value == "incident_response"


class TestActionType:
    """Test ActionType enum"""

    def test_action_type_values(self):
        """Test ActionType enum values"""
        assert ActionType.BLOCK_IP.value == "block_ip"
        assert ActionType.BLOCK_URL.value == "block_url"
        assert ActionType.CREATE_INCIDENT.value == "create_incident"
        assert ActionType.SEND_ALERT.value == "send_alert"
        assert ActionType.NOTIFY.value == "notify"
        assert ActionType.ESCALATE.value == "escalate"


class TestActionResult:
    """Test ActionResult dataclass"""

    def test_action_result_creation(self):
        """Test basic ActionResult creation"""
        result = ActionResult(
            success=True,
            action_type=ActionType.BLOCK_IP,
            target="192.168.1.100",
            details={"rule_id": "rule_123"},
            execution_time=0.25
        )

        assert result.success is True
        assert result.action_type == ActionType.BLOCK_IP
        assert result.target == "192.168.1.100"
        assert result.details["rule_id"] == "rule_123"
        assert result.execution_time == 0.25
        assert isinstance(result.timestamp, datetime)


class TestIntegrationResponse:
    """Test IntegrationResponse model"""

    def test_integration_response_creation(self):
        """Test IntegrationResponse creation"""
        action_result = ActionResult(
            success=True,
            action_type=ActionType.BLOCK_IP,
            target="192.168.1.100",
            details={"rule_id": "rule_456"},
            execution_time=0.1
        )
        response = IntegrationResponse(
            integration_name="test",
            integration_type=IntegrationType.FIREWALL,
            success=True,
            actions_executed=[action_result],
            total_execution_time=0.1,
        )

        assert response.success is True
        assert response.integration_name == "test"
        assert response.integration_type == IntegrationType.FIREWALL
        assert len(response.actions_executed) == 1
        assert response.actions_executed[0].details["rule_id"] == "rule_456"
        assert response.error_details is None


class TestBaseIntegration:
    """Test BaseIntegration abstract class"""

    @pytest.fixture
    def mock_integration_config(self):
        """Mock integration configuration"""
        return {
            "host": "test.example.com",
            "port": 443,
            "username": "test_user",
            "password": "test_pass",
            "api_key": "test_key_123"
        }

    def test_base_integration_initialization(self, mock_integration_config):
        """Test BaseIntegration initialization"""

        class MockIntegration(BaseIntegration):
            async def connect(self): pass
            async def disconnect(self): pass
            async def test_connection(self): pass
            async def execute_action(self, action_type, target, context): pass
            def get_supported_actions(self): return []

        integration = MockIntegration("test_integration", IntegrationType.FIREWALL, mock_integration_config)

        assert integration.config == mock_integration_config
        assert integration.name == "test_integration"
        assert integration.session is None
        assert integration.is_connected is False

    def test_base_integration_get_status(self, mock_integration_config):
        """Test get_status of BaseIntegration"""
        class MockIntegration(BaseIntegration):
            async def connect(self): pass
            async def disconnect(self): pass
            async def test_connection(self): pass
            async def execute_action(self, action_type, target, context): pass
            def get_supported_actions(self): return [ActionType.BLOCK_IP]

        integration = MockIntegration("test_integration", IntegrationType.FIREWALL, mock_integration_config)
        status = integration.get_status()

        assert status["name"] == "test_integration"
        assert status["type"] == "firewall"
        assert status["connected"] is False
        assert "block_ip" in status["supported_actions"]


class TestFirewallIntegrations:
    """Test firewall integration implementations"""

    @pytest.fixture
    def palo_alto_config(self):
        return {
            "hostname": "firewall.company.com",
            "api_key": "palo_api_key_123",
            "port": 443,
            "vsys": "vsys1"
        }

    @pytest.fixture
    def fortinet_config(self):
        return {
            "hostname": "fortinet.company.com",
            "api_key": "fortinet_api_key",
            "vdom": "root"
        }

    @pytest.fixture
    def pfsense_config(self):
        return {
            "hostname": "pfsense.company.com",
            "api_key": "pfsense_api_key",
            "api_secret": "pfsense_api_secret"
        }

    def test_palo_alto_initialization(self, palo_alto_config):
        """Test PaloAlto integration initialization"""
        integration = PaloAltoIntegration(palo_alto_config)

        assert integration.name == "PaloAlto"
        assert integration.integration_type == IntegrationType.FIREWALL
        assert ActionType.BLOCK_IP in integration.get_supported_actions()
        assert ActionType.BLOCK_URL in integration.get_supported_actions()

    @pytest.mark.asyncio
    async def test_palo_alto_block_ip(self, palo_alto_config):
        """Test PaloAlto IP blocking"""
        integration = PaloAltoIntegration(palo_alto_config)

        mock_return = {"msg": {"line": "ref_123"}}

        with patch.object(integration, '_make_request', new_callable=AsyncMock, return_value=mock_return):
            result = await integration.execute_action(
                ActionType.BLOCK_IP,
                "192.168.1.100",
                {"reason": "Malicious activity detected"}
            )

            assert result.success is True
            assert result.action_type == ActionType.BLOCK_IP
            assert result.target == "192.168.1.100"

    def test_fortinet_initialization(self, fortinet_config):
        """Test Fortinet integration initialization"""
        integration = FortinetIntegration(fortinet_config)

        assert integration.name == "Fortinet"
        assert integration.integration_type == IntegrationType.FIREWALL
        assert ActionType.BLOCK_IP in integration.get_supported_actions()

    @pytest.mark.asyncio
    async def test_fortinet_block_url(self, fortinet_config):
        """Test Fortinet URL blocking"""
        integration = FortinetIntegration(fortinet_config)

        mock_return = {"mkey": "policy_123"}

        with patch.object(integration, '_make_request', new_callable=AsyncMock, return_value=mock_return):
            result = await integration.execute_action(
                ActionType.BLOCK_URL,
                "https://malicious-site.com",
                {"reason": "Phishing detected"}
            )

            assert result.success is True
            assert result.action_type == ActionType.BLOCK_URL

    def test_pfsense_initialization(self, pfsense_config):
        """Test pfSense integration initialization"""
        integration = PfSenseIntegration(pfsense_config)

        assert integration.name == "pfSense"
        assert integration.integration_type == IntegrationType.FIREWALL
        assert ActionType.BLOCK_IP in integration.get_supported_actions()


class TestSIEMIntegrations:
    """Test SIEM integration implementations"""

    @pytest.fixture
    def splunk_config(self):
        return {
            "hostname": "splunk.company.com",
            "port": 8089,
            "username": "admin",
            "password": "splunk_pass",
            "index": "security"
        }

    @pytest.fixture
    def qradar_config(self):
        return {
            "hostname": "qradar.company.com",
            "sec_token": "qradar_token_123"
        }

    @pytest.fixture
    def sentinel_config(self):
        return {
            "tenant_id": "tenant_123",
            "client_id": "client_123",
            "client_secret": "secret_123",
            "subscription_id": "sub_123",
            "resource_group": "rg_123",
            "workspace_name": "workspace_123"
        }

    def test_splunk_initialization(self, splunk_config):
        """Test Splunk integration initialization"""
        integration = SplunkIntegration(splunk_config)

        assert integration.name == "Splunk"
        assert integration.integration_type == IntegrationType.SIEM
        assert ActionType.CREATE_INCIDENT in integration.get_supported_actions()
        assert ActionType.SEND_ALERT in integration.get_supported_actions()

    @pytest.mark.asyncio
    async def test_splunk_create_incident(self, splunk_config):
        """Test Splunk incident creation"""
        integration = SplunkIntegration(splunk_config)

        mock_return = {"event_id": "INC_001"}

        with patch.object(integration, '_make_request', new_callable=AsyncMock, return_value=mock_return):
            result = await integration.execute_action(
                ActionType.CREATE_INCIDENT,
                "Suspicious IP Activity",
                {"severity": "high", "description": "Malicious activity detected from 192.168.1.100"}
            )

            assert result.success is True
            assert result.action_type == ActionType.CREATE_INCIDENT

    def test_qradar_initialization(self, qradar_config):
        """Test QRadar integration initialization"""
        integration = QRadarIntegration(qradar_config)

        assert integration.name == "QRadar"
        assert integration.integration_type == IntegrationType.SIEM
        assert ActionType.ADD_TO_WATCHLIST in integration.get_supported_actions()

    def test_sentinel_initialization(self, sentinel_config):
        """Test Sentinel integration initialization"""
        integration = SentinelIntegration(sentinel_config)

        assert integration.name == "Sentinel"
        assert integration.integration_type == IntegrationType.SIEM
        assert ActionType.CREATE_INCIDENT in integration.get_supported_actions()


class TestCommunicationIntegrations:
    """Test communication integration implementations"""

    @pytest.fixture
    def slack_config(self):
        return {
            "webhook_url": "https://hooks.slack.com/services/T00000000/B00000000/XXXXXXXXXXXXXXXXXXXXXXXX",
            "bot_token": "xoxb-test-token",
            "default_channel": "#security-alerts"
        }

    @pytest.fixture
    def teams_config(self):
        return {
            "webhook_url": "https://outlook.office.com/webhook.office.com/xxxx",
            "tenant_id": "tenant_123"
        }

    @pytest.fixture
    def email_config(self):
        return {
            "smtp_server": "smtp.company.com",
            "smtp_port": 587,
            "username": "alerts@company.com",
            "password": "email_pass",
            "from_email": "threatsentinel@company.com",
            "default_recipients": ["soc@company.com"]
        }

    def test_slack_initialization(self, slack_config):
        """Test Slack integration initialization"""
        integration = SlackIntegration(slack_config)

        assert integration.name == "Slack"
        assert integration.integration_type == IntegrationType.COMMUNICATION
        assert ActionType.SEND_ALERT in integration.get_supported_actions()
        assert ActionType.NOTIFY in integration.get_supported_actions()

    @pytest.mark.asyncio
    async def test_slack_send_alert(self, slack_config):
        """Test Slack alert sending"""
        integration = SlackIntegration(slack_config)

        mock_return = {"timestamp": 1234567890.123456}

        with patch.object(integration, '_send_webhook', new_callable=AsyncMock, return_value=mock_return):
            result = await integration.execute_action(
                ActionType.SEND_ALERT,
                "High-risk IP detected: 192.168.1.100",
                {"severity": "high", "channel": "#security-alerts"}
            )

            assert result.success is True
            assert result.action_type == ActionType.SEND_ALERT

    def test_teams_initialization(self, teams_config):
        """Test Teams integration initialization"""
        integration = TeamsIntegration(teams_config)

        assert integration.name == "Teams"
        assert integration.integration_type == IntegrationType.COMMUNICATION

    def test_email_initialization(self, email_config):
        """Test Email integration initialization"""
        integration = EmailIntegration(email_config)

        assert integration.name == "Email"
        assert integration.integration_type == IntegrationType.COMMUNICATION
        assert ActionType.NOTIFY in integration.get_supported_actions()


class TestIncidentIntegrations:
    """Test incident response integration implementations"""

    @pytest.fixture
    def servicenow_config(self):
        return {
            "instance_url": "https://company.service-now.com",
            "username": "itsm_user",
            "password": "itsm_pass",
        }

    @pytest.fixture
    def jira_config(self):
        return {
            "server_url": "https://company.atlassian.net",
            "username": "jira_user",
            "api_token": "jira_token_123",
            "project_key": "SEC"
        }

    @pytest.fixture
    def pagerduty_config(self):
        return {
            "api_token": "pagerduty_token_123",
            "service_key": "SERVICE123",
            "routing_key": "routing_123"
        }

    def test_servicenow_initialization(self, servicenow_config):
        """Test ServiceNow integration initialization"""
        integration = ServiceNowIntegration(servicenow_config)

        assert integration.name == "ServiceNow"
        assert integration.integration_type == IntegrationType.INCIDENT_RESPONSE
        assert ActionType.CREATE_INCIDENT in integration.get_supported_actions()

    @pytest.mark.asyncio
    async def test_servicenow_create_incident(self, servicenow_config):
        """Test ServiceNow incident creation"""
        integration = ServiceNowIntegration(servicenow_config)

        mock_return = {
            "result": {"sys_id": "incident_123", "number": "INC0001234", "state": "1"}
        }

        with patch.object(integration, '_make_request', new_callable=AsyncMock, return_value=mock_return):
            result = await integration.execute_action(
                ActionType.CREATE_INCIDENT,
                "Malicious IP Activity",
                {"severity": "high", "description": "Suspicious activity from 192.168.1.100"}
            )

            assert result.success is True
            assert result.action_type == ActionType.CREATE_INCIDENT

    def test_jira_initialization(self, jira_config):
        """Test Jira integration initialization"""
        integration = JiraIntegration(jira_config)

        assert integration.name == "Jira"
        assert integration.integration_type == IntegrationType.INCIDENT_RESPONSE
        assert ActionType.CREATE_INCIDENT in integration.get_supported_actions()

    def test_pagerduty_initialization(self, pagerduty_config):
        """Test PagerDuty integration initialization"""
        integration = PagerDutyIntegration(pagerduty_config)

        assert integration.name == "PagerDuty"
        assert integration.integration_type == IntegrationType.INCIDENT_RESPONSE
        assert ActionType.ESCALATE in integration.get_supported_actions()


class TestIntegrationRegistry:
    """Test IntegrationRegistry functionality"""

    @pytest.fixture
    def sample_registry_config(self):
        """Sample integration configurations in the format IntegrationRegistry expects"""
        return {
            "integrations": {
                "palo_alto": {
                    "hostname": "firewall.company.com",
                    "api_key": "palo_key_123"
                },
                "splunk": {
                    "hostname": "splunk.company.com",
                    "username": "admin",
                    "password": "splunk_pass"
                },
                "slack": {
                    "webhook_url": "https://hooks.slack.com/test",
                    "bot_token": "xoxb-test"
                }
            }
        }

    @pytest.fixture
    def registry(self, sample_registry_config):
        """Create IntegrationRegistry with sample configs"""
        return IntegrationRegistry(sample_registry_config)

    def test_registry_initialization(self, registry):
        """Test registry initialization"""
        assert len(registry.integrations) == 3
        assert "palo_alto" in registry.integrations
        assert "splunk" in registry.integrations
        assert "slack" in registry.integrations

    def test_get_integrations_by_type(self, registry):
        """Test getting integrations by type (requires active integrations)"""
        for name, integration in registry.integrations.items():
            registry.active_integrations[name] = integration

        firewall_integrations = registry.get_integrations_by_type(IntegrationType.FIREWALL)
        assert len(firewall_integrations) == 1
        assert firewall_integrations[0].name == "PaloAlto"

        siem_integrations = registry.get_integrations_by_type(IntegrationType.SIEM)
        assert len(siem_integrations) == 1
        assert siem_integrations[0].name == "Splunk"

    def test_get_integrations_by_action(self, registry):
        """Test getting integrations by supported action"""
        for name, integration in registry.integrations.items():
            registry.active_integrations[name] = integration

        block_ip_integrations = registry.get_integrations_by_action(ActionType.BLOCK_IP)
        assert len(block_ip_integrations) >= 1

        send_alert_integrations = registry.get_integrations_by_action(ActionType.SEND_ALERT)
        assert len(send_alert_integrations) >= 1

    @pytest.mark.asyncio
    async def test_connect_all(self, registry):
        """Test connecting to all integrations"""
        for integration in registry.integrations.values():
            integration.connect = AsyncMock(return_value=True)

        results = await registry.connect_all()

        for integration in registry.integrations.values():
            integration.connect.assert_called_once()

    @pytest.mark.asyncio
    async def test_disconnect_all(self, registry):
        """Test disconnecting from all integrations"""
        for name, integration in registry.integrations.items():
            integration.disconnect = AsyncMock(return_value=True)
            registry.active_integrations[name] = integration

        results = await registry.disconnect_all()

        assert len(registry.active_integrations) == 0

    @pytest.mark.asyncio
    async def test_execute_action(self, registry):
        """Test executing action via registry"""
        for name, integration in registry.integrations.items():
            registry.active_integrations[name] = integration

        palo_alto_integration = registry.active_integrations["palo_alto"]
        palo_alto_integration.execute_action = AsyncMock(return_value=ActionResult(
            success=True,
            action_type=ActionType.BLOCK_IP,
            target="192.168.1.100",
            details={"rule_id": "rule_123"},
            execution_time=0.25
        ))

        result = await registry.execute_action(
            ActionType.BLOCK_IP,
            "192.168.1.100",
            {"reason": "Malicious activity"}
        )

        assert result.success is True
        palo_alto_integration.execute_action.assert_called_once()

    @pytest.mark.asyncio
    async def test_execute_response_actions(self, registry):
        """Test executing multiple response actions"""
        for name, integration in registry.integrations.items():
            registry.active_integrations[name] = integration
            integration.execute_action = AsyncMock(return_value=ActionResult(
                success=True,
                action_type=ActionType.BLOCK_IP,
                target="test",
                details={"status": "success"},
                execution_time=0.1
            ))

        actions = [
            {
                "action_type": "block_ip",
                "target": "192.168.1.100",
                "context": {"reason": "Malicious IP"}
            },
            {
                "action_type": "send_alert",
                "target": "#security-alerts",
                "context": {"message": "IP blocked successfully"}
            }
        ]

        results = await registry.execute_response_actions(actions, {})

        assert len(results) == 2

    @pytest.mark.asyncio
    async def test_get_registry_status(self, registry):
        """Test getting registry status"""
        for name, integration in registry.integrations.items():
            registry.active_integrations[name] = integration

        status = registry.get_registry_status()

        assert status["total_configured"] == 3
        assert status["total_active"] == 3
        assert "integration_status" in status

    def test_add_integration(self, registry):
        """Test adding new integration to registry"""
        assert hasattr(registry, 'add_integration')

    def test_remove_integration(self, registry):
        """Test removing integration from registry"""
        assert hasattr(registry, 'remove_integration')

    def test_get_available_integration_types(self):
        """Test getting available integration types"""
        available = IntegrationRegistry.get_available_integration_types()
        assert "palo_alto" in available
        assert "splunk" in available
        assert "slack" in available
        assert "servicenow" in available


class TestIntegrationErrorHandling:
    """Test error handling in integrations"""

    @pytest.mark.asyncio
    async def test_connection_error_handling(self):
        """Test handling of connection errors"""
        config = {
            "hostname": "invalid.example.com",
            "api_key": "invalid_key"
        }

        integration = PaloAltoIntegration(config)

        with patch.object(integration, '_create_session') as mock_session:
            with patch.object(integration, '_make_request', new_callable=AsyncMock, side_effect=Exception("Connection failed")):
                mock_session.return_value = MagicMock()
                result = await integration.connect()
                assert result is False
                assert integration.is_connected is False

    @pytest.mark.asyncio
    async def test_action_execution_error_handling(self):
        """Test handling of action execution errors"""
        config = {
            "webhook_url": "https://hooks.slack.com/invalid",
            "bot_token": "xoxb-invalid"
        }

        integration = SlackIntegration(config)

        with patch.object(integration, '_send_via_api', new_callable=AsyncMock, side_effect=Exception("API Error")):
            result = await integration.execute_action(
                ActionType.SEND_ALERT,
                "Test message",
                {"severity": "high"}
            )

            assert result.success is False
            assert result.error_message is not None


# CLI Mock Demonstrations
class TestIntegrationsCLIMockInteractions:
    """Mock CLI interactions for integrations testing"""

    @pytest.mark.mock
    def test_integration_status_cli_mock(self):
        """Mock CLI interaction for integration status"""
        print("\n=== Integration Status CLI Mock Demo ===")
        print("Command: python -m agent.integrations status")
        print("Response:")
        print(json.dumps({
            "integration_status": {
                "total_integrations": 8,
                "connected_integrations": 6,
                "failed_integrations": 2,
                "last_health_check": datetime.now().isoformat(),
                "integrations": {
                    "palo_alto_fw": {
                        "type": "firewall",
                        "status": "connected",
                        "last_action": "2024-07-27T14:25:00Z",
                        "success_rate": 0.96,
                        "avg_response_time_ms": 234,
                        "supported_actions": ["BLOCK_IP", "BLOCK_URL", "CREATE_RULE"]
                    },
                    "splunk_siem": {
                        "type": "siem",
                        "status": "connected",
                        "last_action": "2024-07-27T14:30:00Z",
                        "success_rate": 0.99,
                        "avg_response_time_ms": 156,
                        "supported_actions": ["CREATE_INCIDENT", "SEND_ALERT", "ADD_TO_WATCHLIST"]
                    },
                    "slack_notifications": {
                        "type": "communication",
                        "status": "connected",
                        "last_action": "2024-07-27T14:32:00Z",
                        "success_rate": 1.0,
                        "avg_response_time_ms": 89,
                        "supported_actions": ["SEND_ALERT", "NOTIFY", "ESCALATE"]
                    },
                    "servicenow_itsm": {
                        "type": "incident_response",
                        "status": "degraded",
                        "last_action": "2024-07-27T13:45:00Z",
                        "success_rate": 0.78,
                        "avg_response_time_ms": 1234,
                        "supported_actions": ["CREATE_INCIDENT", "UPDATE_INCIDENT"]
                    }
                }
            },
            "health_summary": {
                "overall_health": "good",
                "critical_integrations_down": 0,
                "degraded_integrations": 1
            }
        }, indent=2))

    @pytest.mark.mock
    def test_integration_execute_action_cli_mock(self):
        """Mock CLI interaction for executing actions"""
        print("\n=== Execute Integration Action CLI Mock Demo ===")
        print("Command: python -m agent.integrations execute --action BLOCK_IP --target 192.168.1.100 --reason 'Malicious activity detected'")
        print("Response:")
        print(json.dumps({
            "action_execution": {
                "action_type": "BLOCK_IP",
                "target": "192.168.1.100",
                "reason": "Malicious activity detected",
                "execution_id": "exec_2024_0892"
            },
            "results": [
                {
                    "integration": "palo_alto_fw",
                    "integration_type": "firewall",
                    "status": "success",
                    "message": "IP successfully blocked via firewall rule",
                    "execution_time_ms": 245,
                    "result_data": {
                        "rule_id": "auto_block_rule_4523",
                        "rule_name": "ThreatSentinel_Block_192.168.1.100",
                        "priority": "high"
                    }
                },
                {
                    "integration": "fortinet_fw",
                    "integration_type": "firewall",
                    "status": "success",
                    "message": "IP added to blocked address group",
                    "execution_time_ms": 189,
                    "result_data": {
                        "address_group": "threat_sentinel_blocked_ips",
                        "policy_updated": "policy_001"
                    }
                }
            ],
            "summary": {
                "total_integrations_executed": 2,
                "successful_executions": 2,
                "failed_executions": 0,
                "total_execution_time_ms": 434,
                "success_rate": 1.0
            },
            "follow_up_actions": [
                {
                    "action": "SEND_ALERT",
                    "target": "#security-alerts",
                    "message": "IP 192.168.1.100 has been successfully blocked across all firewalls"
                }
            ],
            "execution_timestamp": datetime.now().isoformat()
        }, indent=2))

    @pytest.mark.mock
    def test_integration_capabilities_cli_mock(self):
        """Mock CLI interaction for integration capabilities"""
        print("\n=== Integration Capabilities CLI Mock Demo ===")
        print("Command: python -m agent.integrations capabilities --action-type SEND_ALERT")
        print("Response:")
        print(json.dumps({
            "action_capabilities": {
                "action_type": "SEND_ALERT",
                "description": "Send alert notifications to various platforms",
                "supported_integrations": [
                    {
                        "name": "splunk_siem",
                        "type": "siem",
                        "status": "connected",
                        "response_time_ms": 156,
                        "reliability_score": 0.99
                    },
                    {
                        "name": "slack_notifications",
                        "type": "communication",
                        "status": "connected",
                        "response_time_ms": 89,
                        "reliability_score": 1.0
                    },
                    {
                        "name": "teams_notifications",
                        "type": "communication",
                        "status": "connected",
                        "response_time_ms": 124,
                        "reliability_score": 0.98
                    },
                    {
                        "name": "pagerduty_alerts",
                        "type": "incident_response",
                        "status": "connected",
                        "response_time_ms": 234,
                        "reliability_score": 0.97
                    }
                ],
                "total_capable_integrations": 4,
                "recommended_execution_order": [
                    "slack_notifications",
                    "teams_notifications",
                    "splunk_siem",
                    "pagerduty_alerts"
                ]
            },
            "query_timestamp": datetime.now().isoformat()
        }, indent=2))
