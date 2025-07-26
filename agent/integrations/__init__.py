"""
AITIA SOC Agent - Integration Framework

This module provides a modular framework for integrating with various SOC tools
including SIEMs, firewalls, incident response platforms, and communication tools.
"""

from .base import (
    BaseIntegration,
    IntegrationResponse,
    IntegrationType,
    ActionResult
)

from .siem import (
    SplunkIntegration,
    QRadarIntegration,
    SentinelIntegration
)

from .firewall import (
    PaloAltoIntegration,
    FortinetIntegration,
    PfSenseIntegration
)

from .incident import (
    ServiceNowIntegration,
    JiraIntegration,
    PagerDutyIntegration
)

from .communication import (
    SlackIntegration,
    TeamsIntegration,
    EmailIntegration
)

from .registry import IntegrationRegistry

__all__ = [
    'BaseIntegration',
    'IntegrationResponse', 
    'IntegrationType',
    'ActionResult',
    'SplunkIntegration',
    'QRadarIntegration',
    'SentinelIntegration',
    'PaloAltoIntegration',
    'FortinetIntegration',
    'PfSenseIntegration',
    'ServiceNowIntegration',
    'JiraIntegration',
    'PagerDutyIntegration',
    'SlackIntegration',
    'TeamsIntegration',
    'EmailIntegration',
    'IntegrationRegistry'
]

__version__ = "1.0.0" 