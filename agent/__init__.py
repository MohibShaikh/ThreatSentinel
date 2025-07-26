"""
AITIA SOC Agent - Autonomous Security Operations Center Agent

A sophisticated AI agent that combines tool use, memory, and planning
to provide autonomous security incident investigation and response.
"""

__version__ = "2.0.0"
__author__ = "AITIA Agent Team"

from .planner import SOCAgentPlanner
from .tools import ToolRegistry
from .memory import AgentMemory
from .reporter import IncidentReporter

__all__ = [
    "SOCAgentPlanner",
    "ToolRegistry", 
    "AgentMemory",
    "IncidentReporter"
] 