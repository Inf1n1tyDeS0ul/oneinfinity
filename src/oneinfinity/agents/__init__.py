"""
agents — Multi-Agent Autonomous Pentesting System
"""

from oneinfinity.agents.base import AgentState, BaseAgent, Message, MessageType, Task, TaskResult
from oneinfinity.agents.coordinator import AgentCoordinator
from oneinfinity.agents.recon_agent import ReconAgent
from oneinfinity.agents.scan_agent import ScanAgent
from oneinfinity.agents.exploit_agent import ExploitAgent
from oneinfinity.agents.validation_agent import ValidationAgent
from oneinfinity.agents.report_agent import ReportAgent

__all__ = [
    "AgentState", "BaseAgent", "Message", "MessageType", "Task", "TaskResult",
    "AgentCoordinator",
    "ReconAgent", "ScanAgent", "ExploitAgent", "ValidationAgent", "ReportAgent",
]


def build_coordinator(attack_graph=None, learning_system=None) -> AgentCoordinator:
    """Convenience factory: create and register all default agents."""
    coord = AgentCoordinator(
        attack_graph=attack_graph,
        learning_system=learning_system,
    )
    for cls in [ReconAgent, ScanAgent, ExploitAgent, ValidationAgent, ReportAgent]:
        coord.register(cls)
    return coord
