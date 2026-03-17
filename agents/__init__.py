"""
agents — Multi-Agent Autonomous Pentesting System
"""

from agents.base import AgentState, BaseAgent, Message, MessageType, Task, TaskResult
from agents.coordinator import AgentCoordinator
from agents.recon_agent import ReconAgent
from agents.scan_agent import ScanAgent
from agents.exploit_agent import ExploitAgent
from agents.validation_agent import ValidationAgent
from agents.report_agent import ReportAgent

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
