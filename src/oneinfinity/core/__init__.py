"""
Core infrastructure for One&Infinity.
Provides: plugin registry, async task queue, recon cache,
scope validator, scan profiles, deduplicator, and reporter.
"""

from .plugin_registry import PluginRegistry, plugin_registry
from .task_queue import TaskQueue, TaskPriority, Task
from .cache import ReconCache
from .scope_validator import ScopeValidator
from .scan_profiles import ScanProfile, PROFILES, get_profile
from .deduplicator import Deduplicator
from .reporter import Reporter

__all__ = [
    "PluginRegistry", "plugin_registry",
    "TaskQueue", "TaskPriority", "Task",
    "ReconCache",
    "ScopeValidator",
    "ScanProfile", "PROFILES", "get_profile",
    "Deduplicator",
    "Reporter",
]
