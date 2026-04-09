"""
pipeline — Canonical 10-phase scan pipeline for OneInfinity.

Guarantees identical execution in Docker and CLI environments.
"""
from .canonical import CANONICAL_PHASES, CanonicalPhase, PhaseConfig
from .executor import CanonicalExecutor, PipelineResult, PhaseResult
from .parity_checker import ParityChecker, ParityReport

__all__ = [
    "CANONICAL_PHASES",
    "CanonicalPhase",
    "PhaseConfig",
    "CanonicalExecutor",
    "PipelineResult",
    "PhaseResult",
    "ParityChecker",
    "ParityReport",
]
