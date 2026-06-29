"""
Context-Aware Safeguards Layer (CASL)

A unified guard layer that provides:
- Risk scoring based on context signals
- Policy-driven enforcement decisions
- Contract-safe response shaping
- Shadow mode for safe rollout
- Structured telemetry for audit and tuning

Usage:
    from oneinfinity.casl import CASLMiddleware, GuardDecision, EnforcementAction

    # FastAPI integration
    app.add_middleware(CASLMiddleware)

    # Direct usage
    from oneinfinity.casl import GuardContext, SignalEngine, PolicyEngine
    context = GuardContext.from_request(request)
    score = SignalEngine.evaluate(context)
    decision = PolicyEngine.decide(context, score)
"""

from __future__ import annotations

from oneinfinity.casl.guard_context import (
    GuardContext,
    AuthStrength,
    RoutePosture,
    TenantPolicy,
    DataClassification,
)
from oneinfinity.casl.signal_engine import (
    SignalEngine,
    SignalResult,
    RiskSignal,
)
from oneinfinity.casl.policy_engine import (
    PolicyEngine,
    GuardDecision,
    EnforcementAction,
    PolicyRule,
)
from oneinfinity.casl.response_shaper import (
    ResponseShaper,
    RedactionEnvelope,
    RedactionStrategy,
)
from oneinfinity.casl.telemetry import (
    TelemetryEmitter,
    GuardDecisionEvent,
    GuardSignalEvent,
)
from oneinfinity.casl.casl_middleware import CASLMiddleware, CASLConfig
from oneinfinity.casl.shadow_mode import ShadowMode, DecisionDiff

__all__ = [
    # Guard Context
    "GuardContext",
    "AuthStrength",
    "RoutePosture",
    "TenantPolicy",
    "DataClassification",
    # Signal Engine
    "SignalEngine",
    "SignalResult",
    "RiskSignal",
    # Policy Engine
    "PolicyEngine",
    "GuardDecision",
    "EnforcementAction",
    "PolicyRule",
    # Response Shaper
    "ResponseShaper",
    "RedactionEnvelope",
    "RedactionStrategy",
    # Telemetry
    "TelemetryEmitter",
    "GuardDecisionEvent",
    "GuardSignalEvent",
    # Middleware
    "CASLMiddleware",
    "CASLConfig",
    # Shadow Mode
    "ShadowMode",
    "DecisionDiff",
]

__version__ = "1.0.0"
