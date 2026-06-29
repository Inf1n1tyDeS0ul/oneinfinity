import time
import logging
from enum import Enum
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Tuple

from oneinfinity.orchestration.event_bus import get_bus, EventType

log = logging.getLogger(__name__)

class EnforcementAction(str, Enum):
    ALLOW = "allow"
    ALLOW_REDACT = "allow+redact"
    ALLOW_THROTTLE = "allow+throttle"
    READ_ONLY = "read-only"
    BLOCK = "block"

class RoutePosture(str, Enum):
    BLOCK = "block"
    READ_ONLY = "read-only"
    THROTTLE = "throttle"

@dataclass
class GuardContext:
    actor_id: str
    auth_strength: float  # 0.0 to 1.0
    tenant_id: str
    tenant_policy: Dict[str, Any]
    request_traits: Dict[str, Any]
    data_sensitivity: str  # e.g., "public", "internal", "confidential", "restricted"
    route_posture: RoutePosture
    session_age_seconds: float
    request_rate: float  # requests per second
    payload_size_bytes: int
    tenant_risk_flags: List[str]

@dataclass
class SignalResult:
    name: str
    score: float  # 0.0 (safe) to 1.0 (high risk)
    explanation: str

@dataclass
class GuardDecision:
    action: EnforcementAction
    total_risk_score: float
    signals: List[SignalResult]
    context: GuardContext
    shadow_mode: bool
    timestamp: float = field(default_factory=time.time)

class CASL:
    """Context-Aware Safeguards Layer (CASL)"""
    
    def __init__(self, shadow_mode: bool = True):
        self.shadow_mode = shadow_mode
        self._bus = get_bus()
        self._data_classification_manifest = {
            "public": ["id", "name", "status"],
            "internal": ["email", "role", "created_at"],
            "confidential": ["phone", "address", "balance"],
            "restricted": ["ssn", "password_hash", "credit_card"]
        }
        
    def evaluate_signals(self, ctx: GuardContext) -> Tuple[float, List[SignalResult]]:
        signals = []
        total_risk = 0.0
        
        # 1. Session Age Signal
        if ctx.session_age_seconds > 86400:  # > 24 hours
            score = 0.8
            expl = "Session age exceeds 24 hours"
        elif ctx.session_age_seconds > 3600:
            score = 0.3
            expl = "Session age exceeds 1 hour"
        else:
            score = 0.0
            expl = "Session is fresh"
        signals.append(SignalResult("session_age", score, expl))
        
        # 2. Auth Strength Signal
        auth_risk = 1.0 - ctx.auth_strength
        signals.append(SignalResult("auth_strength", auth_risk, f"Auth strength is {ctx.auth_strength:.2f}"))
        
        # 3. Request Rate Signal
        if ctx.request_rate > 100:
            score = 1.0
            expl = "Request rate critically high"
        elif ctx.request_rate > 20:
            score = 0.6
            expl = "Request rate elevated"
        else:
            score = 0.0
            expl = "Request rate normal"
        signals.append(SignalResult("request_rate", score, expl))
        
        # 4. Payload Size Signal
        if ctx.payload_size_bytes > 10 * 1024 * 1024:
            score = 0.9
            expl = "Payload size exceeds 10MB"
        elif ctx.payload_size_bytes > 1024 * 1024:
            score = 0.4
            expl = "Payload size exceeds 1MB"
        else:
            score = 0.0
            expl = "Payload size normal"
        signals.append(SignalResult("payload_size", score, expl))
        
        # 5. Tenant Risk Flags Signal
        if "compromised" in ctx.tenant_risk_flags:
            score = 1.0
            expl = "Tenant flagged as compromised"
        elif "suspicious_activity" in ctx.tenant_risk_flags:
            score = 0.7
            expl = "Tenant has suspicious activity"
        else:
            score = 0.0
            expl = "No tenant risk flags"
        signals.append(SignalResult("tenant_risk", score, expl))
        
        # Calculate weighted total risk (simplified as average for Iteration-1)
        total_risk = sum(s.score for s in signals) / len(signals)
        return total_risk, signals

    def evaluate_policy(self, risk_score: float, ctx: GuardContext) -> EnforcementAction:
        if risk_score > 0.8:
            return EnforcementAction.BLOCK
        
        if risk_score > 0.6:
            if ctx.route_posture == RoutePosture.BLOCK:
                return EnforcementAction.BLOCK
            elif ctx.route_posture == RoutePosture.READ_ONLY:
                return EnforcementAction.READ_ONLY
            else:
                return EnforcementAction.ALLOW_THROTTLE
                
        if risk_score > 0.4:
            if ctx.data_sensitivity in ["confidential", "restricted"]:
                return EnforcementAction.ALLOW_REDACT
            return EnforcementAction.ALLOW_THROTTLE
            
        return EnforcementAction.ALLOW

    def shape_response(self, data: Dict[str, Any], action: EnforcementAction, sensitivity: str) -> Dict[str, Any]:
        """Contract-safe response shaping using typed redaction envelopes."""
        if action == EnforcementAction.BLOCK:
            return {"error": "Blocked by CASL policy", "code": "CASL_BLOCK"}
            
        if action == EnforcementAction.ALLOW_REDACT:
            redacted_data = {}
            allowed_fields = self._data_classification_manifest.get("public", [])
            if sensitivity in ["internal", "confidential", "restricted"]:
                # For Iteration-1, redact everything above public if ALLOW_REDACT is triggered
                pass 
                
            for k, v in data.items():
                if k in allowed_fields:
                    redacted_data[k] = v
                else:
                    # Typed redaction sentinel
                    if isinstance(v, str):
                        redacted_data[k] = "[REDACTED]"
                    elif isinstance(v, int) or isinstance(v, float):
                        redacted_data[k] = 0
                    elif isinstance(v, bool):
                        redacted_data[k] = False
                    elif isinstance(v, list):
                        redacted_data[k] = []
                    elif isinstance(v, dict):
                        redacted_data[k] = {}
                    else:
                        redacted_data[k] = None
            return redacted_data
            
        return data

    def enforce(self, ctx: GuardContext) -> GuardDecision:
        start_time = time.perf_counter()
        
        risk_score, signals = self.evaluate_signals(ctx)
        action = self.evaluate_policy(risk_score, ctx)
        
        decision = GuardDecision(
            action=action,
            total_risk_score=risk_score,
            signals=signals,
            context=ctx,
            shadow_mode=self.shadow_mode
        )
        
        elapsed_ms = (time.perf_counter() - start_time) * 1000
        
        # Emit telemetry
        self._emit_telemetry(decision, elapsed_ms)
        
        return decision
        
    def _emit_telemetry(self, decision: GuardDecision, elapsed_ms: float):
        # Scrub PII from context for telemetry
        safe_context = {
            "actor_id": decision.context.actor_id,
            "tenant_id": decision.context.tenant_id,
            "route_posture": decision.context.route_posture.value,
            "data_sensitivity": decision.context.data_sensitivity,
        }
        
        # Emit guard_decision
        try:
            # Using FORENSIC_SIGNAL as a fallback if custom types aren't registered
            # In a real system we would add GUARD_DECISION to EventType enum
            self._bus.publish(
                EventType.FORENSIC_SIGNAL,
                {
                    "type": "guard_decision",
                    "action": decision.action.value,
                    "risk_score": decision.total_risk_score,
                    "shadow_mode": decision.shadow_mode,
                    "elapsed_ms": elapsed_ms,
                    "context": safe_context
                },
                source="casl"
            )
            
            # Emit guard_signal for each signal
            for sig in decision.signals:
                self._bus.publish(
                    EventType.FORENSIC_SIGNAL,
                    {
                        "type": "guard_signal",
                        "signal_name": sig.name,
                        "score": sig.score,
                        "explanation": sig.explanation,
                        "actor_id": decision.context.actor_id
                    },
                    source="casl"
                )
        except Exception as e:
            log.error(f"Failed to emit CASL telemetry: {e}")

