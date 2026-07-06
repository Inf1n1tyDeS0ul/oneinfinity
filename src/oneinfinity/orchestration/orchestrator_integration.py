"""
orchestrator_integration.py — Wires ModelOrchestrator into existing platform systems

This module registers lightweight hooks/callbacks into:
  1. EventDrivenEngine  — post-finding AI enrichment
  2. GraphTriggerEngine — AI guidance on high-priority trigger firings
  3. IntelligenceDaemon — AI reasoning for hypothesis + exploit chain workers
  4. AgentExecutionFabric — AI enrichment of high-severity findings

Design principle: all hooks are non-blocking (fire-and-forget threads)
and degrade gracefully when the orchestrator or AI APIs are unavailable.
The rest of the platform keeps working without AI enrichment.

Activation:
    from oneinfinity.orchestration.orchestrator_integration import activate
    activate()          # call once at startup (e.g. from main.py)
"""

from __future__ import annotations

import logging
import threading
from typing import Optional

log = logging.getLogger("orchestrator_integration")

_activated = False
_act_lock  = threading.Lock()


# ── Integration helpers ────────────────────────────────────────────────────────

def _async_call(fn, *args, **kwargs) -> None:
    """Run fn in a daemon thread to avoid blocking callers."""
    t = threading.Thread(target=_safe_call, args=(fn, args, kwargs), daemon=True)
    t.start()


def _safe_call(fn, args, kwargs) -> None:
    try:
        fn(*args, **kwargs)
    except Exception as e:
        log.debug("Async integration call failed: %s", e)


# ── 1. EventDrivenEngine: enrich high-severity findings ───────────────────────

def _ede_post_hook(output, classification) -> None:
    """
    Post-execute hook for EDE.
    When the orchestrator itself processes a task, this is called.
    We check if the finding severity is high and publish enriched analysis.
    """
    try:
        content = getattr(output, "content", "")
        if not content:
            return
        # Publish AI analysis as an event
        from oneinfinity.orchestration.event_bus import get_bus, EventType
        get_bus().publish(
            event_type=EventType.HYPOTHESIS_CREATED,
            source="orchestrator_integration",
            data={
                "ai_analysis":  content[:1000],
                "model_id":     output.model_id,
                "confidence":   output.confidence,
                "cost_usd":     output.cost_usd,
                "task_id":      output.task_id,
            },
        )
    except Exception as e:
        log.debug("EDE post-hook failed: %s", e)


def _wire_ede() -> bool:
    try:
        from oneinfinity.orchestration.event_driven_engine import get_engine
        from oneinfinity.orchestration.model_orchestrator import get_orchestrator
        orch = get_orchestrator()
        orch.add_post_hook(_ede_post_hook)
        log.info("Orchestrator wired into EventDrivenEngine (post-hook)")
        return True
    except Exception as e:
        log.debug("EDE wiring failed: %s", e)
        return False


# ── 2. GraphTriggerEngine: AI guidance on high-priority triggers ───────────────

def _trigger_callback(firing) -> None:
    """
    Called when a trigger fires. For high-priority triggers (≥ 8.5),
    request AI attack guidance asynchronously.
    """
    if firing.priority < 8.5:
        return
    _async_call(_trigger_ai_call, firing)


def _trigger_ai_call(firing) -> None:
    try:
        from oneinfinity.orchestration.model_orchestrator import get_orchestrator
        orch   = get_orchestrator()
        output = orch.execute_for_trigger(firing)
        if output and output.confidence >= 0.6 and output.content:
            # Feed AI guidance back into the event bus
            from oneinfinity.orchestration.event_bus import get_bus, EventType
            get_bus().publish(
                event_type=EventType.HYPOTHESIS_CREATED,
                source="orchestrator_trigger",
                data={
                    "trigger_name": firing.trigger_name,
                    "node_id":      firing.node_id,
                    "node_label":   firing.node_label,
                    "ai_guidance":  output.content[:1500],
                    "confidence":   output.confidence,
                    "model_id":     output.model_id,
                },
            )
            log.info("AI guidance generated for trigger '%s' (conf=%.2f model=%s)",
                     firing.trigger_name, output.confidence, output.model_id)
    except Exception as e:
        log.debug("Trigger AI call failed: %s", e)


def _wire_triggers() -> bool:
    try:
        from oneinfinity.orchestration.graph_trigger_engine import get_trigger_engine
        get_trigger_engine().set_trigger_callback(_trigger_callback)
        log.info("Orchestrator wired into GraphTriggerEngine (callback)")
        return True
    except Exception as e:
        log.debug("Trigger wiring failed: %s", e)
        return False


# ── 3. AgentExecutionFabric: enrich high-severity fabric findings ──────────────

def _fabric_finding_hook(finding: dict) -> None:
    """
    Called when a fabric agent produces a finding.
    For HIGH/CRITICAL findings, request deeper AI analysis.
    """
    severity = finding.get("severity", "info")
    if severity not in ("critical", "high"):
        return
    _async_call(_fabric_ai_enrich, finding)


def _fabric_ai_enrich(finding: dict) -> None:
    try:
        from oneinfinity.orchestration.model_orchestrator import get_orchestrator
        orch = get_orchestrator()
        task = {
            "description": (
                f"Analyze this {finding.get('severity','?')} severity finding and provide:\n"
                f"1. Exploit chain opportunities\n"
                f"2. Impact assessment\n"
                f"3. Recommended follow-up tests\n\n"
                f"Finding: {finding.get('vuln_type','?')} on {finding.get('node_label','?')}\n"
                f"Description: {finding.get('description','')}\n"
                f"Evidence: {str(finding.get('evidence',''))[:300]}"
            ),
            "severity":   finding.get("severity", ""),
            "importance": "critical" if finding.get("severity") == "critical" else "high",
            "agent_type": finding.get("agent_type", ""),
            "target":     finding.get("target", ""),
        }
        output = orch.execute(task, task_id=f"fabric:{finding.get('finding_id','?')}")
        if output and output.confidence >= 0.55:
            # Merge AI analysis into the original finding and re-publish
            from oneinfinity.orchestration.event_bus import get_bus, EventType
            enriched = {
                **finding,
                "ai_analysis":  output.content[:2000],
                "ai_model":     output.model_id,
                "ai_confidence": output.confidence,
            }
            get_bus().publish(
                event_type=EventType.NEW_VULNERABILITY,
                source="orchestrator_fabric",
                data=enriched,
            )
    except Exception as e:
        log.debug("Fabric AI enrichment failed: %s", e)


def _wire_fabric() -> bool:
    try:
        from oneinfinity.swarm.agent_execution_fabric import get_fabric
        fabric = get_fabric()
        # Wrap the existing global callback
        existing_cb = fabric._global_on_complete

        def combined_callback(finding: dict) -> None:
            if existing_cb:
                try:
                    existing_cb(finding)
                except Exception:
                    pass
            _fabric_finding_hook(finding)

        fabric.set_global_callback(combined_callback)
        log.info("Orchestrator wired into AgentExecutionFabric (finding callback)")
        return True
    except Exception as e:
        log.debug("Fabric wiring failed: %s", e)
        return False


# ── 4. IntelligenceDaemon: AI for HypothesisWorker fallback ───────────────────

def _patch_daemon_workers() -> bool:
    """
    Monkey-patch daemon workers to use the orchestrator as an enhanced
    fallback when the primary Python-based analysis fails.
    This is the least invasive approach to enriching daemon output.
    """
    try:
        import oneinfinity.intelligence_daemon as _mod
        OrigHyp = _mod.HypothesisWorker

        class EnhancedHypothesisWorker(OrigHyp):
            def _generate(self, event) -> list:
                # Try original rule-based generation first
                results = super()._generate(event)
                # If we got very few theories, augment with AI
                if len(results) < 3:
                    try:
                        from oneinfinity.orchestration.model_orchestrator import get_orchestrator
                        orch   = get_orchestrator()
                        output = orch.execute_for_daemon("HypothesisWorker", {
                            "event_type": str(event.event_type),
                            "data": dict(event.data or {}),
                        })
                        if output and output.content and output.confidence >= 0.55:
                            results.append({
                                "vuln_type":    "ai_hypothesis",
                                "endpoint":     event.data.get("url", event.data.get("target", "")),
                                "confidence":   output.confidence,
                                "reasoning":    output.content[:500],
                                "severity":     "medium",
                                "source":       f"ai:{output.model_id}",
                                "attack_hints": [],
                                "parameters":   [],
                            })
                    except Exception:
                        pass
                return results

        _mod.HypothesisWorker = EnhancedHypothesisWorker
        log.info("Orchestrator patched into IntelligenceDaemon.HypothesisWorker")
        return True
    except Exception as e:
        log.debug("Daemon worker patching failed: %s", e)
        return False


# ── Main activation ────────────────────────────────────────────────────────────

def activate(quiet: bool = False) -> dict:
    """
    Wire the orchestrator into all available platform systems.
    Safe to call multiple times — idempotent.

    Returns a status dict indicating which integrations succeeded.
    """
    global _activated
    with _act_lock:
        if _activated:
            return {"status": "already_active"}
        _activated = True

    results: dict = {}
    try:
        results = {
            "ede":     _wire_ede(),
            "triggers": _wire_triggers(),
            "fabric":  _wire_fabric(),
            "daemon":  _patch_daemon_workers(),
        }
        active = sum(1 for v in results.values() if v)
        if not quiet:
            log.info("Orchestrator integration: %d/%d systems wired: %s",
                     active, len(results),
                     {k: "ok" if v else "skip" for k, v in results.items()})
    except Exception as _exc:
        # Neo4j / Redis / service unavailable — degrade gracefully
        log.debug("Orchestrator integration wiring failed (Neo4j/Redis unavailable?): %s", _exc)
        results = {"error": str(_exc)}
    return {"status": "activated", "wired": results}


def deactivate() -> None:
    """Reset activation state (mainly for testing)."""
    global _activated
    with _act_lock:
        _activated = False
