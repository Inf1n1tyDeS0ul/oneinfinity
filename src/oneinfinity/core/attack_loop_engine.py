"""
core/attack_loop_engine.py — Multi-Step Attack Loop Engine (Phase 4)

Enables iterative scanning: each iteration feeds its results into the
next AI-guided plan, expanding coverage until diminishing returns.

Constraints:
  max_iterations: 2–3 (hard cap prevents runaway loops)
  stop_threshold: < 2 new unique findings → early stop
  iteration_timeout_s: hard wall-clock limit per iteration

Integration::

    loop = get_attack_loop_engine(max_iterations=2)
    new_findings = loop.run(session, ctx, phase_runner)

The caller provides a ``phase_runner(session, ctx, tools) -> List[dict]``
callable that executes one vuln-scan iteration and returns findings.
The loop deduplicates across iterations and stops on diminishing returns.
"""
from __future__ import annotations

import logging
import time
from typing import Any, Callable, Dict, List, Optional, Set

log = logging.getLogger("oneinfinity.core.attack_loop_engine")

_DEFAULT_MAX_ITERATIONS: int = 3
_HARD_MAX_ITERATIONS:    int = 3   # never exceed, regardless of caller config
_DEFAULT_STOP_THRESHOLD: int = 2   # stop if fewer than N new unique findings
_DEFAULT_ITER_TIMEOUT_S: float = 300.0  # 5 min per iteration


# ---------------------------------------------------------------------------
# Data model
# ---------------------------------------------------------------------------


class LoopIteration:
    """Metadata for one completed attack loop iteration."""

    __slots__ = (
        "iteration", "new_findings", "ai_tools",
        "duration_s", "stopped_early", "stop_reason",
    )

    def __init__(self, iteration: int) -> None:
        self.iteration: int = iteration
        self.new_findings: List[dict] = []
        self.ai_tools: List[str] = []
        self.duration_s: float = 0.0
        self.stopped_early: bool = False
        self.stop_reason: str = ""

    def to_dict(self) -> dict:
        return {
            "iteration":     self.iteration,
            "new_findings":  len(self.new_findings),
            "ai_tools":      self.ai_tools,
            "duration_s":    round(self.duration_s, 2),
            "stopped_early": self.stopped_early,
            "stop_reason":   self.stop_reason,
        }


# ---------------------------------------------------------------------------
# Engine
# ---------------------------------------------------------------------------


class AttackLoopEngine:
    """
    Adaptive multi-iteration attack loop.

    Each iteration:
      1. Checks ``_should_continue`` — stops on diminishing returns, no untested
         endpoints, low AI confidence, or hard ceiling
      2. Asks AI for next-step tools informed by history (avoids repeating tests)
      3. Executes ``phase_runner`` with those suggestions
      4. Deduplicates results, updates loop_history in ctx
      5. Accumulates AI signals for next replan
    """

    def __init__(
        self,
        max_iterations: int = _DEFAULT_MAX_ITERATIONS,
        stop_threshold: int = _DEFAULT_STOP_THRESHOLD,
        iteration_timeout_s: float = _DEFAULT_ITER_TIMEOUT_S,
    ) -> None:
        self._max_iter = min(max_iterations, _HARD_MAX_ITERATIONS)
        self._stop_threshold = stop_threshold
        self._iter_timeout = iteration_timeout_s
        self.iterations: List[LoopIteration] = []

    # ── Helpers ────────────────────────────────────────────────────────────────

    @staticmethod
    def _fingerprint(f: dict) -> str:
        """Stable dedup key: vuln_type + url/target + parameter."""
        return (
            f"{(f.get('vuln_type') or '?').lower()}"
            f"|{f.get('url', f.get('target', '?'))}"
            f"|{f.get('parameter', '')}"
        )

    @staticmethod
    def _init_loop_history(ctx: dict) -> None:
        """Initialise ctx["loop_history"] if not already present."""
        if "loop_history" not in ctx:
            ctx["loop_history"] = {
                "tested_endpoints": set(),
                "successful_payloads": [],
                "failed_attempts": [],
                "ai_signals": [],
            }

    def _should_continue(
        self,
        iter_num: int,
        prev_new_count: int,
        ctx: dict,
    ) -> bool:
        """
        Adaptive stop decision:
          - hard ceiling on iterations
          - diminishing returns (< threshold new findings)
          - no untested endpoints remain
          - signals from AI are low-confidence only
        """
        if iter_num >= self._max_iter:
            log.info("[ALEngine] Stop: hard ceiling %d iterations reached", self._max_iter)
            return False
        if iter_num > 0 and prev_new_count < self._stop_threshold:
            log.info("[ALEngine] Stop: %d new findings < threshold %d",
                     prev_new_count, self._stop_threshold)
            return False
        # Check for untested endpoints
        history = ctx.get("loop_history", {})
        tested = history.get("tested_endpoints", set())
        intel = ctx.get("recon_intel")
        all_urls: Set[str] = set(
            getattr(intel, "all_urls", []) or [] if intel else []
        )
        if all_urls and tested and not (all_urls - tested):
            log.info("[ALEngine] Stop: all %d discovered endpoints tested", len(all_urls))
            return False
        # Check AI signal confidence — stop if only low-confidence signals remain
        signals = history.get("ai_signals", [])
        if signals and all(s.get("confidence") == "low" for s in signals[-5:]):
            log.info("[ALEngine] Stop: last 5 AI signals all low-confidence")
            return False
        return True

    def _get_ai_tools(
        self,
        session: Any,
        ctx: dict,
        all_findings_so_far: List[dict],
    ) -> List[str]:
        """
        Ask AI for next-step tools, informed by loop history to avoid repetition.
        Merges signal-driven tools + plan-based tools.
        Returns [] on any failure.
        """
        try:
            from oneinfinity.core.ai_reasoning_engine import get_ai_reasoning_engine
            are = get_ai_reasoning_engine()
            intel = ctx.get("recon_intel")
            history = ctx.get("loop_history", {})

            # Build endpoints list excluding already-tested ones
            all_endpoints: List[str] = (
                getattr(intel, "all_urls", []) or [] if intel else []
            )
            tested: Set[str] = history.get("tested_endpoints", set())
            untested = [u for u in all_endpoints if u not in tested]
            endpoints_for_plan = (untested or all_endpoints)[:50]

            # Generate plan from current findings + history context
            plan = are.generate_attack_plan(
                target=session.target,
                endpoints=endpoints_for_plan,
                params_map=ctx.get("params_map", {}),
                findings=all_findings_so_far,
                tech_stack=str(getattr(intel, "tech_profile", "") if intel else "unknown"),
                auth_context={
                    "authenticated": bool(ctx.get("auth_manager")),
                    "chain_data_available": bool(ctx.get("chain_data")),
                },
            )
            plan_tools = are.map_plan_to_tools(plan)

            # Also convert any pending AI signals → tools
            signal_tools = are.signals_to_tools(history.get("ai_signals", [])[-6:])

            # Merge: signal-driven tools first (already confirmed signals), then plan tools
            seen: set = set()
            merged: List[str] = []
            for t in signal_tools + plan_tools:
                if t and t not in seen:
                    merged.append(t)
                    seen.add(t)
            return merged

        except Exception as exc:
            log.debug("[ALEngine] AI tool suggestions failed: %s", exc)
            return []

    # ── Public API ─────────────────────────────────────────────────────────────

    def run(
        self,
        session: Any,
        ctx: dict,
        phase_runner: Callable[[Any, dict, List[str]], List[dict]],
    ) -> List[dict]:
        """
        Execute the adaptive attack loop.

        Args:
            session:      ScanSession with .target attribute
            ctx:          shared pipeline context dict
            phase_runner: callable(session, ctx, additional_tools) → List[dict]

        Returns:
            All new unique findings across all iterations.
        """
        self._init_loop_history(ctx)
        seen: Set[str] = {
            self._fingerprint(f) for f in ctx.get("scan_findings", [])
        }
        all_new: List[dict] = []
        prev_new_count: int = self._stop_threshold + 1  # allow first iteration
        i: int = 0

        while self._should_continue(i, prev_new_count, ctx):
            iter_obj = LoopIteration(iteration=i + 1)
            t_start = time.time()
            log.info("[ALEngine] Iteration %d starting for %s", i + 1, session.target)

            # Replan using AI + history
            all_findings_so_far = ctx.get("scan_findings", []) + all_new
            ai_tools = self._get_ai_tools(session, ctx, all_findings_so_far)
            iter_obj.ai_tools = ai_tools
            if ai_tools:
                log.info("[ALEngine] Iter %d AI tools: %s", i + 1, ai_tools)

            # Execute iteration
            try:
                raw_findings = phase_runner(session, ctx, ai_tools) or []
            except Exception as exc:
                log.warning("[ALEngine] phase_runner raised in iter %d: %s", i + 1, exc)
                iter_obj.stopped_early = True
                iter_obj.stop_reason = f"phase_runner_error: {exc}"
                self.iterations.append(iter_obj)
                break

            elapsed = time.time() - t_start
            iter_obj.duration_s = elapsed

            if elapsed > self._iter_timeout:
                log.warning("[ALEngine] Iter %d timeout (%.0fs)", i + 1, elapsed)
                iter_obj.stopped_early = True
                iter_obj.stop_reason = "timeout"

            # Deduplicate
            truly_new: List[dict] = []
            for f in raw_findings:
                fp = self._fingerprint(f)
                if fp not in seen:
                    seen.add(fp)
                    truly_new.append(f)

            iter_obj.new_findings = truly_new
            all_new.extend(truly_new)
            prev_new_count = len(truly_new)

            # Update loop_history
            history = ctx["loop_history"]
            # Mark endpoints tested in this iteration
            for t in ai_tools:
                history["tested_endpoints"].add(t)
            # Track successful findings for payload reuse
            for f in truly_new:
                evidence = f.get("evidence", "")
                payload = f.get("payload", f.get("parameter", ""))
                if f.get("severity") in ("high", "critical") and payload:
                    history["successful_payloads"].append({
                        "tool": f.get("tool", ""),
                        "payload": str(payload)[:200],
                        "vuln_type": f.get("vuln_type", ""),
                    })
                    history["successful_payloads"] = history["successful_payloads"][-20:]

            log.info(
                "[ALEngine] Iter %d done: %d new findings, %.1fs",
                i + 1, len(truly_new), elapsed,
            )
            self.iterations.append(iter_obj)

            if iter_obj.stopped_early:
                break

            # Feed new findings into ctx for next replan
            ctx.setdefault("scan_findings", []).extend(truly_new)
            i += 1

        log.info(
            "[ALEngine] Loop complete: %d iterations, %d total new findings",
            len(self.iterations), len(all_new),
        )
        return all_new

    def summary(self) -> dict:
        """Return a structured summary of all completed iterations."""
        return {
            "total_iterations":   len(self.iterations),
            "total_new_findings": sum(len(it.new_findings) for it in self.iterations),
            "early_stops":        sum(1 for it in self.iterations if it.stopped_early),
            "per_iteration":      [it.to_dict() for it in self.iterations],
        }


# ---------------------------------------------------------------------------
# Singleton accessor
# ---------------------------------------------------------------------------

_loop_instance: Optional[AttackLoopEngine] = None


def get_attack_loop_engine(
    max_iterations: int = _DEFAULT_MAX_ITERATIONS,
) -> AttackLoopEngine:
    global _loop_instance
    if _loop_instance is None:
        _loop_instance = AttackLoopEngine(max_iterations=max_iterations)
    return _loop_instance
