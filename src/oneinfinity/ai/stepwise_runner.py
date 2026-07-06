"""
stepwise_runner.py — Executes an ExploitPlan step-by-step.

Each ExploitStep is attempted via HTTP POST; on failure an optional
adaptation_agent is consulted for a bypass before one retry.
"""

from __future__ import annotations

import logging
import time
import urllib.error
import urllib.parse
import urllib.request
from typing import Any, Dict, Optional

from oneinfinity.intelligence.attack_graph_brain import (
    ExploitPlan,
    ExploitStep,
    ExploitTrace,
    StepResult,
)

log = logging.getLogger(__name__)

_DEFAULT_TIMEOUT = 15  # seconds per HTTP request


class StepwiseExploitRunner:
    """Execute an :class:`ExploitPlan` step by step against a target URL.

    Args:
        plan:               The :class:`ExploitPlan` to execute.
        target_url:         Base URL that receives POST payloads.
        http_client:        Optional callable ``(url, data) -> str`` that
                            replaces the built-in urllib transport.
        adaptation_agent:   Optional object with a
                            ``suggest_bypass(step, result) -> str | None``
                            method; called on step failure to get an
                            alternative payload before one retry.
        model_orchestrator: Optional :class:`ModelOrchestrator` used for
                            LLM-assisted scoring (lazy-imported if *None*).
    """

    def __init__(
        self,
        plan: ExploitPlan,
        target_url: str,
        http_client=None,
        adaptation_agent=None,
        model_orchestrator=None,
    ) -> None:
        self.plan = plan
        self.target_url = target_url
        self.http_client = http_client
        self.adaptation_agent = adaptation_agent
        self._model_orchestrator = model_orchestrator

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def run(self) -> ExploitTrace:
        """Execute every step in *plan* and return a full :class:`ExploitTrace`."""
        trace = ExploitTrace(plan_id=self.plan.plan_id, target=self.target_url)
        context: Dict[str, Any] = {}

        for step in self.plan.steps:
            result = self._execute_step(step, context)

            if not result.success and self.adaptation_agent is not None:
                bypass = self._try_bypass(step, result)
                if bypass is not None:
                    step_copy = ExploitStep(
                        step_id=step.step_id,
                        action=step.action,
                        payload_template=bypass,
                        expected_outcome=step.expected_outcome,
                        fallback=step.fallback,
                        success_condition=step.success_condition,
                        metadata=dict(step.metadata, retried=True),
                    )
                    result = self._execute_step(step_copy, context)

            context.update(result.context_update)
            trace.results.append(result)
            log.debug(
                "[StepwiseExploitRunner] step=%s success=%s score=%.2f",
                result.step_id,
                result.success,
                result.score,
            )

        return trace

    # ------------------------------------------------------------------
    # Internals
    # ------------------------------------------------------------------

    def _execute_step(self, step: ExploitStep, context: Dict[str, Any]) -> StepResult:
        """POST the rendered payload and evaluate the response.

        Scoring rules:
        - 1.0 — response contains *success_condition* substring
        - 0.3 — response received but *success_condition* not found
        - 0.0 — transport/HTTP error
        """
        payload = self._render_payload(step.payload_template, context)
        try:
            response_text = self._post(payload)
        except Exception as exc:
            return StepResult(
                step_id=step.step_id,
                success=False,
                score=0.0,
                response="",
                error=str(exc),
            )

        matched = bool(step.success_condition and step.success_condition in response_text)
        score = 1.0 if matched else 0.3
        context_update: Dict[str, Any] = {}
        if matched:
            context_update["last_success_step"] = step.step_id
            context_update["last_response_snippet"] = response_text[:200]

        return StepResult(
            step_id=step.step_id,
            success=matched,
            score=score,
            response=response_text,
            context_update=context_update,
        )

    @staticmethod
    def _render_payload(template: str, context: Dict[str, Any]) -> str:
        """Fill *{key}* placeholders in *template* from *context*."""
        if not template:
            return ""
        try:
            return template.format_map(context)
        except (KeyError, ValueError):
            return template

    def _post(self, payload: str) -> str:
        """Send *payload* via HTTP POST; use custom client if provided."""
        if self.http_client is not None:
            return self.http_client(self.target_url, payload)

        data = payload.encode("utf-8")
        req = urllib.request.Request(
            self.target_url,
            data=data,
            method="POST",
            headers={"Content-Type": "text/plain; charset=utf-8"},
        )
        with urllib.request.urlopen(req, timeout=_DEFAULT_TIMEOUT) as resp:
            return resp.read().decode("utf-8", errors="replace")

    def _try_bypass(self, step: ExploitStep, result: StepResult) -> Optional[str]:
        """Ask adaptation_agent for a bypass payload; returns *None* on failure."""
        try:
            return self.adaptation_agent.suggest_bypass(step, result)
        except Exception as exc:
            log.debug("[StepwiseExploitRunner] adaptation_agent error: %s", exc)
            return None

    @property
    def model_orchestrator(self):
        if self._model_orchestrator is None:
            try:
                from oneinfinity.orchestration.model_orchestrator import get_orchestrator
                self._model_orchestrator = get_orchestrator()
            except Exception:
                pass
        return self._model_orchestrator
