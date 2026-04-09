"""
Campaign Manager — orchestrates large-scale adversarial prompt campaigns.

Campaign modes:
  prompt_injection   — override system instructions
  jailbreak          — bypass safety filters
  data_leak          — extract system prompts / credentials
  rag_attack         — inject via retrieved documents
  tool_abuse         — manipulate AI agent tool calls
  output_manipulation — inject HTML/JS/URLs into output
  full               — all of the above

Execution:
  1. Generate prompts (template + evolved)
  2. Apply mutations
  3. Send to target (async parallel HTTP)
  4. Analyze responses
  5. Record results in evolution DB
  6. Emit vulnerability findings
"""

from __future__ import annotations

import asyncio
import hashlib
import json
import logging
import time
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, AsyncGenerator, Dict, List, Optional

from .prompt_generator import AdversarialPrompt, PromptGenerator
from .payload_mutator import PayloadMutator, MutatedPrompt
from .response_analyzer import AnalysisResult, ResponseAnalyzer
from .vulnerability_detector import AIVulnFinding, VulnerabilityDetector
from .adversarial_prompt_evolution import AdversarialPromptEvolution

log = logging.getLogger(__name__)


class CampaignMode(str, Enum):
    PROMPT_INJECTION    = "prompt_injection"
    JAILBREAK           = "jailbreak"
    DATA_LEAK           = "data_leak"
    RAG_ATTACK          = "rag_attack"
    TOOL_ABUSE          = "tool_abuse"
    OUTPUT_MANIPULATION = "output_manipulation"
    FULL                = "full"


@dataclass
class CampaignConfig:
    target: str
    mode: CampaignMode
    num_prompts: int = 100
    parallel: int = 10
    timeout: int = 30              # per-request timeout (seconds)
    mutations_per_prompt: int = 3
    use_evolution: bool = True
    endpoint_path: str = "/v1/chat/completions"
    auth_header: str = ""          # e.g. "Bearer sk-..."
    extra_headers: Dict[str, str] = field(default_factory=dict)
    model: str = "gpt-3.5-turbo"  # for OpenAI-compat endpoints
    system_prompt: str = ""        # inject a system prompt if testing locally
    context: str = ""              # optional target context description
    stop_on_first_critical: bool = False
    dry_run: bool = False          # generate prompts but don't send


@dataclass
class CampaignResult:
    campaign_id: str
    target: str
    mode: str
    started_at: float
    finished_at: float
    prompts_sent: int
    responses_received: int
    findings: List[AIVulnFinding]
    analysis_results: List[AnalysisResult]
    error_count: int
    stats: Dict[str, Any]

    @property
    def duration(self) -> float:
        return self.finished_at - self.started_at

    @property
    def vuln_count(self) -> int:
        return len(self.findings)

    @property
    def success_rate(self) -> float:
        if self.prompts_sent == 0:
            return 0.0
        return self.vuln_count / self.prompts_sent


class CampaignManager:
    """
    Orchestrates end-to-end adversarial AI testing campaigns.
    """

    def __init__(self) -> None:
        self._generator = PromptGenerator()
        self._mutator = PayloadMutator()
        self._analyzer = ResponseAnalyzer()
        self._detector = VulnerabilityDetector()
        self._evolution = AdversarialPromptEvolution()

    # ── Public API ────────────────────────────────────────────────────────────

    async def run(self, config: CampaignConfig) -> CampaignResult:
        """Execute a full adversarial campaign."""
        import uuid
        campaign_id = uuid.uuid4().hex[:8]
        started_at = time.time()
        log.info("[campaign:%s] Starting — mode=%s, prompts=%d, parallel=%d",
                 campaign_id, config.mode.value, config.num_prompts, config.parallel)

        # 1. Generate prompts
        all_prompts = self._build_prompt_set(config)
        log.info("[campaign:%s] Generated %d prompts", campaign_id, len(all_prompts))

        if config.dry_run:
            log.info("[campaign:%s] DRY RUN — not sending prompts", campaign_id)
            return CampaignResult(
                campaign_id=campaign_id, target=config.target,
                mode=config.mode.value, started_at=started_at,
                finished_at=time.time(), prompts_sent=0,
                responses_received=0, findings=[], analysis_results=[],
                error_count=0, stats={"dry_run": True, "prompts_generated": len(all_prompts)},
            )

        # 2. Send prompts in parallel and collect results
        all_findings: List[AIVulnFinding] = []
        all_analyses: List[AnalysisResult] = []
        errors = 0
        sent = 0

        sem = asyncio.Semaphore(config.parallel)
        tasks = [
            self._probe(p, config, sem)
            for p in all_prompts
        ]

        for coro in asyncio.as_completed(tasks):
            try:
                prompt_obj, response_text, elapsed = await coro
                if response_text is None:
                    errors += 1
                    continue

                sent += 1

                # Analyze
                analysis = self._analyzer.analyze(
                    response=response_text,
                    payload=prompt_obj.text,
                    attack_type=prompt_obj.attack_type,
                )
                all_analyses.append(analysis)

                # Detect vulnerabilities
                findings = self._detector.analyze(
                    target=config.target,
                    payload=prompt_obj.text,
                    response=response_text,
                    tool="AI Red Team Engine",
                    extra_tags=[config.mode.value, prompt_obj.source],
                )
                all_findings.extend(findings)

                # Record in evolution DB
                success = analysis.is_vulnerable
                self._evolution.record_result(
                    prompt_id=hashlib.sha256(prompt_obj.text.encode()).hexdigest()[:16],
                    target=config.target,
                    response=response_text,
                    succeeded=success,
                    score=analysis.overall_score,
                    mutation_type=getattr(prompt_obj, "source", ""),
                    attack_type=prompt_obj.attack_type,
                )

                # Early stop
                if config.stop_on_first_critical:
                    critical = [f for f in findings if f.severity == "critical"]
                    if critical:
                        log.info("[campaign:%s] Critical finding — stopping early", campaign_id)
                        break

            except Exception as exc:
                log.error("[campaign:%s] Error: %s", campaign_id, exc)
                errors += 1

        finished_at = time.time()
        analyzer_stats = self._analyzer.summary_stats(all_analyses)

        return CampaignResult(
            campaign_id=campaign_id,
            target=config.target,
            mode=config.mode.value,
            started_at=started_at,
            finished_at=finished_at,
            prompts_sent=sent,
            responses_received=sent,
            findings=all_findings,
            analysis_results=all_analyses,
            error_count=errors,
            stats={
                **analyzer_stats,
                "duration_seconds": round(finished_at - started_at, 2),
                "prompts_generated": len(all_prompts),
            },
        )

    async def run_sync(self, config: CampaignConfig) -> CampaignResult:
        """Synchronous wrapper for use outside async contexts."""
        return await self.run(config)

    # ── Prompt building ───────────────────────────────────────────────────────

    def _build_prompt_set(self, config: CampaignConfig) -> List[AdversarialPrompt]:
        """Build the full prompt set: templates + mutations + evolved."""
        mode = config.mode
        attack_types = (
            ["prompt_injection", "jailbreak", "data_leak", "rag_attack",
             "tool_abuse", "output_manipulation"]
            if mode == CampaignMode.FULL
            else [mode.value]
        )

        prompts: List[AdversarialPrompt] = []
        per_type = max(1, config.num_prompts // len(attack_types))

        for atype in attack_types:
            # Base templates
            base = self._generator.generate(atype, per_type // 2 + 1, config.context)
            prompts.extend(base)

            # Mutations
            if config.mutations_per_prompt > 0:
                mutations = self._mutator.mutate_batch(
                    base[:20], mutations_per_prompt=config.mutations_per_prompt
                )
                for m in mutations:
                    prompts.append(AdversarialPrompt(
                        text=m.text,
                        attack_type=m.attack_type,
                        category="mutated",
                        severity=m.severity,
                        source=f"mutation:{m.mutation_type}",
                        tags=m.tags,
                    ))

            # Evolved prompts (from DB)
            if config.use_evolution:
                evolved = self._evolution.get_evolved_prompts(
                    attack_type=atype,
                    count=per_type // 4 + 1,
                    auto_evolve=False,
                )
                prompts.extend(evolved)

        # Shuffle and trim
        import random
        random.shuffle(prompts)
        return prompts[:config.num_prompts]

    # ── HTTP probing ─────────────────────────────────────────────────────────

    async def _probe(
        self,
        prompt: AdversarialPrompt,
        config: CampaignConfig,
        sem: asyncio.Semaphore,
    ) -> tuple:
        """Send one probe request. Returns (prompt, response_text, elapsed_ms)."""
        async with sem:
            loop = asyncio.get_event_loop()
            try:
                start = time.time()
                response_text = await loop.run_in_executor(
                    None,
                    self._send_request,
                    prompt.text,
                    config,
                )
                elapsed = (time.time() - start) * 1000
                return prompt, response_text, elapsed
            except Exception as exc:
                log.debug("Probe failed for prompt %s: %s", prompt.text[:40], exc)
                return prompt, None, 0.0

    def _send_request(self, payload_text: str, config: CampaignConfig) -> Optional[str]:
        """
        Send a single HTTP request to the AI endpoint.
        Supports OpenAI-compatible chat completion API format.
        Falls back to raw POST if not an OpenAI endpoint.
        """
        target = config.target
        if not target.startswith(("http://", "https://")):
            target = "https://" + target

        url = target.rstrip("/") + config.endpoint_path

        # Build request body (OpenAI chat completions format)
        messages = []
        if config.system_prompt:
            messages.append({"role": "system", "content": config.system_prompt})
        messages.append({"role": "user", "content": payload_text})

        body = json.dumps({
            "model": config.model,
            "messages": messages,
            "max_tokens": 500,
            "temperature": 1.0,
        }).encode("utf-8")

        headers = {
            "Content-Type": "application/json",
            "Accept": "application/json",
            "User-Agent": "OneInfinity/ai-redteam",
        }
        if config.auth_header:
            headers["Authorization"] = config.auth_header
        headers.update(config.extra_headers)

        req = urllib.request.Request(url, data=body, headers=headers, method="POST")
        try:
            with urllib.request.urlopen(req, timeout=config.timeout) as resp:
                raw = resp.read(65536).decode("utf-8", errors="ignore")
                # Parse OpenAI format
                try:
                    data = json.loads(raw)
                    return (
                        data.get("choices", [{}])[0]
                        .get("message", {})
                        .get("content", raw)
                    )
                except (json.JSONDecodeError, KeyError, IndexError):
                    return raw
        except urllib.error.HTTPError as e:
            body_bytes = e.read(4096)
            return body_bytes.decode("utf-8", errors="ignore")
        except Exception as exc:
            log.debug("Request error: %s", exc)
            return None
