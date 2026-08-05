"""
ai_redteam_orchestrator.py — Unified AI Red-Team Orchestrator
=============================================================
Tier-based engine dependency graph replacing the thin AIRedTeamEngine wrapper.

Execution order
---------------
Tier 0  — Fingerprint + OOB setup  (required before anything else)
  • ModelExtractionEngine          — model/arch identification
  • interactsh OOB URL seed        — inject unique OOB URL into all probe campaigns

Tier 1  — Fast stateless engines   (parallel)
  • IndirectPromptInjectionMapper  — data-source injection
  • AISecurityEngine (garak+pyrit+giskard+rebuff)

Tier 2  — Stateful engines         (parallel, seeded from T1 winners)
  • MultiTurnChainer               — all chain strategies
  • RAGPoisoningEngine             — RAG injection (opt-in)
  • LLMDoSEngine                   — DoS probes (OPT-IN only, explicit enable_dos flag)

Tier 3  — Campaign evolution       (uses T1/T2 winning prompts as seed)
  • CampaignManager + AdversarialPromptEvolution

ShadowBoxer pre-filter
  Applied in Tier3 before sending each evolved prompt to the real target.
  Prompts that pass the local Ollama shadow model are prioritised.
"""
from __future__ import annotations

import asyncio
import hashlib
import json
import logging
import time
import uuid
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional

log = logging.getLogger("oneinfinity.ai_redteam_orchestrator")


# ─────────────────────────────────────────────────────────────────────────────
#  Config & Result types
# ─────────────────────────────────────────────────────────────────────────────

@dataclass
class OrchestratorConfig:
    target: str
    mode: str = "full"
    num_prompts: int = 100
    parallel: int = 5
    endpoint_path: str = "/v1/chat/completions"
    auth_header: str = ""
    cookie_header: str = ""
    request_template: str = ""
    model: str = "gpt-3.5-turbo"
    context: str = ""

    # Engine flags
    enable_multi_turn: bool = True
    enable_rag_poison: bool = True
    enable_model_extraction: bool = True
    enable_indirect_injection: bool = True
    enable_ai_security: bool = True        # garak+pyrit+giskard+rebuff
    enable_dos: bool = False               # EXPLICIT OPT-IN required (destructive)

    # ShadowBoxer pre-filter
    use_shadow_boxer: bool = True
    shadow_ollama_url: str = "http://localhost:11434"
    shadow_model: str = "llama3"

    # Tier timeouts (seconds)
    tier0_timeout: int = 60
    tier1_timeout: int = 120
    tier2_timeout: int = 180
    tier3_timeout: int = 240

    # OOB
    use_oob: bool = True
    oob_server: str = ""


@dataclass
class EngineResult:
    engine_name: str
    findings: List[Dict[str, Any]] = field(default_factory=list)
    error: Optional[str] = None
    duration_s: float = 0.0
    tier: int = 0
    winning_prompts: List[str] = field(default_factory=list)


@dataclass
class OrchestratorResult:
    campaign_id: str
    target: str
    mode: str
    started_at: float
    finished_at: float
    engine_results: List[EngineResult] = field(default_factory=list)
    findings: List[Dict[str, Any]] = field(default_factory=list)
    oob_url: str = ""
    behavior_profile: Dict[str, Any] = field(default_factory=dict)
    error: Optional[str] = None

    @property
    def duration(self) -> float:
        return self.finished_at - self.started_at

    @property
    def finding_count(self) -> int:
        return len(self.findings)

    @property
    def critical_count(self) -> int:
        return sum(1 for f in self.findings if f.get("severity") == "critical")

    @property
    def high_count(self) -> int:
        return sum(1 for f in self.findings if f.get("severity") == "high")

    def engines_run(self) -> List[str]:
        return [er.engine_name for er in self.engine_results if not er.error]

    def to_dict(self) -> Dict[str, Any]:
        sev: Dict[str, int] = {}
        for f in self.findings:
            k = f.get("severity", "info")
            sev[k] = sev.get(k, 0) + 1
        return {
            "campaign_id": self.campaign_id,
            "target": self.target,
            "mode": self.mode,
            "started_at": self.started_at,
            "finished_at": self.finished_at,
            "duration_s": round(self.duration, 1),
            "finding_count": self.finding_count,
            "severity_counts": sev,
            "engines_run": self.engines_run(),
            "engine_results": [
                {
                    "engine": er.engine_name,
                    "tier": er.tier,
                    "findings": len(er.findings),
                    "duration_s": round(er.duration_s, 1),
                    "error": er.error,
                }
                for er in self.engine_results
            ],
            "findings": self.findings,
            "oob_url": self.oob_url,
            "behavior_profile": self.behavior_profile,
            "error": self.error,
        }


# ─────────────────────────────────────────────────────────────────────────────
#  Orchestrator
# ─────────────────────────────────────────────────────────────────────────────

class AIRedTeamOrchestrator:
    """
    Unified orchestrator for all AI red-team engines.
    Replaces the thin AIRedTeamEngine.run_campaign() with a full
    tier-based dependency graph execution.
    """

    def __init__(self) -> None:
        self._scan_id = ""

    # ── Public API ────────────────────────────────────────────────────────

    async def run(self, cfg: OrchestratorConfig) -> OrchestratorResult:
        self._scan_id = f"ort-{uuid.uuid4().hex[:8]}"
        result = OrchestratorResult(
            campaign_id=self._scan_id,
            target=cfg.target,
            mode=cfg.mode,
            started_at=time.time(),
            finished_at=0.0,
        )
        log.info("[Orchestrator] Starting %s on %s (mode=%s)", self._scan_id, cfg.target, cfg.mode)

        try:
            # Tier 0
            t0 = await self._run_tier0(cfg, result)

            # Tier 1 (parallel)
            t1 = await self._run_tier1(cfg, result)
            seed: List[str] = []
            for er in t1:
                seed.extend(er.winning_prompts)

            # Tier 2 (parallel, seeded)
            t2 = await self._run_tier2(cfg, result, seed)
            for er in t2:
                seed.extend(er.winning_prompts)

            # Tier 3 (campaign evolution)
            t3 = await self._run_tier3(cfg, result, seed)

            all_ers = t0 + t1 + t2 + t3
            result.engine_results = all_ers
            result.findings = self._deduplicate(
                [f for er in all_ers for f in er.findings]
            )

            self._emit_events(cfg, result)
            result.behavior_profile = self._build_behavior_profile(cfg, result)
            self._persist_behavior_profile(cfg, result)

        except Exception as exc:
            result.error = str(exc)
            log.exception("[Orchestrator] %s failed: %s", self._scan_id, exc)
        finally:
            result.finished_at = time.time()

        log.info("[Orchestrator] %s done — %d findings in %.1fs",
                 self._scan_id, result.finding_count, result.duration)
        return result

    # ── Tier runners ──────────────────────────────────────────────────────

    async def _run_tier0(self, cfg: OrchestratorConfig, result: OrchestratorResult) -> List[EngineResult]:
        ers: List[EngineResult] = []

        if cfg.use_oob:
            oob = self._setup_oob()
            if oob:
                cfg.oob_server = oob
                result.oob_url = oob
                log.info("[T0] OOB URL: %s", oob)

        if cfg.enable_model_extraction:
            er = await self._safe_run("model_extraction", self._run_model_extraction(cfg), cfg.tier0_timeout, 0)
            ers.append(er)

        return ers

    async def _run_tier1(self, cfg: OrchestratorConfig, result: OrchestratorResult) -> List[EngineResult]:
        tasks = []
        if cfg.enable_indirect_injection:
            tasks.append(("indirect_injection", self._run_indirect_injection(cfg)))
        if cfg.enable_ai_security:
            tasks.append(("ai_security_engine", self._run_ai_security(cfg)))
        if not tasks:
            return []
        return await self._run_parallel(tasks, cfg.tier1_timeout, 1)

    async def _run_tier2(self, cfg: OrchestratorConfig, result: OrchestratorResult, seed: List[str]) -> List[EngineResult]:
        tasks = []
        if cfg.enable_multi_turn:
            tasks.append(("multi_turn_chainer", self._run_multi_turn(cfg)))
        if cfg.enable_rag_poison:
            tasks.append(("rag_poisoning", self._run_rag_poison(cfg)))
        if cfg.enable_dos:
            tasks.append(("llm_dos", self._run_llm_dos(cfg)))
        if not tasks:
            return []
        return await self._run_parallel(tasks, cfg.tier2_timeout, 2)

    async def _run_tier3(self, cfg: OrchestratorConfig, result: OrchestratorResult, seed: List[str]) -> List[EngineResult]:
        er = await self._safe_run("campaign_manager", self._run_campaign(cfg, seed), cfg.tier3_timeout, 3)
        return [er]

    # ── Engine implementations ────────────────────────────────────────────

    async def _run_model_extraction(self, cfg: OrchestratorConfig) -> EngineResult:
        er = EngineResult(engine_name="model_extraction", tier=0)
        t0 = time.time()
        try:
            from oneinfinity.ai.model_extraction_engine import ModelExtractionEngine
            eng = ModelExtractionEngine(
                target_url=cfg.target,
                auth_header=cfg.auth_header,
                model=cfg.model,
            )
            raw = await eng.scan()
            er.findings = [self._norm(f, "model_extraction") for f in (raw or [])]
        except Exception as exc:
            er.error = str(exc)
            log.warning("[T0] ModelExtraction: %s", exc)
        er.duration_s = time.time() - t0
        return er

    async def _run_indirect_injection(self, cfg: OrchestratorConfig) -> EngineResult:
        er = EngineResult(engine_name="indirect_injection", tier=1)
        t0 = time.time()
        try:
            from oneinfinity.ai_security.indirect_prompt_injection_mapper import IndirectPromptInjectionMapper
            mapper = IndirectPromptInjectionMapper(
                target=cfg.target,
                scan_id=self._scan_id,
                auth_headers={"Authorization": cfg.auth_header} if cfg.auth_header else {},
            )
            agent_ep = cfg.target.rstrip("/") + cfg.endpoint_path
            raw = await asyncio.get_event_loop().run_in_executor(
                None,
                lambda: mapper.run(
                    urls=[cfg.target],
                    agent_endpoint=agent_ep,
                    auth_headers={"Authorization": cfg.auth_header} if cfg.auth_header else {},
                )
            )
            er.findings = [self._norm(f, "indirect_injection") for f in (raw or [])]
        except Exception as exc:
            er.error = str(exc)
            log.warning("[T1] IndirectInjection: %s", exc)
        er.duration_s = time.time() - t0
        return er

    async def _run_ai_security(self, cfg: OrchestratorConfig) -> EngineResult:
        er = EngineResult(engine_name="ai_security_engine", tier=1)
        t0 = time.time()
        try:
            from oneinfinity.ai.ai_security_engine import AISecurityEngine, AISecurityScanConfig
            eng = AISecurityEngine()
            sc = AISecurityScanConfig(
                target=cfg.target,
                tools=None,
                endpoint_path=cfg.endpoint_path,
                auth_header=cfg.auth_header,
                model=cfg.model,
                timeout=90,
                output_dir="/tmp/oneinfinity_ai_sec",
            )
            if hasattr(sc, "context"):
                sc.context = cfg.context
            res = await eng.scan(sc)
            er.findings = [self._norm(f.__dict__ if hasattr(f, "__dict__") else f, "ai_security") for f in (res.findings or [])]
            er.winning_prompts = [
                f.get("payload", "") for f in er.findings
                if f.get("severity") in ("critical", "high") and f.get("payload")
            ]
        except Exception as exc:
            er.error = str(exc)
            log.warning("[T1] AISecurityEngine: %s", exc)
        er.duration_s = time.time() - t0
        return er

    async def _run_multi_turn(self, cfg: OrchestratorConfig) -> EngineResult:
        er = EngineResult(engine_name="multi_turn_chainer", tier=2)
        t0 = time.time()
        try:
            from oneinfinity.ai_security.multi_turn_chainer import MultiTurnChainer, ChainStrategy
            target_url = cfg.target.rstrip("/") + cfg.endpoint_path
            chainer = MultiTurnChainer(
                target_url=target_url,
                auth_header=cfg.auth_header,
                model=cfg.model,
            )
            strategies = (
                [ChainStrategy.ROLEPLAY_ESCALATION, ChainStrategy.AUTHORITY_INJECTION, ChainStrategy.DAN_PROGRESSIVE]
                if cfg.mode == "quick"
                else list(ChainStrategy)
            )
            for strat in strategies:
                try:
                    chain_r = await asyncio.wait_for(
                        chainer.run_chain(strategy=strat, max_turns=6), timeout=45
                    )
                    if chain_r:
                        raw_f = chain_r.findings if hasattr(chain_r, "findings") else []
                        er.findings.extend([self._norm(f, "multi_turn") for f in raw_f])
                        if hasattr(chain_r, "turns"):
                            for turn in chain_r.turns:
                                if getattr(turn, "success", False):
                                    p = getattr(turn, "prompt", "")
                                    if p:
                                        er.winning_prompts.append(p)
                except (asyncio.TimeoutError, Exception) as exc:
                    log.debug("[T2] MultiTurn %s: %s", strat, exc)
        except Exception as exc:
            er.error = str(exc)
            log.warning("[T2] MultiTurnChainer: %s", exc)
        er.duration_s = time.time() - t0
        return er

    async def _run_rag_poison(self, cfg: OrchestratorConfig) -> EngineResult:
        er = EngineResult(engine_name="rag_poisoning", tier=2)
        t0 = time.time()
        try:
            from oneinfinity.ai_security.rag_poisoning_engine import RAGPoisoningEngine
            eng = RAGPoisoningEngine(auth_header=cfg.auth_header, model=cfg.model)
            raw = await asyncio.wait_for(eng.scan(cfg.target), timeout=90)
            er.findings = [self._norm(f, "rag_poisoning") for f in (raw or [])]
        except asyncio.TimeoutError:
            er.error = "timeout"
        except Exception as exc:
            er.error = str(exc)
            log.warning("[T2] RAGPoisoning: %s", exc)
        er.duration_s = time.time() - t0
        return er

    async def _run_llm_dos(self, cfg: OrchestratorConfig) -> EngineResult:
        """Opt-in only — never called unless cfg.enable_dos is True."""
        er = EngineResult(engine_name="llm_dos", tier=2)
        t0 = time.time()
        try:
            from oneinfinity.ai_security.llm_dos_engine import LLMDoSEngine
            eng = LLMDoSEngine(auth_header=cfg.auth_header, model=cfg.model)
            raw = await asyncio.wait_for(eng.scan(cfg.target), timeout=90)
            er.findings = [self._norm(f, "llm_dos") for f in (raw or [])]
        except asyncio.TimeoutError:
            er.error = "timeout"
        except Exception as exc:
            er.error = str(exc)
            log.warning("[T2] LLMDoS: %s", exc)
        er.duration_s = time.time() - t0
        return er

    async def _run_campaign(self, cfg: OrchestratorConfig, seed: List[str]) -> EngineResult:
        er = EngineResult(engine_name="campaign_manager", tier=3)
        t0 = time.time()
        try:
            from oneinfinity.ai_security.campaign_manager import CampaignConfig, CampaignManager, CampaignMode
            _mode_map = {
                "full": CampaignMode.FULL,
                "quick": CampaignMode.FULL,
                "prompt_injection": CampaignMode.PROMPT_INJECTION,
                "jailbreak": CampaignMode.JAILBREAK,
                "data_leak": CampaignMode.DATA_LEAK,
                "rag_attack": CampaignMode.RAG_ATTACK,
                "tool_abuse": CampaignMode.TOOL_ABUSE,
                "output_manipulation": CampaignMode.OUTPUT_MANIPULATION,
            }
            cc = CampaignConfig(
                target=cfg.target,
                mode=_mode_map.get(cfg.mode, CampaignMode.FULL),
                num_prompts=cfg.num_prompts,
                parallel=cfg.parallel,
                endpoint_path=cfg.endpoint_path,
                auth_header=cfg.auth_header,
                model=cfg.model,
                use_evolution=True,
                context=cfg.context,
            )

            # ShadowBoxer pre-filter on seed prompts
            if cfg.use_shadow_boxer and seed:
                seed = self._shadow_filter(seed, cfg)
                log.info("[T3] ShadowBoxer: %d seed prompts passed", len(seed))

            # Inject winners into evolution corpus
            if seed:
                try:
                    from oneinfinity.ai_security.adversarial_prompt_evolution import AdversarialPromptEvolution
                    evo = AdversarialPromptEvolution()
                    for p in seed[:50]:
                        if p.strip():
                            evo.record_success(p, "multi_engine_seed", 0.9)
                except Exception:
                    pass

            mgr = CampaignManager()
            camp_r = await mgr.run(cc)
            er.findings = [self._norm(f.__dict__ if hasattr(f, "__dict__") else f, "campaign") for f in (camp_r.findings or [])]
        except Exception as exc:
            er.error = str(exc)
            log.warning("[T3] Campaign: %s", exc)
        er.duration_s = time.time() - t0
        return er

    # ── ShadowBoxer ───────────────────────────────────────────────────────

    def _shadow_filter(self, prompts: List[str], cfg: OrchestratorConfig) -> List[str]:
        try:
            from oneinfinity.scan.ai_red_teamer.shadow_box import ShadowBoxer
            boxer = ShadowBoxer(ollama_url=cfg.shadow_ollama_url, model=cfg.shadow_model)
            passed = []
            for p in prompts:
                try:
                    res = boxer.evaluate_payload(p)
                    if not res.blocked:
                        passed.append(p)
                except Exception:
                    passed.append(p)
            return passed or prompts
        except Exception:
            return prompts

    # ── OOB setup ─────────────────────────────────────────────────────────

    def _setup_oob(self) -> str:
        try:
            import shutil, subprocess
            interactsh = shutil.which("interactsh-client") or shutil.which("interactsh")
            if not interactsh:
                return ""
            res = subprocess.run(
                [interactsh, "-server", "oast.pro", "-n", "1", "-json"],
                capture_output=True, text=True, timeout=10,
            )
            for line in res.stdout.splitlines():
                try:
                    data = json.loads(line)
                    url = data.get("interactsh-url") or data.get("url", "")
                    if url:
                        return url
                except json.JSONDecodeError:
                    continue
        except Exception as exc:
            log.debug("OOB setup: %s", exc)
        return ""

    # ── Parallel helper ───────────────────────────────────────────────────

    async def _run_parallel(self, tasks: List[tuple], timeout: int, tier: int) -> List[EngineResult]:
        return list(await asyncio.gather(
            *[self._safe_run(name, coro, timeout, tier) for name, coro in tasks],
            return_exceptions=False,
        ))

    async def _safe_run(self, name: str, coro, timeout: int, tier: int) -> EngineResult:
        try:
            er = await asyncio.wait_for(coro, timeout=timeout)
            er.tier = tier
            return er
        except asyncio.TimeoutError:
            log.warning("[T%d] %s timed out after %ds", tier, name, timeout)
            return EngineResult(engine_name=name, tier=tier, error=f"timeout after {timeout}s")
        except Exception as exc:
            log.warning("[T%d] %s: %s", tier, name, exc)
            return EngineResult(engine_name=name, tier=tier, error=str(exc))

    # ── Finding normalisation ─────────────────────────────────────────────

    def _norm(self, raw: Any, engine: str) -> Dict[str, Any]:
        f = raw.copy() if isinstance(raw, dict) else (raw.__dict__.copy() if hasattr(raw, "__dict__") else {"evidence": str(raw)})
        fp_src = {k: v for k, v in f.items() if k not in ("fingerprint", "scan_id")}
        return {
            "fingerprint":   f.get("fingerprint") or hashlib.sha256(json.dumps(fp_src, sort_keys=True, default=str).encode()).hexdigest()[:16],
            "vulnerability": f.get("vulnerability") or f.get("vulnerability_type") or f.get("title") or "AI Finding",
            "severity":      f.get("severity", "medium"),
            "confidence":    float(f.get("confidence", 0.7)),
            "attack_type":   f.get("attack_type") or f.get("technique") or engine,
            "target":        f.get("target", ""),
            "payload":       f.get("payload", ""),
            "evidence":      f.get("evidence") or f.get("description", ""),
            "remediation":   f.get("remediation", ""),
            "cvss":          float(f.get("cvss", 0.0)),
            "tool":          f.get("tool", engine),
            "engine":        engine,
            "tags":          f.get("tags") or [engine, "ai_redteam"],
        }

    def _deduplicate(self, findings: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        seen: set = set()
        out: List[Dict[str, Any]] = []
        for f in findings:
            fp = f.get("fingerprint", "")
            if fp and fp in seen:
                continue
            if fp:
                seen.add(fp)
            out.append(f)
        return out

    # ── EventBus ──────────────────────────────────────────────────────────

    def _emit_events(self, cfg: OrchestratorConfig, result: OrchestratorResult) -> None:
        try:
            from oneinfinity.orchestration.event_bus import get_bus, EventType
            bus = get_bus()
            try:
                bus.publish(
                    EventType.AI_ENDPOINT_DISCOVERED,
                    {"target": cfg.target, "endpoint": cfg.endpoint_path, "campaign_id": result.campaign_id},
                    source="ai_redteam_orchestrator",
                )
            except (AttributeError, ValueError):
                pass  # EventType may not yet have this value — handled in Phase2
            for er in result.engine_results:
                if er.engine_name == "model_extraction" and er.findings:
                    try:
                        bus.publish(
                            EventType.AI_MODEL_IDENTIFIED,
                            {"target": cfg.target, "findings": er.findings[:5], "campaign_id": result.campaign_id},
                            source="ai_redteam_orchestrator",
                        )
                    except (AttributeError, ValueError):
                        pass
        except Exception as exc:
            log.debug("EventBus emit (non-critical): %s", exc)

    # ── Behavior Profile ──────────────────────────────────────────────────

    def _build_behavior_profile(self, cfg: OrchestratorConfig, result: OrchestratorResult) -> Dict[str, Any]:
        sev: Dict[str, int] = {}
        atypes: set = set()
        for f in result.findings:
            k = f.get("severity", "info")
            sev[k] = sev.get(k, 0) + 1
            if f.get("attack_type"):
                atypes.add(f["attack_type"])
        return {
            "target":                cfg.target,
            "model":                 cfg.model,
            "endpoint":              cfg.endpoint_path,
            "campaign_id":           result.campaign_id,
            "scan_time":             time.time(),
            "total_findings":        result.finding_count,
            "severity_distribution": sev,
            "attack_surface":        sorted(atypes),
            "engines_tested":        result.engines_run(),
            "oob_used":              bool(result.oob_url),
            "risk_score":            self._risk_score(result),
        }

    def _risk_score(self, result: OrchestratorResult) -> float:
        w = {"critical": 4.0, "high": 2.5, "medium": 1.0, "low": 0.3, "info": 0.1}
        return min(10.0, round(sum(w.get(f.get("severity", "info"), 0.1) for f in result.findings), 1))

    def _persist_behavior_profile(self, cfg: OrchestratorConfig, result: OrchestratorResult) -> None:
        try:
            from oneinfinity.core.db_manager import get_db_manager_sync
            mgr = get_db_manager_sync()
            if mgr and hasattr(mgr, "neo4j_session"):
                sess = mgr.neo4j_session()
                if sess:
                    bp = result.behavior_profile
                    sess.run(
                        """
                        MERGE (b:AI_BEHAVIOR {target: $target, endpoint: $endpoint})
                        SET b.last_scan = $scan_time,
                            b.risk_score = $risk_score,
                            b.total_findings = $total_findings,
                            b.model = $model,
                            b.attack_surface = $attack_surface,
                            b.campaign_id = $campaign_id
                        """,
                        target=bp.get("target"),
                        endpoint=bp.get("endpoint"),
                        scan_time=bp.get("scan_time"),
                        risk_score=bp.get("risk_score"),
                        total_findings=bp.get("total_findings"),
                        model=bp.get("model"),
                        attack_surface=json.dumps(bp.get("attack_surface", [])),
                        campaign_id=bp.get("campaign_id"),
                    )
        except Exception as exc:
            log.debug("Neo4j persist (non-critical): %s", exc)
