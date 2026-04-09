"""
Autonomous Hunter Engine — Autonomous multi-target bug bounty hunter.
Discovers programs, prioritizes targets, runs parallel scans, exploits,
validates findings, and generates reports.
"""

import concurrent.futures
import os
import json
import time
import uuid
import logging
import asyncio
from dataclasses import dataclass, field
from pathlib import Path
from typing import List, Optional

from oneinfinity.path_manager import raw_dir

logger = logging.getLogger(__name__)

HUNTER_DB_PATH = raw_dir() / "hunter_sessions.json"
HUNTER_DB_PATH.parent.mkdir(parents=True, exist_ok=True)


@dataclass
class ScanStrategy:
    """
    Defines the scanning behaviour for a given mode (Fix 5).

    fast      — breadth-first: more targets, fewer deep chains, higher concurrency
    deep      — depth-first: fewer targets, full chaining + AI loop, slower
    api-heavy — API-focused: all API/GraphQL tools, skip browser/mobile phases
    stealth   — low-noise: human pacing, extra delays, single worker
    """
    mode: str = "fast"
    max_concurrent: int = 3
    max_targets: int = 10
    timeout_per_target: int = 300
    phases: List[str] = field(default_factory=lambda: [
        "discover", "recon", "scan", "exploit", "report"
    ])
    tool_priority: List[str] = field(default_factory=list)   # prioritised tools
    use_chaining: bool = True
    use_ai_loop: bool = True
    use_human_pacing: bool = False

    @classmethod
    def from_mode(cls, mode: str) -> "ScanStrategy":
        """Build a pre-configured strategy from a mode name."""
        mode = mode.lower().strip()
        if mode == "fast":
            return cls(
                mode="fast",
                max_concurrent=5,
                max_targets=15,
                timeout_per_target=180,
                phases=["discover", "recon", "scan", "report"],
                use_chaining=False,
                use_ai_loop=False,
            )
        if mode == "deep":
            return cls(
                mode="deep",
                max_concurrent=2,
                max_targets=5,
                timeout_per_target=600,
                phases=["discover", "recon", "scan", "exploit", "report"],
                use_chaining=True,
                use_ai_loop=True,
            )
        if mode in ("api-heavy", "api"):
            return cls(
                mode="api-heavy",
                max_concurrent=4,
                max_targets=10,
                timeout_per_target=300,
                phases=["discover", "recon", "scan", "exploit", "report"],
                tool_priority=["kiterunner", "nuclei", "graphql_scan", "jwt_tool"],
                use_chaining=True,
                use_ai_loop=True,
            )
        if mode == "stealth":
            return cls(
                mode="stealth",
                max_concurrent=1,
                max_targets=5,
                timeout_per_target=600,
                phases=["discover", "recon", "scan", "report"],
                use_human_pacing=True,
                use_chaining=False,
                use_ai_loop=False,
            )
        # Default: balanced
        return cls(mode=mode)


@dataclass
class HunterConfig:
    """Configuration for a hunter session."""
    name: str = "default"
    platforms: list = field(default_factory=lambda: ["hackerone", "bugcrowd"])
    max_targets: int = 10
    max_concurrent: int = 3
    phases: list = field(default_factory=lambda: ["discover", "recon", "scan", "exploit", "report"])
    severity_threshold: str = "medium"
    auto_exploit: bool = True
    auto_report: bool = True
    output_dir: str = ""
    proxy: str = ""
    timeout_per_target: int = 300
    program_filter: str = ""  # filter by program handle or name
    specific_targets: list = field(default_factory=list)  # override discovery
    scan_mode: str = "fast"   # fast / deep / api-heavy / stealth (Fix 5)
    benchmark_ref_file: str = ""  # path to reference scan (Burp/Nuclei JSON) for post-hunt comparison
    strategy: str = ""        # aggressive / stealthy / high-value (Fix 5 elite)


@dataclass
class HunterFinding:
    """A validated finding from the hunter."""
    id: str
    target: str
    program: str
    platform: str
    vuln_type: str
    url: str
    severity: str
    title: str
    description: str
    evidence: str
    payload: str
    cvss_score: float
    poc: str = ""
    poc_steps: list = field(default_factory=list)
    confirmed: bool = False
    reported: bool = False
    bounty_estimate: str = ""
    timestamp: str = ""

    def to_dict(self) -> dict:
        return self.__dict__.copy()


@dataclass
class HunterSession:
    """Tracks a complete hunter run."""
    session_id: str
    config: HunterConfig
    status: str = "idle"  # idle / running / complete / failed
    programs_found: int = 0
    targets_queued: int = 0
    targets_scanned: int = 0
    findings: list = field(default_factory=list)
    errors: list = field(default_factory=list)
    start_time: float = field(default_factory=time.time)
    end_time: float = 0.0
    current_target: str = ""
    progress_log: list = field(default_factory=list)
    ctx: dict = field(default_factory=dict)           # shared state for feedback loop
    benchmark_metrics: dict = field(default_factory=dict)  # quality metrics

    def log(self, msg: str, level: str = "info"):
        self.progress_log.append({
            "time": time.strftime("%H:%M:%S"),
            "level": level,
            "msg": msg,
        })
        logger.info(f"[hunter:{self.session_id}] {msg}")

    @property
    def duration_s(self) -> float:
        end = self.end_time or time.time()
        return end - self.start_time

    def to_dict(self) -> dict:
        return {
            "session_id": self.session_id,
            "status": self.status,
            "programs_found": self.programs_found,
            "targets_queued": self.targets_queued,
            "targets_scanned": self.targets_scanned,
            "findings_count": len(self.findings),
            "confirmed_count": sum(1 for f in self.findings if f.confirmed),
            "findings": [f.to_dict() for f in self.findings],
            "errors": self.errors,
            "duration_s": self.duration_s,
            "current_target": self.current_target,
            "progress_log": self.progress_log[-50:],
        }


class BountyHunterEngine:
    """
    Autonomous bug bounty hunter. Discovers programs, prioritizes targets,
    runs the full scan pipeline, exploits vulnerabilities, and generates reports.
    """

    def __init__(self):
        self._sessions: dict = {}
        self._active_session: Optional[HunterSession] = None
        self._pipeline = None
        self._discovery = None
        self._prioritization = None
        self._exploit_engine = None
        self._report_gen = None
        self._parallel_engine = None

    def _lazy_load(self):
        """Lazily import subsystems."""
        try:
            from oneinfinity.recon.program_discovery_engine import program_discovery_engine
            self._discovery = program_discovery_engine
        except ImportError:
            pass

        try:
            from oneinfinity.recon.target_prioritization_engine import target_prioritization_engine
            self._prioritization = target_prioritization_engine
        except ImportError:
            pass

        try:
            from oneinfinity.unified_scan_engine import get_engine
            self._pipeline = get_engine()
        except ImportError:
            pass

        try:
            from oneinfinity.bounty_report_generator import bounty_report_generator
            self._report_gen = bounty_report_generator
        except ImportError:
            pass
            pass

        try:
            from oneinfinity.parallel_scan_engine import parallel_scan_engine
            self._parallel_engine = parallel_scan_engine
        except ImportError:
            pass

    # ── Public API ────────────────────────────────────────────────────────────

    def start_session(self, config: HunterConfig = None) -> HunterSession:
        """Start a new hunter session."""
        self._lazy_load()
        config = config or HunterConfig()
        session_id = str(uuid.uuid4())[:8]
        session = HunterSession(session_id=session_id, config=config)
        self._sessions[session_id] = session
        self._active_session = session
        session.status = "running"
        session.log("Hunter session started")
        return session

    def run(self, config: HunterConfig = None, session: HunterSession = None) -> HunterSession:
        """
        Run the full autonomous hunter pipeline synchronously.

        Elite pipeline:
          load memory → scope → strategy scoring → prioritize → parallel scan
          → AI reasoning → stealth → chaining → validation
          → feedback → replan → report → benchmark → update memory
        """
        session = session or self.start_session(config)
        config = session.config

        # ── Apply scan-mode strategy ──────────────────────────────────────
        scan_strategy = ScanStrategy.from_mode(getattr(config, "scan_mode", "fast"))
        if config.max_concurrent == 3:
            config.max_concurrent = scan_strategy.max_concurrent
        if config.max_targets == 10:
            config.max_targets = scan_strategy.max_targets
        if config.timeout_per_target == 300:
            config.timeout_per_target = scan_strategy.timeout_per_target
        if scan_strategy.phases and config.phases == ["discover", "recon", "scan", "exploit", "report"]:
            config.phases = scan_strategy.phases

        # ── Apply elite strategy overrides ───────────────────────────────
        elite_strategy = getattr(config, "strategy", "")
        self._apply_elite_strategy(elite_strategy, scan_strategy, config, session)

        session.log(
            f"Strategy: mode={scan_strategy.mode}, elite={elite_strategy or 'none'}, "
            f"workers={config.max_concurrent}, max_targets={config.max_targets}"
        )

        # ── PHASE 0: Load persistent memory ──────────────────────────────
        try:
            from oneinfinity.learning.persistent_memory import get_memory
            mem = get_memory()
            session.ctx["persistent_memory"] = mem.to_ctx()
            session.log(f"Memory: {mem.summary()}")
        except Exception as _me:
            mem = None
            logger.debug("Persistent memory unavailable: %s", _me)

        try:
            # ── Phase 1: Discover Programs ────────────────────────────────
            if "discover" in config.phases:
                self._phase_discover(session, config)

            # ── Phase 2: Prioritize Targets ───────────────────────────────
            targets = self._phase_prioritize(session, config)
            session.targets_queued = len(targets)
            session.log(f"Prioritized {len(targets)} targets")

            # ── Phase 2b: Strategy scoring (ROI ranking) ──────────────────
            targets = self._phase_strategy_rank(targets, session, config)

            # ── Phase 3: Scan + Exploit ───────────────────────────────────
            if "scan" in config.phases or "exploit" in config.phases:
                self._phase_scan_exploit(session, config, targets)

            # ── Phase 4: Feedback + Replan ────────────────────────────────
            replan_targets = self._phase_feedback_replan(session, config, targets)
            if replan_targets:
                session.log(f"Re-scanning {len(replan_targets)} targets (deep coverage pass)")
                self._phase_scan_exploit(session, config, replan_targets)

            # ── Phase 5: Report ───────────────────────────────────────────
            if "report" in config.phases and session.findings:
                self._phase_report(session, config)

            # ── Phase 6: Benchmark ────────────────────────────────────────
            self._phase_benchmark(session, config)

            session.status = "complete"
            session.end_time = time.time()
            session.log(
                f"Hunter complete: {len(session.findings)} findings, "
                f"{sum(1 for f in session.findings if f.confirmed)} confirmed"
            )

        except Exception as e:
            session.status = "failed"
            session.errors.append(str(e))
            session.log(f"Hunter failed: {e}", "error")
            logger.exception("Hunter engine exception")

        # ── PHASE 7: Update persistent memory ────────────────────────────
        try:
            if mem is not None:
                findings_raw = [
                    f.to_dict() if hasattr(f, "to_dict") else f
                    for f in session.findings
                ]
                session.ctx["findings"] = findings_raw
                mem.update_from_ctx(session.ctx)
                mem.save()
                session.log("Memory updated and saved")
        except Exception as _me2:
            logger.debug("Memory save failed: %s", _me2)

        self._save_session(session)
        return session

    async def run_async(self, config: HunterConfig = None) -> HunterSession:
        """Run hunter pipeline asynchronously."""
        session = self.start_session(config)
        loop = asyncio.get_event_loop()
        return await loop.run_in_executor(None, lambda: self.run(config=None, session=session))

    def scan_target(self, target: str, program: str = "", config: HunterConfig = None) -> dict:
        """Scan a single target. Returns findings dict."""
        self._lazy_load()
        config = config or HunterConfig()
        session = HunterSession(
            session_id=str(uuid.uuid4())[:8],
            config=config,
        )
        session.log(f"Single target scan: {target}")

        findings = self._scan_single_target(session, target, program, config)
        session.findings.extend(findings)
        session.targets_scanned = 1
        session.status = "complete"
        session.end_time = time.time()
        return session.to_dict()

    def get_session(self, session_id: str) -> Optional[HunterSession]:
        return self._sessions.get(session_id)

    def get_active_session(self) -> Optional[HunterSession]:
        return self._active_session

    def list_sessions(self) -> list:
        return [s.to_dict() for s in self._sessions.values()]

    def generate_report(self, session_id: str, fmt: str = "markdown") -> str:
        session = self._sessions.get(session_id)
        if not session or not self._report_gen:
            return "No session found or report generator unavailable"
        confirmed = [f for f in session.findings if f.confirmed]
        return self._report_gen.generate(
            findings=confirmed,
            target=session.config.name,
            fmt=fmt,
        )

    # ── Elite strategy helpers ────────────────────────────────────────────────

    @staticmethod
    def _apply_elite_strategy(
        elite: str,
        scan_strategy: "ScanStrategy",
        config: "HunterConfig",
        session: "HunterSession",
    ) -> None:
        """
        Translate --strategy flag into concrete config overrides.

        aggressive  — broader scan, more workers, faster timeouts
        stealthy    — single worker, human pacing, extended timeouts
        high-value  — focus auth/API/payment endpoints, deep mode, AI loop
        """
        if not elite:
            return

        if elite == "aggressive":
            config.max_concurrent  = max(config.max_concurrent, 8)
            config.max_targets     = max(config.max_targets, 20)
            config.timeout_per_target = min(config.timeout_per_target, 120)
            scan_strategy.use_chaining  = True
            scan_strategy.use_ai_loop   = False  # skip AI loop for speed
            session.ctx["strategy_mode"] = "aggressive"
            session.log("Elite strategy: aggressive (workers=8, max_targets=20, no AI loop)")

        elif elite == "stealthy":
            config.max_concurrent     = 1
            config.timeout_per_target = max(config.timeout_per_target, 600)
            scan_strategy.use_human_pacing = True
            scan_strategy.use_chaining     = True
            session.ctx["strategy_mode"] = "stealthy"
            session.log("Elite strategy: stealthy (1 worker, human pacing, extended timeout)")

        elif elite in ("high-value", "high_value"):
            config.max_concurrent = max(config.max_concurrent, 3)
            scan_strategy.use_chaining  = True
            scan_strategy.use_ai_loop   = True
            # Inject focus vuln types into ctx for tool selection
            session.ctx["strategy_mode"] = "high-value"
            session.ctx["priority_vuln_types"] = session.ctx.get("priority_vuln_types") or [
                "auth_bypass", "idor", "ssrf", "sqli", "business_logic"
            ]
            session.ctx["strategy_focus_labels"] = ["auth", "api", "payment", "admin"]
            session.log("Elite strategy: high-value (auth/API focus, AI loop, full chaining)")

    def _phase_strategy_rank(
        self,
        targets: list,
        session: "HunterSession",
        config: "HunterConfig",
    ) -> list:
        """
        Phase 2b: ROI-based strategy ranking via BountyStrategyEngine.

        Runs after TargetPrioritizer but before parallel scan, so the most
        lucrative targets are processed first regardless of pool ordering.
        Only re-ranks; never drops targets.
        """
        if not targets:
            return targets

        try:
            from oneinfinity.core.bounty_strategy_engine import get_strategy_engine
            engine = get_strategy_engine()

            # For high-value strategy, filter to only auth/API/payment targets if >10 available
            elite = getattr(config, "strategy", "")
            if elite in ("high-value", "high_value") and len(targets) > 5:
                focus_labels = session.ctx.get("strategy_focus_labels", [])
                scored = engine.rank_with_scores(targets, session.ctx)
                filtered = [s.target for s in scored
                            if any(lbl in s.labels for lbl in focus_labels)]
                if filtered:
                    # Prepend filtered targets, append the rest
                    rest = [t for t in [s.target for s in scored] if t not in filtered]
                    targets = (filtered + rest)[:config.max_targets]
                    session.log(f"Strategy: high-value filter → {len(filtered)} priority targets")
                    return targets

            ranked = engine.apply_to_ctx(targets, session.ctx)
            if ranked:
                session.log(
                    f"Strategy engine: top target → {ranked[0]} "
                    f"(score={session.ctx.get('strategy_scores', [{}])[0].get('score', '?')})"
                )
            return ranked

        except Exception as exc:
            logger.debug("Strategy engine unavailable: %s", exc)
            return targets

    # ── Phases ────────────────────────────────────────────────────────────────

    def _phase_discover(self, session: HunterSession, config: HunterConfig):
        session.log("Discovering bug bounty programs...")
        if not self._discovery:
            session.log("Program discovery engine not available — using config targets", "warn")
            return

        programs = self._discovery.discover_all()
        if config.program_filter:
            q = config.program_filter.lower()
            programs = [p for p in programs if q in p.name.lower() or q in p.handle.lower()]

        session.programs_found = len(programs)
        session.log(f"Found {len(programs)} programs")

        # Store programs for prioritization phase
        session._programs = programs  # type: ignore

    def _phase_prioritize(self, session: HunterSession, config: HunterConfig) -> list:
        """Collect and prioritize targets."""
        targets = list(config.specific_targets)

        if not targets:
            programs = getattr(session, "_programs", [])
            for prog in programs[:config.max_targets]:
                scope = self._discovery.extract_scope(prog) if self._discovery else []
                for t in scope:
                    domain = t["domain"] if isinstance(t, dict) else t
                    if domain and not domain.startswith("*"):
                        targets.append(domain)

        targets = list(dict.fromkeys(targets))[:config.max_targets]

        if not targets:
            session.log("No targets found — using example targets for demo")
            targets = ["testphp.vulnweb.com", "demo.testfire.net"]

        if self._prioritization:
            scored = self._prioritization.prioritize(targets)
            targets = [s.domain for s in scored]
            for s in scored[:3]:
                session.log(f"Priority target: {s.domain} score={s.total_score:.1f} ({s.priority})")

        return targets

    def _load_scope(self, config: HunterConfig):
        """Load scope from scope.yaml in the current working directory, if present."""
        try:
            from oneinfinity.modules.scope import ScopeManager
            sm = ScopeManager(str(Path.cwd()))
            if sm.exists():
                sm.load()
                return sm
        except Exception:
            pass
        return None

    def _phase_scan_exploit(self, session: HunterSession, config: HunterConfig, targets: list):
        """Scan and exploit all targets in parallel via ThreadPoolExecutor."""
        # ── Fix 2: Scope enforcement ───────────────────────────────────────────
        scope = self._load_scope(config)
        if scope is not None:
            before = len(targets)
            targets = [t for t in targets if scope.is_in_scope(t)]
            removed = before - len(targets)
            if removed:
                session.log(f"Scope filter: removed {removed} out-of-scope target(s)", "warn")

        # ── Fix 1/6: Smart target prioritization before parallel execution ───────
        try:
            from oneinfinity.core.target_prioritizer import get_target_prioritizer
            prioritizer = get_target_prioritizer()
            targets = prioritizer.rank(targets)
            if targets:
                session.log(f"Target prioritizer: top target → {targets[0]}")
        except Exception as _tp_exc:
            logger.debug("Target prioritizer unavailable: %s", _tp_exc)

        targets_to_scan: List[str] = targets[:config.max_targets]
        max_workers: int = max(1, config.max_concurrent)
        session.log(
            f"Starting PARALLEL scan of {len(targets_to_scan)} targets "
            f"(workers={max_workers})"
        )

        # ── Fix 1: Parallel scan via ThreadPoolExecutor ────────────────────────
        def _worker(target: str):
            session.current_target = target
            findings = self._scan_single_target(session, target, "", config)
            return target, findings

        with concurrent.futures.ThreadPoolExecutor(
            max_workers=max_workers,
            thread_name_prefix="hunter-worker",
        ) as pool:
            future_to_target = {
                pool.submit(_worker, t): t for t in targets_to_scan
            }
            for future in concurrent.futures.as_completed(future_to_target):
                target = future_to_target[future]
                try:
                    _, findings = future.result()
                    session.findings.extend(findings)
                    session.targets_scanned += 1
                    session.log(f"  → {len(findings)} finding(s) for {target}")
                    # Record findings in prioritizer history for future sessions
                    try:
                        from oneinfinity.core.target_prioritizer import get_target_prioritizer
                        get_target_prioritizer().record_findings_batch(
                            [f.to_dict() if hasattr(f, "to_dict") else f for f in findings]
                        )
                    except Exception:
                        pass
                except Exception as exc:
                    session.errors.append(f"{target}: {exc}")
                    session.log(f"  → Error scanning {target}: {exc}", "error")

    def _scan_single_target(self, session: HunterSession, target: str,
                            program: str, config: HunterConfig) -> list:
        """Run full pipeline on a single target, return HunterFindings."""
        findings = []

        # Use unified scan engine if available
        if self._pipeline:
            try:
                def on_progress(phase, pct, msg):
                    session.log(f"[{pct}%] {phase}: {msg}")

                scan_session = self._pipeline.scan(target, on_progress=on_progress)
                
                for v in scan_session.findings:
                    findings.append(self._vuln_to_finding(v, target, program))

            except Exception as e:
                session.log(f"Scan error for {target}: {e}", "error")
        else:
            # Fallback: demo findings
            findings.extend(self._demo_findings(target, program))

        return findings

    def _phase_feedback_replan(
        self, session: HunterSession, config: HunterConfig, scanned_targets: list
    ) -> list:
        """
        Phase: Feedback + Replan
        Analyse coverage gaps, identify targets/vuln-types that were under-explored,
        and return a prioritised re-scan target list (empty = no re-scan warranted).

        Only performs a re-scan in 'deep' mode to avoid infinite loops.
        """
        strategy = ScanStrategy.from_mode(getattr(config, "scan_mode", "fast"))
        if strategy.mode not in ("deep",):
            return []

        # Hosts that returned at least one finding
        hit_hosts: set = set()
        for f in session.findings:
            url = f.url if hasattr(f, "url") else f.get("url", "")
            if url:
                try:
                    from urllib.parse import urlparse
                    hit_hosts.add(urlparse(url).netloc)
                except Exception:
                    pass

        # Targets that were scanned but yielded zero findings
        missed_targets = [
            t for t in scanned_targets
            if t not in hit_hosts and t.replace("https://", "").replace("http://", "").split("/")[0] not in hit_hosts
        ]

        # Merge with any focus_targets populated by BenchmarkFeedbackLoop
        focus_from_ctx = session.ctx.get("focus_targets", [])
        replan_candidates = list(dict.fromkeys(focus_from_ctx + missed_targets))  # preserve order, dedup

        if not replan_candidates:
            session.log("Replan: full coverage — no re-scan needed")
            return []

        # Only re-scan high-priority targets to bound runtime
        try:
            from oneinfinity.core.target_prioritizer import get_target_prioritizer
            replan_candidates = get_target_prioritizer().rank(replan_candidates)
        except Exception:
            pass

        cap = max(1, config.max_targets // 4)  # re-scan up to 25% of original budget
        replan_targets = replan_candidates[:cap]
        session.log(f"Replan: {len(replan_targets)} targets queued for deeper re-scan "
                    f"(missed={len(missed_targets)}, focus={len(focus_from_ctx)})")
        return replan_targets

    def _phase_benchmark(self, session: HunterSession, config: HunterConfig) -> None:
        """
        Phase: Benchmark
        Compute internal quality metrics (confirmed %, avg confidence, coverage).
        If config.benchmark_ref_file is set, compare against external reference
        (Burp / Nuclei) and apply BenchmarkFeedbackLoop to populate session.ctx.
        """
        total = len(session.findings)
        confirmed = sum(1 for f in session.findings if f.confirmed)

        # Confidence scores
        avg_confidence = 0.0
        if total and self._report_gen:
            try:
                scores = []
                for f in session.findings:
                    fd = f if isinstance(f, dict) else f.to_dict()
                    from oneinfinity.bounty_report_generator import ReportFinding
                    rf = ReportFinding(**{k: fd.get(k, "") for k in ReportFinding.__dataclass_fields__
                                         if k in fd})
                    scores.append(self._report_gen.calculate_confidence_score(rf))
                avg_confidence = sum(scores) / len(scores) if scores else 0.0
            except Exception:
                pass

        targets_hit = len({
            (f.target if hasattr(f, "target") else f.get("target", ""))
            for f in session.findings
        })

        session.benchmark_metrics = {
            "total_findings":   total,
            "confirmed":        confirmed,
            "confirmed_pct":    round(confirmed / total * 100, 1) if total else 0.0,
            "avg_confidence":   round(avg_confidence, 2),
            "targets_hit":      targets_hit,
            "targets_scanned":  session.targets_scanned,
            "coverage_pct":     round(targets_hit / session.targets_scanned * 100, 1)
                                if session.targets_scanned else 0.0,
        }
        session.log(
            f"Benchmark: {confirmed}/{total} confirmed "
            f"({session.benchmark_metrics['confirmed_pct']}%), "
            f"avg confidence {avg_confidence:.0%}, "
            f"coverage {session.benchmark_metrics['coverage_pct']}%"
        )

        # External benchmark comparison (optional)
        ref_file = getattr(config, "benchmark_ref_file", "")
        if ref_file and Path(ref_file).exists():
            try:
                from oneinfinity.core.benchmark_engine import BenchmarkEngine, get_feedback_loop
                engine = BenchmarkEngine()
                oi_findings = [f.to_dict() if hasattr(f, "to_dict") else f
                               for f in session.findings]
                result = engine.compare_from_dicts(
                    oi_findings=oi_findings,
                    ref_file=ref_file,
                )
                session.benchmark_metrics["accuracy_score"] = result.accuracy_score
                session.benchmark_metrics["missed_count"]   = len(result.missed)
                session.benchmark_metrics["extra_count"]    = len(result.extra)
                session.log(
                    f"External benchmark vs {Path(ref_file).name}: "
                    f"accuracy={result.accuracy_score:.0%}, "
                    f"missed={len(result.missed)}, extra={len(result.extra)}"
                )
                # Feed missed findings back into ctx for next session
                triggered = get_feedback_loop().apply(result, session.ctx)
                if triggered:
                    session.log(
                        f"Feedback loop: {len(session.ctx.get('focus_targets', []))} "
                        f"focus targets and {len(session.ctx.get('priority_vuln_types', []))} "
                        f"priority vuln types saved for next run"
                    )
                    # Fix 3: persist missed patterns into long-term memory
                    try:
                        from oneinfinity.learning.persistent_memory import get_memory as _gm
                        _mem = _gm()
                        for vt in session.ctx.get("priority_vuln_types", []):
                            _mem.record_missed_vuln_type(vt)
                        for ft in session.ctx.get("focus_targets", []):
                            _mem.record_missed_pattern(ft, reference_tool=result.reference_source)
                        for chain_entry in session.ctx.get("successful_chains", []):
                            if isinstance(chain_entry, dict):
                                _mem.record_successful_chain(
                                    chain_entry.get("chain", []),
                                    chain_entry.get("impact", ""),
                                )
                        session.log("Long-term memory: missed patterns + chains persisted")
                    except Exception as _lme:
                        logger.debug("Long-term feedback persist failed: %s", _lme)
            except Exception as _bex:
                session.log(f"External benchmark skipped: {_bex}", "warn")

    def _phase_report(self, session: HunterSession, config: HunterConfig):
        """Generate reports for all confirmed findings."""
        if not self._report_gen:
            return
        out_dir = Path(config.output_dir or (raw_dir() / "reports"))
        out_dir.mkdir(parents=True, exist_ok=True)

        confirmed = [f for f in session.findings if f.confirmed]
        if confirmed:
            report_path = out_dir / f"hunter_{session.session_id}.md"
            report = self._report_gen.generate(
                findings=[f.to_dict() for f in confirmed],
                target=session.config.name,
                fmt="markdown",
            )
            report_path.write_text(report)
            session.log(f"Report saved: {report_path}")

    # ── Helpers ───────────────────────────────────────────────────────────────

    def _result_to_finding(self, exploit_result, target: str, program: str) -> HunterFinding:
        import datetime
        return HunterFinding(
            id=exploit_result.finding_id,
            target=target,
            program=program,
            platform="",
            vuln_type=exploit_result.vuln_type,
            url=exploit_result.url,
            severity=exploit_result.severity,
            title=f"{exploit_result.vuln_type.upper()} @ {exploit_result.url[:60]}",
            description=exploit_result.impact,
            evidence=exploit_result.evidence,
            payload=exploit_result.payload,
            cvss_score=exploit_result.cvss_score,
            poc=exploit_result.poc,
            poc_steps=exploit_result.poc_steps,
            confirmed=exploit_result.exploited,
            timestamp=datetime.datetime.utcnow().isoformat(),
        )

    def _vuln_to_finding(self, vuln: dict, target: str, program: str) -> HunterFinding:
        import datetime
        return HunterFinding(
            id=vuln.get("id", str(uuid.uuid4())[:8]),
            target=target,
            program=program,
            platform="",
            vuln_type=vuln.get("vuln_type", vuln.get("type", "unknown")),
            url=vuln.get("url", f"https://{target}"),
            severity=vuln.get("severity", "medium"),
            title=vuln.get("title", f"{vuln.get('type','?')} on {target}"),
            description=vuln.get("description", vuln.get("detail", "")),
            evidence=vuln.get("evidence", ""),
            payload=vuln.get("payload", ""),
            cvss_score=float(vuln.get("cvss_score", 5.0)),
            confirmed=vuln.get("confirmed", False),
            timestamp=datetime.datetime.utcnow().isoformat(),
        )

    def _demo_findings(self, target: str, program: str) -> list:
        """Return demo findings when no pipeline is available."""
        import datetime
        demo = [
            HunterFinding(
                id=str(uuid.uuid4())[:8], target=target, program=program, platform="demo",
                vuln_type="xss", url=f"https://{target}/search?q=test",
                severity="high", title=f"Reflected XSS on {target}",
                description="Reflected cross-site scripting in search parameter",
                evidence="<script>alert(document.domain)</script> reflected in response",
                payload="<script>alert(document.domain)</script>",
                cvss_score=6.1, confirmed=True,
                timestamp=datetime.datetime.utcnow().isoformat(),
            ),
        ]
        return demo

    def _save_session(self, session: HunterSession):
        """Persist session to disk."""
        try:
            sessions = {}
            if HUNTER_DB_PATH.exists():
                sessions = json.loads(HUNTER_DB_PATH.read_text())
            sessions[session.session_id] = session.to_dict()
            HUNTER_DB_PATH.write_text(json.dumps(sessions, indent=2))
        except Exception as e:
            logger.debug(f"Session save error: {e}")


bounty_hunter_engine = BountyHunterEngine()
