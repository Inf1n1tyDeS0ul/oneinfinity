"""Central orchestrator — runs all 6 phases in sequence."""

import sys
import time
import threading
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from typing import Optional

from oneinfinity.modules.utils import banner, section, ok, info, warn, err, bold, cyan, now_str
from oneinfinity.path_manager import findings_db_path, resolve_output_dir


# ── Rate limiter ──────────────────────────────────────────────────────────────

class RateLimiter:
    """Token-bucket rate limiter (requests/minute)."""

    def __init__(self, rpm: int = 30):
        self.rpm = rpm
        self._lock = threading.Lock()
        self._tokens = rpm
        self._last_refill = time.time()

    def wait(self):
        with self._lock:
            now = time.time()
            elapsed = now - self._last_refill
            if elapsed >= 60:
                self._tokens = self.rpm
                self._last_refill = now
            if self._tokens <= 0:
                sleep_time = 60 - elapsed
                time.sleep(max(0, sleep_time))
                self._tokens = self.rpm
                self._last_refill = time.time()
            self._tokens -= 1


# ── Phase result ──────────────────────────────────────────────────────────────

@dataclass
class PhaseResult:
    phase: int
    name: str
    success: bool
    duration: float = 0.0
    data: object = None
    error: str = ""


@dataclass
class RunSummary:
    target: str
    session_id: int
    phases: list[PhaseResult] = field(default_factory=list)
    total_duration: float = 0.0
    candidates: int = 0
    findings: int = 0
    reports: list[str] = field(default_factory=list)


# ── Orchestrator ──────────────────────────────────────────────────────────────

class FrameworkOrchestrator:
    def __init__(self, program_dir: str, target: str, options: dict = None):
        self.program_dir = Path(program_dir)
        self.target = target
        self.opts = options or {}

        # Resolve DB path
        db_path = str(findings_db_path())
        from oneinfinity_framework.db_ext import ExtendedDB
        self.db = ExtendedDB(db_path)

        # Rate limiter
        rpm = self.opts.get("rate", 30)
        try:
            rpm = int(str(rpm).split("/")[0])
        except (ValueError, TypeError):
            rpm = 30
        self.rate_limiter = RateLimiter(rpm)

    def run(self, phases: str = "1-6", resume: bool = False) -> RunSummary:
        phase_range = self._parse_phase_range(phases)
        t_start = time.time()

        banner(f"Autonomous Security Framework — {self.target}")
        info(f"Phases     : {phases}")
        info(f"Program dir: {self.program_dir}")
        info(f"Rate limit : {self.opts.get('rate', 30)} req/min")
        if self.opts.get("oob_url"):
            info(f"OOB URL    : {self.opts['oob_url']}")
        print()

        # Session management
        session_id = self._resolve_session(resume)
        summary = RunSummary(target=self.target, session_id=session_id)

        # ── Phase runners ──────────────────────────────────────────────────────
        auth_record = None
        recon_result = None
        surface_result = None
        candidates = []

        # Phase 1 — Authorization
        if 1 in phase_range:
            result = self._run_phase(1, "Authorization", lambda: self._phase_auth())
            summary.phases.append(result)
            if not result.success:
                err("Authorization failed — aborting all subsequent phases.")
                self._finalize(summary, t_start)
                return summary
            auth_record = result.data
            self.db.update_session(session_id,
                                   auth_type=auth_record.auth_type,
                                   auth_ref=auth_record.auth_ref,
                                   phase_reached=1)

        # Phase 2 — Recon
        if 2 in phase_range:
            result = self._run_phase(2, "Reconnaissance", lambda: self._phase_recon(session_id))
            summary.phases.append(result)
            if result.success:
                recon_result = result.data

        # Phase 3 — Surface mapping
        # If HTTP probe found no alive hosts, fall back to probing the root target + subdomains
        if 3 in phase_range:
            alive_hosts = recon_result.alive_hosts if recon_result else []
            if not alive_hosts and recon_result:
                from oneinfinity_framework.recon_engine import HostInfo
                # Seed with root target and discovered subdomains (unprobed)
                seed_hosts = [self.target] + recon_result.subdomains[:20]
                alive_hosts = [HostInfo(host=h, url=f"https://{h}") for h in seed_hosts]
                info(f"HTTP probe returned 0 results — seeding Phase 3 with {len(alive_hosts)} hosts from recon")
            result = self._run_phase(3, "Surface Mapping",
                                     lambda: self._phase_surface(alive_hosts, session_id))
            summary.phases.append(result)
            if result.success:
                surface_result = result.data

        # Phase 4 — Vuln scanning
        # If endpoint discovery yielded nothing, seed with root target
        if 4 in phase_range:
            if surface_result and not surface_result.endpoints:
                from oneinfinity_framework.recon_engine import HostInfo
                surface_result.endpoints = [f"https://{self.target}/"]
                if not surface_result.alive_hosts:
                    surface_result.alive_hosts = [
                        HostInfo(host=self.target, url=f"https://{self.target}")
                    ]
            result = self._run_phase(4, "Vulnerability Discovery",
                                     lambda: self._phase_scan(surface_result, session_id))
            summary.phases.append(result)
            if result.success:
                candidates = result.data or []
                summary.candidates = len(candidates)

        # Phase 5 — Validation
        if 5 in phase_range and not self.opts.get("no_validate"):
            result = self._run_phase(5, "PoC Validation",
                                     lambda: self._phase_validate(candidates, session_id))
            summary.phases.append(result)
            if result.success:
                summary.findings = len(result.data or [])

        # Phase 6 — Reporting
        if 6 in phase_range:
            result = self._run_phase(6, "Report Generation",
                                     lambda: self._phase_report(session_id))
            summary.phases.append(result)
            if result.success:
                summary.reports = result.data or []

        self._finalize(summary, t_start)
        return summary

    # ── Phase implementations ─────────────────────────────────────────────────

    def _phase_auth(self):
        from oneinfinity_framework.auth import AuthEnforcer
        enforcer = AuthEnforcer(str(self.program_dir))
        auth_type = self.opts.get("auth_type", "scope_yaml")
        auth_ref = self.opts.get("auth_ref", "")
        return enforcer.verify(self.target, auth_type, auth_ref)

    def _phase_recon(self, session_id: int):
        from oneinfinity_framework.recon_engine import ReconEngine
        engine = ReconEngine(str(self.program_dir), self.db, self.rate_limiter)
        return engine.run(self.target, session_id)

    def _phase_surface(self, alive_hosts, session_id: int):
        from oneinfinity_framework.surface import SurfaceMapper
        mapper = SurfaceMapper(str(self.program_dir), self.db, self.rate_limiter)
        return mapper.run(alive_hosts, session_id)

    def _phase_scan(self, surface_result, session_id: int):
        from oneinfinity_framework.vuln_scanner import VulnScanner
        scanner = VulnScanner(
            str(self.program_dir), self.db, session_id,
            self.rate_limiter, self.opts.get("oob_url", "")
        )
        return scanner.run(surface_result, session_id)

    def _phase_validate(self, candidates, session_id: int):
        # Determine if full PoC mode is authorized
        full_poc = self._is_pentest_authorized()
        from oneinfinity_framework.validator import VulnValidator
        validator = VulnValidator(
            str(self.program_dir), self.db, session_id,
            full_poc_mode=full_poc,
            oob_url=self.opts.get("oob_url", ""),
        )
        # Convert VulnCandidate objects to dicts if needed
        cand_dicts = []
        for c in candidates:
            if hasattr(c, "__dict__"):
                cand_dicts.append(vars(c))
            elif isinstance(c, dict):
                cand_dicts.append(c)
        return validator.run(cand_dicts, session_id)

    def _phase_report(self, session_id: int) -> list[str]:
        from oneinfinity.modules.scope import ScopeManager
        sm = ScopeManager(str(self.program_dir))
        platform = "Private"
        if sm.exists():
            sm.load()
            platform = sm.platform or "Private"

        from oneinfinity.modules.reporter import ReportGenerator
        reports_dir = str(resolve_output_dir(self.program_dir / "reports"))
        gen = ReportGenerator(reports_dir=reports_dir, platform=platform)

        # Generate reports for all verified findings in this session
        findings = self.db.all(status="verified")
        report_files = []
        for f in findings:
            try:
                path = gen.from_finding(f)
                if path:
                    report_files.append(path)
            except Exception as e:
                warn(f"Report generation failed for finding #{f.get('id')}: {e}")
        return report_files

    # ── Phase wrapper ─────────────────────────────────────────────────────────

    def _run_phase(self, n: int, name: str, fn) -> PhaseResult:
        self._print_phase_banner(n, name)
        t0 = time.time()
        try:
            data = fn()
            duration = time.time() - t0
            ok(f"Phase {n} ({name}) completed in {duration:.1f}s")
            return PhaseResult(phase=n, name=name, success=True,
                               duration=duration, data=data)
        except SystemExit:
            raise
        except Exception as e:
            duration = time.time() - t0
            err(f"Phase {n} ({name}) failed: {e}")
            return PhaseResult(phase=n, name=name, success=False,
                               duration=duration, error=str(e))

    def _print_phase_banner(self, n: int, name: str):
        width = 60
        line = "─" * width
        print(f"\n{cyan(line)}")
        print(f"  {bold(f'[Phase {n}/6] {name}')}")
        print(f"{cyan(line)}\n")

    def _print_summary(self, summary: RunSummary):
        banner("Run Summary")
        info(f"Target      : {summary.target}")
        info(f"Session ID  : {summary.session_id}")
        info(f"Duration    : {summary.total_duration:.1f}s")
        info(f"Candidates  : {summary.candidates}")
        info(f"Findings    : {summary.findings}")

        section("Phase Results")
        for pr in summary.phases:
            status = "✓" if pr.success else "✗"
            color = ok if pr.success else err
            msg = f"Phase {pr.phase} — {pr.name}: {status} ({pr.duration:.1f}s)"
            if pr.error:
                msg += f" [{pr.error[:60]}]"
            if pr.success:
                print(f"  {bold('[+]')} {msg}")
            else:
                print(f"  [✗] {msg}")

        if summary.reports:
            section("Reports Generated")
            for r in summary.reports:
                ok(r)

        print()
        info("Run: oneinfinity findings   — to review all findings")
        info("Run: oneinfinity findings stats — for statistics")
        print()

    # ── Helpers ───────────────────────────────────────────────────────────────

    def _resolve_session(self, resume: bool) -> int:
        if resume:
            last = self.db.last_session(self.target)
            if last:
                info(f"Resuming session #{last['id']} "
                     f"(reached phase {last['phase_reached']})")
                self.db.update_session(last["id"], status="running")
                return last["id"]
            warn("No previous session found — starting fresh.")
        sid = self.db.new_session(self.target, "", "")
        info(f"Session ID: {sid}")
        return sid

    def _finalize(self, summary: RunSummary, t_start: float):
        summary.total_duration = time.time() - t_start
        status = "completed" if all(p.success for p in summary.phases) else "failed"
        self.db.update_session(
            summary.session_id,
            status=status,
            completed_at=now_str(),
        )
        self._print_summary(summary)
        self.db.close()

    def _is_pentest_authorized(self) -> bool:
        try:
            from oneinfinity.modules.scope import ScopeManager
            sm = ScopeManager(str(self.program_dir))
            if sm.exists():
                sm.load()
                if sm.is_pentest():
                    return bool(sm._data.get("engagement", {}).get("authorized", False))
        except Exception:
            pass
        return False

    @staticmethod
    def _parse_phase_range(phases: str) -> set[int]:
        """Parse '1-6', '2', '3-5', etc. into a set of phase numbers."""
        phases = str(phases).strip()
        if "-" in phases:
            parts = phases.split("-", 1)
            try:
                start, end = int(parts[0]), int(parts[1])
                return set(range(start, end + 1))
            except ValueError:
                pass
        try:
            return {int(phases)}
        except ValueError:
            return set(range(1, 7))
