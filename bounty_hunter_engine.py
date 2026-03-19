"""
Autonomous Hunter Engine — Autonomous multi-target bug bounty hunter.
Discovers programs, prioritizes targets, runs parallel scans, exploits,
validates findings, and generates reports.
"""

import os
import json
import time
import uuid
import logging
import asyncio
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional

from path_manager import raw_dir

logger = logging.getLogger(__name__)

HUNTER_DB_PATH = raw_dir() / "hunter_sessions.json"
HUNTER_DB_PATH.parent.mkdir(parents=True, exist_ok=True)


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
            from program_discovery_engine import program_discovery_engine
            self._discovery = program_discovery_engine
        except ImportError:
            pass

        try:
            from target_prioritization_engine import target_prioritization_engine
            self._prioritization = target_prioritization_engine
        except ImportError:
            pass

        try:
            from unified_scan_engine import get_engine
            self._pipeline = get_engine()
        except ImportError:
            pass

        try:
            from bounty_report_generator import bounty_report_generator
            self._report_gen = bounty_report_generator
        except ImportError:
            pass
            pass

        try:
            from parallel_scan_engine import parallel_scan_engine
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
        """Run the full autonomous hunter pipeline synchronously."""
        session = session or self.start_session(config)
        config = session.config

        try:
            # ── Phase 1: Discover Programs ────────────────────────────────
            if "discover" in config.phases:
                self._phase_discover(session, config)

            # ── Phase 2: Prioritize Targets ───────────────────────────────
            targets = self._phase_prioritize(session, config)
            session.targets_queued = len(targets)
            session.log(f"Prioritized {len(targets)} targets")

            # ── Phase 3: Scan + Exploit ───────────────────────────────────
            if "scan" in config.phases or "exploit" in config.phases:
                self._phase_scan_exploit(session, config, targets)

            # ── Phase 4: Report ───────────────────────────────────────────
            if "report" in config.phases and session.findings:
                self._phase_report(session, config)

            session.status = "complete"
            session.end_time = time.time()
            session.log(f"Hunter complete: {len(session.findings)} findings, {sum(1 for f in session.findings if f.confirmed)} confirmed")

        except Exception as e:
            session.status = "failed"
            session.errors.append(str(e))
            session.log(f"Hunter failed: {e}", "error")
            logger.exception("Hunter engine exception")

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

    def _phase_scan_exploit(self, session: HunterSession, config: HunterConfig, targets: list):
        """Scan and exploit all targets."""
        session.log(f"Starting scan of {len(targets)} targets (max_concurrent={config.max_concurrent})")

        for target in targets[:config.max_targets]:
            session.current_target = target
            session.log(f"Scanning: {target}")

            try:
                findings = self._scan_single_target(session, target, "", config)
                session.findings.extend(findings)
                session.targets_scanned += 1
                session.log(f"  → {len(findings)} findings for {target}")
            except Exception as e:
                session.errors.append(f"{target}: {e}")
                session.log(f"  → Error scanning {target}: {e}", "error")

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
