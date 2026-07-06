"""
god_mode_engine.py — GOD MODE orchestration for OneInfinity.

Sequences every capability in an adaptive cascade:
  Stage 1: Foundation (doctor + adaptive-recon + analyze-app) — blocking
  Stage 2: FullScanMission starts in a daemon thread
  Stage 3: Event-driven unlocking (research, swarm, chains) via event bus
  Stage 4: Convergence loop — exits on time/cap/convergence/stop
  Stage 5: ReportMission — always runs (finalization)
"""
from __future__ import annotations

import json
import logging
import os
import subprocess
import sys
import threading
import time
import uuid
from abc import ABC, abstractmethod
from dataclasses import dataclass, field, asdict
from pathlib import Path
from typing import Any, Optional

log = logging.getLogger("oneinfinity.god_mode")

# ── Constants ──────────────────────────────────────────────────────────────────

GOD_MODE_DIR = Path.home() / ".oneinfinity"
GOD_MODE_LOG_DIR = GOD_MODE_DIR / "logs"
CONVERGENCE_EMPTY_ITERS_REQUIRED = 2   # 2 consecutive research iters with 0 new findings
EVENT_UNLOCK_VULN_THRESHOLD = 1        # Reduced from 3 — unlock Research earlier in God Mode
EVENT_UNLOCK_ENDPOINT_THRESHOLD = 5   # Reduced from 10 — unlock Swarm earlier in God Mode



def _is_ai_target(target: str, app_context: str, recon) -> bool:
    """Return True if the target appears to be an AI/LLM/chatbot endpoint."""
    _AI_KEYWORDS = (
        "/v1/chat", "/api/chat", "completions", "llm", "chatbot",
        "openai", "anthropic", "ollama", "gemini", "/inference",
        "/generate", "/ai/", "gpt", "claude",
    )
    combined = (target + " " + app_context).lower()
    if any(k in combined for k in _AI_KEYWORDS):
        return True
    if recon and hasattr(recon, "api_map") and recon.api_map:
        for ep in (getattr(recon.api_map, "endpoints", []) or []):
            if any(k in str(ep).lower() for k in _AI_KEYWORDS):
                return True
    return False


def _run_nim_stealth_prober(
    target: str,
    waf_vendor: str,
    timeout_ms: int = 8000,
    scan_id: str | None = None,
) -> list[dict]:
    """
    Run the Nim stealth_prober binary to discover WAF bypass techniques.
    Called by FoundationMission Step 4d when Cloudflare or Akamai is detected.

    Returns list of finding dicts from the prober; empty if binary unavailable.
    """
    import json as _json
    import shutil as _shutil
    import subprocess as _subprocess
    from pathlib import Path as _Path

    # Binary resolution: src/nim/bin/ → ~/.local/bin/ → PATH
    _here = _Path(__file__).parent
    _repo_root = _here.parent.parent
    _local = _repo_root / "src" / "nim" / "bin" / "stealth_prober"
    if not (_local.is_file() and os.access(str(_local), os.X_OK)):
        _found = _shutil.which("stealth_prober")
        _local_bin = _Path.home() / ".local" / "bin" / "stealth_prober"
        if _found:
            _local = _Path(_found)
        elif _local_bin.is_file() and os.access(str(_local_bin), os.X_OK):
            _local = _local_bin
        else:
            log.debug("[god_mode] Nim stealth_prober binary not found — skipping")
            return []

    _sid = scan_id or uuid.uuid4().hex[:16]
    _cmd = [
        str(_local),
        "--target", target if target.startswith("http") else f"https://{target}",
        "--waf", waf_vendor,
        "--timeout", str(timeout_ms),
        "--scan-id", _sid,
        "--concurrency", "5",
        "--jitter", "200",
    ]

    _findings: list[dict] = []
    try:
        _proc = _subprocess.run(
            _cmd,
            capture_output=True, text=True,
            timeout=max(timeout_ms // 1000 + 15, 30),
        )
        for _line in _proc.stdout.splitlines():
            _line = _line.strip()
            if not _line:
                continue
            try:
                _f = _json.loads(_line)
                _f.setdefault("source_type", "nim")
                _f.setdefault("tool", "nim:stealth_prober")
                _findings.append(_f)
            except _json.JSONDecodeError:
                pass
    except _subprocess.TimeoutExpired:
        log.debug("[god_mode] Nim stealth_prober timed out")
    except OSError as _exc:
        log.debug("[god_mode] Nim stealth_prober subprocess error: %s", _exc)
    return _findings


class FoundationError(RuntimeError):
    """Raised when doctor --quick fails. Only hard-abort in GOD MODE."""




# ── GodModeSession ─────────────────────────────────────────────────────────────

@dataclass
class GodModeSession:
    scan_id: str
    target: str
    start_time: float
    phases_complete: list = field(default_factory=list)
    finding_count: int = 0
    missions: dict = field(default_factory=dict)   # name → status str
    terminated_by: Optional[str] = None            # "convergence"|"stop"|"error"
    log_path: str = ""
    background: bool = False
    auth_config: dict = field(default_factory=dict)
    app_context: str = ""
    max_time: int = 0
    max_findings: int = 0
    # WAF bypass state — populated by FoundationMission Step 4, consumed by all missions
    waf_vendor: str = ""                              # "cloudflare"|"akamai"|"aws_waf"|...
    waf_bypass_payloads: dict = field(default_factory=dict)  # {vuln_type: [bypass_payloads]}
    _lock: threading.Lock = field(default_factory=threading.Lock, repr=False, compare=False)

    def add_findings(self, count: int) -> None:
        """Thread-safe increment of finding_count."""
        with self._lock:
            self.finding_count += count

    def elapsed(self) -> float:
        return time.time() - self.start_time


# ── GodModeStateFile ───────────────────────────────────────────────────────────

class GodModeStateFile:
    """Persists GodModeSession to ~/.oneinfinity/god-mode-<scan_id>.json."""

    def __init__(self, scan_id: str):
        GOD_MODE_DIR.mkdir(parents=True, exist_ok=True)
        self.path = GOD_MODE_DIR / f"god-mode-{scan_id}.json"

    def write(self, session: GodModeSession) -> None:
        db_ok = self._persist_to_db(session)
        if not db_ok:
            # DBManager unavailable — JSON is the only persistence path
            log.warning(
                "FALLBACK TRIGGERED: DBManager unavailable — writing JSON only for scan %s",
                session.scan_id,
            )
        # JSON is always written as cache for status() reads and backward compat
        self._write_json(session)

    def _persist_to_db(self, session: GodModeSession) -> bool:
        """Write scan metadata to DBManager. Returns True on success, times out in 8s."""
        try:
            import concurrent.futures as _cf
            with _cf.ThreadPoolExecutor(max_workers=1, thread_name_prefix="gm-persist") as _ex:
                return _ex.submit(self._persist_to_db_blocking, session).result(timeout=8)
        except Exception as exc:
            log.debug("_persist_to_db failed: %s", exc)
            return False

    def _persist_to_db_blocking(self, session: GodModeSession) -> bool:
        """Inner blocking DB write — runs in a dedicated thread with its own event loop."""
        try:
            from oneinfinity.core.db_manager import get_db_manager_sync
            mgr = get_db_manager_sync()
            if mgr is None:
                return False
            scan_dict = {
                "scan_id":          session.scan_id,
                "id":               session.scan_id,
                "target":           session.target,
                "scan_type":        "god_mode",
                "status":           "completed" if session.terminated_by else "running",
                "started_at":       str(session.start_time),
                "finding_count":    session.finding_count,
                "phases_complete":  session.phases_complete,
                "missions":         session.missions,
                "terminated_by":    session.terminated_by,
            }
            mgr.sync_save_scan(scan_dict)
            return True
        except Exception as exc:
            log.debug("_persist_to_db_blocking failed: %s", exc, exc_info=True)
            return False

    def _write_json(self, session: GodModeSession) -> None:
        try:
            import dataclasses as _dc
            # Exclude non-serializable fields (threading.Lock, etc.)
            _skip = {"_lock"}
            data = {f.name: getattr(session, f.name) for f in _dc.fields(session) if f.name not in _skip}
            data["elapsed_seconds"] = round(session.elapsed(), 1)
            tmp = self.path.with_suffix(".tmp")
            tmp.write_text(json.dumps(data, indent=2, default=str))
            tmp.replace(self.path)   # atomic on POSIX
        except Exception as exc:
            log.warning("State file write failed (non-fatal): %s", exc)

    def read(self) -> Optional[dict]:
        try:
            return json.loads(self.path.read_text())
        except FileNotFoundError:
            return None
        except Exception as exc:
            log.warning("State file read failed: %s", exc)
            return None

    @staticmethod
    def find_latest() -> Optional[Path]:
        """Return the most recently modified god-mode state file, or None."""
        GOD_MODE_DIR.mkdir(parents=True, exist_ok=True)
        files = sorted(GOD_MODE_DIR.glob("god-mode-*.json"), key=lambda p: p.stat().st_mtime, reverse=True)
        return files[0] if files else None

    @staticmethod
    def stop_sentinel_path(scan_id: str) -> Path:
        return GOD_MODE_DIR / f"god-mode-{scan_id}.stop"


# ── ConvergenceChecker ─────────────────────────────────────────────────────────

class ConvergenceChecker:
    """
    Fires convergence when:
      - 2 consecutive research iterations each produced 0 new findings, AND
      - CapabilityMap shows all known vuln classes are covered in current findings.
    """

    def __init__(self):
        self._last_finding_count: int = 0
        self.research_iters_with_no_new: int = 0
        self._lock = threading.Lock()

    def record_research_iteration(self, current_finding_count: int) -> None:
        """Call after each research iteration completes."""
        with self._lock:
            delta = current_finding_count - self._last_finding_count
            if delta == 0:
                self.research_iters_with_no_new += 1
            else:
                self.research_iters_with_no_new = 0
            self._last_finding_count = current_finding_count

    def is_converged(self, finding_vuln_types: list[str]) -> bool:
        """
        Return True when 2+ consecutive empty research iters AND
        all known vuln classes appear in finding_vuln_types.
        If CapabilityMap unavailable, skip the coverage check.
        """
        with self._lock:
            if self.research_iters_with_no_new < CONVERGENCE_EMPTY_ITERS_REQUIRED:
                return False
        # If no vuln types specified, convergence is just based on empty iters
        if not finding_vuln_types:
            return True
        try:
            from oneinfinity.modules.capability_map import CapabilityMap, Vuln
            all_classes = {v for k, v in vars(Vuln).items() if not k.startswith("_") and isinstance(v, str)}
            covered = set(finding_vuln_types)
            return all_classes.issubset(covered)
        except Exception:
            # If capmap unavailable, convergence is just based on empty iters
            return True

# ── Mission base class ─────────────────────────────────────────────────────────

class Mission(ABC):
    """
    Base class for all GOD MODE missions.
    Each mission wraps one engine and runs in a daemon thread.
    """

    def __init__(self, name: str):
        self.name = name
        self.status: str = "pending"    # pending|running|done|failed
        self._thread: Optional[threading.Thread] = None
        self._result: dict = {}
        self._stop_event = threading.Event()

    def start(self, session: GodModeSession) -> None:
        """Start the mission in a daemon thread."""
        self.status = "running"
        self._thread = threading.Thread(
            target=self._safe_run,
            args=(session,),
            name=f"god-mode-{self.name}",
            daemon=False,
        )
        self._thread.start()

    def stop(self) -> None:
        self._stop_event.set()

    def is_done(self) -> bool:
        return self.status in ("done", "failed")

    def result(self) -> dict:
        return dict(self._result)

    def _safe_run(self, session: GodModeSession) -> None:
        try:
            self._run(session)
            self.status = "done"
        except FoundationError:
            self.status = "failed"
            raise   # FoundationError propagates — it's the one hard abort
        except Exception as exc:
            log.warning("Mission '%s' failed (non-fatal): %s", self.name, exc, exc_info=True)
            self.status = "failed"

    @abstractmethod
    def _run(self, session: GodModeSession) -> None:
        """Override in each concrete mission."""


# ── FoundationMission ──────────────────────────────────────────────────────────

class FoundationMission(Mission):
    """
    Stage 1 — runs synchronously before any threads start.
    Steps: doctor --quick → adaptive-recon → analyze-app.
    doctor failure → hard abort (FoundationError).
    recon/analyze failures → warn + continue.
    """

    def __init__(self):
        super().__init__("foundation")
        self.recon = None       # ReconIntelligence from AdaptiveReconEngine
        self.app_model = None   # AppModel from ApplicationIntelligenceEngine

    def run_sync(self, session: GodModeSession) -> None:
        """Run foundation synchronously (called from conductor, not in thread)."""
        log.info("[GOD MODE] Stage 1: Foundation starting for %s", session.target)
        self.status = "running"
        try:
            self._run(session)
            self.status = "done"
        except FoundationError:
            self.status = "failed"
            raise

    def _run(self, session: GodModeSession) -> None:
        # ── Step 1: doctor --quick ─────────────────────────────────────────
        log.info("[GOD MODE] Foundation Step 1: doctor --quick")
        try:
            import asyncio as _asyncio
            from oneinfinity.core.doctor import DoctorOrchestrator
            _ws = os.getcwd()
            _report = _asyncio.run(DoctorOrchestrator(_ws).run(quick=True))
            _score = _report.get("score", 10.0) if isinstance(_report, dict) else _report.score
            if _score < 9.0:
                raise FoundationError(
                    f"Doctor score {_score:.1f}/10.0 — fix environment before GOD MODE (minimum 9.0 required)"
                )
            if _score < 10.0:
                log.warning("[GOD MODE] Doctor: %.1f/10.0 — Proceeding with caution", _score)
            else:
                log.info("[GOD MODE] Doctor: %.1f/10.0 — OK", _score)
        except FoundationError:
            raise
        except Exception as exc:
            raise FoundationError(f"Doctor check failed: {exc}") from exc

        # ── Step 2: adaptive-recon --depth deep ───────────────────────────
        log.info("[GOD MODE] Foundation Step 2: adaptive-recon --depth deep")
        try:
            from oneinfinity.recon.adaptive_recon_engine import AdaptiveReconEngine
            recon_out = str(GOD_MODE_DIR / session.scan_id / "recon")
            self.recon = AdaptiveReconEngine(session.target, output_dir=recon_out, depth="deep").run()
            log.info("[GOD MODE] Recon complete — subdomains=%s apis=%s",
                     len(getattr(self.recon, "subdomains", []) or []),
                     len(getattr(getattr(self.recon, "api_map", None), "endpoints", []) or []))
        except Exception as exc:
            log.warning("[GOD MODE] Recon failed (non-fatal): %s — continuing with less intel", exc, exc_info=True)
            self.recon = None

        # ── Step 3: analyze-app ───────────────────────────────────────────
        log.info("[GOD MODE] Foundation Step 3: analyze-app")
        try:
            from oneinfinity.intelligence.application_intelligence import ApplicationIntelligenceEngine
            tech_profile = None
            if self.recon and hasattr(self.recon, "tech_profile"):
                tech_profile = vars(self.recon.tech_profile) if self.recon.tech_profile else None
            _aie = ApplicationIntelligenceEngine(session.target)
            self.app_model = _aie.analyze_application_structure(tech_profile=tech_profile)
            log.info("[GOD MODE] App model built — endpoints=%s auth_flows=%s",
                     len(getattr(self.app_model, "api_endpoints", []) or []),
                     len(getattr(self.app_model, "auth_flows", []) or []))
        except Exception as exc:
            log.warning("[GOD MODE] App analysis failed (non-fatal): %s — continuing", exc, exc_info=True)
            self.app_model = None

        # ── Step 3a: Target Discovery Engine ─────────────────────────────
        log.info("[GOD MODE] Foundation Step 3a: TargetDiscoveryEngine")
        try:
            from oneinfinity.recon.target_discovery_engine import TargetDiscoveryEngine
            _domain = session.target.split("/")[0]
            _tde = TargetDiscoveryEngine()
            _discovered_targets = _tde.discover_all(seed_domains=[_domain])
            log.info("[GOD MODE] TargetDiscovery: %d targets discovered", len(_discovered_targets))
            # Merge new subdomains back into recon intel if available
            if self.recon and _discovered_targets:
                _existing_subs = set(getattr(self.recon, "subdomains", []) or [])
                _new_subs = [t.domain for t in _discovered_targets if t.domain not in _existing_subs]
                if _new_subs:
                    self.recon.subdomains = list(_existing_subs) + _new_subs
            # Emit endpoints to bus
            try:
                from oneinfinity.orchestration.event_bus import get_bus, EventType
                for _dt in (_discovered_targets or []):
                    get_bus().publish(EventType.NEW_ENDPOINT, {
                        "url": _dt.domain,
                        "source": f"target_discovery/{_dt.source}",
                        "target": session.target,
                        "confidence": _dt.confidence,
                    }, source="target_discovery_engine")
            except Exception:
                pass
        except Exception as exc:
            log.warning("[GOD MODE] TargetDiscoveryEngine failed (non-fatal): %s", exc, exc_info=True)

        # ── Step 3b: GitHub Secrets Scanner ──────────────────────────────
        # Skip entirely when no real GitHub token is configured — running without
        # a token consumes the 60 req/hr anonymous quota instantly and produces noise.
        import os as _os
        _gh_token = _os.environ.get("GITHUB_TOKEN") or _os.environ.get("GITHUB_TOKENS", "").split(",")[0].strip() or None
        _gh_token_placeholder = _gh_token and (_gh_token.startswith("ghp_REPLACE") or len(_gh_token) < 10)
        if not _gh_token or _gh_token_placeholder:
            log.info("[GOD MODE] Foundation Step 3b: GitHubSecretsScanner — SKIPPED (no GitHub token configured)")
        else:
            log.info("[GOD MODE] Foundation Step 3b: GitHubSecretsScanner")
            try:
                from oneinfinity.recon.github_secrets_scanner import GitHubSecretsScanner
                _org = session.target.split(".")[0]  # best-effort org name from domain prefix
                _gss = GitHubSecretsScanner(github_token=_gh_token)
                _secrets_result = _gss.scan_org(_org, max_repos=30, commits_per_repo=5, timeout=120)
                log.info("[GOD MODE] GitHubSecretsScanner: %d findings for org %s",
                         len(_secrets_result.findings), _org)
                if _secrets_result.findings:
                    # Persist to PostgreSQL
                    try:
                        import asyncio as _asyncio
                        from oneinfinity.core.pg_client import store_recon_findings
                        _asyncio.get_event_loop().run_until_complete(
                            store_recon_findings(
                                session.scan_id, session.target,
                                "github_secret", _secrets_result.findings,
                            )
                        )
                    except Exception as _pg_exc:
                        log.debug("[GOD MODE] PG persist secrets failed: %s", _pg_exc)
                    # Emit CREDENTIAL_ACQUIRED for each secret
                    try:
                        from oneinfinity.orchestration.event_bus import get_bus, EventType
                        for _sf in _secrets_result.findings:
                            get_bus().publish(EventType.CREDENTIAL_ACQUIRED, {
                                "scan_id": session.scan_id,
                                "target": session.target,
                                "service": "github",
                                "secret_type": _sf.get("secret_type", "unknown"),
                                "repo": _sf.get("repo", ""),
                                "severity": _sf.get("severity", "medium"),
                                "source": "github_secrets_scanner",
                            }, source="github_secrets_scanner")
                    except Exception:
                        pass
            except Exception as exc:
                log.warning("[GOD MODE] GitHubSecretsScanner failed (non-fatal): %s", exc, exc_info=True)

        # ── Step 3c: GitHub Deep Intel ────────────────────────────────────
        log.info("[GOD MODE] Foundation Step 3c: GitHubDeepIntel")
        try:
            if not _gh_token or _gh_token_placeholder:
                log.info("[GOD MODE] Step 3c: skipping GitHubDeepIntel — no valid GitHub token")
            else:
                from oneinfinity.recon.github_deep_intel import GitHubDeepIntel
                _org2 = session.target.split(".")[0]
                _gdi = GitHubDeepIntel(github_token=_gh_token)
                _deep_intel = _gdi.scan_org(_org2, max_repos=100, deep_scan=True, timeout=300)
                log.info("[GOD MODE] GitHubDeepIntel: %d contributors, %d api_endpoints, org=%s",
                         len(_deep_intel.contributors), len(_deep_intel.api_endpoints), _org2)
                # Save employee names for credential spray (Phase 7)
                # employees.json schema: { target, org, scan_id, employees: [{name,email,username,source,repos}] }
                if _deep_intel.contributors or _deep_intel.emails:
                    try:
                        import json as _json
                        from pathlib import Path as _Path
                        _recon_dir = _Path(GOD_MODE_DIR / session.scan_id / "recon")
                        _recon_dir.mkdir(parents=True, exist_ok=True)
                        _employees_file = _recon_dir / "employees.json"
                        # Build structured employee records — email dicts first (richer),
                        # then any contributor logins not already captured by email records.
                        _seen_logins: set = set()
                        _employees: list = []
                        for _ei in (_deep_intel.emails or []):
                            # EmailIntel serialised as dict: email, name, github_username, commit_count, repos
                            _login = (_ei.get("github_username") or "") if isinstance(_ei, dict) else ""
                            _email_addr = (_ei.get("email") or "") if isinstance(_ei, dict) else ""
                            _display = (_ei.get("name") or _login) if isinstance(_ei, dict) else ""
                            _repos = (_ei.get("repos") or []) if isinstance(_ei, dict) else []
                            if _login:
                                _seen_logins.add(_login)
                            _employees.append({
                                "name":     _display,
                                "email":    _email_addr,
                                "username": _login,
                                "source":   "github_deep_intel",
                                "repos":    _repos,
                            })
                        for _login in sorted(_deep_intel.contributors or []):
                            if _login in _seen_logins:
                                continue
                            _employees.append({
                                "name":     _login,
                                "email":    "",
                                "username": _login,
                                "source":   "github_deep_intel",
                                "repos":    [],
                            })
                        _employees_file.write_text(_json.dumps({
                            "target":    session.target,
                            "org":       _org2,
                            "scan_id":   session.scan_id,
                            "employees": _employees,
                        }, indent=2))
                        log.info("[GOD MODE] Employees saved to %s (%d records)", _employees_file, len(_employees))
                    except Exception as _ef:
                        log.warning("[GOD MODE] Failed to save employees file: %s", _ef)
                # Persist deep intel findings
                if _deep_intel.findings:
                    try:
                        import asyncio as _asyncio
                        from oneinfinity.core.pg_client import store_recon_findings
                        _asyncio.get_event_loop().run_until_complete(
                            store_recon_findings(
                                session.scan_id, session.target,
                                "github_deep_intel", _deep_intel.findings,
                            )
                        )
                    except Exception as _pg_exc:
                        log.debug("[GOD MODE] PG persist deep-intel failed: %s", _pg_exc)
                    # Emit CREDENTIAL_ACQUIRED for each deep-intel finding
                    try:
                        from oneinfinity.orchestration.event_bus import get_bus, EventType
                        for _df in _deep_intel.findings:
                            get_bus().publish(EventType.CREDENTIAL_ACQUIRED, {
                                "scan_id": session.scan_id,
                                "target": session.target,
                                "service": "github",
                                "secret_type": _df.get("secret_type", "unknown") if isinstance(_df, dict) else "unknown",
                                "source": "github_deep_intel",
                            }, source="github_deep_intel")
                    except Exception:
                        pass
                # Persist discovered API endpoints from deep intel
                if _deep_intel.api_endpoints:
                    try:
                        import asyncio as _asyncio
                        from oneinfinity.core.pg_client import store_recon_findings
                        _asyncio.get_event_loop().run_until_complete(
                            store_recon_findings(
                                session.scan_id, session.target,
                                "api_endpoint",
                                [{"url": u, "source": "github_deep_intel"} for u in _deep_intel.api_endpoints],
                            )
                        )
                    except Exception:
                        pass
                    try:
                        from oneinfinity.orchestration.event_bus import get_bus, EventType
                        for _ep_url in _deep_intel.api_endpoints:
                            get_bus().publish(EventType.NEW_ENDPOINT, {
                                "url": _ep_url,
                                "source": "github_deep_intel",
                                "target": session.target,
                            }, source="github_deep_intel")
                    except Exception:
                        pass
        except Exception as exc:
            log.warning("[GOD MODE] GitHubDeepIntel failed (non-fatal): %s", exc, exc_info=True)

        # ── Step 3d: OSINT Collector ──────────────────────────────────────
        log.info("[GOD MODE] Foundation Step 3d: OSINTCollector")
        try:
            from oneinfinity.recon.osint_collector import OSINTCollector
            _domain_for_osint = session.target.split("/")[0]
            _oc = OSINTCollector()
            _osint_results = _oc.collect_all(_domain_for_osint)
            _osint_summary = {
                "subdomains": sum(len(r.subdomains) for r in _osint_results),
                "emails": sum(len(r.emails) for r in _osint_results),
                "ips": sum(len(r.ips) for r in _osint_results),
                "api_keys": sum(len(r.api_keys_found) for r in _osint_results),
            }
            log.info("[GOD MODE] OSINTCollector: subdomains=%d emails=%d ips=%d api_keys=%d",
                     _osint_summary["subdomains"], _osint_summary["emails"],
                     _osint_summary["ips"], _osint_summary["api_keys"])
            # Merge subdomains into recon intel
            if self.recon:
                _existing_subs2 = set(getattr(self.recon, "subdomains", []) or [])
                for _or in _osint_results:
                    for _sd in (_or.subdomains or []):
                        if _sd not in _existing_subs2:
                            _existing_subs2.add(_sd)
                            self.recon.subdomains.append(_sd)
            # Persist OSINT API keys as credentials
            for _or in _osint_results:
                if _or.api_keys_found:
                    try:
                        import asyncio as _asyncio
                        from oneinfinity.core.pg_client import store_recon_findings
                        _asyncio.get_event_loop().run_until_complete(
                            store_recon_findings(
                                session.scan_id, session.target,
                                "osint_api_key", _or.api_keys_found,
                            )
                        )
                    except Exception:
                        pass
                    try:
                        from oneinfinity.orchestration.event_bus import get_bus, EventType
                        for _ak in _or.api_keys_found:
                            get_bus().publish(EventType.CREDENTIAL_ACQUIRED, {
                                "scan_id": session.scan_id,
                                "target": session.target,
                                "service": _or.source,
                                "secret_type": "api_key",
                                "source": "osint_collector",
                                "value_hint": str(_ak)[:20] + "…" if len(str(_ak)) > 20 else str(_ak),
                            }, source="osint_collector")
                    except Exception:
                        pass
        except Exception as exc:
            log.warning("[GOD MODE] OSINTCollector failed (non-fatal): %s", exc, exc_info=True)

        # ── Step 3e: SecretIntelAgent (GitHub + dork-based) ───────────────
        # Skip entirely when no real GitHub token is configured — running without
        # a token consumes the 60 req/hr anonymous quota instantly and spins in
        # a 60s sleep loop for every dork batch, stalling the whole pipeline.
        import os as _os3
        _gh_token3 = _os3.environ.get("GITHUB_TOKEN") or _os3.environ.get("GITHUB_TOKENS", "").split(",")[0].strip() or None
        _is_placeholder = _gh_token3 and (_gh_token3.startswith("ghp_REPLACE") or len(_gh_token3) < 10)
        if not _gh_token3 or _is_placeholder:
            log.info("[GOD MODE] Foundation Step 3e: SecretIntelAgent — SKIPPED (no GitHub token configured)")
        else:
            log.info("[GOD MODE] Foundation Step 3e: SecretIntelAgent")
            try:
                from oneinfinity.agents.secret_intel import SecretIntelAgent
                _sia = SecretIntelAgent(token=_gh_token3)
                _intel_result = _sia.run(
                    session.target,
                    stop_on_critical=False,
                    max_dorks=15,
                    concurrency=3,
                )
                _intel_findings = _intel_result.get("findings", []) if isinstance(_intel_result, dict) else []
                log.info("[GOD MODE] SecretIntelAgent: %d findings", len(_intel_findings))
                if _intel_findings:
                    try:
                        import asyncio as _asyncio
                        from oneinfinity.core.pg_client import store_recon_findings
                        _asyncio.get_event_loop().run_until_complete(
                            store_recon_findings(
                                session.scan_id, session.target,
                                "secret_intel", _intel_findings,
                            )
                        )
                    except Exception:
                        pass
                    try:
                        from oneinfinity.orchestration.event_bus import get_bus, EventType
                        for _if in _intel_findings:
                            if not isinstance(_if, dict):
                                continue
                            get_bus().publish(EventType.CREDENTIAL_ACQUIRED, {
                                "scan_id": session.scan_id,
                                "target": session.target,
                                "service": "github",
                                "secret_type": _if.get("secret_type", "unknown"),
                                "severity": _if.get("severity", "medium"),
                                "source": "secret_intel_agent",
                                "repo": _if.get("repo_url", ""),
                            }, source="secret_intel_agent")
                    except Exception:
                        pass
            except Exception as exc:
                log.warning("[GOD MODE] SecretIntelAgent failed (non-fatal): %s", exc, exc_info=True)

        # ── Step 4: WAF detection + bypass payload pre-generation ────────
        # Runs AFTER recon so we know the tech_profile (waf field).
        # Populates session.waf_vendor and session.waf_bypass_payloads so all
        # downstream missions (FullScan, Swarm, Research) use bypass payloads
        # instead of plain payloads when a WAF is detected.
        log.info("[GOD MODE] Foundation Step 4: WAF detection + bypass payload generation")
        try:
            from oneinfinity.ai_security.adversarial_waf_engine import AdversarialWAFEngine
            from oneinfinity.scan.adaptive_mutation_helper import get_waf_vendor as _detect_waf_vendor

            # Step 4a: detect WAF vendor from tech_profile first (free, no HTTP)
            waf_vendor = ""
            if self.recon and hasattr(self.recon, "tech_profile"):
                tp = self.recon.tech_profile
                raw_tech = getattr(tp, "raw_tech", []) or []
                waf_field = getattr(tp, "waf", "") or ""
                tech_str = " ".join(raw_tech + [waf_field]).lower()
                if "cloudflare" in tech_str:
                    waf_vendor = "cloudflare"
                elif "akamai" in tech_str:
                    waf_vendor = "akamai"
                elif "aws" in tech_str and "waf" in tech_str:
                    waf_vendor = "aws_waf"
                elif "imperva" in tech_str or "incapsula" in tech_str:
                    waf_vendor = "imperva"
                elif "f5" in tech_str or "big-ip" in tech_str:
                    waf_vendor = "f5"
                elif "modsecurity" in tech_str or "modsec" in tech_str:
                    waf_vendor = "modsecurity"

            # Step 4b: if still unknown, probe HTTP to detect WAF from response headers
            if not waf_vendor:
                waf_engine = AdversarialWAFEngine(vuln_type="sqli", target=session.target)
                waf_vendor = waf_engine.detect_waf()

            session.waf_vendor = waf_vendor or ""

            if waf_vendor:
                log.info("[GOD MODE] WAF detected: %s — generating bypass payloads", waf_vendor)
                # Step 4c: generate bypass payloads for critical vuln types via LLM self-play
                # Runs AdversarialWAFEngine: Attacker LLM vs WAF-Simulator LLM, up to 8 iterations
                adv_engine = AdversarialWAFEngine(
                    vuln_type="sqli",
                    target=session.target,
                    max_iterations=5,   # balance quality vs speed
                    timeout=8,
                )
                bypass_payloads = adv_engine.generate_all_types(
                    endpoint="/login",  # most critical endpoint for auth bypass
                    vuln_types=["sqli", "xss", "ssrf", "ssti", "cmdi", "lfi"],
                )
                session.waf_bypass_payloads = bypass_payloads
                total = sum(len(v) for v in bypass_payloads.values())
                log.info("[GOD MODE] WAF bypass payloads generated: %d total across %d vuln types",
                         total, len(bypass_payloads))
            else:
                log.info("[GOD MODE] No WAF detected — standard payloads will be used")
                session.waf_bypass_payloads = {}
        except Exception as exc:
            log.warning("[GOD MODE] WAF bypass generation failed (non-fatal): %s", exc, exc_info=True)
            session.waf_bypass_payloads = {}

        # ── Step 4d: Nim stealth_prober for Cloudflare/Akamai WAF evasion ────
        # When a heavy-fingerprinting WAF is detected, kick off the Nim stealth
        # prober to pre-test bypass techniques before the main scan begins.
        # Results are merged into session.waf_bypass_payloads for downstream use.
        if session.waf_vendor in ("cloudflare", "akamai"):
            log.info("[GOD MODE] Foundation Step 4d: Nim stealth_prober for %s WAF evasion", session.waf_vendor)
            try:
                _nim_findings = _run_nim_stealth_prober(
                    target=session.target,
                    waf_vendor=session.waf_vendor,
                    timeout_ms=8000,
                )
                if _nim_findings:
                    # Integrate bypass payloads discovered by the Nim prober
                    _nim_payloads: list = [
                        f.get("payload", "") for f in _nim_findings
                        if f.get("payload") and not f.get("blocked", True)
                    ]
                    if _nim_payloads:
                        session.waf_bypass_payloads.setdefault("nim_stealth", []).extend(_nim_payloads[:20])
                        log.info("[GOD MODE] Nim stealth_prober: %d bypass techniques found for %s",
                                 len(_nim_payloads), session.waf_vendor)
                    session.add_findings(len(_nim_findings))
            except Exception as _nim_exc:
                log.debug("[GOD MODE] Nim stealth_prober failed (non-fatal): %s", _nim_exc)


        self._result = {
            "recon_ok": self.recon is not None,
            "app_model_ok": self.app_model is not None,
            "waf_vendor": session.waf_vendor,
            "waf_bypass_ready": bool(session.waf_bypass_payloads),
        }


# ── FullScanMission ────────────────────────────────────────────────────────────

class FullScanMission(Mission):
    """Runs the canonical 10-phase pipeline via run_canonical_pipeline()."""

    def __init__(self, foundation: FoundationMission, auth_config: dict = None,
                 findings_pipeline_cb=None):
        super().__init__("full_scan")
        self._foundation = foundation
        self._auth_config = auth_config or {}
        self._findings_pipeline_cb = findings_pipeline_cb

    def _run(self, session: GodModeSession) -> None:
        from oneinfinity.pipeline.executor import run_canonical_pipeline

        log.info("[GOD MODE] FullScanMission: starting canonical pipeline for %s", session.target)
        if self._auth_config and any(self._auth_config.values()):
            log.info("[GOD MODE] FullScanMission: authenticated scan mode active")
        if session.waf_vendor:
            log.info("[GOD MODE] FullScanMission: WAF bypass mode active — vendor=%s, bypass_types=%s",
                     session.waf_vendor, list(session.waf_bypass_payloads.keys()))

        # Output dir: ~/.oneinfinity/<scan_id>/full_scan/
        out_dir = str(GOD_MODE_DIR / session.scan_id / "full_scan")
        recon_dir = str(GOD_MODE_DIR / session.scan_id / "recon")
        Path(out_dir).mkdir(parents=True, exist_ok=True)

        def _on_progress(phase: str, pct: int, msg: str) -> None:
            log.info("[GOD MODE] full_scan [%d%%] [%s] %s", pct, phase, msg)

        # Build waf_profile from session so pipeline uses bypass mode and
        # rate-limits correctly for detected WAF vendor
        waf_profile = None
        if session.waf_vendor:
            # Bypass403Engine: run header + path bypass tests — council-approved call
            _bypass_report = None
            try:
                from oneinfinity.attack.bypass_403_engine import Bypass403Engine
                _bypass_engine = Bypass403Engine(
                    waf_vendor=session.waf_vendor,
                    delay_between_requests=0.3,
                    max_requests=100,        # cap: security council requirement
                )
                _target_url = (session.target if session.target.startswith("http")
                               else f"https://{session.target}")
                _bypass_report = _bypass_engine.test(_target_url)
                log.info("[GOD MODE] Bypass403Engine: %d bypasses found (%d techniques tested) for %s",
                         _bypass_report.bypasses_found, _bypass_report.techniques_tested,
                         session.waf_vendor)
            except Exception as _be:
                log.debug("[GOD MODE] Bypass403Engine test failed (non-fatal): %s", _be)
            waf_profile = {
                "waf_detected": True,
                "waf_name": session.waf_vendor,
                "rate_limit_rps": 5 if session.waf_vendor == "cloudflare" else 8,
                "jitter_ms": 300 if session.waf_vendor == "cloudflare" else 200,
                "bypass_payloads": session.waf_bypass_payloads,
                "bypass_403_findings": [
                    {"technique": r.technique, "category": r.category,
                     "status_code": r.status_code, "bypassed": r.bypassed,
                     "evidence": r.evidence}
                    for r in (_bypass_report.findings if _bypass_report else [])
                    if r.bypassed or r.is_significant
                ],
            }
            if waf_profile.get("bypass_403_findings"):
                session.add_findings(len(waf_profile["bypass_403_findings"]))

        # ── AdaptivePlanner: vocabulary adapter + phase wiring ─────────────────
        # Maps old planner phase names to canonical pipeline phase names.
        _PLANNER_TO_CANONICAL: dict = {
            "recon":        "deep_recon",
            "scan_nuclei":  "vuln_scan",
            "triage":       None,
            "scan_xss":     "active_testing",
            "scan_sqli":    "active_testing",
            "scan_ssrf":    "active_testing",
            "scan_secrets": "deep_recon",
            "exploit":      "exploit_chains",
            "validate":     "exploit_validation",
            "report":       None,
        }
        _adaptive_focus_vulns: list = []
        _adaptive_skip_phases: list = []
        try:
            from oneinfinity.learning.adaptive_planner import AdaptivePlanner
            from oneinfinity.learning.neo4j_knowledge_base import Neo4jKnowledgeBase
            _ap_kb = Neo4jKnowledgeBase()
            _planner = AdaptivePlanner(_ap_kb)
            _app_model = self._foundation.app_model if self._foundation else None
            _tech = list(getattr(_app_model, "tech_stack", None) or []) if _app_model else None
            _plan = _planner.plan(session.target, tech_stack=_tech)
            _adaptive_focus_vulns = _plan.focus_vuln_types or []
            # Translate old vocabulary to canonical phase names
            _adaptive_skip_phases = list({
                _PLANNER_TO_CANONICAL[p]
                for p in (_plan.skip_phases or [])
                if _PLANNER_TO_CANONICAL.get(p)
            })
            log.info("[GOD MODE] AdaptivePlanner: focus_vulns=%s skip=%s rationale=%s",
                     _adaptive_focus_vulns[:5], _adaptive_skip_phases,
                     (_plan.rationale or [])[:2])
        except Exception as _ap_exc:
            log.debug("[GOD MODE] AdaptivePlanner skipped (non-fatal — requires Neo4j KB): %s", _ap_exc)

        # Uses Foundation recon results (seeded via prior_results_dir) to speed up deep_recon phase
        result = run_canonical_pipeline(
            target=session.target,
            output_dir=out_dir,
            mode="subprocess",
            on_progress=_on_progress,
            prior_results_dir=recon_dir if self._foundation.recon else None,
            auth_config=self._auth_config if self._auth_config else None,
            waf_profile=waf_profile,
            skip_phases=_adaptive_skip_phases if _adaptive_skip_phases else None,
            # Double phase timeouts when WAF is active — bypass payloads add latency
            timeout_multiplier=2.0 if waf_profile else 1.0,
        )

        # Update session finding count
        new_count = len(result.findings) if result and result.findings else 0
        session.add_findings(new_count)
        session.phases_complete.append("full_scan")

        # Push findings into the ingestion engine so ReportMission can read them
        if result and result.findings:
            try:
                from oneinfinity.findings.result_ingestion_engine import get_ingestion_engine, RawResult
                bus = get_ingestion_engine()
                for f in result.findings:
                    fd = f if isinstance(f, dict) else (f.__dict__ if hasattr(f, "__dict__") else {})
                    if fd:
                        bus.ingest(RawResult(scan_id=session.scan_id, source="god-mode-full-scan", raw=fd))
            except Exception as exc:
                log.warning("[GOD MODE] FullScanMission ingestion bus publish failed: %s", exc)

        # Fire NEW_VULNERABILITY events so ResearchMission can unlock
        if result and result.findings:
            try:
                from oneinfinity.orchestration.event_bus import get_bus, EventType
                bus = get_bus()
                for f in result.findings:
                    fd = f if isinstance(f, dict) else {}
                    if fd:
                        bus.publish(EventType.NEW_VULNERABILITY, fd, source="god-mode-full-scan")
            except Exception as exc:
                log.warning("[GOD MODE] FullScanMission event bus publish failed: %s", exc)

        # Apply confidence scoring + confirmation pipeline per-phase
        if self._findings_pipeline_cb is not None and result and result.findings:
            try:
                _fds = [
                    f if isinstance(f, dict) else (f.__dict__ if hasattr(f, "__dict__") else {})
                    for f in result.findings if f
                ]
                self._findings_pipeline_cb(_fds, scan_id=session.scan_id)
            except Exception as _cb_exc:
                log.warning("[GOD MODE] FullScanMission findings_pipeline_cb failed: %s", _cb_exc)

        log.info("[GOD MODE] FullScanMission complete — %d findings", new_count)
        self._result = {"findings": new_count, "output_dir": out_dir}


# ── ResearchMission ────────────────────────────────────────────────────────────

class ResearchMission(Mission):
    """
    Runs the iterative research loop via ResearchModeController.
    Each completed iteration notifies the ConvergenceChecker.
    Unlocked by: NEW_VULNERABILITY count >= 1 (EVENT_UNLOCK_VULN_THRESHOLD).
    """

    def __init__(self, convergence: ConvergenceChecker):
        super().__init__("research")
        self._convergence = convergence
        self._iterations_done: int = 0

    def _run(self, session: GodModeSession) -> None:
        from oneinfinity.orchestration.research_mode_controller import ResearchModeController

        log.info("[GOD MODE] ResearchMission: starting research loop for %s", session.target)

        out_dir = str(GOD_MODE_DIR / session.scan_id / "research")
        Path(out_dir).mkdir(parents=True, exist_ok=True)

        ctrl = ResearchModeController(
            target=session.target,
            output_dir=out_dir,
            max_iterations=5,
            passive_only=False,
            auth_config=session.auth_config,
        )
        discoveries = ctrl.run_research()

        new_count = len(discoveries) if discoveries else 0
        session.add_findings(new_count)
        self._iterations_done += 1
        session.phases_complete.append("research")

        # Notify convergence checker
        self._convergence.record_research_iteration(session.finding_count)
        log.info("[GOD MODE] ResearchMission complete — %d discoveries, iter=%d",
                 new_count, self._iterations_done)
        self._result = {"discoveries": new_count, "iterations": self._iterations_done}


# ── SwarmMission ───────────────────────────────────────────────────────────────

class SwarmMission(Mission):
    """
    Runs all 8 specialized swarm agents in parallel via run_swarm().
    Unlocked by: NEW_ENDPOINT count >= 5 (EVENT_UNLOCK_ENDPOINT_THRESHOLD).
    """

    def __init__(self):
        super().__init__("swarm")

    def _run(self, session: GodModeSession) -> None:
        import asyncio as _asyncio
        import json as _json
        from oneinfinity.swarm.agent_swarm_coordinator import run_swarm

        log.info("[GOD MODE] SwarmMission: deploying 8 agents against %s", session.target)

        # Build context including auth
        ctx: dict = {}
        if session.auth_config:
            ctx["auth_sessions"] = [session.auth_config]

        # Wire WAF bypass payloads into swarm context so each agent uses
        # bypass-encoded variants instead of plain payloads when WAF detected
        if session.waf_vendor and session.waf_bypass_payloads:
            ctx["waf_vendor"] = session.waf_vendor
            ctx["waf_bypass_payloads"] = session.waf_bypass_payloads
            log.info("[GOD MODE] SwarmMission: WAF bypass context injected — vendor=%s types=%s",
                     session.waf_vendor, list(session.waf_bypass_payloads.keys()))

        # Inject discovered endpoints from recon so agents test real attack surface
        # rather than just the root URL.
        _endpoints: list[str] = []
        for _candidate in [
            GOD_MODE_DIR / session.scan_id / "full_scan" / "adaptive_recon.json",
            GOD_MODE_DIR / session.scan_id / "recon" / "urls.json",
        ]:
            try:
                if _candidate.exists():
                    _d = _json.loads(_candidate.read_text())
                    _urls = _d if isinstance(_d, list) else _d.get("urls", [])
                    _endpoints.extend(u for u in _urls if u not in _endpoints)
            except Exception:
                pass
        if _endpoints:
            ctx["endpoints"] = _endpoints
            log.info("[GOD MODE] SwarmMission: seeded %d endpoints from recon", len(_endpoints))
        else:
            log.warning("[GOD MODE] SwarmMission: no recon endpoints found — agents will probe root URL only")

        # Partial output file so the coordinator can flush findings after each agent;
        # used for recovery when the 20-minute hard timeout fires.
        _partial_file = GOD_MODE_DIR / session.scan_id / "swarm_partial.json"
        try:
            _partial_file.parent.mkdir(parents=True, exist_ok=True)
        except Exception:
            pass

        # Run with a hard timeout (default 20 min) so a hung agent can't block the pipeline
        SWARM_TIMEOUT = 1200  # 20 minutes
        try:
            result = _asyncio.run(
                _asyncio.wait_for(
                    run_swarm(
                        target=session.target,
                        context=ctx,
                        concurrency=4,
                        agent_types=None,
                        output_file=str(_partial_file),
                    ),
                    timeout=SWARM_TIMEOUT,
                )
            )
        except _asyncio.TimeoutError:
            log.warning("[GOD MODE] SwarmMission timed out after %ds — continuing with partial results", SWARM_TIMEOUT)
            result = None
            # Recover findings flushed to disk by the coordinator before the timeout
            try:
                if _partial_file.exists():
                    _pdata = _json.loads(_partial_file.read_text())
                    _pfds = _pdata.get("findings", [])
                    if _pfds:
                        log.warning(
                            "[GOD MODE] SwarmMission timeout recovery: ingesting %d partial findings from %s",
                            len(_pfds), _partial_file,
                        )
                        result = type("_PartialResult", (), {"findings": _pfds})()
            except Exception as _pe:
                log.debug("[GOD MODE] SwarmMission partial recovery failed: %s", _pe)
        except Exception as _exc:
            log.warning("[GOD MODE] SwarmMission run_swarm error (non-fatal): %s", _exc)
            result = None

        new_count = len(result.findings) if result and hasattr(result, "findings") else 0
        session.add_findings(new_count)
        session.phases_complete.append("swarm")

        # Publish to ingestion bus
        try:
            from oneinfinity.findings.result_ingestion_engine import get_ingestion_engine, RawResult
            sid = session.scan_id
            bus = get_ingestion_engine()
            for f in (result.findings if result and hasattr(result, "findings") else []):
                fd = f if isinstance(f, dict) else (f.__dict__ if hasattr(f, "__dict__") else {})
                if fd:
                    bus.ingest(RawResult(scan_id=sid, source="god-mode-swarm", raw=fd))
        except Exception as exc:
            log.warning("[GOD MODE] SwarmMission ingestion bus publish failed: %s", exc)

        log.info("[GOD MODE] SwarmMission complete — %d findings", new_count)
        self._result = {"findings": new_count}


# ── AuthTestMission ────────────────────────────────────────────────────────────

class AuthTestMission(Mission):
    """
    Runs 16 post-login security test categories.
    Silently skipped if no auth_context — does not affect unauthenticated scans.
    """

    def __init__(self, auth_context=None):
        super().__init__("auth_test")
        self._auth_context = auth_context

    def _run(self, session: GodModeSession) -> None:
        import json as _json
        if self._auth_context is None:
            log.info("[GOD MODE] AuthTestMission: no auth context — skipping")
            return

        log.info("[GOD MODE] AuthTestMission: running 16 authenticated test categories for %s", session.target)

        _endpoints: list[str] = [session.target]
        for _candidate in [
            GOD_MODE_DIR / session.scan_id / "full_scan" / "adaptive_recon.json",
            GOD_MODE_DIR / session.scan_id / "recon" / "urls.json",
        ]:
            try:
                if _candidate.exists():
                    _d = _json.loads(_candidate.read_text())
                    _urls = _d if isinstance(_d, list) else _d.get("urls", [])
                    _endpoints.extend(_urls)
            except Exception:
                pass

        try:
            from oneinfinity.auth.authenticated_test_suite import AuthenticatedTestSuite
            suite = AuthenticatedTestSuite(
                target=session.target,
                endpoints=list(dict.fromkeys(_endpoints))[:100],
                auth_context=self._auth_context,
            )
            findings = suite.run_all()
        except Exception as exc:
            log.warning("[GOD MODE] AuthTestMission: test suite failed — %s", exc, exc_info=True)
            return

        new_count = len(findings)
        session.add_findings(new_count)
        session.phases_complete.append("auth_test")

        out_dir = GOD_MODE_DIR / session.scan_id / "full_scan"
        out_dir.mkdir(parents=True, exist_ok=True)
        out_file = out_dir / "auth_test_findings.json"
        try:
            out_file.write_text(_json.dumps([f.to_dict() for f in findings], indent=2, default=str))
            log.info("[GOD MODE] AuthTestMission: wrote %d findings to %s", new_count, out_file)
        except Exception as exc:
            log.warning("[GOD MODE] AuthTestMission: could not write findings — %s", exc, exc_info=True)

        try:
            from oneinfinity.findings.result_ingestion_engine import get_ingestion_engine, RawResult
            bus = get_ingestion_engine()
            for f in findings:
                bus.ingest(RawResult(scan_id=session.scan_id, source="auth-test", raw=f.to_dict()))
        except Exception as exc:
            log.warning("[GOD MODE] AuthTestMission ingestion failed: %s", exc, exc_info=True)

        log.info("[GOD MODE] AuthTestMission complete — %d findings", new_count)
        self._result = {"findings": new_count}


# ── ChainsMission ──────────────────────────────────────────────────────────────

class ChainsMission(Mission):
    """
    Runs exploit chain detection on all accumulated findings.
    Unlocked by: ResearchMission iteration 2+ complete.
    """

    def __init__(self):
        super().__init__("chains")

    def _run(self, session: GodModeSession) -> None:
        from oneinfinity.attack.exploit_chain_engine import ExploitChainEngine
        from oneinfinity.findings.result_ingestion_engine import get_ingestion_engine

        log.info("[GOD MODE] ChainsMission: running chain analysis for %s", session.target)

        findings = []
        try:
            findings = get_ingestion_engine().get_findings() or []
        except Exception as exc:
            log.warning("[GOD MODE] ChainsMission: could not load findings: %s", exc, exc_info=True)

        engine = ExploitChainEngine()
        try:
            chains = engine.detect_chains(findings, session.target)
        except Exception as exc:
            log.warning("[GOD MODE] ChainsMission: chain detection failed: %s", exc, exc_info=True)
            chains = None
        finally:
            session.phases_complete.append("chains")

        chain_count = len(chains) if chains else 0
        log.info("[GOD MODE] ChainsMission complete — %d chains detected", chain_count)
        self._result = {"chains": chain_count}


# ── AIRedTeamMission ───────────────────────────────────────────────────────────

class AIRedTeamMission(Mission):
    """
    Runs the full AI/LLM red-team battery against AI-type targets.
    Wraps: MultiTurnChainer (6 strategies), RAGPoisoningEngine, LLMDoSEngine,
    LLMSupplyChainScanner, AgentHijackHarness.

    Unlock condition: _is_ai_target() at startup OR NEW_ENDPOINT event
    matching AI API path patterns.
    """

    _AI_PATH_HINTS = (
        "/v1/chat", "/api/chat", "/completions", "/llm/",
        "/inference", "/generate", "/ai/",
    )

    def __init__(self, auth_header: str = "", findings_pipeline_cb=None) -> None:
        super().__init__("ai_red_team")
        self._auth_header = auth_header
        self._findings_pipeline_cb = findings_pipeline_cb

    def _run(self, session: GodModeSession) -> None:
        import asyncio as _asyncio
        target = session.target
        auth = self._auth_header or ""
        if session.auth_config:
            token = (session.auth_config.get("token") or
                     session.auth_config.get("bearer") or
                     session.auth_config.get("bearer_token") or "")
            if token:
                auth = f"Bearer {token}"

        log.info("[GOD MODE] AIRedTeamMission: starting AI red-team battery against %s", target)
        all_findings: list = []
        TIMEOUT_PER_ENGINE = 120  # seconds per async engine call

        async def _run_async_engines():
            _results = []
            # 1. Multi-turn chaining across 6 strategies
            try:
                from oneinfinity.ai_security.multi_turn_chainer import (
                    MultiTurnChainer, ChainStrategy,
                )
                chainer = MultiTurnChainer(target_url=target)
                for strategy in ChainStrategy:
                    try:
                        result = await _asyncio.wait_for(
                            chainer.run_chain(
                                strategy=strategy,
                                max_turns=5,
                                auth_header=auth,
                                stop_on_success=False,
                            ),
                            timeout=90,
                        )
                        if getattr(result, "finding", None):
                            _results.append(result.finding)
                        for turn in getattr(result, "turns", []) or []:
                            if getattr(turn, "success", False) and getattr(turn, "score", 0) >= 0.5:
                                _results.append({
                                    "vuln_type": "llm_jailbreak",
                                    "sub_type": strategy.value,
                                    "severity": "high",
                                    "endpoint": target,
                                    "payload": str(getattr(turn, "prompt", ""))[:400],
                                    "evidence": f"Multi-turn {strategy.value}: turn {getattr(turn, 'turn_num', 0)} (score={getattr(turn, 'score', 0):.2f})",
                                    "confidence": float(getattr(turn, "score", 0.85)),
                                    "source_type": "ai_red_team",
                                    "tool": "multi_turn_chainer",
                                })
                    except _asyncio.TimeoutError:
                        log.debug("[GOD MODE] AIRedTeamMission: strategy %s timed out", strategy.value)
                    except Exception as _se:
                        log.debug("[GOD MODE] AIRedTeamMission: strategy %s error: %s", strategy.value, _se)
            except ImportError:
                log.debug("[GOD MODE] AIRedTeamMission: MultiTurnChainer not available")
            except Exception as _ce:
                log.warning("[GOD MODE] AIRedTeamMission: MultiTurnChainer failed: %s", _ce)

            # 2. RAG Poisoning
            try:
                from oneinfinity.ai_security.rag_poisoning_engine import RAGPoisoningEngine
                rag = RAGPoisoningEngine(auth_header=auth, timeout=30)
                rag_findings = await _asyncio.wait_for(rag.scan(target), timeout=TIMEOUT_PER_ENGINE)
                _results.extend(rag_findings or [])
            except _asyncio.TimeoutError:
                log.debug("[GOD MODE] AIRedTeamMission: RAGPoisoningEngine timed out")
            except ImportError:
                log.debug("[GOD MODE] AIRedTeamMission: RAGPoisoningEngine not available")
            except Exception as _re:
                log.debug("[GOD MODE] AIRedTeamMission: RAGPoisoningEngine error: %s", _re)

            # 3. LLM DoS
            try:
                from oneinfinity.ai_security.llm_dos_engine import LLMDoSEngine
                dos = LLMDoSEngine(auth_header=auth, timeout=60)
                dos_findings = await _asyncio.wait_for(dos.scan(target), timeout=TIMEOUT_PER_ENGINE)
                _results.extend(dos_findings or [])
            except _asyncio.TimeoutError:
                log.debug("[GOD MODE] AIRedTeamMission: LLMDoSEngine timed out")
            except ImportError:
                log.debug("[GOD MODE] AIRedTeamMission: LLMDoSEngine not available")
            except Exception as _de:
                log.debug("[GOD MODE] AIRedTeamMission: LLMDoSEngine error: %s", _de)

            # 4. LLM Supply Chain Scanner
            try:
                from oneinfinity.ai_security.llm_supply_chain_scanner import LLMSupplyChainScanner
                supply = LLMSupplyChainScanner(auth_header=auth, timeout=30)
                supply_findings = await _asyncio.wait_for(supply.scan(target), timeout=TIMEOUT_PER_ENGINE)
                _results.extend(supply_findings or [])
            except _asyncio.TimeoutError:
                log.debug("[GOD MODE] AIRedTeamMission: LLMSupplyChainScanner timed out")
            except ImportError:
                log.debug("[GOD MODE] AIRedTeamMission: LLMSupplyChainScanner not available")
            except Exception as _sce:
                log.debug("[GOD MODE] AIRedTeamMission: LLMSupplyChainScanner error: %s", _sce)


            # 5. ModelExtractionEngine (system prompt / architecture / boundary probes)
            try:
                from oneinfinity.ai.model_extraction_engine import ModelExtractionEngine
                extractor = ModelExtractionEngine(target_url=target, auth_header=auth, timeout=60)
                extraction_findings = await _asyncio.wait_for(
                    extractor.scan(), timeout=TIMEOUT_PER_ENGINE
                )
                _results.extend(extraction_findings or [])
            except _asyncio.TimeoutError:
                log.debug("[GOD MODE] AIRedTeamMission: ModelExtractionEngine timed out")
            except ImportError:
                log.debug("[GOD MODE] AIRedTeamMission: ModelExtractionEngine not available")
            except Exception as _mee:
                log.debug("[GOD MODE] AIRedTeamMission: ModelExtractionEngine error: %s", _mee)
            return _results

        # Run async engines via asyncio.run()
        try:
            all_findings = _asyncio.run(
                _asyncio.wait_for(_run_async_engines(), timeout=600)
            )
        except _asyncio.TimeoutError:
            log.warning("[GOD MODE] AIRedTeamMission: async battery timed out after 600s")
        except Exception as exc:
            log.warning("[GOD MODE] AIRedTeamMission: async run error: %s", exc)

        # 5. AgentHijackHarness (synchronous .scan())
        try:
            from oneinfinity.ai.agent_hijack_harness import AgentHijackHarness
            api_key = session.auth_config.get("api_key", "") if session.auth_config else ""
            harness = AgentHijackHarness()
            harness_findings = harness.scan(target_url=target, api_key=api_key, timeout=120)
            all_findings.extend(harness_findings or [])
        except ImportError:
            log.debug("[GOD MODE] AIRedTeamMission: AgentHijackHarness not available")
        except Exception as exc:
            log.warning("[GOD MODE] AIRedTeamMission: AgentHijackHarness error: %s", exc)

        # Ingest findings
        new_count = len(all_findings)
        session.add_findings(new_count)
        session.phases_complete.append("ai_red_team")
        if all_findings:
            try:
                from oneinfinity.findings.result_ingestion_engine import get_ingestion_engine, RawResult
                bus = get_ingestion_engine()
                for f in all_findings:
                    fd = f if isinstance(f, dict) else (f.__dict__ if hasattr(f, "__dict__") else {})
                    if fd:
                        # Normalise: all AI red-team findings use ai_-prefixed vuln_type in PG
                        fd = dict(fd)
                        _vt = fd.get("vuln_type") or ""
                        if not _vt.startswith("ai_"):
                            fd["vuln_type"] = f"ai_{_vt}" if _vt else "ai_finding"
                        # Severity derived from confidence / jailbreak success rate when absent
                        if not fd.get("severity"):
                            _conf = float(fd.get("confidence", 0) or 0)
                            fd["severity"] = (
                                "critical" if _conf >= 0.8 else
                                "high"     if _conf >= 0.5 else
                                "medium"
                            )
                        bus.ingest(RawResult(scan_id=session.scan_id, source="god-mode-ai-red-team", raw=fd))
            except Exception as exc:
                log.warning("[GOD MODE] AIRedTeamMission ingestion failed: %s", exc)

        # Apply confidence scoring + confirmation pipeline per-phase
        if self._findings_pipeline_cb is not None and all_findings:
            try:
                _fds = [
                    f if isinstance(f, dict) else (f.__dict__ if hasattr(f, "__dict__") else {})
                    for f in all_findings if f
                ]
                self._findings_pipeline_cb(_fds, scan_id=session.scan_id)
            except Exception as _cb_exc:
                log.warning("[GOD MODE] AIRedTeamMission findings_pipeline_cb failed: %s", _cb_exc)

        log.info("[GOD MODE] AIRedTeamMission complete — %d findings", new_count)
        self._result = {"findings": new_count, "tools_run": [
            "multi_turn_chainer", "rag_poisoning", "llm_dos",
            "llm_supply_chain", "model_extraction", "agent_hijack",
        ]}


# ── AICouncilMission ───────────────────────────────────────────────────────────

class AICouncilMission(Mission):
    """
    Runs the full Autonomous Vulnerability Discovery Council pipeline:
    SensorAgent → ReasoningAgent → AdaptationAgent → StepwiseExploitRunner
    → MCPSurfaceScanner → LLMGuidedPostExploit → ScribeAgent → save_council_run.

    Conditional on _is_ai_target() — only starts for AI-type endpoints.
    Every sub-step is independently try/except wrapped; the mission never raises.
    """

    def __init__(self, foundation: "FoundationMission", auth_config: dict = None) -> None:
        super().__init__("ai_council")
        self._foundation = foundation
        self._auth_config = auth_config or {}

    def _run(self, session: GodModeSession) -> None:  # noqa: C901
        import asyncio as _asyncio
        target   = session.target
        scan_id  = session.scan_id
        auth_cfg = self._auth_config or {}

        auth_headers: dict = {}
        _bearer = (
            auth_cfg.get("bearer_token") or
            auth_cfg.get("token") or
            auth_cfg.get("bearer") or ""
        )
        if _bearer:
            if not _bearer.startswith("Bearer "):
                _bearer = f"Bearer {_bearer}"
            auth_headers["Authorization"] = _bearer

        log.info("[GOD MODE] AICouncilMission starting for %s", target)

        surface_profile = None
        # ── Step 1: SensorAgent surface profiling ──────────────────────────
        try:
            from oneinfinity.ai.sensor_agent import SensorAgent
            auth_header_str = auth_headers.get("Authorization", "")
            sensor = SensorAgent(auth_header=auth_header_str)
            surface_profile = sensor.run(target, scan_id)
            log.info("[AICouncilMission] SensorAgent complete — profile=%r", type(surface_profile).__name__)
        except Exception as exc:
            log.warning("[AICouncilMission] SensorAgent failed (non-fatal): %s", exc)

        exploit_plan = None
        # ── Step 2: ReasoningAgent — build exploit plan ────────────────────
        try:
            from oneinfinity.ai.reasoning_agent import ReasoningAgent
            profile_dict = {}
            if surface_profile is not None:
                profile_dict = (
                    surface_profile.to_dict()
                    if hasattr(surface_profile, "to_dict")
                    else surface_profile.__dict__
                )
            profile_dict.setdefault("target", target)
            exploit_plan = ReasoningAgent(surface_profile=profile_dict).build_plan()
            log.info("[AICouncilMission] ReasoningAgent complete — plan=%r", type(exploit_plan).__name__)
        except Exception as exc:
            log.warning("[AICouncilMission] ReasoningAgent failed (non-fatal): %s", exc)

        # ── Step 3: AdaptationAgent instantiation ─────────────────────────
        adaptation_agent = None
        try:
            from oneinfinity.ai.adaptation_agent import AdaptationAgent
            adaptation_agent = AdaptationAgent(surface_profile=surface_profile)
            log.info("[AICouncilMission] AdaptationAgent instantiated")
        except Exception as exc:
            log.warning("[AICouncilMission] AdaptationAgent init failed (non-fatal): %s", exc)

        exploit_trace = None
        # ── Step 4: StepwiseExploitRunner ─────────────────────────────────
        try:
            from oneinfinity.ai.stepwise_runner import StepwiseExploitRunner
            runner = StepwiseExploitRunner(
                exploit_plan,
                target,
                adaptation_agent=adaptation_agent,
            )
            exploit_trace = runner.run()
            log.info("[AICouncilMission] StepwiseExploitRunner complete — trace=%r", type(exploit_trace).__name__)
        except Exception as exc:
            log.warning("[AICouncilMission] StepwiseExploitRunner failed (non-fatal): %s", exc)

        # ── Step 5: Ingest ExploitTrace findings ──────────────────────────
        try:
            if exploit_trace is not None:
                from oneinfinity.findings.result_ingestion_engine import get_ingestion_engine, RawResult
                bus = get_ingestion_engine()
                steps = getattr(exploit_trace, "steps", []) or []
                for step in steps:
                    fd = step if isinstance(step, dict) else (step.__dict__ if hasattr(step, "__dict__") else {})
                    if fd:
                        bus.ingest(RawResult(scan_id=scan_id, source="god-mode-ai-council", raw=fd))
                log.info("[AICouncilMission] Ingested %d exploit trace steps", len(steps))
        except Exception as exc:
            log.warning("[AICouncilMission] ExploitTrace ingestion failed (non-fatal): %s", exc)

        mcp_result = None
        # ── Step 6: MCPSurfaceScanner ─────────────────────────────────────
        try:
            from oneinfinity.ai_security.mcp_surface_scanner import MCPSurfaceScanner
            mcp_result = MCPSurfaceScanner().scan(target, scan_id)
            log.info("[AICouncilMission] MCPSurfaceScanner complete — result=%r", type(mcp_result).__name__)
        except ImportError:
            log.debug("[AICouncilMission] MCPSurfaceScanner not available")
        except Exception as exc:
            log.warning("[AICouncilMission] MCPSurfaceScanner failed (non-fatal): %s", exc)

        post_exploit_report = None
        # ── Step 7: LLMGuidedPostExploit (only if overall_success) ────────
        try:
            overall_success = bool(
                exploit_trace is not None and
                getattr(exploit_trace, "overall_success", False)
            )
            if overall_success:
                from oneinfinity.attack.post_exploit_engine import LLMGuidedPostExploit, PostExploitContext
                pe_findings = []
                if exploit_trace is not None:
                    steps = getattr(exploit_trace, "steps", []) or []
                    for s in steps:
                        pe_findings.append(
                            s if isinstance(s, dict) else (s.__dict__ if hasattr(s, "__dict__") else {})
                        )
                pec = PostExploitContext(target=target)
                pe = LLMGuidedPostExploit(target=target, findings=pe_findings)
                post_exploit_report = pe.run_llm_guided(pec)
                log.info("[AICouncilMission] LLMGuidedPostExploit complete")
        except Exception as exc:
            log.warning("[AICouncilMission] LLMGuidedPostExploit failed (non-fatal): %s", exc)

        report = None
        # ── Step 8: ScribeAgent — generate report ─────────────────────────
        try:
            from oneinfinity.agents.scribe_agent import ScribeAgent
            sp_d  = (surface_profile.to_dict() if hasattr(surface_profile, "to_dict")
                     else (surface_profile.__dict__ if surface_profile else {}))
            ep_d  = (exploit_plan.to_dict() if hasattr(exploit_plan, "to_dict")
                     else (exploit_plan.__dict__ if exploit_plan else {}))
            et_d  = (exploit_trace.to_dict() if hasattr(exploit_trace, "to_dict")
                     else (exploit_trace.__dict__ if exploit_trace else {}))
            per_d = (post_exploit_report.to_dict() if hasattr(post_exploit_report, "to_dict")
                     else (post_exploit_report.__dict__ if post_exploit_report else {}))
            report = ScribeAgent().write(sp_d, ep_d, et_d, per_d, {}, scan_id=scan_id)
            log.info("[AICouncilMission] ScribeAgent report generated (%d chars)", len(report) if report else 0)
        except Exception as exc:
            log.warning("[AICouncilMission] ScribeAgent failed (non-fatal): %s", exc)

        # ── Step 9: Persist to council_runs ───────────────────────────────
        try:
            from oneinfinity.core.pg_client import save_council_run
            sp_d  = (surface_profile.to_dict() if hasattr(surface_profile, "to_dict")
                     else (surface_profile.__dict__ if surface_profile else {}))
            ep_d  = (exploit_plan.to_dict() if hasattr(exploit_plan, "to_dict")
                     else (exploit_plan.__dict__ if exploit_plan else {}))
            et_d  = (exploit_trace.to_dict() if hasattr(exploit_trace, "to_dict")
                     else (exploit_trace.__dict__ if exploit_trace else {}))
            overall_ok = bool(exploit_trace is not None and getattr(exploit_trace, "overall_success", False))
            success_n  = int(getattr(exploit_trace, "success_count", 0) if exploit_trace else 0)
            try:
                _asyncio.run(save_council_run(
                    scan_id=scan_id, target=target,
                    surface_profile=sp_d, exploit_plan=ep_d,
                    exploit_trace=et_d,
                    overall_success=overall_ok,
                    findings_count=success_n,
                ))
            except RuntimeError:
                # already in a running loop (background thread edge case) — fire-and-forget
                import threading as _t
                _t.Thread(
                    target=lambda: _asyncio.run(save_council_run(
                        scan_id=scan_id, target=target,
                        surface_profile=sp_d, exploit_plan=ep_d,
                        exploit_trace=et_d,
                        overall_success=overall_ok,
                        findings_count=success_n,
                    )),
                    daemon=True,
                ).start()
            log.info("[AICouncilMission] council_run persisted scan_id=%s", scan_id)
        except Exception as exc:
            log.warning("[AICouncilMission] save_council_run failed (non-fatal): %s", exc)

        # ── Step 10: add findings to session ──────────────────────────────
        try:
            success_count = int(getattr(exploit_trace, "success_count", 0) if exploit_trace else 0)
            session.add_findings(success_count)
        except Exception as exc:
            log.warning("[AICouncilMission] add_findings failed (non-fatal): %s", exc)

        # ── Step 11: mark phase complete ──────────────────────────────────
        session.phases_complete.append("ai_council")
        log.info("[GOD MODE] AICouncilMission complete — target=%s", target)
        self._result = {
            "surface_profile": bool(surface_profile),
            "exploit_plan":    bool(exploit_plan),
            "exploit_trace":   bool(exploit_trace),
            "mcp_result":      bool(mcp_result),
            "post_exploit":    bool(post_exploit_report),
            "report":          bool(report),
        }


# ── ZeroHypothesisMission ──────────────────────────────────────────────────────

class ZeroHypothesisMission(Mission):
    """
    Generates zero-day vulnerability hypotheses from the attack graph AFTER
    FullScanMission completes. Polls full_scan.is_done() before running.

    Starts alongside FullScanMission but blocks internally until FullScan completes.
    """

    def __init__(self, full_scan: "FullScanMission", foundation: "FoundationMission") -> None:
        super().__init__("zero_hypothesis")
        self._full_scan = full_scan
        self._foundation = foundation

    def _run(self, session: GodModeSession) -> None:
        import time as _time
        # Wait for FullScanMission to complete (or stop event)
        log.info("[GOD MODE] ZeroHypothesisMission: waiting for FullScanMission to complete")
        while not self._full_scan.is_done() and not self._stop_event.is_set():
            _time.sleep(5)

        if self._full_scan.status != "done":
            log.warning("[GOD MODE] ZeroHypothesisMission: FullScanMission did not complete (status=%s) — skipping",
                        self._full_scan.status)
            self._result = {"hypotheses": 0, "skipped": True}
            return

        log.info("[GOD MODE] ZeroHypothesisMission: FullScan done — generating hypotheses for %s", session.target)

        hypotheses = []
        try:
            from oneinfinity.intelligence.zero_day_hypothesis import ZeroDayHypothesisEngine
            engine = ZeroDayHypothesisEngine()
            hypotheses = engine.generate(target=session.target, top_n=25) or []
        except ImportError:
            log.debug("[GOD MODE] ZeroHypothesisMission: ZeroDayHypothesisEngine not available")
        except Exception as exc:
            log.warning("[GOD MODE] ZeroHypothesisMission: hypothesis generation failed: %s", exc)

        count = len(hypotheses)
        log.info("[GOD MODE] ZeroHypothesisMission: generated %d hypotheses", count)
        session.phases_complete.append("zero_hypothesis")

        if hypotheses:
            session.add_findings(count)
            try:
                from oneinfinity.findings.result_ingestion_engine import get_ingestion_engine, RawResult
                bus = get_ingestion_engine()
                for h in hypotheses:
                    fd = h.to_dict() if hasattr(h, "to_dict") else (h.__dict__ if hasattr(h, "__dict__") else {})
                    if fd:
                        bus.ingest(RawResult(scan_id=session.scan_id, source="god-mode-zero-hypothesis", raw=fd))
            except Exception as exc:
                log.warning("[GOD MODE] ZeroHypothesisMission ingestion failed: %s", exc)

            # Emit events so ResearchMission can act on hypotheses
            try:
                from oneinfinity.orchestration.event_bus import get_bus, EventType
                ebus = get_bus()
                for h in hypotheses:
                    fd = h.to_dict() if hasattr(h, "to_dict") else {}
                    if fd:
                        ebus.publish(EventType.NEW_VULNERABILITY, fd, source="god-mode-zero-hypothesis")
            except Exception as exc:
                log.warning("[GOD MODE] ZeroHypothesisMission event publish failed: %s", exc)

        self._result = {"hypotheses": count}


# ── AdvancedScanMission ─────────────────────────────────────────────────────────

class AdvancedScanMission(Mission):
    """
    Runs UnifiedAdvancedScanner as a parallel 'second opinion' mission
    alongside FullScanMission. Always-on — starts immediately with FullScan.

    Deduplication: if FullScanMission's executor already wrote
    advanced_findings.json (via _inline_advanced_scan), we ingest from that
    file instead of re-running the 32-scanner battery (~40 min saved).
    """

    def __init__(self, foundation: "FoundationMission", auth_config: dict = None,
                 full_scan_mission: "FullScanMission" = None) -> None:
        super().__init__("advanced_scan_mission")
        self._foundation = foundation
        self._auth_config = auth_config or {}
        self._full_scan_mission = full_scan_mission

    @staticmethod
    def _advanced_findings_exist(session: "GodModeSession") -> bool:
        """Return True if executor already wrote a non-empty advanced_findings.json."""
        p = GOD_MODE_DIR / session.scan_id / "full_scan" / "advanced_findings.json"
        try:
            if p.exists() and p.stat().st_size > 2:
                data = json.loads(p.read_text())
                return bool(data.get("findings") or data.get("count", 0))
        except Exception:
            pass
        return False

    def _run(self, session: GodModeSession) -> None:
        import json as _json

        log.info("[GOD MODE] AdvancedScanMission: starting for %s", session.target)
        out_dir = str(GOD_MODE_DIR / session.scan_id / "advanced_mission")
        Path(out_dir).mkdir(parents=True, exist_ok=True)

        # Wait for FullScanMission to complete before deciding whether to re-run
        if self._full_scan_mission is not None:
            log.info("[GOD MODE] AdvancedScanMission: waiting for FullScanMission to complete…")
            while not self._full_scan_mission.is_done():
                if self._stop_event.wait(timeout=5.0):
                    log.info("[GOD MODE] AdvancedScanMission: stop requested while waiting")
                    self._result = {"findings": 0, "output_dir": out_dir, "skipped": "stopped"}
                    return

        # Check if executor already produced advanced_findings.json
        if self._advanced_findings_exist(session):
            adv_path = GOD_MODE_DIR / session.scan_id / "full_scan" / "advanced_findings.json"
            log.info("[GOD MODE] AdvancedScanMission: executor already produced advanced_findings.json — ingesting, skip re-run")
            new_count = 0
            try:
                data = _json.loads(adv_path.read_text())
                findings = data.get("findings", [])
                new_count = data.get("total_findings", len(findings))
                session.add_findings(new_count)
                if findings:
                    from oneinfinity.findings.result_ingestion_engine import get_ingestion_engine, RawResult
                    bus = get_ingestion_engine()
                    for f in findings:
                        if isinstance(f, dict):
                            bus.ingest(RawResult(scan_id=session.scan_id,
                                                 source="god-mode-advanced-mission", raw=f))
            except Exception as exc:
                log.warning("[GOD MODE] AdvancedScanMission ingest from existing file failed: %s", exc)
            session.phases_complete.append("advanced_scan_mission")
            log.info("[GOD MODE] AdvancedScanMission complete (from executor cache) — %d findings", new_count)
            self._result = {"findings": new_count, "output_dir": out_dir, "source": "executor_cache"}
            return

        # Full scan didn't run the advanced phase — run it now
        import asyncio as _asyncio
        log.info("[GOD MODE] AdvancedScanMission: running 17-phase UnifiedAdvancedScanner for %s", session.target)
        result = None
        try:
            from oneinfinity.scan.unified_advanced_scanner import UnifiedAdvancedScanner
            scanner = UnifiedAdvancedScanner(target=session.target)
            result = _asyncio.run(
                _asyncio.wait_for(
                    scanner.run_full_scan(account_configs=None, oob_domain=None),
                    timeout=1800,
                )
            )
        except _asyncio.TimeoutError:
            log.warning("[GOD MODE] AdvancedScanMission: timed out after 1800s — using partial results")
        except ImportError:
            log.debug("[GOD MODE] AdvancedScanMission: UnifiedAdvancedScanner not available")
        except Exception as exc:
            log.warning("[GOD MODE] AdvancedScanMission: run_full_scan error (non-fatal): %s", exc)

        new_count = 0
        if result is not None:
            raw = result.to_dict() if hasattr(result, "to_dict") else {}
            findings = raw.get("idor_findings", []) + raw.get("race_findings", []) + raw.get("bypass_findings", [])
            # Quick count — detailed breakdown written by Phase 2 pipeline phase
            new_count = raw.get("total_findings", len(findings))
            session.add_findings(new_count)
            if findings:
                try:
                    from oneinfinity.findings.result_ingestion_engine import get_ingestion_engine, RawResult
                    bus = get_ingestion_engine()
                    for f in findings:
                        if isinstance(f, dict):
                            bus.ingest(RawResult(scan_id=session.scan_id, source="god-mode-advanced-mission", raw=f))
                except Exception as exc:
                    log.warning("[GOD MODE] AdvancedScanMission ingestion failed: %s", exc)

        session.phases_complete.append("advanced_scan_mission")
        log.info("[GOD MODE] AdvancedScanMission complete — %d findings", new_count)
        self._result = {"findings": new_count, "output_dir": out_dir}


# ── ReportMission ──────────────────────────────────────────────────────────────

class ReportMission(Mission):
    """
    Finalization — always runs regardless of termination condition.
    Steps: validate → dedup → capmap → learn.
    Each step is independently try/except wrapped.
    """

    def __init__(self, report_fmt: str = "markdown"):
        super().__init__("report")
        self._report_fmt = report_fmt

    def run_sync(self, session: GodModeSession) -> None:
        """Run finalization synchronously so conductor waits for it."""
        log.info("[GOD MODE] Stage 5: Finalization starting")
        self.status = "running"
        try:
            self._run(session)
            self.status = "done"
        except Exception as exc:
            log.warning("[GOD MODE] ReportMission failed: %s", exc, exc_info=True)
            self.status = "failed"

    def _run(self, session: GodModeSession) -> None:
        # Step 1: validate findings
        try:
            from oneinfinity.findings.result_ingestion_engine import get_ingestion_engine
            from oneinfinity.orchestration.enforcement_controller import get_enforcement_controller
            raw_findings = get_ingestion_engine().get_findings(scan_id=session.scan_id, target=session.target) or []
            validated = get_enforcement_controller().validate_findings(raw_findings)
            log.info("[GOD MODE] Report: validated %d/%d findings", len(validated), len(raw_findings))
        except Exception as exc:
            log.warning("[GOD MODE] Report: validation failed (non-fatal): %s", exc, exc_info=True)
            validated = []

        # Step 2: dedup
        try:
            from oneinfinity.core.deduplicator import Deduplicator
            validated = Deduplicator().filter_new(validated)
            log.info("[GOD MODE] Report: %d unique findings after dedup", len(validated))
        except Exception as exc:
            log.warning("[GOD MODE] Report: dedup failed (non-fatal): %s", exc, exc_info=True)

        # Step 3: capmap coverage
        try:
            found_types = [f.get("vuln_type", "") for f in validated if isinstance(f, dict)]
            from oneinfinity.modules.capability_map import Vuln
            all_classes = {v for k, v in vars(Vuln).items() if not k.startswith("_") and isinstance(v, str)}
            covered = {vt for vt in found_types if vt}
            uncovered = all_classes - covered
            log.info("[GOD MODE] Capmap: %d/%d vuln classes covered. Uncovered: %s",
                     len(covered), len(all_classes), sorted(uncovered)[:5] if uncovered else "none")
        except Exception as exc:
            log.warning("[GOD MODE] Report: capmap check failed (non-fatal): %s", exc, exc_info=True)

        # Step 4: learn
        try:
            import types
            from oneinfinity.learning import LearningSystem
            ls = LearningSystem()
            task_result = types.SimpleNamespace(
                target=session.target,
                findings=validated,
                tools_used=[],
                success=True,
                duration=session.elapsed(),
            )
            ls.record_result(task_result)
            ls.close()
            log.info("[GOD MODE] Report: learning system updated")
        except Exception as exc:
            log.warning("[GOD MODE] Report: learning update failed (non-fatal): %s", exc, exc_info=True)

        session.phases_complete.append("report")
        self._result = {"validated_findings": len(validated)}


# ── GodModeConductor ───────────────────────────────────────────────────────────

class GodModeConductor:
    """
    Master orchestrator for GOD MODE.
    Manages mission lifecycle and convergence loop.
    """

    def __init__(self):
        self._session: Optional[GodModeSession] = None
        self._state_file: Optional[GodModeStateFile] = None
        self._convergence = ConvergenceChecker()
        self._foundation: Optional[FoundationMission] = None
        self._missions: list[Mission] = []
        self._lock = threading.Lock()
        self._log_handler: Optional[logging.FileHandler] = None
        self._wakeup = threading.Event()  # set by stop() to interrupt convergence loop sleep

        # Event bus counters (guarded by _lock)
        self._vuln_count: int = 0
        self._endpoint_count: int = 0
        self._research_iters_done: int = 0

        # Phase C+F: auth-tier state (guarded by _lock)
        self._auth_ctx_registry: dict = {}       # session_id → AuthSessionContext
        self._spawned_auth_tiers: set = set()    # session_ids already spawned (dedup guard)
        self._tested_endpoints: dict = {}        # session_id → set[str] (anti-retesting)
        self._idor_engine = None                 # MultiAccountIDOREngine (lazy-init on first cred)
        self._idor_accounts: list = []           # AccountContext objects accumulated

        # Event bus unsubscribe handles
        self._bus_handlers: list = []

        # Findings pipeline components (wired in after each phase)
        try:
            from oneinfinity.findings.confirmed_pipeline import ConfirmationCoordinator
            self._confirmation_coordinator = ConfirmationCoordinator()
        except Exception as _e:
            log.warning("[GOD MODE] ConfirmationCoordinator unavailable: %s", _e)
            self._confirmation_coordinator = None

        try:
            from oneinfinity.findings.confidence_engine import ConfidenceEngine
            self._confidence_engine = ConfidenceEngine(auto_upgrade=True)
        except Exception as _e:
            log.warning("[GOD MODE] ConfidenceEngine unavailable: %s", _e)
            self._confidence_engine = None

        try:
            from oneinfinity.findings.result_aggregator import ResultAggregator
            self._result_aggregator = ResultAggregator()
        except Exception as _e:
            log.warning("[GOD MODE] ResultAggregator unavailable: %s", _e)
            self._result_aggregator = None

        # Learning stack — wired at conductor construction
        self._learner = None
        try:
            from oneinfinity.learning.realtime_learner import RealtimeLearner
            self._learner = RealtimeLearner()
            self._learner.start()
            log.info("[GOD MODE] RealtimeLearner started")
        except Exception as _le:
            log.debug("[GOD MODE] RealtimeLearner unavailable (non-fatal): %s", _le)

        # Orchestrator integration — activates ModelOrchestrator + EventDrivenEngine + GraphTriggerEngine
        try:
            from oneinfinity.orchestration.orchestrator_integration import activate as _orchestrator_activate
            _orchestrator_activate()
            log.info("[GOD MODE] ModelOrchestrator + EventDrivenEngine + GraphTriggerEngine activated")
        except Exception as _oa_exc:
            log.debug("[GOD MODE] orchestrator_integration.activate failed (non-fatal — requires Redis/Neo4j): %s", _oa_exc)

    # ── Event bus ─────────────────────────────────────────────────────────────

    def _subscribe_to_event_bus(self) -> None:
        try:
            from oneinfinity.orchestration.event_bus import get_bus, EventType

            def _on_vuln(event) -> None:
                with self._lock:
                    self._vuln_count += 1
                    count = self._vuln_count
                if count == EVENT_UNLOCK_VULN_THRESHOLD:
                    log.info("[GOD MODE] %d vulns → unlocking ResearchMission", count)
                    self._unlock_mission("research")

            def _on_endpoint(event) -> None:
                with self._lock:
                    self._endpoint_count += 1
                    count = self._endpoint_count
                if count == EVENT_UNLOCK_ENDPOINT_THRESHOLD:
                    log.info("[GOD MODE] %d endpoints → unlocking SwarmMission", count)
                    self._unlock_mission("swarm")
                # Also unlock AIRedTeamMission if a new endpoint looks like an AI API
                _event_url = (event.data or {}).get("url", "")
                if any(hint in _event_url.lower() for hint in AIRedTeamMission._AI_PATH_HINTS):
                    log.info("[GOD MODE] AI endpoint detected (%s) → unlocking AIRedTeamMission", _event_url)
                    self._unlock_mission("ai_red_team")

            def _on_credential_acquired(event) -> None:
                """Phase C: spawn scoped auth-tiered recon + Phase F: feed IDOR engine."""
                data = event.data or {}
                session_id = data.get("session_id", "")
                target = data.get("target") or (self._session.target if self._session else "")
                scan_id = data.get("scan_id", "")
                auth_tier = data.get("auth_tier", 1)
                username = data.get("username", "unknown")
                # Foundation CREDENTIAL_ACQUIRED events (GitHub secrets, OSINT) do not include
                # session_id. Synthesise a stable one from (source, secret_type, repo) so
                # Phase C + Phase F can fire for these credentials too.
                if not session_id:
                    _src = data.get("source", "unknown")
                    _stype = data.get("secret_type", "unknown")
                    _repo = data.get("repo", "")
                    session_id = f"cred-{_src[:8]}-{_stype[:8]}-{uuid.uuid4().hex[:8]}"
                    log.debug("[GOD MODE] CREDENTIAL_ACQUIRED: synthesised session_id=%s (source=%s)", session_id, _src)
                if not self._session:
                    return
                with self._lock:
                    if session_id in self._spawned_auth_tiers:
                        log.debug("[GOD MODE] CREDENTIAL_ACQUIRED duplicate skipped for session %s", session_id)
                        return
                    self._spawned_auth_tiers.add(session_id)
                log.info("[GOD MODE] CREDENTIAL_ACQUIRED — username=%s tier=%d — spawning scoped recon",
                         username, auth_tier)
                # Spawn scoped recon in a daemon thread (PE2: sync handler, no await)
                threading.Thread(
                    target=self._run_scoped_auth_recon,
                    args=(target, session_id, auth_tier, scan_id),
                    daemon=True,
                    name=f"auth-recon-tier{auth_tier}-{session_id[:8]}",
                ).start()
                # Phase F: feed MultiAccountIDOREngine
                threading.Thread(
                    target=self._feed_idor_engine,
                    args=(session_id, data.get("role_hint", "attacker"), target, scan_id),
                    daemon=True,
                    name=f"idor-feed-{session_id[:8]}",
                ).start()

            def _on_surface_enriched(event) -> None:
                """Run AuthenticatedTestSuite on newly discovered auth-tier endpoints."""
                data = event.data or {}
                new_urls = data.get("new_urls", [])
                session_id = data.get("source_session_id", "")
                target = data.get("target", "")
                scan_id = data.get("scan_id", "")
                if not new_urls or not session_id:
                    return
                auth_ctx = self._auth_ctx_registry.get(session_id)
                if not auth_ctx:
                    return
                threading.Thread(
                    target=self._run_auth_test_suite,
                    args=(target, new_urls, auth_ctx, session_id, scan_id),
                    daemon=True,
                    name=f"auth-test-{session_id[:8]}",
                ).start()

            bus = get_bus()
            bus.on(EventType.NEW_VULNERABILITY, _on_vuln)
            bus.on(EventType.NEW_ENDPOINT, _on_endpoint)
            bus.on(EventType.CREDENTIAL_ACQUIRED, _on_credential_acquired)
            bus.on(EventType.SURFACE_ENRICHED, _on_surface_enriched)
            self._bus_handlers = [
                (EventType.NEW_VULNERABILITY, _on_vuln),
                (EventType.NEW_ENDPOINT, _on_endpoint),
                (EventType.CREDENTIAL_ACQUIRED, _on_credential_acquired),
                (EventType.SURFACE_ENRICHED, _on_surface_enriched),
            ]
            log.info("[GOD MODE] Event bus subscriptions active (incl. CREDENTIAL_ACQUIRED)")
        except Exception as exc:
            log.warning("[GOD MODE] Event bus subscription failed (non-fatal): %s", exc)

    def _unsubscribe_from_event_bus(self) -> None:
        try:
            from oneinfinity.orchestration.event_bus import get_bus
            bus = get_bus()
            for event_type, handler in self._bus_handlers:
                try:
                    bus.off(event_type, handler)
                except Exception:
                    pass
        except Exception as exc:
            log.warning("[GOD MODE] Event bus unsubscribe failed: %s", exc)
        self._bus_handlers = []

    def _run_scoped_auth_recon(self, target: str, session_id: str,
                                auth_tier: int, scan_id: str) -> None:
        """Phase C: Run AdaptiveReconEngine scoped to a new auth tier.
        Copies tier-0 artifacts so phases 1-3 are skipped; only the
        auth-aware Playwright crawl adds new surface.
        DA2 design: output_dir namespacing + set-diff for SURFACE_ENRICHED.
        """
        try:
            from oneinfinity.auth.session_manager import SessionManager
            from oneinfinity.auth.auth_session_context import AuthSessionContext
            from oneinfinity.recon.adaptive_recon_engine import AdaptiveReconEngine
            from oneinfinity.orchestration.event_bus import get_bus, EventType
            import shutil

            session = (SessionManager().load(name=f"spray_{session_id}") or
                       SessionManager().load(name=session_id))
            if not session:
                log.warning("[GOD MODE] _run_scoped_auth_recon: session %s not found", session_id)
                return

            auth_ctx = AuthSessionContext(session)
            with self._lock:
                self._auth_ctx_registry[session_id] = auth_ctx

            # Scoped output dir (DA2: separate from tier-0 to avoid cache collision)
            scoped_out = GOD_MODE_DIR / scan_id / f"recon_tier{auth_tier}_{session_id[:8]}"
            scoped_out.mkdir(parents=True, exist_ok=True)

            # Copy tier-0 artifacts so _load_existing_recon() skips phases 1-3
            tier0_dir = GOD_MODE_DIR / scan_id / "recon"
            for fname in ("subdomains.json", "alive_hosts.json", "urls.json"):
                src = tier0_dir / fname
                dst = scoped_out / fname
                if src.exists() and not dst.exists():
                    shutil.copy2(src, dst)

            # Load tier-0 URL set for delta computation
            tier0_urls: set = set()
            urls_file = tier0_dir / "urls.json"
            if urls_file.exists():
                import json as _j
                tier0_urls = set(_j.loads(urls_file.read_text()))

            log.info("[GOD MODE] Scoped auth recon starting — tier=%d session=%s", auth_tier, session_id[:8])
            engine = AdaptiveReconEngine(
                target=target,
                output_dir=str(scoped_out),
                depth="standard",
                auth_context=auth_ctx,
            )
            intel = engine.run()

            # Compute new surface vs tier-0
            auth_urls = set(intel.all_urls) if intel and intel.all_urls else set()
            new_urls = auth_urls - tier0_urls
            log.info("[GOD MODE] Scoped auth recon complete — %d total URLs, %d new vs tier-0",
                     len(auth_urls), len(new_urls))

            if new_urls:
                # Emit SURFACE_ENRICHED with delta URLs
                get_bus().publish(
                    EventType.SURFACE_ENRICHED,
                    {
                        "target": target,
                        "auth_tier": auth_tier,
                        "new_urls": sorted(new_urls),
                        "all_urls": sorted(auth_urls),
                        "source_session_id": session_id,
                        "scan_id": scan_id,
                        "endpoints_found": len(new_urls),
                    },
                    source="auth-recon",
                    correlation_id=scan_id,
                )
            # Emit AUTH_TIER_UNLOCKED for convergence tracking
            get_bus().publish(
                EventType.AUTH_TIER_UNLOCKED,
                {"auth_tier": auth_tier, "target": target, "scan_id": scan_id,
                 "endpoints_found": len(auth_urls)},
                source="auth-recon",
            )
        except Exception as exc:
            log.warning("[GOD MODE] _run_scoped_auth_recon failed (non-fatal): %s", exc, exc_info=True)

    def _run_auth_test_suite(self, target: str, new_urls: list, auth_ctx,
                              session_id: str, scan_id: str) -> None:
        """Run AuthenticatedTestSuite on newly discovered auth-tier endpoints.
        RTL2 anti-retesting: skip endpoints already tested for this session.
        """
        try:
            from oneinfinity.auth.authenticated_test_suite import AuthenticatedTestSuite
            from oneinfinity.findings.result_ingestion_engine import get_ingestion_engine, RawResult

            # Anti-retesting: filter endpoints already tested for this session
            already_tested = self._tested_endpoints.get(session_id, set())
            fresh_eps = [ep for ep in new_urls if ep not in already_tested]
            if not fresh_eps:
                log.debug("[GOD MODE] AuthTestSuite: no new endpoints for session %s", session_id[:8])
                return

            # Limit to 200 endpoints per run (RTL2 recommendation)
            fresh_eps = fresh_eps[:200]
            log.info("[GOD MODE] AuthTestSuite running %d endpoints for session %s",
                     len(fresh_eps), session_id[:8])

            suite = AuthenticatedTestSuite(target=target, endpoints=fresh_eps, auth_context=auth_ctx)
            findings = suite.run_all()

            # Mark tested
            with self._lock:
                self._tested_endpoints.setdefault(session_id, set()).update(fresh_eps)

            # Ingest findings
            if findings:
                ie = get_ingestion_engine()
                for f in findings:
                    try:
                        ie.ingest(RawResult(
                            scan_id=scan_id,
                            source="auth-test-scoped",
                            raw=f.to_dict() if hasattr(f, "to_dict") else f.__dict__,
                        ))
                    except Exception as _ie:
                        log.debug("[GOD MODE] AuthTestSuite ingest error: %s", _ie)
                log.info("[GOD MODE] AuthTestSuite complete — %d findings ingested", len(findings))
                if self._session:
                    self._session.add_findings(len(findings))
        except Exception as exc:
            log.warning("[GOD MODE] _run_auth_test_suite failed (non-fatal): %s", exc, exc_info=True)

    def _feed_idor_engine(self, session_id: str, role: str, target: str, scan_id: str) -> None:
        """Phase F: Feed MultiAccountIDOREngine with new credential.
        RTL2: buffer accounts, trigger test when ≥2 accounts available.
        """
        try:
            from oneinfinity.auth.session_manager import SessionManager
            from oneinfinity.auth.multi_account_idor_engine import (
                MultiAccountIDOREngine, AccountContext, get_multi_account_idor_engine
            )
            from oneinfinity.findings.result_ingestion_engine import get_ingestion_engine, RawResult
            import asyncio as _asyncio

            session = (SessionManager().load(name=f"spray_{session_id}") or
                       SessionManager().load(name=session_id))
            if not session:
                log.warning("[GOD MODE] _feed_idor_engine: session %s not found", session_id)
                return

            account = AccountContext(role=role, session=session)
            engine = get_multi_account_idor_engine(target)
            engine.add_account_from_session(role=role, session=session)

            with self._lock:
                self._idor_accounts.append(account)
                account_count = len(self._idor_accounts)

            log.info("[GOD MODE] IDOR engine: %d accounts loaded (need ≥2 to run)", account_count)

            # Need at least 2 accounts for cross-account IDOR testing
            if account_count < 2:
                # Add anonymous baseline account if none exists yet (OR2 recommendation)
                from oneinfinity.auth.session_manager import LoginSession
                import uuid as _uuid, time as _time
                anon_session = LoginSession(
                    session_id=f"anon_{scan_id[:8]}",
                    target=target,
                    login_url=target,
                    cookies=[], auth_headers={}, local_storage={},
                    session_storage={}, indexeddb_snapshot={},
                    har_path="", recorder="anon_baseline",
                )
                engine.add_account_from_session(role="victim_anon", session=anon_session)
                with self._lock:
                    self._idor_accounts.append(AccountContext(role="victim_anon", session=anon_session))
                log.info("[GOD MODE] IDOR engine: added anonymous baseline account")

            # Run IDOR tests
            log.info("[GOD MODE] Triggering MultiAccountIDOREngine for target %s", target)
            idor_findings = _asyncio.run(engine.test_all_captured_traffic())

            if idor_findings:
                ie = get_ingestion_engine()
                for f in idor_findings:
                    try:
                        ie.ingest(RawResult(
                            scan_id=scan_id,
                            source="idor-engine",
                            raw=f.to_dict() if hasattr(f, "to_dict") else (f.__dict__ if hasattr(f, "__dict__") else {}),
                        ))
                    except Exception as _ie:
                        log.debug("[GOD MODE] IDOR ingest error: %s", _ie)
                log.info("[GOD MODE] IDOR engine complete — %d findings", len(idor_findings))
                if self._session:
                    self._session.add_findings(len(idor_findings))
        except Exception as exc:
            log.warning("[GOD MODE] _feed_idor_engine failed (non-fatal): %s", exc, exc_info=True)

    def _unlock_mission(self, name: str) -> None:
        """Start a mission by name if it's still pending."""
        if self._session is None:
            return
        for m in self._missions:
            if m.name == name and m.status in ("pending", "failed"):
                log.info("[GOD MODE] Starting mission: %s", name)
                m.start(self._session)
                self._update_session_missions()
                break

    def _update_session_missions(self) -> None:
        """Sync mission statuses into session and persist."""
        if self._session and self._state_file:
            self._session.missions = {m.name: m.status for m in self._missions}
            self._state_file.write(self._session)

    # ── Status + Stop ─────────────────────────────────────────────────────────

    def status(self, scan_id: Optional[str] = None) -> Optional[dict]:
        """Read state from disk. Returns None if session not found."""
        if scan_id:
            sf = GodModeStateFile(scan_id)
            return sf.read()
        # Find most recent
        latest = GodModeStateFile.find_latest()
        if latest:
            try:
                return json.loads(latest.read_text())
            except Exception:
                return None
        return None

    def stop(self, scan_id: Optional[str] = None) -> bool:
        """Write stop sentinel. Returns True if sentinel written."""
        if scan_id is None and self._session:
            scan_id = self._session.scan_id
        if not scan_id:
            # Find latest
            latest = GodModeStateFile.find_latest()
            if latest:
                scan_id = latest.stem.replace("god-mode-", "")
        if not scan_id:
            return False
        # Verify the session exists on disk OR is the active in-memory session
        state_file_exists = GodModeStateFile(scan_id).path.exists()
        in_memory_match = self._session is not None and self._session.scan_id == scan_id
        if not state_file_exists and not in_memory_match:
            return False
        sentinel = GodModeStateFile.stop_sentinel_path(scan_id)
        sentinel.touch()
        log.info("[GOD MODE] Stop sentinel written for %s", scan_id)
        # Wake up the convergence loop immediately instead of waiting for the next 30s tick
        self._wakeup.set()
        return True

    # ── Findings pipeline helpers ──────────────────────────────────────────────

    def _apply_findings_pipeline(self, findings: list, scan_id: str = "") -> list:
        """
        Score confidence on all findings, store updated scores in PostgreSQL,
        then dispatch ConfirmationCoordinator.process() for confirmed findings.
        Returns the updated findings list.
        """
        if not findings:
            return findings

        # 1. Re-score confidence
        if self._confidence_engine is not None:
            try:
                findings = self._confidence_engine.score_all(findings)
                log.info("[GOD MODE] confidence_engine.score_all: %d findings re-scored", len(findings))
            except Exception as _ce:
                log.warning("[GOD MODE] confidence_engine.score_all failed: %s", _ce)

        # 2. Persist updated confidence to PostgreSQL
        self._pg_update_confidence(findings, scan_id)

        # 3. Run ConfirmationCoordinator post-confirmation actions
        if self._confirmation_coordinator is not None:
            try:
                confirmed = self._confirmation_coordinator.process(findings)
                log.info("[GOD MODE] ConfirmationCoordinator processed %d confirmed findings", confirmed)
            except Exception as _cc:
                log.warning("[GOD MODE] ConfirmationCoordinator.process failed: %s", _cc)

        return findings

    def _pg_update_confidence(self, findings: list, scan_id: str) -> None:
        """Upsert finding confidence scores into PostgreSQL findings table."""
        if not findings:
            return
        try:
            import asyncio as _asyncio
            from oneinfinity.core.db_manager import get_db_manager_sync

            async def _upsert_all():
                mgr = get_db_manager_sync()
                if not mgr:
                    return
                for f in findings:
                    fid  = f.get("finding_id") or f.get("id")
                    conf = f.get("confidence")
                    sev  = f.get("severity")
                    if not fid or conf is None:
                        continue
                    try:
                        await mgr.execute(
                            """
                            UPDATE findings
                               SET confidence        = $1,
                                   severity          = $2,
                                   confidence_breakdown = $3,
                                   updated_at        = NOW()
                             WHERE finding_id = $4
                                OR id          = $4
                            """,
                            conf,
                            sev or f.get("severity", "info"),
                            f.get("confidence_breakdown", ""),
                            str(fid),
                        )
                    except Exception as _row_exc:
                        log.debug("[GOD MODE] _pg_update_confidence row %s: %s", fid, _row_exc)

            try:
                _asyncio.run(_upsert_all())
            except RuntimeError:
                # Already inside an event loop
                import concurrent.futures as _cf
                with _cf.ThreadPoolExecutor(max_workers=1) as _ex:
                    _ex.submit(_asyncio.run, _upsert_all()).result(timeout=10)
        except Exception as exc:
            log.debug("[GOD MODE] _pg_update_confidence failed: %s", exc)

    # ── Logging setup ─────────────────────────────────────────────────────────

    def _setup_logging(self, scan_id: str) -> str:
        """Set up file logging for GOD MODE session. Returns log path."""
        import re as _re

        class _TokenRedactFilter(logging.Filter):
            """Redact Bearer tokens and API keys from all log records."""
            _BEARER_RE = _re.compile(r'Bearer\s+[A-Za-z0-9._\-]{20,}', _re.I)
            _APIKEY_RE = _re.compile(r'(api[_-]?key|x-api-key|authorization)[=:\s]+[A-Za-z0-9._\-]{16,}', _re.I)

            def filter(self, record: logging.LogRecord) -> bool:
                msg = record.getMessage()
                msg = self._BEARER_RE.sub('Bearer [REDACTED]', msg)
                msg = self._APIKEY_RE.sub(r'\1=[REDACTED]', msg)
                record.msg = msg
                record.args = ()
                return True

        GOD_MODE_LOG_DIR.mkdir(parents=True, exist_ok=True)
        log_path = str(GOD_MODE_LOG_DIR / f"god-mode-{scan_id}.log")
        fh = logging.FileHandler(log_path, encoding="utf-8")
        fh.setLevel(logging.DEBUG)
        fh.setFormatter(logging.Formatter("%(asctime)s %(levelname)s %(message)s"))
        fh.addFilter(_TokenRedactFilter())
        logging.getLogger("oneinfinity").addHandler(fh)
        self._log_handler = fh
        return log_path

    def _teardown_logging(self) -> None:
        if self._log_handler:
            try:
                logging.getLogger("oneinfinity").removeHandler(self._log_handler)
                self._log_handler.close()
            except Exception:
                pass
            self._log_handler = None

    # ── Convergence loop ──────────────────────────────────────────────────────

    def _convergence_loop(self) -> str:
        """
        Polls every 30s for termination conditions.
        Returns the reason: 'convergence'|'time'|'cap'|'stop'|'all_done'.
        """
        if self._session is None:
            raise RuntimeError("_convergence_loop() called before session is initialized")
        session = self._session

        while True:
            # Check stop sentinel immediately before waiting (catches stop written before loop starts)
            sentinel = GodModeStateFile.stop_sentinel_path(session.scan_id)
            if sentinel.exists():
                log.info("[GOD MODE] Stop sentinel detected — finalizing")
                return "stop"

            # Wait up to 30s, but wake immediately if stop() signals _wakeup
            self._wakeup.wait(timeout=30)
            self._wakeup.clear()

            # Re-check sentinel right after wakeup (could be a stop signal)
            if sentinel.exists():
                log.info("[GOD MODE] Stop sentinel detected — finalizing")
                return "stop"

            # Convergence
            found_types: list[str] = []
            try:
                from oneinfinity.findings.result_ingestion_engine import get_ingestion_engine
                findings = get_ingestion_engine().get_findings() or []
                found_types = [f.get("vuln_type", "") for f in findings if isinstance(f, dict)]
            except Exception:
                pass
            if self._convergence.is_converged(found_types):
                log.info("[GOD MODE] Convergence detected — finalizing")
                return "convergence"

            # max_time guard (0 = unlimited)
            if session.max_time > 0 and session.elapsed() >= session.max_time:
                log.info("[GOD MODE] Max time %ds reached — finalizing", session.max_time)
                return "time"

            # max_findings guard (0 = unlimited)
            if session.max_findings > 0 and session.finding_count >= session.max_findings:
                log.info("[GOD MODE] Max findings cap %d reached — finalizing", session.max_findings)
                return "cap"

            # Fallback unlock: event bus fires from subprocesses can race with shutdown.
            # Re-check unlock thresholds directly from session finding/endpoint counts.
            with self._lock:
                vuln_count    = self._vuln_count
                endpoint_count = self._endpoint_count
            if session.finding_count > 0 and vuln_count < EVENT_UNLOCK_VULN_THRESHOLD:
                # findings exist but event never fired — unlock research now
                with self._lock:
                    self._vuln_count = EVENT_UNLOCK_VULN_THRESHOLD
                log.info("[GOD MODE] Fallback unlock: %d findings found — triggering ResearchMission",
                         session.finding_count)
                self._unlock_mission("research")
            if session.finding_count > 0 and endpoint_count < EVENT_UNLOCK_ENDPOINT_THRESHOLD:
                # pipeline ran endpoints — unlock swarm via fallback
                with self._lock:
                    self._endpoint_count = EVENT_UNLOCK_ENDPOINT_THRESHOLD
                log.info("[GOD MODE] Fallback unlock: findings found — triggering SwarmMission")
                self._unlock_mission("swarm")

            # Reap missions whose thread exited without updating status (crash/kill)
            for m in self._missions:
                if m.status == "running" and m._thread is not None and not m._thread.is_alive():
                    log.warning("[GOD MODE] Mission '%s' thread dead but status still 'running' — marking done", m.name)
                    m.status = "done"

            # All missions done naturally
            active = [m for m in self._missions if m.status == "running"]
            if not active:
                log.info("[GOD MODE] All missions complete — finalizing")
                return "all_done"

            # Update state
            self._update_session_missions()
            log.debug("[GOD MODE] Convergence loop tick — elapsed=%.0fs findings=%d",
                      session.elapsed(), session.finding_count)

    # ── Main entry point ──────────────────────────────────────────────────────

    def run(
        self,
        target: str,
        background: bool = False,
        no_swarm: bool = False,
        no_research: bool = False,
        report_fmt: str = "markdown",
        auth_config: dict = None,
        _override_scan_id: str = None,
        app_context: str = "",
        max_time: int = 0,
        max_findings: int = 0,
    ) -> GodModeSession:
        """
        Run GOD MODE against target.
        Blocks until convergence (foreground) or returns after Stage 1 (background).
        """
        # ── Session setup ──────────────────────────────────────────────────
        scan_id = _override_scan_id or ("gm-" + str(uuid.uuid4())[:6])
        log_path = self._setup_logging(scan_id)
        session = GodModeSession(
            scan_id=scan_id,
            target=target,
            start_time=time.time(),
            log_path=log_path,
            background=background,
            auth_config=auth_config or {},
            app_context=app_context or "",
            max_time=int(max_time or 0),
            max_findings=int(max_findings or 0),
        )
        self._session = session
        self._state_file = GodModeStateFile(scan_id)
        self._state_file.write(session)

        log.info("[GOD MODE] Session %s started — target=%s", scan_id, target)
        print(f"\n[*] GOD MODE — Session: {scan_id}")
        print(f"    Target:    {target}")
        print(f"    Log:       {log_path}")
        if session.app_context:
            print(f"    Context:   {session.app_context[:120]}")
        if session.max_time:
            print(f"    Max time:  {session.max_time}s")
        if session.max_findings:
            print(f"    Max finds: {session.max_findings}")

        # ── Stage 1: Foundation (blocking) ─────────────────────────────────
        print(f"\n[*] Stage 1: Foundation...")
        foundation = FoundationMission()
        self._foundation = foundation
        try:
            foundation.run_sync(session)
        except FoundationError as exc:
            print(f"\n[!] GOD MODE aborted — Foundation failed: {exc}")
            session.terminated_by = "error"
            self._state_file.write(session)
            self._teardown_logging()
            return session

        # ── Auth detection (after Foundation, before stages 2-5) ──────────────
        _auth_ctx = None
        try:
            from oneinfinity.auth import LoginFormDetector, LoginSessionRecorder, SessionManager, AuthSessionContext
            _sm = SessionManager()
            _existing = _sm.load(target=target)
            if _existing:
                _auth_ctx = AuthSessionContext(_existing)
                session.auth_config = _existing.to_auth_config()
                log.info("[GOD MODE] Loaded existing auth session for %s", target)
            else:
                _detector = LoginFormDetector()
                _form = _detector.detect(target)
                if _form.has_login_form:
                    log.info("[GOD MODE] Login form detected at %s", _form.login_url)
                    _creds = None
                    import os as _os
                    _u = _os.environ.get("ONEINFINITY_USERNAME")
                    _p = _os.environ.get("ONEINFINITY_PASSWORD")
                    if _u and _p:
                        _creds = (_u, _p)
                    _rec = LoginSessionRecorder()
                    _recorded = _rec.record_auto_or_interactive(
                        login_form=_form, credentials=_creds
                    )
                    if _recorded:
                        _sm.save(_recorded)
                        _auth_ctx = AuthSessionContext(_recorded)
                        session.auth_config = _recorded.to_auth_config()
                        log.info("[GOD MODE] Auth session recorded and saved for %s", target)
                else:
                    log.info("[GOD MODE] No login form detected — scanning unauthenticated")
        except Exception as _auth_exc:
            log.warning("[GOD MODE] Auth detection failed (non-fatal): %s", _auth_exc)
        # Store auth_context as dynamic attribute (not a dataclass field — not serialized)
        session.auth_context = _auth_ctx  # type: ignore[attr-defined]

        print(f"    [+] Foundation complete — recon={'ok' if foundation.recon else 'skipped'} "
              f"app_model={'ok' if foundation.app_model else 'skipped'}")

        # ── Background detach ──────────────────────────────────────────────
        if background:
            print(f"\n[+] GOD MODE running in background. Session: {scan_id}")
            print(f"    Status:  oneinfinity god-mode status {scan_id}")
            print(f"    Logs:    oneinfinity god-mode logs --follow")
            print(f"    Stop:    oneinfinity god-mode stop {scan_id}")
            # Start background thread (non-daemon keeps process alive after main thread exits)
            bg_thread = threading.Thread(
                target=self._run_stages_2_to_5,
                args=(session, foundation, no_swarm, no_research, report_fmt),
                name="god-mode-bg",
                daemon=False,   # non-daemon: process stays alive until this thread finishes
            )
            bg_thread.start()
            return session

        # ── Foreground: run stages 2–5 directly ───────────────────────────
        self._run_stages_2_to_5(session, foundation, no_swarm, no_research, report_fmt)
        return session

    def _run_stages_2_to_5(
        self,
        session: GodModeSession,
        foundation: FoundationMission,
        no_swarm: bool,
        no_research: bool,
        report_fmt: str,
    ) -> None:
        """Stages 2-5: pipeline + event missions + convergence + report."""

        # ── Build mission list ─────────────────────────────────────────────
        full_scan = FullScanMission(foundation, auth_config=session.auth_config,
                                    findings_pipeline_cb=self._apply_findings_pipeline)
        research = ResearchMission(self._convergence) if not no_research else None
        swarm = SwarmMission() if not no_swarm else None
        auth_test = AuthTestMission(getattr(session, "auth_context", None))
        chains = ChainsMission()
        report = ReportMission(report_fmt)

        # ── Phase 4 missions ──────────────────────────────────────────────
        # AIRedTeamMission: conditional on AI target detection
        _ai_target = _is_ai_target(session.target, session.app_context, foundation.recon)
        _auth_bearer = ""
        if session.auth_config:
            _auth_bearer = (session.auth_config.get("bearer_token") or
                            session.auth_config.get("token") or
                            session.auth_config.get("bearer") or "")
            if _auth_bearer and not _auth_bearer.startswith("Bearer "):
                _auth_bearer = f"Bearer {_auth_bearer}"
        ai_red_team = (AIRedTeamMission(auth_header=_auth_bearer,
                                         findings_pipeline_cb=self._apply_findings_pipeline)
                       if _ai_target else None)
        if not _ai_target:
            log.info("[GOD MODE] AIRedTeamMission + AICouncilMission SKIPPED — target %s not detected as AI/LLM endpoint. "
                     "Set app_context='llm' or ensure recon finds /v1/chat, /completions, /ai/ etc. to enable.",
                     session.target)
        # AICouncilMission: full council pipeline, conditional on AI target
        ai_council = AICouncilMission(foundation, auth_config=session.auth_config) if _ai_target else None
        # ZeroHypothesisMission: polls until FullScan done
        zero_hypothesis = ZeroHypothesisMission(full_scan, foundation)
        # AdvancedScanMission: parallel cross-validation scanner (always-on)
        advanced_scan_mission = AdvancedScanMission(foundation, auth_config=session.auth_config,
                                                    full_scan_mission=full_scan)

        self._missions = [m for m in [
            full_scan, advanced_scan_mission, zero_hypothesis, ai_red_team,
            ai_council, research, swarm, auth_test, chains, report
        ] if m is not None]
        self._update_session_missions()

        # ── Intelligence Daemon: start autonomous OSINT workers ───────────
        try:
            from oneinfinity.intelligence.intelligence_daemon import IntelligenceDaemon
            _intel_daemon = IntelligenceDaemon()
            _intel_daemon.start(target=session.target)
            log.info("[GOD MODE] IntelligenceDaemon started — 9 autonomous OSINT workers active for %s", session.target)
        except Exception as _id_exc:
            log.debug("[GOD MODE] IntelligenceDaemon start failed (non-fatal): %s", _id_exc)

        # ── Orchestrator integration + learner scan init ──────────────────
        try:
            from oneinfinity.orchestration.orchestrator_integration import activate
            activate()
        except Exception as _act_exc:
            log.debug("[GOD MODE] orchestrator_integration.activate failed (non-fatal): %s", _act_exc)
        if self._learner is not None:
            try:
                self._learner.start_scan(scan_id=session.scan_id, target=session.target)
            except Exception as _ls_exc:
                log.debug("[GOD MODE] RealtimeLearner.start_scan failed (non-fatal): %s", _ls_exc)

        # ── Stage 2: subscribe to event bus + launch FullScanMission ──────
        print(f"\n[*] Stage 2: Full scan + event bus active")
        self._subscribe_to_event_bus()

        # Start recursive watch — handlers self-unregister on interruption
        _enforcement = None
        try:
            from oneinfinity.orchestration.enforcement_controller import get_enforcement_controller
            _enforcement = get_enforcement_controller()
            _enforcement.start_recursive_watch(session.scan_id, session.target)
        except Exception as exc:
            log.warning("[GOD MODE] Recursive watch start failed (non-fatal): %s", exc)
            _enforcement = None

        try:
            full_scan.start(session)

            # ── Phase 4 mission starts ─────────────────────────────────────────────
            # AdvancedScanMission: always-on parallel cross-validation
            advanced_scan_mission.start(session)
            log.info("[GOD MODE] AdvancedScanMission started in parallel with FullScanMission")

            # ZeroHypothesisMission: starts now, blocks internally until full_scan.is_done()
            zero_hypothesis.start(session)
            log.info("[GOD MODE] ZeroHypothesisMission started — will wait for FullScan completion")

            # AIRedTeamMission: only if AI target was detected
            if ai_red_team is not None:
                ai_red_team.start(session)
                log.info("[GOD MODE] AI target detected — AIRedTeamMission launched immediately")

            # AICouncilMission: only if AI target was detected
            if ai_council is not None:
                ai_council.start(session)
                log.info("[GOD MODE] AI target detected — AICouncilMission launched immediately")

            # Fire NEW_ENDPOINT events from Foundation recon so SwarmMission can unlock
            try:
                from oneinfinity.orchestration.event_bus import get_bus, EventType
                bus = get_bus()
                recon = foundation.recon
                if recon:
                    urls = list(getattr(recon, "all_urls", []) or [])
                    api_map = getattr(recon, "api_map", None)
                    if api_map:
                        urls += list(getattr(api_map, "endpoints", []) or [])
                    for url in urls[:EVENT_UNLOCK_ENDPOINT_THRESHOLD + 5]:
                        bus.publish(EventType.NEW_ENDPOINT, {"url": str(url)}, source="god-mode-foundation")
                    if urls:
                        log.info("[GOD MODE] Fired %d NEW_ENDPOINT events from Foundation recon", min(len(urls), EVENT_UNLOCK_ENDPOINT_THRESHOLD + 5))
            except Exception as exc:
                log.warning("[GOD MODE] Foundation endpoint event fire failed: %s", exc)

            self._update_session_missions()

            # ── Stage 3 is automatic (event-driven unlocking from _on_vuln/_on_endpoint)

            # ── Stage 4: Convergence loop ──────────────────────────────────────
            print(f"[*] Stage 4: Convergence loop (checks every 30s)")
            reason = self._convergence_loop()
            session.terminated_by = reason
            self._update_session_missions()

            # Stop all running missions
            for m in self._missions:
                if not m.is_done():
                    m.stop()

            # Wait up to 15s for missions to stop; they run blocking calls so they
            # may not honour the stop event — we proceed regardless after the timeout.
            _stop_deadline = time.time() + 15
            for m in self._missions:
                if m._thread is not None and m._thread.is_alive():
                    remaining = max(0.1, _stop_deadline - time.time())
                    m._thread.join(timeout=remaining)
                    if m._thread.is_alive():
                        log.warning("[GOD MODE] Mission '%s' still running after stop timeout — proceeding", m.name)

            # ── Also start ChainsMission if findings were found but it hasn't run ──────
            if (session.finding_count > 0) and chains.status == "pending":
                log.info("[GOD MODE] Triggering ChainsMission post-convergence (findings found)")
                chains.start(session)
                if chains._thread is not None:
                    chains._thread.join(timeout=120)  # wait up to 2 min for chains

            # ── Attack-graph chain suggestions (AttackGraphBuilder.suggest_chains) ──
            # Build an AttackGraph from all accumulated findings, run BFS chain
            # detection, write suggestions to JSON, and surface the file path via
            # the findings-pipeline waf_profile dict so ReportMission can embed it.
            try:
                from oneinfinity.attack_graph_core.builder import AttackGraphBuilder
                from oneinfinity.findings.result_ingestion_engine import get_ingestion_engine as _sgie
                import json as _sc_json
                _sc_findings = _sgie().get_findings() or []
                _sc_builder = AttackGraphBuilder(target=session.target)
                for _scf in _sc_findings:
                    if isinstance(_scf, dict):
                        _sc_builder._add_finding(_scf)
                _sc_suggestions = _sc_builder.suggest_chains()
                if _sc_suggestions:
                    _sc_out_dir = GOD_MODE_DIR / session.scan_id
                    _sc_out_dir.mkdir(parents=True, exist_ok=True)
                    _sc_file = _sc_out_dir / "suggested_chains.json"
                    _sc_file.write_text(_sc_json.dumps(_sc_suggestions, indent=2))
                    # Surface path via waf_profile-style ctx dict so downstream
                    # phases (severity_followup, report) can locate it.
                    session.phases_complete.append("suggest_chains")
                    log.info("[GOD MODE] suggest_chains: %d chain suggestions → %s",
                             len(_sc_suggestions), _sc_file)
                else:
                    log.debug("[GOD MODE] suggest_chains: no chain suggestions (graph likely sparse)")
            except Exception as _sc_exc:
                log.debug("[GOD MODE] suggest_chains skipped (non-fatal): %s", _sc_exc)


            self._unsubscribe_from_event_bus()

            # ── Findings pipeline: score + confirm + aggregate ─────────────────
            # Pull all ingested findings from the engine, run confidence scoring,
            # ConfirmationCoordinator (all 6 post-confirm actions), then aggregate
            # into a single deduped set before ReportMission.
            try:
                from oneinfinity.findings.result_ingestion_engine import get_ingestion_engine
                _all_findings = get_ingestion_engine().get_findings() or []
                if _all_findings:
                    _all_findings = self._apply_findings_pipeline(
                        _all_findings, scan_id=session.scan_id
                    )
                    # Consolidate via ResultAggregator for dedup + graph update
                    if self._result_aggregator is not None:
                        _task_results = [{"findings": _all_findings,
                                          "worker_id": "god-mode-aggregator"}]
                        _agg_result = self._result_aggregator.aggregate(
                            _task_results, target=session.target
                        )
                        self._result_aggregator.store_result(_agg_result)
                        log.info(
                            "[GOD MODE] ResultAggregator: %d unique findings "
                            "(risk=%.1f) stored for ReportMission",
                            _agg_result.total_findings, _agg_result.risk_score,
                        )
                        # Re-ingest deduped findings so ReportMission sees the consolidated set
                        try:
                            from oneinfinity.findings.result_ingestion_engine import (
                                get_ingestion_engine as _gie, RawResult,
                            )
                            _eng = _gie()
                            for _f in _agg_result.findings:
                                if isinstance(_f, dict) and _f:
                                    _eng.ingest(RawResult(
                                        scan_id=session.scan_id,
                                        source="god-mode-aggregated",
                                        raw=_f,
                                    ))
                        except Exception as _ri:
                            log.debug("[GOD MODE] Aggregated re-ingest failed: %s", _ri)
            except Exception as _fp:
                log.warning("[GOD MODE] Findings pipeline (score+confirm+aggregate) failed: %s", _fp)

            # Stage 5: ReportMission (always)
            print(f"\n[*] Stage 5: Finalization...")
            report.run_sync(session)
            self._update_session_missions()

            # Final state write — captures elapsed + finding_count after all missions
            self._state_file.write(session)

            # Final summary
            print(f"\n[+] GOD MODE complete — Session: {session.scan_id}")
            print(f"    Terminated by: {session.terminated_by}")
            print(f"    Elapsed:       {session.elapsed():.0f}s")
            print(f"    Findings:      {session.finding_count}")
            print(f"    Phases:        {', '.join(session.phases_complete)}")
            print(f"    Report:        {GOD_MODE_DIR / session.scan_id}")

            # ── Cleanup connection pools ───────────────────────────────────────
            try:
                import asyncio as _asyncio
                from oneinfinity.core.pg_client import close_pg
                # Since we are in a non-async thread, use a small run to close pool
                _asyncio.run(close_pg())
            except Exception as exc:
                log.debug("[GOD MODE] pg_client cleanup failed: %s", exc)

            self._teardown_logging()

            # If stopped manually, exit after finalization.
            # Mission threads are daemon=False and blocking calls (subprocesses, asyncio)
            # may not be interruptible; sys.exit raises SystemExit allowing atexit handlers to run.
            if session.terminated_by == "stop":
                _still_alive = [m.name for m in self._missions if m._thread and m._thread.is_alive()]
                if _still_alive:
                    log.info("[GOD MODE] Force-exiting; missions still running: %s", _still_alive)
                sys.exit(0)
        finally:
            if _enforcement is not None:
                _enforcement.stop_recursive_watch(session.scan_id)


# ── Singleton ──────────────────────────────────────────────────────────────────

_conductor_singleton: Optional[GodModeConductor] = None
_conductor_lock = threading.Lock()


def get_god_mode_conductor() -> GodModeConductor:
    global _conductor_singleton
    if _conductor_singleton is None:
        with _conductor_lock:
            if _conductor_singleton is None:
                _conductor_singleton = GodModeConductor()
    return _conductor_singleton
