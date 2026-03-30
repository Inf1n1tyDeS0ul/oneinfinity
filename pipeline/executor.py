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

ROOT = Path(__file__).parent.parent  # project root
CLI_SCRIPT = str(ROOT / "oneinfinity.py")


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
        Internal phases (_internal_*) run inline even in subprocess mode.
        """
        # Internal phases always run inline (no CLI equivalent needed)
        if phase.cli_command.startswith("_internal_"):
            return self._run_phase_inline(phase, target, output_dir, result)

        # Build args — same as canonical.phase_cli_args()
        # Commands fall into three categories for --output:
        #   _no_output_flag   — no --output flag at all (_internal_*)
        #   _file_output_cmds — write a single JSON file; pass full file path
        #   everything else   — resolve_output_dir(path, target); pass directory
        _file_output_cmds = {
            "swarm-scan", "simulate-attacks", "zero-day",
            "graphql-scan", "browser-scan", "smuggling-scan",
        }
        _no_output_flag   = {"_internal_register", "_internal_validate", "_internal_oob_check"}
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
        except subprocess.TimeoutExpired:
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
            from adaptive_recon_engine import AdaptiveReconEngine
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
            from modules.owasp_gap_checks import (
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
            from modules.owasp_gap_checks import (
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

        if seeded:
            log.info("vuln_scan inline: loaded %d seeded findings from %s", len(seeded), findings_file)
            return seeded

        # No seeded findings — run Pipeline inline
        try:
            from modules.pipeline import Pipeline
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
            return result.findings if result.findings else []
        except Exception as exc:
            log.error("vuln_scan inline failed: %s", exc)
            return []

    def _inline_active_testing(self, target: str, out: Path, waf: dict) -> List[dict]:
        findings = []
        auth_headers = self._build_auth_headers()
        probe_target = target if target.startswith("http") else f"https://{target}"

        # ── Original validation engine ─────────────────────────────────────
        try:
            from validation_engine_web import WebValidationEngine
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
        from modules.tool_wrappers import (
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
            from modules.owasp_gap_checks import (
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

        (out / "swarm_findings.json").write_text(
            json.dumps({"findings": findings, "validated": len(findings)}, indent=2)
        )
        return findings

    def _inline_auth_session(self, target: str, out: Path, waf: dict) -> List[dict]:
        findings = []
        auth_headers_extra = self._build_auth_headers()
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
            from modules.tool_wrappers import run_rate_limit_test, run_mfa_bypass_test
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
            from modules.owasp_gap_checks import (
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
            from attack_simulation_engine import AttackSimulationEngine
            engine = AttackSimulationEngine()
            sim_results = engine.simulate_all_paths()
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
            from modules.tool_wrappers import run_race_condition_test
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
            from modules.tool_wrappers import run_payment_tampering_test
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

        return findings

    def _inline_exploit_validation(self, target: str, out: Path) -> List[dict]:
        findings = []
        try:
            from validation_engine_web import WebValidationEngine
            all_f = self._load_findings_from_dir(out)
            engine = WebValidationEngine()
            results = engine.validate_all(all_f)
            # apply_results is a method on the engine instance
            updated = engine.apply_results(all_f, results)
            confirmed = [f for f in updated if f.get("validation_status") == "confirmed"]
            (out / "validation_results.json").write_text(
                json.dumps({"validated": len(confirmed), "findings": confirmed}, indent=2)
            )
            return confirmed
        except Exception as exc:
            log.warning("exploit_validation inline failed: %s", exc)
        return findings

    def _inline_exploit_chains(self, target: str, out: Path) -> List[dict]:
        findings = []
        try:
            from exploit_chains import ExploitChainEngine
            from exploit_chains.poc_generator import PoCGenerator
            from exploit_chains.chain_patterns import CHAIN_PATTERNS
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
        return findings

    def _inline_attack_graph(self, target: str, out: Path) -> List[dict]:
        try:
            from attack_graph import AttackGraphBuilder
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
            (out / "attack_graph.json").write_text(json.dumps(graph_data, indent=2, default=str))
        except Exception as exc:
            log.warning("attack_graph inline failed: %s", exc)
        return []  # Attack graph produces no new findings

    def _inline_ai_theory(self, target: str, out: Path) -> List[dict]:
        findings = []
        try:
            from zero_day_engine import ZeroDayEngine
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
            from graphql_scan_engine import GraphQLScanEngine
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

    def _inline_browser_analysis(self, target: str, out: Path) -> List[dict]:
        """Run headless browser: DOM XSS, JS secrets, dynamic endpoint extraction.
        Also runs source map scanner, clickjacking test, and WebSocket security tests."""
        findings: List[dict] = []
        auth_headers = self._build_auth_headers()
        probe_url = target if target.startswith("http") else f"https://{target}"

        # ── Headless browser engine ────────────────────────────────────────
        js_urls: List[str] = []
        try:
            from headless_browser_engine import HeadlessBrowserEngine
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
            from modules.tool_wrappers import run_source_map_scanner
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
            from modules.tool_wrappers import run_clickjacking_test
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
            from modules.tool_wrappers import run_websocket_test
            ws_result = run_websocket_test(probe_url, headers=auth_headers)
            for f in (ws_result.data or {}).get("findings", []):
                f.setdefault("source_type", "tool")
                f.setdefault("vuln_type", "WebSocket Security Issue")
                f.setdefault("confidence", 0.80)
                findings.append(f)
        except Exception as exc:
            log.debug("browser_analysis websocket: %s", exc)

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
            from smuggling_engine import SmugglingEngine
            engine = SmugglingEngine(target=probe_url, timeout=8)
            findings = engine.run() or []
            engine_succeeded = True
            log.info("smuggling_test engine: %d findings for %s", len(findings), target)
        except Exception as exc:
            log.debug("smuggling_test engine unavailable: %s — using Python fallback", exc)

        # Fallback: pure-Python raw socket implementation (always runs if engine unavailable)
        if not engine_succeeded:
            try:
                from modules.tool_wrappers import run_smuggling_python
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
            from oob_engine import OOBEngine
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
        """Write unified findings and pipeline report."""
        # Unified findings
        (out / "unified_findings.json").write_text(
            json.dumps(result.findings, indent=2, default=str)
        )
        # Pipeline execution report
        (out / "pipeline_report.json").write_text(
            json.dumps(result.to_dict(), indent=2, default=str)
        )
        log.info("Pipeline outputs written to %s (unified=%d findings)", out, len(result.findings))

    def _emit(self, phase: str, pct: int, msg: str) -> None:
        if self.on_progress:
            try:
                # Clamp to last emitted value so progress never goes backwards
                pct = max(pct, self._last_emitted_pct)
                self._last_emitted_pct = pct
                self.on_progress(phase, pct, msg)
            except Exception:
                pass


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
) -> PipelineResult:
    """One-call entry point used by both CLI and Docker worker."""
    executor = CanonicalExecutor(
        mode=mode,
        waf_profile=waf_profile,
        on_progress=on_progress,
        skip_phases=skip_phases,
        prior_results_dir=prior_results_dir,
        auth_config=auth_config,
    )
    return executor.run(target, output_dir)
