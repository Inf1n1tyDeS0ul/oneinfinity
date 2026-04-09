"""
OneInfinity Task Executor
=========================
Translates a ScanTask dict into actual OneInfinity module calls.

Module routing:
  recon         → adaptive_recon_engine.main_cli  (or CLI subprocess)
  vuln_scan     → modules/tool_wrappers (nuclei, dalfox, sqlmap)
  exploit       → exploit_chains.ExploitChainEngine
  ai_security   → ai_security_engine.main_cli
  mobile        → mobile_security_engine
  full_pipeline → unified_scan_engine

Execution strategy:
  1. Try direct Python import (fastest, shares memory)
  2. Fall back to subprocess `python oneinfinity.py <command>` (safer isolation)

Results are written to ONEINFINITY_HOME/raw/<target>/ and also
returned as a structured dict for Redis result publishing.
"""

from __future__ import annotations

import json
import logging
import os
import subprocess
import sys
import time
import types
from pathlib import Path
from typing import Any

ROOT = Path(__file__).parent.parent
sys.path.insert(0, str(ROOT))

log = logging.getLogger("oi.executor")


# ---------------------------------------------------------------------------
# Finding schema normalization
# ---------------------------------------------------------------------------

_REQUIRED_FINDING_KEYS = {
    "title", "severity", "vuln_type", "url", "evidence", "tool", "source_type",
}
_SEVERITY_ALIASES = {
    "critical": "critical", "high": "high", "medium": "medium",
    "med": "medium", "low": "low", "info": "info", "informational": "info",
    "warn": "low", "warning": "low",
}


def _normalize_finding_dict(f: dict, default_target: str = "") -> dict:
    """
    Coerce a raw finding dict from any tool into the canonical schema.

    Guarantees: title, severity, vuln_type, url, evidence, tool, source_type.
    Coerces all values to str/float as appropriate (no non-serializable types).
    """
    if not isinstance(f, dict):
        try:
            f = f.to_dict()
        except Exception:
            return {"title": "Unknown", "severity": "info", "vuln_type": "unknown",
                    "url": default_target, "evidence": "", "tool": "unknown",
                    "source_type": "tool"}

    out = dict(f)

    # Canonical key aliases
    out.setdefault("title",      out.pop("name",        out.get("template-id", "Unknown")))
    out.setdefault("vuln_type",  out.pop("type",        out.get("tags", ["unknown"])[0]
                                         if isinstance(out.get("tags"), list) else "unknown"))
    out.setdefault("url",        out.pop("endpoint",    out.get("matched-at", default_target)))
    out.setdefault("evidence",   out.pop("description", out.get("info", {}).get("description", "")
                                         if isinstance(out.get("info"), dict) else ""))
    out.setdefault("tool",       "unknown")
    out.setdefault("source_type", "tool")

    # Normalize severity
    raw_sev = str(out.get("severity", "info")).lower()
    out["severity"] = _SEVERITY_ALIASES.get(raw_sev, "info")

    # Ensure all text fields are str, not bytes/None
    for key in ("title", "vuln_type", "url", "evidence", "tool", "source_type",
                "payload", "poc", "reproduction_cmd"):
        if key in out:
            out[key] = str(out[key]) if out[key] is not None else ""

    # Ensure numeric fields are float
    for key in ("confidence", "cvss", "risk_score"):
        if key in out:
            try:
                out[key] = float(out[key])
            except (TypeError, ValueError):
                out[key] = 0.0

    return out


# Module → (CLI command, CLI args builder) mapping
_MODULE_COMMANDS: dict[str, tuple[str, ...]] = {
    "recon":          ("adaptive-recon",),
    "vuln_scan":      ("vuln-scan",),
    "exploit":        ("chains",),
    "ai_security":    ("ai-test",),
    "mobile":         ("mobile-analyze",),
    "full_pipeline":  ("agents", "run"),
    "secrets":        ("secrets-scan",),
    "research":       ("research",),
    "zero_day":       ("zero-day",),
}


class TaskExecutor:
    """
    Executes a single scan task and returns a result dict.

    Result schema:
    {
      "task_id":       str,
      "target":        str,
      "module":        str,
      "finding_count": int,
      "output_dir":    str,
      "findings":      [...],   # list of finding dicts
      "summary":       str,
      "elapsed_s":     float,
    }
    """

    CLI_SCRIPT = str(ROOT / "oneinfinity.py")

    def __init__(
        self,
        task_id: str,
        module: str,
        target: str,
        config: dict,
        data_dir: Path,
    ):
        self.task_id   = task_id
        self.module    = module
        self.target    = target
        self.config    = config
        self.data_dir  = Path(data_dir)

        # Per-task output dir: /data/raw/<safe_target>/<task_id>/
        safe = target.replace("://", "_").replace("/", "_").replace(":", "_")
        self.output_dir = self.data_dir / "raw" / safe
        self.output_dir.mkdir(parents=True, exist_ok=True)

    # ── Public API ────────────────────────────────────────────────────────────

    def run(self) -> dict:
        start = time.time()
        log.info("[executor] task=%s module=%s target=%s", self.task_id, self.module, self.target)

        handler = getattr(self, f"_run_{self.module}", self._run_generic)
        result = handler()

        result.setdefault("task_id",   self.task_id)
        result.setdefault("target",    self.target)
        result.setdefault("module",    self.module)
        result.setdefault("output_dir", str(self.output_dir))
        result["elapsed_s"] = round(time.time() - start, 2)
        return result

    # ── Module-specific runners ───────────────────────────────────────────────

    def _run_recon(self) -> dict:
        """Run adaptive recon and return discovered URLs/hosts."""
        try:
            from oneinfinity.recon.adaptive_recon_engine import AdaptiveReconEngine  # type: ignore
            engine = AdaptiveReconEngine(
                target=self.target,
                output_dir=str(self.output_dir),
                depth=self.config.get("depth", "standard"),
            )
            result = engine.run()
            urls = result.get("urls", []) if isinstance(result, dict) else []
            return {
                "finding_count": len(urls),
                "findings":      [],
                "summary":       f"Recon complete: {len(urls)} URLs discovered",
                "recon_data":    result if isinstance(result, dict) else {},
            }
        except Exception as exc:
            log.debug("[executor] Direct import failed for recon (%s), using CLI", exc)
            return self._run_via_cli("adaptive-recon", ["--depth", self.config.get("depth", "standard")])

    def _run_vuln_scan(self) -> dict:
        """Run vulnerability scan pipeline."""
        try:
            from oneinfinity.modules.tool_wrappers import ToolRegistry, TOOL_REGISTRY  # type: ignore

            findings = []
            registry = ToolRegistry(TOOL_REGISTRY)
            severity = self.config.get("severity", "medium,high,critical")

            # Nuclei
            nuclei_result = registry.run("nuclei", target=self.target,
                                         severity=severity, timeout=600)
            if nuclei_result.success and nuclei_result.data:
                _nd = nuclei_result.data
                if isinstance(_nd, dict):
                    findings.extend(_nd.get("findings", []))
                elif isinstance(_nd, list):
                    findings.extend(_nd)

            # Dalfox (XSS)
            if self.config.get("xss", True):
                dalfox_result = registry.run("dalfox", url=self.target, timeout=120)
                if (dalfox_result.success
                        and dalfox_result.parsed
                        and isinstance(dalfox_result.parsed, list)):
                    findings.extend(dalfox_result.parsed)

            # Normalize all findings to a consistent schema before persisting
            findings = [_normalize_finding_dict(f, self.target) for f in findings]
            self._persist_findings(findings)
            return {
                "finding_count": len(findings),
                "findings":      findings[:50],   # cap payload size
                "summary":       f"Vuln scan: {len(findings)} findings",
            }
        except Exception as exc:
            log.debug("[executor] Direct import failed for vuln_scan (%s), using CLI", exc)
            extra = ["--severity", self.config.get("severity", "medium,high,critical")]
            return self._run_via_cli("vuln-scan", extra)

    def _run_exploit(self) -> dict:
        """Run exploit chain detection."""
        try:
            from oneinfinity.attack.exploit_chain_engine import ExploitChainEngine
            from oneinfinity.attack.poc_generator import PoCGenerator
            from oneinfinity.attack.chain_patterns import CHAIN_PATTERNS
            from oneinfinity.modules.findings import FindingsDB  # type: ignore

            db_path = self.data_dir / "findings.db"
            db = FindingsDB(str(db_path))
            # Support both .all() and .list_all() method names defensively
            all_findings = (
                db.all() if hasattr(db, "all") else
                db.list_all() if hasattr(db, "list_all") else []
            )

            engine = ExploitChainEngine()
            chains = engine.detect_chains(all_findings, self.target)

            pocs = []
            if self.config.get("generate_pocs", True) and chains:
                gen = PoCGenerator()
                for chain in chains:
                    pattern = CHAIN_PATTERNS.get(chain.chain_type, {})
                    relevant = [
                        f for f in all_findings
                        if f.get("vuln_type", "").lower()
                        in pattern.get("trigger_types", set())
                    ]
                    poc = gen.generate(chain.chain_type, pattern, relevant, self.target)
                    if poc:
                        poc_path = self.output_dir / f"poc_{poc.chain_id}.json"
                        poc_path.write_text(json.dumps(poc.to_dict(), indent=2))
                        pocs.append(str(poc_path))

            return {
                "finding_count": len(chains),
                "findings":      [c.to_dict() for c in chains],
                "pocs":          pocs,
                "summary":       f"Chain detection: {len(chains)} chains, {len(pocs)} PoCs",
            }
        except Exception as exc:
            log.debug("[executor] Direct import failed for exploit (%s), using CLI", exc)
            return self._run_via_cli("chains")

    def _run_research(self) -> dict:
        """Run autonomous research loop."""
        extra = [
            "--yes",
            "--iterations", str(self.config.get("iterations", 3)),
        ]
        if self.config.get("active"):
            extra.append("--active")
        if self.config.get("oob"):
            extra += ["--oob", self.config["oob"]]
        return self._run_via_cli("research", extra)

    def _run_ai_security(self) -> dict:
        """Run AI security tests."""
        extra = ["--all", "--yes"]
        if self.config.get("endpoint"):
            extra += ["--endpoint", self.config["endpoint"]]
        if self.config.get("auth"):
            extra += ["--auth", self.config["auth"]]
        return self._run_via_cli("ai-test", extra)

    def _run_mobile(self) -> dict:
        """Run mobile security analysis."""
        apk_path = self.config.get("apk_path", self.target)
        extra = ["--output", str(self.output_dir)]
        if self.config.get("dynamic"):
            extra.append("--dynamic")
        return self._run_via_cli("mobile-analyze", extra, target_override=apk_path)

    def _run_secrets(self) -> dict:
        """Run secret scanning."""
        extra = [
            "--target", self.target,
            "--mode", self.config.get("mode", "balanced"),
        ]
        if self.config.get("github_token"):
            extra += ["--github-token", self.config["github_token"]]
        return self._run_via_cli("secrets-scan", extra, target_in_extra=True)

    def _run_zero_day(self) -> dict:
        """Run zero-day anomaly detection."""
        return self._run_via_cli("zero-day")

    def _run_full_pipeline(self) -> dict:
        """
        Run the canonical 10-phase pipeline using the unified executor.
        This is the Docker-side execution — identical to CLI full-scan.
        """
        t_start = time.time()
        try:
            sys.path.insert(0, str(ROOT))
            from oneinfinity.pipeline.executor import run_canonical_pipeline

            # WAF detection
            waf_profile = {}
            try:
                from oneinfinity.scan.waf_detection_engine import WAFDetectionEngine
                probe = self.target if self.target.startswith("http") else f"https://{self.target}"
                waf_p = WAFDetectionEngine().detect(probe)
                waf_profile = waf_p.as_scan_config()
                if waf_p.detected:
                    log.info("WAF detected: %s (rps=%.1f)", waf_p.waf_name, waf_p.recommended_rps)
            except Exception as wex:
                log.warning("WAF detection failed: %s", wex)

            # Progress logger
            def on_progress(phase: str, pct: int, msg: str):
                log.info("[canonical][%d%%][%s] %s", pct, phase, msg)

            result = run_canonical_pipeline(
                target=self.target,
                output_dir=str(self.output_dir),
                mode="inline",          # Docker uses inline (direct imports)
                waf_profile=waf_profile,
                on_progress=on_progress,
                skip_phases=self.config.get("skip_phases", []),
            )

            # Score findings
            try:
                from oneinfinity.findings.confidence_engine import ConfidenceEngine
                scored = ConfidenceEngine().score_findings(result.findings)
            except Exception:
                scored = result.findings

            elapsed = round(time.time() - t_start, 2)
            return {
                "task_id":       self.task_id,
                "target":        self.target,
                "module":        "full_pipeline",
                "run_id":        result.run_id,
                "finding_count": len(scored),
                "findings":      scored[:200],   # cap payload size
                "output_dir":    str(self.output_dir),
                "summary":       (
                    f"Canonical pipeline complete: {len(scored)} findings "
                    f"({result.status}) in {elapsed}s"
                ),
                "phases_run":    [p for p, pr in result.phases.items() if pr.status == "completed"],
                "phases_failed": result.phases_failed,
                "phases_skipped": result.phases_skipped,
                "elapsed_s":     elapsed,
                "waf_detected":  result.waf_detected,
                "waf_name":      result.waf_name,
            }
        except Exception as exc:
            log.error("full_pipeline canonical executor failed: %s", exc)
            # Fallback to CLI subprocess
            return self._run_via_cli("full-scan", ["--mode", "subprocess"])

    def _run_generic(self) -> dict:
        """Fallback: run the module name as a CLI command."""
        cmd_parts = _MODULE_COMMANDS.get(self.module, (self.module,))
        return self._run_via_cli(cmd_parts[0], list(cmd_parts[1:]))

    # ── CLI subprocess execution ──────────────────────────────────────────────

    def _run_via_cli(
        self,
        command: str,
        extra_args: list[str] | None = None,
        target_override: str | None = None,
        target_in_extra: bool = False,
        max_retries: int = 3,
    ) -> dict:
        """
        Execute `python oneinfinity.py <command> [target] [extra_args]` as a
        subprocess. Captures stdout/stderr and parses summary JSON if written.
        Retries up to max_retries times with exponential backoff on failure.
        """
        target = target_override or self.target
        cmd = [sys.executable, self.CLI_SCRIPT, command]

        if not target_in_extra:
            cmd.append(target)

        if extra_args:
            cmd.extend(extra_args)

        cmd += ["--output", str(self.output_dir)]

        env = os.environ.copy()
        env["ONEINFINITY_HOME"] = str(self.data_dir)

        last_error: str = ""
        for attempt in range(1, max_retries + 1):
            if attempt > 1:
                backoff = 2 ** (attempt - 1)  # 2s, 4s
                log.info("[cli] Retry %d/%d for %s (backoff=%ds)", attempt, max_retries, command, backoff)
                time.sleep(backoff)

            log.info("[cli] Running (attempt %d): %s", attempt, " ".join(cmd))
            t_start = time.time()

            try:
                proc = subprocess.run(
                    cmd,
                    capture_output=True,
                    text=True,
                    timeout=self.config.get("timeout", 3600),
                    env=env,
                    cwd=str(ROOT),
                )
                elapsed = round(time.time() - t_start, 2)

                if proc.returncode != 0:
                    log.warning("[cli] Command exited %d: %s", proc.returncode, proc.stderr[-500:])
                    last_error = proc.stderr[-500:]
                    # Don't retry on non-retryable errors
                    if any(x in proc.stderr for x in ("ImportError", "SyntaxError", "ModuleNotFoundError")):
                        break
                    if attempt < max_retries:
                        continue

                # Try to read summary JSON written by the command
                summary = self._read_summary_json()
                if summary:
                    summary["cli_exit_code"] = proc.returncode
                    if attempt > 1:
                        summary["retried"] = attempt
                    return summary

                # Fallback: parse stdout for finding counts
                return self._parse_cli_output(proc.stdout, proc.stderr, elapsed)

            except subprocess.TimeoutExpired:
                last_error = f"timeout after {self.config.get('timeout', 3600)}s"
                log.warning("[cli] Timeout on attempt %d for %s", attempt, command)
                break  # Don't retry timeouts
            except Exception as exc:
                last_error = str(exc)
                log.warning("[cli] Exception on attempt %d for %s: %s", attempt, command, exc)
                if attempt < max_retries:
                    continue
                break

        return {
            "finding_count": 0,
            "findings": [],
            "summary": f"CLI execution failed after {max_retries} attempt(s): {last_error}",
            "error": last_error,
        }

    def _read_summary_json(self) -> dict | None:
        """Read research_summary.json or similar output written by the command."""
        for fname in ["research_summary.json", "scan_summary.json", "result.json"]:
            p = self.output_dir / fname
            if p.exists():
                try:
                    data = json.loads(p.read_text())
                    fc = data.get("confirmed_vulns", data.get("finding_count", 0))
                    return {
                        "finding_count": fc,
                        "findings":      data.get("discoveries", []),
                        "summary":       f"Complete: {fc} findings",
                        "raw":           data,
                    }
                except Exception:
                    pass
        return None

    def _parse_cli_output(self, stdout: str, stderr: str, elapsed: float) -> dict:
        """Heuristic parser for CLI output when no JSON summary exists."""
        combined = stdout + stderr
        finding_count = 0

        # Look for common patterns: "X confirmed findings", "X findings"
        import re
        for pattern in [r"(\d+) confirmed finding", r"(\d+) finding", r"findings?: (\d+)"]:
            m = re.search(pattern, combined, re.IGNORECASE)
            if m:
                finding_count = int(m.group(1))
                break

        return {
            "finding_count": finding_count,
            "findings":      [],
            "summary":       f"CLI run complete in {elapsed}s ({finding_count} findings)",
            "stdout_tail":   stdout[-1000:] if stdout else "",
        }

    def _persist_findings(self, findings: list[dict]):
        """Write findings to shared SQLite DB for cross-worker aggregation."""
        if not findings:
            return
        try:
            from oneinfinity.modules.findings import FindingsDB  # type: ignore
            db_path = self.data_dir / "findings.db"
            db = FindingsDB(str(db_path))
            for f in findings:
                if isinstance(f, dict):
                    db.add(
                        target=self.target,
                        title=f.get("name", f.get("title", "Unknown")),
                        severity=f.get("severity", "info"),
                        vuln_type=f.get("type", "unknown"),
                        evidence=f.get("description", ""),
                        url=f.get("url", self.target),
                        tool=f.get("tool", self.module),
                    )
        except Exception as exc:
            log.debug("[executor] Finding persistence failed: %s", exc)
