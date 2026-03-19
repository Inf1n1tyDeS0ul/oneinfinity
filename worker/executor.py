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
            from adaptive_recon_engine import AdaptiveReconEngine  # type: ignore
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
            from modules.tool_wrappers import ToolRegistry, TOOL_REGISTRY  # type: ignore

            findings = []
            registry = ToolRegistry(TOOL_REGISTRY)
            severity = self.config.get("severity", "medium,high,critical")

            # Nuclei
            nuclei_result = registry.run("nuclei", target=self.target,
                                         severity=severity, timeout=600)
            if nuclei_result.success and nuclei_result.parsed:
                findings.extend(nuclei_result.parsed)

            # Dalfox (XSS)
            if self.config.get("xss", True):
                dalfox_result = registry.run("dalfox", url=self.target, timeout=120)
                if dalfox_result.success and dalfox_result.parsed:
                    findings.extend(dalfox_result.parsed)

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
            from exploit_chains import ExploitChainEngine, PocGenerator  # type: ignore
            from modules.findings import FindingsDB  # type: ignore

            db_path = self.data_dir / "findings.db"
            db = FindingsDB(str(db_path))
            all_findings = db.list_all() if hasattr(db, "list_all") else []

            engine = ExploitChainEngine()
            chains = engine.detect(all_findings)

            pocs = []
            if self.config.get("generate_pocs", True):
                gen = PocGenerator()
                for chain in chains:
                    poc = gen.generate(chain)
                    if poc:
                        poc_path = self.output_dir / f"poc_{poc.chain_id}.py"
                        poc_path.write_text(poc.script)
                        pocs.append(str(poc_path))

            return {
                "finding_count": len(chains),
                "findings":      [c.__dict__ if hasattr(c, "__dict__") else c for c in chains],
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
        """Run complete autonomous multi-agent pentest."""
        extra = [
            "--yes",
            "--platform", self.config.get("platform", "hackerone"),
        ]
        return self._run_via_cli("agents", ["run"] + extra)

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
    ) -> dict:
        """
        Execute `python oneinfinity.py <command> [target] [extra_args]` as a
        subprocess. Captures stdout/stderr and parses summary JSON if written.
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

        log.info("[cli] Running: %s", " ".join(cmd))
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

            # Try to read summary JSON written by the command
            summary = self._read_summary_json()
            if summary:
                summary["cli_exit_code"] = proc.returncode
                return summary

            # Fallback: parse stdout for finding counts
            return self._parse_cli_output(proc.stdout, proc.stderr, elapsed)

        except subprocess.TimeoutExpired:
            return {
                "finding_count": 0,
                "findings": [],
                "summary": f"Task timed out after {self.config.get('timeout', 3600)}s",
                "error": "timeout",
            }
        except Exception as exc:
            return {
                "finding_count": 0,
                "findings": [],
                "summary": f"CLI execution failed: {exc}",
                "error": str(exc),
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
            from modules.findings import FindingsDB  # type: ignore
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
