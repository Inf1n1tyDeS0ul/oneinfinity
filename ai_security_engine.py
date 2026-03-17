"""
AI Security Engine — orchestrates parallel AI security testing tools.

Execution pipeline:
  target AI endpoint
  │
  AI Security Engine
  │
  parallel tool execution (Garak / PyRIT / Giskard / Purple Llama / Rebuff / ART)
  │
  result parsing & normalization
  │
  deduplication
  │
  attack graph integration
  │
  report generation (JSON / Markdown / HTML)

CLI:
  oneinfinity ai-test <target>
  oneinfinity ai-test <target> --all
  oneinfinity ai-test <target> --garak
  oneinfinity ai-test <target> --pyrit
  oneinfinity ai-test <target> --giskard
  oneinfinity ai-test <target> --rebuff
"""

from __future__ import annotations

import asyncio
import json
import logging
import sys
import time
from dataclasses import dataclass, field, asdict
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional

from ai_security.vulnerability_detector import AIVulnFinding

log = logging.getLogger(__name__)

# ─────────────────────────────────────────────────────────────────────────────
#  Tool availability check (printed in banner)
# ─────────────────────────────────────────────────────────────────────────────

def _tool_available(name: str) -> bool:
    import importlib.util
    return importlib.util.find_spec(name) is not None

TOOL_STATUS = {
    "garak":   _tool_available("garak"),
    "pyrit":   _tool_available("pyrit"),
    "giskard": _tool_available("giskard"),
    "rebuff":  _tool_available("rebuff"),
    "art":     _tool_available("art"),
}


# ─────────────────────────────────────────────────────────────────────────────
#  Engine
# ─────────────────────────────────────────────────────────────────────────────

@dataclass
class AISecurityScanConfig:
    target: str
    tools: List[str]                # which tools to run
    endpoint_path: str = "/v1/chat/completions"
    auth_header: str = ""
    model: str = "gpt-3.5-turbo"
    extra_headers: Dict[str, str] = field(default_factory=dict)
    output_dir: str = "recon"
    platform: str = "hackerone"
    report_formats: List[str] = field(default_factory=lambda: ["markdown", "json", "html"])
    attack_graph = None
    learning_system = None
    timeout: int = 300


@dataclass
class AISecurityScanResult:
    target: str
    tools_run: List[str]
    findings: List[AIVulnFinding]
    duration: float
    started_at: str
    finished_at: str
    report_paths: List[str] = field(default_factory=list)
    error_log: List[str] = field(default_factory=list)

    @property
    def critical_count(self) -> int:
        return sum(1 for f in self.findings if f.severity == "critical")

    @property
    def high_count(self) -> int:
        return sum(1 for f in self.findings if f.severity == "high")

    def print_summary(self) -> None:
        sev_counts: Dict[str, int] = {}
        for f in self.findings:
            sev_counts[f.severity] = sev_counts.get(f.severity, 0) + 1

        print(f"\n{'═'*60}")
        print(f"  AI Security Scan Complete — {self.target}")
        print(f"{'═'*60}")
        print(f"  Tools run      : {', '.join(self.tools_run)}")
        print(f"  Duration       : {self.duration:.1f}s")
        print(f"  Total findings : {len(self.findings)}")
        for sev in ["critical", "high", "medium", "low", "info"]:
            cnt = sev_counts.get(sev, 0)
            if cnt:
                marker = {"critical": "🔴", "high": "🟠", "medium": "🟡", "low": "🔵", "info": "⚪"}.get(sev, "")
                print(f"  {marker} {sev.capitalize():<10}: {cnt}")
        print()
        for i, f in enumerate(
            sorted(self.findings, key=lambda x: {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}.get(x.severity, 5)),
            1
        ):
            print(f"  {i:>2}. [{f.severity.upper():<8}] {f.vulnerability}")
            print(f"      Tool: {f.tool} | Confidence: {int(f.confidence * 100)}%")
            print(f"      Payload: {f.payload[:60]}...")
            print()
        if self.report_paths:
            print(f"  Reports:")
            for p in self.report_paths:
                print(f"    → {p}")


class AISecurityEngine:
    """
    Orchestrates multiple AI security testing tools in parallel.
    """

    _ALL_TOOLS = ["garak", "pyrit", "giskard", "purple_llama", "rebuff", "art"]

    def __init__(self) -> None:
        self._wrappers: Dict[str, Any] = {}
        self._load_wrappers()

    def _load_wrappers(self) -> None:
        from ai_security.tool_wrappers.garak_wrapper import GarakWrapper
        from ai_security.tool_wrappers.pyrit_wrapper import PyRITWrapper
        from ai_security.tool_wrappers.giskard_wrapper import GiskardWrapper
        from ai_security.tool_wrappers.purple_llama_wrapper import PurpleLlamaWrapper
        from ai_security.tool_wrappers.rebuff_wrapper import RebuffWrapper
        from ai_security.tool_wrappers.art_wrapper import ARTWrapper

        self._wrappers = {
            "garak":       GarakWrapper(),
            "pyrit":       PyRITWrapper(),
            "giskard":     GiskardWrapper(),
            "purple_llama": PurpleLlamaWrapper(),
            "rebuff":      RebuffWrapper(),
            "art":         ARTWrapper(),
        }

    # ── Public API ────────────────────────────────────────────────────────────

    async def scan(self, config: AISecurityScanConfig) -> AISecurityScanResult:
        """Run all requested tools in parallel and aggregate findings."""
        started_at = datetime.now(timezone.utc).isoformat()
        t0 = time.time()

        tools = config.tools if config.tools else self._ALL_TOOLS
        tool_config = {
            "endpoint_path": config.endpoint_path,
            "auth_header": config.auth_header,
            "model": config.model,
        }

        print(f"\n[*] AI Security Engine — scanning {config.target}")
        print(f"[*] Tools: {', '.join(tools)}")
        print()

        # Run all tools concurrently
        tasks = {
            tool: asyncio.create_task(
                self._run_tool(tool, config.target, tool_config),
                name=f"ai-sec-{tool}",
            )
            for tool in tools
            if tool in self._wrappers
        }

        all_findings: List[AIVulnFinding] = []
        errors: List[str] = []
        tools_run: List[str] = []

        for tool, task in tasks.items():
            print(f"[*] Running {tool}...", end=" ", flush=True)
            try:
                findings = await asyncio.wait_for(task, timeout=config.timeout)
                all_findings.extend(findings)
                tools_run.append(tool)
                print(f"→ {len(findings)} finding(s)")
            except asyncio.TimeoutError:
                msg = f"{tool}: timeout after {config.timeout}s"
                errors.append(msg)
                print(f"→ TIMEOUT")
                log.warning(msg)
            except Exception as exc:
                msg = f"{tool}: {exc}"
                errors.append(msg)
                print(f"→ ERROR: {exc}")
                log.error(msg)

        # Deduplicate
        all_findings = self._deduplicate(all_findings)

        # Integrate with attack graph
        if config.attack_graph:
            self._update_attack_graph(config.attack_graph, config.target, all_findings)

        # Update learning system
        if config.learning_system:
            self._update_learning(config.learning_system, all_findings)

        # Generate reports
        finished_at = datetime.now(timezone.utc).isoformat()
        duration = time.time() - t0
        report_paths = self._write_reports(config, all_findings)

        result = AISecurityScanResult(
            target=config.target,
            tools_run=tools_run,
            findings=all_findings,
            duration=duration,
            started_at=started_at,
            finished_at=finished_at,
            report_paths=report_paths,
            error_log=errors,
        )
        return result

    # ── Tool dispatch ─────────────────────────────────────────────────────────

    async def _run_tool(
        self, tool: str, target: str, config: Dict[str, Any]
    ) -> List[AIVulnFinding]:
        wrapper = self._wrappers.get(tool)
        if wrapper is None:
            return []
        return await wrapper.run(target, config)

    # ── Post-processing ───────────────────────────────────────────────────────

    def _deduplicate(self, findings: List[AIVulnFinding]) -> List[AIVulnFinding]:
        """Deduplicate by fingerprint."""
        seen: set = set()
        unique: List[AIVulnFinding] = []
        for f in findings:
            if f.fingerprint not in seen:
                seen.add(f.fingerprint)
                unique.append(f)
        log.info("Deduplication: %d → %d findings", len(findings), len(unique))
        return unique

    def _update_attack_graph(
        self, attack_graph: Any, target: str, findings: List[AIVulnFinding]
    ) -> None:
        try:
            for f in findings:
                attack_graph.add_vulnerability(
                    target=target,
                    vuln_type=f.vulnerability,
                    severity=f.severity,
                    endpoint=target,
                    evidence=f.evidence[:200],
                    tool=f.tool,
                )
            log.info("Attack graph updated with %d AI security findings", len(findings))
        except Exception as exc:
            log.error("Attack graph update failed: %s", exc)

    def _update_learning(self, learning_system: Any, findings: List[AIVulnFinding]) -> None:
        try:
            for f in findings:
                if hasattr(learning_system, "record_ai_vuln"):
                    learning_system.record_ai_vuln(asdict(f))
        except Exception as exc:
            log.debug("Learning system update error: %s", exc)

    def _write_reports(
        self, config: AISecurityScanConfig, findings: List[AIVulnFinding]
    ) -> List[str]:
        paths = []
        try:
            from core.reporter import Reporter
            out_dir = Path(config.output_dir) / config.target / "ai_security"
            reporter = Reporter(output_dir=out_dir, target=config.target, platform=config.platform)
            for f in findings:
                reporter.add_finding(f.to_bounty_finding())
            written = reporter.write_all(config.report_formats)
            paths = [str(p) for p in written]
        except Exception as exc:
            log.error("Report generation failed: %s", exc)
            # Fallback: write JSON
            try:
                out_dir = Path(config.output_dir) / config.target / "ai_security"
                out_dir.mkdir(parents=True, exist_ok=True)
                json_path = out_dir / "ai_security_findings.json"
                json_path.write_text(
                    json.dumps([asdict(f) for f in findings], indent=2, default=str)
                )
                paths = [str(json_path)]
            except Exception:
                pass
        return paths


# ─────────────────────────────────────────────────────────────────────────────
#  CLI entry point
# ─────────────────────────────────────────────────────────────────────────────

def main_cli(args) -> None:
    """Entry point called by oneinfinity.py cmd_ai_test()."""
    import types

    target = args.target
    output_dir = getattr(args, "output", "recon")
    platform = getattr(args, "platform", "hackerone")
    auth = getattr(args, "auth", "")
    model = getattr(args, "model", "gpt-3.5-turbo")
    endpoint = getattr(args, "endpoint", "/v1/chat/completions")
    formats = getattr(args, "formats", ["markdown", "json", "html"])

    # Determine which tools to run
    run_all = getattr(args, "all", False)
    tools = []
    for tool in ["garak", "pyrit", "giskard", "purple_llama", "rebuff", "art"]:
        if run_all or getattr(args, tool, False):
            tools.append(tool)
    if not tools:
        tools = AISecurityEngine._ALL_TOOLS  # default: all

    # Auth confirmation
    yes = getattr(args, "yes", False)
    if not yes:
        confirm = input(
            f"\n[!] This will actively probe {target} with AI security tests.\n"
            f"    Tools: {', '.join(tools)}\n"
            f"    Ensure you have written authorization. Proceed? [y/N] "
        ).strip().lower()
        if confirm != "y":
            print("[-] Aborted.")
            return

    config = AISecurityScanConfig(
        target=target,
        tools=tools,
        endpoint_path=endpoint,
        auth_header=auth,
        model=model,
        output_dir=output_dir,
        platform=platform,
        report_formats=formats if isinstance(formats, list) else [formats],
    )

    engine = AISecurityEngine()

    print_banner()
    result = asyncio.run(engine.scan(config))
    result.print_summary()


def print_banner() -> None:
    print()
    print("╔══════════════════════════════════════════════════════════╗")
    print("║          AI Security Engine — One&Infinity              ║")
    print("╠══════════════════════════════════════════════════════════╣")
    for tool, available in TOOL_STATUS.items():
        status = "✓ installed" if available else "  built-in fallback"
        print(f"║  {tool:<20} {status:<30}   ║")
    print("╚══════════════════════════════════════════════════════════╝")


if __name__ == "__main__":
    import argparse
    p = argparse.ArgumentParser(description="AI Security Engine")
    p.add_argument("target", help="Target AI endpoint")
    p.add_argument("--all", action="store_true")
    p.add_argument("--garak", action="store_true")
    p.add_argument("--pyrit", action="store_true")
    p.add_argument("--giskard", action="store_true")
    p.add_argument("--purple-llama", dest="purple_llama", action="store_true")
    p.add_argument("--rebuff", action="store_true")
    p.add_argument("--art", action="store_true")
    p.add_argument("--auth", default="", help="Authorization header value")
    p.add_argument("--model", default="gpt-3.5-turbo")
    p.add_argument("--endpoint", default="/v1/chat/completions")
    p.add_argument("--output", default="recon")
    p.add_argument("--yes", "-y", action="store_true")
    args = p.parse_args()
    main_cli(args)
