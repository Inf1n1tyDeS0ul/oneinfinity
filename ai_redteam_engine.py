"""
AI Red Team Engine — automated adversarial testing of AI systems at scale.

Automatically generates and sends thousands of attack prompts, analyzes
responses, detects successful attacks, and evolves prompts over time.

Attack campaigns:
  prompt_injection   — override system instructions
  jailbreak          — bypass safety filters
  data_leak          — extract system prompts / credentials
  rag_attack         — inject via retrieved documents
  tool_abuse         — manipulate AI agent tool calls
  output_manipulation — inject HTML/JS/URLs into output

CLI:
  oneinfinity ai-redteam <target>
  oneinfinity ai-redteam <target> --campaign jailbreak
  oneinfinity ai-redteam <target> --prompts 5000
  oneinfinity ai-redteam <target> --parallel 20
  oneinfinity ai-redteam <target> --evolve
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

from ai_security.campaign_manager import CampaignConfig, CampaignManager, CampaignMode, CampaignResult
from ai_security.vulnerability_detector import AIVulnFinding
from ai_security.adversarial_prompt_evolution import AdversarialPromptEvolution

log = logging.getLogger(__name__)


# ─────────────────────────────────────────────────────────────────────────────
#  Red Team Engine
# ─────────────────────────────────────────────────────────────────────────────

class AIRedTeamEngine:
    """
    Fully automated AI red team engine for adversarial testing at scale.
    """

    def __init__(self) -> None:
        self._campaign_manager = CampaignManager()
        self._evolution = AdversarialPromptEvolution()

    # ── Public API ────────────────────────────────────────────────────────────

    async def run_campaign(
        self,
        target: str,
        mode: str = "full",
        num_prompts: int = 100,
        parallel: int = 10,
        endpoint_path: str = "/v1/chat/completions",
        auth_header: str = "",
        model: str = "gpt-3.5-turbo",
        use_evolution: bool = True,
        stop_on_critical: bool = False,
        dry_run: bool = False,
        context: str = "",
        output_dir: str = "recon",
        platform: str = "hackerone",
        report_formats: Optional[List[str]] = None,
        attack_graph: Any = None,
        learning_system: Any = None,
    ) -> CampaignResult:
        """
        Run a full adversarial campaign.
        """
        campaign_mode = self._parse_mode(mode)
        config = CampaignConfig(
            target=target,
            mode=campaign_mode,
            num_prompts=num_prompts,
            parallel=parallel,
            endpoint_path=endpoint_path,
            auth_header=auth_header,
            model=model,
            use_evolution=use_evolution,
            stop_on_first_critical=stop_on_critical,
            dry_run=dry_run,
            context=context,
        )

        print(f"\n[*] AI Red Team Engine — {campaign_mode.value} campaign")
        print(f"[*] Target    : {target}")
        print(f"[*] Prompts   : {num_prompts}")
        print(f"[*] Parallel  : {parallel}")
        print(f"[*] Evolution : {'enabled' if use_evolution else 'disabled'}")
        print()

        result = await self._campaign_manager.run(config)

        # Post-campaign processing
        self._print_campaign_summary(result)

        # Integrate with attack graph
        if attack_graph and result.findings:
            self._update_attack_graph(attack_graph, target, result.findings)

        # Update learning system
        if learning_system and result.findings:
            self._update_learning(learning_system, result)

        # Seed evolution DB with results
        if use_evolution and not dry_run:
            self._seed_evolution(result)

        # Write reports
        report_paths = self._write_reports(
            result, output_dir, platform, report_formats or ["markdown", "json", "html"]
        )
        result.stats["report_paths"] = report_paths

        return result

    async def run_all_campaigns(
        self,
        target: str,
        num_prompts_per_campaign: int = 50,
        **kwargs,
    ) -> Dict[str, CampaignResult]:
        """Run all campaign modes and return results."""
        modes = [m.value for m in CampaignMode if m != CampaignMode.FULL]
        results: Dict[str, CampaignResult] = {}
        for mode in modes:
            print(f"\n{'─'*50}")
            print(f"  Campaign: {mode.upper()}")
            print(f"{'─'*50}")
            result = await self.run_campaign(
                target=target,
                mode=mode,
                num_prompts=num_prompts_per_campaign,
                **kwargs,
            )
            results[mode] = result
        return results

    def evolve_prompts(
        self, attack_type: Optional[str] = None, generations: int = 3
    ) -> Dict[str, Any]:
        """Run evolution loop without testing (offline evolution)."""
        print(f"[*] Evolving prompts — {generations} generation(s), attack_type={attack_type or 'all'}")
        for gen in range(generations):
            offspring = self._evolution.evolve(attack_type, num_offspring=50)
            print(f"  Generation {gen + 1}: {len(offspring)} new prompts")
        stats = self._evolution.stats()
        print(f"[*] Evolution complete: {stats}")
        return stats

    # ── Integration helpers ───────────────────────────────────────────────────

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
            log.info("Attack graph updated with %d red team findings", len(findings))
        except Exception as exc:
            log.error("Attack graph update error: %s", exc)

    def _update_learning(
        self, learning_system: Any, result: CampaignResult
    ) -> None:
        try:
            if hasattr(learning_system, "record_ai_campaign"):
                learning_system.record_ai_campaign({
                    "mode": result.mode,
                    "target": result.target,
                    "findings": len(result.findings),
                    "success_rate": result.success_rate,
                    "duration": result.duration,
                })
        except Exception as exc:
            log.debug("Learning system update error: %s", exc)

    def _seed_evolution(self, result: CampaignResult) -> None:
        """Feed campaign results back into the evolution engine."""
        try:
            for analysis in result.analysis_results:
                pass  # Evolution DB is updated during campaign run via campaign_manager
        except Exception as exc:
            log.debug("Evolution seeding error: %s", exc)

    def _write_reports(
        self,
        result: CampaignResult,
        output_dir: str,
        platform: str,
        formats: List[str],
    ) -> List[str]:
        paths = []
        if not result.findings:
            return paths
        try:
            from core.reporter import Reporter
            out_dir = Path(output_dir) / result.target / "ai_redteam"
            reporter = Reporter(out_dir, target=result.target, platform=platform)
            for f in result.findings:
                reporter.add_finding({
                    "vuln_type": f.vulnerability,
                    "severity": f.severity,
                    "endpoint": result.target,
                    "parameter": "prompt",
                    "description": f.evidence[:500],
                    "evidence": f"Payload: {f.payload[:200]}\n\nResponse: {f.response[:200]}",
                    "confidence": f.confidence,
                    "remediation": f.remediation,
                    "tool": f.tool,
                    "tags": f.tags,
                    "cvss": f.cvss,
                })
            written = reporter.write_all(formats)
            paths = [str(p) for p in written]
            for p in paths:
                print(f"[+] Report: {p}")
        except Exception as exc:
            log.error("Report generation failed: %s", exc)
            # JSON fallback
            try:
                out_dir = Path(output_dir) / result.target / "ai_redteam"
                out_dir.mkdir(parents=True, exist_ok=True)
                json_path = out_dir / f"campaign_{result.campaign_id}.json"
                json_path.write_text(json.dumps({
                    "campaign_id": result.campaign_id,
                    "target": result.target,
                    "mode": result.mode,
                    "findings": [asdict(f) for f in result.findings],
                    "stats": result.stats,
                }, indent=2, default=str))
                paths = [str(json_path)]
            except Exception:
                pass
        return paths

    # ── Display ───────────────────────────────────────────────────────────────

    @staticmethod
    def _print_campaign_summary(result: CampaignResult) -> None:
        sev: Dict[str, int] = {}
        for f in result.findings:
            sev[f.severity] = sev.get(f.severity, 0) + 1

        print(f"\n{'─'*60}")
        print(f"  Campaign Complete — {result.campaign_id}")
        print(f"{'─'*60}")
        print(f"  Mode       : {result.mode}")
        print(f"  Target     : {result.target}")
        print(f"  Duration   : {result.duration:.1f}s")
        print(f"  Sent       : {result.prompts_sent}")
        print(f"  Findings   : {result.vuln_count}")
        print(f"  Bypass rate: {result.success_rate:.1%}")
        print()
        for s in ["critical", "high", "medium", "low", "info"]:
            cnt = sev.get(s, 0)
            if cnt:
                marks = {"critical": "🔴", "high": "🟠", "medium": "🟡", "low": "🔵", "info": "⚪"}
                print(f"  {marks.get(s,'')} {s.capitalize():<10}: {cnt}")
        print()
        if result.findings:
            print("  Top Findings:")
            sorted_findings = sorted(
                result.findings,
                key=lambda f: {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}.get(f.severity, 5)
            )
            for i, f in enumerate(sorted_findings[:5], 1):
                print(f"  {i}. [{f.severity.upper()}] {f.vulnerability}")
                print(f"     Payload: {f.payload[:70]}...")
        print()

    @staticmethod
    def _parse_mode(mode: str) -> CampaignMode:
        mode_map = {
            "prompt_injection": CampaignMode.PROMPT_INJECTION,
            "jailbreak": CampaignMode.JAILBREAK,
            "data_leak": CampaignMode.DATA_LEAK,
            "rag_attack": CampaignMode.RAG_ATTACK,
            "tool_abuse": CampaignMode.TOOL_ABUSE,
            "output_manipulation": CampaignMode.OUTPUT_MANIPULATION,
            "full": CampaignMode.FULL,
        }
        m = mode_map.get(mode.lower())
        if m is None:
            available = ", ".join(mode_map.keys())
            raise ValueError(f"Unknown campaign mode: '{mode}'. Available: {available}")
        return m


# ─────────────────────────────────────────────────────────────────────────────
#  CLI entry point
# ─────────────────────────────────────────────────────────────────────────────

def main_cli(args) -> None:
    """Called by oneinfinity.py cmd_ai_redteam()."""
    target = args.target
    campaign_mode = getattr(args, "campaign", "full")
    num_prompts = getattr(args, "prompts", 100)
    parallel = getattr(args, "parallel", 10)
    auth = getattr(args, "auth", "")
    model = getattr(args, "model", "gpt-3.5-turbo")
    endpoint = getattr(args, "endpoint", "/v1/chat/completions")
    output_dir = getattr(args, "output", "recon")
    platform = getattr(args, "platform", "hackerone")
    use_evolution = getattr(args, "evolve", True)
    dry_run = getattr(args, "dry_run", False)
    context = getattr(args, "context", "")
    yes = getattr(args, "yes", False)

    if not yes:
        confirm = input(
            f"\n[!] This will send {num_prompts} adversarial prompts to {target}.\n"
            f"    Campaign: {campaign_mode} | Parallel: {parallel}\n"
            f"    Ensure you have written authorization. Proceed? [y/N] "
        ).strip().lower()
        if confirm != "y":
            print("[-] Aborted.")
            return

    # Attack graph integration
    attack_graph = None
    try:
        from attack_graph.graph_engine import AttackGraph
        ag_path = Path("recon") / target / "attack_graph.json"
        attack_graph = AttackGraph(target)
        if ag_path.exists():
            attack_graph.load(str(ag_path))
    except Exception:
        pass

    engine = AIRedTeamEngine()
    asyncio.run(engine.run_campaign(
        target=target,
        mode=campaign_mode,
        num_prompts=num_prompts,
        parallel=parallel,
        auth_header=auth,
        model=model,
        endpoint_path=endpoint,
        use_evolution=use_evolution,
        dry_run=dry_run,
        context=context,
        output_dir=output_dir,
        platform=platform,
        attack_graph=attack_graph,
    ))


if __name__ == "__main__":
    import argparse
    p = argparse.ArgumentParser(description="AI Red Team Engine")
    p.add_argument("target", help="Target AI endpoint URL")
    p.add_argument("--campaign", default="full",
                   choices=["prompt_injection", "jailbreak", "data_leak",
                            "rag_attack", "tool_abuse", "output_manipulation", "full"])
    p.add_argument("--prompts", type=int, default=100, help="Number of prompts")
    p.add_argument("--parallel", type=int, default=10, help="Parallel requests")
    p.add_argument("--auth", default="", help="Authorization header (e.g. 'Bearer sk-...')")
    p.add_argument("--model", default="gpt-3.5-turbo")
    p.add_argument("--endpoint", default="/v1/chat/completions")
    p.add_argument("--output", default="recon")
    p.add_argument("--platform", default="hackerone")
    p.add_argument("--evolve", action="store_true", default=True)
    p.add_argument("--dry-run", dest="dry_run", action="store_true")
    p.add_argument("--context", default="", help="Target context (e.g. 'customer support chatbot')")
    p.add_argument("--yes", "-y", action="store_true")
    args = p.parse_args()
    main_cli(args)
