"""
CLI command handlers for ai domain.
Each public function is cmd_* (handler) or register() (argparse setup).
"""
from __future__ import annotations
import sys
import os
import asyncio
import logging
from pathlib import Path
from oneinfinity.cli._helpers import (
    CLI_COMMAND, WORKSPACE_DIRNAME, LEGACY_WORKSPACE_DIRNAME,
    get_workspace_root, find_program_dir, get_program_dir,
)

log = logging.getLogger(__name__)

def cmd_ai_test(args):
    """
    oneinfinity ai-test <target> — AI security engine: test an AI endpoint for vulnerabilities.

    Examples:
      oneinfinity ai-test https://api.openai.com --all --auth "Bearer sk-..."
      oneinfinity ai-test https://chatbot.acme.com --garak --pyrit
      oneinfinity ai-test https://ai.target.com --rebuff --yes
    """
    _inject_proxy(args)
    from oneinfinity.ai.ai_security_engine import main_cli
    main_cli(args)


def cmd_ai_redteam(args):
    """
    oneinfinity ai-redteam <target> — AI red team engine: adversarial prompt campaigns.

    Examples:
      oneinfinity ai-redteam https://chatbot.acme.com
      oneinfinity ai-redteam https://ai.target.com --campaign jailbreak --prompts 5000
      oneinfinity ai-redteam https://rag.acme.com --campaign rag_attack --parallel 20
      oneinfinity ai-redteam https://agent.acme.com --campaign tool_abuse --evolve
    """
    try:
        from oneinfinity.enforcement_controller import get_enforcement_controller as _get_ec
        _get_ec().register_module("ai-redteam")
    except Exception:
        pass
    _inject_proxy(args)
    from oneinfinity.ai.ai_redteam_engine import main_cli
    main_cli(args)


def _inject_proxy(args) -> None:
    """Inject --proxy arg into global proxy_manager if provided."""
    proxy_addr = getattr(args, "proxy", None)
    if proxy_addr:
        try:
            from oneinfinity.infra.proxy_manager import configure_proxy_from_args
            configure_proxy_from_args(args)
        except Exception:
            pass


def cmd_ai_agent_test(args):
    """
    oneinfinity ai-agent-test <target> — AI Agent Pentesting Engine.

    Tests AI agents that can execute tools, APIs, or code for:
      • Tool abuse (bash, code_exec, file read, shell commands)
      • API abuse (SSRF, admin paths, credential forwarding, GraphQL)
      • Data exfiltration (OOB callbacks, PII leakage, sensitive data)

    Examples:
      oneinfinity ai-agent-test https://agent.acme.com --all
      oneinfinity ai-agent-test https://agent.acme.com --tool-abuse --api-abuse
      oneinfinity ai-agent-test https://agent.acme.com --data-exfiltration --oob-domain your.burp.collaborator.net
      oneinfinity ai-agent-test https://agent.acme.com --all --auth "Bearer sk-..." --parallel 10
    """
    try:
        from oneinfinity.enforcement_controller import get_enforcement_controller as _get_ec
        _get_ec().register_module("ai-redteam")
    except Exception:
        pass
    _inject_proxy(args)
    from oneinfinity.ai.ai_agent_pentest_engine import main_cli
    main_cli(args)


def cmd_ai_execute(args):
    """oneinfinity ai <prompt> [--tier FAST|STANDARD|PREMIUM] — run a task through the AI orchestrator."""
    raw = getattr(args, 'args', [])
    tier_arg = None
    prompt_parts = []
    i = 0
    while i < len(raw):
        if raw[i] in ('--tier', '-t') and i + 1 < len(raw):
            tier_arg = raw[i + 1].upper()
            i += 2
        else:
            prompt_parts.append(raw[i])
            i += 1

    prompt = ' '.join(prompt_parts).strip()
    if not prompt:
        print("Usage: oneinfinity ai <prompt> [--tier FAST|STANDARD|PREMIUM]")
        return

    try:
        from oneinfinity.model_orchestrator import get_orchestrator, ModelTier
        orch = get_orchestrator()
        force_tier = ModelTier[tier_arg] if tier_arg else None
        task = {"description": prompt, "prompt": prompt}
        print(f"  [*] Classifying and routing task...")
        output = orch.execute(task, force_tier=force_tier)
        print(f"\n  Model: {output.model_id} ({output.tier.name})")
        print(f"  Confidence: {output.confidence:.0%}")
        if output.escalated_from:
            print(f"  Escalated from: {output.escalated_from} ({output.escalation_reason})")
        print(f"  Tokens: {output.total_tokens}  Cost: ${output.cost_usd:.6f}")
        print(f"  Retries: {output.retries}\n")
        print("─" * 60)
        print(output.content)
        print("─" * 60)
    except Exception as e:
        print(f"  [!] Error: {e}")


def cmd_ai_status(args):
    """oneinfinity ai-status — show orchestrator status, models, and budget."""
    try:
        from oneinfinity.model_orchestrator import get_orchestrator
        status = get_orchestrator().status()
        print(f"\n  Model Orchestrator")
        print(f"  Loaded:          {status['loaded']}")
        print(f"  Models total:    {status['models_total']}")
        print(f"  Models enabled:  {status['models_enabled']}")
        print(f"  Budget today:    ${status['budget']['today_usd']:.4f} / ${status['budget']['daily_limit']} ({status['budget']['daily_pct']}%)")
        print(f"  Budget month:    ${status['budget']['month_usd']:.4f} / ${status['budget']['monthly_limit']} ({status['budget']['monthly_pct']}%)")
        print(f"  Projected/month: ${status['budget']['projected_monthly']:.4f}")
        p = status['policy']
        print(f"  Escalation:      FAST→STANDARD @ {p['fast_to_standard_threshold']:.0%}  STANDARD→PREMIUM @ {p['standard_to_premium_threshold']:.0%}")
        print(f"  Max retries:     {p['max_retries']}")
        print()
    except Exception as e:
        print(f"  [!] Error: {e}")


def cmd_ai_budget(args):
    """oneinfinity ai-budget [today|this_month|all_time] — show model usage and costs."""
    raw    = getattr(args, 'args', [])
    period = raw[0] if raw else "today"
    try:
        from oneinfinity.infra.model_budget_manager import get_budget_manager
        summary = get_budget_manager().get_summary(period).to_dict()
        print(f"\n  AI Model Usage — {summary['period']}")
        print(f"  Total calls:    {summary['total_calls']}")
        print(f"  Total tokens:   {summary['total_tokens']:,}")
        print(f"  Total cost:     ${summary['total_cost_usd']:.6f}")
        print(f"  Escalation rate:{summary['escalation_rate']:.0%}")
        print(f"  Daily budget:   {summary['daily_budget_used']:.0%} used")
        print(f"  Monthly budget: {summary['monthly_budget_used']:.0%} used")
        if summary['cost_by_model']:
            print(f"\n  Cost by model:")
            for m, c in sorted(summary['cost_by_model'].items(), key=lambda x: -x[1]):
                calls = summary['calls_by_model'].get(m, 0)
                print(f"    {m:<30}  ${c:.6f}  ({calls} calls)")
        if summary['cost_by_category']:
            print(f"\n  Cost by category:")
            for cat, c in sorted(summary['cost_by_category'].items(), key=lambda x: -x[1]):
                print(f"    {cat:<20}  ${c:.6f}")
        print()
    except Exception as e:
        print(f"  [!] Error: {e}")


def cmd_ai_models(args):
    """oneinfinity ai-models — list registered models and their tiers/costs."""
    try:
        from oneinfinity.model_orchestrator import get_orchestrator
        models = get_orchestrator().list_models()
        print(f"\n  {'Model':<25}  {'Provider':<10}  {'Tier':<8}  {'$/1k in':>8}  {'$/1k out':>9}  {'Ctx':>7}  {'En':>3}")
        print(f"  {'─'*25}  {'─'*10}  {'─'*8}  {'─'*8}  {'─'*9}  {'─'*7}  {'─'*3}")
        for m in models:
            en = '✓' if m['enabled'] else '✗'
            print(f"  {m['model_id']:<25}  {m['provider']:<10}  {m['tier']:<8}  "
                  f"{m['cost_per_1k_input']:>8.5f}  {m['cost_per_1k_output']:>9.5f}  "
                  f"{m['max_context_tokens']//1000:>6}k  {en:>3}")
        print()
    except Exception as e:
        print(f"  [!] Error: {e}")


# ── Graph Brain handlers ───────────────────────────────────────────────────────




def register(subparsers):
    """Register ai commands with the CLI argument parser."""
    sub = subparsers
    ai_test = sub.add_parser(
        "ai-test",
        help="AI Security Engine: test AI endpoints for prompt injection, jailbreaks, data leaks",
    )
    ai_test.add_argument("target", help="Target AI endpoint URL")
    ai_test.add_argument("--all", action="store_true", help="Run all AI security tools")
    ai_test.add_argument("--garak", action="store_true", help="Run Garak LLM scanner")
    ai_test.add_argument("--pyrit", action="store_true", help="Run PyRIT (Microsoft) red team")
    ai_test.add_argument("--giskard", action="store_true", help="Run Giskard test suite")
    ai_test.add_argument("--purple-llama", dest="purple_llama", action="store_true",
                         help="Run Purple Llama CyberSecEval")
    ai_test.add_argument("--rebuff", action="store_true", help="Run Rebuff injection bypass tests")
    ai_test.add_argument("--art", action="store_true", help="Run Adversarial Robustness Toolbox")
    ai_test.add_argument("--auth", default="", metavar="HEADER",
                         help="Authorization header value (e.g. 'Bearer sk-...')")
    ai_test.add_argument("--model", default="gpt-3.5-turbo", help="Model name for OpenAI-compat APIs")
    ai_test.add_argument("--endpoint", default="/v1/chat/completions",
                         help="API endpoint path (default: /v1/chat/completions)")
    ai_test.add_argument("--output", "-o", default="recon", help="Output directory")
    ai_test.add_argument("--platform", default="hackerone",
                         choices=["hackerone", "bugcrowd", "intigriti", "yeswehack"])
    ai_test.add_argument("--formats", nargs="+", default=["markdown", "json", "html"],
                         metavar="FMT", help="Report formats")
    ai_test.add_argument("--yes", "-y", action="store_true", help="Skip authorization prompt")
    ai_test.add_argument("--proxy", default="", metavar="URL",
                         help="Route traffic through proxy (e.g. http://127.0.0.1:8080)")

    ai_rt = sub.add_parser(
        "ai-redteam",
        help="AI Red Team Engine: adversarial prompt campaigns at scale",
    )
    ai_rt.add_argument("target", help="Target AI endpoint URL")
    ai_rt.add_argument("--campaign", default="full",
                       choices=["prompt_injection", "jailbreak", "data_leak",
                                "rag_attack", "tool_abuse", "output_manipulation", "full"],
                       help="Campaign mode (default: full)")
    ai_rt.add_argument("--prompts", type=int, default=100,
                       help="Number of adversarial prompts to generate (default: 100)")
    ai_rt.add_argument("--parallel", type=int, default=10,
                       help="Number of parallel requests (default: 10)")
    ai_rt.add_argument("--auth", default="", metavar="HEADER",
                       help="Authorization header value")
    ai_rt.add_argument("--model", default="gpt-3.5-turbo")
    ai_rt.add_argument("--endpoint", default="/v1/chat/completions")
    ai_rt.add_argument("--output", "-o", default="recon")
    ai_rt.add_argument("--platform", default="hackerone",
                       choices=["hackerone", "bugcrowd", "intigriti", "yeswehack"])
    ai_rt.add_argument("--evolve", action="store_true", default=True,
                       help="Use evolved prompts from learning DB (default: on)")
    ai_rt.add_argument("--no-evolve", dest="evolve", action="store_false",
                       help="Disable evolved prompts")
    ai_rt.add_argument("--dry-run", dest="dry_run", action="store_true",
                       help="Generate prompts but do not send")
    ai_rt.add_argument("--context", default="",
                       help="Target context description (e.g. 'customer support chatbot')")
    ai_rt.add_argument("--yes", "-y", action="store_true")
    ai_rt.add_argument("--proxy", default="", metavar="URL",
                       help="Route traffic through proxy (e.g. http://127.0.0.1:8080)")

    ai_agent = sub.add_parser(
        "ai-agent-test",
        help="AI Agent Pentest Engine: test AI agents for tool abuse, API abuse, data exfiltration",
    )
    ai_agent.add_argument("target", help="Target AI agent endpoint URL")
    ai_agent.add_argument("--all", action="store_true",
                          help="Run all test modules (tool-abuse + api-abuse + data-exfiltration)")
    ai_agent.add_argument("--tool-abuse", dest="tool_abuse", action="store_true",
                          help="Test for dangerous tool/command execution")
    ai_agent.add_argument("--api-abuse", dest="api_abuse", action="store_true",
                          help="Test for SSRF, admin path access, credential forwarding")
    ai_agent.add_argument("--data-exfiltration", dest="data_exfiltration", action="store_true",
                          help="Test for data exfiltration via OOB callbacks and response leakage")
    ai_agent.add_argument("--auth", default="", metavar="HEADER",
                          help="Authorization header value (e.g. 'Bearer sk-...')")
    ai_agent.add_argument("--model", default="gpt-3.5-turbo",
                          help="Model name for OpenAI-compatible APIs")
    ai_agent.add_argument("--endpoint", default="/v1/chat/completions",
                          help="API endpoint path (default: /v1/chat/completions)")
    ai_agent.add_argument("--oob-domain", dest="oob_domain", default="",
                          metavar="DOMAIN",
                          help="OOB callback domain for exfil detection (e.g. your.burpcollaborator.net)")
    ai_agent.add_argument("--parallel", type=int, default=5,
                          help="Number of parallel probes (default: 5)")
    ai_agent.add_argument("--timeout", type=int, default=30,
                          help="Timeout per probe in seconds (default: 30)")
    ai_agent.add_argument("--context", default="",
                          help="Agent context description (e.g. 'customer support chatbot')")
    ai_agent.add_argument("--output", "-o", default="recon", help="Output directory")
    ai_agent.add_argument("--platform", default="hackerone",
                          choices=["hackerone", "bugcrowd", "intigriti", "yeswehack"])
    ai_agent.add_argument("--formats", nargs="+", default=["markdown", "json", "html"],
                          metavar="FMT", help="Report formats (default: markdown json html)")
    ai_agent.add_argument("--yes", "-y", action="store_true", help="Skip authorization prompt")


