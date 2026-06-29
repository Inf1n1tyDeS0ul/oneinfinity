"""
hackerone_mcp_tool.py — HackerOne MCP tool for Claude Code / Gemini CLI

Exposes HackerOne and Bugcrowd APIs as callable MCP tools.
All submission functions require explicit human approval — cannot auto-submit.

Register with MCP server via mcp/server.py.
"""
from __future__ import annotations

import logging
from typing import Any, Dict, List, Optional

log = logging.getLogger("oneinfinity.mcp.hackerone")


def h1_get_scope(handle: str) -> Dict[str, Any]:
    """
    Fetch the current in-scope assets for a HackerOne program.

    Args:
        handle: HackerOne program handle (e.g., "shopify", "uber")

    Returns:
        {
          "handle": "...",
          "in_scope": [{"asset": "*.shopify.com", "type": "wildcard", "max_severity": "critical"}, ...],
          "out_of_scope": [...],
          "error": ""
        }
    """
    try:
        from oneinfinity.bounty.platform_api import HackerOneClient
        client = HackerOneClient()
        if not client.is_available():
            return {"error": "H1_USERNAME and H1_API_TOKEN env vars required", "in_scope": [], "out_of_scope": []}
        in_scope, out_of_scope = client.get_scope(handle)
        return {
            "handle": handle,
            "in_scope": [
                {"asset": a.asset, "type": a.asset_type, "max_severity": a.max_severity,
                 "eligible_for_bounty": a.eligible_for_bounty}
                for a in in_scope
            ],
            "out_of_scope": [{"asset": a.asset, "type": a.asset_type} for a in out_of_scope],
            "error": "",
        }
    except Exception as exc:
        log.warning("h1_get_scope(%s) failed: %s", handle, exc)
        return {"error": str(exc), "in_scope": [], "out_of_scope": []}


def h1_get_hacktivity(handle: str, limit: int = 20) -> Dict[str, Any]:
    """
    Fetch recent disclosed reports from a HackerOne program.

    Useful for understanding which vuln types actually get paid.

    Args:
        handle: HackerOne program handle
        limit: Max number of reports (default 20)

    Returns:
        {
          "handle": "...",
          "reports": [{"title": "...", "severity": "high", "bounty_usd": 1000.0, ...}, ...],
          "top_vuln_types": ["xss", "idor", ...]
        }
    """
    try:
        from oneinfinity.bounty.platform_api import HackerOneClient
        from collections import Counter
        client = HackerOneClient()
        if not client.is_available():
            return {"error": "H1_USERNAME and H1_API_TOKEN env vars required", "reports": []}
        reports = client.get_hacktivity(handle, limit=limit)
        vuln_types = Counter(r.vuln_type for r in reports if r.vuln_type)
        return {
            "handle": handle,
            "reports": [
                {
                    "id": r.report_id,
                    "title": r.title,
                    "vuln_type": r.vuln_type,
                    "severity": r.severity,
                    "bounty_usd": r.bounty_usd,
                    "disclosed_at": r.disclosed_at,
                    "url": r.url,
                }
                for r in reports
            ],
            "top_vuln_types": [vt for vt, _ in vuln_types.most_common(10)],
            "total_bounty_disclosed": sum(r.bounty_usd for r in reports),
            "error": "",
        }
    except Exception as exc:
        log.warning("h1_get_hacktivity(%s) failed: %s", handle, exc)
        return {"error": str(exc), "reports": []}


def h1_get_program(handle: str) -> Dict[str, Any]:
    """
    Fetch details about a HackerOne program including bounty ranges.

    Args:
        handle: HackerOne program handle

    Returns:
        Program details with bounty info, submission state, scope counts.
    """
    try:
        from oneinfinity.bounty.platform_api import HackerOneClient
        client = HackerOneClient()
        if not client.is_available():
            return {"error": "H1_USERNAME and H1_API_TOKEN env vars required"}
        prog = client.get_program(handle)
        if prog is None:
            return {"error": f"Program '{handle}' not found"}
        return {
            "handle": prog.handle,
            "name": prog.name,
            "offers_bounties": prog.offers_bounties,
            "min_bounty_usd": prog.min_bounty_usd,
            "max_bounty_usd": prog.max_bounty_usd,
            "submission_state": prog.submission_state,
            "in_scope_count": len(prog.in_scope),
            "policy_url": prog.policy_url,
            "error": "",
        }
    except Exception as exc:
        log.warning("h1_get_program(%s) failed: %s", handle, exc)
        return {"error": str(exc)}


def h1_draft_report(
    handle: str,
    title: str,
    severity: str,
    vuln_type: str,
    summary: str,
    steps: str,
    impact: str,
    cvss_score: float = 0.0,
) -> Dict[str, Any]:
    """
    Create a draft report for human review. Does NOT submit — requires explicit approval.

    Args:
        handle: HackerOne program handle
        title: Report title
        severity: critical | high | medium | low
        vuln_type: Vulnerability type (e.g., "XSS", "IDOR")
        summary: Brief vulnerability description
        steps: Steps to reproduce
        impact: Impact statement
        cvss_score: CVSS 3.1 base score

    Returns:
        Draft report dict with approved=False.
        To submit, set approved=True and call h1_submit_report().
        NEVER set approved=True without human review.
    """
    return {
        "handle": handle,
        "title": title,
        "severity": severity,
        "vuln_type": vuln_type,
        "summary": summary,
        "steps": steps,
        "impact": impact,
        "cvss_score": cvss_score,
        "approved": False,
        "warning": (
            "This is a DRAFT only. Review all fields carefully before approving. "
            "Set approved=True only after thorough human review. "
            "Submitting invalid/low-quality reports damages researcher reputation."
        ),
    }


def h1_get_report_status(report_id: str) -> Dict[str, Any]:
    """
    Check the triage status of a submitted HackerOne report.

    Args:
        report_id: Numeric H1 report ID

    Returns:
        {state, severity, bounty_usd, updated_at}
    """
    try:
        from oneinfinity.bounty.platform_api import HackerOneClient
        client = HackerOneClient()
        if not client.is_available():
            return {"error": "H1_USERNAME and H1_API_TOKEN env vars required"}
        status = client.get_report_status(report_id)
        if status is None:
            return {"error": f"Report {report_id} not found"}
        return {
            "report_id": report_id,
            "state": status.state,
            "severity": status.severity,
            "bounty_usd": status.bounty_usd,
            "updated_at": status.updated_at,
            "error": "",
        }
    except Exception as exc:
        return {"error": str(exc)}


def bugcrowd_get_scope(program_code: str) -> Dict[str, Any]:
    """
    Fetch in-scope assets for a Bugcrowd program.

    Args:
        program_code: Bugcrowd program code/slug

    Returns:
        {in_scope: [{asset, type, max_severity}, ...]}
    """
    try:
        from oneinfinity.bounty.platform_api import BugcrowdClient
        client = BugcrowdClient()
        if not client.is_available():
            return {"error": "BUGCROWD_API_TOKEN env var required", "in_scope": []}
        assets = client.get_scope(program_code)
        return {
            "program": program_code,
            "in_scope": [
                {"asset": a.asset, "type": a.asset_type, "max_severity": a.max_severity}
                for a in assets
            ],
            "error": "",
        }
    except Exception as exc:
        return {"error": str(exc), "in_scope": []}


# Tool manifest for MCP server registration
MCP_TOOLS = [
    {
        "name": "h1_get_scope",
        "description": "Fetch HackerOne program scope (in-scope assets and their max severity)",
        "fn": h1_get_scope,
        "parameters": {
            "handle": {"type": "string", "description": "HackerOne program handle"},
        },
    },
    {
        "name": "h1_get_hacktivity",
        "description": "Fetch recent disclosed reports from a HackerOne program to understand which vuln types pay",
        "fn": h1_get_hacktivity,
        "parameters": {
            "handle": {"type": "string", "description": "HackerOne program handle"},
            "limit": {"type": "integer", "description": "Max reports (default 20)", "default": 20},
        },
    },
    {
        "name": "h1_get_program",
        "description": "Fetch HackerOne program details including bounty ranges and submission state",
        "fn": h1_get_program,
        "parameters": {
            "handle": {"type": "string", "description": "HackerOne program handle"},
        },
    },
    {
        "name": "h1_draft_report",
        "description": "Create a draft H1 report for human review. Does NOT submit. Returns draft with approved=False.",
        "fn": h1_draft_report,
        "parameters": {
            "handle": {"type": "string"},
            "title": {"type": "string"},
            "severity": {"type": "string", "enum": ["critical", "high", "medium", "low"]},
            "vuln_type": {"type": "string"},
            "summary": {"type": "string"},
            "steps": {"type": "string"},
            "impact": {"type": "string"},
            "cvss_score": {"type": "number", "default": 0.0},
        },
    },
    {
        "name": "h1_get_report_status",
        "description": "Check triage status of a submitted HackerOne report",
        "fn": h1_get_report_status,
        "parameters": {
            "report_id": {"type": "string", "description": "H1 numeric report ID"},
        },
    },
    {
        "name": "bugcrowd_get_scope",
        "description": "Fetch Bugcrowd program scope (requires BUGCROWD_API_TOKEN)",
        "fn": bugcrowd_get_scope,
        "parameters": {
            "program_code": {"type": "string", "description": "Bugcrowd program code/slug"},
        },
    },
]
