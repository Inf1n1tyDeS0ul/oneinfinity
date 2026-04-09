"""
core/context_builder.py — Structured LLM Context Builder (Phase 5)

Builds lean, consistent context dicts for all LLM calls.
Replaces ad-hoc ctx-slicing in ai_reasoning_engine.py.

Rules:
  - max 10 endpoints (parameterised first, then auth, then rest)
  - max 5 findings (highest severity first)
  - max 5 param URLs
  - chain_data summarised (no raw tokens sent to LLM)
  - fingerprint for call-guard deduplication
"""
from __future__ import annotations

import hashlib
import json
import logging
from typing import Any, Dict, List, Optional

log = logging.getLogger("oneinfinity.core.context_builder")

_SEVERITY_RANK: Dict[str, int] = {
    "critical": 4, "high": 3, "medium": 2, "low": 1, "info": 0,
}


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------


def build_llm_context(
    ctx: dict,
    target: str,
    max_endpoints: int = 10,
    max_findings:  int = 5,
    max_params:    int = 5,
) -> dict:
    """
    Build a lean, structured context dict for LLM prompts.

    Returns a dict with keys:
      target, top_endpoints, key_parameters, auth_endpoints,
      recent_findings, chain_summary, loop_summary, tech_stack
    """
    intel = ctx.get("recon_intel")
    all_urls: List[str] = getattr(intel, "all_urls", []) or [] if intel else []
    params_map: Dict[str, List[str]] = ctx.get("params_map", {}) or {}
    auth_eps: List[str] = ctx.get("auth_endpoints", []) or []

    # ── Top endpoints: parameterised → auth → rest ─────────────────────────
    parameterised = [u for u in all_urls if "?" in u]
    auth_set = set(auth_eps)
    rest = [u for u in all_urls if "?" not in u and u not in auth_set]
    top_endpoints = (parameterised + auth_eps + rest)[:max_endpoints]

    # ── Key parameters: top N URLs from params_map ─────────────────────────
    # Parameterised endpoints first for relevance
    key_parameters: Dict[str, List[str]] = {}
    for url in parameterised[:max_params]:
        if url in params_map:
            key_parameters[url] = params_map[url]
    if len(key_parameters) < max_params:
        for url, params in params_map.items():
            if url not in key_parameters:
                key_parameters[url] = params
            if len(key_parameters) >= max_params:
                break

    # ── Recent findings: sorted by severity ───────────────────────────────
    raw_findings: List[dict] = ctx.get("scan_findings", []) or []
    sorted_findings = sorted(
        raw_findings,
        key=lambda f: _SEVERITY_RANK.get((f.get("severity") or "info").lower(), 0),
        reverse=True,
    )
    recent_findings = [
        {
            "severity":  f.get("severity", "info"),
            "vuln_type": f.get("vuln_type", "unknown"),
            "url":       f.get("url", f.get("target", "")),
        }
        for f in sorted_findings[:max_findings]
    ]

    # ── Chain data summary (no raw token values sent to LLM) ───────────────
    cd: dict = ctx.get("chain_data", {}) or {}
    toks: dict = cd.get("tokens", {})
    chain_summary = {
        "tokens_available":  bool(toks.get("jwt") or toks.get("api_key") or toks.get("session")),
        "jwt_count":         len(toks.get("jwt", [])),
        "api_key_count":     len(toks.get("api_key", [])),
        "session_count":     len(toks.get("session", [])),
        "chain_types":       cd.get("chain_types_executed", [])[-5:],
        "accessible_ids":    len(cd.get("accessible_ids", [])),
    }

    # ── Loop history summary ───────────────────────────────────────────────
    lh: dict = ctx.get("loop_history", {}) or {}
    tested_eps = lh.get("tested_endpoints", set())
    loop_summary = {
        "iterations_done":      lh.get("iteration_count", 0),
        "tested_endpoint_count": len(tested_eps) if isinstance(tested_eps, set) else tested_eps,
        "successful_payloads":  len(lh.get("successful_payloads", [])),
        "pending_signals":      len(lh.get("ai_signals", [])),
        "successful_payload_types": list({
            p.get("vuln_type", "") for p in lh.get("successful_payloads", [])[:5]
        }),
    }

    # ── Tech stack ────────────────────────────────────────────────────────
    tech_stack = str(getattr(intel, "tech_profile", "") if intel else ctx.get("tech_stack", "unknown"))[:200]

    return {
        "target":          target,
        "top_endpoints":   top_endpoints,
        "key_parameters":  key_parameters,
        "auth_endpoints":  auth_eps[:5],
        "recent_findings": recent_findings,
        "chain_summary":   chain_summary,
        "loop_summary":    loop_summary,
        "tech_stack":      tech_stack,
    }


def context_fingerprint(built_ctx: dict) -> str:
    """
    Stable SHA256 fingerprint of a built context dict.
    Used as call-guard: if fingerprint matches last call, skip LLM.
    """
    # Only fingerprint the parts that drive different AI decisions
    relevant = {
        "target":           built_ctx.get("target", ""),
        "endpoint_count":   len(built_ctx.get("top_endpoints", [])),
        "finding_count":    len(built_ctx.get("recent_findings", [])),
        "finding_types":    sorted({f.get("vuln_type", "") for f in built_ctx.get("recent_findings", [])}),
        "chain_types":      sorted(built_ctx.get("chain_summary", {}).get("chain_types", [])),
        "tokens_available": built_ctx.get("chain_summary", {}).get("tokens_available", False),
    }
    raw = json.dumps(relevant, sort_keys=True)
    return hashlib.sha256(raw.encode()).hexdigest()[:20]


def format_for_prompt(built_ctx: dict) -> str:
    """
    Convert a built context dict to a compact human-readable string
    for embedding directly in LLM prompts.
    """
    lines = [f"TARGET: {built_ctx['target']}"]
    lines.append(f"TECH STACK: {built_ctx.get('tech_stack', 'unknown')}")

    eps = built_ctx.get("top_endpoints", [])
    lines.append(f"\nENDPOINTS ({len(eps)} shown):")
    for ep in eps[:10]:
        lines.append(f"  {ep}")

    params = built_ctx.get("key_parameters", {})
    if params:
        lines.append("\nPARAMETERS:")
        for url, plist in list(params.items())[:5]:
            lines.append(f"  {url}: {', '.join(plist)}")

    auths = built_ctx.get("auth_endpoints", [])
    if auths:
        lines.append(f"\nAUTH ENDPOINTS: {', '.join(auths[:3])}")

    findings = built_ctx.get("recent_findings", [])
    if findings:
        lines.append(f"\nEXISTING FINDINGS ({len(findings)}):")
        for f in findings:
            lines.append(f"  [{f.get('severity','?')}] {f.get('vuln_type','?')} @ {f.get('url','?')}")
    else:
        lines.append("\nEXISTING FINDINGS: none")

    cs = built_ctx.get("chain_summary", {})
    if cs.get("tokens_available"):
        lines.append(
            f"\nCHAIN DATA: {cs['jwt_count']} JWT / {cs['api_key_count']} API keys / "
            f"{cs['session_count']} sessions extracted. "
            f"Chains executed: {', '.join(cs.get('chain_types', [])) or 'none'}"
        )

    ls = built_ctx.get("loop_summary", {})
    if ls.get("iterations_done", 0) > 0:
        lines.append(
            f"\nLOOP HISTORY: {ls['iterations_done']} iterations, "
            f"{ls['tested_endpoint_count']} endpoints tested, "
            f"{ls['successful_payloads']} successful payloads, "
            f"pending signals: {ls['pending_signals']}"
        )

    return "\n".join(lines)
