"""Shared finding utilities: deduplication and PoC construction."""
from __future__ import annotations
import re
from urllib.parse import urlparse


def _normalize_path(url: str) -> str:
    """Strip query/fragment, normalize numeric path segments to {id}."""
    try:
        path = urlparse(url).path or url
    except Exception:
        path = url
    path = re.sub(r"(?<=/)\d+(?=/|$)", "{id}", path)
    return path.rstrip("/").lower()


def deduplicate_findings(findings: list) -> list:
    """
    Deduplicate by (normalized_path, vuln_type).
    Keeps highest-confidence finding; merges evidence from duplicates.
    """
    groups: dict = {}
    for f in findings:
        if not isinstance(f, dict):
            continue
        url = f.get("url") or f.get("endpoint") or ""
        vuln_type = (f.get("vuln_type") or f.get("attack_type") or f.get("type") or "").lower()
        key = (_normalize_path(url), vuln_type)

        if key not in groups:
            groups[key] = dict(f)
        else:
            existing = groups[key]
            # Promote higher-confidence variant as the canonical record
            if float(f.get("confidence", 0)) > float(existing.get("confidence", 0)):
                saved_ev = existing.get("evidence", "")
                saved_pl = existing.get("payload", "")
                groups[key] = dict(f)
                existing = groups[key]
                # Re-apply merged fields below using saved values
                if saved_ev and saved_ev not in existing.get("evidence", ""):
                    existing["evidence"] = f"{existing.get('evidence', '')}\n{saved_ev}".strip()
                if saved_pl and not existing.get("payload"):
                    existing["payload"] = saved_pl
            else:
                # Merge evidence from lower-priority duplicate
                ev_new = f.get("evidence", "")
                if ev_new and ev_new not in existing.get("evidence", ""):
                    existing["evidence"] = f"{existing.get('evidence', '')}\n{ev_new}".strip()
                if f.get("payload") and not existing.get("payload"):
                    existing["payload"] = f["payload"]

    return list(groups.values())


def build_poc(f: dict) -> dict:
    """
    Build a complete PoC dict from a raw finding dict.
    Generates a curl command and structured exploitation narrative.
    """
    url = f.get("url") or f.get("endpoint") or ""
    method = (f.get("method") or "GET").upper()
    payload = f.get("payload") or ""
    headers = f.get("headers") or {}
    parameter = f.get("parameter") or ""
    evidence = f.get("evidence") or ""
    validation_status = f.get("validation_status") or ""
    vuln_type = f.get("vuln_type") or f.get("attack_type") or ""

    # Build curl command
    curl_parts = ["curl", "-s", "-i"]
    if method != "GET":
        curl_parts += ["-X", method]
    if isinstance(headers, dict):
        for hname, hval in headers.items():
            curl_parts += ["-H", f'"{hname}: {hval}"']
    if payload and method in ("POST", "PUT", "PATCH"):
        curl_parts += ["--data-raw", f"'{payload}'"]
    curl_parts.append(f'"{url}"')
    request_poc = " ".join(curl_parts)

    how_exploited = f.get("how_exploited") or _infer_exploitation(vuln_type, payload, parameter, url)
    how_validated = f.get("how_validated") or _infer_validation(validation_status, evidence, vuln_type)
    reproduction_steps = f.get("reproduction_steps") or _build_steps(
        url, method, payload, parameter, vuln_type, how_exploited
    )
    remediation = f.get("remediation") or _infer_remediation(vuln_type)
    tags = f.get("tags") or ([vuln_type] if vuln_type else [])

    return {
        "request_poc": request_poc,
        "method": method,
        "headers": headers,
        "parameter": parameter,
        "how_exploited": how_exploited,
        "how_validated": how_validated,
        "validation_status": validation_status,
        "response_excerpt": f.get("response_excerpt") or f.get("response") or "",
        "reproduction_steps": reproduction_steps,
        "remediation": remediation,
        "tags": tags,
    }


def _infer_exploitation(vuln_type: str, payload: str, parameter: str, url: str) -> str:
    vt = vuln_type.lower()
    if "sql" in vt:
        return f"SQL injection via parameter '{parameter}' with payload: {payload}" if parameter else f"SQL injection with payload: {payload}"
    if "xss" in vt:
        return f"Cross-site scripting via parameter '{parameter}' with payload: {payload}"
    if "default_cred" in vt or ("auth" in vt and "bypass" in vt):
        return f"Authentication bypass using default credentials. Payload: {payload}"
    if "idor" in vt:
        return f"Insecure direct object reference at endpoint: {url}"
    if "ssrf" in vt:
        return f"Server-side request forgery via parameter '{parameter}' with payload: {payload}"
    if "rce" in vt or "command_inj" in vt:
        return f"Remote code execution via payload: {payload}"
    if "graphql" in vt:
        return f"GraphQL vulnerability via query manipulation: {payload}"
    if "open_redirect" in vt:
        return f"Open redirect via parameter '{parameter}' pointing to: {payload}"
    if payload:
        return f"Exploited via payload: {payload}"
    return f"Vulnerability identified at endpoint: {url}"


def _infer_validation(validation_status: str, evidence: str, vuln_type: str) -> str:
    snippet = (evidence[:300] + "...") if len(evidence) > 300 else evidence
    if validation_status == "confirmed":
        return f"Confirmed: server response matched known vulnerability signature. {snippet}"
    if validation_status == "likely":
        return f"High-confidence indicator: response pattern matches known vulnerability. {snippet}"
    if evidence:
        return f"Evidence collected from response: {snippet}"
    return "Validated via automated testing and response analysis."


def _build_steps(url: str, method: str, payload: str, parameter: str, vuln_type: str, how_exploited: str) -> str:
    steps = [f"1. Send {method} request to: {url}"]
    n = 2
    if parameter:
        steps.append(f"{n}. Target parameter: {parameter}")
        n += 1
    if payload:
        steps.append(f"{n}. Inject/send payload: {payload}")
        n += 1
    steps.append(f"{n}. Observe response for vulnerability indicators.")
    n += 1
    steps.append(f"{n}. Confirm {vuln_type}: {how_exploited}")
    return "\n".join(steps)


def _infer_remediation(vuln_type: str) -> str:
    vt = vuln_type.lower()
    if "sql" in vt:
        return "Use parameterized queries. Never interpolate user input into SQL statements."
    if "xss" in vt:
        return "HTML-encode all user-supplied output. Apply a strict Content-Security-Policy."
    if "default_cred" in vt or "auth" in vt:
        return "Change all default credentials. Enforce strong password policy and account lockout."
    if "idor" in vt:
        return "Implement server-side authorization for all object references. Use indirect reference maps."
    if "ssrf" in vt:
        return "Validate and allowlist outbound URLs. Block access to internal network ranges."
    if "rce" in vt or "command" in vt:
        return "Never pass user input to shell commands. Use safe language APIs."
    if "graphql" in vt:
        return "Apply query depth/complexity limits, field-level authorization, and rate limiting."
    if "open_redirect" in vt:
        return "Validate redirect targets against an allowlist of trusted domains."
    return "Apply input validation, least privilege, and defense-in-depth. Conduct regular security testing."
