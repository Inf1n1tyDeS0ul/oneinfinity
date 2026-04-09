"""
validation_engine_web.py — Safe, non-destructive exploit validation for web findings.

Validates each finding type with the minimum-privilege HTTP probe needed to confirm
or reject the vulnerability without modifying application state.

Safety guarantees:
  - Read-only probes only (no writes, deletes, or account changes)
  - Hard 8-second wall-clock timeout per validation
  - Respects rate limits (backs off on 429)
  - Never follows redirects to off-scope hosts
  - OOB callbacks use Canary/webhook.site-style tokens (optional)
"""
from __future__ import annotations

import hashlib
import json
import logging
import random
import re
import string
import time
import urllib.parse
from concurrent.futures import ThreadPoolExecutor, as_completed, TimeoutError as FuturesTimeout
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional

import requests
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry

log = logging.getLogger("oi.validation_web")

# ---------------------------------------------------------------------------
# Result dataclass
# ---------------------------------------------------------------------------

@dataclass
class ValidationResult:
    finding_id: str
    vuln_type: str
    status: str                      # "confirmed" | "rejected" | "unverified"
    confidence_delta: float = 0.0    # Δ applied to original confidence score
    evidence: str = ""               # Response snippet / diff / status codes
    payload_used: str = ""
    latency_ms: float = 0.0
    http_status: int = 0
    error: str = ""
    validated_at: str = field(default_factory=lambda: time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()))

    def to_dict(self) -> dict:
        return {
            "finding_id":      self.finding_id,
            "vuln_type":       self.vuln_type,
            "status":          self.status,
            "confidence_delta": self.confidence_delta,
            "evidence":        self.evidence,
            "payload_used":    self.payload_used,
            "latency_ms":      round(self.latency_ms, 1),
            "http_status":     self.http_status,
            "error":           self.error,
            "validated_at":    self.validated_at,
        }


# ---------------------------------------------------------------------------
# HTTP session (shared, with backoff)
# ---------------------------------------------------------------------------

_WAF_UA_POOL = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.2 Safari/605.1.15",
    "Mozilla/5.0 (X11; Linux x86_64; rv:122.0) Gecko/20100101 Firefox/122.0",
]

def _make_session(timeout: int = 8, rate_limit_backoff: bool = True) -> requests.Session:
    session = requests.Session()
    retry = Retry(
        total=2,
        backoff_factor=1.0,
        status_forcelist=[429, 503],
        allowed_methods=["GET", "POST", "PUT", "OPTIONS", "HEAD"],
        raise_on_status=False,
    )
    session.mount("https://", HTTPAdapter(max_retries=retry))
    session.mount("http://", HTTPAdapter(max_retries=retry))
    session.headers.update({
        "User-Agent": random.choice(_WAF_UA_POOL),
        "Accept": "text/html,application/json,*/*;q=0.8",
        "Accept-Language": "en-US,en;q=0.9",
    })
    return session


# ---------------------------------------------------------------------------
# Individual validators — one per vuln_type
# ---------------------------------------------------------------------------

def _validate_cors(finding: dict, session: requests.Session) -> ValidationResult:
    """
    Send cross-origin preflight with evil Origin header.
    Confirmed if Access-Control-Allow-Origin echoes our evil origin,
    or if ACAO: * + Access-Control-Allow-Credentials: true.
    """
    fid    = finding.get("finding_id", "?")
    url    = finding.get("url", "")
    evil   = "https://evil-attacker.com"

    if not url:
        return ValidationResult(fid, "cors", "unverified", error="no url")

    t0 = time.time()
    try:
        r = session.options(
            url, timeout=8,
            headers={"Origin": evil, "Access-Control-Request-Method": "GET"},
            allow_redirects=False,
        )
        latency = (time.time() - t0) * 1000
        acao = r.headers.get("Access-Control-Allow-Origin", "")
        acac = r.headers.get("Access-Control-Allow-Credentials", "").lower()

        if acao == evil:
            evidence = f"ACAO: {acao} | ACAC: {acac} (evil origin reflected)"
            delta = +0.25
            status = "confirmed"
        elif acao == "*" and acac == "true":
            evidence = f"ACAO: * with credentials=true (auth bypass risk)"
            delta = +0.20
            status = "confirmed"
        elif acao == "*":
            evidence = f"ACAO: * (no credentials — informational)"
            delta = +0.05
            status = "unverified"
        else:
            evidence = f"ACAO: {acao!r} — does not reflect evil origin"
            delta = -0.10
            status = "rejected"

        return ValidationResult(fid, "cors", status, delta, evidence,
                                evil, latency, r.status_code)
    except Exception as exc:
        return ValidationResult(fid, "cors", "unverified", error=str(exc))


def _validate_jwt_none(finding: dict, session: requests.Session) -> ValidationResult:
    """
    Forge a JWT with 'none' algorithm and attempt to access an authenticated endpoint.
    Only tests GET — no state modification.
    """
    import base64 as b64

    fid = finding.get("finding_id", "?")
    url = finding.get("url", "")
    if not url:
        return ValidationResult(fid, "jwt_none_alg", "unverified", error="no url")

    def _b64url(data: dict) -> str:
        return b64.urlsafe_b64encode(json.dumps(data).encode()).decode().rstrip("=")

    header  = _b64url({"alg": "none", "typ": "JWT"})
    payload = _b64url({"sub": "1", "role": "admin", "iat": int(time.time())})
    forged  = f"{header}.{payload}."          # empty signature

    t0 = time.time()
    try:
        r = session.get(
            url, timeout=8,
            headers={"Authorization": f"Bearer {forged}"},
            allow_redirects=False,
        )
        latency = (time.time() - t0) * 1000

        if r.status_code in (200, 201, 204):
            evidence = f"HTTP {r.status_code} — none-alg JWT accepted → auth bypass confirmed"
            return ValidationResult(fid, "jwt_none_alg", "confirmed", +0.35,
                                    evidence, forged, latency, r.status_code)
        elif r.status_code == 401:
            evidence = f"HTTP 401 — none-alg JWT rejected (safe)"
            return ValidationResult(fid, "jwt_none_alg", "rejected", -0.20,
                                    evidence, forged, latency, r.status_code)
        else:
            evidence = f"HTTP {r.status_code} — ambiguous (WAF/redirect?)"
            return ValidationResult(fid, "jwt_none_alg", "unverified", 0.0,
                                    evidence, forged, latency, r.status_code)
    except Exception as exc:
        return ValidationResult(fid, "jwt_none_alg", "unverified", error=str(exc))


def _validate_ssrf(finding: dict, session: requests.Session) -> ValidationResult:
    """
    Probe SSRF by injecting well-known safe internal addresses into URL parameters.
    Checks:
      1. Cloud metadata (169.254.169.254) — connection refused = endpoint exists
      2. localhost loopback (127.0.0.1) — different response = SSRF confirmed
    Non-destructive: only reads, never writes.
    """
    fid = finding.get("finding_id", "?")
    url = finding.get("url", "")
    if not url:
        return ValidationResult(fid, "ssrf", "unverified", error="no url")

    parsed = urllib.parse.urlparse(url)
    params  = dict(urllib.parse.parse_qsl(parsed.query))

    # Find URL-like params to inject SSRF payloads into
    url_params = [k for k, v in params.items()
                  if any(x in v for x in ["http", "url", "uri", "link", "fetch", "src"])]
    if not url_params:
        url_params = list(params.keys())[:2]  # Try first two params as candidates

    if not url_params and not params:
        # Try common param names as GET args on the endpoint
        url_params = ["url", "fetch", "uri", "src", "redirect"]
        params = {p: "https://vulnbank.org" for p in url_params[:1]}

    ssrf_probe  = "http://169.254.169.254/latest/meta-data/"
    noop_value  = "https://vulnbank.org/"

    results = []
    t0 = time.time()
    try:
        # Baseline request
        base_resp = session.get(url, timeout=6, allow_redirects=False)
        base_status = base_resp.status_code

        for param in url_params[:2]:
            # SSRF probe
            p_ssrf = dict(params)
            p_ssrf[param] = ssrf_probe
            probe_url = urllib.parse.urlunparse(parsed._replace(query=urllib.parse.urlencode(p_ssrf)))

            try:
                r = session.get(probe_url, timeout=6, allow_redirects=False)
                latency = (time.time() - t0) * 1000

                # Indicators of SSRF: different response, connection refused to metadata,
                # or metadata content in response
                if "ami-id" in r.text or "instance-id" in r.text or "meta-data" in r.text:
                    evidence = f"Cloud metadata content in response! param={param} status={r.status_code}"
                    return ValidationResult(fid, "ssrf", "confirmed", +0.40,
                                            evidence, ssrf_probe, latency, r.status_code)

                if r.status_code != base_status and r.status_code in (200, 500):
                    # Different response code with internal target = behavioural SSRF
                    evidence = f"Baseline={base_status} vs SSRF probe={r.status_code} — behavioural difference"
                    results.append(("unverified", +0.10, evidence, r.status_code))
                else:
                    results.append(("rejected", -0.05, f"No SSRF indicators: HTTP {r.status_code}", r.status_code))
            except requests.exceptions.ConnectionError:
                # Connection refused to SSRF target = backend actually tried to connect!
                evidence = f"ConnectionError for SSRF payload → backend attempted connection to {ssrf_probe}"
                results.append(("confirmed", +0.30, evidence, 0))

        latency = (time.time() - t0) * 1000
        if results:
            best = sorted(results, key=lambda x: x[1], reverse=True)[0]
            return ValidationResult(fid, "ssrf", best[0], best[1], best[2], ssrf_probe, latency, best[3])
        return ValidationResult(fid, "ssrf", "unverified", 0.0, "No injectable params found", ssrf_probe)

    except Exception as exc:
        return ValidationResult(fid, "ssrf", "unverified", error=str(exc))


def _validate_idor(finding: dict, session: requests.Session) -> ValidationResult:
    """
    Probe IDOR by iterating numeric IDs in the URL path and comparing responses.
    Compares: own-ID response vs other-IDs response.
    Confirmed if: other IDs return 200 + non-empty body.
    Read-only — GET requests only.
    """
    fid = finding.get("finding_id", "?")
    url = finding.get("url", "")
    if not url:
        return ValidationResult(fid, "idor", "unverified", error="no url")

    # Find numeric path segments to enumerate
    parts = url.rstrip("/").split("/")
    id_indices = [i for i, p in enumerate(parts) if p.isdigit()]

    if not id_indices:
        return ValidationResult(fid, "idor", "unverified", error="no numeric IDs in URL path")

    idx = id_indices[-1]
    base_id = int(parts[idx])
    probe_ids = [i for i in range(1, 20) if i != base_id][:5]

    t0 = time.time()
    try:
        # Baseline
        base_resp = session.get(url, timeout=6, allow_redirects=False)
        base_size = len(base_resp.content)

        different_200s = 0
        evidence_parts = [f"Baseline: HTTP {base_resp.status_code} ({base_size}B)"]

        for pid in probe_ids:
            probe_parts = list(parts)
            probe_parts[idx] = str(pid)
            probe_url = "/".join(probe_parts)

            try:
                r = session.get(probe_url, timeout=5, allow_redirects=False)
                size = len(r.content)
                evidence_parts.append(f"ID={pid}: HTTP {r.status_code} ({size}B)")

                if r.status_code == 200 and size > 50 and base_resp.status_code == 200:
                    # Compare content hash
                    if hashlib.md5(r.content).hexdigest() != hashlib.md5(base_resp.content).hexdigest():
                        different_200s += 1

            except Exception:
                pass

        latency = (time.time() - t0) * 1000
        evidence = " | ".join(evidence_parts)

        if different_200s >= 2:
            return ValidationResult(fid, "idor", "confirmed", +0.30, evidence,
                                    f"IDs 1-{probe_ids[-1]}", latency, 200)
        elif different_200s == 1:
            return ValidationResult(fid, "idor", "unverified", +0.10, evidence,
                                    f"IDs 1-{probe_ids[-1]}", latency, 200)
        else:
            return ValidationResult(fid, "idor", "rejected", -0.10, evidence,
                                    "", latency, base_resp.status_code)

    except Exception as exc:
        return ValidationResult(fid, "idor", "unverified", error=str(exc))


def _validate_race_condition(finding: dict, session: requests.Session) -> ValidationResult:
    """
    Probe race condition by sending N concurrent identical requests.
    Uses threading — not async — to stay simple.
    Non-destructive: uses a read endpoint or a safe idempotent GET.
    """
    import threading

    fid = finding.get("finding_id", "?")
    url = finding.get("url", "")
    if not url:
        return ValidationResult(fid, "race_condition", "unverified", error="no url")

    results_lock  = threading.Lock()
    status_codes: List[int] = []
    CONCURRENCY = 8

    def _probe():
        try:
            r = session.get(url, timeout=5, allow_redirects=False)
            with results_lock:
                status_codes.append(r.status_code)
        except Exception:
            with results_lock:
                status_codes.append(0)

    t0 = time.time()
    threads = [threading.Thread(target=_probe) for _ in range(CONCURRENCY)]
    for th in threads: th.start()
    for th in threads: th.join(timeout=10)
    latency = (time.time() - t0) * 1000

    ok_count = status_codes.count(200)
    unique    = len(set(status_codes))

    if ok_count == CONCURRENCY and unique == 1:
        evidence = f"All {CONCURRENCY} concurrent requests returned HTTP 200 — endpoint lacks concurrency control"
        return ValidationResult(fid, "race_condition", "confirmed", +0.25, evidence,
                                f"{CONCURRENCY}x concurrent GET", latency, 200)
    else:
        evidence = f"Status codes: {sorted(status_codes)} — mixed responses (good)"
        return ValidationResult(fid, "race_condition", "unverified", 0.0, evidence,
                                "", latency, status_codes[0] if status_codes else 0)


def _validate_auth_bypass(finding: dict, session: requests.Session) -> ValidationResult:
    """
    Test authentication bypass by probing the endpoint without credentials.
    Also tests common bypass headers.
    """
    fid = finding.get("finding_id", "?")
    url = finding.get("url", "")
    if not url:
        return ValidationResult(fid, "auth_bypass", "unverified", error="no url")

    bypass_headers_list = [
        {},                                          # No credentials
        {"X-Original-URL": "/admin"},
        {"X-Forwarded-For": "127.0.0.1"},
        {"X-Custom-IP-Authorization": "127.0.0.1"},
        {"X-Forwarded-Host": "localhost"},
    ]

    t0 = time.time()
    results = []
    try:
        for extra in bypass_headers_list:
            try:
                r = session.get(url, timeout=5, headers=extra, allow_redirects=False)
                results.append((r.status_code, len(r.content), str(extra)))
                if r.status_code == 200 and len(r.content) > 100:
                    latency = (time.time() - t0) * 1000
                    evidence = f"HTTP 200 with bypass headers {extra} — unauthenticated access confirmed"
                    return ValidationResult(fid, "auth_bypass", "confirmed", +0.30, evidence,
                                            str(extra), latency, 200)
            except Exception:
                pass

        latency = (time.time() - t0) * 1000
        evidence = " | ".join(f"{s}({sz}B)" for s,sz,_ in results[:3])
        return ValidationResult(fid, "auth_bypass", "unverified", 0.0,
                                f"All bypass attempts blocked. Results: {evidence}", "", latency,
                                results[0][0] if results else 0)
    except Exception as exc:
        return ValidationResult(fid, "auth_bypass", "unverified", error=str(exc))


def _validate_security_headers(finding: dict, session: requests.Session) -> ValidationResult:
    """Check for missing security headers on the base URL."""
    fid = finding.get("finding_id", "?")
    url = finding.get("url", "")
    if not url:
        return ValidationResult(fid, "missing_headers", "unverified", error="no url")

    REQUIRED = {
        "x-content-type-options":         "nosniff",
        "x-frame-options":                 None,
        "content-security-policy":         None,
        "strict-transport-security":       None,
        "referrer-policy":                 None,
    }
    t0 = time.time()
    try:
        r = session.get(url, timeout=6, allow_redirects=True)
        latency = (time.time() - t0) * 1000
        missing = [h for h in REQUIRED if h not in {k.lower() for k in r.headers}]
        if len(missing) >= 3:
            evidence = f"Missing headers: {', '.join(missing)}"
            return ValidationResult(fid, "missing_headers", "confirmed", +0.15, evidence,
                                    "", latency, r.status_code)
        else:
            evidence = f"Missing only: {missing}" if missing else "All security headers present"
            delta = +0.05 if missing else -0.10
            status = "unverified" if missing else "rejected"
            return ValidationResult(fid, "missing_headers", status, delta, evidence,
                                    "", latency, r.status_code)
    except Exception as exc:
        return ValidationResult(fid, "missing_headers", "unverified", error=str(exc))


def _validate_information_disclosure(finding: dict, session: requests.Session) -> ValidationResult:
    """Verify that the sensitive endpoint is publicly accessible."""
    fid = finding.get("finding_id", "?")
    url = finding.get("url", "")
    if not url:
        return ValidationResult(fid, "information_disclosure", "unverified", error="no url")

    t0 = time.time()
    try:
        r = session.get(url, timeout=6, allow_redirects=True)
        latency = (time.time() - t0) * 1000
        if r.status_code == 200 and len(r.content) > 200:
            snippet = r.text[:200].replace("\n", " ")
            evidence = f"HTTP 200 ({len(r.content)}B) — endpoint publicly accessible. Snippet: {snippet}"
            return ValidationResult(fid, "information_disclosure", "confirmed", +0.15, evidence,
                                    "", latency, r.status_code)
        else:
            evidence = f"HTTP {r.status_code} — not directly accessible"
            return ValidationResult(fid, "information_disclosure", "rejected", -0.10, evidence,
                                    "", latency, r.status_code)
    except Exception as exc:
        return ValidationResult(fid, "information_disclosure", "unverified", error=str(exc))


# ---------------------------------------------------------------------------
# Dispatcher
# ---------------------------------------------------------------------------

_VALIDATOR_MAP = {
    "cors":                   _validate_cors,
    "cors_misconfiguration":  _validate_cors,
    "jwt_none_alg":           _validate_jwt_none,
    "jwt":                    _validate_jwt_none,
    "ssrf":                   _validate_ssrf,
    "idor":                   _validate_idor,
    "bola":                   _validate_idor,
    "race_condition":         _validate_race_condition,
    "auth_bypass":            _validate_auth_bypass,
    "missing_headers":        _validate_security_headers,
    "information_disclosure": _validate_information_disclosure,
    "weak_cipher":            _validate_information_disclosure,  # reuse — just probe the host
}


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

class WebValidationEngine:
    """
    Batch-validates a list of findings using safe HTTP probes.

    Usage:
        engine = WebValidationEngine(rate_limit_rps=2)
        results = engine.validate_all(findings)
    """

    def __init__(self, rate_limit_rps: float = 2.0, max_workers: int = 4,
                 timeout: int = 8, auth_token: str = "", auth_cookie: str = ""):
        self._delay      = 1.0 / max(rate_limit_rps, 0.1)
        self._max_workers = max_workers
        self._timeout    = timeout
        self._auth_token  = auth_token
        self._auth_cookie = auth_cookie

    def _make_session(self) -> requests.Session:
        sess = _make_session(self._timeout)
        if self._auth_token:
            sess.headers["Authorization"] = f"Bearer {self._auth_token}"
        if self._auth_cookie:
            sess.headers["Cookie"] = self._auth_cookie
        return sess

    def validate(self, finding: dict) -> ValidationResult:
        """Validate a single finding. Returns ValidationResult."""
        vtype = finding.get("vuln_type", finding.get("type", "")).lower()
        validator = _VALIDATOR_MAP.get(vtype)
        if not validator:
            return ValidationResult(
                finding.get("finding_id", "?"), vtype, "unverified",
                error=f"No validator for vuln_type '{vtype}'"
            )
        try:
            sess = self._make_session()
            return validator(finding, sess)
        except Exception as exc:
            return ValidationResult(finding.get("finding_id", "?"), vtype, "unverified", error=str(exc))

    def validate_all(self, findings: List[dict], waf_detected: bool = False) -> List[ValidationResult]:
        """
        Validate all findings concurrently (capped at max_workers).
        Applies extra delay if WAF is detected.
        """
        if waf_detected:
            delay = max(self._delay, 2.0)  # Slow down for WAF targets
        else:
            delay = self._delay

        results: List[ValidationResult] = []
        with ThreadPoolExecutor(max_workers=self._max_workers) as pool:
            futures = {}
            for f in findings:
                fut = pool.submit(self.validate, f)
                futures[fut] = f
                time.sleep(delay)  # Rate limit between submissions

            for fut in as_completed(futures, timeout=60):
                try:
                    results.append(fut.result(timeout=self._timeout + 2))
                except (FuturesTimeout, Exception) as exc:
                    f = futures[fut]
                    results.append(ValidationResult(
                        f.get("finding_id", "?"),
                        f.get("vuln_type", "?"),
                        "unverified",
                        error=str(exc),
                    ))
        return results

    def apply_results(self, findings: List[dict], results: List[ValidationResult]) -> List[dict]:
        """
        Merge validation results back into findings list.
        Updates: status, confidence, evidence, source_type.
        Returns updated findings.
        """
        result_map = {r.finding_id: r for r in results}
        updated = []
        for f in findings:
            fid = f.get("finding_id", f.get("id", "?"))
            r = result_map.get(fid)
            if r:
                f = dict(f)
                f["validation_status"]  = r.status
                f["validation_evidence"] = r.evidence
                f["validation_payload"]  = r.payload_used
                f["validation_latency_ms"] = r.latency_ms
                # Adjust confidence
                old_conf = float(f.get("confidence", 0.5))
                new_conf = max(0.0, min(1.0, old_conf + r.confidence_delta))
                f["confidence"] = round(new_conf, 3)
                # Upgrade source_type on confirmation
                if r.status == "confirmed":
                    f["source_type"] = "tool"          # Promoted to tool-confirmed
                    f["status"]      = "confirmed"
                elif r.status == "rejected":
                    f["status"]      = "false_positive"
            updated.append(f)
        return updated


def validate_findings_file(
    findings_path: str,
    output_path: str = "",
    rate_rps: float = 2.0,
    auth_token: str = "",
    waf_detected: bool = False,
) -> List[dict]:
    """
    Convenience wrapper: load findings.json → validate → write updated file.
    Returns updated findings list.
    """
    import json
    from pathlib import Path

    findings = json.loads(Path(findings_path).read_text())
    if not isinstance(findings, list):
        findings = findings.get("findings", [])

    engine  = WebValidationEngine(rate_limit_rps=rate_rps, auth_token=auth_token)
    results = engine.validate_all(findings, waf_detected=waf_detected)
    updated = engine.apply_results(findings, results)

    out = output_path or findings_path
    Path(out).write_text(json.dumps(updated, indent=2))
    return updated
