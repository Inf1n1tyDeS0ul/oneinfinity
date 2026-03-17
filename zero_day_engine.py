"""
Zero-Day Discovery Engine
===========================
Detects unusual, anomalous, and previously unknown vulnerability patterns
by comparing responses, analyzing deviations, and identifying behaviors
that deviate from the application's baseline.
"""

from __future__ import annotations

import json
import math
import re
import time
import urllib.request
import urllib.error
import urllib.parse
from collections import defaultdict
from dataclasses import dataclass, field
from pathlib import Path

from path_manager import resolve_output_dir
from typing import Any, Optional


# ── Data models ───────────────────────────────────────────────────────────────

@dataclass
class ResponseProfile:
    """Snapshot of a single HTTP response for comparison."""
    url: str
    method: str = "GET"
    status_code: int = 0
    content_length: int = 0
    content_type: str = ""
    response_time_ms: float = 0.0
    headers: dict[str, str] = field(default_factory=dict)
    body_snippet: str = ""          # first 2KB
    body_hash: str = ""             # SHA-256 truncated
    redirect_location: str = ""
    server: str = ""
    error_present: bool = False
    json_keys: list[str] = field(default_factory=list)  # top-level JSON keys
    parameter: str = ""             # which param was varied (if any)
    payload: str = ""               # payload used (if any)

    def to_dict(self) -> dict:
        return {
            "url": self.url,
            "status_code": self.status_code,
            "content_length": self.content_length,
            "content_type": self.content_type,
            "response_time_ms": round(self.response_time_ms, 1),
            "redirect_location": self.redirect_location,
            "error_present": self.error_present,
            "json_keys": self.json_keys,
            "parameter": self.parameter,
            "payload": self.payload,
        }


@dataclass
class Anomaly:
    """A detected anomalous behavior."""
    anomaly_id: str
    anomaly_type: str           # StatusCodeChange | SizeDeviation | TimingAnomaly |
                                # ErrorDisclosure | UnexpectedRedirect | DataLeakage |
                                # AuthInconsistency | NewFields | ReflectionDetected |
                                # AccessControlFlip
    endpoint: str
    parameter: str
    baseline_value: str         # what was expected
    observed_value: str         # what was actually seen
    severity: str               # critical | high | medium | low
    confidence: float           # 0.0–1.0
    evidence: str
    payload_used: str = ""
    recommended_follow_up: str = ""

    def to_dict(self) -> dict:
        return {
            "anomaly_id": self.anomaly_id,
            "anomaly_type": self.anomaly_type,
            "endpoint": self.endpoint,
            "parameter": self.parameter,
            "severity": self.severity,
            "confidence": round(self.confidence, 2),
            "evidence": self.evidence,
            "baseline_value": self.baseline_value,
            "observed_value": self.observed_value,
            "payload_used": self.payload_used,
            "recommended_follow_up": self.recommended_follow_up,
        }


# ── Detection patterns ────────────────────────────────────────────────────────

_ERROR_DISCLOSURE_PATTERNS: list[tuple[re.Pattern, str, str]] = [
    (re.compile(r"Traceback \(most recent call last\)", re.I),
     "Python traceback", "critical"),
    (re.compile(r"at .+\.java:\d+|java\.lang\.", re.I),
     "Java stack trace", "high"),
    (re.compile(r"System\.Web\.HttpUnhandledException|at System\.", re.I),
     ".NET/C# stack trace", "high"),
    (re.compile(r"PHP (Fatal|Warning|Notice|Parse) error", re.I),
     "PHP error", "high"),
    (re.compile(r"You have an error in your SQL syntax|mysql_fetch|pg_query", re.I),
     "SQL error", "critical"),
    (re.compile(r"ORA-\d{4}|oci_execute", re.I),
     "Oracle SQL error", "critical"),
    (re.compile(r"Microsoft OLE DB|ODBC SQL Server", re.I),
     "MSSQL error", "critical"),
    (re.compile(r"SQLSTATE\[|PDOException", re.I),
     "PDO SQL error", "high"),
    (re.compile(r"Whoops!|Symfony\s+Exception|Illuminate\\", re.I),
     "Framework debug page", "high"),
    (re.compile(r"django.core.exceptions|DoesNotExist|SuspiciousOperation", re.I),
     "Django exception", "high"),
    (re.compile(r"An unhandled exception occurred|500 Internal Server Error", re.I),
     "Unhandled server error", "medium"),
]

_DATA_LEAKAGE_PATTERNS: list[tuple[re.Pattern, str, str]] = [
    (re.compile(r"password[\"']?\s*[:=]\s*[\"'][^\"']{4,}", re.I),
     "Password in response", "critical"),
    (re.compile(r"(secret|api_?key|private_?key|token)\s*[=:]\s*[\"']?[a-z0-9/+]{16,}", re.I),
     "Secret/API key in response", "critical"),
    (re.compile(r"-----BEGIN (RSA |EC )?PRIVATE KEY-----"),
     "Private key in response", "critical"),
    (re.compile(r"AKIA[0-9A-Z]{16}", re.I),
     "AWS Access Key in response", "critical"),
    (re.compile(r"ghp_[a-zA-Z0-9]{36}|ghs_[a-zA-Z0-9]{36}"),
     "GitHub token in response", "critical"),
    (re.compile(r"\b\d{4}[- ]?\d{4}[- ]?\d{4}[- ]?\d{4}\b"),
     "Credit card number pattern", "critical"),
    (re.compile(r"\b\d{3}-\d{2}-\d{4}\b"),
     "SSN pattern", "critical"),
    (re.compile(r"\"admin\"\s*:\s*true|\"is_admin\"\s*:\s*true", re.I),
     "Admin flag exposed", "high"),
    (re.compile(r"internal.*\b(192\.168|10\.\d+|172\.(1[6-9]|2\d|3[01]))\b", re.I),
     "Internal IP in response", "medium"),
    (re.compile(r"/var/www|/home/\w+|/opt/|/usr/local/", re.I),
     "Server file path in response", "medium"),
]

_INTERESTING_HEADERS: set[str] = {
    "x-powered-by", "server", "x-aspnet-version", "x-aspnetmvc-version",
    "x-debug", "x-debug-token", "x-request-id", "x-correlation-id",
    "x-internal", "x-forwarded-server",
}

_TIMING_THRESHOLD_MS = 4000   # >4s response = possible blind injection
_SIZE_DEVIATION_PCT  = 0.25   # >25% size change = significant
_MIN_BODY_SIZE       = 100    # ignore tiny responses for size comparisons


# ── Zero-Day Engine ───────────────────────────────────────────────────────────

class ZeroDayEngine:
    """
    Detects anomalous application behaviors that may indicate novel vulnerabilities.

    Workflow:
    1. Collect baseline response profiles for each endpoint
    2. Probe with varied parameters and payloads
    3. Compare probe responses against baseline
    4. Flag anomalies (status changes, size deviations, timing, data leakage, etc.)
    """

    def __init__(
        self,
        target: str,
        output_dir: str = "",
        base_url: str = "",
        timeout: int = 12,
        rate_limit: float = 0.5,
    ):
        self.target = target
        self.output_dir = resolve_output_dir(output_dir, target)
        self.base_url = base_url or f"http://{target}"
        self.timeout = timeout
        self.rate_limit = rate_limit
        self._last_request = 0.0
        self._anomaly_counter = 0

    # ── Public API ────────────────────────────────────────────────────────────

    def detect_anomalies(
        self,
        endpoints: list[str] | None = None,
        test_results: list[dict] | None = None,
    ) -> list[Anomaly]:
        """
        Full anomaly detection pipeline.

        1. Load endpoints from disk if not provided
        2. Probe baseline for each endpoint
        3. Probe with mutations and compare
        4. Scan existing test_results for missed anomalies
        """
        endpoints = endpoints or self._load_endpoints()
        anomalies: list[Anomaly] = []

        # Phase 1: Probe each endpoint and detect passive anomalies
        for ep in endpoints[:30]:  # cap at 30 to stay within time budget
            baseline = self._fetch_profile(ep)
            if not baseline:
                continue
            anomalies.extend(self._detect_passive_anomalies(baseline))
            time.sleep(self.rate_limit)

        # Phase 2: Parameter mutation probes
        params_map = self._load_parameters()
        for path, params in list(params_map.items())[:15]:
            ep_url = self._build_url(path)
            baseline = self._fetch_profile(ep_url)
            if not baseline:
                continue
            for param in params[:3]:
                for mutation, payload in self._param_mutations(param):
                    probe_url = self._build_url(path, {param: mutation})
                    probe = self._fetch_profile(probe_url, parameter=param, payload=mutation)
                    if probe:
                        anomalies.extend(
                            self.analyze_responses(baseline, probe, payload)
                        )
                    time.sleep(self.rate_limit)

        # Phase 3: Scan existing test results for anomalies
        if test_results:
            anomalies.extend(self._scan_test_results(test_results))

        # Deduplicate
        seen: set[str] = set()
        unique: list[Anomaly] = []
        for a in anomalies:
            key = f"{a.anomaly_type}:{a.endpoint}:{a.parameter}"
            if key not in seen:
                seen.add(key)
                unique.append(a)

        # Sort by severity
        _sev = {"critical": 0, "high": 1, "medium": 2, "low": 3}
        unique.sort(key=lambda a: (_sev.get(a.severity, 4), -a.confidence))

        # Save
        out = self.output_dir / "anomalies.json"
        out.parent.mkdir(parents=True, exist_ok=True)
        out.write_text(json.dumps([a.to_dict() for a in unique], indent=2))

        return unique

    def analyze_responses(
        self,
        baseline: ResponseProfile,
        probe: ResponseProfile,
        context: str = "",
    ) -> list[Anomaly]:
        """
        Compare a baseline response against a probe response and return anomalies.
        This is the core comparison engine.
        """
        anomalies: list[Anomaly] = []

        # 1. Status code change
        if baseline.status_code != probe.status_code:
            severity = self._status_change_severity(baseline.status_code, probe.status_code)
            if severity:
                anomalies.append(self._make_anomaly(
                    anomaly_type="StatusCodeChange",
                    endpoint=baseline.url,
                    parameter=probe.parameter,
                    baseline_value=str(baseline.status_code),
                    observed_value=str(probe.status_code),
                    severity=severity,
                    confidence=0.80,
                    evidence=(
                        f"Status changed from {baseline.status_code} → {probe.status_code} "
                        f"when {probe.parameter}='{probe.payload[:40]}'"
                    ),
                    payload_used=probe.payload,
                    recommended_follow_up=(
                        "Investigate access control bypass" if probe.status_code == 200
                        else "Check for auth inconsistency"
                    ),
                ))

        # 2. Response size deviation
        if (baseline.content_length > _MIN_BODY_SIZE and
                probe.content_length > 0):
            delta_pct = abs(probe.content_length - baseline.content_length) / max(baseline.content_length, 1)
            if delta_pct > _SIZE_DEVIATION_PCT:
                sev = "high" if delta_pct > 0.75 else "medium"
                anomalies.append(self._make_anomaly(
                    anomaly_type="SizeDeviation",
                    endpoint=baseline.url,
                    parameter=probe.parameter,
                    baseline_value=f"{baseline.content_length} bytes",
                    observed_value=f"{probe.content_length} bytes ({delta_pct:.0%} change)",
                    severity=sev,
                    confidence=0.65 + min(delta_pct, 0.30),
                    evidence=(
                        f"Response size changed by {delta_pct:.0%} "
                        f"({baseline.content_length} → {probe.content_length} bytes) "
                        f"when {probe.parameter}='{probe.payload[:40]}'"
                    ),
                    payload_used=probe.payload,
                    recommended_follow_up="Larger response may indicate data injection or IDOR",
                ))

        # 3. Timing anomaly (potential blind injection)
        if probe.response_time_ms > _TIMING_THRESHOLD_MS:
            anomalies.append(self._make_anomaly(
                anomaly_type="TimingAnomaly",
                endpoint=baseline.url,
                parameter=probe.parameter,
                baseline_value=f"{baseline.response_time_ms:.0f}ms",
                observed_value=f"{probe.response_time_ms:.0f}ms",
                severity="high",
                confidence=0.75 if probe.response_time_ms > 6000 else 0.60,
                evidence=(
                    f"Response took {probe.response_time_ms:.0f}ms (baseline: {baseline.response_time_ms:.0f}ms) "
                    f"with {probe.parameter}='{probe.payload[:40]}' — possible blind SQLi or SSRF"
                ),
                payload_used=probe.payload,
                recommended_follow_up="Test time-based blind SQLi: AND SLEEP(5)--",
            ))

        # 4. New JSON fields in probe response
        new_fields = set(probe.json_keys) - set(baseline.json_keys)
        if new_fields:
            high_value = {"password", "secret", "token", "key", "hash",
                          "private", "internal", "admin", "ssn", "credit"}
            sev = "critical" if new_fields & high_value else "medium"
            anomalies.append(self._make_anomaly(
                anomaly_type="NewFields",
                endpoint=baseline.url,
                parameter=probe.parameter,
                baseline_value=str(sorted(baseline.json_keys)[:5]),
                observed_value=str(sorted(probe.json_keys)[:5]),
                severity=sev,
                confidence=0.70,
                evidence=f"New JSON fields appeared: {sorted(new_fields)} when probe param modified",
                payload_used=probe.payload,
                recommended_follow_up="New fields may indicate excessive data exposure or IDOR",
            ))

        # 5. Reflection detection
        if probe.payload and len(probe.payload) >= 4:
            if probe.payload in probe.body_snippet and probe.payload not in baseline.body_snippet:
                sev = "high" if any(c in probe.payload for c in "<>\"'") else "medium"
                anomalies.append(self._make_anomaly(
                    anomaly_type="ReflectionDetected",
                    endpoint=baseline.url,
                    parameter=probe.parameter,
                    baseline_value="(no reflection)",
                    observed_value=f"'{probe.payload[:60]}' reflected",
                    severity=sev,
                    confidence=0.75,
                    evidence=f"Input '{probe.payload[:40]}' reflected in response body (XSS candidate)",
                    payload_used=probe.payload,
                    recommended_follow_up="Run dalfox for XSS confirmation: dalfox url <URL>",
                ))

        # 6. Redirect change
        if probe.redirect_location and probe.redirect_location != baseline.redirect_location:
            suspicious = any(
                d in probe.redirect_location.lower()
                for d in ["evil", "attacker", "169.254", "localhost", "127.0.0.1"]
            )
            anomalies.append(self._make_anomaly(
                anomaly_type="UnexpectedRedirect",
                endpoint=baseline.url,
                parameter=probe.parameter,
                baseline_value=baseline.redirect_location or "(none)",
                observed_value=probe.redirect_location,
                severity="high" if suspicious else "medium",
                confidence=0.85 if suspicious else 0.55,
                evidence=f"Redirect destination changed to: {probe.redirect_location}",
                payload_used=probe.payload,
                recommended_follow_up="Investigate open redirect or SSRF via redirect",
            ))

        # 7. Error in probe but not baseline
        if probe.error_present and not baseline.error_present:
            anomalies.append(self._make_anomaly(
                anomaly_type="ErrorDisclosure",
                endpoint=probe.url,
                parameter=probe.parameter,
                baseline_value="(no error)",
                observed_value="Server error triggered",
                severity="medium",
                confidence=0.65,
                evidence=f"Server error triggered by {probe.parameter}='{probe.payload[:40]}'",
                payload_used=probe.payload,
                recommended_follow_up="Server errors on input may indicate injection point",
            ))

        return anomalies

    # ── Passive response scanner ───────────────────────────────────────────────

    def _detect_passive_anomalies(self, profile: ResponseProfile) -> list[Anomaly]:
        """Scan a single response profile for anomalies without comparison."""
        anomalies: list[Anomaly] = []
        body = profile.body_snippet

        # Error disclosure
        for pattern, description, severity in _ERROR_DISCLOSURE_PATTERNS:
            if pattern.search(body):
                anomalies.append(self._make_anomaly(
                    anomaly_type="ErrorDisclosure",
                    endpoint=profile.url,
                    parameter="",
                    baseline_value="(no error expected)",
                    observed_value=description,
                    severity=severity,
                    confidence=0.88,
                    evidence=f"{description} found in response to GET {profile.url}",
                    recommended_follow_up="Disable debug mode; review error handling",
                ))

        # Data leakage
        for pattern, description, severity in _DATA_LEAKAGE_PATTERNS:
            m = pattern.search(body)
            if m:
                snippet = m.group(0)[:60]
                anomalies.append(self._make_anomaly(
                    anomaly_type="DataLeakage",
                    endpoint=profile.url,
                    parameter="",
                    baseline_value="(no sensitive data expected)",
                    observed_value=description,
                    severity=severity,
                    confidence=0.90,
                    evidence=f"{description} in response: '{snippet}...'",
                    recommended_follow_up="Remove sensitive data from response; implement proper masking",
                ))

        # Auth inconsistency: 200 on obvious sensitive path
        sensitive_paths = ["/admin", "/dashboard", "/.env", "/config", "/debug",
                           "/actuator", "/internal", "/private"]
        for sp in sensitive_paths:
            if sp in profile.url and profile.status_code == 200:
                anomalies.append(self._make_anomaly(
                    anomaly_type="AuthInconsistency",
                    endpoint=profile.url,
                    parameter="",
                    baseline_value="401/403",
                    observed_value=str(profile.status_code),
                    severity="critical",
                    confidence=0.85,
                    evidence=f"Sensitive path '{sp}' returned HTTP 200 without authentication",
                    recommended_follow_up="Verify authorization check on this endpoint",
                ))
                break

        # Interesting headers that disclose technology
        for hdr in (profile.headers or {}):
            if hdr.lower() in _INTERESTING_HEADERS:
                val = profile.headers[hdr]
                if any(v in val for v in ["PHP", "ASP.NET", "nginx", "Apache", "Jetty", "Tomcat"]):
                    anomalies.append(self._make_anomaly(
                        anomaly_type="DataLeakage",
                        endpoint=profile.url,
                        parameter="",
                        baseline_value="(server version hidden)",
                        observed_value=f"{hdr}: {val}",
                        severity="low",
                        confidence=0.95,
                        evidence=f"Server version disclosed: {hdr}: {val}",
                        recommended_follow_up="Hide server version headers in web server config",
                    ))

        return anomalies

    def _scan_test_results(self, test_results: list[dict]) -> list[Anomaly]:
        """Re-analyse existing test results for missed anomalies."""
        anomalies: list[Anomaly] = []
        for r in test_results:
            if not r.get("success"):
                continue
            body = r.get("response_snippet", "")
            status = r.get("status_code", 0)

            # Check for error disclosure
            for pattern, description, severity in _ERROR_DISCLOSURE_PATTERNS:
                if pattern.search(body):
                    anomalies.append(self._make_anomaly(
                        anomaly_type="ErrorDisclosure",
                        endpoint=r.get("endpoint", ""),
                        parameter=r.get("payload_used", ""),
                        baseline_value="(clean response)",
                        observed_value=description,
                        severity=severity,
                        confidence=0.85,
                        evidence=f"{description} found in test result for {r.get('vuln_type', '?')}",
                    ))

            # Check for data leakage
            for pattern, description, severity in _DATA_LEAKAGE_PATTERNS:
                if pattern.search(body):
                    anomalies.append(self._make_anomaly(
                        anomaly_type="DataLeakage",
                        endpoint=r.get("endpoint", ""),
                        parameter="",
                        baseline_value="",
                        observed_value=description,
                        severity=severity,
                        confidence=0.88,
                        evidence=f"{description} in test response",
                    ))

            # Access control flip: test expected 403, got 200
            if (status == 200 and r.get("vuln_type") in
                    ("Authentication Bypass", "Privilege Escalation", "IDOR")):
                anomalies.append(self._make_anomaly(
                    anomaly_type="AccessControlFlip",
                    endpoint=r.get("endpoint", ""),
                    parameter=r.get("payload_used", ""),
                    baseline_value="403 expected",
                    observed_value="200 received",
                    severity="critical",
                    confidence=0.80,
                    evidence=(
                        f"HTTP 200 received when testing {r.get('vuln_type')} — "
                        f"access control may be missing"
                    ),
                    payload_used=r.get("payload_used", ""),
                    recommended_follow_up="Manually verify: can this endpoint be accessed without proper auth?",
                ))

        return anomalies

    # ── HTTP probing ──────────────────────────────────────────────────────────

    def _fetch_profile(
        self,
        url: str,
        method: str = "GET",
        parameter: str = "",
        payload: str = "",
    ) -> Optional[ResponseProfile]:
        """Fetch a URL and return a ResponseProfile."""
        self._sleep_rate()
        t0 = time.time()
        try:
            req = urllib.request.Request(url, method=method)
            req.add_header("User-Agent", "Mozilla/5.0 (BountyResearch/1.0)")
            with urllib.request.urlopen(req, timeout=self.timeout) as resp:
                raw = resp.read(8192).decode("utf-8", errors="replace")
                status = resp.getcode()
                headers = dict(resp.headers)
                content_type = resp.headers.get_content_type() or ""
                location = resp.headers.get("Location", "")
        except urllib.error.HTTPError as e:
            status = e.code
            raw = ""
            try:
                raw = e.read(2048).decode("utf-8", errors="replace")
            except Exception:
                pass
            headers = {}
            content_type = ""
            location = e.headers.get("Location", "") if e.headers else ""
        except Exception:
            return None

        elapsed = (time.time() - t0) * 1000

        # Parse JSON keys
        json_keys: list[str] = []
        try:
            parsed = json.loads(raw)
            if isinstance(parsed, dict):
                json_keys = list(parsed.keys())
            elif isinstance(parsed, list) and parsed and isinstance(parsed[0], dict):
                json_keys = list(parsed[0].keys())
        except Exception:
            pass

        # Body hash
        import hashlib
        body_hash = hashlib.sha256(raw.encode()).hexdigest()[:12]

        error_present = any(
            pat.search(raw) for pat, _, _ in _ERROR_DISCLOSURE_PATTERNS
        )

        return ResponseProfile(
            url=url,
            method=method,
            status_code=status,
            content_length=len(raw),
            content_type=content_type,
            response_time_ms=elapsed,
            headers={k.lower(): v for k, v in headers.items()},
            body_snippet=raw[:2048],
            body_hash=body_hash,
            redirect_location=location,
            server=headers.get("server", headers.get("Server", "")),
            error_present=error_present,
            json_keys=json_keys,
            parameter=parameter,
            payload=payload,
        )

    # ── Parameter mutations ───────────────────────────────────────────────────

    def _param_mutations(self, param: str) -> list[tuple[str, str]]:
        """
        Generate (mutated_value, payload_label) pairs for a parameter.
        Keeps mutations safe (passive / non-destructive by default).
        """
        mutations = []
        # Type confusion
        mutations += [("0", "zero"), ("-1", "negative_one"), ("1", "one"),
                      ("999999", "large_int"), ("null", "null_str"),
                      ("undefined", "undefined_str"), ("true", "bool_true")]
        # SQL-like probes (non-destructive error check)
        mutations += [("'", "single_quote"), ("\"", "double_quote"),
                      ("1 OR 1=1", "or_condition")]
        # XSS probe
        mutations += [("<XSSTEST>", "xss_probe")]
        # Path traversal
        mutations += [("../", "path_traversal"), ("%2e%2e%2f", "path_traversal_enc")]
        # Empty / whitespace
        mutations += [("", "empty"), (" ", "space"), ("%20", "encoded_space")]
        # Long string (buffer overflow / truncation behavior)
        mutations += [("A" * 512, "long_string")]
        return mutations

    # ── Helpers ───────────────────────────────────────────────────────────────

    def _load_endpoints(self) -> list[str]:
        urls: list[str] = []
        for fname in ["urls.json", "endpoints.json"]:
            f = self.output_dir / fname
            if f.exists():
                try:
                    data = json.loads(f.read_text())
                    if isinstance(data, list):
                        urls = data
                        break
                    urls = data.get("urls", data.get("endpoints", []))
                    break
                except Exception:
                    pass
        alive_f = self.output_dir / "alive_hosts.json"
        if alive_f.exists():
            try:
                data = json.loads(alive_f.read_text())
                hosts = data.get("hosts", data) if isinstance(data, dict) else data
                for h in hosts:
                    u = h.get("url", "") if isinstance(h, dict) else h
                    if u and u not in urls:
                        urls.insert(0, u)
            except Exception:
                pass
        return urls

    def _load_parameters(self) -> dict[str, list[str]]:
        model_f = self.output_dir / "app_model.json"
        if model_f.exists():
            try:
                data = json.loads(model_f.read_text())
                return data.get("all_parameters", {})
            except Exception:
                pass
        return {}

    def _build_url(self, path: str, params: dict | None = None) -> str:
        if path.startswith("http"):
            url = path
        else:
            url = self.base_url.rstrip("/") + "/" + path.lstrip("/")
        if params:
            qs = urllib.parse.urlencode(params)
            url = f"{url}?{qs}" if "?" not in url else f"{url}&{qs}"
        return url

    def _sleep_rate(self):
        now = time.time()
        wait = self.rate_limit - (now - self._last_request)
        if wait > 0:
            time.sleep(wait)
        self._last_request = time.time()

    def _status_change_severity(self, baseline: int, probe: int) -> Optional[str]:
        """Map a status code transition to a severity label."""
        if baseline in (401, 403) and probe == 200:
            return "critical"   # Access control bypass
        if baseline == 200 and probe in (401, 403):
            return "low"        # Normal auth check
        if baseline == 200 and probe == 500:
            return "medium"     # Server error triggered
        if probe in (301, 302, 307, 308) and baseline not in (301, 302, 307, 308):
            return "medium"     # Unexpected redirect
        return None

    def _make_anomaly(self, **kwargs) -> Anomaly:
        self._anomaly_counter += 1
        return Anomaly(
            anomaly_id=f"anomaly_{self._anomaly_counter:04d}",
            **kwargs,
        )


# ── Report formatter ──────────────────────────────────────────────────────────

def print_anomaly_report(anomalies: list[Anomaly]):
    """Pretty-print anomaly results to stdout."""
    _sev_color = {
        "critical": "\033[0;31m", "high": "\033[0;33m",
        "medium": "\033[0;36m",   "low":  "\033[0;37m",
    }
    _reset = "\033[0m"

    if not anomalies:
        print("  No anomalies detected.")
        return

    for sev in ["critical", "high", "medium", "low"]:
        group = [a for a in anomalies if a.severity == sev]
        if not group:
            continue
        col = _sev_color.get(sev, "")
        print(f"\n  {col}── {sev.upper()} ({len(group)}) ──────────────────────────{_reset}")
        for a in group:
            print(f"  {col}[{sev.upper()}]{_reset} {a.anomaly_type} — {a.endpoint}")
            print(f"    {a.evidence}")
            if a.recommended_follow_up:
                print(f"    → {a.recommended_follow_up}")
            print()


# ── CLI entry point ───────────────────────────────────────────────────────────

def main_cli(args):
    from modules.utils import banner, section, ok, info, warn
    target = args.domain
    output = resolve_output_dir(getattr(args, "output", None), target)
    banner(f"Zero-Day Discovery Engine — {target}")
    warn("Performing anomaly-based probing. Ensure you have written authorization.")
    print()

    # Load existing test results if available
    test_results: list[dict] = []
    tr_file = Path(output) / "test_results.json"
    if tr_file.exists():
        try:
            test_results = json.loads(tr_file.read_text())
            info(f"Loaded {len(test_results)} existing test results")
        except Exception:
            pass

    # Determine base URL
    base_url = f"https://{target}"
    alive_file = Path(output) / "alive_hosts.json"
    if alive_file.exists():
        try:
            data = json.loads(alive_file.read_text())
            hosts = data.get("hosts", data) if isinstance(data, dict) else data
            if hosts:
                base_url = (hosts[0].get("url", base_url)
                            if isinstance(hosts[0], dict) else base_url)
        except Exception:
            pass

    engine = ZeroDayEngine(
        target=target, output_dir=output, base_url=base_url,
        timeout=getattr(args, "timeout", 12),
        rate_limit=getattr(args, "rate", 0.5),
    )

    info("Running anomaly detection pipeline...")
    anomalies = engine.detect_anomalies(test_results=test_results)

    section(f"Anomalies Detected: {len(anomalies)}")
    print_anomaly_report(anomalies)

    ok(f"Anomalies saved: {output}/anomalies.json")
    print()
    return anomalies
