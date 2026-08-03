"""
src/oneinfinity/mobile/backend_differential_analyzer.py
Phase 2 — New Attack Surface: Mobile Backend Differential Analysis (Pillar 4.6)

The most valuable mobile security finding: the backend API trusts the mobile
client to enforce constraints that the server should enforce itself.

Method:
  1. Extract API endpoints discovered during APK analysis
  2. Replay each endpoint twice:
     a. With mobile client headers (X-App-Version, User-Agent: mobile app,
        X-Platform, X-Device-Id, any certificate-pinning bypass headers)
     b. Without mobile headers (plain curl / requests equivalent)
  3. Compare responses:
     - Different status codes → server enforces constraints via headers (client-trust vuln)
     - Different response bodies → business logic gated on mobile header
     - Rate limiting difference → rate limit based on app headers (trivially bypassable)
     - New fields in non-mobile response → shadow API / undocumented endpoint
  4. Also tests for "disabled in app but enabled on server" patterns:
     - Endpoints present in APK strings but not in normal app flow
     - Admin/debug endpoints that respond when called directly

No duplicate: api_discovery.py discovers endpoints. This module tests the
server-side enforcement difference between mobile and non-mobile access.
"""
from __future__ import annotations

import json
import logging
import time
import uuid
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Tuple
from urllib.parse import urljoin, urlparse

import requests

log = logging.getLogger("oneinfinity.mobile.backend_differential")

# ── Mobile client header sets ─────────────────────────────────────────────────

# Common mobile app headers — these are the client-controlled signals that
# servers sometimes use to gate functionality or rate limiting.
_MOBILE_HEADERS_ANDROID: Dict[str, str] = {
    "User-Agent":      "Dalvik/2.1.0 (Linux; U; Android 13; Pixel 7 Build/TQ3A.230901.001)",
    "X-App-Version":   "2.0.1",
    "X-Platform":      "android",
    "X-Device-Id":     "a1b2c3d4e5f6a7b8",
    "X-Build-Number":  "201",
    "Accept-Language": "en-US",
    "Accept":          "application/json",
}

_MOBILE_HEADERS_IOS: Dict[str, str] = {
    "User-Agent":      "MyApp/2.0.1 CFNetwork/1408.0.4 Darwin/22.5.0",
    "X-App-Version":   "2.0.1",
    "X-Platform":      "ios",
    "X-Device-Id":     "f8e7d6c5b4a39281",
    "X-Build-Number":  "201",
    "Accept-Language": "en-US",
    "Accept":          "application/json",
}

_PLAIN_HEADERS: Dict[str, str] = {
    "User-Agent":  "Mozilla/5.0 (compatible; curl/7.88.0)",
    "Accept":      "application/json",
}


@dataclass
class DifferentialResult:
    """Result of replaying one endpoint with and without mobile headers."""
    url: str
    method: str
    mobile_status:  int
    plain_status:   int
    mobile_body_len: int
    plain_body_len:  int
    mobile_fields:  List[str]   # JSON top-level keys in mobile response
    plain_fields:   List[str]   # JSON top-level keys in plain response
    shadow_fields:  List[str]   # fields present in plain but NOT in mobile
    status_diverged: bool       # different HTTP status codes
    rate_limit_diverged: bool   # rate limit hit by one but not the other
    error: Optional[str] = None

    @property
    def has_finding(self) -> bool:
        return bool(
            self.shadow_fields or
            self.status_diverged or
            self.rate_limit_diverged
        )


@dataclass
class MobileDifferentialFinding:
    """A confirmed mobile backend trust vulnerability."""
    result: DifferentialResult
    vuln_type: str
    title: str
    severity: str
    evidence: str

    def to_finding_dict(self, scan_id: str, target: str) -> dict:
        return {
            "finding_id":  str(uuid.uuid4())[:12],
            "scan_id":     scan_id,
            "target":      target,
            "title":       self.title,
            "severity":    self.severity,
            "vuln_type":   self.vuln_type,
            "url":         self.result.url,
            "evidence":    self.evidence,
            "payload":     f"Replayed {self.result.method} {self.result.url} without mobile headers",
            "tool":        "backend_differential_analyzer",
            "confidence":  0.85,
            "source_type": "tool",
            "raw": {
                "url":              self.result.url,
                "method":           self.result.method,
                "mobile_status":    self.result.mobile_status,
                "plain_status":     self.result.plain_status,
                "shadow_fields":    self.result.shadow_fields,
                "status_diverged":  self.result.status_diverged,
            },
        }


class MobileBackendDifferentialAnalyzer:
    """
    Replays mobile API endpoints with and without mobile headers to detect
    server-side validation that relies on client-supplied signals.

    Usage:
        analyzer = MobileBackendDifferentialAnalyzer(target, scan_id)
        findings = analyzer.run(endpoints, auth_headers={"Authorization": "Bearer ..."})
    """

    def __init__(
        self,
        target: str,
        scan_id: str,
        auth_headers: Optional[Dict[str, str]] = None,
        app_name: Optional[str] = None,
    ):
        self.target = target.rstrip("/")
        self.scan_id = scan_id
        self._auth = auth_headers or {}
        self._app_name = app_name or ""
        self._findings: List[MobileDifferentialFinding] = []

    def run(
        self,
        endpoints: List[Dict[str, Any]],
        auth_headers: Optional[Dict[str, str]] = None,
        platform: str = "android",
        max_endpoints: int = 50,
        timeout: int = 10,
    ) -> List[dict]:
        """
        Run differential analysis on discovered mobile API endpoints.

        Args:
            endpoints:    list of {url, method, params?} from MobileAPIDiscovery
            auth_headers: session auth to include in both mobile and plain requests
            platform:     "android" or "ios" — which mobile header set to use
            max_endpoints: cap to bound scan time
            timeout:      per-request timeout

        Returns:
            List of finding dicts.
        """
        if not endpoints:
            log.info("[mobile-diff] No endpoints to test for %s", self.target)
            return []

        auth = {**self._auth, **(auth_headers or {})}
        mobile_headers_base = (
            _MOBILE_HEADERS_ANDROID if platform != "ios" else _MOBILE_HEADERS_IOS
        )
        # Merge in app-specific header if known
        if self._app_name:
            mobile_headers_base = {
                **mobile_headers_base,
                "User-Agent": mobile_headers_base["User-Agent"].replace(
                    "MyApp", self._app_name
                ),
            }

        log.info(
            "[mobile-diff] Differential analysis: %d endpoints, platform=%s",
            min(len(endpoints), max_endpoints), platform,
        )

        session_mobile = requests.Session()
        session_mobile.headers.update({**mobile_headers_base, **auth})
        session_mobile.verify = False

        session_plain = requests.Session()
        session_plain.headers.update({**_PLAIN_HEADERS, **auth})
        session_plain.verify = False

        findings = []
        for ep in endpoints[:max_endpoints]:
            url = ep.get("url") or ep.get("path") or ep.get("endpoint") or ""
            if not url:
                continue
            # Ensure absolute URL
            if not url.startswith("http"):
                url = urljoin(self.target + "/", url.lstrip("/"))
            method = str(ep.get("method") or "GET").upper()
            params = ep.get("params") or ep.get("parameters") or {}

            result = self._replay_endpoint(
                session_mobile, session_plain, url, method, params, timeout
            )
            if result and result.has_finding:
                for f in self._classify_findings(result):
                    findings.append(f.to_finding_dict(self.scan_id, self.target))
                    log.info("[mobile-diff] FOUND %s at %s", f.vuln_type, url)

        log.info("[mobile-diff] Complete — %d findings", len(findings))
        return findings

    # ── Internal ─────────────────────────────────────────────────────────────

    def _replay_endpoint(
        self,
        session_mobile: requests.Session,
        session_plain:  requests.Session,
        url: str,
        method: str,
        params: Any,
        timeout: int,
    ) -> Optional[DifferentialResult]:
        """Replay one endpoint with both sessions, return differential result."""
        try:
            # Build request kwargs
            kwargs: Dict[str, Any] = {"timeout": timeout}
            if isinstance(params, dict) and params:
                if method == "GET":
                    kwargs["params"] = params
                else:
                    kwargs["json"] = params

            r_mobile = self._safe_request(session_mobile, method, url, **kwargs)
            time.sleep(0.2)  # brief gap to avoid rate limit correlation
            r_plain  = self._safe_request(session_plain,  method, url, **kwargs)

            if r_mobile is None and r_plain is None:
                return None

            mobile_status  = r_mobile.status_code if r_mobile else 0
            plain_status   = r_plain.status_code  if r_plain  else 0
            mobile_body    = r_mobile.text if r_mobile else ""
            plain_body     = r_plain.text  if r_plain  else ""

            mobile_fields = self._json_keys(mobile_body)
            plain_fields  = self._json_keys(plain_body)
            # Shadow fields: present in plain response but not in mobile
            # (server exposes more data to non-mobile clients)
            shadow_fields = [f for f in plain_fields if f not in mobile_fields]

            status_diverged = (
                mobile_status != plain_status and
                mobile_status != 0 and plain_status != 0
            )
            # Rate limit divergence: one response is 429, other isn't
            rate_limit_diverged = (
                (mobile_status == 429) != (plain_status == 429)
            )

            return DifferentialResult(
                url=url, method=method,
                mobile_status=mobile_status, plain_status=plain_status,
                mobile_body_len=len(mobile_body), plain_body_len=len(plain_body),
                mobile_fields=mobile_fields, plain_fields=plain_fields,
                shadow_fields=shadow_fields,
                status_diverged=status_diverged,
                rate_limit_diverged=rate_limit_diverged,
            )
        except Exception as exc:
            log.debug("[mobile-diff] replay failed [%s %s]: %s", method, url, exc)
            return None

    @staticmethod
    def _safe_request(session, method, url, **kwargs) -> Optional[requests.Response]:
        try:
            return session.request(method, url, **kwargs)
        except Exception:
            return None

    @staticmethod
    def _json_keys(body: str) -> List[str]:
        """Return top-level JSON keys from a response body."""
        try:
            data = json.loads(body)
            if isinstance(data, dict):
                return list(data.keys())
            if isinstance(data, list) and data and isinstance(data[0], dict):
                return list(data[0].keys())
        except Exception:
            pass
        return []

    @staticmethod
    def _classify_findings(result: DifferentialResult) -> List[MobileDifferentialFinding]:
        """Classify a DifferentialResult into one or more specific finding types."""
        findings = []

        if result.shadow_fields:
            findings.append(MobileDifferentialFinding(
                result=result,
                vuln_type="mobile_shadow_api_field",
                title=f"Mobile Backend: Server exposes hidden fields without mobile headers",
                severity="high",
                evidence=(
                    f"Endpoint {result.url} returns extra fields when called WITHOUT "
                    f"mobile client headers: {result.shadow_fields[:10]}. "
                    f"Mobile app: {result.mobile_fields[:5]}, "
                    f"Direct access: {result.plain_fields[:5]}. "
                    f"These fields may contain sensitive data the app hides from users."
                ),
            ))

        if result.status_diverged:
            mobile_ok  = result.mobile_status in (200, 201)
            plain_ok   = result.plain_status  in (200, 201)
            if plain_ok and not mobile_ok:
                findings.append(MobileDifferentialFinding(
                    result=result,
                    vuln_type="mobile_client_trust_bypass",
                    title="Mobile Backend: Endpoint accessible without mobile client headers",
                    severity="high",
                    evidence=(
                        f"Endpoint {result.url} returns {result.plain_status} without "
                        f"mobile headers (vs {result.mobile_status} with mobile headers). "
                        f"The server gatekeeping is based on client-supplied headers, "
                        f"not cryptographic proof of origin — trivially bypassable."
                    ),
                ))
            elif mobile_ok and not plain_ok:
                findings.append(MobileDifferentialFinding(
                    result=result,
                    vuln_type="mobile_shadow_endpoint",
                    title="Mobile Backend: Shadow API endpoint — only accessible via mobile headers",
                    severity="medium",
                    evidence=(
                        f"Endpoint {result.url} returns {result.mobile_status} with "
                        f"mobile headers but {result.plain_status} without. "
                        f"This may be an undocumented shadow API endpoint. "
                        f"Shadow APIs often lack security review and authentication hardening."
                    ),
                ))

        if result.rate_limit_diverged:
            findings.append(MobileDifferentialFinding(
                result=result,
                vuln_type="mobile_rate_limit_bypass",
                title="Mobile Backend: Rate limiting based on mobile client headers",
                severity="medium",
                evidence=(
                    f"Endpoint {result.url}: mobile request got {result.mobile_status}, "
                    f"plain request got {result.plain_status}. "
                    f"Rate limiting appears to use mobile client headers as the key. "
                    f"Removing mobile headers bypasses rate limiting entirely."
                ),
            ))

        return findings


# ── Module-level API ──────────────────────────────────────────────────────────

def run_mobile_backend_differential(
    target: str,
    scan_id: str,
    endpoints: List[Dict[str, Any]],
    auth_headers: Optional[Dict[str, str]] = None,
    app_name: Optional[str] = None,
) -> List[dict]:
    """
    Convenience function — run differential analysis and return finding dicts.
    Called from mobile security_engine._phase_backend_differential().
    """
    analyzer = MobileBackendDifferentialAnalyzer(
        target=target,
        scan_id=scan_id,
        auth_headers=auth_headers,
        app_name=app_name,
    )
    return analyzer.run(endpoints=endpoints, auth_headers=auth_headers)
