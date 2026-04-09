"""
Mobile Network Traffic Analysis Engine
========================================
Intercepts and analyzes mobile application network traffic.
Integrates with Burp Suite and platform proxy systems.
Detects authentication vulnerabilities, certificate issues, and data leakage.
"""
from __future__ import annotations

import logging
import re
import subprocess
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Tuple
from urllib.parse import urlparse

try:
    from oneinfinity.burp_proxy_wrapper import burp_proxy_wrapper, BurpConfig
except ImportError:
    burp_proxy_wrapper = None  # type: ignore
    BurpConfig = None  # type: ignore

from oneinfinity.mobile.tool_registry import UnifiedFinding

logger = logging.getLogger("oneinfinity.mobile.network_analysis")

# ---------------------------------------------------------------------------
# Patterns for sensitive data detection in request/response bodies
# ---------------------------------------------------------------------------
_SENSITIVE_BODY_PATTERNS = [
    (re.compile(r'\b\d{4}[- ]?\d{4}[- ]?\d{4}[- ]?\d{4}\b'), "Credit card number", "critical"),
    (re.compile(r'\b\d{3}-\d{2}-\d{4}\b'), "Social Security Number (SSN)", "critical"),
    (re.compile(r'(?i)"?password"?\s*[:=]\s*["\']?[^"\',\s]{4,}'), "Password in body", "critical"),
    (re.compile(r'(?i)"?passwd"?\s*[:=]\s*["\']?[^"\',\s]{4,}'), "Password in body", "critical"),
    (re.compile(r'(?i)"?secret"?\s*[:=]\s*["\']?[^"\',\s]{8,}'), "Secret/key in body", "high"),
    (re.compile(r'eyJ[A-Za-z0-9_\-]+\.eyJ[A-Za-z0-9_\-]+\.[A-Za-z0-9_\-]+'), "JWT token in body", "high"),
    (re.compile(r'AKIA[0-9A-Z]{16}'), "AWS Access Key", "critical"),
    (re.compile(r'(?i)"?api[_-]?key"?\s*[:=]\s*["\']?[A-Za-z0-9_\-]{20,}'), "API key in body", "high"),
    (re.compile(r'(?i)"?access_token"?\s*[:=]\s*["\']?[A-Za-z0-9_\-\.]{20,}'), "Access token in body", "high"),
    (re.compile(r'(?i)"?refresh_token"?\s*[:=]\s*["\']?[A-Za-z0-9_\-\.]{20,}'), "Refresh token in body", "high"),
]

# Patterns for API keys in request headers
_HEADER_API_KEY_PATTERNS = [
    re.compile(r'(?i)^x-api-key$'),
    re.compile(r'(?i)^api-key$'),
    re.compile(r'(?i)^x-auth-token$'),
    re.compile(r'(?i)^x-secret-key$'),
    re.compile(r'(?i)^access-token$'),
]

# Auth token in URL query string
_URL_TOKEN_PATTERNS = [
    re.compile(r'[?&](token|access_token|api_key|apikey|auth|secret|key|password|passwd|jwt)=([^&\s]+)', re.I),
]

# Internal network ranges
_INTERNAL_IP_PATTERNS = [
    re.compile(r'^https?://10\.\d{1,3}\.\d{1,3}\.\d{1,3}'),
    re.compile(r'^https?://192\.168\.\d{1,3}\.\d{1,3}'),
    re.compile(r'^https?://172\.(1[6-9]|2[0-9]|3[0-1])\.\d{1,3}\.\d{1,3}'),
    re.compile(r'^https?://127\.0\.0\.1'),
    re.compile(r'^https?://localhost'),
]

# Debug endpoint patterns
_DEBUG_ENDPOINT_PATTERNS = [
    re.compile(r'(?i)/(debug|test|staging|dev|local|sandbox|actuator|health|metrics|swagger|api-docs)'),
]

# Bare IP address URL (not hostname)
_IP_URL_PATTERN = re.compile(r'^https?://\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}')


# ---------------------------------------------------------------------------
# Dataclasses
# ---------------------------------------------------------------------------


@dataclass
class NetworkAnalysisConfig:
    proxy_host: str = "127.0.0.1"
    proxy_port: int = 8080
    capture_duration: int = 60
    use_burp: bool = True
    device_id: str = ""


@dataclass
class NetworkFinding:
    finding_type: str
    url: str
    method: str
    severity: str
    description: str
    evidence: str
    headers: Dict[str, str] = field(default_factory=dict)
    body_snippet: str = ""

    def to_dict(self) -> dict:
        return {
            "finding_type": self.finding_type,
            "url": self.url,
            "method": self.method,
            "severity": self.severity,
            "description": self.description,
            "evidence": self.evidence,
            "headers": self.headers,
            "body_snippet": self.body_snippet,
        }


# ---------------------------------------------------------------------------
# Main class
# ---------------------------------------------------------------------------


class MobileNetworkAnalyzer:
    """
    Analyzes mobile application network traffic for security vulnerabilities.
    Supports both live proxy capture (Burp Suite) and static URL analysis.
    """

    def __init__(self, config: NetworkAnalysisConfig = None) -> None:
        self.config = config or NetworkAnalysisConfig()
        self._capturing: bool = False
        self._burp_session_id: Optional[str] = None

    # ------------------------------------------------------------------
    # Proxy-based capture
    # ------------------------------------------------------------------

    def start_analysis(self, package_name: str, device_id: str = "") -> bool:
        """
        Configure proxy and start traffic capture.
        Returns True if capture started successfully.
        """
        effective_device = device_id or self.config.device_id

        # Configure ADB proxy
        adb_proxy_set = self._configure_adb_proxy(effective_device)
        if not adb_proxy_set:
            logger.warning("Failed to configure ADB proxy for device %s", effective_device)

        # Start Burp capture session
        if self.config.use_burp and burp_proxy_wrapper is not None:
            try:
                if hasattr(burp_proxy_wrapper, "start_capture"):
                    session_id = burp_proxy_wrapper.start_capture(package_name=package_name)
                    self._burp_session_id = session_id
                    logger.info("Burp capture session started: %s", session_id)
            except Exception as exc:
                logger.warning("Burp proxy start_capture failed: %s", exc)

        self._capturing = True
        logger.info(
            "Network analysis started for %s on device %s (proxy=%s:%d)",
            package_name, effective_device,
            self.config.proxy_host, self.config.proxy_port,
        )
        return True

    def stop_analysis(self) -> List[NetworkFinding]:
        """
        Stop traffic capture and analyse collected traffic.
        Returns list of NetworkFinding objects.
        """
        self._capturing = False
        findings: List[NetworkFinding] = []

        if not self.config.use_burp or burp_proxy_wrapper is None:
            logger.info("No live capture data — returning empty findings from stop_analysis")
            return findings

        # Fetch captured requests from Burp
        try:
            if hasattr(burp_proxy_wrapper, "get_history"):
                requests = burp_proxy_wrapper.get_history(session_id=self._burp_session_id)
                findings = self._analyze_captured_traffic(requests)
        except Exception as exc:
            logger.warning("Error fetching Burp history: %s", exc)

        # Clear proxy on device
        self._clear_adb_proxy()

        logger.info("Network analysis stopped. %d findings from live capture.", len(findings))
        return findings

    # ------------------------------------------------------------------
    # Static URL analysis
    # ------------------------------------------------------------------

    def analyze_static_urls(
        self,
        urls: List[str],
        endpoints: list,
    ) -> List[UnifiedFinding]:
        """
        Perform static analysis of discovered URLs without live capture.
        Detects cleartext, token-in-URL, mixed content, debug endpoints,
        hardcoded IPs, and internal network endpoints.
        """
        findings: List[UnifiedFinding] = []
        network_findings: List[NetworkFinding] = []

        seen_types: Dict[str, set] = {}

        all_urls = list(urls)
        # Also extract URLs from endpoint objects
        for ep in endpoints:
            ep_url = ""
            if hasattr(ep, "url"):
                ep_url = ep.url
            elif isinstance(ep, dict):
                ep_url = ep.get("url", ep.get("full_url", ""))
            if ep_url:
                all_urls.append(ep_url)

        for url in all_urls:
            if not url or not url.startswith("http"):
                continue

            # ── Cleartext HTTP ────────────────────────────────────
            if url.startswith("http://") and not url.startswith("http://localhost"):
                nf = self._detect_insecure_communication(url)
                if nf:
                    network_findings.append(nf)

            # ── Token in URL ──────────────────────────────────────
            for pat in _URL_TOKEN_PATTERNS:
                m = pat.search(url)
                if m:
                    param = m.group(1)
                    key = f"token_in_url:{param}"
                    seen_types.setdefault("token_in_url", set())
                    if key not in seen_types["token_in_url"]:
                        seen_types["token_in_url"].add(key)
                        network_findings.append(NetworkFinding(
                            finding_type="token_in_url",
                            url=url,
                            method="GET",
                            severity="critical",
                            description=(
                                f"Authentication token/secret found in URL query parameter '{param}'. "
                                "Tokens in URLs are logged by proxies, CDNs, and server logs, exposing credentials."
                            ),
                            evidence=f"URL: {url[:200]}",
                        ))

            # ── Internal network endpoints ─────────────────────────
            for pat in _INTERNAL_IP_PATTERNS:
                if pat.match(url):
                    key = f"internal:{url[:50]}"
                    seen_types.setdefault("internal_endpoint", set())
                    if key not in seen_types["internal_endpoint"]:
                        seen_types["internal_endpoint"].add(key)
                        network_findings.append(NetworkFinding(
                            finding_type="internal_endpoint",
                            url=url,
                            method="GET",
                            severity="high",
                            description=(
                                "Endpoint on internal network range (10.x, 192.168.x, 172.16-31.x) detected. "
                                "Hardcoded internal URLs may expose server infrastructure or indicate SSRF potential."
                            ),
                            evidence=f"Internal URL: {url}",
                        ))
                    break

            # ── Hardcoded IP address ───────────────────────────────
            if _IP_URL_PATTERN.match(url):
                seen_types.setdefault("hardcoded_ip", set())
                if url[:60] not in seen_types["hardcoded_ip"]:
                    seen_types["hardcoded_ip"].add(url[:60])
                    network_findings.append(NetworkFinding(
                        finding_type="hardcoded_ip",
                        url=url,
                        method="GET",
                        severity="medium",
                        description=(
                            "API endpoint is specified as a raw IP address rather than a hostname. "
                            "IP-based URLs bypass certificate CN validation and are fragile to infrastructure changes."
                        ),
                        evidence=f"IP URL: {url}",
                    ))

            # ── Debug/staging endpoints ───────────────────────────
            for pat in _DEBUG_ENDPOINT_PATTERNS:
                if pat.search(url):
                    seen_types.setdefault("debug_endpoint", set())
                    if url[:80] not in seen_types["debug_endpoint"]:
                        seen_types["debug_endpoint"].add(url[:80])
                        network_findings.append(NetworkFinding(
                            finding_type="debug_endpoint",
                            url=url,
                            method="GET",
                            severity="medium",
                            description=(
                                "Endpoint path matches debug/staging/monitoring patterns. "
                                "Debug endpoints in production may expose stack traces, metrics, or internal info."
                            ),
                            evidence=f"Debug URL: {url}",
                        ))
                    break

        # ── Mixed content detection ────────────────────────────────
        has_https = any(u.startswith("https://") for u in all_urls)
        http_endpoints = [u for u in all_urls if u.startswith("http://")]
        if has_https and http_endpoints:
            network_findings.append(NetworkFinding(
                finding_type="mixed_content",
                url=http_endpoints[0],
                method="GET",
                severity="high",
                description=(
                    f"Application uses HTTPS for some endpoints but makes HTTP calls to {len(http_endpoints)} "
                    "others. Mixed content undermines transport security."
                ),
                evidence=f"HTTP endpoints: {', '.join(http_endpoints[:3])}",
            ))

        return self.to_unified_findings(network_findings)

    # ------------------------------------------------------------------
    # Live traffic analysis
    # ------------------------------------------------------------------

    def _analyze_captured_traffic(self, requests: List) -> List[NetworkFinding]:
        """
        Analyse a list of captured HTTP requests for security issues.
        Each request is expected to be a dict or object with method, url, headers, body.
        """
        findings: List[NetworkFinding] = []
        seen: set = set()

        for req in requests:
            # Normalise to dict
            if isinstance(req, dict):
                method = req.get("method", "GET")
                url = req.get("url", "")
                headers = req.get("headers", {})
                body = req.get("body", "")
                response_headers = req.get("response_headers", {})
                # response body if available
                resp_body = req.get("response_body", "")
            elif hasattr(req, "url"):
                method = getattr(req, "method", "GET")
                url = req.url
                headers = getattr(req, "headers", {}) or {}
                body = getattr(req, "body", "") or ""
                response_headers = getattr(req, "response_headers", {}) or {}
                resp_body = getattr(req, "response_body", "") or ""
            else:
                continue

            if not url:
                continue

            # ── HSTS missing ────────────────────────────────────
            hsts = response_headers.get("Strict-Transport-Security", "") if isinstance(response_headers, dict) else ""
            if url.startswith("https://") and not hsts:
                key = f"hsts:{urlparse(url).netloc}"
                if key not in seen:
                    seen.add(key)
                    findings.append(NetworkFinding(
                        finding_type="missing_hsts",
                        url=url, method=method,
                        severity="medium",
                        description="HTTPS response missing Strict-Transport-Security (HSTS) header.",
                        evidence=f"URL: {url} — no HSTS header in response",
                        headers=dict(headers) if isinstance(headers, dict) else {},
                    ))

            # ── Certificate Transparency missing ─────────────────
            ct_header = response_headers.get("Expect-CT", "") or response_headers.get("expect-ct", "") if isinstance(response_headers, dict) else ""
            if url.startswith("https://") and not ct_header:
                key = f"ct:{urlparse(url).netloc}"
                if key not in seen:
                    seen.add(key)
                    findings.append(NetworkFinding(
                        finding_type="missing_certificate_transparency",
                        url=url, method=method,
                        severity="low",
                        description="Response missing Expect-CT header. Certificate Transparency enforcement not configured.",
                        evidence=f"URL: {url}",
                        headers=dict(headers) if isinstance(headers, dict) else {},
                    ))

            # ── Auth token in URL ──────────────────────────────
            for pat in _URL_TOKEN_PATTERNS:
                m = pat.search(url)
                if m:
                    key = f"token_url:{url[:60]}"
                    if key not in seen:
                        seen.add(key)
                        findings.append(NetworkFinding(
                            finding_type="token_in_url",
                            url=url, method=method,
                            severity="critical",
                            description=f"Auth token in URL parameter '{m.group(1)}'. Will appear in logs and Referrer headers.",
                            evidence=f"URL: {url[:150]}",
                            headers=dict(headers) if isinstance(headers, dict) else {},
                        ))

            # ── Session cookies missing Secure/HttpOnly ────────────
            set_cookie = ""
            if isinstance(response_headers, dict):
                set_cookie = (response_headers.get("Set-Cookie", "")
                              or response_headers.get("set-cookie", ""))
            if set_cookie:
                _session_names = re.compile(r'(session|auth|token|jwt|access|user)', re.I)
                if _session_names.search(set_cookie):
                    if "Secure" not in set_cookie or "HttpOnly" not in set_cookie:
                        key = f"cookie:{url[:60]}"
                        if key not in seen:
                            seen.add(key)
                            missing_flags = []
                            if "Secure" not in set_cookie:
                                missing_flags.append("Secure")
                            if "HttpOnly" not in set_cookie:
                                missing_flags.append("HttpOnly")
                            findings.append(NetworkFinding(
                                finding_type="insecure_cookie",
                                url=url, method=method,
                                severity="high",
                                description=f"Session/auth cookie missing flags: {', '.join(missing_flags)}.",
                                evidence=f"Set-Cookie: {set_cookie[:100]}",
                                headers=dict(headers) if isinstance(headers, dict) else {},
                            ))

            # ── Sensitive data in request body ─────────────────────
            if body:
                for pat, label, sev in _SENSITIVE_BODY_PATTERNS:
                    m = pat.search(body)
                    if m:
                        key = f"body_leak:{label}:{url[:50]}"
                        if key not in seen:
                            seen.add(key)
                            snippet = body[max(0, m.start() - 20): m.end() + 20]
                            findings.append(NetworkFinding(
                                finding_type="sensitive_data_in_request",
                                url=url, method=method,
                                severity=sev,
                                description=f"Sensitive data ({label}) detected in request body.",
                                evidence=f"Snippet: {snippet[:80]}",
                                headers=dict(headers) if isinstance(headers, dict) else {},
                                body_snippet=snippet[:200],
                            ))

            # ── API key in request headers ──────────────────────────
            if isinstance(headers, dict):
                for h_name, h_val in headers.items():
                    for pat in _HEADER_API_KEY_PATTERNS:
                        if pat.match(h_name):
                            key = f"api_key_header:{h_name}:{url[:50]}"
                            if key not in seen:
                                seen.add(key)
                                findings.append(NetworkFinding(
                                    finding_type="api_key_in_header",
                                    url=url, method=method,
                                    severity="high",
                                    description=f"API key transmitted in request header '{h_name}'.",
                                    evidence=f"Header: {h_name}: {str(h_val)[:20]}...",
                                    headers={h_name: str(h_val)[:20] + "..."},
                                ))

            # ── Unencrypted WebSocket ──────────────────────────────
            if url.startswith("ws://"):
                key = f"ws:{url[:60]}"
                if key not in seen:
                    seen.add(key)
                    findings.append(NetworkFinding(
                        finding_type="unencrypted_websocket",
                        url=url, method="WS",
                        severity="high",
                        description="Unencrypted WebSocket (ws://) connection detected. Traffic can be intercepted.",
                        evidence=f"WebSocket URL: {url}",
                    ))

        return findings

    # ------------------------------------------------------------------
    # Single URL insecure communication check
    # ------------------------------------------------------------------

    def _detect_insecure_communication(self, url: str) -> Optional[NetworkFinding]:
        """Check a single URL for insecure communication and return a NetworkFinding or None."""
        if not url.startswith("http://"):
            return None

        # Exclude localhost from warnings
        try:
            parsed = urlparse(url)
            if parsed.hostname in ("localhost", "127.0.0.1", "::1"):
                return None
        except Exception:
            pass

        return NetworkFinding(
            finding_type="cleartext_communication",
            url=url,
            method="GET",
            severity="high",
            description=(
                "API endpoint uses unencrypted HTTP. "
                "All data transmitted is visible to MITM attackers on the network path."
            ),
            evidence=f"HTTP URL: {url}",
        )

    # ------------------------------------------------------------------
    # Certificate pinning detection
    # ------------------------------------------------------------------

    def _check_certificate_pinning(self, requests: List) -> bool:
        """
        Heuristically determine if certificate pinning is in use.
        Returns True if pinning-related errors are observed or all HTTPS requests succeed through proxy.
        """
        pinning_error_patterns = re.compile(
            r"(javax\.net\.ssl|certificate|pinning|handshake|ssl_error|ssl error|trust anchor|CertPathValidatorException)",
            re.I,
        )
        ssl_errors_seen = 0
        https_success = 0

        for req in requests:
            if isinstance(req, dict):
                url = req.get("url", "")
                error = req.get("error", "") or req.get("ssl_error", "")
                status = req.get("status_code", 0)
            elif hasattr(req, "url"):
                url = req.url
                error = getattr(req, "error", "") or ""
                status = getattr(req, "status_code", 0)
            else:
                continue

            if url.startswith("https://"):
                if error and pinning_error_patterns.search(str(error)):
                    ssl_errors_seen += 1
                elif status and 200 <= status < 400:
                    https_success += 1

        # If SSL errors seen through proxy → pinning is blocking MITM
        return ssl_errors_seen > 0

    # ------------------------------------------------------------------
    # Convert to UnifiedFinding
    # ------------------------------------------------------------------

    def to_unified_findings(
        self, network_findings: List[NetworkFinding], target: str = ""
    ) -> List[UnifiedFinding]:
        """Convert NetworkFinding list to UnifiedFinding list for the main pipeline."""
        unified: List[UnifiedFinding] = []

        _FINDING_METADATA = {
            "cleartext_communication": (
                "Cleartext HTTP Communication",
                "CWE-319", 7.4,
                "Migrate all API endpoints to HTTPS. Set android:usesCleartextTraffic=false.",
            ),
            "token_in_url": (
                "Authentication Token in URL",
                "CWE-598", 9.1,
                "Move authentication tokens to Authorization headers. Never include credentials in URL query parameters.",
            ),
            "mixed_content": (
                "Mixed HTTP/HTTPS Content",
                "CWE-311", 6.5,
                "Migrate all API calls to HTTPS. Enable HSTS with includeSubDomains.",
            ),
            "debug_endpoint": (
                "Debug/Internal Endpoint Exposed",
                "CWE-200", 5.3,
                "Remove or password-protect debug endpoints before production deployment.",
            ),
            "hardcoded_ip": (
                "Hardcoded IP Address Endpoint",
                "CWE-547", 4.3,
                "Use hostname-based URLs with proper TLS certificates rather than bare IP addresses.",
            ),
            "internal_endpoint": (
                "Internal Network Endpoint Hardcoded",
                "CWE-918", 7.2,
                "Remove internal network references from app code. Use service discovery or environment config.",
            ),
            "missing_hsts": (
                "Missing HSTS Header",
                "CWE-523", 5.4,
                "Add 'Strict-Transport-Security: max-age=31536000; includeSubDomains' to all HTTPS responses.",
            ),
            "missing_certificate_transparency": (
                "Missing Certificate Transparency Header",
                "CWE-295", 3.1,
                "Add Expect-CT header with appropriate max-age and enforce directive.",
            ),
            "insecure_cookie": (
                "Session Cookie Missing Security Flags",
                "CWE-614", 6.8,
                "Set Secure, HttpOnly, and SameSite=Strict flags on all authentication cookies.",
            ),
            "sensitive_data_in_request": (
                "Sensitive Data in HTTP Request Body",
                "CWE-312", 8.0,
                "Ensure sensitive data is transmitted over HTTPS only. Never log request bodies in production.",
            ),
            "api_key_in_header": (
                "API Key Transmitted in HTTP Header",
                "CWE-312", 5.5,
                "Store API keys server-side; use short-lived tokens; rotate keys regularly.",
            ),
            "unencrypted_websocket": (
                "Unencrypted WebSocket Connection",
                "CWE-319", 7.4,
                "Upgrade WebSocket connections to wss:// (WebSocket Secure).",
            ),
        }

        for nf in network_findings:
            meta = _FINDING_METADATA.get(nf.finding_type, (
                nf.finding_type.replace("_", " ").title(), "", 0.0, ""
            ))
            title_prefix, cwe, cvss, recommendation = meta

            unified.append(UnifiedFinding(
                title=f"{title_prefix}: {nf.url[:60]}",
                severity=nf.severity,
                finding_type=nf.finding_type,
                tool="mobile_network_analyzer",
                description=nf.description,
                evidence=nf.evidence,
                recommendation=recommendation,
                cwe=cwe,
                cvss_score=cvss,
                package=target,
                location=nf.url[:120],
                raw=nf.to_dict(),
            ))

        return unified

    # ------------------------------------------------------------------
    # Curl command generator
    # ------------------------------------------------------------------

    def generate_curl_commands(self, urls: List[str], headers: Dict = {}) -> List[str]:
        """
        Generate curl test commands for a list of discovered API endpoints.
        Includes common security test variants.
        """
        commands: List[str] = []

        for url in urls:
            if not url or not url.startswith("http"):
                continue

            # Base header string
            header_str = " ".join(f'-H "{k}: {v}"' for k, v in headers.items())

            # 1. Basic GET request
            commands.append(f'curl -sk -o /dev/null -w "%{{http_code}} %{{url_effective}}" {header_str} "{url}"')

            # 2. Auth bypass: no auth header
            commands.append(f'# Auth bypass test:\ncurl -sk "{url}"')

            # 3. Method tampering: try HEAD
            commands.append(f'curl -sk -X HEAD -I "{url}"')

            # 4. OPTIONS to discover allowed methods
            commands.append(f'curl -sk -X OPTIONS -I "{url}"')

            # 5. IDOR: replace numeric IDs
            if re.search(r'/\d+', url):
                alt_url = re.sub(r'/(\d+)', '/1337', url, count=1)
                commands.append(f'# IDOR test (ID=1337):\ncurl -sk {header_str} "{alt_url}"')

            # 6. SQL injection in query params
            parsed = urlparse(url)
            if parsed.query:
                sqli_url = url.replace("=", "='%20OR%20'1'='1")
                commands.append(f'# SQLi test:\ncurl -sk {header_str} "{sqli_url}"')

            # 7. SSRF test (if URL param present)
            if re.search(r'[?&](url|redirect|next|target|link)=', url, re.I):
                ssrf_url = re.sub(r'([?&](?:url|redirect|next|target|link)=)[^&]+', r'\1http://169.254.169.254/latest/meta-data/', url, flags=re.I)
                commands.append(f'# SSRF test:\ncurl -sk {header_str} "{ssrf_url}"')

        return commands

    # ------------------------------------------------------------------
    # ADB proxy helpers
    # ------------------------------------------------------------------

    def _configure_adb_proxy(self, device_id: str) -> bool:
        """Set ADB proxy settings for the device."""
        import shutil
        adb = shutil.which("adb")
        if not adb:
            return False

        cmd = [adb]
        if device_id:
            cmd += ["-s", device_id]
        cmd += [
            "shell", "settings", "put", "global", "http_proxy",
            f"{self.config.proxy_host}:{self.config.proxy_port}",
        ]

        try:
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=10)
            return result.returncode == 0
        except Exception as exc:
            logger.debug("ADB proxy set failed: %s", exc)
            return False

    def _clear_adb_proxy(self) -> None:
        """Remove ADB proxy settings from the device."""
        import shutil
        adb = shutil.which("adb")
        if not adb:
            return

        device_id = self.config.device_id
        cmd = [adb]
        if device_id:
            cmd += ["-s", device_id]
        cmd += ["shell", "settings", "put", "global", "http_proxy", ":0"]

        try:
            subprocess.run(cmd, capture_output=True, timeout=10)
        except Exception:
            pass


# Module-level singleton
mobile_network_analyzer = MobileNetworkAnalyzer()
