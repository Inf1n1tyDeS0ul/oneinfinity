"""
Burp Proxy Wrapper
==================
Integrates with Burp Suite proxy for mobile traffic interception.
Manages proxy configuration, certificate installation, and traffic capture.
"""

from __future__ import annotations

import json
import logging
import os
import re
import shutil
import socket
import subprocess
import tempfile
from dataclasses import dataclass, field
from datetime import datetime
from typing import List, Optional
from urllib.parse import urlparse

try:
    import urllib.request as _urllib_request
    import urllib.error as _urllib_error
except ImportError:  # pragma: no cover
    _urllib_request = None  # type: ignore
    _urllib_error = None  # type: ignore

from oneinfinity.mobile_tool_registry import UnifiedFinding

logger = logging.getLogger("oneinfinity.mobile.burp_proxy")

_TOOL = "burp_proxy"


@dataclass
class BurpConfig:
    host: str = "127.0.0.1"
    port: int = 8080
    api_port: int = 1337
    api_key: str = ""
    ca_cert_path: str = ""


@dataclass
class CapturedRequest:
    id: str
    method: str
    url: str
    headers: dict = field(default_factory=dict)
    body: str = ""
    timestamp: str = field(default_factory=lambda: datetime.utcnow().isoformat())

    def to_dict(self) -> dict:
        return {
            "id": self.id,
            "method": self.method,
            "url": self.url,
            "headers": self.headers,
            "body": self.body,
            "timestamp": self.timestamp,
        }


@dataclass
class CapturedResponse:
    id: str
    status_code: int
    headers: dict = field(default_factory=dict)
    body: str = ""
    timestamp: str = field(default_factory=lambda: datetime.utcnow().isoformat())

    def to_dict(self) -> dict:
        return {
            "id": self.id,
            "status_code": self.status_code,
            "headers": self.headers,
            "body": self.body,
            "timestamp": self.timestamp,
        }


class BurpProxyWrapper:
    """Wraps Burp Suite REST API and ADB proxy configuration for mobile testing."""

    # Patterns considered sensitive in request bodies / query strings
    _SENSITIVE_BODY_RE = re.compile(
        r"(password|passwd|secret|token|ssn|credit_card|cc_number|cvv|pin\b|dob|"
        r"date_of_birth|social_security|private_key)",
        re.IGNORECASE,
    )
    _API_KEY_IN_URL_RE = re.compile(
        r"[?&](api[_-]?key|apikey|access[_-]?token|auth[_-]?token|key)=([^&\s]{10,})",
        re.IGNORECASE,
    )
    _AUTH_TOKEN_IN_QUERY_RE = re.compile(
        r"[?&](token|auth|jwt|bearer|session[_-]?id)=([^&\s]{6,})",
        re.IGNORECASE,
    )
    _JWT_RE = re.compile(
        r"eyJ[A-Za-z0-9_\-]+\.eyJ[A-Za-z0-9_\-]+\.[A-Za-z0-9_\-]+"
    )

    def __init__(self, config: BurpConfig = None) -> None:
        self.config = config or BurpConfig()
        self._adb = shutil.which("adb")

    # ------------------------------------------------------------------ internals

    def _is_burp_running(self) -> bool:
        """Check if Burp proxy is listening on host:port."""
        try:
            with socket.create_connection(
                (self.config.host, self.config.port), timeout=2
            ):
                return True
        except (OSError, ConnectionRefusedError, socket.timeout):
            return False

    def _burp_api_request(
        self,
        path: str,
        method: str = "GET",
        data: Optional[dict] = None,
    ) -> Optional[dict]:
        """Make a request to the Burp REST API. Returns parsed JSON or None."""
        if not _urllib_request:
            return None

        url = f"http://{self.config.host}:{self.config.api_port}{path}"
        headers = {"Content-Type": "application/json"}
        if self.config.api_key:
            headers["Authorization"] = f"token {self.config.api_key}"

        try:
            body = json.dumps(data).encode() if data else None
            req = _urllib_request.Request(url, data=body, headers=headers, method=method)
            with _urllib_request.urlopen(req, timeout=10) as resp:
                raw = resp.read()
                return json.loads(raw) if raw else {}
        except Exception as exc:
            logger.debug("Burp API request failed (%s): %s", path, exc)
            return None

    # ------------------------------------------------------------------ ADB helpers

    def _run_adb(self, device_id: str, *args: str, timeout: int = 15) -> tuple:
        """Run an adb command, return (returncode, stdout, stderr)."""
        if not self._adb:
            return -1, "", "adb not found"
        cmd = [self._adb]
        if device_id:
            cmd += ["-s", device_id]
        cmd += list(args)
        try:
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
            return result.returncode, result.stdout, result.stderr
        except subprocess.TimeoutExpired:
            return -1, "", f"adb command timed out after {timeout}s"
        except Exception as exc:
            return -1, "", str(exc)

    def _set_adb_proxy(self, device_id: str, host: str, port: int) -> bool:
        """Configure ADB global HTTP proxy to host:port."""
        rc, _, stderr = self._run_adb(
            device_id,
            "shell", "settings", "put", "global", "http_proxy",
            f"{host}:{port}",
        )
        if rc != 0:
            logger.warning("Failed to set ADB proxy: %s", stderr)
            return False
        logger.info("ADB proxy set to %s:%d on device %r", host, port, device_id or "default")
        return True

    def _clear_adb_proxy(self, device_id: str = "") -> bool:
        """Remove the global HTTP proxy setting from the Android device."""
        rc, _, _stderr = self._run_adb(
            device_id,
            "shell", "settings", "put", "global", "http_proxy", ":0",
        )
        if rc != 0:
            # Fallback: delete the key entirely
            self._run_adb(device_id, "shell", "settings", "delete", "global", "http_proxy")
            logger.debug("Fallback proxy clear issued for device %r", device_id or "default")
            return False
        logger.info("ADB proxy cleared on device %r", device_id or "default")
        return True

    def _install_burp_cert(self, device_id: str = "") -> bool:
        """
        Push Burp CA certificate to the Android device and launch the system
        cert installer.  Uses config.ca_cert_path or downloads from proxy endpoint.
        """
        cert_path = self.config.ca_cert_path

        if not cert_path or not os.path.exists(cert_path):
            cert_path = self._download_burp_cert()

        if not cert_path or not os.path.exists(cert_path):
            logger.warning("Burp CA certificate not available — skipping cert install")
            return False

        device_dest = "/sdcard/burp_ca.cer"
        rc, _, stderr = self._run_adb(device_id, "push", cert_path, device_dest)
        if rc != 0:
            logger.warning("Failed to push Burp cert: %s", stderr)
            return False

        # Launch the Android certificate installer
        rc, _, stderr = self._run_adb(
            device_id,
            "shell",
            "am", "start",
            "-n", "com.android.certinstaller/.CertInstallerMain",
            "-a", "android.intent.action.VIEW",
            "-t", "application/x-x509-ca-cert",
            "-d", f"file://{device_dest}",
        )
        if rc != 0:
            logger.warning("Cert installer launch failed: %s", stderr)
            return False

        logger.info(
            "Burp CA certificate installation initiated on device %r",
            device_id or "default",
        )
        return True

    def _download_burp_cert(self) -> Optional[str]:
        """Download the Burp CA certificate from the proxy's /cert endpoint."""
        if not _urllib_request:
            return None
        cert_url = f"http://{self.config.host}:{self.config.port}/cert"
        try:
            with _urllib_request.urlopen(cert_url, timeout=5) as resp:
                cert_bytes = resp.read()
                tmp = tempfile.NamedTemporaryFile(
                    suffix=".cer", delete=False, prefix="burp_ca_"
                )
                tmp.write(cert_bytes)
                tmp.close()
                logger.info("Downloaded Burp CA cert to %s", tmp.name)
                return tmp.name
        except Exception as exc:
            logger.debug("Could not download Burp cert: %s", exc)
            return None

    # ------------------------------------------------------------------ capture control

    def start_capture(self, device_id: str = "") -> bool:
        """
        Configure the Android device to route traffic through Burp.
        Returns True if the proxy is reachable and ADB proxy was set.
        """
        if not self._is_burp_running():
            logger.error(
                "Burp Suite is not running at %s:%d — start Burp first",
                self.config.host,
                self.config.port,
            )
            return False

        proxy_ok = self._set_adb_proxy(device_id, self.config.host, self.config.port)
        cert_ok = self._install_burp_cert(device_id)

        if not proxy_ok:
            logger.warning("ADB proxy configuration failed")
            return False

        logger.info(
            "Traffic capture started: proxy=%s:%d cert_install=%s",
            self.config.host,
            self.config.port,
            cert_ok,
        )
        return True

    def stop_capture(self, device_id: str = "") -> bool:
        """Remove the proxy configuration from the Android device."""
        ok = self._clear_adb_proxy(device_id)
        if ok:
            logger.info("Traffic capture stopped — ADB proxy cleared")
        return ok

    # ------------------------------------------------------------------ traffic access

    def get_captured_traffic(self) -> List[CapturedRequest]:
        """
        Retrieve captured requests from Burp Suite via its REST API.

        Tries the v0.1 endpoint first, then the legacy /burp/proxy/history path.
        Returns an empty list if the API is not reachable or returns no data.
        """
        if not self._is_burp_running():
            logger.warning("Burp is not running — cannot retrieve traffic")
            return []

        data = self._burp_api_request("/v0.1/proxy/history")
        if data is None:
            data = self._burp_api_request("/burp/proxy/history")
        if not data:
            logger.info("No traffic data returned from Burp API")
            return []

        requests: List[CapturedRequest] = []
        messages = data if isinstance(data, list) else data.get("messages", [])

        for idx, item in enumerate(messages):
            request_info = item.get("request", item)
            url = (
                request_info.get("url")
                or request_info.get("path")
                or item.get("url", "")
            )
            method = request_info.get("method", "GET")
            headers_raw = request_info.get("headers", {})

            # Normalise header list → dict
            if isinstance(headers_raw, list):
                headers_dict: dict = {}
                for h in headers_raw:
                    if ": " in h:
                        k, _, v = h.partition(": ")
                        headers_dict[k] = v
                headers_raw = headers_dict

            requests.append(CapturedRequest(
                id=str(item.get("id", idx)),
                method=method,
                url=url,
                headers=headers_raw,
                body=request_info.get("body", ""),
                timestamp=item.get("timestamp", datetime.utcnow().isoformat()),
            ))

        logger.info("Retrieved %d requests from Burp proxy history", len(requests))
        return requests

    # ------------------------------------------------------------------ analysis

    def analyze_traffic(self, requests: List[CapturedRequest]) -> List[UnifiedFinding]:
        """
        Analyse captured requests for mobile security issues.

        Checks:
          - JWT in Authorization header or body over HTTP → CRITICAL
          - API keys / secrets in URL parameters          → CRITICAL
          - Auth tokens in query parameters               → HIGH
          - HTTP (cleartext) endpoints                    → MEDIUM
          - Sensitive field names in request body         → HIGH
        """
        findings: List[UnifiedFinding] = []
        seen: set = set()

        def _add(
            vulnerability: str,
            attack_type: str,
            severity: str,
            evidence: str,
            url: str,
            remediation: str,
        ) -> None:
            key = (attack_type, url[:100])
            if key in seen:
                return
            seen.add(key)
            findings.append(UnifiedFinding(
                target=url[:200],
                vulnerability=vulnerability,
                attack_type=attack_type,
                tool=_TOOL,
                severity=severity,
                evidence=evidence[:300],
                remediation=remediation,
            ))

        for req in requests:
            url = req.url or ""
            parsed = urlparse(url)
            is_http = parsed.scheme == "http"
            query = parsed.query or ""
            body = req.body or ""
            auth_header = req.headers.get("Authorization", "")

            # 1. JWT over plain HTTP (Authorization header)
            if is_http and self._JWT_RE.search(auth_header):
                _add(
                    vulnerability="JWT in Authorization Header Over Plaintext HTTP",
                    attack_type="jwt_over_http",
                    severity="critical",
                    evidence=f"URL: {url[:100]} | Auth: {auth_header[:40]}...",
                    url=url,
                    remediation="Migrate to HTTPS. Never send auth tokens over HTTP.",
                )

            # 2. JWT in request body over plain HTTP
            if is_http and self._JWT_RE.search(body):
                _add(
                    vulnerability="JWT Token Transmitted in HTTP Request Body",
                    attack_type="jwt_over_http",
                    severity="critical",
                    evidence=f"URL: {url[:100]}",
                    url=url,
                    remediation=(
                        "Enforce HTTPS for all API endpoints. "
                        "Configure HSTS on the server side."
                    ),
                )

            # 3. API keys in URL
            for match in self._API_KEY_IN_URL_RE.finditer(query):
                _add(
                    vulnerability="API Key / Secret Exposed in URL Parameter",
                    attack_type="api_key_in_url",
                    severity="critical",
                    evidence=f"{match.group(1)}={match.group(2)[:20]}...",
                    url=url,
                    remediation=(
                        "Pass credentials in request headers (Authorization or X-API-Key) "
                        "or in the encrypted request body — never in the URL."
                    ),
                )

            # 4. Auth tokens in query params
            for match in self._AUTH_TOKEN_IN_QUERY_RE.finditer(query):
                _add(
                    vulnerability="Authentication Token Exposed in URL Query Parameter",
                    attack_type="auth_token_in_query",
                    severity="high",
                    evidence=f"{match.group(1)}={match.group(2)[:20]}...",
                    url=url,
                    remediation=(
                        "Use Authorization headers or POST body for auth tokens. "
                        "Query parameters are logged by servers and CDNs."
                    ),
                )

            # 5. Cleartext HTTP endpoint
            if is_http and url:
                _add(
                    vulnerability=f"Cleartext HTTP Endpoint: {parsed.netloc}",
                    attack_type="cleartext_http",
                    severity="medium",
                    evidence=f"{req.method} {url[:100]}",
                    url=url,
                    remediation=(
                        "Migrate all endpoints to HTTPS and enforce HSTS. "
                        "Add android:cleartextTrafficPermitted=\"false\" to network_security_config."
                    ),
                )

            # 6. Sensitive field names in body
            for match in self._SENSITIVE_BODY_RE.finditer(body):
                field_name = match.group(0)
                _add(
                    vulnerability=f"Sensitive Field '{field_name}' Transmitted in Request Body",
                    attack_type="sensitive_data_in_body",
                    severity="high",
                    evidence=f"Field: {field_name} | URL: {url[:80]}",
                    url=url,
                    remediation=(
                        f"Ensure '{field_name}' is only transmitted over HTTPS. "
                        "Audit server-side logging to prevent credential exposure."
                    ),
                )

        logger.info(
            "analyze_traffic: %d findings from %d requests",
            len(findings),
            len(requests),
        )
        return findings

    # ------------------------------------------------------------------ export

    def export_requests_to_file(
        self,
        requests: List[CapturedRequest],
        output_path: str,
    ) -> None:
        """
        Write captured requests to a JSON file.

        Each element in the JSON array is the dict produced by
        CapturedRequest.to_dict().
        """
        data = [r.to_dict() for r in requests]
        os.makedirs(os.path.dirname(os.path.abspath(output_path)), exist_ok=True)
        with open(output_path, "w", encoding="utf-8") as fh:
            json.dump(data, fh, indent=2)
        logger.info("Exported %d requests to %s", len(requests), output_path)


# Module-level singleton
burp_proxy_wrapper = BurpProxyWrapper()
