"""
Proxy Manager
=============
Centralized proxy configuration for all HTTP-making modules in the platform.

Supports:
  - Burp Suite / OWASP ZAP / mitmproxy / any HTTP(S) proxy
  - Per-module enable/disable (recon, scan, ai, agent)
  - SSL verification bypass for intercepting proxies
  - Request logging for all proxied traffic
  - urllib.request.ProxyHandler integration
  - Subprocess env-var injection (for CLI tools)

Usage:
    from oneinfinity.proxy_manager import proxy_manager, get_proxied_opener

    proxy_manager.configure("http://127.0.0.1:8080")
    proxy_manager.enable()

    # urllib integration
    opener = get_proxied_opener()
    resp = opener.open(req)

    # requests library integration
    proxies = proxy_manager.as_requests_dict()

    # subprocess env injection
    env = proxy_manager.subprocess_env()
    subprocess.run(cmd, env=env)
"""

from __future__ import annotations

import logging
import os
import ssl
import urllib.request
import urllib.error
from dataclasses import dataclass, field
from datetime import datetime
from typing import Dict, List, Optional, Tuple
from urllib.parse import urlparse

from oneinfinity.traffic_capture_engine import traffic_capture_engine, CapturedRequest

log = logging.getLogger("oneinfinity.proxy")


# ─────────────────────────────────────────────────────────────────────────────
#  Module-level proxy scope flags
# ─────────────────────────────────────────────────────────────────────────────

class ProxyScope:
    RECON      = "recon"
    SCAN       = "scan"
    AI         = "ai"
    AGENT      = "agent"
    REPORT     = "report"
    ALL        = "__all__"


# ─────────────────────────────────────────────────────────────────────────────
#  Config dataclass
# ─────────────────────────────────────────────────────────────────────────────

@dataclass
class ProxyConfig:
    address: str = ""                        # e.g. "http://127.0.0.1:8080"
    enabled: bool = False
    verify_ssl: bool = False                 # False = trust proxy's MITM cert
    scopes: List[str] = field(default_factory=lambda: [ProxyScope.ALL])
    username: str = ""
    password: str = ""
    # Per-request capture
    capture_traffic: bool = True
    log_requests: bool = True

    @property
    def host(self) -> str:
        if not self.address:
            return ""
        p = urlparse(self.address)
        return p.hostname or ""

    @property
    def port(self) -> int:
        if not self.address:
            return 0
        p = urlparse(self.address)
        return p.port or 8080

    @property
    def scheme(self) -> str:
        if not self.address:
            return "http"
        return urlparse(self.address).scheme or "http"

    def is_scope_enabled(self, scope: str) -> bool:
        return self.enabled and (
            ProxyScope.ALL in self.scopes or scope in self.scopes
        )


# ─────────────────────────────────────────────────────────────────────────────
#  Proxy Manager
# ─────────────────────────────────────────────────────────────────────────────

class ProxyManager:
    """
    Singleton proxy manager — configure once, used everywhere.
    """

    def __init__(self) -> None:
        self._config = ProxyConfig()
        self._request_log: List[Dict] = []

    # ── Configuration ─────────────────────────────────────────────────────────

    def configure(
        self,
        address: str,
        verify_ssl: bool = False,
        scopes: Optional[List[str]] = None,
        username: str = "",
        password: str = "",
        capture: bool = True,
    ) -> None:
        """Configure proxy address and options."""
        self._config.address = address.strip()
        self._config.verify_ssl = verify_ssl
        self._config.scopes = scopes or [ProxyScope.ALL]
        self._config.username = username
        self._config.password = password
        self._config.capture_traffic = capture
        log.info("Proxy configured: %s (scopes=%s)", address, self._config.scopes)

    def enable(self, scope: Optional[str] = None) -> None:
        """Enable proxy globally or for a specific scope."""
        if not self._config.address:
            raise ValueError("Configure proxy address first with proxy_manager.configure()")
        self._config.enabled = True
        if scope and scope not in self._config.scopes:
            self._config.scopes.append(scope)
        log.info("Proxy enabled: %s", self._config.address)

    def disable(self) -> None:
        """Disable proxy routing."""
        self._config.enabled = False
        log.info("Proxy disabled")

    def enable_for_scope(self, scope: str) -> None:
        if ProxyScope.ALL in self._config.scopes:
            self._config.scopes.remove(ProxyScope.ALL)
        if scope not in self._config.scopes:
            self._config.scopes.append(scope)
        self._config.enabled = True

    def disable_for_scope(self, scope: str) -> None:
        if scope in self._config.scopes:
            self._config.scopes.remove(scope)
        if not self._config.scopes:
            self._config.enabled = False

    @property
    def config(self) -> ProxyConfig:
        return self._config

    @property
    def is_active(self) -> bool:
        return self._config.enabled and bool(self._config.address)

    # ── urllib.request integration ────────────────────────────────────────────

    def build_opener(self, scope: str = ProxyScope.ALL) -> urllib.request.OpenerDirector:
        """
        Build a urllib.request opener that routes through the proxy.
        Falls back to default opener if proxy is not active for this scope.
        """
        handlers: list = []

        if self._config.is_scope_enabled(scope):
            proxy_dict = self._proxy_dict()
            proxy_handler = urllib.request.ProxyHandler(proxy_dict)
            handlers.append(proxy_handler)
            log.debug("Proxy handler added for scope=%s → %s", scope, self._config.address)

        # SSL context — bypass verification when using intercepting proxy
        if not self._config.verify_ssl:
            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
            https_handler = urllib.request.HTTPSHandler(context=ctx)
            handlers.append(https_handler)

        return urllib.request.build_opener(*handlers)

    def make_request(
        self,
        req: urllib.request.Request,
        timeout: int = 30,
        scope: str = ProxyScope.ALL,
        capture_tag: str = "",
    ) -> Tuple[int, str, Dict]:
        """
        Send a urllib Request through the proxy (if enabled).
        Returns (status_code, response_body, response_headers).
        Captures traffic automatically if capture is enabled.
        """
        opener = self.build_opener(scope)
        t0 = datetime.utcnow().isoformat()

        try:
            with opener.open(req, timeout=timeout) as resp:
                status = resp.getcode()
                body = resp.read(1 << 20).decode("utf-8", errors="ignore")
                headers = dict(resp.headers)
        except urllib.error.HTTPError as exc:
            status = exc.code
            body = exc.read(4096).decode("utf-8", errors="ignore")
            headers = dict(exc.headers) if exc.headers else {}
        except Exception as exc:
            raise

        # Log
        if self._config.log_requests and self._config.is_scope_enabled(scope):
            log.debug("PROXIED %s %s → %d", req.get_method(), req.full_url, status)

        # Capture
        if self._config.capture_traffic:
            req_body = ""
            try:
                req_body = req.data.decode("utf-8", errors="ignore") if req.data else ""
            except Exception:
                pass
            captured = CapturedRequest(
                method=req.get_method(),
                url=req.full_url,
                headers=dict(req.headers),
                body=req_body,
                response_status=status,
                response_headers=headers,
                response_body=body,
                source=capture_tag or scope,
                proxied=self._config.is_scope_enabled(scope),
                proxy_address=self._config.address if self._config.is_scope_enabled(scope) else "",
            )
            traffic_capture_engine.store(captured)

        return status, body, headers

    # ── As-dict for third-party libraries ─────────────────────────────────────

    def as_requests_dict(self) -> Dict[str, str]:
        """Return proxy dict compatible with the `requests` library."""
        if not self.is_active:
            return {}
        return {
            "http":  self._config.address,
            "https": self._config.address,
        }

    def subprocess_env(self, base_env: Optional[Dict] = None) -> Dict[str, str]:
        """
        Return environment dict with HTTP_PROXY / HTTPS_PROXY set.
        Inject into subprocess.run(env=...) so CLI tools also route through proxy.
        """
        env = dict(base_env or os.environ)
        if self.is_active:
            env["http_proxy"]  = self._config.address
            env["https_proxy"] = self._config.address
            env["HTTP_PROXY"]  = self._config.address
            env["HTTPS_PROXY"] = self._config.address
            env["no_proxy"]    = ""
        return env

    def curl_args(self) -> List[str]:
        """Return --proxy args for curl subprocess calls."""
        if not self.is_active:
            return []
        args = ["--proxy", self._config.address, "--insecure"]
        if self._config.username:
            args += ["--proxy-user", f"{self._config.username}:{self._config.password}"]
        return args

    # ── Status ────────────────────────────────────────────────────────────────

    def status(self) -> Dict:
        return {
            "enabled":  self._config.enabled,
            "address":  self._config.address,
            "scopes":   self._config.scopes,
            "verify_ssl": self._config.verify_ssl,
            "capture":  self._config.capture_traffic,
            "active":   self.is_active,
        }

    def __repr__(self) -> str:
        return f"ProxyManager(address={self._config.address!r}, enabled={self._config.enabled})"

    # ── Internal ──────────────────────────────────────────────────────────────

    def _proxy_dict(self) -> Dict[str, str]:
        return {
            "http":  self._config.address,
            "https": self._config.address,
        }


# ─────────────────────────────────────────────────────────────────────────────
#  Global singleton + convenience helpers
# ─────────────────────────────────────────────────────────────────────────────

proxy_manager = ProxyManager()


def configure_proxy_from_args(args) -> None:
    """
    Parse --proxy flag from argparse namespace and configure global proxy.
    Call this at the top of any CLI handler that accepts --proxy.

    Example:
        configure_proxy_from_args(args)   # args.proxy = "http://127.0.0.1:8080"
    """
    proxy_addr = getattr(args, "proxy", None)
    if proxy_addr:
        proxy_manager.configure(proxy_addr)
        proxy_manager.enable()
        log.info("[proxy] Routing through %s", proxy_addr)


def get_proxied_opener(scope: str = ProxyScope.ALL) -> urllib.request.OpenerDirector:
    """Convenience: get an opener for a given scope."""
    return proxy_manager.build_opener(scope)
