"""
headless_browser_engine.py — Headless Browser Analysis Engine for OneInfinity

Drives a real browser (via Playwright) to extract dynamic content invisible to
plain HTTP scanners:
  - XHR / fetch API calls made by JavaScript
  - DOM elements including dynamically rendered forms
  - JavaScript-injected URLs and API endpoints
  - DOM-based XSS via canary injection
  - Client-side open redirects (window.location assignments, meta refresh)
  - Inline & loaded JS secrets (API keys, tokens, passwords)

Falls back to requests + BeautifulSoup when Playwright is not installed,
providing a best-effort static analysis mode.

Usage::

    engine = HeadlessBrowserEngine("https://example.com", output_dir="/tmp/out")
    result = engine.run()
    print(result["endpoints"])
    print(result["findings"])
    print(result["js_secrets"])
"""

from __future__ import annotations

import json
import logging
import re
import uuid
from typing import Any, Dict, List, Optional
from urllib.parse import urljoin, urlparse, urlencode, parse_qs, urlunparse

log = logging.getLogger("oi.headless_browser_engine")

# ---------------------------------------------------------------------------
# Regex patterns for secret detection
# ---------------------------------------------------------------------------

_SECRET_PATTERNS: List[Dict[str, Any]] = [
    {
        "name": "aws_access_key",
        "pattern": re.compile(r"(?<![A-Z0-9])[A-Z0-9]{20}(?![A-Z0-9])"),
        "severity": "critical",
        "context_check": re.compile(r"AKIA|ASIA|AROA", re.I),
    },
    {
        "name": "aws_secret_key",
        "pattern": re.compile(r"(?<![A-Za-z0-9/+=])[A-Za-z0-9/+=]{40}(?![A-Za-z0-9/+=])"),
        "severity": "critical",
        "context_check": re.compile(r"secret|aws|key", re.I),
    },
    {
        "name": "generic_api_key",
        "pattern": re.compile(
            r"""(?:api[_\-]?key|apikey|api[_\-]?token|access[_\-]?key)\s*[=:]\s*["']?([A-Za-z0-9_\-]{20,60})["']?""",
            re.I,
        ),
        "severity": "high",
        "context_check": None,
    },
    {
        "name": "jwt_token",
        "pattern": re.compile(r"eyJ[A-Za-z0-9_\-]+\.eyJ[A-Za-z0-9_\-]+\.[A-Za-z0-9_\-]+"),
        "severity": "high",
        "context_check": None,
    },
    {
        "name": "bearer_token",
        "pattern": re.compile(r"[Bb]earer\s+([A-Za-z0-9_\-\.]{20,200})"),
        "severity": "high",
        "context_check": None,
    },
    {
        "name": "private_key",
        "pattern": re.compile(r"-----BEGIN (RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----"),
        "severity": "critical",
        "context_check": None,
    },
    {
        "name": "google_api_key",
        "pattern": re.compile(r"AIza[0-9A-Za-z_\-]{35}"),
        "severity": "high",
        "context_check": None,
    },
    {
        "name": "password_in_js",
        "pattern": re.compile(
            r"""(?:password|passwd|secret|pwd)\s*[=:]\s*["']([^"']{6,60})["']""",
            re.I,
        ),
        "severity": "high",
        "context_check": None,
    },
    {
        "name": "slack_token",
        "pattern": re.compile(r"xox[baprs]-[0-9A-Za-z\-]{10,48}"),
        "severity": "high",
        "context_check": None,
    },
    {
        "name": "github_token",
        "pattern": re.compile(r"gh[pousr]_[A-Za-z0-9]{36,255}"),
        "severity": "critical",
        "context_check": None,
    },
]

# XSS canary injected into URL parameters
_XSS_CANARY_TEMPLATE = "OI_XSS_{uid}"
_XSS_PAYLOADS = [
    '<script>alert("{canary}")</script>',
    '"><img src=x onerror="alert(\'{canary}\')">',
    "javascript:alert('{canary}')",
    "';alert('{canary}')//",
]

# Open-redirect patterns (client-side)
_REDIRECT_JS_PATTERNS = [
    re.compile(r"window\.location\s*=\s*[\"']?(https?://)", re.I),
    re.compile(r"window\.location\.href\s*=\s*[\"']?(https?://)", re.I),
    re.compile(r"window\.location\.replace\s*\(", re.I),
    re.compile(r"window\.location\.assign\s*\(", re.I),
    re.compile(r"document\.location\s*=", re.I),
]

_META_REFRESH_PATTERN = re.compile(
    r'<meta[^>]+http-equiv\s*=\s*["\']refresh["\'][^>]*content\s*=\s*["\'][^"\']*url\s*=\s*([^"\'>\s]+)',
    re.I,
)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _make_finding(
    vuln_type: str,
    severity: str,
    url: str,
    evidence: str,
    payload: str = "",
    confidence: float = 0.7,
    extra: Optional[dict] = None,
) -> dict:
    f = {
        "vuln_type": vuln_type,
        "severity": severity,
        "url": url,
        "endpoint": url,
        "payload": payload,
        "evidence": evidence,
        "confidence": confidence,
        "tool": "headless_browser_engine",
        "source_type": "tool",
        "finding_id": f"HBE-{uuid.uuid4().hex[:8].upper()}",
    }
    if extra:
        f.update(extra)
    return f


def _inject_param(url: str, param: str, value: str) -> str:
    """Return a copy of *url* with query parameter *param* set to *value*."""
    from urllib.parse import parse_qs, urlencode, urlparse, urlunparse
    parsed = urlparse(url)
    params = parse_qs(parsed.query, keep_blank_values=True)
    params[param] = [value]
    new_query = urlencode(params, doseq=True)
    return urlunparse(parsed._replace(query=new_query))


# ---------------------------------------------------------------------------
# Engine
# ---------------------------------------------------------------------------

class HeadlessBrowserEngine:
    """
    Headless browser analysis engine.

    Uses Playwright (chromium) when available; falls back to
    requests + BeautifulSoup for static analysis.

    Parameters
    ----------
    target : str
        Base URL to analyse.
    output_dir : str
        Directory where results are written.
    """

    def __init__(self, target: str, output_dir: str = ".",
                 auth_context: Optional[Any] = None) -> None:
        self.target = target.rstrip("/")
        self.output_dir = output_dir
        self._playwright_ok: Optional[bool] = None  # lazily set
        self._auth_context = auth_context  # Optional[AuthSessionContext]

    # ------------------------------------------------------------------ #
    # Playwright availability check
    # ------------------------------------------------------------------ #

    def _check_playwright(self) -> bool:
        """Return True if playwright is importable and chromium is installed."""
        if self._playwright_ok is not None:
            return self._playwright_ok
        try:
            import importlib.util
            spec = importlib.util.find_spec("playwright")
            if spec is None:
                self._playwright_ok = False
                return False
            # Check that the sync API is importable
            from playwright.sync_api import sync_playwright  # noqa: F401
            self._playwright_ok = True
        except (ImportError, ModuleNotFoundError):
            self._playwright_ok = False
        return self._playwright_ok

    # ------------------------------------------------------------------ #
    # Crawl
    # ------------------------------------------------------------------ #

    def crawl(self, url: str, max_pages: int = 20) -> dict:
        """
        Visit *url* with a headless browser (or static fallback) and extract:
          - ``urls``       — all unique URLs observed (href + XHR)
          - ``forms``      — list of form dicts {action, method, inputs}
          - ``xhr_calls``  — URLs called via XHR/fetch
          - ``js_secrets`` — secrets found in inline JS

        Parameters
        ----------
        url : str
            Page URL to crawl from.
        max_pages : int
            Maximum number of pages to visit (Playwright mode only).
        """
        if self._check_playwright():
            return self._crawl_playwright(url, max_pages)
        return self._crawl_static(url)

    def _crawl_playwright(self, start_url: str, max_pages: int) -> dict:
        """Playwright-based deep crawl."""
        from playwright.sync_api import sync_playwright, TimeoutError as PWTimeout

        visited: set = set()
        queue = [start_url]
        all_urls: set = set()
        all_forms: List[dict] = []
        xhr_calls: List[str] = []
        js_secrets: List[dict] = []

        with sync_playwright() as pw:
            browser = pw.chromium.launch(headless=True)
            context = browser.new_context(
                ignore_https_errors=True,
                user_agent="OneInfinity-HeadlessBrowser/1.0",
            )

            # Phase B: inject auth session into Playwright context if provided.
            # Must happen AFTER new_context() but BEFORE any page.goto() call.
            # AuthSessionContext.inject_playwright() sets cookies + local/session storage.
            if self._auth_context is not None:
                try:
                    self._auth_context.inject_playwright(context)
                    log.debug("HeadlessBrowserEngine: auth context injected into Playwright context")
                except Exception as _auth_exc:
                    log.warning("HeadlessBrowserEngine: auth injection failed (non-fatal): %s", _auth_exc)

            # Intercept network requests (URLs) and XHR response bodies for secret scanning
            intercepted: List[str] = []
            xhr_response_secrets: List[dict] = []

            def _on_request(req):
                intercepted.append(req.url)

            def _on_response(resp):
                # Scan XHR/fetch response bodies for tokens/secrets (OR2 recommendation)
                try:
                    rt = resp.request.resource_type
                    if rt in ("xhr", "fetch") and "application/json" in (resp.headers.get("content-type") or ""):
                        body = resp.body()
                        if body:
                            xhr_response_secrets.extend(
                                self._scan_text_for_secrets(body.decode("utf-8", errors="ignore"), resp.url)
                            )
                except Exception:
                    pass

            context.on("request", _on_request)
            context.on("response", _on_response)

            # Intercept SPA route registration via history.pushState (OR2 lazy-route recommendation)
            spa_routes: List[str] = []

            page = context.new_page()
            # Inject SPA route tracker before first navigation
            try:
                page.add_init_script("""
                    window.__oi_spa_routes = [];
                    const _origPush = history.pushState;
                    history.pushState = function(state, title, url) {
                        if (url) window.__oi_spa_routes.push(String(url));
                        return _origPush.apply(this, arguments);
                    };
                    const _origReplace = history.replaceState;
                    history.replaceState = function(state, title, url) {
                        if (url) window.__oi_spa_routes.push(String(url));
                        return _origReplace.apply(this, arguments);
                    };
                """)
            except Exception:
                pass

            while queue and len(visited) < max_pages:
                current = queue.pop(0)
                if current in visited:
                    continue
                visited.add(current)

                try:
                    page.goto(current, timeout=15000, wait_until="networkidle")
                except PWTimeout:
                    log.debug("Playwright timeout navigating to %s", current)
                    continue
                except Exception as exc:
                    log.debug("Playwright navigation error %s: %s", current, exc)
                    continue

                # Collect all links
                try:
                    links = page.eval_on_selector_all(
                        "a[href]",
                        "els => els.map(e => e.href)",
                    )
                    base_origin = urlparse(start_url).netloc
                    for link in links:
                        all_urls.add(link)
                        if urlparse(link).netloc == base_origin and link not in visited:
                            queue.append(link)
                except Exception:
                    pass

                # Collect forms
                try:
                    forms = page.eval_on_selector_all(
                        "form",
                        """forms => forms.map(f => ({
                            action: f.action,
                            method: f.method || 'GET',
                            inputs: Array.from(f.elements).map(e => ({
                                name: e.name, type: e.type, value: e.value
                            }))
                        }))""",
                    )
                    all_forms.extend(forms)
                except Exception:
                    pass

                # Scan inline scripts for secrets
                try:
                    scripts = page.eval_on_selector_all(
                        "script:not([src])",
                        "els => els.map(e => e.textContent)",
                    )
                    for script_text in scripts:
                        js_secrets.extend(
                            self._scan_text_for_secrets(script_text, current)
                        )
                except Exception:
                    pass

            # Collect SPA routes discovered via pushState/replaceState interception
            try:
                spa_routes = page.evaluate("window.__oi_spa_routes || []")
                for route in spa_routes:
                    if route and isinstance(route, str):
                        full = urljoin(start_url, route)
                        all_urls.add(full)
            except Exception:
                pass

            # XHR calls = intercepted - navigations
            for r in intercepted:
                r_parsed = urlparse(r)
                # Skip obvious page navigations and static assets
                if r_parsed.path.endswith((".js", ".css", ".png", ".jpg", ".gif", ".ico", ".woff")):
                    continue
                if r not in visited:
                    xhr_calls.append(r)
                    all_urls.add(r)

            browser.close()

        # Merge XHR response secrets into js_secrets list
        js_secrets.extend(xhr_response_secrets)

        return {
            "urls": sorted(all_urls),
            "forms": all_forms,
            "xhr_calls": sorted(set(xhr_calls)),
            "js_secrets": js_secrets,
            "spa_routes": list(set(spa_routes)) if spa_routes else [],
            "authenticated": self._auth_context is not None,
        }

    def _crawl_static(self, url: str) -> dict:
        """Requests + BeautifulSoup static fallback."""
        import requests
        import urllib3
        urllib3.disable_warnings()

        all_urls: set = set()
        all_forms: List[dict] = []
        js_secrets: List[dict] = []

        # Phase B: build an authenticated session if auth_context provided
        session = requests.Session()
        session.verify = False
        session.headers.update({"User-Agent": "OneInfinity-HeadlessBrowser/1.0"})
        if self._auth_context is not None:
            try:
                self._auth_context.inject_requests(session)
                log.debug("HeadlessBrowserEngine._crawl_static: auth context injected into requests.Session")
            except Exception as _ae:
                log.warning("HeadlessBrowserEngine._crawl_static: auth injection failed (non-fatal): %s", _ae)

        try:
            resp = session.get(url, timeout=10)
            html = resp.text
        except Exception as exc:
            log.warning("Static crawl request failed for %s: %s", url, exc)
            return {"urls": [], "forms": [], "xhr_calls": [], "js_secrets": [],
                    "spa_routes": [], "authenticated": False}

        try:
            from bs4 import BeautifulSoup
            soup = BeautifulSoup(html, "html.parser")

            # Links
            base_origin = urlparse(url).netloc
            for tag in soup.find_all("a", href=True):
                href = urljoin(url, tag["href"])
                all_urls.add(href)

            # Forms
            for form in soup.find_all("form"):
                inputs = [
                    {"name": i.get("name", ""), "type": i.get("type", "text"), "value": i.get("value", "")}
                    for i in form.find_all(["input", "textarea", "select"])
                ]
                all_forms.append({
                    "action": urljoin(url, form.get("action") or ""),
                    "method": (form.get("method") or "GET").upper(),
                    "inputs": inputs,
                })

            # Inline scripts
            for script in soup.find_all("script", src=False):
                text = script.get_text()
                if text:
                    js_secrets.extend(self._scan_text_for_secrets(text, url))

            # Script src URLs
            # Script src URLs — use authenticated session for JS bundle fetch
            for script in soup.find_all("script", src=True):
                script_url = urljoin(url, script["src"])
                all_urls.add(script_url)
                try:
                    sr = session.get(script_url, timeout=8)
                    js_secrets.extend(self._scan_text_for_secrets(sr.text, script_url))
                except Exception:
                    pass

        except ImportError:
            log.warning("BeautifulSoup not available; static crawl limited to raw HTML regex")
            # Minimal regex fallback
            for m in re.finditer(r'href=["\']([^"\']+)["\']', html):
                all_urls.add(urljoin(url, m.group(1)))
            js_secrets.extend(self._scan_text_for_secrets(html, url))

        return {
            "urls": sorted(all_urls),
            "forms": all_forms,
            "xhr_calls": [],
            "js_secrets": js_secrets,
            "spa_routes": [],
            "authenticated": self._auth_context is not None,
        }

    # ------------------------------------------------------------------ #
    # DOM endpoint extraction
    # ------------------------------------------------------------------ #

    def extract_dom_endpoints(self, url: str) -> List[str]:
        """
        Load *url* in a headless browser (or static fallback) and return
        the unique set of URLs requested during page load (XHR, fetch, img,
        script, etc.).
        """
        if self._check_playwright():
            return self._extract_dom_endpoints_playwright(url)
        return self._extract_dom_endpoints_static(url)

    def _extract_dom_endpoints_playwright(self, url: str) -> List[str]:
        from playwright.sync_api import sync_playwright, TimeoutError as PWTimeout
        endpoints: set = set()
        try:
            with sync_playwright() as pw:
                browser = pw.chromium.launch(headless=True)
                context = browser.new_context(ignore_https_errors=True)
                context.on("request", lambda req: endpoints.add(req.url))
                page = context.new_page()
                try:
                    page.goto(url, timeout=15000, wait_until="networkidle")
                except PWTimeout:
                    pass
                browser.close()
        except Exception as exc:
            log.warning("extract_dom_endpoints playwright error for %s: %s", url, exc)
        return sorted(endpoints)

    def _extract_dom_endpoints_static(self, url: str) -> List[str]:
        import requests, urllib3
        urllib3.disable_warnings()
        endpoints: set = {url}
        try:
            resp = requests.get(url, timeout=10, verify=False)
            html = resp.text
            for m in re.finditer(r'(?:href|src|action|data-url|data-src)\s*=\s*["\']([^"\']+)["\']', html):
                endpoints.add(urljoin(url, m.group(1)))
            for m in re.finditer(r'["\'](\bhttps?://[^\s"\'<>]+)["\']', html):
                endpoints.add(m.group(1))
        except Exception as exc:
            log.warning("extract_dom_endpoints static error for %s: %s", url, exc)
        return sorted(endpoints)

    # ------------------------------------------------------------------ #
    # DOM XSS detection
    # ------------------------------------------------------------------ #

    def detect_dom_xss(self, url: str) -> List[dict]:
        """
        Inject XSS canary strings into URL query parameters and check whether
        the canary appears unescaped in the rendered DOM.

        Returns a list of finding dicts.
        """
        findings: List[dict] = []

        # Collect parameters to fuzz
        parsed = urlparse(url)
        params = list(parse_qs(parsed.query).keys())
        if not params:
            # No params in URL — inject a synthetic one
            params = ["q", "search", "id", "input", "data"]

        uid = uuid.uuid4().hex[:8].upper()
        canary = _XSS_CANARY_TEMPLATE.format(uid=uid)

        for param in params[:5]:
            for xss_tmpl in _XSS_PAYLOADS[:2]:
                payload = xss_tmpl.format(canary=canary)
                probe_url = _inject_param(url, param, payload)

                dom_content = self._get_rendered_dom(probe_url)
                if canary in dom_content:
                    findings.append(_make_finding(
                        vuln_type="dom_xss",
                        severity="high",
                        url=probe_url,
                        evidence=(
                            f"XSS canary '{canary}' reflected in DOM of {probe_url} "
                            f"via parameter '{param}'"
                        ),
                        payload=payload,
                        confidence=0.80,
                        extra={"parameter": param},
                    ))

        return findings

    def _get_rendered_dom(self, url: str) -> str:
        """Return rendered page text (Playwright) or raw HTML (static)."""
        if self._check_playwright():
            from playwright.sync_api import sync_playwright, TimeoutError as PWTimeout
            try:
                with sync_playwright() as pw:
                    browser = pw.chromium.launch(headless=True)
                    context = browser.new_context(ignore_https_errors=True)
                    page = context.new_page()
                    try:
                        page.goto(url, timeout=12000, wait_until="domcontentloaded")
                        content = page.content()
                    except PWTimeout:
                        content = ""
                    browser.close()
                return content
            except Exception:
                pass
        # Static fallback
        import requests, urllib3
        urllib3.disable_warnings()
        try:
            return requests.get(url, timeout=10, verify=False).text
        except Exception:
            return ""

    # ------------------------------------------------------------------ #
    # Client-side redirect detection
    # ------------------------------------------------------------------ #

    def detect_client_redirects(self, url: str) -> List[dict]:
        """
        Check page source for client-side redirect patterns:
          - window.location assignments to external URLs
          - Meta refresh tags
          - Open redirect patterns in JS

        Returns a list of finding dicts.
        """
        findings: List[dict] = []
        html = self._get_rendered_dom(url)

        if not html:
            return findings

        # Check window.location assignments
        for pattern in _REDIRECT_JS_PATTERNS:
            for m in pattern.finditer(html):
                findings.append(_make_finding(
                    vuln_type="client_side_open_redirect",
                    severity="medium",
                    url=url,
                    evidence=f"Client-side redirect pattern found: {m.group(0)[:120]}",
                    payload="",
                    confidence=0.55,
                ))

        # Check meta refresh
        for m in _META_REFRESH_PATTERN.finditer(html):
            redirect_target = m.group(1)
            findings.append(_make_finding(
                vuln_type="meta_refresh_redirect",
                severity="low",
                url=url,
                evidence=f"Meta refresh redirect to: {redirect_target}",
                payload="",
                confidence=0.70,
            ))

        # Deduplicate by evidence prefix
        seen: set = set()
        deduped: List[dict] = []
        for f in findings:
            key = f["evidence"][:80]
            if key not in seen:
                seen.add(key)
                deduped.append(f)
        return deduped

    # ------------------------------------------------------------------ #
    # JS secret extraction
    # ------------------------------------------------------------------ #

    def extract_js_secrets(self, url: str) -> List[dict]:
        """
        Scan inline scripts and loaded JS files for sensitive strings
        (API keys, tokens, passwords, private keys).

        Returns a list of finding dicts.
        """
        findings: List[dict] = []
        html = self._get_rendered_dom(url)
        if not html:
            return findings

        # Scan inline scripts
        for m in re.finditer(r"<script[^>]*>(.*?)</script>", html, re.DOTALL | re.I):
            text = m.group(1)
            findings.extend(self._scan_text_for_secrets(text, url))

        # Scan loaded script files
        import requests, urllib3
        urllib3.disable_warnings()
        for m in re.finditer(r'<script[^>]+src=["\']([^"\']+)["\']', html, re.I):
            script_url = urljoin(url, m.group(1))
            try:
                resp = requests.get(script_url, timeout=8, verify=False,
                                    headers={"User-Agent": "OneInfinity/1.0"})
                findings.extend(self._scan_text_for_secrets(resp.text, script_url))
            except Exception as exc:
                log.debug("Failed to fetch script %s: %s", script_url, exc)

        return findings

    def _scan_text_for_secrets(self, text: str, source_url: str) -> List[dict]:
        """Run all secret regex patterns against *text* and return findings."""
        results: List[dict] = []
        if not text:
            return results
        for pat in _SECRET_PATTERNS:
            for m in pat["pattern"].finditer(text):
                matched = m.group(0)
                # Apply context check if defined
                if pat.get("context_check"):
                    context_window = text[max(0, m.start() - 50): m.end() + 50]
                    if not pat["context_check"].search(context_window):
                        continue
                # Avoid reporting very short or obviously false-positive matches
                if len(matched) < 8:
                    continue
                results.append(_make_finding(
                    vuln_type=f"js_secret:{pat['name']}",
                    severity=pat["severity"],
                    url=source_url,
                    evidence=f"Pattern '{pat['name']}' matched: {matched[:60]}",
                    payload="",
                    confidence=0.65,
                ))
        return results

    # ------------------------------------------------------------------ #
    # Main entry point
    # ------------------------------------------------------------------ #

    def run(self) -> dict:
        """
        Run the full headless browser analysis against ``self.target``.

        Returns
        -------
        dict
            ``{endpoints, findings, js_secrets}``
        """
        log.info("HeadlessBrowserEngine starting for %s (playwright=%s)",
                 self.target, self._check_playwright())

        all_endpoints: set = set()
        all_findings: List[dict] = []
        all_js_secrets: List[dict] = []

        # Step 1: Crawl
        try:
            crawl_data = self.crawl(self.target, max_pages=20)
            all_endpoints.update(crawl_data.get("urls", []))
            all_endpoints.update(crawl_data.get("xhr_calls", []))
            all_js_secrets.extend(crawl_data.get("js_secrets", []))
        except Exception as exc:
            log.warning("crawl() failed: %s", exc)

        # Step 2: DOM endpoint extraction
        try:
            dom_eps = self.extract_dom_endpoints(self.target)
            all_endpoints.update(dom_eps)
        except Exception as exc:
            log.warning("extract_dom_endpoints() failed: %s", exc)

        # Step 3: DOM XSS detection
        try:
            xss_findings = self.detect_dom_xss(self.target)
            all_findings.extend(xss_findings)
        except Exception as exc:
            log.warning("detect_dom_xss() failed: %s", exc)

        # Step 4: Client-side redirect detection
        try:
            redirect_findings = self.detect_client_redirects(self.target)
            all_findings.extend(redirect_findings)
        except Exception as exc:
            log.warning("detect_client_redirects() failed: %s", exc)

        # Step 5: JS secret extraction
        try:
            secret_findings = self.extract_js_secrets(self.target)
            all_js_secrets.extend(secret_findings)
        except Exception as exc:
            log.warning("extract_js_secrets() failed: %s", exc)

        # Convert JS secret findings to proper finding dicts if needed
        for s in all_js_secrets:
            if "vuln_type" in s:
                all_findings.append(s)

        log.info(
            "HeadlessBrowserEngine done — %d endpoints, %d findings",
            len(all_endpoints),
            len(all_findings),
        )
        return {
            "endpoints": sorted(all_endpoints),
            "findings": all_findings,
            "js_secrets": all_js_secrets,
        }


# ---------------------------------------------------------------------------
# CLI entry point
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    import argparse
    import json
    import os
    import sys

    logging.basicConfig(level=logging.INFO, format="%(levelname)s %(name)s %(message)s")

    parser = argparse.ArgumentParser(description="Headless Browser Engine")
    parser.add_argument("target", help="Target URL (e.g. https://example.com)")
    parser.add_argument("--output-dir", default=".", help="Directory for output files")
    parser.add_argument(
        "--max-pages", type=int, default=20, help="Maximum pages to crawl"
    )
    args = parser.parse_args()

    engine = HeadlessBrowserEngine(target=args.target, output_dir=args.output_dir)
    print(f"[*] Playwright available: {engine._check_playwright()}")

    result = engine.run()

    print(f"\n[+] Endpoints found: {len(result['endpoints'])}")
    for ep in result["endpoints"][:10]:
        print(f"    {ep}")

    print(f"\n[+] Findings: {len(result['findings'])}")
    for f in result["findings"]:
        print(f"    [{f['severity'].upper()}] {f['vuln_type']} — {f['evidence'][:100]}")

    print(f"\n[+] JS Secrets: {len(result['js_secrets'])}")
    for s in result["js_secrets"][:5]:
        print(f"    [{s.get('severity','?').upper()}] {s.get('vuln_type','?')} — {s.get('evidence','')[:100]}")

    out_path = os.path.join(args.output_dir, "headless_browser_findings.json")
    with open(out_path, "w") as fh:
        json.dump(result, fh, indent=2, default=str)
    print(f"\n[+] Results written to {out_path}")
