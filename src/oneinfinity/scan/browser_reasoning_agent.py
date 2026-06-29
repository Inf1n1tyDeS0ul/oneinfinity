"""
browser_reasoning_agent.py — Browser-Native Reasoning Agent

LLM agent that discovers vulnerabilities in:
- Single Page Applications (React/Vue/Angular/Next.js)
- Complex JS-heavy authentication flows
- Client-side validation bypasses (button disabled → API call still works)
- Hidden API calls intercepted from XHR/fetch
- Business logic flaws in stateful multi-step flows

Architecture:
- Playwright (preferred): headless browser with XHR/fetch interception
- BeautifulSoup fallback: static HTML parsing when Playwright unavailable
- LLM reasoning over DOM + intercepted API calls
- Direct HTTP exploitation via urllib for confirmed attack vectors

Council Sprint 3 — NEW capability.
"""
from __future__ import annotations

import asyncio
import json
import logging
import re
import ssl
import time
import urllib.parse
import urllib.request
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional

log = logging.getLogger("oneinfinity.scan.browser_reasoning_agent")


# ---------------------------------------------------------------------------
# Data models
# ---------------------------------------------------------------------------

@dataclass
class BrowserFinding:
    vuln_type: str
    element: str = ""
    api_endpoint: str = ""
    attack_description: str = ""
    severity: str = "medium"
    evidence: str = ""
    confidence: float = 0.5
    source: str = "browser_reasoning"

    def to_dict(self) -> dict:
        return {
            "vuln_type": self.vuln_type,
            "element": self.element,
            "url": self.api_endpoint,
            "title": f"Browser-Detected: {self.vuln_type}",
            "severity": self.severity,
            "evidence": self.evidence,
            "confidence": self.confidence,
            "source": self.source,
            "attack_description": self.attack_description,
        }


# ---------------------------------------------------------------------------
# Main agent
# ---------------------------------------------------------------------------

class BrowserReasoningAgent:
    """
    Browser-Native Reasoning Agent for SPA and JS-heavy vulnerability discovery.

    Usage::
        agent = BrowserReasoningAgent(target="https://example.com")
        findings = asyncio.run(agent.scan(session_id="scan-123"))
    """

    def __init__(
        self,
        target: str,
        llm_provider=None,
        timeout: int = 30,
    ) -> None:
        self.target = target if target.startswith("http") else f"https://{target}"
        self._provider = llm_provider
        self.timeout = timeout
        self._ssl_ctx = ssl.create_default_context()
        self._ssl_ctx.check_hostname = False
        self._ssl_ctx.verify_mode = ssl.CERT_NONE

    def _get_provider(self):
        if self._provider is not None:
            return self._provider
        try:
            from oneinfinity.infra.llm_provider import LLMProviderFactory
            self._provider = LLMProviderFactory().auto_detect()
        except Exception as exc:
            log.debug("[BrowserAgent] LLM unavailable: %s", exc)
        return self._provider

    # ── Main entry point ──────────────────────────────────────────────────────

    async def scan(self, session_id: str = "") -> list[dict]:
        """
        Run the browser-based reasoning scan. Returns list of finding dicts.
        Tries Playwright first, falls back to BeautifulSoup.
        """
        findings: list[BrowserFinding] = []

        try:
            playwright_findings = await self._scan_with_playwright()
            findings.extend(playwright_findings)
        except ImportError:
            log.info("[BrowserAgent] Playwright not available — using BS4 fallback")
            bs4_findings = await asyncio.to_thread(self._scan_with_bs4)
            findings.extend(bs4_findings)
        except Exception as exc:
            log.warning("[BrowserAgent] Playwright scan failed: %s — using BS4 fallback", exc)
            try:
                bs4_findings = await asyncio.to_thread(self._scan_with_bs4)
                findings.extend(bs4_findings)
            except Exception as exc2:
                log.debug("[BrowserAgent] BS4 fallback also failed: %s", exc2)

        log.info("[BrowserAgent] Scan complete — %d findings for %s", len(findings), self.target)
        return [f.to_dict() for f in findings]

    # ── Playwright path ───────────────────────────────────────────────────────

    async def _scan_with_playwright(self) -> list[BrowserFinding]:
        """Full browser scan with XHR interception and DOM accessibility analysis."""
        from playwright.async_api import async_playwright

        intercepted_api_calls: list[dict] = []
        findings: list[BrowserFinding] = []

        async with async_playwright() as pw:
            browser = await pw.chromium.launch(headless=True)
            context = await browser.new_context(
                ignore_https_errors=True,
                user_agent="Mozilla/5.0 (compatible; SecurityScanner/1.0)",
            )
            page = await context.new_page()

            # Intercept all network requests
            async def on_request(request):
                if request.resource_type in ("fetch", "xhr"):
                    intercepted_api_calls.append({
                        "url": request.url,
                        "method": request.method,
                        "headers": dict(request.headers),
                        "post_data": request.post_data or "",
                    })

            page.on("request", on_request)

            try:
                await page.goto(self.target, wait_until="networkidle", timeout=self.timeout * 1000)
                await asyncio.sleep(2)  # Allow dynamic content to load

                # Capture DOM accessibility tree (page.accessibility removed in Playwright 1.46+)
                dom_snapshot = None
                try:
                    dom_snapshot = await page.accessibility.snapshot()
                    dom_str = json.dumps(dom_snapshot, indent=2)[:3000] if dom_snapshot else ""
                except AttributeError:
                    # Playwright ≥1.46 removed page.accessibility — use aria snapshot instead
                    try:
                        dom_str = await page.locator("body").aria_snapshot()
                        dom_str = dom_str[:3000] if dom_str else ""
                    except Exception:
                        dom_str = (await page.content())[:3000]

                # Look for disabled/hidden elements that suggest client-side validation
                disabled_elements = await page.evaluate("""
                    () => {
                        const disabled = [];
                        document.querySelectorAll('[disabled], [aria-disabled="true"]').forEach(el => {
                            disabled.push({
                                tag: el.tagName,
                                id: el.id,
                                text: el.textContent?.trim()?.slice(0, 50),
                                type: el.type,
                                form: el.form?.id || el.form?.action || '',
                            });
                        });
                        return disabled.slice(0, 20);
                    }
                """)

                # Look for hidden form fields
                hidden_inputs = await page.evaluate("""
                    () => {
                        const hidden = [];
                        document.querySelectorAll('input[type="hidden"]').forEach(el => {
                            hidden.push({name: el.name, value: el.value?.slice(0, 50)});
                        });
                        return hidden.slice(0, 20);
                    }
                """)

                # Screenshot for context
                screenshot_path = None
                try:
                    ss_dir = Path.home() / ".oneinfinity" / "browser_scans"
                    ss_dir.mkdir(parents=True, exist_ok=True)
                    screenshot_path = str(ss_dir / f"browser_scan_{int(time.time())}.png")
                    await page.screenshot(path=screenshot_path, full_page=False)
                except Exception:
                    pass

            finally:
                await browser.close()

        # Send to LLM for analysis
        llm_findings = self._analyze_dom_with_llm(
            dom_str=dom_str,
            intercepted_apis=intercepted_api_calls[:20],
            disabled_elements=disabled_elements,
            hidden_inputs=hidden_inputs,
        )
        findings.extend(llm_findings)

        # Attempt exploitation of LLM-identified targets
        for finding in llm_findings:
            if finding.api_endpoint and finding.confidence >= 0.6:
                confirmed = self._attempt_exploitation(finding)
                if confirmed:
                    finding.evidence = confirmed
                    finding.confidence = min(1.0, finding.confidence + 0.2)

        return findings

    # ── BeautifulSoup fallback ────────────────────────────────────────────────

    def _scan_with_bs4(self) -> list[BrowserFinding]:
        """Static HTML analysis fallback when Playwright is unavailable."""
        findings: list[BrowserFinding] = []

        try:
            # Fetch the page
            req = urllib.request.Request(
                self.target,
                headers={"User-Agent": "Mozilla/5.0 (compatible; SecurityScanner/1.0)"},
            )
            with urllib.request.urlopen(req, timeout=self.timeout, context=self._ssl_ctx) as resp:
                html = resp.read().decode(errors="replace")

            # Try BeautifulSoup
            try:
                from bs4 import BeautifulSoup
                soup = BeautifulSoup(html, "html.parser")
                findings.extend(self._analyze_html_static(soup, html))
            except ImportError:
                findings.extend(self._analyze_html_regex(html))

        except Exception as exc:
            log.debug("[BrowserAgent] BS4 page fetch failed: %s", exc)

        return findings

    def _analyze_html_static(self, soup, html: str) -> list[BrowserFinding]:
        """Analyze parsed HTML for security issues."""
        findings: list[BrowserFinding] = []

        # Find forms with sensitive actions
        for form in soup.find_all("form"):
            action = form.get("action", "")
            method = form.get("method", "GET").upper()
            hidden_fields = form.find_all("input", type="hidden")

            # CSRF: form without anti-CSRF token?
            has_csrf = any(
                "csrf" in str(inp.get("name", "")).lower() or
                "token" in str(inp.get("name", "")).lower()
                for inp in hidden_fields
            )
            if not has_csrf and method == "POST":
                findings.append(BrowserFinding(
                    vuln_type="missing_csrf",
                    element=f"FORM action={action}",
                    api_endpoint=urllib.parse.urljoin(self.target, action),
                    attack_description="POST form without visible CSRF token",
                    severity="medium",
                    confidence=0.5,
                ))

            # Hidden admin/debug fields
            for inp in hidden_fields:
                name = str(inp.get("name", "")).lower()
                value = str(inp.get("value", ""))
                if any(k in name for k in ["admin", "debug", "internal", "role", "privilege"]):
                    findings.append(BrowserFinding(
                        vuln_type="hidden_parameter_manipulation",
                        element=f"hidden input: {inp.get('name')}={value[:30]}",
                        api_endpoint=urllib.parse.urljoin(self.target, action),
                        attack_description=f"Manipulable hidden field '{inp.get('name')}' with value '{value[:30]}'",
                        severity="high",
                        confidence=0.65,
                    ))

        # Find API calls in inline scripts
        api_patterns = re.findall(r'fetch\([\'"]([^\'"]+)[\'"]', html)
        api_patterns += re.findall(r'axios\.(get|post|put|delete)\([\'"]([^\'"]+)[\'"]', html)
        api_patterns += re.findall(r'XMLHttpRequest.*?open\([\'"](?:GET|POST)[\'"],\s*[\'"]([^\'"]+)[\'"]', html)

        for path in set(api_patterns):
            if path.startswith("/"):
                full_url = urllib.parse.urljoin(self.target, path)
                findings.append(BrowserFinding(
                    vuln_type="api_endpoint_discovery",
                    element="inline JavaScript",
                    api_endpoint=full_url,
                    attack_description=f"API endpoint discovered in JavaScript: {path}",
                    severity="info",
                    confidence=0.8,
                    source="js_analysis",
                ))

        return findings

    def _analyze_html_regex(self, html: str) -> list[BrowserFinding]:
        """Minimal regex-only analysis when BeautifulSoup unavailable."""
        findings: list[BrowserFinding] = []

        # Find API paths
        for path in re.findall(r'["\']/(api|v\d+|graphql|admin|internal)[^\'"]*["\']', html, re.I):
            if isinstance(path, tuple):
                path = "/" + path[0]
            findings.append(BrowserFinding(
                vuln_type="api_endpoint_discovery",
                element="HTML source",
                api_endpoint=urllib.parse.urljoin(self.target, path),
                attack_description=f"API path found in source: {path}",
                severity="info",
                confidence=0.6,
            ))

        return findings

    # ── LLM analysis ──────────────────────────────────────────────────────────

    def _analyze_dom_with_llm(
        self,
        dom_str: str,
        intercepted_apis: list[dict],
        disabled_elements: list[dict],
        hidden_inputs: list[dict],
    ) -> list[BrowserFinding]:
        """Use LLM to reason over DOM + intercepted APIs for security issues."""
        provider = self._get_provider()
        if provider is None:
            return []

        api_summary = json.dumps(intercepted_apis[:10], indent=2)[:2000]
        disabled_summary = json.dumps(disabled_elements[:10], indent=2)[:500] if disabled_elements else "none"
        hidden_summary = json.dumps(hidden_inputs[:10], indent=2)[:500] if hidden_inputs else "none"

        prompt = (
            f"You are an expert web security researcher analyzing a web application for vulnerabilities.\n\n"
            f"Target: {self.target}\n\n"
            f"DOM Accessibility Tree (first 2000 chars):\n{dom_str[:2000]}\n\n"
            f"Intercepted API Calls:\n{api_summary}\n\n"
            f"Disabled UI Elements (potential client-side bypass):\n{disabled_summary}\n\n"
            f"Hidden Form Fields:\n{hidden_summary}\n\n"
            f"Identify security vulnerabilities. Look for:\n"
            f"1. Disabled buttons/inputs that bypass client-side validation via direct API call\n"
            f"2. Sensitive data exposed in DOM or intercepted API responses\n"
            f"3. IDOR-prone API endpoints with numeric IDs or user references\n"
            f"4. Business logic flaws visible in the flow (e.g., price=0, quantity=-1)\n"
            f"5. Authentication bypass indicators\n"
            f"6. Privilege escalation vectors\n\n"
            f"Return ONLY valid JSON:\n"
            '{"findings": [{"vuln_type": "idor", "element": "disabled button", '
            '"api_endpoint": "/api/users/1", "attack": "bypass client validation via direct POST", '
            '"severity": "high", "confidence": 0.7}]}'
        )

        try:
            resp = provider.chat(
                prompt,
                system="You are an expert web security researcher. Respond ONLY with valid JSON.",
                max_tokens=2000,
                temperature=0.3,
            )
            raw = json.loads(resp.text.strip() if resp else "{}")
            results = []
            for f in raw.get("findings", []):
                results.append(BrowserFinding(
                    vuln_type=f.get("vuln_type", "unknown"),
                    element=f.get("element", ""),
                    api_endpoint=f.get("api_endpoint", ""),
                    attack_description=f.get("attack", ""),
                    severity=f.get("severity", "medium"),
                    confidence=float(f.get("confidence", 0.5)),
                    source="browser_llm_analysis",
                ))
            log.info("[BrowserAgent] LLM identified %d potential findings", len(results))
            return results

        except Exception as exc:
            log.debug("[BrowserAgent] LLM analysis failed: %s", exc)
            return []

    # ── Exploitation attempt ──────────────────────────────────────────────────

    def _attempt_exploitation(self, finding: BrowserFinding) -> str:
        """Attempt HTTP exploitation of an LLM-identified finding. Returns evidence or ''."""
        endpoint = finding.api_endpoint
        if not endpoint:
            return ""
        try:
            if not endpoint.startswith("http"):
                endpoint = urllib.parse.urljoin(self.target, endpoint)

            req = urllib.request.Request(endpoint)
            req.add_header("User-Agent", "Mozilla/5.0")
            with urllib.request.urlopen(req, timeout=8, context=self._ssl_ctx) as resp:
                body = resp.read(2000).decode(errors="replace")
                # Check for sensitive data patterns
                if re.search(r'"email"|"username"|"password"|"token"|"secret"', body, re.I):
                    return f"Sensitive data exposed: {body[:200]}"
                if resp.status == 200 and finding.vuln_type == "unauthenticated_access":
                    return f"Unauthenticated access confirmed (HTTP 200): {body[:100]}"
        except Exception as exc:
            log.debug("[BrowserAgent] Exploitation attempt failed for %s: %s", endpoint, exc)
        return ""


# ---------------------------------------------------------------------------
# Sync wrapper for non-async contexts
# ---------------------------------------------------------------------------

def run_browser_scan(target: str, session_id: str = "") -> list[dict]:
    """Synchronous wrapper for BrowserReasoningAgent.scan()."""
    agent = BrowserReasoningAgent(target=target)
    try:
        return asyncio.run(agent.scan(session_id=session_id))
    except RuntimeError:
        # Already in an event loop — use a new thread
        import concurrent.futures
        with concurrent.futures.ThreadPoolExecutor(max_workers=1) as ex:
            future = ex.submit(asyncio.run, agent.scan(session_id=session_id))
            return future.result(timeout=120)
