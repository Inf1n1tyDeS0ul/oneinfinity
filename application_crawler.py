"""
Application Crawler — Discover pages, forms, inputs, API calls, auth flows
"""
from __future__ import annotations

import re
import json
import time
import logging
import urllib.request
import urllib.parse
import urllib.error
import urllib.robotparser
import html.parser
from dataclasses import dataclass, field
from typing import Optional, Any
from collections import deque

logger = logging.getLogger(__name__)


# ── Data models ───────────────────────────────────────────────────────────────

@dataclass
class FormField:
    """A single field within an HTML form."""
    name: str
    field_type: str          # text | password | hidden | select | textarea | email | file | etc.
    value: str = ""
    required: bool = False

    def to_dict(self) -> dict:
        return {
            "name": self.name,
            "field_type": self.field_type,
            "value": self.value,
            "required": self.required,
        }


@dataclass
class PageForm:
    """An HTML form extracted from a page."""
    action: str
    method: str              # GET | POST
    fields: list[FormField] = field(default_factory=list)
    has_csrf_token: bool = False
    has_file_upload: bool = False

    def to_dict(self) -> dict:
        return {
            "action": self.action,
            "method": self.method,
            "fields": [f.to_dict() for f in self.fields],
            "has_csrf_token": self.has_csrf_token,
            "has_file_upload": self.has_file_upload,
        }


@dataclass
class APICall:
    """An API call pattern detected in JavaScript or HTML."""
    url: str
    method: str                          # GET | POST | PUT | DELETE | PATCH | unknown
    headers_observed: list[str] = field(default_factory=list)
    body_type: str = "unknown"           # json | form | multipart | unknown
    auth_required: bool = False

    def to_dict(self) -> dict:
        return {
            "url": self.url,
            "method": self.method,
            "headers_observed": self.headers_observed,
            "body_type": self.body_type,
            "auth_required": self.auth_required,
        }


@dataclass
class CrawlPage:
    """Represents one crawled page and its metadata."""
    url: str
    title: str
    status_code: int
    forms: list[PageForm] = field(default_factory=list)
    links: list[str] = field(default_factory=list)
    api_calls: list[APICall] = field(default_factory=list)
    scripts: list[str] = field(default_factory=list)      # script src URLs
    has_login_form: bool = False
    has_search_form: bool = False
    is_admin_page: bool = False

    def to_dict(self) -> dict:
        return {
            "url": self.url,
            "title": self.title,
            "status_code": self.status_code,
            "forms": [f.to_dict() for f in self.forms],
            "links": self.links,
            "api_calls": [a.to_dict() for a in self.api_calls],
            "scripts": self.scripts,
            "has_login_form": self.has_login_form,
            "has_search_form": self.has_search_form,
            "is_admin_page": self.is_admin_page,
        }


@dataclass
class CrawlResult:
    """Aggregated result of a full crawl."""
    target: str
    total_pages: int
    pages: list[CrawlPage] = field(default_factory=list)
    all_forms: list[PageForm] = field(default_factory=list)
    all_endpoints: list[str] = field(default_factory=list)
    auth_pages: list[str] = field(default_factory=list)
    admin_pages: list[str] = field(default_factory=list)

    def to_dict(self) -> dict:
        return {
            "target": self.target,
            "total_pages": self.total_pages,
            "pages": [p.to_dict() for p in self.pages],
            "all_forms": [f.to_dict() for f in self.all_forms],
            "all_endpoints": self.all_endpoints,
            "auth_pages": self.auth_pages,
            "admin_pages": self.admin_pages,
        }


# ── HTML parser ───────────────────────────────────────────────────────────────

class HTMLFormParser(html.parser.HTMLParser):
    """
    Custom SAX-style HTML parser that extracts forms, input fields,
    links, script tags, and page title in a single pass.
    """

    def __init__(self, base_url: str = "") -> None:
        super().__init__(convert_charrefs=True)
        self.base_url = base_url

        self.forms: list[dict] = []
        self.links: list[str] = []
        self.scripts: list[str] = []
        self.title: str = ""
        self.inline_scripts: list[str] = []

        self._current_form: Optional[dict] = None
        self._in_title = False
        self._in_script = False
        self._script_content: list[str] = []
        self._select_name: str = ""
        self._in_select = False

    # -- HTMLParser overrides

    def handle_starttag(self, tag: str, attrs: list[tuple[str, Optional[str]]]) -> None:
        a = dict(attrs)

        if tag == "form":
            self._current_form = {
                "action": a.get("action", ""),
                "method": (a.get("method") or "GET").upper(),
                "fields": [],
                "enctype": a.get("enctype", ""),
            }

        elif tag in ("input", "textarea", "select") and self._current_form is not None:
            name = a.get("name") or a.get("id") or ""
            if not name:
                return

            if tag == "input":
                ftype = (a.get("type") or "text").lower()
            elif tag == "textarea":
                ftype = "textarea"
            else:  # select
                ftype = "select"
                self._select_name = name
                self._in_select = True

            required = "required" in a or a.get("required") is not None
            value = a.get("value", "")
            self._current_form["fields"].append({
                "name": name,
                "field_type": ftype,
                "value": value,
                "required": required,
            })

        elif tag == "a":
            href = a.get("href", "")
            if href and not href.startswith(("#", "javascript:", "mailto:", "tel:")):
                full = urllib.parse.urljoin(self.base_url, href)
                self.links.append(full)

        elif tag == "script":
            src = a.get("src", "")
            if src:
                full_src = urllib.parse.urljoin(self.base_url, src)
                self.scripts.append(full_src)
            self._in_script = True
            self._script_content = []

        elif tag == "title":
            self._in_title = True

        elif tag == "base":
            href = a.get("href", "")
            if href:
                self.base_url = href

    def handle_endtag(self, tag: str) -> None:
        if tag == "form" and self._current_form is not None:
            self.forms.append(self._current_form)
            self._current_form = None

        elif tag == "select":
            self._in_select = False
            self._select_name = ""

        elif tag == "script":
            if self._script_content:
                self.inline_scripts.append("".join(self._script_content))
            self._in_script = False
            self._script_content = []

        elif tag == "title":
            self._in_title = False

    def handle_data(self, data: str) -> None:
        if self._in_title:
            self.title += data.strip()
        if self._in_script:
            self._script_content.append(data)

    # -- Helper

    def get_parsed(self) -> dict:
        return {
            "forms": self.forms,
            "links": self.links,
            "scripts": self.scripts,
            "title": self.title,
            "inline_scripts": self.inline_scripts,
        }


# ── Crawler ───────────────────────────────────────────────────────────────────

_CSRF_FIELD_NAMES = {
    "csrf", "csrf_token", "_token", "csrfmiddlewaretoken",
    "authenticity_token", "xsrf", "_csrf", "__requestverificationtoken",
    "nonce", "_wpnonce",
}

_LOGIN_KEYWORDS = {
    "login", "log in", "sign in", "signin", "authenticate",
    "username", "password", "forgot password", "remember me", "log-in",
}

_SEARCH_KEYWORDS = {
    "search", "q=", "query", "find", "lookup", "s=",
}

_ADMIN_URL_PATTERNS = [
    r"/admin", r"/administrator", r"/manage", r"/management",
    r"/backend", r"/cp", r"/controlpanel", r"/dashboard",
    r"/cms", r"/staff", r"/superuser", r"/root",
]

_LOGIN_URL_PATTERNS = [
    r"/login", r"/signin", r"/sign-in", r"/log-in",
    r"/auth", r"/authenticate", r"/account/login", r"/user/login",
    r"/session/new", r"/wp-login",
]

_API_CALL_PATTERNS = [
    # fetch()
    (r"""fetch\s*\(\s*['"]((?:https?://[^'"]+|/[^'"]+))['"]\s*(?:,\s*\{[^}]*method\s*:\s*['"](GET|POST|PUT|DELETE|PATCH|HEAD)['"]\s*)?""",
     "fetch"),
    # axios.get/post/put/delete/patch/request
    (r"""axios\.(?:get|post|put|delete|patch|request)\s*\(\s*['"]((?:https?://[^'"]+|/[^'"]+))['"]\s*""",
     "axios"),
    # $.ajax({ url: ... })
    (r"""\$\.ajax\s*\(\s*\{[^}]*url\s*:\s*['"]((?:https?://[^'"]+|/[^'"]+))['"]\s*""",
     "jquery_ajax"),
    # $.get / $.post
    (r"""\$\.(get|post)\s*\(\s*['"]((?:https?://[^'"]+|/[^'"]+))['"]\s*""",
     "jquery_get_post"),
    # XMLHttpRequest open
    (r"""\.open\s*\(\s*['"](GET|POST|PUT|DELETE|PATCH)['"]\s*,\s*['"]((?:https?://[^'"]+|/[^'"]+))['"]\s*""",
     "xhr"),
]


class ApplicationCrawler:
    """
    Crawls a web application to map pages, forms, API calls, and auth/admin surfaces.
    Uses only stdlib (urllib) — no third-party dependencies required.
    """

    def __init__(self, request_delay: float = 0.5, timeout: int = 15) -> None:
        self.request_delay = request_delay
        self.timeout = timeout
        self._user_agent = (
            "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 "
            "(KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36 BountyBot/1.0"
        )

    # ── Public API ────────────────────────────────────────────────────────────

    def crawl(
        self,
        target: str,
        max_pages: int = 100,
        max_depth: int = 5,
        auth_cookies: Optional[dict] = None,
    ) -> CrawlResult:
        """
        BFS crawl of `target`.  Returns a CrawlResult with all discovered pages,
        forms, API endpoints, auth pages, and admin pages.
        """
        if not target.startswith("http"):
            target = f"https://{target}"

        parsed_target = urllib.parse.urlparse(target)
        base_origin = f"{parsed_target.scheme}://{parsed_target.netloc}"

        # Load robots.txt (optional — we note disallowed paths but do not error)
        disallowed = self._load_robots(base_origin)

        visited: set[str] = set()
        crawl_pages: list[CrawlPage] = []
        all_forms: list[PageForm] = []
        all_endpoints: list[str] = []
        auth_pages: list[str] = []
        admin_pages: list[str] = []

        # BFS queue: (url, depth)
        queue: deque[tuple[str, int]] = deque()
        queue.append((self._normalize_url(target), 0))

        cookie_header = self._build_cookie_header(auth_cookies or {})

        while queue and len(visited) < max_pages:
            url, depth = queue.popleft()

            # Skip already-visited or out-of-scope URLs
            if url in visited:
                continue
            if not self._is_in_scope(url, target):
                continue
            if depth > max_depth:
                continue

            # Respect robots.txt (soft — just log, do not hard-fail)
            url_path = urllib.parse.urlparse(url).path
            if any(url_path.startswith(d) for d in disallowed):
                logger.debug("Skipping robots.txt disallowed: %s", url)
                visited.add(url)
                continue

            visited.add(url)
            logger.debug("Crawling [depth=%d]: %s", depth, url)

            html, status, headers = self._fetch_page(url, cookies=cookie_header)
            if not html and status == 0:
                time.sleep(self.request_delay)
                continue

            all_endpoints.append(url)

            page = self._build_crawl_page(url, html, status)
            crawl_pages.append(page)

            # Accumulate forms and API calls
            all_forms.extend(page.forms)

            # Categorise page
            if page.has_login_form or self._url_matches_patterns(url, _LOGIN_URL_PATTERNS):
                if url not in auth_pages:
                    auth_pages.append(url)
            if page.is_admin_page or self._url_matches_patterns(url, _ADMIN_URL_PATTERNS):
                if url not in admin_pages:
                    admin_pages.append(url)

            # Enqueue discovered links
            for link in page.links:
                norm = self._normalize_url(link)
                if norm not in visited and self._is_in_scope(norm, target):
                    queue.append((norm, depth + 1))

            # Fetch and parse linked JS files for more API calls (limit to 5 per page)
            for script_url in page.scripts[:5]:
                if not self._is_in_scope(script_url, target):
                    continue
                js_html, js_status, _ = self._fetch_page(script_url)
                if js_html:
                    api_calls = self._extract_api_calls("", js_html)
                    page.api_calls.extend(api_calls)

            time.sleep(self.request_delay)

        result = CrawlResult(
            target=target,
            total_pages=len(crawl_pages),
            pages=crawl_pages,
            all_forms=all_forms,
            all_endpoints=list(dict.fromkeys(all_endpoints)),
            auth_pages=list(dict.fromkeys(auth_pages)),
            admin_pages=list(dict.fromkeys(admin_pages)),
        )
        logger.info(
            "Crawl complete: %d pages, %d forms, %d endpoints, %d auth pages, %d admin pages",
            result.total_pages, len(result.all_forms),
            len(result.all_endpoints), len(result.auth_pages), len(result.admin_pages),
        )
        return result

    def get_attack_surface(self, result: CrawlResult) -> dict:
        """
        Summarise the attack surface derived from a CrawlResult.
        """
        file_upload_forms = [
            f.to_dict() for f in result.all_forms if f.has_file_upload
        ]
        api_endpoints: list[str] = []
        for page in result.pages:
            for call in page.api_calls:
                if call.url not in api_endpoints:
                    api_endpoints.append(call.url)

        # Collect unique form actions (endpoints that accept POST/GET via forms)
        form_endpoints = list({f.action for f in result.all_forms})

        return {
            "forms_count": len(result.all_forms),
            "endpoints_count": len(result.all_endpoints),
            "login_pages": result.auth_pages,
            "admin_pages": result.admin_pages,
            "file_upload_forms": file_upload_forms,
            "api_endpoints": api_endpoints,
            "form_endpoints": form_endpoints,
            "total_pages_crawled": result.total_pages,
        }

    # ── Internal helpers ──────────────────────────────────────────────────────

    def _normalize_url(self, url: str, base: str = "") -> str:
        """
        Resolve relative URLs against base, strip fragment, sort query params
        for deduplication.
        """
        if base:
            url = urllib.parse.urljoin(base, url)

        try:
            p = urllib.parse.urlparse(url)
            # Drop fragment
            p = p._replace(fragment="")
            # Sort query params for canonical form
            if p.query:
                qs = urllib.parse.parse_qsl(p.query, keep_blank_values=True)
                qs_sorted = sorted(qs, key=lambda kv: kv[0])
                p = p._replace(query=urllib.parse.urlencode(qs_sorted))
            # Strip trailing slash from path (except root)
            path = p.path.rstrip("/") or "/"
            p = p._replace(path=path)
            return urllib.parse.urlunparse(p)
        except Exception:
            return url

    def _is_in_scope(self, url: str, target: str) -> bool:
        """Return True if url is on the same host (and optional port) as target."""
        try:
            t = urllib.parse.urlparse(target)
            u = urllib.parse.urlparse(url)
            return (
                u.scheme in ("http", "https")
                and u.netloc.lower() == t.netloc.lower()
            )
        except Exception:
            return False

    def _fetch_page(
        self, url: str, cookies: str = ""
    ) -> tuple[str, int, dict]:
        """
        Fetch a URL with urllib.  Returns (html, status_code, headers).
        Returns ("", 0, {}) on network error.
        """
        try:
            headers: dict[str, str] = {
                "User-Agent": self._user_agent,
                "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
                "Accept-Language": "en-US,en;q=0.5",
                "Accept-Encoding": "identity",  # avoid gzip to keep simple
            }
            if cookies:
                headers["Cookie"] = cookies

            req = urllib.request.Request(url, headers=headers)
            with urllib.request.urlopen(req, timeout=self.timeout) as resp:
                raw = resp.read(5 * 1024 * 1024)  # max 5 MB
                enc = resp.headers.get_content_charset("utf-8")
                try:
                    html = raw.decode(enc, errors="replace")
                except (LookupError, TypeError):
                    html = raw.decode("utf-8", errors="replace")
                return html, resp.status, dict(resp.headers)
        except urllib.error.HTTPError as exc:
            try:
                html = exc.read(1024 * 512).decode("utf-8", errors="replace")
            except Exception:
                html = ""
            return html, exc.code, {}
        except urllib.error.URLError as exc:
            logger.debug("URLError fetching %s: %s", url, exc.reason)
            return "", 0, {}
        except Exception as exc:
            logger.debug("_fetch_page error for %s: %s", url, exc)
            return "", 0, {}

    def _extract_links(self, base_url: str, html: str) -> list[str]:
        """Extract all in-scope anchor hrefs from HTML."""
        links: list[str] = []
        for m in re.finditer(
            r'<a[^>]+href=["\']([^"\'#][^"\']*)["\']', html, re.IGNORECASE
        ):
            href = m.group(1).strip()
            if href.startswith(("mailto:", "tel:", "javascript:")):
                continue
            full = urllib.parse.urljoin(base_url, href)
            links.append(full)
        return links

    def _extract_forms(self, base_url: str, html: str) -> list[PageForm]:
        """
        Parse all <form> elements from HTML.  Returns list of PageForm.
        Uses HTMLFormParser for accurate field extraction.
        """
        parser = HTMLFormParser(base_url=base_url)
        try:
            parser.feed(html)
        except Exception as exc:
            logger.debug("HTMLFormParser error: %s", exc)

        page_forms: list[PageForm] = []
        for raw_form in parser.forms:
            raw_action = raw_form.get("action", "")
            action = urllib.parse.urljoin(base_url, raw_action) if raw_action else base_url
            method = (raw_form.get("method") or "GET").upper()
            enctype = raw_form.get("enctype", "")

            fields: list[FormField] = []
            has_csrf = False
            has_file = bool(re.search(r"multipart", enctype, re.IGNORECASE))

            for f in raw_form.get("fields", []):
                fname = f.get("name", "")
                ftype = f.get("field_type", "text")
                fval = f.get("value", "")
                freq = bool(f.get("required", False))

                if ftype == "file":
                    has_file = True

                # CSRF detection
                if fname.lower() in _CSRF_FIELD_NAMES:
                    has_csrf = True

                fields.append(FormField(
                    name=fname,
                    field_type=ftype,
                    value=fval,
                    required=freq,
                ))

            # Also check HTML for CSRF meta / hidden fields we may have missed
            if not has_csrf:
                has_csrf = bool(
                    re.search(r'csrf[_-]?token', html, re.IGNORECASE)
                    and method == "POST"
                )

            page_forms.append(PageForm(
                action=action,
                method=method,
                fields=fields,
                has_csrf_token=has_csrf,
                has_file_upload=has_file,
            ))

        return page_forms

    def _extract_api_calls(self, html: str, js_content: str) -> list[APICall]:
        """
        Extract API call patterns from inline JS within HTML or a JS file body.
        Detects fetch(), axios, $.ajax(), $.get/post, and XMLHttpRequest.open().
        """
        combined = (html or "") + "\n" + (js_content or "")
        calls: list[APICall] = []
        seen_urls: set[str] = set()

        for pattern, kind in _API_CALL_PATTERNS:
            for m in re.finditer(pattern, combined, re.IGNORECASE | re.DOTALL):
                groups = m.groups()

                if kind == "xhr":
                    # groups = (method, url)
                    method = groups[0].upper() if groups[0] else "GET"
                    url = groups[1] if len(groups) > 1 else ""
                elif kind == "jquery_get_post":
                    # groups = (get|post, url)
                    method = groups[0].upper() if groups[0] else "GET"
                    url = groups[1] if len(groups) > 1 else ""
                else:
                    # groups = (url, optional_method)
                    url = groups[0] if groups else ""
                    method_raw = groups[1] if len(groups) > 1 and groups[1] else ""
                    method = method_raw.upper() if method_raw else "GET"

                if not url or url in seen_urls:
                    continue
                seen_urls.add(url)

                # Detect auth headers
                auth_required = bool(
                    re.search(r'Authorization|Bearer|X-Auth|X-API-Key|api.key|token', combined, re.IGNORECASE)
                )
                # Detect body type
                if re.search(r'Content-Type.*application/json|JSON\.stringify|json\s*:', combined[:5000], re.IGNORECASE):
                    body_type = "json"
                elif re.search(r'FormData|multipart', combined[:5000], re.IGNORECASE):
                    body_type = "multipart"
                elif re.search(r'application/x-www-form-urlencoded', combined[:5000], re.IGNORECASE):
                    body_type = "form"
                else:
                    body_type = "unknown"

                calls.append(APICall(
                    url=url,
                    method=method,
                    headers_observed=[],
                    body_type=body_type,
                    auth_required=auth_required,
                ))

        return calls

    def _detect_page_type(self, url: str, html: str, title: str) -> dict[str, bool]:
        """
        Classify a page as login, admin, search, etc. based on URL patterns,
        HTML content, and title keywords.
        """
        lower_html = html.lower() if html else ""
        lower_title = title.lower() if title else ""
        lower_url = url.lower()

        has_login_form = False
        has_search_form = False
        is_admin_page = False

        # Admin detection: URL pattern OR page content
        if self._url_matches_patterns(url, _ADMIN_URL_PATTERNS):
            is_admin_page = True
        if any(kw in lower_title for kw in ["admin", "administrator", "management", "control panel"]):
            is_admin_page = True
        if lower_html.count("admin") > 5:
            is_admin_page = True

        # Login form: page has password field
        if re.search(r'<input[^>]+type=["\']password["\']', html, re.IGNORECASE):
            has_login_form = True
        if self._url_matches_patterns(url, _LOGIN_URL_PATTERNS):
            has_login_form = True
        if any(kw in lower_title for kw in ["login", "sign in", "log in", "authenticate"]):
            has_login_form = True

        # Search form: form has a field named q, s, query, search
        search_field_pat = r'<input[^>]+name=["\'](?:q|s|query|search|keyword|term)["\']'
        if re.search(search_field_pat, html, re.IGNORECASE):
            has_search_form = True

        return {
            "has_login_form": has_login_form,
            "has_search_form": has_search_form,
            "is_admin_page": is_admin_page,
        }

    def _build_crawl_page(self, url: str, html: str, status: int) -> CrawlPage:
        """Assemble a CrawlPage from raw HTML and page metadata."""
        # Use HTMLFormParser for links, forms, scripts, title in one pass
        parser = HTMLFormParser(base_url=url)
        try:
            parser.feed(html or "")
        except Exception as exc:
            logger.debug("Parser error on %s: %s", url, exc)

        parsed = parser.get_parsed()
        title = parsed["title"] or self._extract_title_regex(html or "")

        # Filter links to valid http(s) URLs
        links = [
            self._normalize_url(lnk)
            for lnk in parsed["links"]
            if lnk.startswith("http")
        ]

        forms = self._extract_forms(url, html or "")

        # Combine inline scripts into one block for API extraction
        inline_js = "\n".join(parsed["inline_scripts"])
        api_calls = self._extract_api_calls(html or "", inline_js)

        page_type = self._detect_page_type(url, html or "", title)

        return CrawlPage(
            url=url,
            title=title,
            status_code=status,
            forms=forms,
            links=links,
            api_calls=api_calls,
            scripts=parsed["scripts"],
            has_login_form=page_type["has_login_form"],
            has_search_form=page_type["has_search_form"],
            is_admin_page=page_type["is_admin_page"],
        )

    # ── Utility methods ───────────────────────────────────────────────────────

    def _load_robots(self, base_origin: str) -> list[str]:
        """
        Fetch and parse robots.txt.  Returns list of disallowed path prefixes.
        Non-fatal: returns empty list on any error.
        """
        disallowed: list[str] = []
        try:
            robots_url = f"{base_origin}/robots.txt"
            rp = urllib.robotparser.RobotFileParser()
            rp.set_url(robots_url)
            rp.read()
            # We present ourselves as a generic crawler — respect Disallow entries
            # by building a simple disallowed prefix list
            try:
                entries = rp.entries  # type: ignore[attr-defined]
                for entry in entries:
                    for ruleline in entry.rulelines:  # type: ignore[attr-defined]
                        if not ruleline.allowance:  # type: ignore[attr-defined]
                            disallowed.append(str(ruleline.path))  # type: ignore[attr-defined]
            except AttributeError:
                pass
        except Exception as exc:
            logger.debug("robots.txt fetch failed for %s: %s", base_origin, exc)
        return disallowed

    def _build_cookie_header(self, cookies: dict) -> str:
        """Build a Cookie header string from a dict."""
        if not cookies:
            return ""
        return "; ".join(f"{k}={v}" for k, v in cookies.items())

    def _url_matches_patterns(self, url: str, patterns: list[str]) -> bool:
        """Return True if any regex pattern matches the URL path."""
        path = urllib.parse.urlparse(url).path.lower()
        return any(re.search(p, path, re.IGNORECASE) for p in patterns)

    def _extract_title_regex(self, html: str) -> str:
        """Fallback regex title extraction."""
        m = re.search(r'<title[^>]*>(.*?)</title>', html, re.IGNORECASE | re.DOTALL)
        return m.group(1).strip() if m else ""


# ── Global singleton ──────────────────────────────────────────────────────────

application_crawler = ApplicationCrawler()
