"""
Traffic Replay Engine
=====================
Replay captured HTTP requests with optional modifications.

Features:
  - Replay original request verbatim
  - Override any field: method, URL, headers, body, query params
  - Parameter fuzzing (auto-generate value variations)
  - Response analysis: reflection detection, status changes, error messages, data leakage
  - Diff comparison between original and replayed response
  - Proxy routing support
  - Full capture of replay requests into traffic DB

CLI:
    oneinfinity replay-request <request_id>
    oneinfinity replay-request <request_id> --param user_id --fuzz
    oneinfinity replay-request <request_id> --body '{"id": 999}'
"""

from __future__ import annotations

import difflib
import json
import logging
import re
import time
import urllib.request
import urllib.error
import urllib.parse
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any, Dict, Generator, List, Optional, Tuple

from oneinfinity.scan.traffic_capture_engine import CapturedRequest, traffic_capture_engine

log = logging.getLogger("oneinfinity.replay")


# ─────────────────────────────────────────────────────────────────────────────
#  Response analysis patterns
# ─────────────────────────────────────────────────────────────────────────────

_REFLECTION_PATTERNS = [
    r"<script[^>]*>",
    r"alert\s*\(",
    r"onerror\s*=",
    r"javascript:",
    r"on\w+\s*=",
    r"\beval\s*\(",
]

_ERROR_PATTERNS = [
    (r"SQL syntax|ORA-\d+|mysql_fetch|pg_query|SQLite3::", "sql_error"),
    (r"stack trace|traceback|exception in thread", "stack_trace"),
    (r"undefined (variable|index|method)|notice:|warning:", "php_error"),
    (r"Internal Server Error|500 Internal", "server_error"),
    (r"access denied|permission denied|forbidden", "access_control"),
    (r"(api_key|secret|token|password)\s*[=:]\s*['\"]?[a-z0-9\-_]{8,}", "credential_leak"),
]

_SENSITIVE_PATTERNS = [
    (r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b", "email"),
    (r"\b\d{4}[- ]?\d{4}[- ]?\d{4}[- ]?\d{4}\b", "credit_card"),
    (r"(?:AKIA|ASIA)[A-Z0-9]{16}", "aws_key"),
    (r"eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+", "jwt_token"),
    (r"\b\d{3}-\d{2}-\d{4}\b", "ssn"),
]

_COMPILED_REFLECT = [re.compile(p, re.IGNORECASE) for p in _REFLECTION_PATTERNS]
_COMPILED_ERRORS = [(re.compile(p, re.IGNORECASE), t) for p, t in _ERROR_PATTERNS]
_COMPILED_SENSITIVE = [(re.compile(p), t) for p, t in _SENSITIVE_PATTERNS]


# ─────────────────────────────────────────────────────────────────────────────
#  Fuzzing helpers
# ─────────────────────────────────────────────────────────────────────────────

def _fuzz_integer(val: str) -> List[str]:
    """Generate integer fuzzing variations."""
    try:
        n = int(val)
        return [
            str(n + 1), str(n - 1), str(n + 100), str(0), str(-1),
            str(2**31 - 1), str(2**31), str(-2**31), "null", "undefined",
            "' OR 1=1--", "1; DROP TABLE users--", f"{n}' OR '1'='1",
        ]
    except ValueError:
        return _fuzz_string(val)


def _fuzz_string(val: str) -> List[str]:
    """Generate string fuzzing variations."""
    base = [
        "",
        "' OR '1'='1",
        "\" OR \"1\"=\"1",
        "<script>alert(1)</script>",
        "{{7*7}}",
        "${7*7}",
        "../../etc/passwd",
        "%00",
        "admin",
        "' UNION SELECT null--",
        val + "'",
        val * 100,
        "../" * 5,
    ]
    return base


def _fuzz_param(name: str, value: str) -> List[Tuple[str, str]]:
    """Return list of (name, fuzzed_value) pairs."""
    fuzzed = _fuzz_integer(value) if value.strip().lstrip("-").isdigit() else _fuzz_string(value)
    return [(name, v) for v in fuzzed]


def _inject_param_into_url(url: str, param: str, value: str) -> str:
    """Replace or add a query parameter in a URL."""
    parsed = urllib.parse.urlparse(url)
    qs = urllib.parse.parse_qs(parsed.query, keep_blank_values=True)
    qs[param] = [value]
    new_query = urllib.parse.urlencode(qs, doseq=True)
    return urllib.parse.urlunparse(parsed._replace(query=new_query))


def _inject_param_into_body(body: str, param: str, value: str) -> str:
    """Replace a parameter in JSON or form-encoded body."""
    # Try JSON
    try:
        data = json.loads(body)
        if isinstance(data, dict):
            data[param] = value
            return json.dumps(data)
    except Exception:
        pass
    # Try form-encoded
    try:
        qs = urllib.parse.parse_qs(body, keep_blank_values=True)
        qs[param] = [value]
        return urllib.parse.urlencode(qs, doseq=True)
    except Exception:
        pass
    return body


# ─────────────────────────────────────────────────────────────────────────────
#  Replay result
# ─────────────────────────────────────────────────────────────────────────────

@dataclass
class ReplayResult:
    request_id: str             = ""
    original_status: int        = 0
    replayed_status: int        = 0
    original_body_len: int      = 0
    replayed_body_len: int      = 0
    response_body: str          = ""
    response_headers: Dict      = field(default_factory=dict)
    duration_ms: int            = 0
    diff: str                   = ""

    # Analysis
    reflections_found: List[str]    = field(default_factory=list)
    errors_found: List[Tuple[str,str]] = field(default_factory=list)
    sensitive_data: List[Tuple[str,str]] = field(default_factory=list)
    status_changed: bool            = False
    size_changed: bool              = False
    suspicious: bool                = False
    flags: List[str]                = field(default_factory=list)

    # Fuzz
    fuzz_param: str             = ""
    fuzz_value: str             = ""

    # Captured request id
    captured_id: str            = ""

    def print_summary(self) -> None:
        print(f"\n{'─'*60}")
        print(f"  Replay Result: {self.request_id}")
        print(f"  Status: {self.original_status} → {self.replayed_status}  {'⚠ CHANGED' if self.status_changed else ''}")
        print(f"  Body size: {self.original_body_len}B → {self.replayed_body_len}B  {'⚠ CHANGED' if self.size_changed else ''}")
        print(f"  Duration: {self.duration_ms}ms")
        if self.reflections_found:
            print(f"  [!] Reflections: {', '.join(self.reflections_found)}")
        if self.errors_found:
            print(f"  [!] Errors: {', '.join(f'{t}:{m[:40]}' for m, t in self.errors_found)}")
        if self.sensitive_data:
            print(f"  [!] Sensitive: {', '.join(t for _, t in self.sensitive_data)}")
        if self.flags:
            print(f"  [!] Flags: {', '.join(self.flags)}")
        if self.suspicious:
            print(f"  [!!] SUSPICIOUS RESPONSE")
        print(f"{'─'*60}\n")


# ─────────────────────────────────────────────────────────────────────────────
#  Traffic Replay Engine
# ─────────────────────────────────────────────────────────────────────────────

class TrafficReplayEngine:
    """
    Replay captured HTTP requests with optional modifications and analysis.
    """

    def __init__(self) -> None:
        self._timeout = 30

    # ── Single replay ─────────────────────────────────────────────────────────

    def replay(
        self,
        request_id: str,
        *,
        method: Optional[str] = None,
        url: Optional[str] = None,
        headers: Optional[Dict[str, str]] = None,
        body: Optional[str] = None,
        params: Optional[Dict[str, str]] = None,   # query param overrides
        use_proxy: bool = True,
        timeout: int = 30,
        source_tag: str = "replay",
    ) -> ReplayResult:
        """
        Load a captured request and replay it with optional overrides.
        """
        original = traffic_capture_engine.get(request_id)
        if not original:
            raise ValueError(f"Request {request_id!r} not found in traffic DB")

        # Apply overrides
        replay_method  = (method or original.method).upper()
        replay_url     = url or original.url
        replay_headers = {**original.headers, **(headers or {})}
        replay_body    = body if body is not None else original.body

        # Apply query param overrides
        if params:
            for k, v in params.items():
                replay_url = _inject_param_into_url(replay_url, k, v)

        result = self._send(
            method=replay_method,
            url=replay_url,
            headers=replay_headers,
            body=replay_body,
            original=original,
            use_proxy=use_proxy,
            timeout=timeout,
            source_tag=source_tag,
        )
        result.print_summary()
        return result

    # ── Fuzzing ───────────────────────────────────────────────────────────────

    def fuzz_param(
        self,
        request_id: str,
        param: str,
        custom_values: Optional[List[str]] = None,
        use_proxy: bool = True,
        timeout: int = 30,
    ) -> List[ReplayResult]:
        """
        Fuzz a specific parameter in a captured request.
        Returns list of ReplayResult for each fuzz value.
        """
        original = traffic_capture_engine.get(request_id)
        if not original:
            raise ValueError(f"Request {request_id!r} not found")

        # Determine original value for parameter
        qs = urllib.parse.parse_qs(urllib.parse.urlparse(original.url).query)
        orig_val = qs.get(param, [""])[0]
        if not orig_val:
            # Try body
            try:
                bd = json.loads(original.body)
                orig_val = str(bd.get(param, ""))
            except Exception:
                pass

        fuzz_values = custom_values or [v for _, v in _fuzz_param(param, orig_val)]
        results = []

        print(f"\n[*] Fuzzing param '{param}' with {len(fuzz_values)} values on {original.url}")
        for val in fuzz_values:
            # Try URL first, then body
            parsed = urllib.parse.urlparse(original.url)
            qs_dict = urllib.parse.parse_qs(parsed.query, keep_blank_values=True)

            fuzz_url = original.url
            fuzz_body = original.body

            if param in qs_dict:
                fuzz_url = _inject_param_into_url(original.url, param, val)
            else:
                fuzz_body = _inject_param_into_body(original.body, param, val)

            result = self._send(
                method=original.method,
                url=fuzz_url,
                headers=original.headers,
                body=fuzz_body,
                original=original,
                use_proxy=use_proxy,
                timeout=timeout,
                source_tag="fuzz",
            )
            result.fuzz_param = param
            result.fuzz_value = val
            results.append(result)

            indicator = "⚠" if result.suspicious else "·"
            print(f"  {indicator} [{result.replayed_status}] {param}={val[:40]!r:40} | "
                  f"{result.replayed_body_len}B | {result.duration_ms}ms"
                  + (f" | {', '.join(result.flags)}" if result.flags else ""))

        return results

    # ── Generator for streaming fuzz results ─────────────────────────────────

    def fuzz_stream(
        self,
        request_id: str,
        param: str,
        custom_values: Optional[List[str]] = None,
        use_proxy: bool = True,
    ) -> Generator[ReplayResult, None, None]:
        """Yield replay results one at a time for streaming to UI."""
        original = traffic_capture_engine.get(request_id)
        if not original:
            return
        qs = urllib.parse.parse_qs(urllib.parse.urlparse(original.url).query)
        orig_val = qs.get(param, [""])[0]
        values = custom_values or [v for _, v in _fuzz_param(param, orig_val)]
        for val in values:
            fuzz_url = _inject_param_into_url(original.url, param, val) \
                if param in qs else original.url
            fuzz_body = _inject_param_into_body(original.body, param, val) \
                if param not in qs else original.body
            yield self._send(
                method=original.method, url=fuzz_url,
                headers=original.headers, body=fuzz_body,
                original=original, use_proxy=use_proxy, timeout=20,
                source_tag="fuzz_stream",
                fuzz_param=param, fuzz_value=val,
            )

    # ── HTTP sender ───────────────────────────────────────────────────────────

    def _send(
        self,
        method: str,
        url: str,
        headers: Dict[str, str],
        body: str,
        original: CapturedRequest,
        use_proxy: bool,
        timeout: int,
        source_tag: str,
        fuzz_param: str = "",
        fuzz_value: str = "",
    ) -> ReplayResult:
        import ssl
        from oneinfinity.infra.proxy_manager import proxy_manager, ProxyScope

        # Build request
        data = body.encode("utf-8") if body else None
        req = urllib.request.Request(url, data=data, method=method)
        for k, v in headers.items():
            if k.lower() not in ("content-length", "host"):
                try:
                    req.add_header(k, v)
                except Exception:
                    pass

        t0 = time.time()
        status = 0
        resp_body = ""
        resp_headers: Dict[str, str] = {}

        try:
            if use_proxy and proxy_manager.is_active:
                status, resp_body, resp_headers = proxy_manager.make_request(
                    req, timeout=timeout, scope=ProxyScope.SCAN, capture_tag=source_tag
                )
            else:
                ctx = ssl.create_default_context()
                ctx.check_hostname = False
                ctx.verify_mode = ssl.CERT_NONE
                opener = urllib.request.build_opener(urllib.request.HTTPSHandler(context=ctx))
                with opener.open(req, timeout=timeout) as resp:
                    status = resp.getcode()
                    resp_body = resp.read(1 << 20).decode("utf-8", errors="ignore")
                    resp_headers = dict(resp.headers)
        except urllib.error.HTTPError as exc:
            status = exc.code
            try:
                resp_body = exc.read(4096).decode("utf-8", errors="ignore")
            except Exception:
                pass
            resp_headers = dict(exc.headers) if exc.headers else {}
        except Exception as exc:
            resp_body = f"[error] {exc}"
            status = 0

        duration = int((time.time() - t0) * 1000)

        # Build result
        result = ReplayResult(
            request_id=original.id,
            original_status=original.response_status,
            replayed_status=status,
            original_body_len=len(original.response_body),
            replayed_body_len=len(resp_body),
            response_body=resp_body,
            response_headers=resp_headers,
            duration_ms=duration,
            fuzz_param=fuzz_param,
            fuzz_value=fuzz_value,
        )

        # Diff
        if original.response_body and resp_body:
            diff_lines = list(difflib.unified_diff(
                original.response_body[:3000].splitlines(),
                resp_body[:3000].splitlines(),
                lineterm="", n=2,
            ))
            result.diff = "\n".join(diff_lines[:100])

        result.status_changed = (status != original.response_status)
        result.size_changed   = abs(len(resp_body) - len(original.response_body)) > 50

        # Analysis
        self._analyze(result, resp_body)

        # Store replay in traffic DB
        if not (use_proxy and proxy_manager.is_active):
            captured = traffic_capture_engine.capture(
                method=method, url=url, headers=headers, body=body,
                response_status=status, response_headers=resp_headers,
                response_body=resp_body, source=source_tag,
                duration_ms=duration, tags=["replay"],
            )
            result.captured_id = captured.id

        return result

    # ── Response analysis ─────────────────────────────────────────────────────

    def _analyze(self, result: ReplayResult, body: str) -> None:
        # Reflections
        for pat in _COMPILED_REFLECT:
            m = pat.search(body)
            if m:
                result.reflections_found.append(m.group()[:60])
                result.flags.append("reflection")

        # Error messages
        for pat, etype in _COMPILED_ERRORS:
            m = pat.search(body)
            if m:
                result.errors_found.append((m.group()[:80], etype))
                result.flags.append(etype)

        # Sensitive data
        for pat, dtype in _COMPILED_SENSITIVE:
            m = pat.search(body)
            if m:
                result.sensitive_data.append((m.group()[:40], dtype))
                result.flags.append(f"leak:{dtype}")

        # Status changes
        if result.status_changed:
            result.flags.append(f"status:{result.original_status}→{result.replayed_status}")

        result.suspicious = bool(
            result.reflections_found or
            result.errors_found or
            result.sensitive_data or
            result.status_changed
        )

        if result.suspicious:
            # Flag in DB
            try:
                traffic_capture_engine.flag(result.request_id, ", ".join(result.flags))
            except Exception:
                pass


# ─────────────────────────────────────────────────────────────────────────────
#  Global singleton
# ─────────────────────────────────────────────────────────────────────────────

traffic_replay_engine = TrafficReplayEngine()
