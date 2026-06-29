"""
frida_dtrace_tracer.py — macOS tracer backend (Module 1, Phase 5).

Phase-5 enhancement: full Frida session manager with process attachment,
TypeScript hook injection, event streaming, JNI tracing, heap memory
scanning, and network interception.  DTrace probes are retained for syscall
and network modes on macOS.

Conforms to TRACER_CONTRACT.md v1.0.0.

Do NOT import this module directly; use StealthTracer from stealth_tracer.py.
"""

from __future__ import annotations

import json
import logging
import pathlib
import platform
import re
import shutil
import subprocess
import tempfile
import threading
import time
import uuid
from dataclasses import dataclass, field
from queue import Empty, Queue
from typing import Callable, Dict, Iterator, List, Optional

try:
    import select as _select
    _HAS_SELECT = True
except ImportError:  # pragma: no cover
    _HAS_SELECT = False

# Frida Python bindings — optional; graceful degradation when absent
try:
    import frida  # type: ignore[import-untyped]
    _HAS_FRIDA_LIB = True
except ImportError:
    frida = None  # type: ignore[assignment]
    _HAS_FRIDA_LIB = False

log = logging.getLogger("oi.tracer")

# ── hook script paths ─────────────────────────────────────────────────────────
_HOOKS_DIST  = pathlib.Path(__file__).parent.parent.parent / "frida-hooks" / "dist"
_SSL_HOOK    = _HOOKS_DIST / "ssl_hook.js"
_CRYPTO_HOOK = _HOOKS_DIST / "crypto_extract.js"
_JNI_HOOK    = _HOOKS_DIST / "jni_trace.js"
_MEM_HOOK    = _HOOKS_DIST / "memory_scan.js"
_NET_BRIDGE  = _HOOKS_DIST / "native_bridge.js"
_CERT_BYPASS = _HOOKS_DIST / "certificate_pinning_bypass.js"
_MEM_SEARCH_HOOK = _HOOKS_DIST / "memory_search.js"
_HOOKS_SRC   = pathlib.Path(__file__).parent.parent.parent / "frida-hooks" / "src"

# ── secret patterns for in-process heap scanning ──────────────────────────────
_SECRET_PATTERNS: List[tuple[str, str]] = [
    ("jwt",              r"eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}"),
    ("aws_key",          r"AKIA[0-9A-Z]{16}"),
    ("bearer_token",     r"Bearer\s+[A-Za-z0-9\-._~+/]{20,}"),
    ("google_api",       r"AIza[0-9A-Za-z\-_]{35}"),
    ("private_key",      r"-----BEGIN (RSA |EC )?PRIVATE KEY-----"),
    ("api_key_kv",       r"(?:api_key|apikey)[=:]\s*[A-Za-z0-9_\-]{16,}"),
    # ── JWT HS256 secret: HS256 algorithm label in memory ─────────────────────
    ("jwt_hs256",        r'"alg"\s*:\s*"HS256"'),
    ("jwt_hs256_secret", r'(?:secret|signing_key|jwt_secret)[=:"\s]+[A-Za-z0-9+/=_\-]{32,}'),
    # ── bcrypt hash patterns ──────────────────────────────────────────────────
    ("bcrypt_hash",      r'\$2[aby]\$\d{2}\$[A-Za-z0-9./]{53}'),
    # ── PEM private-key headers ───────────────────────────────────────────────
    ("pem_rsa_key",      r"-----BEGIN RSA PRIVATE KEY-----"),
    ("pem_ec_key",       r"-----BEGIN EC PRIVATE KEY-----"),
    ("pem_priv_key",     r"-----BEGIN PRIVATE KEY-----"),
    ("pem_cert",         r"-----BEGIN CERTIFICATE-----"),
    # ── Android KeyStore alias names ──────────────────────────────────────────
    ("keystore_android", r"AndroidKeyStore"),
    ("keystore_alias",   r'KeyStore\.getInstance\s*\(\s*["\']AndroidKeyStore["\']'),
    ("keystore_getentry",r'getEntry\s*\(\s*["\']([^"\']{1,64})["\']'),
]
_COMPILED_PATTERNS = [(name, re.compile(pat)) for name, pat in _SECRET_PATTERNS]

# ── network libc inline script ────────────────────────────────────────────────
_NETWORK_INLINE_JS = """
'use strict';
var _connectPtr = Module.findExportByName(null, 'connect');
var _sendPtr    = Module.findExportByName(null, 'send');
var _recvPtr    = Module.findExportByName(null, 'recv');

function emitNet(fn, data) {
    send(JSON.stringify({ type: 'network', fn: fn, ts: Date.now()/1000, data: data }));
}

if (_connectPtr) Interceptor.attach(_connectPtr, {
    onEnter: function(args) {
        try {
            var sa_family = args[1].readU16();
            var port = ((args[1].add(2).readU8() << 8) | args[1].add(3).readU8());
            emitNet('connect', { sa_family: sa_family, port: port });
        } catch(e) {}
    }
});
if (_sendPtr) Interceptor.attach(_sendPtr, {
    onEnter: function(args) {
        try {
            var len = args[2].toInt32();
            var preview = args[1].readByteArray(Math.min(len, 128));
            emitNet('send', { len: len, preview: preview ? Array.from(new Uint8Array(preview)).map(b=>b.toString(16).padStart(2,'0')).join('') : '' });
        } catch(e) {}
    }
});
if (_recvPtr) Interceptor.attach(_recvPtr, {
    onLeave: function(retval) {
        try {
            var len = retval.toInt32();
            if (len > 0) emitNet('recv', { len: len });
        } catch(e) {}
    }
});
"""

# ── JNI inline script (fallback when dist/jni_trace.js absent) ───────────────
_JNI_INLINE_JS = """
'use strict';
var JNI_FNS = ["FindClass","GetMethodID","GetStaticMethodID","CallObjectMethod","CallStaticObjectMethod"];
if (typeof Java !== 'undefined' && Java.available) {
    try {
        var env_table = Java.vm.getEnv();
        JNI_FNS.forEach(function(fn) {
            try {
                var ptr = env_table[fn];
                if (!ptr || ptr.isNull()) return;
                Interceptor.attach(ptr, { onEnter: function(args) {
                    try {
                        var name = args[1].readCString();
                        if (name && name.length > 0 && name.length <= 255) {
                            send(JSON.stringify({ type: 'jni_call', fn: fn, arg: name, ts: Date.now()/1000 }));
                        }
                    } catch(e) {}
                }});
            } catch(e) {}
        });
    } catch(e) {}
}
"""


def _dtrace_cmd(pid: int, target: str) -> list[str]:
    """Return the dtrace subprocess argv for syscall or network tracing."""
    if target == "syscall":
        probe = (
            f"syscall:::entry /pid == {pid}/ "
            f'{{ printf("{{\\\"probefunc\\\":\\\"%s\\\"}}\\n", probefunc); }}'
        )
    else:  # network
        probe = (
            f"syscall:::entry /pid == {pid} && "
            f'(probefunc == "sendto" || probefunc == "recvfrom")/ '
            f'{{ printf("{{\\\"probefunc\\\":\\\"%s\\\"}}\\n", probefunc); }}'
        )
    return ["dtrace", "-n", probe]


# ── Custom exceptions ─────────────────────────────────────────────────────────

class FridaNotAvailableError(RuntimeError):
    """Raised when the frida CLI binary cannot be found on PATH."""


# ── Finding dataclass ─────────────────────────────────────────────────────────

@dataclass
class TracerFinding:
    """A structured finding emitted by a Frida hook or memory scan."""

    session_id: str
    pid:        int
    target:     str
    kind:       str          # "jni_call" | "network" | "secret" | "hook_event" | "raw"
    data:       Dict[str, object] = field(default_factory=dict)
    ts:         float        = field(default_factory=time.time)
    severity:   str          = "info"

    def to_event(self) -> dict:
        return {
            "schema_version": "1.0.0",
            "session_id":     self.session_id,
            "pid":            self.pid,
            "target":         self.target,
            "kind":           self.kind,
            "data":           self.data,
            "ts":             self.ts,
            "severity":       self.severity,
            "source_engine":  "frida_session",
        }


# ── Main session manager ──────────────────────────────────────────────────────

class FridaDTraceTracer:
    """
    Phase-5 Frida session manager + DTrace fallback.

    Public API (TRACER_CONTRACT.md §2):
        attach(pid, name)   — attach to running process or spawn by name
        inject(script_path, inline_js)  — load TypeScript-compiled hook or inline JS
        scan(patterns)      — heap memory scan for secret patterns
        stream()            — iterator over pending TracerFinding objects
        stop()              — terminate session (idempotent)
        read_events()       — legacy: non-blocking list[dict] drain

    Targets (constructor `target` kwarg):
        ssl, crypto         — Frida JS hooks
        jni                 — JNI method call tracer
        memory              — malloc/free + heap scanner
        network_hook        — libc connect/send/recv via Frida
        syscall, network    — DTrace probes (macOS only)
        native_bridge       — dlopen/dlsym tracer
    """

    def __init__(
        self,
        pid: int,
        target: str,
        timeout: int,
        on_finding: Optional[Callable[[TracerFinding], None]] = None,
    ) -> None:
        self.pid        = pid
        self.target     = target
        self.timeout    = timeout
        self.session_id = str(uuid.uuid4())
        self.on_finding = on_finding

        # Frida Python session (frida lib mode)
        self._frida_session: object | None = None
        self._frida_script:  object | None = None

        # DTrace / frida-CLI subprocess fallback
        self._proc: subprocess.Popen | None = None  # type: ignore[type-arg]

        self._unavailable = False
        self._stopped     = False
        self._event_queue: Queue[dict] = Queue()
        self._reader_thread: threading.Thread | None = None
        self._hooks_compiled: bool = False  # lazily set after _ensure_hooks_compiled() runs

        self._start()

    # ── internal bootstrap ────────────────────────────────────────────────────

    def _start(self) -> None:
        """Select and start the appropriate backend."""
        frida_lib_targets  = {"ssl", "crypto", "jni", "memory", "network_hook", "native_bridge"}
        dtrace_targets     = {"syscall", "network"}

        if self.target in frida_lib_targets:
            self._start_frida_lib()
        elif self.target in dtrace_targets:
            self._start_dtrace()
        else:
            log.warning("Unknown target %r for session %s", self.target, self.session_id)
            self._unavailable = True

    def _start_frida_lib(self) -> None:
        """Use the frida Python library for real session management."""
        if not _HAS_FRIDA_LIB:
            log.warning(
                "frida Python package not installed — falling back to CLI "
                "pid=%s target=%s session=%s",
                self.pid, self.target, self.session_id,
            )
            self._start_frida_cli_fallback()
            return

        try:
            self._frida_session = self.attach(self.pid)
        except Exception as exc:
            log.warning(
                "frida.attach(%d) failed: %s — session=%s", self.pid, exc, self.session_id
            )
            self._unavailable = True
            return

        inline_js = self._pick_inline_js()
        script_path = self._pick_script_path()
        try:
            self.inject(script_path=script_path, inline_js=inline_js)
        except Exception as exc:
            log.warning("inject failed: %s — session=%s", exc, self.session_id)
            self._unavailable = True

    def _start_frida_cli_fallback(self) -> None:
        """Spawn frida CLI subprocess when the Python library is absent."""
        frida_bin = shutil.which("frida")
        if frida_bin is None:
            log.warning(
                "frida not on PATH — FridaDTraceTracer unavailable pid=%s target=%s session=%s",
                self.pid, self.target, self.session_id,
            )
            self._unavailable = True
            return

        script_path = self._pick_script_path()
        if script_path is None or not script_path.exists():
            log.warning(
                "No compiled script for target %r — unavailable session=%s",
                self.target, self.session_id,
            )
            self._unavailable = True
            return

        cmd = [
            frida_bin,
            "--pid", str(self.pid),
            "-l", str(script_path),
            "--runtime=v8",
            "--no-pause",
        ]
        try:
            self._proc = subprocess.Popen(
                cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
            )
        except OSError as exc:
            log.warning("Failed to launch frida CLI: %s session=%s", exc, self.session_id)
            self._unavailable = True
            return

        log.info("frida CLI started pid=%s target=%s session=%s", self.pid, self.target, self.session_id)

    def _start_dtrace(self) -> None:
        """Launch DTrace subprocess for syscall/network probing."""
        if platform.system() != "Darwin":
            log.warning("DTrace only available on macOS — unavailable session=%s", self.session_id)
            self._unavailable = True
            return
        dtrace_bin = shutil.which("dtrace")
        if dtrace_bin is None:
            log.warning("dtrace not on PATH — unavailable session=%s", self.session_id)
            self._unavailable = True
            return
        cmd = _dtrace_cmd(self.pid, self.target)
        try:
            self._proc = subprocess.Popen(
                cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                start_new_session=False,
            )
        except OSError as exc:
            log.warning("Failed to launch dtrace: %s session=%s", exc, self.session_id)
            self._unavailable = True
            return
        log.info("dtrace started pid=%s target=%s session=%s", self.pid, self.target, self.session_id)

    def _pick_script_path(self) -> Optional[pathlib.Path]:
        mapping = {
            "ssl":          _SSL_HOOK,
            "crypto":       _CRYPTO_HOOK,
            "jni":          _JNI_HOOK,
            "memory":       _MEM_HOOK,
            "native_bridge": _NET_BRIDGE,
            "network_hook": None,
        }
        return mapping.get(self.target)

    def _pick_inline_js(self) -> Optional[str]:
        if self.target == "network_hook":
            return _NETWORK_INLINE_JS
        if self.target == "jni" and (_JNI_HOOK is None or not _JNI_HOOK.exists()):
            return _JNI_INLINE_JS
        return None

    # ── Public contract methods ───────────────────────────────────────────────

    def attach(self, pid: int, spawn_name: Optional[str] = None) -> object:
        """
        Attach to a running process by PID or spawn a new process by name.

        Returns the frida.Session object.  Raises RuntimeError when the frida
        package is unavailable.
        """
        if not _HAS_FRIDA_LIB or frida is None:
            raise RuntimeError("frida Python package not installed")

        device = frida.get_local_device()

        if spawn_name:
            pid_actual = device.spawn([spawn_name])
            session = device.attach(pid_actual)
            device.resume(pid_actual)
            log.info("Spawned+attached %r pid=%d session=%s", spawn_name, pid_actual, self.session_id)
        else:
            session = device.attach(pid)
            log.info("Attached to pid=%d session=%s", pid, self.session_id)

        self._frida_session = session

        def _on_detached(reason: str, crash: object | None) -> None:
            log.info("Frida detached reason=%r pid=%d session=%s", reason, pid, self.session_id)
            self._stopped = True

        session.on("detached", _on_detached)
        return session

    def inject(
        self,
        script_path: Optional[pathlib.Path] = None,
        inline_js: Optional[str] = None,
    ) -> None:
        """
        Load a compiled JS hook or inline JavaScript into the attached session.

        Priority: script_path (read from disk) > inline_js.
        Raises RuntimeError when no session is attached or no script provided.
        """
        if not _HAS_FRIDA_LIB or frida is None:
            raise RuntimeError("frida Python package not installed")
        if self._frida_session is None:
            raise RuntimeError("No active frida session — call attach() first")

        if script_path is not None and script_path.exists():
            js_source = script_path.read_text(encoding="utf-8")
            log.info("Injecting script %s session=%s", script_path.name, self.session_id)
        elif inline_js:
            js_source = inline_js
            log.info("Injecting inline JS session=%s", self.session_id)
        else:
            raise RuntimeError("inject() requires script_path or inline_js")

        session = self._frida_session
        script_obj = session.create_script(js_source)  # type: ignore[union-attr]

        def _on_message(message: object, data: object) -> None:
            self._handle_frida_message(message, data)

        script_obj.on("message", _on_message)
        script_obj.load()
        self._frida_script = script_obj
        log.info("Script loaded session=%s", self.session_id)

    def scan(self, patterns: Optional[List[tuple[str, re.Pattern[str]]]] = None) -> List[TracerFinding]:
        """
        Scan process memory ranges for secret patterns.

        Uses frida.enumerate_ranges() when the frida library is available,
        otherwise applies patterns to buffered event text from the subprocess.
        Returns a list of TracerFinding with kind="secret".
        """
        if not _HAS_FRIDA_LIB or self._frida_session is None:
            return self._scan_subprocess_buffer(patterns)

        pat_list = patterns or _COMPILED_PATTERNS
        findings: List[TracerFinding] = []

        try:
            session = self._frida_session
            ranges = session.enumerate_ranges("r--")  # type: ignore[union-attr]
        except Exception as exc:
            log.debug("enumerate_ranges failed: %s", exc)
            return findings

        for rng in ranges:
            try:
                base   = rng["base"]
                size   = min(int(rng["size"]), 1024 * 64)  # cap at 64 KB per range
                raw    = base.read_bytes(size)
                text   = raw.decode("latin-1")  # latin-1 preserves all bytes
            except Exception:
                continue

            for name, pattern in pat_list:
                m = pattern.search(text)
                if m:
                    findings.append(TracerFinding(
                        session_id=self.session_id,
                        pid=self.pid,
                        target=self.target,
                        kind="secret",
                        data={"pattern": name, "excerpt": m.group(0)[:60], "range_base": str(base)},
                        severity="critical" if name in ("jwt", "private_key", "aws_key", "aws_secret") else "high",
                    ))

        log.info("Memory scan found %d secrets session=%s", len(findings), self.session_id)
        return findings

    def _scan_subprocess_buffer(
        self, patterns: Optional[List[tuple[str, re.Pattern[str]]]]
    ) -> List[TracerFinding]:
        """Fallback: scan already-received subprocess output text."""
        pat_list = patterns or _COMPILED_PATTERNS
        findings: List[TracerFinding] = []
        # Drain current queue for text
        seen: List[str] = []
        while True:
            try:
                ev = self._event_queue.get_nowait()
                seen.append(json.dumps(ev))
                self._event_queue.put_nowait(ev)  # put back
            except Empty:
                break
        combined = " ".join(seen)
        for name, pattern in pat_list:
            m = pattern.search(combined)
            if m:
                findings.append(TracerFinding(
                    session_id=self.session_id,
                    pid=self.pid,
                    target=self.target,
                    kind="secret",
                    data={"pattern": name, "excerpt": m.group(0)[:60]},
                    severity="high",
                ))
        return findings

    def stream(self) -> Iterator[TracerFinding]:
        """
        Yield TracerFinding objects as they arrive.

        Checks both the internal queue (populated by Frida message callbacks)
        and the subprocess stdout.  Non-blocking: returns immediately when the
        queue is empty.
        """
        # Drain queue
        while True:
            try:
                ev = self._event_queue.get_nowait()
                yield TracerFinding(
                    session_id=self.session_id,
                    pid=self.pid,
                    target=self.target,
                    kind=ev.get("type", "raw"),
                    data=ev,
                    ts=float(ev.get("ts", time.time())),
                    severity=ev.get("severity", "info"),
                )
            except Empty:
                break

        # Also drain subprocess if running
        for ev in self._drain_subprocess():
            yield TracerFinding(
                session_id=self.session_id,
                pid=self.pid,
                target=self.target,
                kind=ev.get("type", "raw"),
                data=ev,
                ts=float(ev.get("ts", time.time())),
                severity=ev.get("severity", "info"),
            )

    def stop(self) -> None:
        """Terminate all backends (idempotent)."""
        if self._stopped:
            return
        self._stopped = True

        if self._frida_script is not None:
            try:
                self._frida_script.unload()  # type: ignore[union-attr]
            except Exception:
                pass

        if self._frida_session is not None:
            try:
                self._frida_session.detach()  # type: ignore[union-attr]
            except Exception:
                pass

        if self._proc is not None:
            try:
                self._proc.terminate()
                self._proc.wait(timeout=5)
            except (OSError, subprocess.TimeoutExpired):
                try:
                    self._proc.kill()
                except OSError:
                    pass

        log.info("FridaDTraceTracer stopped pid=%s target=%s session=%s",
                 self.pid, self.target, self.session_id)

    # ── Legacy read_events() ──────────────────────────────────────────────────

    def read_events(self) -> list[dict]:
        """
        Non-blocking drain for legacy callers expecting list[dict].
        Returns schema-conformant event dicts from both queue and subprocess.
        """
        if self._unavailable or self._stopped:
            return []

        out: list[dict] = []
        for finding in self.stream():
            out.append(finding.to_event())
        return out

    # ── Frida message handler ─────────────────────────────────────────────────

    def _handle_frida_message(self, message: object, _data: object) -> None:
        """Called by the Frida runtime for each send() from the script."""
        if not (isinstance(message, dict) and "type" in message):
            return

        msg: dict = message  # type: ignore[assignment]
        if msg["type"] == "send":
            payload = msg.get("payload", {})
            # payload may be a dict (structured) or a JSON string
            if isinstance(payload, str):
                try:
                    payload = json.loads(payload)
                except json.JSONDecodeError:
                    payload = {"raw": payload}
            if isinstance(payload, dict):
                self._event_queue.put_nowait(payload)
                if self.on_finding:
                    finding = TracerFinding(
                        session_id=self.session_id,
                        pid=self.pid,
                        target=self.target,
                        kind=payload.get("type", "hook_event"),
                        data=payload,
                        severity=payload.get("severity", "info"),
                    )
                    try:
                        self.on_finding(finding)
                    except Exception as exc:
                        log.debug("on_finding callback error: %s", exc)
        elif msg["type"] == "error":
            log.warning("Frida script error: %s session=%s", msg.get("description", ""), self.session_id)

    # ── Subprocess line drain (CLI fallback + DTrace) ─────────────────────────

    def _drain_subprocess(self) -> list[dict]:
        if self._proc is None or self._proc.stdout is None:
            return []
        events: list[dict] = []
        try:
            if _HAS_SELECT:
                ready, _, _ = _select.select([self._proc.stdout], [], [], 0.05)
                if not ready:
                    return []
            line = self._proc.stdout.readline()
        except OSError:
            return []
        if not line:
            return []
        ev = self._parse_subprocess_line(line.strip())
        if ev:
            events.append(ev)
        return events

    def _parse_subprocess_line(self, line: str) -> dict | None:
        if not line:
            return None
        try:
            obj = json.loads(line)
        except json.JSONDecodeError:
            obj = {"data": line.encode().hex()}

        source_engine = "frida_cli" if self.target in ("ssl", "crypto", "jni", "memory", "network_hook", "native_bridge") else "dtrace"
        return {
            "schema_version": "1.0.0",
            "pid":            int(obj.get("pid", self.pid)),
            "target":         str(obj.get("target", self.target)),
            "data":           str(obj.get("data", line.encode().hex()))[:4096],
            "ts":             float(obj.get("ts", time.time())),
            "source_engine":  source_engine,
            "session_id":     self.session_id,
            "type":           obj.get("type", "raw"),
        }

    # ── Convenience class-methods ─────────────────────────────────────────────

    @classmethod
    def for_jni_tracing(cls, pid: int, timeout: int = 30, **kwargs: object) -> "FridaDTraceTracer":
        """Factory: create a session preconfigured for JNI method tracing."""
        return cls(pid=pid, target="jni", timeout=timeout, **kwargs)  # type: ignore[arg-type]

    @classmethod
    def for_memory_scan(cls, pid: int, timeout: int = 30, **kwargs: object) -> "FridaDTraceTracer":
        """Factory: create a session preconfigured for heap secret scanning."""
        return cls(pid=pid, target="memory", timeout=timeout, **kwargs)  # type: ignore[arg-type]

    @classmethod
    def for_network_intercept(cls, pid: int, timeout: int = 60, **kwargs: object) -> "FridaDTraceTracer":
        """Factory: create a session that hooks libc connect/send/recv."""
        return cls(pid=pid, target="network_hook", timeout=timeout, **kwargs)  # type: ignore[arg-type]

    @classmethod
    def is_available(cls) -> bool:
        """Return True iff frida (Python lib or CLI) is accessible."""
        if _HAS_FRIDA_LIB:
            return True
        return shutil.which("frida") is not None

    # ── Advanced dynamic-analysis methods (Phase 5 extension) ─────────────────

    # ── TypeScript hook auto-compilation ──────────────────────────────────────

    def _ensure_hooks_compiled(self) -> None:
        """Compile any missing dist/<hook>.js files from src/<hook>.ts via frida-compile.

        Called lazily on the first ``inject_spawn`` invocation so that hooks
        authored in TypeScript are available without a separate build step.
        Silently skips hooks whose ``.ts`` source is absent or when
        ``frida-compile`` is not on PATH.
        """
        if self._hooks_compiled:
            return
        self._hooks_compiled = True

        frida_compile = shutil.which("frida-compile")
        if not frida_compile:
            log.debug("_ensure_hooks_compiled: frida-compile not on PATH — skipping TS compilation")
            return

        _HOOKS_DIST.mkdir(parents=True, exist_ok=True)
        # Well-known TypeScript hooks that may live in src/ but not yet in dist/
        _KNOWN_TS_HOOKS = [
            "process_injection",
            "ipc_intercept",
            "objc_swizzle",
            "ssl_hook",
            "crypto_extract",
            "jni_trace",
            "memory_scan",
            "native_bridge",
            "certificate_pinning_bypass",
        ]
        for hook_name in _KNOWN_TS_HOOKS:
            js_path = _HOOKS_DIST / f"{hook_name}.js"
            ts_path = _HOOKS_SRC / f"{hook_name}.ts"
            if js_path.exists() or not ts_path.exists():
                continue  # already compiled or no source to compile
            try:
                subprocess.run(
                    [frida_compile, str(ts_path), "-o", str(js_path)],
                    check=True,
                    timeout=60,
                    stdout=subprocess.DEVNULL,
                    stderr=subprocess.PIPE,
                )
                log.info("_ensure_hooks_compiled: compiled %s -> %s", ts_path.name, js_path.name)
            except subprocess.CalledProcessError as exc:
                stderr_text = exc.stderr.decode("utf-8", errors="replace").strip() if exc.stderr else ""
                log.warning(
                    "_ensure_hooks_compiled: frida-compile failed for %s: %s",
                    hook_name, stderr_text[:200],
                )
            except subprocess.TimeoutExpired:
                log.warning("_ensure_hooks_compiled: frida-compile timed out for %s", hook_name)
            except OSError as exc:
                log.warning("_ensure_hooks_compiled: OS error compiling %s: %s", hook_name, exc)

    def inject_spawn(
        self,
        binary_path: str,
        argv: list[str],
        hooks: list[str],
    ) -> list[dict]:
        """
        Spawn *binary_path* under Frida and load one or more hook scripts.

        For each name in *hooks* the method resolves:
          1. ``src/frida-hooks/dist/<hook>.js``  (pre-compiled)
          2. Falls back to compiling ``src/frida-hooks/src/<hook>.ts`` via
             ``frida-compile`` if the ``.js`` file is absent.

        The process is launched with ``frida --no-pause -f <binary> -- <argv>``.
        NDJSON lines emitted to stdout are collected and returned.

        Raises
        ------
        FridaNotAvailableError
            When the ``frida`` binary cannot be found on PATH.
        """
        frida_bin = shutil.which("frida")
        if frida_bin is None:
            raise FridaNotAvailableError(
                "frida binary not found on PATH — install frida-tools"
            )
        # Ensure TypeScript hooks are compiled to dist/ before resolving paths
        self._ensure_hooks_compiled()


        cmd: list[str] = [frida_bin, "--no-pause", "-f", binary_path]

        # Resolve and attach hook scripts
        for hook in hooks:
            hook_js = _HOOKS_DIST / f"{hook}.js"
            if not hook_js.exists():
                # Try to compile the TypeScript source on-the-fly
                hook_ts = _HOOKS_SRC / f"{hook}.ts"
                frida_compile = shutil.which("frida-compile")
                if frida_compile and hook_ts.exists():
                    out_js = pathlib.Path(tempfile.mktemp(suffix=f"_{hook}.js"))
                    try:
                        subprocess.run(
                            [frida_compile, str(hook_ts), "-o", str(out_js)],
                            check=True,
                            timeout=30,
                            stdout=subprocess.DEVNULL,
                            stderr=subprocess.DEVNULL,
                        )
                        hook_js = out_js
                    except (subprocess.CalledProcessError, subprocess.TimeoutExpired, OSError):
                        log.warning(
                            "inject_spawn: frida-compile failed for %s — hook skipped", hook
                        )
                        continue
                else:
                    log.warning(
                        "inject_spawn: no compiled JS for hook %r and frida-compile unavailable"
                        " — hook skipped",
                        hook,
                    )
                    continue
            cmd += ["-l", str(hook_js)]

        # Append target binary argv after '--'
        if argv:
            cmd += ["--", *argv]

        log.info("inject_spawn: %s", " ".join(cmd))
        events: list[dict] = []
        try:
            proc = subprocess.Popen(
                cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.DEVNULL,
                text=True,
            )
            assert proc.stdout is not None
            for raw_line in proc.stdout:
                line = raw_line.strip()
                if not line:
                    continue
                try:
                    ev = json.loads(line)
                    if isinstance(ev, dict):
                        events.append(ev)
                except json.JSONDecodeError:
                    events.append({"type": "raw", "data": line})
            proc.wait(timeout=5)
        except FileNotFoundError:
            raise FridaNotAvailableError(
                f"frida binary vanished at runtime: {frida_bin}"
            ) from None
        except subprocess.TimeoutExpired:
            proc.kill()
            log.warning("inject_spawn: subprocess timeout")
        except OSError as exc:
            log.warning("inject_spawn: OS error: %s", exc)

        return events

    def inject_pid(self, pid: int, hook: str) -> list[dict]:
        """
        Attach to a running process and stream NDJSON events from *hook*.

        *hook* is resolved the same way as in ``inject_spawn`` (dist JS first,
        then frida-compile fallback).  Returns an empty list and logs a warning
        on permission errors (e.g. missing root/SIP on macOS).

        Raises
        ------
        FridaNotAvailableError
            When the ``frida`` binary cannot be found on PATH.
        """
        frida_bin = shutil.which("frida")
        if frida_bin is None:
            raise FridaNotAvailableError(
                "frida binary not found on PATH — install frida-tools"
            )

        # Resolve hook path (same logic as inject_spawn, single hook)
        hook_js = _HOOKS_DIST / f"{hook}.js"
        if not hook_js.exists():
            hook_ts = _HOOKS_SRC / f"{hook}.ts"
            frida_compile = shutil.which("frida-compile")
            if frida_compile and hook_ts.exists():
                out_js = pathlib.Path(tempfile.mktemp(suffix=f"_{hook}.js"))
                try:
                    subprocess.run(
                        [frida_compile, str(hook_ts), "-o", str(out_js)],
                        check=True,
                        timeout=30,
                        stdout=subprocess.DEVNULL,
                        stderr=subprocess.DEVNULL,
                    )
                    hook_js = out_js
                except (subprocess.CalledProcessError, subprocess.TimeoutExpired, OSError) as exc:
                    log.warning("inject_pid: frida-compile failed for %s: %s", hook, exc)
                    return []
            else:
                log.warning("inject_pid: hook %r not found and frida-compile unavailable", hook)
                return []

        cmd = [frida_bin, "--no-pause", "-p", str(pid), "-l", str(hook_js)]
        log.info("inject_pid: %s", " ".join(cmd))

        events: list[dict] = []
        try:
            proc = subprocess.Popen(
                cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
            )
            assert proc.stdout is not None
            assert proc.stderr is not None
            for raw_line in proc.stdout:
                line = raw_line.strip()
                if not line:
                    continue
                try:
                    ev = json.loads(line)
                    if isinstance(ev, dict):
                        events.append(ev)
                except json.JSONDecodeError:
                    events.append({"type": "raw", "data": line})
            _, stderr_out = proc.communicate(timeout=5)
            if proc.returncode not in (0, 1, None):
                # Check for permission-related errors
                if any(
                    kw in (stderr_out or "").lower()
                    for kw in ("permission", "denied", "not permitted", "eperm", "operation not allowed")
                ):
                    log.warning(
                        "inject_pid: permission error attaching to pid=%d — "
                        "try running as root or grant entitlements",
                        pid,
                    )
                    return []
        except FileNotFoundError:
            raise FridaNotAvailableError(
                f"frida binary vanished at runtime: {frida_bin}"
            ) from None
        except subprocess.TimeoutExpired:
            proc.kill()
            log.warning("inject_pid: subprocess timeout for pid=%d", pid)
        except OSError as exc:
            log.warning("inject_pid: OS error for pid=%d: %s", pid, exc)

        return events

    def memory_patch(self, pid: int, address: int, patch_bytes: bytes) -> bool:
        """
        Patch *len(patch_bytes)* bytes at *address* inside a live process.

        Generates a minimal inline Frida script using ``Memory.patchCode``,
        writes it to a temporary file, and runs ``frida -p pid -l tmpfile``.
        The temp file is removed in a ``finally`` block.

        Returns
        -------
        True  — frida exited with code 0 or 1 (normal script finish).
        False — frida not available, or the patch attempt failed.
        """
        frida_bin = shutil.which("frida")
        if frida_bin is None:
            log.warning(
                "memory_patch: frida not on PATH — cannot patch pid=%d addr=0x%x",
                pid, address,
            )
            return False

        # Build a minimal JS snippet: write each byte via Memory.patchCode
        hex_bytes = ", ".join(f"0x{b:02x}" for b in patch_bytes)
        patch_len = len(patch_bytes)
        inline_js = (
            f"'use strict';\n"
            f"var _addr = ptr('{hex(address)}');\n"
            f"var _bytes = [{hex_bytes}];\n"
            f"Memory.patchCode(_addr, {patch_len}, function(code) {{\n"
            f"    var w = new Uint8Array(code.readByteArray({patch_len}));\n"
            f"    for (var i = 0; i < _bytes.length; i++) w[i] = _bytes[i];\n"
            f"    Memory.writeByteArray(code, w);\n"
            f"}});\n"
            f"send({{type: 'memory_patch', address: '{hex(address)}', "
            f"length: {patch_len}, status: 'ok'}});\n"
        )

        tmp_path: Optional[str] = None
        try:
            with tempfile.NamedTemporaryFile(
                mode="w",
                suffix=".js",
                prefix="oi_patch_",
                delete=False,
            ) as tmp:
                tmp.write(inline_js)
                tmp_path = tmp.name

            cmd = [frida_bin, "--no-pause", "-p", str(pid), "-l", tmp_path]
            log.info("memory_patch: pid=%d addr=0x%x bytes=%d", pid, address, patch_len)
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=15,
            )
            if result.returncode not in (0, 1):
                log.warning(
                    "memory_patch: frida exited %d stderr=%s",
                    result.returncode,
                    (result.stderr or "")[:200],
                )
                return False
            return True

        except subprocess.TimeoutExpired:
            log.warning("memory_patch: timeout for pid=%d addr=0x%x", pid, address)
            return False
        except OSError as exc:
            log.warning("memory_patch: OS error: %s", exc)
            return False
        finally:
            if tmp_path is not None:
                try:
                    pathlib.Path(tmp_path).unlink(missing_ok=True)
                except OSError:
                    pass

    def find_runtime_secrets(self, pid: int) -> List[Dict]:
        """
        Inject memory_search.js (compiled from memory_search.ts) into *pid* and
        collect structured secret matches.

        The hook emits ``send({type:'memory_match', pattern:str, offset:str,
        preview:str})`` for each hit.  This method drives a one-shot Frida
        session, waits up to 30 s for the script to finish scanning, then
        returns a list of finding dicts suitable for the OneInfinity schema:

            {
                "type":     "runtime_secret",
                "pattern":  <pattern name>,
                "offset":   <hex address string>,
                "preview":  <first 32 chars of match>,
                "pid":      <int>,
                "severity": "critical"|"high",
                "tool":     "memory_search",
            }

        Falls back to the Python-side regex scan (``self.scan()``) when the
        compiled JS hook is absent or Frida is unavailable.
        """
        secrets: List[Dict] = []

        # ── Try Frida JS hook first (more thorough: scans all r-- ranges) ──────
        if _HAS_FRIDA_LIB and frida is not None and (_MEM_SEARCH_HOOK.exists() or _HOOKS_SRC.exists()):
            js_source: Optional[str] = None

            if _MEM_SEARCH_HOOK.exists():
                try:
                    js_source = _MEM_SEARCH_HOOK.read_text(encoding="utf-8")
                except OSError as exc:
                    log.debug("find_runtime_secrets: could not read %s: %s", _MEM_SEARCH_HOOK, exc)

            # If compiled hook missing, try raw TypeScript source as inline JS (best-effort)
            if js_source is None:
                ts_src = _HOOKS_SRC / "memory_search.ts"
                if ts_src.exists():
                    try:
                        js_source = ts_src.read_text(encoding="utf-8")
                    except OSError:
                        pass

            if js_source:
                done_event = threading.Event()

                def _on_msg(message: object, _data: object) -> None:
                    if not isinstance(message, dict):
                        return
                    if message.get("type") == "send":
                        payload = message.get("payload", {})
                        if isinstance(payload, dict) and payload.get("type") == "memory_match":
                            pattern = str(payload.get("pattern", "unknown"))
                            secret_entry = {
                                "type":     "runtime_secret",
                                "pattern":  pattern,
                                "offset":   str(payload.get("offset", "")),
                                "preview":  str(payload.get("preview", ""))[:32],
                                "pid":      pid,
                                "severity": "critical" if pattern in (
                                    "jwt_hs256_secret", "pem_rsa_key", "pem_ec_key",
                                    "pem_priv_key", "bcrypt_hash", "aws_key",
                                ) else "high",
                                "tool":     "memory_search",
                            }
                            secrets.append(secret_entry)
                    elif message.get("type") == "error":
                        log.debug("find_runtime_secrets JS error: %s", message.get("description", ""))
                        done_event.set()

                try:
                    device = frida.get_local_device()
                    session = device.attach(pid)
                    script_obj = session.create_script(js_source)
                    script_obj.on("message", _on_msg)
                    script_obj.load()
                    # memory_search.ts scans synchronously then terminates;
                    # wait up to 30 s for scan completion (script runs to EOF)
                    done_event.wait(timeout=30)
                    try:
                        script_obj.unload()
                    except Exception:
                        pass
                    try:
                        session.detach()
                    except Exception:
                        pass
                    log.info(
                        "find_runtime_secrets: pid=%d js_scan found %d secrets",
                        pid, len(secrets),
                    )
                    return secrets
                except Exception as exc:
                    log.warning(
                        "find_runtime_secrets: Frida JS scan failed pid=%d: %s — falling back to regex scan",
                        pid, exc,
                    )
                    secrets.clear()

        # ── Python-side regex scan fallback ───────────────────────────────────
        tracer_findings = self.scan()
        for tf in tracer_findings:
            if tf.kind == "secret":
                pattern_name = tf.data.get("pattern", "unknown")
                secrets.append({
                    "type":     "runtime_secret",
                    "pattern":  pattern_name,
                    "offset":   tf.data.get("range_base", ""),
                    "preview":  tf.data.get("excerpt", "")[:32],
                    "pid":      pid,
                    "severity": tf.severity,
                    "tool":     "memory_search",
                })

        log.info(
            "find_runtime_secrets: pid=%d regex_fallback found %d secrets",
            pid, len(secrets),
        )
        return secrets

    def __del__(self) -> None:
        self.stop()
