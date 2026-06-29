"""
stealth_tracer.py — StealthTracer facade (Module 1, Phase 5).

Callers import ONLY from this module.  The concrete backend is selected at
construction time and is NEVER exposed directly.

Backend selection order (per-platform):
  Linux:
    1. EBPFTracer  (sidecar if BTF+binary available; /proc fallback otherwise)
    2. FridaDTraceTracer (universal Frida fallback if frida-tools installed)
  macOS (Darwin):
    1. FridaDTraceTracer (Frida primary + DTrace secondary)
    2. EBPFTracer degraded-/proc-mode (graceful no-op on Darwin — never raises)
  Other:
    TracerUnavailableError

Capability matrix is resolved once at import time via ``_detect_capabilities()``
and cached in module-level ``_CAPS``.

Conforms to TRACER_CONTRACT.md v1.0.0.
"""

from __future__ import annotations

import logging
import platform
import shutil

log = logging.getLogger('oi.stealth_tracer')


# ---------------------------------------------------------------------------
# Public exception hierarchy
# ---------------------------------------------------------------------------

class TracerUnavailableError(RuntimeError):
    """Raised when no tracer backend is available on the current OS/host."""


class TracerPermissionError(RuntimeError):
    """Raised when the process lacks the privileges required by the backend."""


class TracerTimeoutError(RuntimeError):
    """Raised when the backend subprocess produces no events within timeout."""


# ---------------------------------------------------------------------------
# Capability detection (runs once at import time)
# ---------------------------------------------------------------------------

class _Caps:
    """Immutable platform capability snapshot."""
    __slots__ = (
        'os_name',
        'has_btf',
        'has_sidecar',
        'has_frida',
        'has_dtrace',
        'has_proc',
        'linux_fallback_available',
    )

    def __init__(self) -> None:
        import pathlib
        self.os_name   = platform.system()
        self.has_btf   = pathlib.Path('/sys/kernel/btf/vmlinux').exists()
        self.has_sidecar = shutil.which('oi-ebpf-trace') is not None
        self.has_frida   = shutil.which('frida') is not None
        self.has_dtrace  = shutil.which('dtrace') is not None
        self.has_proc    = pathlib.Path('/proc').exists()
        # /proc fallback is available on any Linux host
        self.linux_fallback_available = (self.os_name == 'Linux' and self.has_proc)

    @property
    def ebpf_full(self) -> bool:
        """Full BPF sidecar path available."""
        return self.os_name == 'Linux' and self.has_btf and self.has_sidecar

    @property
    def ebpf_proc(self) -> bool:
        """Pure-Python /proc fallback available."""
        return self.linux_fallback_available

    @property
    def frida_primary(self) -> bool:
        """Frida usable as primary or fallback backend."""
        return self.has_frida

    def __repr__(self) -> str:
        return (
            f'_Caps(os={self.os_name} ebpf_full={self.ebpf_full} '
            f'ebpf_proc={self.ebpf_proc} frida={self.frida_primary} '
            f'dtrace={self.has_dtrace})'
        )


def _detect_capabilities() -> _Caps:
    try:
        return _Caps()
    except Exception as exc:  # pragma: no cover
        log.debug('_detect_capabilities error: %s', exc)
        # Return a minimal no-capability object
        cap = object.__new__(_Caps)
        for attr in _Caps.__slots__:
            object.__setattr__(cap, attr, False)
        object.__setattr__(cap, 'os_name', platform.system())
        return cap  # type: ignore[return-value]


_CAPS: _Caps = _detect_capabilities()
log.debug('StealthTracer capabilities: %s', _CAPS)


# ---------------------------------------------------------------------------
# StealthTracer — OS-dispatching facade
# ---------------------------------------------------------------------------

class StealthTracer:
    """
    OS-dispatching facade; construction returns a concrete backend instance.

    The returned object is the backend directly (not a StealthTracer wrapper),
    so all backend methods (trace_syscalls, verify_rce, scan_memory_secrets,
    etc.) are available on the returned instance.

    Usage::

        if StealthTracer.is_available():
            tracer = StealthTracer(pid=1234, target='ssl', timeout=30)
            events = tracer.read_events()
            # Offensive capabilities (EBPFTracer on Linux):
            rce_events = tracer.verify_rce()
            ssrf_events = tracer.confirm_ssrf()
            tracer.stop()

    Backend selection
    -----------------
    Linux (any):
      - Primary: EBPFTracer  (sidecar when BTF+binary available; /proc otherwise)
      - Fallback: FridaDTraceTracer  (when Frida installed)

    macOS / Darwin:
      - Primary: FridaDTraceTracer  (Frida+DTrace)
      - Fallback: EBPFTracer in no-op/degraded mode  (never raises, returns [])

    Other OS:
      - TracerUnavailableError

    Args:
        pid: target process ID to trace (0 = not yet attached)
        target: tracing target hint ('ssl', 'syscall', 'network', 'key', ...)
        timeout: max seconds to wait for events
        target_host: IP/hostname used for SSRF/connect correlation (optional)
    """

    def __new__(
        cls,
        pid: int = 0,
        target: str = 'ssl',
        timeout: int = 30,
        target_host: str = '',
    ):
        os_name = _CAPS.os_name

        if os_name == 'Linux':
            tracer = _build_linux_tracer(pid, target, timeout, target_host)
        elif os_name == 'Darwin':
            tracer = _build_darwin_tracer(pid, target, timeout, target_host)
        else:
            raise TracerUnavailableError(
                f'No StealthTracer backend for {os_name}'
            )

        log.debug(
            'StealthTracer backend=%s pid=%s target=%s session=%s',
            type(tracer).__name__, pid, target,
            getattr(tracer, 'session_id', 'unknown'),
        )
        return tracer

    @staticmethod
    def is_available() -> bool:
        """
        Return True iff at least one tracer backend can function on this host.

        Per TRACER_CONTRACT.md §3 (Tracing-Off Invariant): callers MUST
        check this before constructing a StealthTracer.  A False return
        MUST NOT alter any scan result.

        On Linux  : True when /proc is available (EBPFTracer /proc fallback)
        On macOS  : True when frida or dtrace is on PATH
        Other     : False
        """
        caps = _CAPS
        if caps.os_name == 'Linux':
            return caps.ebpf_full or caps.ebpf_proc
        if caps.os_name == 'Darwin':
            return caps.frida_primary or caps.has_dtrace
        return False

    @staticmethod
    def backend_info() -> dict:
        """
        Return a dict describing the resolved backend and its capabilities.

        Useful for diagnostics and unit tests.
        """
        caps = _CAPS
        return {
            'os':              caps.os_name,
            'ebpf_sidecar':    caps.ebpf_full,
            'ebpf_proc':       caps.ebpf_proc,
            'frida':           caps.frida_primary,
            'dtrace':          caps.has_dtrace,
            'available':       StealthTracer.is_available(),
            'linux_primary':   caps.os_name == 'Linux',
            'darwin_primary':  caps.os_name == 'Darwin',
        }


# ---------------------------------------------------------------------------
# Backend builder helpers (not public API)
# ---------------------------------------------------------------------------

def _build_linux_tracer(
    pid: int,
    target: str,
    timeout: int,
    target_host: str,
):
    """
    Build the Linux tracer chain:
    1. Try EBPFTracer (sidecar or /proc fallback — always available on Linux)
    2. If EBPFTracer import fails, try FridaDTraceTracer
    """
    from .ebpf_tracer import EBPFTracer
    try:
        tracer = EBPFTracer(pid=pid, target=target, timeout=timeout,
                            target_host=target_host)
        log.info(
            'Linux backend: EBPFTracer sidecar=%s proc_fallback=%s',
            tracer._use_sidecar, tracer._proc_fallback,
        )
        return tracer
    except Exception as exc:
        log.warning('EBPFTracer init failed: %s — trying Frida fallback', exc)

    # Frida universal fallback
    if _CAPS.has_frida:
        try:
            from .frida_dtrace_tracer import FridaDTraceTracer
            tracer = FridaDTraceTracer(pid, target, timeout)
            log.info('Linux backend: FridaDTraceTracer (fallback)')
            return tracer
        except Exception as exc2:
            log.warning('FridaDTraceTracer fallback also failed: %s', exc2)

    raise TracerUnavailableError(
        'All Linux tracer backends failed. '
        f'EBPFTracer and FridaDTraceTracer both unavailable on this host.'
    )


def _build_darwin_tracer(
    pid: int,
    target: str,
    timeout: int,
    target_host: str,
):
    """
    Build the macOS tracer chain:
    1. FridaDTraceTracer (primary)
    2. EBPFTracer in degraded/no-op mode (graceful — never raises, returns [])
    """
    if _CAPS.has_frida or _CAPS.has_dtrace:
        try:
            from .frida_dtrace_tracer import FridaDTraceTracer
            tracer = FridaDTraceTracer(pid, target, timeout)
            log.info('Darwin backend: FridaDTraceTracer (frida=%s dtrace=%s)',
                     _CAPS.has_frida, _CAPS.has_dtrace)
            return tracer
        except Exception as exc:
            log.warning('FridaDTraceTracer init failed: %s', exc)

    # Graceful degraded fallback: EBPFTracer on Darwin is a no-op
    # (it sets _proc_fallback=False, _unavailable=True on non-Linux)
    log.warning(
        'Darwin: neither frida nor dtrace available — '
        'EBPFTracer degraded mode (returns [])'
    )
    from .ebpf_tracer import EBPFTracer
    return EBPFTracer(pid=pid, target=target, timeout=timeout,
                      target_host=target_host)


# ---------------------------------------------------------------------------
# Module-level convenience: re-export exception classes
# ---------------------------------------------------------------------------

__all__ = [
    'StealthTracer',
    'TracerUnavailableError',
    'TracerPermissionError',
    'TracerTimeoutError',
]
