"""
syscall_tracer_loader.py — Python loader and userspace consumer for syscall_tracer.bpf.c

Loads the BPF program, attaches to tracepoints for execve/openat/connect,
optionally filters to specific PIDs, and emits findings as NDJSON.

Usage (requires root + libbpf/bcc):
    sudo python3 syscall_tracer_loader.py [--pids 1234,5678] [--duration 30] [--output findings.ndjson]

Output per event (NDJSON):
    {"vuln_type":"suspicious_syscall","syscall":"execve","pid":1234,"ppid":100,
     "comm":"sh","arg0":"/bin/sh","uid":0,"ts_ns":1700000000000,"evidence":"...","scan_id":"..."}

Falls back gracefully when BPF tools are not available (returns empty findings).
"""
from __future__ import annotations

import ctypes
import json
import logging
import os
import platform
import shutil
import struct
import subprocess
import sys
import time
import uuid
from pathlib import Path
from typing import Any

log = logging.getLogger("oi.syscall_tracer")

# ── Constants ──────────────────────────────────────────────────────────────────

_BPF_OBJ_NAME = "syscall_tracer.bpf.o"
_LOADER_DIR = Path(__file__).parent

# Structure matching the BPF event struct
TASK_COMM_LEN = 16
ARG_LEN = 256

class BpfEvent(ctypes.Structure):  # noqa: E302
    _fields_ = [
        ("pid",           ctypes.c_uint32),
        ("ppid",          ctypes.c_uint32),
        ("uid",           ctypes.c_uint32),
        ("gid",           ctypes.c_uint32),
        ("comm",          ctypes.c_char * TASK_COMM_LEN),
        ("syscall",       ctypes.c_char * 16),
        ("arg0",          ctypes.c_char * ARG_LEN),
        ("ts_ns",         ctypes.c_uint64),
        ("retval",        ctypes.c_uint32),
        ("is_suspicious", ctypes.c_uint8),
    ]


def _is_linux() -> bool:
    return platform.system() == "Linux"


def _bpf_obj_path() -> Path | None:
    obj = _LOADER_DIR / _BPF_OBJ_NAME
    if obj.exists():
        return obj
    # Also check if it was compiled by the Makefile
    alt = _LOADER_DIR / "syscall_tracer.bpf.o"
    return alt if alt.exists() else None


# ── BCC-based loader (preferred) ──────────────────────────────────────────────

def _run_with_bcc(
    pids: list[int],
    duration: float,
    scan_id: str,
    findings: list[dict],
) -> None:
    """Load BPF via BCC Python bindings."""
    try:
        from bcc import BPF
    except ImportError:
        raise RuntimeError("bcc Python bindings not installed")

    bpf_src = (_LOADER_DIR / "syscall_tracer.bpf.c").read_text()

    b = BPF(text=bpf_src)

    # Attach tracepoints
    try:
        b.attach_tracepoint(tp="syscalls:sys_enter_execve",  fn_name="trace_execve")
        b.attach_tracepoint(tp="syscalls:sys_enter_openat",  fn_name="trace_openat")
        b.attach_tracepoint(tp="syscalls:sys_enter_connect", fn_name="trace_connect")
    except Exception as exc:
        log.warning("syscall_tracer: tracepoint attach failed: %s", exc)
        return

    # Populate PID filter map
    pid_filter = b.get_table("pid_filter")
    if pids:
        for pid in pids:
            pid_filter[ctypes.c_uint32(pid)] = ctypes.c_uint8(1)
    else:
        # Empty filter = trace all — set key 0 to 0xFF as sentinel
        pid_filter[ctypes.c_uint32(0)] = ctypes.c_uint8(0xFF)

    start = time.monotonic()

    def handle_event(cpu: int, data: Any, size: int) -> None:
        event = ctypes.cast(data, ctypes.POINTER(BpfEvent)).contents

        comm = event.comm.decode("utf-8", errors="replace").rstrip("\x00")
        syscall = event.syscall.decode("utf-8", errors="replace").rstrip("\x00")
        arg0_raw = event.arg0

        # Decode arg0 based on syscall type
        if syscall == "connect":
            # Packed format: 4 bytes IP + 2 bytes port + 2 bytes family
            if len(arg0_raw) >= 8 and arg0_raw[6] == 2:  # AF_INET
                ip = ".".join(str(b) for b in arg0_raw[:4])
                port = (arg0_raw[4] << 8) | arg0_raw[5]
                arg0 = f"{ip}:{port}"
            else:
                arg0 = arg0_raw.decode("utf-8", errors="replace").rstrip("\x00")
        else:
            arg0 = arg0_raw.decode("utf-8", errors="replace").rstrip("\x00")

        evidence = _build_evidence(syscall, comm, arg0, event.uid)

        finding = {
            "vuln_type":     "suspicious_syscall",
            "syscall":       syscall,
            "pid":           event.pid,
            "ppid":          event.ppid,
            "uid":           event.uid,
            "comm":          comm,
            "arg0":          arg0,
            "ts_ns":         event.ts_ns,
            "is_suspicious": bool(event.is_suspicious),
            "evidence":      evidence,
            "severity":      "high" if event.uid == 0 else "medium",
            "scan_id":       scan_id,
            "tool":          "syscall_tracer",
            "source_type":   "ebpf",
            "ts":            time.time(),
        }
        findings.append(finding)
        print(json.dumps(finding), flush=True)

    b["events"].open_ring_buffer(handle_event)

    while time.monotonic() - start < duration:
        b.ring_buffer_poll(timeout=100)

    b.detach_tracepoint(tp="syscalls:sys_enter_execve")
    b.detach_tracepoint(tp="syscalls:sys_enter_openat")
    b.detach_tracepoint(tp="syscalls:sys_enter_connect")


# ── bpftool-based loader (fallback) ───────────────────────────────────────────

def _run_with_bpftool(
    pids: list[int],
    duration: float,
    scan_id: str,
    findings: list[dict],
) -> None:
    """Fallback: load pre-compiled .o via bpftool. Limited event streaming."""
    if not shutil.which("bpftool"):
        raise RuntimeError("bpftool not in PATH")

    obj_path = _bpf_obj_path()
    if not obj_path:
        raise RuntimeError(f"BPF object {_BPF_OBJ_NAME} not found in {_LOADER_DIR}")

    pin_path = f"/sys/fs/bpf/oi_syscall_tracer_{os.getpid()}"
    try:
        subprocess.run(
            ["bpftool", "prog", "load", str(obj_path), pin_path, "type", "tracepoint"],
            check=True, capture_output=True, timeout=10,
        )
        log.info("syscall_tracer: BPF prog loaded via bpftool at %s", pin_path)
        time.sleep(min(duration, 5))
    except subprocess.CalledProcessError as exc:
        raise RuntimeError(f"bpftool load failed: {exc.stderr.decode()}")
    finally:
        # Clean up pinned prog
        Path(pin_path).unlink(missing_ok=True)


def _build_evidence(syscall: str, comm: str, arg0: str, uid: int) -> str:
    parts = [f"syscall={syscall}", f"process={comm}", f"arg0={arg0!r}", f"uid={uid}"]
    if uid == 0:
        parts.append("RUNNING AS ROOT")
    if syscall == "execve":
        if any(sh in arg0 for sh in ["/bin/sh", "/bin/bash", "/bin/dash", "curl", "wget", "nc"]):
            parts.append("shell/tool execution — potential code execution after injection")
    elif syscall == "openat":
        if "/etc/passwd" in arg0 or "/etc/shadow" in arg0:
            parts.append("sensitive credential file access")
        elif "docker.sock" in arg0:
            parts.append("Docker socket access — potential container escape")
        elif "/proc/" in arg0 and "/mem" in arg0:
            parts.append("process memory read — potential memory scraping")
    elif syscall == "connect":
        parts.append(f"outbound connection to {arg0}")
    return "; ".join(parts)


# ── Public API ─────────────────────────────────────────────────────────────────

def trace_pids(
    pids: list[int] | None = None,
    duration: float = 10.0,
    scan_id: str | None = None,
) -> list[dict]:
    """
    Trace suspicious syscalls from specified PIDs (or all processes if pids is None/empty).

    Parameters
    ----------
    pids : list[int] | None
        Process IDs to monitor. If None or empty, monitor all processes.
    duration : float
        Seconds to trace.
    scan_id : str | None
        Correlation ID for findings.

    Returns
    -------
    list[dict]
        List of finding dicts in OneInfinity standard format.
    """
    if not _is_linux():
        log.info("syscall_tracer: non-Linux OS — skipping eBPF tracing")
        return []

    if os.geteuid() != 0:
        log.warning("syscall_tracer: not running as root — eBPF requires CAP_BPF or root")
        return []

    sid = scan_id or uuid.uuid4().hex[:16]
    pids_list = list(pids or [])
    findings: list[dict] = []

    # Try BCC first, then bpftool
    errors: list[str] = []
    for loader_fn, name in [(_run_with_bcc, "bcc"), (_run_with_bpftool, "bpftool")]:
        try:
            loader_fn(pids_list, duration, sid, findings)
            log.info("syscall_tracer: traced %d events via %s", len(findings), name)
            return findings
        except RuntimeError as exc:
            errors.append(f"{name}: {exc}")
        except Exception as exc:
            errors.append(f"{name}: {exc}")

    log.warning("syscall_tracer: all loaders failed: %s", "; ".join(errors))
    return []


def trace_scan_target(
    target_url: str,
    scan_id: str | None = None,
    duration: float = 5.0,
) -> list[dict]:
    """
    Convenience wrapper: trace all processes briefly to detect post-scan side effects.
    Used by the container_scan phase in executor.py.
    """
    return trace_pids(pids=None, duration=duration, scan_id=scan_id)


# ── CLI entry point ────────────────────────────────────────────────────────────

def main() -> None:
    import argparse

    parser = argparse.ArgumentParser(
        description="OneInfinity eBPF syscall tracer — traces execve/connect/openat",
    )
    parser.add_argument("--pids", help="Comma-separated PIDs to monitor (default: all)")
    parser.add_argument("--duration", type=float, default=10.0, help="Trace duration in seconds")
    parser.add_argument("--scan-id", default="", help="Scan correlation ID")
    parser.add_argument("--output", help="Write findings NDJSON to file (default: stdout)")

    args = parser.parse_args()

    logging.basicConfig(
        level=logging.WARNING,
        format="%(levelname)s [%(name)s] %(message)s",
        stream=sys.stderr,
    )

    pids: list[int] = []
    if args.pids:
        try:
            pids = [int(p.strip()) for p in args.pids.split(",") if p.strip()]
        except ValueError as exc:
            print(f"Invalid --pids: {exc}", file=sys.stderr)
            sys.exit(1)

    findings = trace_pids(
        pids=pids or None,
        duration=args.duration,
        scan_id=args.scan_id or None,
    )

    # Stats line
    stats = {
        "type": "stats",
        "total_events": len(findings),
        "suspicious": sum(1 for f in findings if f.get("is_suspicious")),
        "duration": args.duration,
        "ts": time.time(),
    }
    print(json.dumps(stats), flush=True)

    if args.output:
        with open(args.output, "w") as fh:
            for f in findings:
                fh.write(json.dumps(f) + "\n")


if __name__ == "__main__":
    main()
