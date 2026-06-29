"""
ebpf_tracer.py — Linux eBPF tracer backend (Module 1, Phase 5).

Primary path: delegates to the ``oi-ebpf-trace`` Go sidecar, which loads BPF
object files and streams NDJSON events on stdout.

Secondary path (pure-Python, no sidecar): direct /proc filesystem and
perf_event_open syscall tracing — activated automatically when the sidecar is
unavailable.  This path provides:
  - Syscall tracing via /proc/<pid>/syscall
  - Network connection tracing via /proc/net/tcp[6]
  - File-descriptor tracing via /proc/<pid>/fd + /proc/<pid>/fdinfo
  - Process fork/exec detection via /proc scanning
  - /proc/<pid>/mem scanning for in-memory secrets
  - RCE verification (execve detected after payload delivery)
  - Data-exfiltration detection (write on network FD after file read)
  - Blind SSRF confirmation (connect() from target process)

Conforms to TRACER_CONTRACT.md v1.0.0.

Do NOT import this module directly; use StealthTracer from stealth_tracer.py.
"""

from __future__ import annotations

import asyncio
import ctypes
import io
import json
import logging
import os
import pathlib
import platform
import re
import shutil
import socket
import struct
import subprocess
import time
import uuid
from typing import Callable, Iterator

try:
    import select as _select
    _HAS_SELECT = True
except ImportError:  # pragma: no cover
    _HAS_SELECT = False

log = logging.getLogger('oi.tracer')

_BTF_VMLINUX   = pathlib.Path('/sys/kernel/btf/vmlinux')
_SIDECAR_BIN   = 'oi-ebpf-trace'
_PROC_ROOT     = pathlib.Path('/proc')

# Syscall numbers (x86-64); populated lazily
_SYSCALL_NAMES: dict[int, str] = {
    0:   'read',
    1:   'write',
    2:   'open',
    3:   'close',
    56:  'clone',
    57:  'fork',
    58:  'vfork',
    59:  'execve',
    257: 'openat',
    288: 'accept4',
    293: 'sendmmsg',
    42:  'connect',
    43:  'accept',
    44:  'sendto',
    45:  'recvfrom',
    322: 'execveat',
}

# Secret file patterns — FD tracing watches for these
_SECRET_PATTERNS = re.compile(
    r'(\.pem|\.key|\.crt|\.p12|id_rsa|id_ed25519|\.env|'
    r'\.token|secret|passwd|shadow|authorized_keys|\.aws/credentials)',
    re.IGNORECASE,
)

# --- Offensive verdict constants ---
VERDICT_RCE_CONFIRMED    = 'RCE_CONFIRMED'
VERDICT_SSRF_CONFIRMED   = 'SSRF_CONFIRMED'
VERDICT_SECRET_READ      = 'SECRET_FILE_READ'
VERDICT_EXFIL_DETECTED   = 'DATA_EXFILTRATION'
VERDICT_PROCESS_SPAWNED  = 'CHILD_PROCESS_SPAWNED'


# ---------------------------------------------------------------------------
# Pure-Python /proc-based tracing helpers
# ---------------------------------------------------------------------------

def _proc_path(pid: int) -> pathlib.Path:
    return _PROC_ROOT / str(pid)


def _read_proc(path: pathlib.Path) -> str | None:
    """Read a /proc file, returning None on any error."""
    try:
        return path.read_text(errors='replace')
    except (PermissionError, FileNotFoundError, OSError):
        return None


def _current_syscall(pid: int) -> tuple[int, list[int]] | None:
    """
    Read /proc/<pid>/syscall.
    Returns (syscall_nr, [args...]) or None if unreadable.
    """
    text = _read_proc(_proc_path(pid) / 'syscall')
    if not text:
        return None
    parts = text.split()
    if not parts or parts[0] == 'running':
        return None
    try:
        nr = int(parts[0])
        args = [int(x, 16) for x in parts[1:7]]
        return nr, args
    except ValueError:
        return None


def _list_children(pid: int) -> list[int]:
    """Return child PIDs from /proc/<pid>/task/<tid>/children."""
    children: list[int] = []
    task_dir = _proc_path(pid) / 'task'
    try:
        for tid_dir in task_dir.iterdir():
            children_path = tid_dir / 'children'
            text = _read_proc(children_path)
            if text:
                for tok in text.split():
                    try:
                        children.append(int(tok))
                    except ValueError:
                        pass
    except (FileNotFoundError, NotADirectoryError, PermissionError):
        pass
    return children


def _open_fds(pid: int) -> dict[int, str]:
    """
    Return {fd: resolved_path} for all open file descriptors of pid.
    Unresolvable FDs are skipped.
    """
    fd_dir = _proc_path(pid) / 'fd'
    result: dict[int, str] = {}
    try:
        for entry in fd_dir.iterdir():
            try:
                target = os.readlink(entry)
                result[int(entry.name)] = target
            except (ValueError, OSError, PermissionError):
                pass
    except (FileNotFoundError, PermissionError, NotADirectoryError):
        pass
    return result


def _parse_tcp_table(path: pathlib.Path) -> list[dict]:
    """
    Parse /proc/net/tcp or /proc/net/tcp6.
    Returns list of {local_addr, local_port, remote_addr, remote_port, state, inode}.
    """
    text = _read_proc(path)
    if not text:
        return []
    rows = []
    for line in text.splitlines()[1:]:
        cols = line.split()
        if len(cols) < 10:
            continue
        try:
            local_hex, local_port_hex = cols[1].split(':')
            remote_hex, remote_port_hex = cols[2].split(':')
            state = int(cols[3], 16)
            inode = int(cols[9])

            def _hex_to_ip4(h: str) -> str:
                b = bytes.fromhex(h)[::-1]
                return socket.inet_ntoa(b)

            local_addr  = _hex_to_ip4(local_hex)
            remote_addr = _hex_to_ip4(remote_hex)
            rows.append({
                'local_addr':   local_addr,
                'local_port':   int(local_port_hex, 16),
                'remote_addr':  remote_addr,
                'remote_port':  int(remote_port_hex, 16),
                'state':        state,
                'inode':        inode,
            })
        except (ValueError, IndexError):
            pass
    return rows


def _fd_inodes(pid: int) -> set[int]:
    """Return set of inodes backing the process's socket FDs."""
    inodes: set[int] = set()
    for _fd, target in _open_fds(pid).items():
        m = re.match(r'socket:\[(\d+)\]', target)
        if m:
            inodes.add(int(m.group(1)))
    return inodes


def _proc_connections(pid: int) -> list[dict]:
    """
    Return all TCP connections belonging to pid by cross-referencing
    /proc/net/tcp inodes with /proc/<pid>/fd symlinks.
    """
    inodes = _fd_inodes(pid)
    if not inodes:
        return []
    rows = _parse_tcp_table(_PROC_ROOT / 'net' / 'tcp')
    rows += _parse_tcp_table(_PROC_ROOT / 'net' / 'tcp6')
    return [r for r in rows if r['inode'] in inodes]


def _scan_mem_for_secrets(pid: int, patterns: list[bytes], limit_mb: int = 32) -> list[str]:
    """
    Scan /proc/<pid>/mem for secret patterns by walking /proc/<pid>/maps.
    Returns list of hex offsets where a pattern matched.
    Gracefully returns [] when /proc/<pid>/mem is unreadable (insufficient privilege).
    """
    maps_text = _read_proc(_proc_path(pid) / 'maps')
    if not maps_text:
        return []

    mem_path = _proc_path(pid) / 'mem'
    findings: list[str] = []
    limit_bytes = limit_mb * 1024 * 1024

    try:
        with open(mem_path, 'rb', buffering=0) as mem:
            for line in maps_text.splitlines():
                parts = line.split()
                if not parts:
                    continue
                if 'r' not in parts[1]:
                    continue  # skip non-readable regions
                perms = parts[1]
                if 'x' in perms:
                    continue  # skip executable (code) pages — too noisy
                try:
                    start_hex, end_hex = parts[0].split('-')
                    start = int(start_hex, 16)
                    end   = int(end_hex, 16)
                except ValueError:
                    continue

                region_size = end - start
                if region_size > limit_bytes:
                    region_size = limit_bytes

                try:
                    mem.seek(start)
                    chunk = mem.read(region_size)
                except (OSError, OverflowError):
                    continue

                for pat in patterns:
                    offset = chunk.find(pat)
                    if offset != -1:
                        findings.append(f'0x{start + offset:016x}')
    except (PermissionError, FileNotFoundError, OSError):
        pass

    return findings


# ---------------------------------------------------------------------------
# EBPFTracer
# ---------------------------------------------------------------------------

class EBPFTracer:
    """
    Linux eBPF tracer backend — production-grade kernel tracing engine.

    Strategy:
      1. If ``oi-ebpf-trace`` sidecar is on PATH and BTF is available, use it
         (full BPF object loading, ring buffer).
      2. Otherwise, fall back to pure-Python /proc tracing: syscall polling,
         TCP table cross-reference, FD scanning, and /proc/mem secret scanning.

    Offensive capabilities
    ----------------------
    - ``trace_syscalls()``           — poll current syscall for monitored pid
    - ``trace_network_events()``     — detect outbound connections via /proc/net/tcp
    - ``trace_fd_secrets()``         — detect secret-file reads via /proc/<pid>/fd
    - ``trace_process_spawn()``      — detect fork/exec child processes
    - ``verify_rce()``               — confirm RCE when execve traced after payload
    - ``detect_data_exfiltration()`` — write() on network FD after file read
    - ``confirm_ssrf()``             — connect() calls matching scan target
    - ``scan_memory_secrets()``      — /proc/<pid>/mem secret pattern scan
    - ``read_events()``              — unified non-blocking event stream (contract)
    - ``stop()``                     — idempotent teardown
    - ``is_available()``             — class-level capability check
    """

    def __init__(
        self,
        pid: int = 0,
        target: str | None = None,
        timeout: int = 0,
        target_host: str = '',
        *,
        targets: list[str] | None = None,
        filter_pid: int | None = None,
        filter_comm: str | None = None,
    ) -> None:
        # --- Backward-compatibility: accept single 'target' or list 'targets' ---
        if targets is not None:
            resolved_targets = list(targets)
        elif target is not None:
            resolved_targets = [target]
        else:
            resolved_targets = ['ssl']

        self.pid         = pid
        self.target      = resolved_targets[0]   # primary target (legacy attr)
        self.targets     = resolved_targets       # all requested programs
        self.timeout     = timeout
        self.target_host = target_host
        self.filter_pid  = filter_pid
        self.filter_comm = filter_comm
        self.session_id  = str(uuid.uuid4())

        self._proc: subprocess.Popen | None = None
        self._unavailable  = False
        self._stopped      = False
        self._use_sidecar  = False
        self._proc_fallback = False

        # Offensive state tracking
        self._file_reads: set[str] = set()     # paths read during session
        self._net_fds:    set[int] = set()     # FDs that are sockets
        self._seen_children: set[int] = set()  # child PIDs seen so far
        self._session_start = time.time()

        # Event subscription callbacks: event_type -> list[Callable[[dict], None]]
        self._subscribers: dict[str, list[Callable[[dict], None]]] = {}
        # Per-type event counters populated by read_events()
        self._event_counts: dict[str, int] = {}

        self._start()

    # ------------------------------------------------------------------
    # Internal startup
    # ------------------------------------------------------------------

    def _start(self) -> None:
        """Validate environment: try sidecar, then fall back to /proc."""
        if platform.system() != 'Linux':
            log.warning(
                'EBPFTracer requires Linux, current OS=%s — '
                'pid=%s target=%s session_id=%s using degraded mode',
                platform.system(), self.pid, self.target, self.session_id,
            )
            self._proc_fallback = True
            return

        if not _BTF_VMLINUX.exists():
            log.info(
                '%s absent — BTF unavailable; using /proc fallback '
                'pid=%s target=%s session_id=%s',
                _BTF_VMLINUX, self.pid, self.target, self.session_id,
            )
            self._proc_fallback = True
            return

        if shutil.which(_SIDECAR_BIN) is None:
            log.info(
                '%s not on PATH — using /proc fallback '
                'pid=%s target=%s session_id=%s',
                _SIDECAR_BIN, self.pid, self.target, self.session_id,
            )
            self._proc_fallback = True
            return

        cmd = [
            _SIDECAR_BIN,
            '--program', ','.join(self.targets),
            '--timeout', str(self.timeout),
        ]
        if self.filter_pid is not None and self.filter_pid > 0:
            cmd += ['--pid', str(self.filter_pid)]
        elif self.pid:
            cmd += ['--pid', str(self.pid)]
        if self.filter_comm:
            cmd += ['--filter-comm', self.filter_comm]

        try:
            self._proc = subprocess.Popen(
                cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                start_new_session=False,
            )
            self._use_sidecar = True
            log.info(
                '%s sidecar enabled pid=%s targets=%s session_id=%s',
                self.__class__.__name__, self.pid, self.targets, self.session_id,
            )
        except OSError as exc:
            log.warning(
                'Failed to launch %s: %s — using /proc fallback pid=%s targets=%s session_id=%s',
                _SIDECAR_BIN, exc, self.pid, self.targets, self.session_id,
            )
            self._proc_fallback = True

    # ------------------------------------------------------------------
    # Event construction helpers
    # ------------------------------------------------------------------

    def _event(
        self,
        syscall: str,
        data: str,
        verdict: str = '',
        extra: dict | None = None,
    ) -> dict:
        ev = {
            'schema_version': '1.0.0',
            'pid':            self.pid,
            'target':         self.target,
            'syscall':        syscall,
            'data':           data[:4096],
            'ts':             time.time(),
            'source_engine':  'ebpf',
            'session_id':     self.session_id,
        }
        if verdict:
            ev['verdict'] = verdict
        if extra:
            ev.update(extra)
        return ev

    def _parse_line(self, line: str) -> dict | None:
        """Parse a single NDJSON line from the sidecar, preserving the 'type' field."""
        line = line.strip()
        if not line:
            return None
        try:
            obj = json.loads(line)
        except json.JSONDecodeError:
            log.debug('EBPFTracer: unparseable line: %.120r', line)
            obj = {'data': line.encode().hex()}

        event = {
            'schema_version': '1.0.0',
            'pid':            int(obj.get('pid', self.pid)),
            'target':         str(obj.get('target', self.target)),
            'syscall':        str(obj.get('syscall', '')),
            'data':           str(obj.get('data', line.encode().hex()))[:4096],
            'ts':             float(obj.get('ts', time.time())),
            'source_engine':  'ebpf',
            'session_id':     self.session_id,
            'verdict':        str(obj.get('verdict', '')),
        }
        # Preserve 'type' from sidecar if present; derive from target otherwise.
        if 'type' in obj:
            event['type'] = str(obj['type'])
        else:
            event['type'] = event['target'] + '_event'
        return event

    # ------------------------------------------------------------------
    # Tracing methods — core offensive capabilities
    # ------------------------------------------------------------------

    def trace_syscalls(self) -> list[dict]:
        """
        Poll /proc/<pid>/syscall and emit an event for monitored syscalls.

        Monitored: openat, connect, execve, write, read, clone, fork, execveat.
        Returns [] when /proc is unavailable or syscall is unmonitored.
        """
        if not self._proc_path_exists():
            return []

        result = _current_syscall(self.pid)
        if result is None:
            return []

        nr, args = result
        name = _SYSCALL_NAMES.get(nr)
        if name is None:
            return []

        data = f'syscall={name} nr={nr} args={args[:6]}'
        verdict = ''

        if name in ('execve', 'execveat'):
            verdict = VERDICT_RCE_CONFIRMED
            log.warning(
                'RCE DETECTED: execve in pid=%s session_id=%s',
                self.pid, self.session_id,
            )
        elif name == 'connect':
            verdict = VERDICT_SSRF_CONFIRMED

        return [self._event(name, data, verdict)]

    def trace_network_events(self) -> list[dict]:
        """
        Capture outbound TCP connections from the target PID via /proc/net/tcp.

        Cross-references socket inodes between /proc/<pid>/fd and /proc/net/tcp.
        Returns one event per established or SYN_SENT connection.
        """
        if not self._proc_path_exists():
            return []

        events = []
        conns = _proc_connections(self.pid)
        for conn in conns:
            # TCP states: 1=ESTABLISHED, 2=SYN_SENT
            if conn['state'] not in (1, 2):
                continue
            remote = f"{conn['remote_addr']}:{conn['remote_port']}"
            verdict = ''
            if self.target_host and self.target_host in conn['remote_addr']:
                verdict = VERDICT_SSRF_CONFIRMED
            data = (
                f"connect {conn['local_addr']}:{conn['local_port']}"
                f" -> {remote} state={conn['state']}"
            )
            events.append(self._event('connect', data, verdict, extra={'remote': remote}))
        return events

    def trace_fd_secrets(self) -> list[dict]:
        """
        Detect secret file reads by examining /proc/<pid>/fd symlinks.

        Matches FD targets against known secret file patterns
        (keys, certs, .env, tokens, shadow, authorized_keys, etc.).
        Returns one event per newly discovered secret FD.
        """
        if not self._proc_path_exists():
            return []

        events = []
        fds = _open_fds(self.pid)
        for fd, target in fds.items():
            if _SECRET_PATTERNS.search(target) and target not in self._file_reads:
                self._file_reads.add(target)
                log.warning(
                    'SECRET FILE READ: pid=%s fd=%d path=%s session_id=%s',
                    self.pid, fd, target, self.session_id,
                )
                events.append(self._event(
                    'openat',
                    f'secret_file fd={fd} path={target}',
                    VERDICT_SECRET_READ,
                    extra={'fd': fd, 'path': target},
                ))
        return events

    def trace_process_spawn(self) -> list[dict]:
        """
        Detect child processes (fork/exec) via /proc/<pid>/task/<tid>/children.

        Compares against previously seen children — each new child is an event.
        This provides RCE verification: if a process spawns children after
        payload delivery, it indicates code execution.
        """
        if not self._proc_path_exists():
            return []

        events = []
        children = _list_children(self.pid)
        for child_pid in children:
            if child_pid not in self._seen_children:
                self._seen_children.add(child_pid)
                comm = _read_proc(_proc_path(child_pid) / 'comm') or ''
                comm = comm.strip()
                log.warning(
                    'CHILD PROCESS: pid=%s spawned child=%d comm=%s session_id=%s',
                    self.pid, child_pid, comm, self.session_id,
                )
                events.append(self._event(
                    'fork',
                    f'child_pid={child_pid} comm={comm}',
                    VERDICT_PROCESS_SPAWNED,
                    extra={'child_pid': child_pid, 'comm': comm},
                ))
        return events

    def verify_rce(self, check_window: float = 5.0) -> list[dict]:
        """
        Confirm RCE: poll for execve syscall within check_window seconds.

        If execve is currently executing in the target PID, emit a
        RCE_CONFIRMED verdict.  This is the primary RCE verification path.

        Args:
            check_window: seconds to poll for execve (non-blocking, single pass).

        Returns list of verdict events (may be empty if no execve detected).
        """
        if not self._proc_path_exists():
            return []

        result = _current_syscall(self.pid)
        if result is None:
            return []

        nr, args = result
        name = _SYSCALL_NAMES.get(nr, '')
        if name not in ('execve', 'execveat'):
            # Also check children that may have exec'd
            child_events = self.trace_process_spawn()
            return child_events

        data = f'execve confirmed at offset={time.time() - self._session_start:.3f}s args_ptr=0x{args[0]:x}'
        log.warning(
            'RCE CONFIRMED via execve: pid=%s session_id=%s',
            self.pid, self.session_id,
        )
        return [self._event('execve', data, VERDICT_RCE_CONFIRMED, extra={'args': args[:3]})]

    def detect_data_exfiltration(self) -> list[dict]:
        """
        Detect data exfiltration: write() on a network socket FD after secret file reads.

        Pattern: process reads a secret file (tracked in trace_fd_secrets), then
        writes to a network socket.  Both conditions must be true in the same session.

        Returns EXFIL verdict events when the pattern is matched.
        """
        if not self._proc_path_exists():
            return []

        # Must have seen at least one secret file read this session
        if not self._file_reads:
            return []

        # Check if any current FDs are sockets (network write target)
        fds = _open_fds(self.pid)
        socket_fds = [fd for fd, target in fds.items() if target.startswith('socket:')]

        if not socket_fds:
            return []

        # Check if process is currently in write() to a socket inode
        result = _current_syscall(self.pid)
        if result is None:
            return []
        nr, args = result
        name = _SYSCALL_NAMES.get(nr, '')

        if name != 'write':
            return []

        write_fd = args[0] if args else -1
        if write_fd not in socket_fds:
            return []

        secret_list = ', '.join(list(self._file_reads)[:5])
        data = (
            f'write fd={write_fd} socket after reading secrets: {secret_list}'
        )
        log.warning(
            'DATA EXFILTRATION: pid=%s writing to socket fd=%d after reading secrets session_id=%s',
            self.pid, write_fd, self.session_id,
        )
        return [self._event('write', data, VERDICT_EXFIL_DETECTED,
                            extra={'socket_fd': write_fd, 'secret_files': list(self._file_reads)})]

    def confirm_ssrf(self, target_cidrs: list[str] | None = None) -> list[dict]:
        """
        Confirm blind SSRF by tracing connect() calls from the target process.

        Matches outbound connections against:
          1. self.target_host (set at construction)
          2. target_cidrs (optional list of CIDR strings or IP prefixes)

        Returns SSRF_CONFIRMED events for matching connections.
        """
        if not self._proc_path_exists():
            return []

        events = []
        conns = _proc_connections(self.pid)
        for conn in conns:
            remote_ip = conn['remote_addr']
            matched = False

            if self.target_host and self.target_host in remote_ip:
                matched = True

            if not matched and target_cidrs:
                for cidr in target_cidrs:
                    if remote_ip.startswith(cidr):
                        matched = True
                        break

            if matched:
                remote = f"{remote_ip}:{conn['remote_port']}"
                data = f'ssrf_connect -> {remote} state={conn["state"]}'
                log.warning(
                    'SSRF CONFIRMED: pid=%s connect to %s session_id=%s',
                    self.pid, remote, self.session_id,
                )
                events.append(self._event('connect', data, VERDICT_SSRF_CONFIRMED,
                                          extra={'remote': remote}))
        return events

    def scan_memory_secrets(
        self,
        patterns: list[bytes] | None = None,
        limit_mb: int = 32,
    ) -> list[dict]:
        """
        Scan /proc/<pid>/mem for in-memory secrets.

        Default patterns: common API key prefixes, PEM headers, AWS tokens.
        Requires read access to /proc/<pid>/mem (typically needs ptrace or
        same UID, or CAP_SYS_PTRACE).

        Args:
            patterns: list of byte patterns to search for.
            limit_mb: max bytes to scan per memory region (default 32 MB).

        Returns list of events with memory offsets where patterns matched.
        """
        if not self._proc_path_exists():
            return []

        if patterns is None:
            patterns = [
                b'-----BEGIN RSA PRIVATE KEY-----',
                b'-----BEGIN EC PRIVATE KEY-----',
                b'-----BEGIN PRIVATE KEY-----',
                b'AKIA',             # AWS access key prefix
                b'AIza',             # Google API key prefix
                b'ghp_',            # GitHub personal token
                b'xoxb-',           # Slack bot token
                b'password=',
                b'secret=',
                b'api_key=',
                b'Authorization: Bearer ',
            ]

        findings = _scan_mem_for_secrets(self.pid, patterns, limit_mb)
        if not findings:
            return []

        data = f'memory_secrets count={len(findings)} offsets={findings[:10]}'
        log.warning(
            'MEMORY SECRETS: pid=%s found %d hits session_id=%s',
            self.pid, len(findings), self.session_id,
        )
        return [self._event(
            'mem_scan',
            data,
            VERDICT_SECRET_READ,
            extra={'offsets': findings[:50], 'pattern_count': len(patterns)},
        )]

    # ------------------------------------------------------------------
    # Public API (TRACER_CONTRACT.md §2)
    # ------------------------------------------------------------------

    def read_events(self) -> list[dict]:
        """
        Non-blocking read of events from the active backend.

        Sidecar path: reads one NDJSON line from the sidecar stdout.
        Fallback path: runs all /proc tracing methods and returns all events.

        Events include a 'type' field (e.g. 'ssl_event', 'net_event', …).
        Subscribed callbacks registered via subscribe() are invoked per event.

        Returns [] on timeout, EOF, or if the backend is unavailable.
        """
        if self._stopped:
            return []

        events: list[dict] = []

        # --- Sidecar path ---
        if self._use_sidecar and self._proc is not None:
            try:
                if _HAS_SELECT:
                    ready, _, _ = _select.select([self._proc.stdout], [], [], 0.1)
                    if not ready:
                        return []
                line = self._proc.stdout.readline()
            except OSError as exc:
                log.debug('read_events OSError: %s', exc)
                return []

            if not line:
                return []

            event = self._parse_line(line)
            if event is None:
                return []
            events = [event]

        # --- /proc fallback path ---
        elif self._proc_fallback or platform.system() != 'Linux':
            if platform.system() != 'Linux':
                return []
            events = []
            events.extend(self.trace_syscalls())
            events.extend(self.trace_network_events())
            events.extend(self.trace_fd_secrets())
            events.extend(self.trace_process_spawn())
            events.extend(self.detect_data_exfiltration())

        # Update per-type counters and dispatch to subscribers.
        for ev in events:
            etype = ev.get('type', ev.get('target', '') + '_event')
            self._event_counts[etype] = self._event_counts.get(etype, 0) + 1
            for cb in self._subscribers.get(etype, []):
                try:
                    cb(ev)
                except Exception as exc:  # pragma: no cover
                    log.debug('subscribe callback error type=%s: %s', etype, exc)

        return events

    def subscribe(self, event_type: str, callback: Callable[[dict], None]) -> None:
        """
        Register a callback invoked for every event of the given type.

        Args:
            event_type: one of 'ssl_event', 'net_event', 'key_event',
                        'syscall_event', 'inject_event', or any custom type.
            callback:   callable receiving the event dict; exceptions are
                        swallowed and logged at DEBUG level.

        Multiple callbacks for the same type are supported and invoked
        in registration order.
        """
        self._subscribers.setdefault(event_type, []).append(callback)

    def get_stats(self) -> dict:
        """
        Return event counts by type accumulated since construction.

        Returns:
            dict mapping event-type strings to non-negative integers,
            e.g. {'ssl_event': 42, 'net_event': 7}.
        """
        return dict(self._event_counts)

    def stop(self) -> None:
        """Terminate the sidecar process (idempotent)."""
        if self._stopped:
            log.debug(
                '%s.stop() called but already stopped session_id=%s',
                self.__class__.__name__, self.session_id,
            )
            return
        self._stopped = True
        if self._proc is not None:
            try:
                self._proc.terminate()
                self._proc.wait(timeout=5)
            except (OSError, subprocess.TimeoutExpired) as exc:
                log.debug('stop() warning: %s', exc)
                try:
                    self._proc.kill()
                except OSError:
                    pass
        log.info(
            '%s disabled pid=%s target=%s session_id=%s',
            self.__class__.__name__, self.pid, self.target, self.session_id,
        )

    def __del__(self) -> None:
        self.stop()

    # ------------------------------------------------------------------
    # Internal utilities
    # ------------------------------------------------------------------

    def _proc_path_exists(self) -> bool:
        """Return True iff /proc/<pid> exists (process is alive)."""
        return _proc_path(self.pid).exists()

    # ------------------------------------------------------------------
    # Class-level capability check
    # ------------------------------------------------------------------

    @classmethod
    def is_available(cls) -> bool:
        """
        Return True iff this host can run the eBPF backend:
        - OS must be Linux
        - /sys/kernel/btf/vmlinux must exist (for sidecar path)
        OR
        - /proc filesystem is available (for fallback path)
        """
        try:
            if platform.system() != 'Linux':
                return False
            # Fallback path always available on Linux
            return _PROC_ROOT.exists()
        except Exception:  # pragma: no cover
            return False

    @classmethod
    def is_sidecar_available(cls) -> bool:
        """Return True iff the full BPF sidecar path is available."""
        try:
            if platform.system() != 'Linux':
                return False
            if not _BTF_VMLINUX.exists():
                return False
            return shutil.which(_SIDECAR_BIN) is not None
        except Exception:  # pragma: no cover
            return False

    # ------------------------------------------------------------------
    # Async-safe interface
    # ------------------------------------------------------------------

    async def async_read_events(self) -> list[dict]:
        """
        Async-safe wrapper around read_events().

        Delegates the blocking /proc poll to a thread pool so it never
        stalls the event loop.  Always returns a list (may be empty).
        """
        try:
            return await asyncio.to_thread(self.read_events)
        except Exception as exc:
            log.debug('async_read_events error: %s', exc)
            return []

    async def store_events_to_db(self, events: list[dict], scan_id: str = '') -> int:
        """
        Persist eBPF/proc events as findings in the DB via db_manager.

        Each event is stored as a finding with:
          - vuln_type: event['type'] or 'ebpf_event'
          - severity: 'critical' for verdict events, else 'info'
          - tool: 'ebpf_tracer'
          - source_type: 'ebpf'

        Returns the count of events successfully stored.
        """
        if not events:
            return 0
        try:
            from oneinfinity.core.db_manager import get_db_manager
            db = await get_db_manager()
        except Exception as exc:
            log.debug('store_events_to_db: db_manager unavailable: %s', exc)
            return 0

        stored = 0
        for ev in events:
            verdict = ev.get('verdict', '')
            severity = 'critical' if verdict else 'info'
            finding = {
                'scan_id':     scan_id or ev.get('session_id', ''),
                'target':      ev.get('target', self.target),
                'title':       f"eBPF event: {ev.get('syscall', ev.get('type', 'unknown'))}",
                'severity':    severity,
                'vuln_type':   ev.get('type', 'ebpf_event'),
                'url':         '',
                'tool':        'ebpf_tracer',
                'confidence':  0.9 if verdict else 0.6,
                'source_type': 'ebpf',
                'evidence':    ev.get('data', ''),
                'raw_json':    json.dumps(ev),
            }
            if verdict:
                finding['title'] = f"eBPF VERDICT: {verdict}"
            try:
                await db.save_finding(finding)
                stored += 1
            except Exception as exc:
                log.debug('store_events_to_db: save_finding failed: %s', exc)
        if stored:
            log.info(
                'EBPFTracer: stored %d events to DB session_id=%s',
                stored, self.session_id,
            )
        return stored
