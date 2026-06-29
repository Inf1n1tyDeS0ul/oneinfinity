"""
test_phase5_ebpf.py — Phase 5 eBPF tracer tests.

Covers:
  - Platform dispatch via StealthTracer
  - Graceful degradation when sidecar/BTF unavailable
  - All EBPFTracer offensive capability methods (no-op on non-Linux)
  - RCE verification via execve trace
  - /proc helper functions (mocked for portability)
  - Event schema conformance
  - Memory secret scanning (mocked)
"""

from __future__ import annotations

import os
import pathlib
import platform
import sys
import types
import unittest
from unittest.mock import MagicMock, patch, PropertyMock

# Make src importable
_REPO_ROOT = pathlib.Path(__file__).parent.parent
sys.path.insert(0, str(_REPO_ROOT / 'src'))

from oneinfinity.core.ebpf_tracer import (
    EBPFTracer,
    VERDICT_RCE_CONFIRMED,
    VERDICT_SSRF_CONFIRMED,
    VERDICT_SECRET_READ,
    VERDICT_EXFIL_DETECTED,
    VERDICT_PROCESS_SPAWNED,
    _current_syscall,
    _list_children,
    _open_fds,
    _parse_tcp_table,
    _scan_mem_for_secrets,
    _SECRET_PATTERNS,
    _SYSCALL_NAMES,
)
from oneinfinity.core.stealth_tracer import (
    StealthTracer,
    TracerUnavailableError,
    _CAPS,
    _Caps,
)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

_IS_LINUX = platform.system() == 'Linux'
_IS_DARWIN = platform.system() == 'Darwin'


def _make_tracer(pid: int = 99999, target: str = 'ssl', timeout: int = 5) -> EBPFTracer:
    """Construct an EBPFTracer that always uses /proc fallback."""
    with patch('oneinfinity.core.ebpf_tracer.shutil.which', return_value=None), \
         patch('oneinfinity.core.ebpf_tracer._BTF_VMLINUX') as mock_btf:
        mock_btf.exists.return_value = False
        t = EBPFTracer(pid=pid, target=target, timeout=timeout)
    return t


# ---------------------------------------------------------------------------
# 1. Module importability
# ---------------------------------------------------------------------------

class TestImport:
    def test_ebpf_tracer_importable(self):
        import oneinfinity.core.ebpf_tracer as m
        assert hasattr(m, 'EBPFTracer')

    def test_stealth_tracer_importable(self):
        import oneinfinity.core.stealth_tracer as m
        assert hasattr(m, 'StealthTracer')

    def test_verdict_constants_defined(self):
        assert VERDICT_RCE_CONFIRMED == 'RCE_CONFIRMED'
        assert VERDICT_SSRF_CONFIRMED == 'SSRF_CONFIRMED'
        assert VERDICT_SECRET_READ == 'SECRET_FILE_READ'
        assert VERDICT_EXFIL_DETECTED == 'DATA_EXFILTRATION'
        assert VERDICT_PROCESS_SPAWNED == 'CHILD_PROCESS_SPAWNED'


class _TestImport(unittest.TestCase, TestImport):
    pass


# ---------------------------------------------------------------------------
# 2. EBPFTracer construction and graceful degradation
# ---------------------------------------------------------------------------

class TestEBPFTracerConstruction(unittest.TestCase):
    def test_unavailable_sidecar_uses_proc_fallback(self):
        """When sidecar absent, _proc_fallback=True and _use_sidecar=False."""
        t = _make_tracer()
        assert t._proc_fallback is True
        assert t._use_sidecar is False

    def test_session_id_unique(self):
        t1 = _make_tracer()
        t2 = _make_tracer()
        assert t1.session_id != t2.session_id

    def test_stop_idempotent(self):
        t = _make_tracer()
        t.stop()
        t.stop()  # Must not raise

    def test_read_events_stopped_returns_empty(self):
        t = _make_tracer()
        t.stop()
        assert t.read_events() == []

    def test_non_linux_sets_proc_fallback(self):
        with patch('oneinfinity.core.ebpf_tracer.platform.system', return_value='Darwin'):
            t = EBPFTracer(pid=1, target='ssl', timeout=5)
        assert t._proc_fallback is True
        assert t._use_sidecar is False


# ---------------------------------------------------------------------------
# 3. EBPFTracer.is_available()
# ---------------------------------------------------------------------------

class TestEBPFTracerAvailability(unittest.TestCase):
    def test_non_linux_not_available(self):
        with patch('oneinfinity.core.ebpf_tracer.platform.system', return_value='Darwin'):
            assert EBPFTracer.is_available() is False

    def test_linux_with_proc_is_available(self):
        with patch('oneinfinity.core.ebpf_tracer.platform.system', return_value='Linux'), \
             patch('oneinfinity.core.ebpf_tracer._PROC_ROOT') as mock_proc:
            mock_proc.exists.return_value = True
            assert EBPFTracer.is_available() is True

    def test_sidecar_available_checks_btf_and_binary(self):
        with patch('oneinfinity.core.ebpf_tracer.platform.system', return_value='Linux'), \
             patch('oneinfinity.core.ebpf_tracer._BTF_VMLINUX') as mock_btf, \
             patch('oneinfinity.core.ebpf_tracer.shutil.which', return_value='/usr/bin/oi-ebpf-trace'):
            mock_btf.exists.return_value = True
            assert EBPFTracer.is_sidecar_available() is True

    def test_sidecar_unavailable_when_btf_missing(self):
        with patch('oneinfinity.core.ebpf_tracer.platform.system', return_value='Linux'), \
             patch('oneinfinity.core.ebpf_tracer._BTF_VMLINUX') as mock_btf:
            mock_btf.exists.return_value = False
            assert EBPFTracer.is_sidecar_available() is False


# ---------------------------------------------------------------------------
# 4. Event schema conformance
# ---------------------------------------------------------------------------

REQUIRED_SCHEMA_KEYS = {
    'schema_version', 'pid', 'target', 'data', 'ts', 'source_engine', 'session_id',
}

class TestEventSchema(unittest.TestCase):
    def _make_event(self, **kwargs):
        t = _make_tracer()
        return t._event('execve', 'test data', **kwargs)

    def test_event_has_required_keys(self):
        ev = self._make_event()
        for key in REQUIRED_SCHEMA_KEYS:
            assert key in ev, f'Missing key: {key}'

    def test_schema_version(self):
        ev = self._make_event()
        assert ev['schema_version'] == '1.0.0'

    def test_source_engine(self):
        ev = self._make_event()
        assert ev['source_engine'] == 'ebpf'

    def test_data_capped_at_4096(self):
        t = _make_tracer()
        ev = t._event('read', 'x' * 10000)
        assert len(ev['data']) <= 4096

    def test_verdict_present_when_set(self):
        ev = self._make_event(verdict=VERDICT_RCE_CONFIRMED)
        assert ev['verdict'] == VERDICT_RCE_CONFIRMED


# ---------------------------------------------------------------------------
# 5. trace_syscalls() — with mocked /proc/pid/syscall
# ---------------------------------------------------------------------------

class TestTraceSyscalls(unittest.TestCase):
    def _tracer_with_proc(self, pid=1234):
        t = _make_tracer(pid=pid)
        return t

    def test_execve_syscall_returns_rce_verdict(self):
        t = self._tracer_with_proc()
        # execve = syscall 59
        with patch('oneinfinity.core.ebpf_tracer._current_syscall', return_value=(59, [0] * 6)), \
             patch.object(t, '_proc_path_exists', return_value=True):
            events = t.trace_syscalls()
        assert len(events) == 1
        assert events[0]['verdict'] == VERDICT_RCE_CONFIRMED
        assert events[0]['syscall'] == 'execve'

    def test_connect_syscall_returns_ssrf_verdict(self):
        t = self._tracer_with_proc()
        # connect = syscall 42
        with patch('oneinfinity.core.ebpf_tracer._current_syscall', return_value=(42, [3, 0, 16, 0, 0, 0])), \
             patch.object(t, '_proc_path_exists', return_value=True):
            events = t.trace_syscalls()
        assert len(events) == 1
        assert events[0]['verdict'] == VERDICT_SSRF_CONFIRMED
        assert events[0]['syscall'] == 'connect'

    def test_unmonitored_syscall_returns_empty(self):
        t = self._tracer_with_proc()
        # syscall 999 — not in _SYSCALL_NAMES
        with patch('oneinfinity.core.ebpf_tracer._current_syscall', return_value=(999, [])), \
             patch.object(t, '_proc_path_exists', return_value=True):
            events = t.trace_syscalls()
        assert events == []

    def test_dead_process_returns_empty(self):
        t = self._tracer_with_proc()
        with patch.object(t, '_proc_path_exists', return_value=False):
            events = t.trace_syscalls()
        assert events == []

    def test_no_syscall_data_returns_empty(self):
        t = self._tracer_with_proc()
        with patch('oneinfinity.core.ebpf_tracer._current_syscall', return_value=None), \
             patch.object(t, '_proc_path_exists', return_value=True):
            events = t.trace_syscalls()
        assert events == []


# ---------------------------------------------------------------------------
# 6. trace_network_events() — TCP connection tracing
# ---------------------------------------------------------------------------

class TestTraceNetworkEvents(unittest.TestCase):
    def test_established_connection_emits_event(self):
        t = _make_tracer()
        conn = {
            'local_addr': '10.0.0.1', 'local_port': 54321,
            'remote_addr': '1.2.3.4', 'remote_port': 443,
            'state': 1,  # ESTABLISHED
            'inode': 12345,
        }
        with patch('oneinfinity.core.ebpf_tracer._proc_connections', return_value=[conn]), \
             patch.object(t, '_proc_path_exists', return_value=True):
            events = t.trace_network_events()
        assert len(events) == 1
        assert 'connect' == events[0]['syscall']
        assert '1.2.3.4' in events[0]['data']

    def test_target_host_match_adds_ssrf_verdict(self):
        t = _make_tracer()
        t.target_host = '192.168.1.100'
        conn = {
            'local_addr': '10.0.0.1', 'local_port': 55555,
            'remote_addr': '192.168.1.100', 'remote_port': 80,
            'state': 1, 'inode': 1,
        }
        with patch('oneinfinity.core.ebpf_tracer._proc_connections', return_value=[conn]), \
             patch.object(t, '_proc_path_exists', return_value=True):
            events = t.trace_network_events()
        assert events[0]['verdict'] == VERDICT_SSRF_CONFIRMED

    def test_non_established_state_skipped(self):
        t = _make_tracer()
        conn = {
            'local_addr': '10.0.0.1', 'local_port': 55555,
            'remote_addr': '8.8.8.8', 'remote_port': 53,
            'state': 6,  # TIME_WAIT — not 1 or 2
            'inode': 2,
        }
        with patch('oneinfinity.core.ebpf_tracer._proc_connections', return_value=[conn]), \
             patch.object(t, '_proc_path_exists', return_value=True):
            events = t.trace_network_events()
        assert events == []

    def test_no_connections_returns_empty(self):
        t = _make_tracer()
        with patch('oneinfinity.core.ebpf_tracer._proc_connections', return_value=[]), \
             patch.object(t, '_proc_path_exists', return_value=True):
            events = t.trace_network_events()
        assert events == []


# ---------------------------------------------------------------------------
# 7. trace_fd_secrets() — secret file detection
# ---------------------------------------------------------------------------

class TestTraceFdSecrets(unittest.TestCase):
    def test_pem_key_triggers_verdict(self):
        t = _make_tracer()
        fds = {3: '/home/user/.ssh/id_rsa', 4: '/tmp/test.txt'}
        with patch('oneinfinity.core.ebpf_tracer._open_fds', return_value=fds), \
             patch.object(t, '_proc_path_exists', return_value=True):
            events = t.trace_fd_secrets()
        assert len(events) == 1
        assert events[0]['verdict'] == VERDICT_SECRET_READ
        assert 'id_rsa' in events[0]['data']

    def test_env_file_triggers_verdict(self):
        t = _make_tracer()
        fds = {5: '/app/.env'}
        with patch('oneinfinity.core.ebpf_tracer._open_fds', return_value=fds), \
             patch.object(t, '_proc_path_exists', return_value=True):
            events = t.trace_fd_secrets()
        assert events[0]['verdict'] == VERDICT_SECRET_READ

    def test_already_seen_not_repeated(self):
        t = _make_tracer()
        t._file_reads.add('/etc/shadow')
        fds = {6: '/etc/shadow'}
        with patch('oneinfinity.core.ebpf_tracer._open_fds', return_value=fds), \
             patch.object(t, '_proc_path_exists', return_value=True):
            events = t.trace_fd_secrets()
        assert events == []

    def test_non_secret_file_ignored(self):
        t = _make_tracer()
        fds = {7: '/tmp/output.txt', 8: '/usr/lib/libssl.so'}
        with patch('oneinfinity.core.ebpf_tracer._open_fds', return_value=fds), \
             patch.object(t, '_proc_path_exists', return_value=True):
            events = t.trace_fd_secrets()
        assert events == []

    def test_multiple_secret_fds(self):
        t = _make_tracer()
        fds = {3: '/app/.env', 4: '/etc/shadow', 5: '/tmp/ok.txt'}
        with patch('oneinfinity.core.ebpf_tracer._open_fds', return_value=fds), \
             patch.object(t, '_proc_path_exists', return_value=True):
            events = t.trace_fd_secrets()
        assert len(events) == 2


# ---------------------------------------------------------------------------
# 8. trace_process_spawn() — child process detection
# ---------------------------------------------------------------------------

class TestTraceProcessSpawn(unittest.TestCase):
    def test_new_child_emits_event(self):
        t = _make_tracer()
        with patch('oneinfinity.core.ebpf_tracer._list_children', return_value=[5678]), \
             patch('oneinfinity.core.ebpf_tracer._read_proc', return_value='bash\n'), \
             patch.object(t, '_proc_path_exists', return_value=True):
            events = t.trace_process_spawn()
        assert len(events) == 1
        assert events[0]['verdict'] == VERDICT_PROCESS_SPAWNED
        assert events[0]['extra']['child_pid'] == 5678 if 'extra' in events[0] else \
               '5678' in events[0]['data']

    def test_already_seen_child_not_repeated(self):
        t = _make_tracer()
        t._seen_children.add(5678)
        with patch('oneinfinity.core.ebpf_tracer._list_children', return_value=[5678]), \
             patch.object(t, '_proc_path_exists', return_value=True):
            events = t.trace_process_spawn()
        assert events == []

    def test_no_children_returns_empty(self):
        t = _make_tracer()
        with patch('oneinfinity.core.ebpf_tracer._list_children', return_value=[]), \
             patch.object(t, '_proc_path_exists', return_value=True):
            events = t.trace_process_spawn()
        assert events == []


# ---------------------------------------------------------------------------
# 9. verify_rce() — RCE confirmation
# ---------------------------------------------------------------------------

class TestVerifyRCE(unittest.TestCase):
    def test_execve_confirms_rce(self):
        """If target PID is in execve syscall, verify_rce returns RCE_CONFIRMED."""
        t = _make_tracer()
        # syscall 59 = execve
        with patch('oneinfinity.core.ebpf_tracer._current_syscall', return_value=(59, [0xABCD, 0, 0])), \
             patch.object(t, '_proc_path_exists', return_value=True):
            events = t.verify_rce()
        assert len(events) == 1
        assert events[0]['verdict'] == VERDICT_RCE_CONFIRMED

    def test_execveat_also_confirms_rce(self):
        """execveat (322) is also an RCE indicator."""
        t = _make_tracer()
        with patch('oneinfinity.core.ebpf_tracer._current_syscall', return_value=(322, [0, 0, 0])), \
             patch.object(t, '_proc_path_exists', return_value=True):
            events = t.verify_rce()
        assert len(events) == 1
        assert events[0]['verdict'] == VERDICT_RCE_CONFIRMED

    def test_non_execve_falls_through_to_spawn_check(self):
        """Non-execve syscall defers to trace_process_spawn."""
        t = _make_tracer()
        with patch('oneinfinity.core.ebpf_tracer._current_syscall', return_value=(1, [])), \
             patch.object(t, '_proc_path_exists', return_value=True), \
             patch.object(t, 'trace_process_spawn', return_value=[]) as mock_spawn:
            events = t.verify_rce()
        mock_spawn.assert_called_once()

    def test_dead_process_returns_empty(self):
        t = _make_tracer()
        with patch.object(t, '_proc_path_exists', return_value=False):
            events = t.verify_rce()
        assert events == []


# ---------------------------------------------------------------------------
# 10. detect_data_exfiltration()
# ---------------------------------------------------------------------------

class TestDataExfiltration(unittest.TestCase):
    def test_write_to_socket_after_secret_read(self):
        t = _make_tracer()
        t._file_reads.add('/etc/shadow')
        fds = {3: 'socket:[12345]', 4: '/etc/shadow'}
        # write() = syscall 1, fd=3 (socket)
        with patch('oneinfinity.core.ebpf_tracer._open_fds', return_value=fds), \
             patch('oneinfinity.core.ebpf_tracer._current_syscall', return_value=(1, [3, 0, 0])), \
             patch.object(t, '_proc_path_exists', return_value=True):
            events = t.detect_data_exfiltration()
        assert len(events) == 1
        assert events[0]['verdict'] == VERDICT_EXFIL_DETECTED

    def test_no_secret_reads_returns_empty(self):
        t = _make_tracer()
        # _file_reads is empty
        with patch.object(t, '_proc_path_exists', return_value=True):
            events = t.detect_data_exfiltration()
        assert events == []

    def test_write_to_non_socket_returns_empty(self):
        t = _make_tracer()
        t._file_reads.add('/etc/passwd')
        fds = {3: '/tmp/file.txt'}  # not a socket
        with patch('oneinfinity.core.ebpf_tracer._open_fds', return_value=fds), \
             patch('oneinfinity.core.ebpf_tracer._current_syscall', return_value=(1, [3, 0, 0])), \
             patch.object(t, '_proc_path_exists', return_value=True):
            events = t.detect_data_exfiltration()
        assert events == []


# ---------------------------------------------------------------------------
# 11. confirm_ssrf()
# ---------------------------------------------------------------------------

class TestConfirmSSRF(unittest.TestCase):
    def test_target_host_match_confirms_ssrf(self):
        t = _make_tracer()
        t.target_host = '10.0.0.1'
        conn = {
            'local_addr': '172.16.0.1', 'local_port': 49000,
            'remote_addr': '10.0.0.1', 'remote_port': 8080,
            'state': 1, 'inode': 1,
        }
        with patch('oneinfinity.core.ebpf_tracer._proc_connections', return_value=[conn]), \
             patch.object(t, '_proc_path_exists', return_value=True):
            events = t.confirm_ssrf()
        assert len(events) == 1
        assert events[0]['verdict'] == VERDICT_SSRF_CONFIRMED

    def test_cidr_prefix_match(self):
        t = _make_tracer()
        conn = {
            'local_addr': '172.16.0.1', 'local_port': 49001,
            'remote_addr': '192.168.100.50', 'remote_port': 80,
            'state': 2, 'inode': 2,
        }
        with patch('oneinfinity.core.ebpf_tracer._proc_connections', return_value=[conn]), \
             patch.object(t, '_proc_path_exists', return_value=True):
            events = t.confirm_ssrf(target_cidrs=['192.168.'])
        assert events[0]['verdict'] == VERDICT_SSRF_CONFIRMED

    def test_no_match_returns_empty(self):
        t = _make_tracer()
        t.target_host = '10.0.0.1'
        conn = {
            'local_addr': '172.16.0.1', 'local_port': 49002,
            'remote_addr': '8.8.8.8', 'remote_port': 443,
            'state': 1, 'inode': 3,
        }
        with patch('oneinfinity.core.ebpf_tracer._proc_connections', return_value=[conn]), \
             patch.object(t, '_proc_path_exists', return_value=True):
            events = t.confirm_ssrf()
        assert events == []


# ---------------------------------------------------------------------------
# 12. scan_memory_secrets()
# ---------------------------------------------------------------------------

class TestScanMemorySecrets(unittest.TestCase):
    def test_returns_empty_when_process_dead(self):
        t = _make_tracer()
        with patch.object(t, '_proc_path_exists', return_value=False):
            events = t.scan_memory_secrets()
        assert events == []

    def test_finding_emits_secret_verdict(self):
        t = _make_tracer()
        with patch('oneinfinity.core.ebpf_tracer._scan_mem_for_secrets',
                   return_value=['0x00007f1234560000']), \
             patch.object(t, '_proc_path_exists', return_value=True):
            events = t.scan_memory_secrets()
        assert len(events) == 1
        assert events[0]['verdict'] == VERDICT_SECRET_READ
        assert 'memory_secrets' in events[0]['data']

    def test_no_findings_returns_empty(self):
        t = _make_tracer()
        with patch('oneinfinity.core.ebpf_tracer._scan_mem_for_secrets', return_value=[]), \
             patch.object(t, '_proc_path_exists', return_value=True):
            events = t.scan_memory_secrets()
        assert events == []

    def test_custom_patterns_passed_through(self):
        t = _make_tracer()
        patterns = [b'MYTOKEN']
        with patch('oneinfinity.core.ebpf_tracer._scan_mem_for_secrets',
                   return_value=['0xdeadbeef']) as mock_scan, \
             patch.object(t, '_proc_path_exists', return_value=True):
            t.scan_memory_secrets(patterns=patterns)
        mock_scan.assert_called_once_with(t.pid, patterns, 32)


# ---------------------------------------------------------------------------
# 13. StealthTracer platform dispatch
# ---------------------------------------------------------------------------

class TestStealthTracerDispatch(unittest.TestCase):
    def test_is_available_returns_bool(self):
        result = StealthTracer.is_available()
        assert isinstance(result, bool)

    def test_backend_info_returns_dict(self):
        info = StealthTracer.backend_info()
        assert isinstance(info, dict)
        assert 'os' in info
        assert 'available' in info
        assert info['available'] == StealthTracer.is_available()

    def test_linux_dispatch_returns_ebpf_tracer(self):
        """On Linux (mocked), StealthTracer must return an EBPFTracer."""
        with patch('oneinfinity.core.stealth_tracer._CAPS') as mock_caps:
            mock_caps.os_name = 'Linux'
            mock_caps.has_frida = False
            mock_caps.ebpf_full = False
            mock_caps.ebpf_proc = True
            mock_caps.linux_fallback_available = True
            with patch('oneinfinity.core.stealth_tracer._build_linux_tracer') as mock_build:
                mock_tracer = MagicMock()
                mock_tracer.session_id = 'test-session'
                mock_build.return_value = mock_tracer
                tracer = StealthTracer(pid=1, target='ssl', timeout=5)
            mock_build.assert_called_once_with(1, 'ssl', 5, '')

    def test_darwin_dispatch_returns_frida_tracer(self):
        """On Darwin (mocked), StealthTracer must call _build_darwin_tracer."""
        with patch('oneinfinity.core.stealth_tracer._CAPS') as mock_caps:
            mock_caps.os_name = 'Darwin'
            mock_caps.has_frida = True
            mock_caps.has_dtrace = True
            with patch('oneinfinity.core.stealth_tracer._build_darwin_tracer') as mock_build:
                mock_tracer = MagicMock()
                mock_tracer.session_id = 'darwin-session'
                mock_build.return_value = mock_tracer
                tracer = StealthTracer(pid=2, target='ssl', timeout=5)
            mock_build.assert_called_once()

    def test_unknown_os_raises(self):
        with patch('oneinfinity.core.stealth_tracer._CAPS') as mock_caps:
            mock_caps.os_name = 'Windows'
            with self.assertRaises(TracerUnavailableError):
                StealthTracer(pid=1, target='ssl', timeout=5)

    def test_is_available_linux_with_proc(self):
        with patch('oneinfinity.core.stealth_tracer._CAPS') as mock_caps:
            mock_caps.os_name = 'Linux'
            mock_caps.ebpf_full = False
            mock_caps.ebpf_proc = True
            assert StealthTracer.is_available() is True

    def test_is_available_darwin_with_frida(self):
        with patch('oneinfinity.core.stealth_tracer._CAPS') as mock_caps:
            mock_caps.os_name = 'Darwin'
            mock_caps.frida_primary = True
            mock_caps.has_dtrace = False
            assert StealthTracer.is_available() is True

    def test_is_available_false_on_no_capabilities(self):
        with patch('oneinfinity.core.stealth_tracer._CAPS') as mock_caps:
            mock_caps.os_name = 'Linux'
            mock_caps.ebpf_full = False
            mock_caps.ebpf_proc = False
            assert StealthTracer.is_available() is False


# ---------------------------------------------------------------------------
# 14. Graceful degradation: read_events on non-Linux
# ---------------------------------------------------------------------------

class TestGracefulDegradation(unittest.TestCase):
    def test_read_events_returns_empty_on_non_linux(self):
        """EBPFTracer on non-Linux must return [] from read_events, never raise."""
        with patch('oneinfinity.core.ebpf_tracer.platform.system', return_value='Darwin'):
            t = EBPFTracer(pid=1, target='ssl', timeout=5)
        events = t.read_events()
        assert events == []

    def test_all_trace_methods_return_empty_when_dead_proc(self):
        """All trace methods return [] gracefully when the process doesn't exist."""
        t = _make_tracer(pid=99999999)
        with patch.object(t, '_proc_path_exists', return_value=False):
            assert t.trace_syscalls() == []
            assert t.trace_network_events() == []
            assert t.trace_fd_secrets() == []
            assert t.trace_process_spawn() == []
            assert t.verify_rce() == []
            assert t.detect_data_exfiltration() == []
            assert t.confirm_ssrf() == []
            assert t.scan_memory_secrets() == []

    def test_stopped_tracer_read_events_empty(self):
        t = _make_tracer()
        t.stop()
        assert t.read_events() == []


# ---------------------------------------------------------------------------
# 15. /proc helper unit tests
# ---------------------------------------------------------------------------

class TestProcHelpers(unittest.TestCase):
    def test_current_syscall_parses_valid_line(self):
        text = '59 0x7fff1234 0x0 0x0 0x0 0x0 0x0 0x7fff5678\n'
        with patch('oneinfinity.core.ebpf_tracer._read_proc', return_value=text):
            result = _current_syscall(1234)
        assert result is not None
        nr, args = result
        assert nr == 59
        assert len(args) == 6

    def test_current_syscall_returns_none_for_running(self):
        with patch('oneinfinity.core.ebpf_tracer._read_proc', return_value='running\n'):
            result = _current_syscall(1234)
        assert result is None

    def test_current_syscall_returns_none_for_empty(self):
        with patch('oneinfinity.core.ebpf_tracer._read_proc', return_value=None):
            result = _current_syscall(1234)
        assert result is None

    def test_secret_patterns_match_known_secrets(self):
        assert _SECRET_PATTERNS.search('/home/user/.ssh/id_rsa')
        assert _SECRET_PATTERNS.search('/etc/shadow')
        assert _SECRET_PATTERNS.search('/app/.env')
        assert _SECRET_PATTERNS.search('/certs/server.pem')
        assert _SECRET_PATTERNS.search('/keys/auth.token')
        assert _SECRET_PATTERNS.search('/root/.aws/credentials')

    def test_secret_patterns_no_false_positive(self):
        assert not _SECRET_PATTERNS.search('/usr/lib/libssl.so')
        assert not _SECRET_PATTERNS.search('/tmp/output.txt')
        assert not _SECRET_PATTERNS.search('/var/log/app.log')

    def test_syscall_names_has_execve(self):
        assert 59 in _SYSCALL_NAMES
        assert _SYSCALL_NAMES[59] == 'execve'

    def test_syscall_names_has_connect(self):
        assert 42 in _SYSCALL_NAMES
        assert _SYSCALL_NAMES[42] == 'connect'


# ---------------------------------------------------------------------------
# 16. _Caps detection
# ---------------------------------------------------------------------------

class TestCapsDetection(unittest.TestCase):
    def test_caps_has_required_attributes(self):
        caps = _CAPS
        assert hasattr(caps, 'os_name')
        assert hasattr(caps, 'has_btf')
        assert hasattr(caps, 'has_sidecar')
        assert hasattr(caps, 'has_frida')
        assert hasattr(caps, 'has_proc')
        assert hasattr(caps, 'ebpf_full')
        assert hasattr(caps, 'ebpf_proc')

    def test_caps_os_name_is_string(self):
        assert isinstance(_CAPS.os_name, str)
        assert _CAPS.os_name in ('Linux', 'Darwin', 'Windows', 'FreeBSD')

    def test_ebpf_full_requires_all_three(self):
        """ebpf_full must be False if any of OS/BTF/sidecar is missing."""
        with patch('oneinfinity.core.stealth_tracer.platform.system', return_value='Darwin'):
            caps = _Caps.__new__(_Caps)
            caps.os_name = 'Darwin'
            caps.has_btf = True
            caps.has_sidecar = True
            caps.has_frida = False
            caps.has_dtrace = False
            caps.has_proc = False
            caps.linux_fallback_available = False
        assert caps.ebpf_full is False  # Darwin, not Linux


# ---------------------------------------------------------------------------
# Run
# ---------------------------------------------------------------------------

if __name__ == '__main__':
    unittest.main(verbosity=2)
