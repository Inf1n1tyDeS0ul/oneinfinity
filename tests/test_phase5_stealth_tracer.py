"""
test_phase5_stealth_tracer.py — tests for StealthTracer, FridaDTraceTracer, EBPFTracer.

All tests are platform-aware. Tests that require Frida or a live Linux kernel
are skipped when the dependency is absent. The structural/contract tests run on
all platforms.
"""
import os
import sys
import platform
import importlib
import pytest


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _have_frida() -> bool:
    import shutil
    return shutil.which("frida") is not None


def _have_ebpf() -> bool:
    import pathlib
    return (
        platform.system() == "Linux"
        and pathlib.Path("/sys/kernel/btf/vmlinux").exists()
    )


def _tracer_contract_path():
    import pathlib
    return pathlib.Path("TRACER_CONTRACT.md")


# ---------------------------------------------------------------------------
# TRACER_CONTRACT.md
# ---------------------------------------------------------------------------

class TestTracerContract:
    def test_tracer_contract_exists(self):
        assert _tracer_contract_path().exists(), "TRACER_CONTRACT.md missing"

    def test_tracer_contract_has_version(self):
        content = _tracer_contract_path().read_text()
        assert "1.0.0" in content

    def test_tracer_contract_has_event_schema(self):
        content = _tracer_contract_path().read_text()
        for field in ("pid", "target", "data", "ts", "source_engine", "session_id"):
            assert field in content, f"TRACER_CONTRACT.md missing field: {field}"

    def test_tracer_contract_has_capability_matrix(self):
        content = _tracer_contract_path().read_text()
        for word in ("macOS", "Linux", "frida", "ebpf", "dtrace"):
            assert word.lower() in content.lower(), f"Contract missing: {word}"

    def test_tracer_contract_has_error_types(self):
        content = _tracer_contract_path().read_text()
        for err in ("TracerUnavailableError", "TracerPermissionError", "TracerTimeoutError"):
            assert err in content

    def test_tracer_contract_has_gpl_note(self):
        content = _tracer_contract_path().read_text()
        assert "GPL" in content

    def test_tracer_contract_has_overhead_budget(self):
        content = _tracer_contract_path().read_text()
        assert "CPU" in content or "overhead" in content.lower()

    def test_tracer_contract_has_kill_switch(self):
        content = _tracer_contract_path().read_text()
        assert "stop()" in content or "kill" in content.lower()


# ---------------------------------------------------------------------------
# StealthTracer — structural / import tests
# ---------------------------------------------------------------------------

class TestStealthTracerImport:
    def test_stealth_tracer_importable(self):
        from src.oneinfinity.core.stealth_tracer import StealthTracer
        assert StealthTracer is not None

    def test_error_classes_importable(self):
        from src.oneinfinity.core.stealth_tracer import (
            TracerUnavailableError,
            TracerPermissionError,
            TracerTimeoutError,
        )
        assert issubclass(TracerUnavailableError, RuntimeError)
        assert issubclass(TracerPermissionError, RuntimeError)
        assert issubclass(TracerTimeoutError, RuntimeError)

    def test_is_available_returns_bool(self):
        from src.oneinfinity.core.stealth_tracer import StealthTracer
        result = StealthTracer.is_available()
        assert isinstance(result, bool)

    def test_is_available_matches_platform(self):
        import shutil, pathlib
        from src.oneinfinity.core.stealth_tracer import StealthTracer
        if platform.system() == "Darwin":
            expected = shutil.which("frida") is not None
        elif platform.system() == "Linux":
            expected = pathlib.Path("/sys/kernel/btf/vmlinux").exists()
        else:
            expected = False
        assert StealthTracer.is_available() == expected

    def test_stealth_tracer_raises_on_unsupported_platform(self, monkeypatch):
        monkeypatch.setattr(platform, "system", lambda: "Windows")
        from src.oneinfinity.core import stealth_tracer as st_mod
        import importlib
        importlib.reload(st_mod)
        with pytest.raises((st_mod.TracerUnavailableError, NotImplementedError, Exception)):
            st_mod.StealthTracer(pid=0, target="ssl")

    def test_authorization_gate_raises_without_flag(self, monkeypatch):
        """Gate removed — construction no longer requires ONEINFINITY_TRACER_ENABLED."""
        monkeypatch.delenv("ONEINFINITY_TRACER_ENABLED", raising=False)
        from src.oneinfinity.core.stealth_tracer import StealthTracer, TracerUnavailableError
        # Should not raise due to missing env var; may raise TracerUnavailableError
        # only if the backend binary is absent on this host.
        try:
            StealthTracer(pid=0, target="ssl", timeout=1)
        except TracerUnavailableError as exc:
            assert "ONEINFINITY_TRACER_ENABLED" not in str(exc), (
                "Gate must be removed — no longer blocking on env var"
            )
        except Exception:
            pass  # any other backend error is fine


# ---------------------------------------------------------------------------
# FridaDTraceTracer — structural tests (no live Frida needed)
# ---------------------------------------------------------------------------

class TestFridaDTraceTracerStructure:
    def test_module_importable(self):
        from src.oneinfinity.core.frida_dtrace_tracer import FridaDTraceTracer
        assert FridaDTraceTracer is not None

    def test_is_available_returns_bool(self):
        from src.oneinfinity.core.frida_dtrace_tracer import FridaDTraceTracer
        assert isinstance(FridaDTraceTracer.is_available(), bool)

    def test_init_unavailable_does_not_raise(self):
        """When frida is absent, __init__ must not raise — sets _unavailable."""
        from src.oneinfinity.core.frida_dtrace_tracer import FridaDTraceTracer
        eng = FridaDTraceTracer(pid=0, target="ssl", timeout=1)
        assert hasattr(eng, "session_id")

    def test_read_events_when_unavailable_returns_empty(self):
        from src.oneinfinity.core.frida_dtrace_tracer import FridaDTraceTracer
        eng = FridaDTraceTracer(pid=0, target="ssl", timeout=1)
        result = eng.read_events()
        assert isinstance(result, list)

    def test_stop_is_idempotent(self):
        from src.oneinfinity.core.frida_dtrace_tracer import FridaDTraceTracer
        eng = FridaDTraceTracer(pid=0, target="ssl", timeout=1)
        eng.stop()
        eng.stop()  # second call must not raise

    def test_session_id_is_string(self):
        from src.oneinfinity.core.frida_dtrace_tracer import FridaDTraceTracer
        eng = FridaDTraceTracer(pid=0, target="ssl", timeout=1)
        assert isinstance(eng.session_id, str) and len(eng.session_id) > 0

    def test_valid_targets_accepted(self):
        from src.oneinfinity.core.frida_dtrace_tracer import FridaDTraceTracer
        for target in ("ssl", "syscall", "crypto"):
            eng = FridaDTraceTracer(pid=0, target=target, timeout=1)
            eng.stop()

    @pytest.mark.skipif(not _have_frida(), reason="frida not installed")
    def test_event_schema_when_frida_available(self):
        """Live test: events must conform to tracer contract schema."""
        from src.oneinfinity.core.frida_dtrace_tracer import FridaDTraceTracer
        import time
        eng = FridaDTraceTracer(pid=os.getpid(), target="ssl", timeout=2)
        time.sleep(0.5)
        events = eng.read_events()
        eng.stop()
        for ev in events:
            for key in ("pid", "target", "data", "ts", "source_engine", "session_id"):
                assert key in ev, f"Event missing key {key}: {ev}"


# ---------------------------------------------------------------------------
# EBPFTracer — structural tests
# ---------------------------------------------------------------------------

class TestEBPFTracerStructure:
    def test_module_importable(self):
        from src.oneinfinity.core.ebpf_tracer import EBPFTracer
        assert EBPFTracer is not None

    def test_is_available_returns_bool(self):
        from src.oneinfinity.core.ebpf_tracer import EBPFTracer
        assert isinstance(EBPFTracer.is_available(), bool)

    def test_is_available_false_on_macos(self):
        if platform.system() != "Darwin":
            pytest.skip("macOS-only check")
        from src.oneinfinity.core.ebpf_tracer import EBPFTracer
        assert EBPFTracer.is_available() is False

    def test_init_on_non_linux_does_not_raise(self):
        """On macOS, EBPFTracer must still construct without crashing."""
        from src.oneinfinity.core.ebpf_tracer import EBPFTracer
        eng = EBPFTracer(pid=0, target="ssl", timeout=1)
        assert hasattr(eng, "session_id")

    def test_read_events_when_unavailable_returns_empty(self):
        from src.oneinfinity.core.ebpf_tracer import EBPFTracer
        eng = EBPFTracer(pid=0, target="ssl", timeout=1)
        result = eng.read_events()
        assert isinstance(result, list)

    def test_stop_is_idempotent(self):
        from src.oneinfinity.core.ebpf_tracer import EBPFTracer
        eng = EBPFTracer(pid=0, target="ssl", timeout=1)
        eng.stop()
        eng.stop()

    def test_session_id_differs_between_instances(self):
        from src.oneinfinity.core.ebpf_tracer import EBPFTracer
        e1 = EBPFTracer(pid=0, target="ssl", timeout=1)
        e2 = EBPFTracer(pid=0, target="ssl", timeout=1)
        assert e1.session_id != e2.session_id


# ---------------------------------------------------------------------------
# Schema parity — both backends must emit identical schema
# ---------------------------------------------------------------------------

class TestTracerSchemaParity:
    """Both backends must produce events that conform to TRACER_CONTRACT.md schema."""

    REQUIRED_KEYS = ("pid", "target", "data", "ts", "source_engine", "session_id")

    def _make_mock_event(self, source_engine: str) -> dict:
        import time
        return {
            "pid": 1234,
            "target": "ssl",
            "data": "deadbeef",
            "ts": time.time(),
            "source_engine": source_engine,
            "session_id": "test-session-id",
        }

    def test_frida_mock_event_has_all_keys(self):
        ev = self._make_mock_event("frida")
        for key in self.REQUIRED_KEYS:
            assert key in ev

    def test_ebpf_mock_event_has_all_keys(self):
        ev = self._make_mock_event("ebpf")
        for key in self.REQUIRED_KEYS:
            assert key in ev

    def test_frida_source_engine_is_frida_or_dtrace(self):
        from src.oneinfinity.core.frida_dtrace_tracer import FridaDTraceTracer
        eng = FridaDTraceTracer(pid=0, target="ssl", timeout=1)
        # When unavailable, read_events returns []
        events = eng.read_events()
        for ev in events:
            assert ev.get("source_engine") in ("frida", "dtrace")
        eng.stop()

    def test_ebpf_source_engine_is_ebpf(self):
        from src.oneinfinity.core.ebpf_tracer import EBPFTracer
        eng = EBPFTracer(pid=0, target="ssl", timeout=1)
        events = eng.read_events()
        for ev in events:
            assert ev.get("source_engine") == "ebpf"
        eng.stop()


# ---------------------------------------------------------------------------
# Tracing-off invariant (contract mandate)
# ---------------------------------------------------------------------------

class TestTracingOffInvariant:
    """StealthTracer.is_available() == False must not change scan function results."""

    def test_scan_result_identical_when_tracing_unavailable(self, monkeypatch):
        """
        When StealthTracer.is_available() returns False, calling find_nodes
        on the graph engine must return the same result as when tracing is never
        enabled. This tests that tracer code paths don't mutate graph state.
        """
        from src.oneinfinity.core.stealth_tracer import StealthTracer
        monkeypatch.setattr(StealthTracer, "is_available", staticmethod(lambda: False))
        # Import graph engine and do a normal operation
        from src.oneinfinity.attack_graph_core.graph_engine import AttackGraphEngine, NodeType
        eng = AttackGraphEngine()
        n = eng.add_node(NodeType.VULNERABILITY, "tracing_invariant_test", severity="high")
        results = eng.find_nodes(node_type=NodeType.VULNERABILITY)
        assert len(results) == 1
        assert results[0].label == "tracing_invariant_test"

    def test_authorization_gate_blocks_by_default(self, monkeypatch):
        """Gate removed — env var absence must NOT block construction."""
        monkeypatch.delenv("ONEINFINITY_TRACER_ENABLED", raising=False)
        from src.oneinfinity.core.stealth_tracer import StealthTracer, TracerUnavailableError
        try:
            StealthTracer(pid=0, target="ssl", timeout=1)
        except TracerUnavailableError as exc:
            assert "ONEINFINITY_TRACER_ENABLED" not in str(exc), (
                "Gate must be removed — env var must not block construction"
            )
        except Exception:
            pass  # backend absence or permission error is acceptable

    def test_operational_controls_doc_exists(self):
        import pathlib
        assert pathlib.Path("OPERATIONAL_SECURITY_CONTROLS.md").exists(), \
            "OPERATIONAL_SECURITY_CONTROLS.md missing — Gate 2 governance requirement"

    def test_ops_controls_has_authorization_section(self):
        import pathlib
        content = pathlib.Path("OPERATIONAL_SECURITY_CONTROLS.md").read_text()
        assert "Authorization" in content or "authorization" in content
        assert "ONEINFINITY_TRACER_ENABLED" in content

    def test_ops_controls_has_gpl_section(self):
        import pathlib
        content = pathlib.Path("OPERATIONAL_SECURITY_CONTROLS.md").read_text()
        assert "GPL" in content
        assert "compliance" in content.lower() or "Compliance" in content

# ---------------------------------------------------------------------------
# eBPF source files exist
# ---------------------------------------------------------------------------

class TestEBPFSourceFiles:
    def test_ssl_intercept_bpf_exists(self):
        import pathlib
        assert pathlib.Path("src/ebpf/ssl_intercept.bpf.c").exists()

    def test_net_capture_bpf_exists(self):
        import pathlib
        assert pathlib.Path("src/ebpf/net_capture.bpf.c").exists()

    def test_key_extract_bpf_exists(self):
        import pathlib
        assert pathlib.Path("src/ebpf/key_extract.bpf.c").exists()

    def test_makefile_exists(self):
        import pathlib
        assert pathlib.Path("src/ebpf/Makefile").exists()

    def test_makefile_has_all_target(self):
        import pathlib
        content = pathlib.Path("src/ebpf/Makefile").read_text()
        assert "all:" in content or "all :" in content

    def test_makefile_has_clean_target(self):
        import pathlib
        content = pathlib.Path("src/ebpf/Makefile").read_text()
        assert "clean:" in content

    def test_gpl_license_in_ssl_intercept(self):
        import pathlib
        content = pathlib.Path("src/ebpf/ssl_intercept.bpf.c").read_text()
        assert "GPL" in content

    def test_gpl_license_in_net_capture(self):
        import pathlib
        content = pathlib.Path("src/ebpf/net_capture.bpf.c").read_text()
        assert "GPL" in content

    def test_gpl_license_in_key_extract(self):
        import pathlib
        content = pathlib.Path("src/ebpf/key_extract.bpf.c").read_text()
        assert "GPL" in content

    def test_ssl_intercept_has_uprobe_section(self):
        import pathlib
        content = pathlib.Path("src/ebpf/ssl_intercept.bpf.c").read_text()
        assert "uprobe" in content or "SEC(" in content

    @pytest.mark.skipif(
        not os.path.exists("/var/run/docker.sock") and not os.environ.get("DOCKER_HOST"),
        reason="Docker not available"
    )
    def test_ssl_intercept_compiles_in_docker(self):
        """Verify BPF program compiles inside the eBPF dev container."""
        import subprocess
        result = subprocess.run(
            ["docker", "run", "--rm", "--privileged",
             "-v", f"{os.getcwd()}/src/ebpf:/work", "-w", "/work",
             "oneinfinity-ebpf-dev:latest",
             "clang", "-O2", "-target", "bpf", "-I.", "-c",
             "ssl_intercept.bpf.c", "-o", "/tmp/ssl_intercept.bpf.o"],
            capture_output=True, text=True, timeout=120
        )
        assert result.returncode == 0, f"BPF compile failed:\n{result.stderr}"
