"""Phase 3 Nim binary integration tests.

Tests cover:
- Source file existence
- Compiled binary existence
- NDJSON output correctness for all 6 binaries
- nim_runner.py integrity / security contract
- Python shim fallback behaviour
"""
import json
import os
import shutil
import subprocess
import sys
from pathlib import Path

import pytest

# ---------------------------------------------------------------------------
# Paths
# ---------------------------------------------------------------------------
REPO_ROOT = Path(__file__).resolve().parents[1]
NIM_SRC_DIR = REPO_ROOT / "src" / "nim"
BIN_DIR = REPO_ROOT / "src" / "nim" / "bin"

NIM_SOURCES = [
    "oi-shell-gen.nim",
    "oi-bypass-gen.nim",
    "oi-payloads.nim",
    "oi-post-exploit.nim",
    "oi-fuzzer.nim",
    "oi-privesc-gen.nim",
]

NIM_BINARIES = [
    "oi-shell-gen",
    "oi-bypass-gen",
    "oi-payloads",
    "oi-post-exploit",
    "oi-fuzzer",
    "oi-privesc-gen",
]

_ANY_BINARY_PRESENT = any((BIN_DIR / b).exists() for b in NIM_BINARIES)

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _run_binary(binary: str, extra_args: list[str] | None = None) -> list[dict]:
    """Run a Nim binary with ONEINFINITY_SKIP_INTEGRITY=1; return parsed NDJSON results."""
    path = BIN_DIR / binary
    env = {**os.environ, "ONEINFINITY_SKIP_INTEGRITY": "1"}
    result = subprocess.run(
        [str(path)] + (extra_args or []),
        capture_output=True,
        text=True,
        timeout=60,
        env=env,
    )
    assert result.returncode == 0, (
        f"{binary} exited {result.returncode}: {result.stderr[:1000]}"
    )
    objects = []
    for line in result.stdout.splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            obj = json.loads(line)
        except json.JSONDecodeError:
            continue
        if isinstance(obj, dict) and obj.get("event") == "result":
            objects.append(obj)
    return objects


# ---------------------------------------------------------------------------
# 1. Source existence
# ---------------------------------------------------------------------------

def test_all_nim_sources_exist():
    """All 6 .nim source files must exist in src/nim/."""
    missing = [s for s in NIM_SOURCES if not (NIM_SRC_DIR / s).exists()]
    assert not missing, f"Missing Nim sources: {missing}"


# ---------------------------------------------------------------------------
# 2. Binary existence
# ---------------------------------------------------------------------------

def test_all_nim_binaries_compiled():
    """All 6 Nim binaries must be present in src/nim/bin/."""
    missing = [b for b in NIM_BINARIES if not (BIN_DIR / b).exists()]
    assert not missing, f"Missing compiled binaries: {missing}"


# ---------------------------------------------------------------------------
# 3–8. Binary output correctness
# ---------------------------------------------------------------------------

@pytest.mark.skipif(
    not (BIN_DIR / "oi-shell-gen").exists(),
    reason="oi-shell-gen not compiled",
)
def test_shell_gen_produces_valid_json():
    """oi-shell-gen must emit >= 10 NDJSON result objects."""
    results = _run_binary("oi-shell-gen")
    assert len(results) >= 10, f"Expected >= 10 results, got {len(results)}"


@pytest.mark.skipif(
    not (BIN_DIR / "oi-bypass-gen").exists(),
    reason="oi-bypass-gen not compiled",
)
def test_bypass_gen_produces_valid_json():
    """oi-bypass-gen must emit >= 20 NDJSON result objects."""
    results = _run_binary("oi-bypass-gen", ["--target=/admin"])
    assert len(results) >= 20, f"Expected >= 20 results, got {len(results)}"


@pytest.mark.skipif(
    not (BIN_DIR / "oi-payloads").exists(),
    reason="oi-payloads not compiled",
)
def test_payloads_produces_valid_json():
    """oi-payloads must emit >= 15 NDJSON result objects."""
    results = _run_binary("oi-payloads", ["--type=xss", "--context=html"])
    assert len(results) >= 15, f"Expected >= 15 results, got {len(results)}"


@pytest.mark.skipif(
    not (BIN_DIR / "oi-post-exploit").exists(),
    reason="oi-post-exploit not compiled",
)
def test_post_exploit_produces_valid_json():
    """oi-post-exploit must emit >= 5 NDJSON result objects."""
    results = _run_binary("oi-post-exploit")
    assert len(results) >= 5, f"Expected >= 5 results, got {len(results)}"


@pytest.mark.skipif(
    not (BIN_DIR / "oi-fuzzer").exists(),
    reason="oi-fuzzer not compiled",
)
def test_fuzzer_produces_valid_json():
    """oi-fuzzer must emit >= 20 NDJSON result objects."""
    results = _run_binary("oi-fuzzer", ["--target=generic", "--count=20"])
    assert len(results) >= 20, f"Expected >= 20 results, got {len(results)}"


@pytest.mark.skipif(
    not (BIN_DIR / "oi-privesc-gen").exists(),
    reason="oi-privesc-gen not compiled",
)
def test_privesc_gen_produces_valid_json():
    """oi-privesc-gen must emit >= 3 NDJSON result objects."""
    results = _run_binary("oi-privesc-gen", ["--os=linux", "--technique=sudo"])
    assert len(results) >= 3, f"Expected >= 3 results, got {len(results)}"


# ---------------------------------------------------------------------------
# 9. Integrity error on tampered binary
# ---------------------------------------------------------------------------

@pytest.mark.skipif(
    not _ANY_BINARY_PRESENT,
    reason="No compiled binaries available",
)
def test_nim_runner_integrity_error(tmp_path):
    """run_nim_binary must raise NimIntegrityError when binary is tampered."""
    sys.path.insert(0, str(REPO_ROOT / "src"))
    from oneinfinity.infra.nim_runner import NimIntegrityError, _BIN_DIR, _CHECKSUMS_PATH
    import hashlib, json, importlib

    # Find a binary that exists
    binary = next((b for b in NIM_BINARIES if (BIN_DIR / b).exists()), None)
    assert binary is not None

    # Write a real-looking but wrong checksum into a temp checksums file
    fake_checksums = {binary: {"sha256": "a" * 64}}

    # Patch environment — use real binary but wrong checksum
    import oneinfinity.infra.nim_runner as nim_runner_mod
    original_load = nim_runner_mod._load_checksums
    nim_runner_mod._load_checksums = lambda: fake_checksums

    try:
        env_backup = os.environ.copy()
        os.environ.pop("ONEINFINITY_SKIP_INTEGRITY", None)
        os.environ.pop("ONEINFINITY_ENV", None)
        with pytest.raises(NimIntegrityError, match="SHA-256 mismatch|tampered"):
            nim_runner_mod.run_nim_binary(binary)
    finally:
        nim_runner_mod._load_checksums = original_load
        os.environ.clear()
        os.environ.update(env_backup)


# ---------------------------------------------------------------------------
# 10. Execution error on bad args
# ---------------------------------------------------------------------------

@pytest.mark.skipif(
    not _ANY_BINARY_PRESENT,
    reason="No compiled binaries available",
)
def test_nim_runner_execution_error():
    """run_nim_binary must raise NimExecutionError on non-zero exit."""
    sys.path.insert(0, str(REPO_ROOT / "src"))
    from oneinfinity.infra.nim_runner import NimExecutionError

    # Find a binary that exists
    binary = next((b for b in NIM_BINARIES if (BIN_DIR / b).exists()), None)
    assert binary is not None

    import oneinfinity.infra.nim_runner as nim_runner_mod

    # Patch run to simulate non-zero exit
    import subprocess as sp
    original_run = sp.run

    class FakeResult:
        returncode = 1
        stdout = ""
        stderr = "simulated failure"

    sp.run = lambda *a, **kw: FakeResult()
    env_backup = os.environ.copy()
    os.environ["ONEINFINITY_SKIP_INTEGRITY"] = "1"
    try:
        with pytest.raises(NimExecutionError):
            nim_runner_mod.run_nim_binary(binary)
    finally:
        sp.run = original_run
        os.environ.clear()
        os.environ.update(env_backup)


# ---------------------------------------------------------------------------
# 11. Python shim fallback — shell
# ---------------------------------------------------------------------------

def test_python_shim_fallback_shell():
    """With ONEINFINITY_NIM_SHELL=0 the Python shim must return a non-empty list."""
    env_backup = os.environ.copy()
    os.environ["ONEINFINITY_NIM_SHELL"] = "0"
    try:
        sys.path.insert(0, str(REPO_ROOT / "src"))
        # Try importing the shells shim; skip if module not yet present
        try:
            import oneinfinity.arsenal.shells.shell_payloads as shell_mod
            # Reload to pick up env change
            import importlib
            importlib.reload(shell_mod)
        except ModuleNotFoundError:
            pytest.skip("shell_payloads module not yet present")

        func = getattr(shell_mod, "generate_shell_payloads", None)
        if func is None:
            pytest.skip("generate_shell_payloads function not found in shell_payloads")
        result = func()
        assert isinstance(result, list) and len(result) > 0
    finally:
        os.environ.clear()
        os.environ.update(env_backup)


# ---------------------------------------------------------------------------
# 12. Python shim fallback — bypass
# ---------------------------------------------------------------------------

def test_python_shim_fallback_bypass():
    """With ONEINFINITY_NIM_BYPASS=0 the Python bypass shim must return a non-empty list."""
    env_backup = os.environ.copy()
    os.environ["ONEINFINITY_NIM_BYPASS"] = "0"
    try:
        sys.path.insert(0, str(REPO_ROOT / "src"))
        try:
            import oneinfinity.arsenal.bypass.bypass_payloads as bypass_mod
            import importlib
            importlib.reload(bypass_mod)
        except ModuleNotFoundError:
            pytest.skip("bypass_payloads module not yet present")

        func = getattr(bypass_mod, "generate_bypass_payloads", None)
        if func is None:
            pytest.skip("generate_bypass_payloads function not found in bypass_payloads")
        result = func()
        assert isinstance(result, list) and len(result) > 0
    finally:
        os.environ.clear()
        os.environ.update(env_backup)


# ---------------------------------------------------------------------------
# 13. Path traversal rejection
# ---------------------------------------------------------------------------

def test_nim_runner_path_traversal():
    """run_nim_binary must raise NimIntegrityError on path traversal names."""
    sys.path.insert(0, str(REPO_ROOT / "src"))
    from oneinfinity.infra.nim_runner import NimIntegrityError, _validate_binary_path

    for bad_name in ["../../../etc/passwd", "../evil", "evil/../../../bin/sh", "oi-shell-gen/../../x"]:
        with pytest.raises(NimIntegrityError):
            _validate_binary_path(bad_name)


# ---------------------------------------------------------------------------
# 14. Production blocks SKIP_INTEGRITY
# ---------------------------------------------------------------------------

def test_nim_runner_production_blocks_skip_integrity():
    """ONEINFINITY_SKIP_INTEGRITY=1 must be blocked when ONEINFINITY_ENV=production."""
    sys.path.insert(0, str(REPO_ROOT / "src"))
    from oneinfinity.infra.nim_runner import NimIntegrityError
    import oneinfinity.infra.nim_runner as nim_runner_mod

    env_backup = os.environ.copy()
    os.environ["ONEINFINITY_ENV"] = "production"
    os.environ["ONEINFINITY_SKIP_INTEGRITY"] = "1"

    # Create a fake binary so we get past the exists() check
    fake_bin = BIN_DIR / "oi-shell-gen"
    created = False
    if not fake_bin.exists():
        BIN_DIR.mkdir(parents=True, exist_ok=True)
        fake_bin.write_bytes(b"\x00")
        created = True

    try:
        with pytest.raises(NimIntegrityError, match="production"):
            nim_runner_mod.run_nim_binary("oi-shell-gen")
    finally:
        if created:
            fake_bin.unlink(missing_ok=True)
        os.environ.clear()
        os.environ.update(env_backup)
