"""Phase 3 security invariant tests.

Verifies:
- No Nim source imports network/socket modules (loopback policy)
- All 6 sources declare antiAnalysis() and verifySelfIntegrity()
- nim_runner path validation and integrity policy enforcement
"""
import os
import sys
from pathlib import Path

import pytest

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

# Network-binding module names that must never appear in Nim sources
_FORBIDDEN_IMPORTS = ["socket", "asyncnet", "httpclient", "net"]


def _read_nim_source(name: str) -> str:
    path = NIM_SRC_DIR / name
    if not path.exists():
        return ""
    return path.read_text(errors="replace")


def _all_sources_content() -> list[tuple[str, str]]:
    return [(name, _read_nim_source(name)) for name in NIM_SOURCES]


# ---------------------------------------------------------------------------
# 1. No socket/network imports
# ---------------------------------------------------------------------------

def test_no_nim_socket_imports():
    """No Nim source file may import socket, asyncnet, httpclient, or net."""
    violations: list[str] = []
    for name, content in _all_sources_content():
        if not content:
            continue  # source not yet written — skip (covered by existence test)
        for forbidden in _FORBIDDEN_IMPORTS:
            # Match 'import <module>' or 'import <module>,' patterns
            import re
            pattern = re.compile(
                r"^\s*import\b.*\b" + re.escape(forbidden) + r"\b",
                re.MULTILINE | re.IGNORECASE,
            )
            if pattern.search(content):
                violations.append(f"{name}: imports '{forbidden}'")

    assert not violations, (
        "BLOCKER SA-1: Nim sources contain forbidden network imports:\n"
        + "\n".join(violations)
    )


# ---------------------------------------------------------------------------
# 2. antiAnalysis proc present in all sources
# ---------------------------------------------------------------------------

def test_anti_analysis_present():
    """All 6 Nim sources must declare 'proc antiAnalysis'."""
    missing: list[str] = []
    for name, content in _all_sources_content():
        if not content:
            missing.append(f"{name} (file missing)")
            continue
        if "proc antiAnalysis" not in content:
            missing.append(name)

    assert not missing, f"Missing 'proc antiAnalysis' in: {missing}"


# ---------------------------------------------------------------------------
# 3. verifySelfIntegrity proc present in all sources
# ---------------------------------------------------------------------------

def test_verify_self_integrity_present():
    """All 6 Nim sources must declare 'proc verifySelfIntegrity'."""
    missing: list[str] = []
    for name, content in _all_sources_content():
        if not content:
            missing.append(f"{name} (file missing)")
            continue
        if "proc verifySelfIntegrity" not in content:
            missing.append(name)

    assert not missing, f"Missing 'proc verifySelfIntegrity' in: {missing}"


# ---------------------------------------------------------------------------
# 4. Path validation rejects traversal
# ---------------------------------------------------------------------------

def test_nim_runner_path_validation():
    """_validate_binary_path must raise NimIntegrityError on traversal names."""
    sys.path.insert(0, str(REPO_ROOT / "src"))
    from oneinfinity.infra.nim_runner import NimIntegrityError, _validate_binary_path

    traversal_names = ["../evil", "../../etc/passwd", "oi-shell-gen/../../x", "../oi-shell-gen"]
    for bad in traversal_names:
        with pytest.raises(NimIntegrityError):
            _validate_binary_path(bad)


# ---------------------------------------------------------------------------
# 5. SKIP_INTEGRITY works in dev (non-production)
# ---------------------------------------------------------------------------

def test_nim_runner_skip_integrity_dev(tmp_path):
    """ONEINFINITY_SKIP_INTEGRITY=1 with ONEINFINITY_ENV=dev must not raise NimIntegrityError
    due to the policy check (it may raise FileNotFoundError if binary absent)."""
    sys.path.insert(0, str(REPO_ROOT / "src"))
    import oneinfinity.infra.nim_runner as nim_runner_mod
    from oneinfinity.infra.nim_runner import NimIntegrityError, NimExecutionError

    env_backup = os.environ.copy()
    os.environ["ONEINFINITY_ENV"] = "dev"
    os.environ["ONEINFINITY_SKIP_INTEGRITY"] = "1"

    # Provide a dummy executable so we don't get FileNotFoundError either
    fake_bin = BIN_DIR / "oi-shell-gen"
    BIN_DIR.mkdir(parents=True, exist_ok=True)
    created = not fake_bin.exists()
    if created:
        # Write a minimal shell script that exits 0 with one NDJSON line
        fake_bin.write_text('#!/bin/sh\necho \'{"event":"result","data":"test"}\'\n')
        fake_bin.chmod(0o755)

    original_run = None
    try:
        import subprocess as sp
        original_run = sp.run

        class FakeResult:
            returncode = 0
            stdout = '{"event":"result","data":"test"}\n'
            stderr = ""

        sp.run = lambda *a, **kw: FakeResult()

        # Must NOT raise NimIntegrityError — production policy must not trigger
        try:
            result = nim_runner_mod.run_nim_binary("oi-shell-gen")
            # If no exception, verify we got result objects
            assert isinstance(result, list)
        except NimIntegrityError as exc:
            pytest.fail(f"NimIntegrityError should not fire in dev mode: {exc}")
        except (FileNotFoundError, NimExecutionError):
            pass  # acceptable — binary may not be real

    finally:
        if original_run is not None:
            sp.run = original_run
        if created and fake_bin.exists():
            fake_bin.unlink(missing_ok=True)
        os.environ.clear()
        os.environ.update(env_backup)


# ---------------------------------------------------------------------------
# 6. Production blocks SKIP_INTEGRITY
# ---------------------------------------------------------------------------

def test_nim_runner_production_blocks_skip():
    """ONEINFINITY_ENV=production + ONEINFINITY_SKIP_INTEGRITY=1 must raise NimIntegrityError."""
    sys.path.insert(0, str(REPO_ROOT / "src"))
    from oneinfinity.infra.nim_runner import NimIntegrityError
    import oneinfinity.infra.nim_runner as nim_runner_mod

    env_backup = os.environ.copy()
    os.environ["ONEINFINITY_ENV"] = "production"
    os.environ["ONEINFINITY_SKIP_INTEGRITY"] = "1"

    fake_bin = BIN_DIR / "oi-shell-gen"
    BIN_DIR.mkdir(parents=True, exist_ok=True)
    created = not fake_bin.exists()
    if created:
        fake_bin.write_bytes(b"\x7fELF")

    try:
        with pytest.raises(NimIntegrityError, match="production"):
            nim_runner_mod.run_nim_binary("oi-shell-gen")
    finally:
        if created and fake_bin.exists():
            fake_bin.unlink(missing_ok=True)
        os.environ.clear()
        os.environ.update(env_backup)
