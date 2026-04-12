# tests/orchestration/test_cli_backends.py
"""Tests for CodexCliBackend and ClaudeCliBackend."""
import os
import subprocess
from unittest.mock import patch, MagicMock

import pytest


def _proc(returncode=0, stdout="output text", stderr=""):
    return subprocess.CompletedProcess([], returncode, stdout=stdout, stderr=stderr)


# ── _estimate_tokens ─────────────────────────────────────────────────────────

def test_estimate_tokens_minimum_one():
    from oneinfinity.orchestration.backends.cli import _estimate_tokens
    assert _estimate_tokens("") == 1


def test_estimate_tokens_approximation():
    from oneinfinity.orchestration.backends.cli import _estimate_tokens
    assert _estimate_tokens("hello world") == max(1, len("hello world") // 4)


# ── CodexCliBackend.is_available ─────────────────────────────────────────────

def test_codex_available_when_binary_found():
    from oneinfinity.orchestration.backends.cli import CodexCliBackend
    with patch("shutil.which", return_value="/usr/bin/codex"):
        assert CodexCliBackend().is_available() is True


def test_codex_unavailable_when_binary_missing():
    from oneinfinity.orchestration.backends.cli import CodexCliBackend
    with patch("shutil.which", return_value=None):
        assert CodexCliBackend().is_available() is False


# ── CodexCliBackend.call ─────────────────────────────────────────────────────

def test_codex_call_reads_output_file(tmp_path):
    from oneinfinity.orchestration.backends.cli import CodexCliBackend
    expected_content = "vulnerability analysis result"

    def fake_run(cmd, **kwargs):
        # codex writes to the -o flag path
        o_idx = cmd.index("-o")
        open(cmd[o_idx + 1], "w").write(expected_content)
        return _proc(0, stdout="", stderr="")

    with patch("subprocess.run", side_effect=fake_run):
        result = CodexCliBackend().call("o4-mini", "test prompt", "system", 0.2, 512)

    assert result.content == expected_content
    assert not result.failed
    assert result.input_tokens >= 1


def test_codex_call_returns_failed_on_nonzero_exit():
    from oneinfinity.orchestration.backends.cli import CodexCliBackend
    with patch("subprocess.run", return_value=_proc(1, stdout="", stderr="auth error")):
        result = CodexCliBackend().call("o4-mini", "test", "", 0.2, 512)
    assert result.failed
    assert "exit 1" in result.error


def test_codex_call_returns_failed_on_timeout():
    from oneinfinity.orchestration.backends.cli import CodexCliBackend
    with patch("subprocess.run", side_effect=subprocess.TimeoutExpired([], 120)):
        result = CodexCliBackend().call("o4-mini", "test", "", 0.2, 512)
    assert result.failed
    assert "timed out" in result.error


def test_codex_call_passes_model_arg():
    from oneinfinity.orchestration.backends.cli import CodexCliBackend

    def fake_run(cmd, **kwargs):
        o_idx = cmd.index("-o")
        open(cmd[o_idx + 1], "w").write("ok")
        return _proc()

    with patch("subprocess.run", side_effect=fake_run) as mock_run:
        CodexCliBackend().call("o3-mini", "prompt", "", 0.2, 512)
        cmd = mock_run.call_args[0][0]

    assert "-m" in cmd
    assert "o3-mini" in cmd


# ── ClaudeCliBackend.is_available ────────────────────────────────────────────

def test_claude_available_when_binary_found():
    from oneinfinity.orchestration.backends.cli import ClaudeCliBackend
    with patch("shutil.which", return_value="/usr/local/bin/claude"):
        assert ClaudeCliBackend().is_available() is True


def test_claude_unavailable_when_binary_missing():
    from oneinfinity.orchestration.backends.cli import ClaudeCliBackend
    with patch("shutil.which", return_value=None):
        assert ClaudeCliBackend().is_available() is False


# ── ClaudeCliBackend.call ─────────────────────────────────────────────────────

def test_claude_call_returns_stripped_stdout():
    from oneinfinity.orchestration.backends.cli import ClaudeCliBackend
    with patch("subprocess.run", return_value=_proc(0, stdout="  analysis result  ")):
        result = ClaudeCliBackend().call("claude-opus-4-6", "prompt", "system", 0.3, 512)
    assert result.content == "analysis result"
    assert not result.failed


def test_claude_call_returns_failed_on_nonzero_exit():
    from oneinfinity.orchestration.backends.cli import ClaudeCliBackend
    with patch("subprocess.run", return_value=_proc(1, stdout="", stderr="budget exceeded")):
        result = ClaudeCliBackend().call("claude-opus-4-6", "test", "", 0.3, 512)
    assert result.failed
    assert "exit 1" in result.error


def test_claude_call_returns_failed_on_timeout():
    from oneinfinity.orchestration.backends.cli import ClaudeCliBackend
    with patch("subprocess.run", side_effect=subprocess.TimeoutExpired([], 120)):
        result = ClaudeCliBackend().call("claude-opus-4-6", "test", "", 0.3, 512)
    assert result.failed
    assert "timed out" in result.error


def test_claude_call_passes_model_and_budget():
    from oneinfinity.orchestration.backends.cli import ClaudeCliBackend
    with patch("subprocess.run", return_value=_proc()) as mock_run:
        ClaudeCliBackend(max_budget_usd=0.05).call("claude-sonnet-4-6", "p", "", 0.2, 512)
        cmd = mock_run.call_args[0][0]
    assert "--model" in cmd
    idx_model = cmd.index("--model")
    assert cmd[idx_model + 1] == "claude-sonnet-4-6"
    assert "--max-budget-usd" in cmd
    idx_budget = cmd.index("--max-budget-usd")
    assert cmd[idx_budget + 1] == "0.05"


def test_cli_backends_registered_at_import():
    import importlib
    import oneinfinity.orchestration.backends.cli
    importlib.reload(oneinfinity.orchestration.backends.cli)
    from oneinfinity.orchestration.backends import get_backend
    assert get_backend("codex") is not None
    assert get_backend("claude-cli") is not None
