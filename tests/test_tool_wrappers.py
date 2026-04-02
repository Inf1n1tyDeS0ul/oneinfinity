# tests/test_tool_wrappers.py
import sys, logging
import logging as _logging
sys.path.insert(0, "/home/devendra-yadav/oneinfinity")

from modules.tool_wrappers import _wrap


def test_bearer_token_not_in_command_string():
    """Authorization header values must be redacted in tool command logging."""
    # Call _wrap with a fake tool that has an Authorization header
    result = _wrap(
        tool="echo",
        cmd=["echo", "-H", "Authorization: Bearer supersecrettoken123"],
        timeout=5,
    )

    # Check that the command string in the result doesn't contain the token
    assert "supersecrettoken123" not in result.command, \
        f"Token leaked in command string: {result.command!r}"


def test_x_api_key_not_in_command_string():
    """X-API-Key header values must be redacted."""
    result = _wrap(
        tool="echo",
        cmd=["echo", "--header", "X-API-Key: mysecretkey999"],
        timeout=5,
    )

    # Check that the command string in the result doesn't contain the API key
    assert "mysecretkey999" not in result.command, \
        f"API key leaked in command string: {result.command!r}"


def test_normal_commands_not_redacted():
    """Non-sensitive command arguments must still appear in logs."""
    result = _wrap(
        tool="echo",
        cmd=["echo", "-u", "https://example.com", "--timeout", "30"],
        timeout=5,
    )

    # The URL should appear in the command string
    assert "example.com" in result.command, \
        f"Normal command args should not be redacted: {result.command!r}"


def test_missing_tool_returns_success_false():
    """rc=127 (tool not found) must result in ToolResult.success=False."""
    from modules.tool_wrappers import _wrap
    result = _wrap(tool="definitely_not_installed_xyz_abc", cmd=["definitely_not_installed_xyz_abc", "--help"])
    assert result.success is False, f"Missing tool should have success=False, got {result.success}"
    assert result.returncode == 127, f"Missing tool should have rc=127, got {result.returncode}"


def test_missing_tool_logs_warning_not_debug():
    """rc=127 must be logged at WARNING level so users see it, not just DEBUG."""
    import logging
    from modules.tool_wrappers import _wrap
    import modules.tool_wrappers as tw

    warning_messages = []

    class WarningCapture(logging.Handler):
        def emit(self, record):
            if record.levelno >= logging.WARNING:
                warning_messages.append(record.getMessage())

    handler = WarningCapture()
    tw.log.addHandler(handler)
    old_level = tw.log.level
    tw.log.setLevel(logging.DEBUG)

    _wrap(tool="definitely_not_installed_xyz_abc", cmd=["definitely_not_installed_xyz_abc", "--help"])

    tw.log.removeHandler(handler)
    tw.log.setLevel(old_level)

    assert warning_messages, (
        "Missing tool (rc=127) must produce a WARNING-level log message. "
        "Currently only logged at DEBUG level — users never see it."
    )


def test_success_false_on_nonzero_exit():
    """ToolResult.success must be False when tool exits non-zero, even if it produced output."""
    from modules.tool_wrappers import _wrap
    # python3 -c 'print("output"); exit(1)' — exits non-zero but produces stdout
    result = _wrap(
        tool="python3",
        cmd=["python3", "-c", "import sys; print('some output'); sys.exit(1)"],
    )
    assert result.success is False, (
        f"Tool that exits non-zero must have success=False even with output. Got success={result.success}"
    )


def test_success_true_only_on_rc_zero():
    """ToolResult.success must be True when tool exits 0."""
    from modules.tool_wrappers import _wrap
    result = _wrap(
        tool="python3",
        cmd=["python3", "-c", "print('ok')"],
    )
    assert result.success is True, f"Tool exiting 0 should have success=True, got {result.success}"
