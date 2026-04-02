# tests/test_tool_wrappers.py
import sys, logging
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
