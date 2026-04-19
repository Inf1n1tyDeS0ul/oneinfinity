"""Verify the HTTP client does not leak GitHub-specific headers to arbitrary targets."""
import sys


def _fresh_client():
    """Get a fresh OneInfinityHTTPClient bypassing the singleton."""
    mod_name = "oneinfinity.core.http_client"
    if mod_name in sys.modules:
        del sys.modules[mod_name]
    from oneinfinity.core.http_client import OneInfinityHTTPClient
    OneInfinityHTTPClient._instance = None
    client = OneInfinityHTTPClient()
    return client


def test_no_github_accept_header_in_default_session():
    """Default session headers must NOT contain the GitHub v3 Accept header."""
    client = _fresh_client()
    accept = client.session.headers.get("Accept", "")
    assert "vnd.github" not in accept, (
        f"GitHub-specific Accept header found in default session: {accept!r}"
    )


def test_user_agent_present():
    """User-Agent must still be set correctly."""
    client = _fresh_client()
    ua = client.session.headers.get("User-Agent", "")
    assert "OneInfinity" in ua
