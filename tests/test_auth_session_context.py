# tests/test_auth_session_context.py
import pytest
from unittest.mock import MagicMock, patch
from oneinfinity.auth.session_manager import LoginSession
from oneinfinity.auth.auth_session_context import AuthSessionContext

def _session(cookies=None, auth_headers=None):
    return LoginSession(
        session_id="ctx1", target="https://app.com",
        login_url="https://app.com/login",
        cookies=cookies or [{"name": "session", "value": "abc123", "domain": "app.com"}],
        auth_headers=auth_headers or {"Authorization": "Bearer tok123"},
        local_storage={}, session_storage={}, indexeddb_snapshot={},
        har_path="", recorder="playwright",
    )

def test_inject_requests_sets_cookies_and_headers():
    import requests
    ctx = AuthSessionContext(_session())
    s = requests.Session()
    ctx.inject_requests(s)
    assert s.cookies.get("session") == "abc123"
    assert s.headers.get("Authorization") == "Bearer tok123"

def test_inject_subprocess_env():
    ctx = AuthSessionContext(_session())
    env = {}
    result = ctx.inject_subprocess_env(env)
    assert "COOKIE" in result
    assert "session=abc123" in result["COOKIE"]
    assert "AUTH_HEADER" in result

def test_is_session_expired_401():
    ctx = AuthSessionContext(_session())
    mock_resp = MagicMock()
    mock_resp.status_code = 401
    mock_resp.url = "https://app.com/api/data"
    assert ctx.is_session_expired(mock_resp) is True

def test_is_session_expired_redirect_to_login():
    ctx = AuthSessionContext(_session())
    mock_resp = MagicMock()
    mock_resp.status_code = 302
    mock_resp.url = "https://app.com/login?next=/api/data"
    assert ctx.is_session_expired(mock_resp) is True

def test_is_session_expired_200():
    ctx = AuthSessionContext(_session())
    mock_resp = MagicMock()
    mock_resp.status_code = 200
    mock_resp.url = "https://app.com/api/data"
    assert ctx.is_session_expired(mock_resp) is False

def test_to_auth_config():
    ctx = AuthSessionContext(_session(
        cookies=[{"name": "sess", "value": "val1", "domain": "app.com"}],
        auth_headers={"Authorization": "Bearer mytoken"},
    ))
    cfg = ctx.to_auth_config()
    assert cfg["session_cookie"] == "sess=val1"
    assert cfg["bearer_token"] == "mytoken"
