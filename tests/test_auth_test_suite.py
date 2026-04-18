# tests/test_auth_test_suite.py
import pytest
from unittest.mock import patch, MagicMock
from oneinfinity.auth.session_manager import LoginSession
from oneinfinity.auth.auth_session_context import AuthSessionContext
from oneinfinity.auth.authenticated_test_suite import AuthenticatedTestSuite, Finding

def _ctx():
    session = LoginSession(
        session_id="t1", target="https://app.com", login_url="https://app.com/login",
        cookies=[{"name": "session", "value": "abc", "domain": "app.com",
                  "httpOnly": False, "secure": False, "sameSite": "None"}],
        auth_headers={"Authorization": "Bearer eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0.eyJzdWIiOiIxIn0."},
        local_storage={}, session_storage={}, indexeddb_snapshot={},
        har_path="", recorder="playwright",
    )
    return AuthSessionContext(session)

def _suite(endpoints=None):
    return AuthenticatedTestSuite(
        target="https://app.com",
        endpoints=endpoints or ["https://app.com/api/users/1", "https://app.com/api/orders/42"],
        auth_context=_ctx(),
    )

def test_finding_has_required_fields():
    f = Finding(vuln_type="test", title="Test", severity="medium",
                url="https://app.com/test", evidence="evidence", payload="", parameter="")
    assert f.vuln_type
    assert f.severity in ("critical", "high", "medium", "low", "info")

def test_test_cookie_security_detects_missing_httponly():
    suite = _suite()
    findings = suite.test_cookie_security()
    vuln_types = [f.vuln_type for f in findings]
    assert "missing_httponly" in vuln_types

def test_test_cookie_security_detects_missing_secure():
    suite = _suite()
    findings = suite.test_cookie_security()
    vuln_types = [f.vuln_type for f in findings]
    assert "missing_secure_flag" in vuln_types

def test_test_jwt_detects_alg_none():
    suite = _suite()
    # The fixture has a JWT with alg:none in auth_headers
    findings = suite.test_jwt()
    vuln_types = [f.vuln_type for f in findings]
    assert "jwt_alg_none" in vuln_types

def test_test_csrf_makes_http_calls():
    suite = _suite()
    mock_resp = MagicMock()
    mock_resp.status_code = 200
    with patch("httpx.Client") as MockClient:
        instance = MockClient.return_value.__enter__.return_value
        instance.request.return_value = mock_resp
        findings = suite.test_csrf()
    # test runs without error; may or may not find CSRF
    assert isinstance(findings, list)

def test_run_all_returns_list():
    suite = _suite()
    # Patch all HTTP calls to avoid network
    mock_resp = MagicMock()
    mock_resp.status_code = 200
    mock_resp.text = ""
    mock_resp.headers = {}
    mock_resp.cookies = {}
    with patch("httpx.Client") as MockClient:
        instance = MockClient.return_value.__enter__.return_value
        instance.get.return_value = mock_resp
        instance.post.return_value = mock_resp
        instance.request.return_value = mock_resp
        findings = suite.run_all()
    assert isinstance(findings, list)
