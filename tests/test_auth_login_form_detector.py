# tests/test_auth_login_form_detector.py
import pytest
from unittest.mock import patch, MagicMock
from oneinfinity.auth.login_form_detector import LoginFormDetector, LoginFormResult

SIMPLE_LOGIN_HTML = """
<html><body>
<form action="/login" method="POST">
  <input type="text" name="username" />
  <input type="password" name="password" />
  <button type="submit">Login</button>
</form>
</body></html>
"""

EMAIL_LOGIN_HTML = """
<html><body>
<form action="/auth/signin" method="post">
  <input type="email" name="email" />
  <input type="password" name="pass" />
  <input type="submit" value="Sign in" />
</form>
</body></html>
"""

NO_LOGIN_HTML = """
<html><body>
<form action="/search" method="GET">
  <input type="text" name="q" />
</form>
</body></html>
"""

def _mock_fetch(html):
    def _fetch(url, timeout=10):
        return html, 200, {}
    return _fetch

def test_detects_simple_login_form():
    d = LoginFormDetector()
    with patch.object(d, '_fetch', _mock_fetch(SIMPLE_LOGIN_HTML)):
        r = d.detect("https://example.com")
    assert r.has_login_form is True
    assert r.username_field == "username"
    assert r.password_field == "password"
    assert r.form_action == "/login"
    assert r.form_method == "POST"

def test_detects_email_login_form():
    d = LoginFormDetector()
    with patch.object(d, '_fetch', _mock_fetch(EMAIL_LOGIN_HTML)):
        r = d.detect("https://example.com/signin")
    assert r.has_login_form is True
    assert r.username_field == "email"
    assert r.password_field == "pass"
    assert r.login_url == "https://example.com/signin"

def test_no_login_form():
    d = LoginFormDetector()
    with patch.object(d, '_fetch', _mock_fetch(NO_LOGIN_HTML)):
        r = d.detect("https://example.com/search")
    assert r.has_login_form is False

def test_fetch_failure_returns_no_form():
    d = LoginFormDetector()
    def _fail(url, timeout=10):
        raise ConnectionError("timeout")
    with patch.object(d, '_fetch', _fail):
        r = d.detect("https://example.com")
    assert r.has_login_form is False
