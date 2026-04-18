# tests/test_auth_login_session_recorder.py
import pytest
from unittest.mock import patch, MagicMock, call
from oneinfinity.auth.login_form_detector import LoginFormResult
from oneinfinity.auth.login_session_recorder import LoginSessionRecorder

def _form(action="https://app.com/login", user="username", pw="password"):
    return LoginFormResult(
        has_login_form=True,
        login_url="https://app.com/login",
        username_field=user,
        password_field=pw,
        form_action=action,
        form_method="POST",
    )

def test_record_auto_no_credentials_returns_none():
    rec = LoginSessionRecorder()
    session = rec.record_auto(login_form=_form(), credentials=None)
    assert session is None

def test_record_auto_or_interactive_no_display_no_creds_returns_none():
    rec = LoginSessionRecorder()
    with patch.dict("os.environ", {}, clear=True):
        with patch("oneinfinity.auth.login_session_recorder._has_display", return_value=False):
            result = rec.record_auto_or_interactive(login_form=_form(), credentials=None)
    assert result is None

def test_record_auto_or_interactive_prefers_auto():
    rec = LoginSessionRecorder()
    fake_session = MagicMock()
    with patch.object(rec, "record_auto", return_value=fake_session) as mock_auto:
        result = rec.record_auto_or_interactive(
            login_form=_form(),
            credentials=("admin", "pass"),
        )
    mock_auto.assert_called_once()
    assert result is fake_session
