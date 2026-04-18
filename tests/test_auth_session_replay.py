# tests/test_auth_session_replay.py
import json
import pytest
from unittest.mock import patch, MagicMock
from oneinfinity.auth.session_replay import SessionReplay
from oneinfinity.auth.session_manager import LoginSession

def _make_session(cookies=None, har_path=""):
    return LoginSession(
        session_id="r1", target="https://app.com",
        login_url="https://app.com/login",
        cookies=cookies or [{"name": "session", "value": "old", "domain": "app.com"}],
        auth_headers={}, local_storage={}, session_storage={},
        indexeddb_snapshot={}, har_path=har_path, recorder="playwright",
    )

# Minimal HAR with a single POST /login entry
MINIMAL_HAR = json.dumps({
    "log": {
        "entries": [{
            "request": {
                "method": "POST",
                "url": "https://app.com/login",
                "headers": [{"name": "Content-Type", "value": "application/x-www-form-urlencoded"}],
                "postData": {"text": "username=admin&password=secret"},
            }
        }]
    }
})

def test_replay_updates_cookies(tmp_path):
    har_file = tmp_path / "session.har"
    har_file.write_text(MINIMAL_HAR)
    session = _make_session(har_path=str(har_file))

    mock_resp = MagicMock()
    mock_resp.status_code = 200
    mock_resp.cookies = {"session": "newsession456", "csrf": "abc"}
    mock_resp.headers = {"Set-Cookie": "session=newsession456"}

    with patch("httpx.Client") as MockClient:
        instance = MockClient.return_value.__enter__.return_value
        instance.send.return_value = mock_resp
        instance.cookies = {"session": "newsession456"}
        replay = SessionReplay()
        success = replay.replay(session)

    # SessionReplay should return True on 200
    assert success is True

def test_replay_returns_false_on_empty_har(tmp_path):
    har_file = tmp_path / "empty.har"
    har_file.write_text(json.dumps({"log": {"entries": []}}))
    session = _make_session(har_path=str(har_file))
    replay = SessionReplay()
    assert replay.replay(session) is False

def test_replay_returns_false_on_missing_har():
    session = _make_session(har_path="/nonexistent/path.har")
    replay = SessionReplay()
    assert replay.replay(session) is False
