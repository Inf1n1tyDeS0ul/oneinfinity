# tests/test_auth_session_manager.py
import json
import pytest
from pathlib import Path
from oneinfinity.auth.session_manager import SessionManager, LoginSession

def test_save_and_load_auto(tmp_path):
    mgr = SessionManager(base_dir=tmp_path)
    s = LoginSession(
        session_id="abc123",
        target="https://example.com",
        login_url="https://example.com/login",
        cookies=[{"name": "session", "value": "s1", "domain": "example.com"}],
        auth_headers={"Authorization": "Bearer tok"},
        local_storage={"token": "tok"},
        session_storage={},
        indexeddb_snapshot={},
        har_path="",
        recorder="playwright",
    )
    mgr.save(s)
    loaded = mgr.load(target="https://example.com")
    assert loaded is not None
    assert loaded.session_id == "abc123"
    assert loaded.cookies[0]["name"] == "session"

def test_save_and_load_named(tmp_path):
    mgr = SessionManager(base_dir=tmp_path)
    s = LoginSession(
        session_id="xyz999",
        target="https://app.io",
        login_url="https://app.io/signin",
        cookies=[],
        auth_headers={},
        local_storage={},
        session_storage={},
        indexeddb_snapshot={},
        har_path="",
        recorder="playwright",
    )
    mgr.save(s, name="myapp")
    loaded = mgr.load(name="myapp")
    assert loaded is not None
    assert loaded.session_id == "xyz999"

def test_list_all(tmp_path):
    mgr = SessionManager(base_dir=tmp_path)
    for i in range(3):
        s = LoginSession(
            session_id=f"s{i}", target=f"https://t{i}.com", login_url=f"https://t{i}.com/login",
            cookies=[], auth_headers={}, local_storage={}, session_storage={},
            indexeddb_snapshot={}, har_path="", recorder="playwright",
        )
        mgr.save(s, name=f"sess{i}")
    assert len(mgr.list_all()) == 3

def test_delete(tmp_path):
    mgr = SessionManager(base_dir=tmp_path)
    s = LoginSession(
        session_id="del1", target="https://del.com", login_url="https://del.com/login",
        cookies=[], auth_headers={}, local_storage={}, session_storage={},
        indexeddb_snapshot={}, har_path="", recorder="playwright",
    )
    mgr.save(s, name="todelete")
    mgr.delete("del1")
    assert mgr.load(name="todelete") is None

def test_exists(tmp_path):
    mgr = SessionManager(base_dir=tmp_path)
    assert mgr.exists(target="https://example.com") is False
    s = LoginSession(
        session_id="ex1", target="https://example.com", login_url="https://example.com/login",
        cookies=[], auth_headers={}, local_storage={}, session_storage={},
        indexeddb_snapshot={}, har_path="", recorder="playwright",
    )
    mgr.save(s)
    assert mgr.exists(target="https://example.com") is True

def test_load_missing_returns_none(tmp_path):
    mgr = SessionManager(base_dir=tmp_path)
    assert mgr.load(target="https://nobody.com") is None
    assert mgr.load(name="nonexistent") is None
