"""Tests for new validate_* methods added for OWASP gap checks."""
import sys, os
sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))

from finding_validation_engine import FindingValidationEngine, ValidationResult


def _make_result():
    return ValidationResult(
        vuln_type="test",
        url="http://test.local",
        validated=False,
        confidence=0.5,
        evidence="",
        evidence_type="",
        flags=[],
    )


def _make_engine():
    return FindingValidationEngine()


# ── validate_ssrf_oob ─────────────────────────────────────────────────────────

def test_ssrf_oob_confirmed_when_flag_set():
    engine = _make_engine()
    result = _make_result()
    finding = {"oob_callback_received": True, "evidence": "OOB DNS callback from 1.2.3.4"}
    ok = engine.validate_ssrf_oob(result, finding, "http://test.local", "", "url", "GET")
    assert ok is True
    assert result.confidence == 0.95
    assert "ssrf_oob_confirmed" in result.flags


def test_ssrf_oob_not_confirmed_without_flag():
    engine = _make_engine()
    result = _make_result()
    finding = {"oob_callback_received": False}
    ok = engine.validate_ssrf_oob(result, finding, "http://test.local", "", "url", "GET")
    assert ok is False
    assert result.confidence == 0.35
    assert "ssrf_unconfirmed_no_oob" in result.flags


def test_ssrf_oob_missing_flag_treated_as_false():
    engine = _make_engine()
    result = _make_result()
    finding = {}  # no oob_callback_received key
    ok = engine.validate_ssrf_oob(result, finding, "http://test.local", "", "url", "GET")
    assert ok is False
    assert result.confidence <= 0.4


# ── validate_cookie_attrs ─────────────────────────────────────────────────────

def test_cookie_attrs_passive_finding_updates_result():
    engine = _make_engine()
    result = _make_result()
    finding = {"response_headers": {"Set-Cookie": "session=abc; Path=/"}}
    # passive_finding=True, confidence>=0.7 expected for missing HttpOnly/Secure/SameSite
    # method returns active_confirmed (False when HTTP confirm fails/not attempted)
    engine.validate_cookie_attrs(result, finding, "http://test.local", "", "", "GET")
    assert result.evidence != ""
    assert "insecure_cookie" in result.flags


def test_cookie_attrs_no_cookie_header_does_nothing():
    engine = _make_engine()
    result = _make_result()
    finding = {"response_headers": {}}
    engine.validate_cookie_attrs(result, finding, "http://test.local", "", "", "GET")
    # No cookie → no change to flags
    assert "insecure_cookie" not in result.flags


# ── validate_session_fixation ─────────────────────────────────────────────────

def test_session_fixation_same_id_before_after_fires():
    engine = _make_engine()
    result = _make_result()
    finding = {
        "pre_login_session_id": "SESS_BEFORE_LOGIN",
        "post_login_session_id": "SESS_BEFORE_LOGIN",  # same = fixation
    }
    ok = engine.validate_session_fixation(result, finding, "http://test.local", "", "", "POST")
    assert ok is True
    assert "session_fixation" in result.flags


def test_session_fixation_different_id_does_not_fire():
    engine = _make_engine()
    result = _make_result()
    finding = {
        "pre_login_session_id": "OLD_SESSION",
        "post_login_session_id": "NEW_SESSION",  # changed = correct behaviour
    }
    ok = engine.validate_session_fixation(result, finding, "http://test.local", "", "", "POST")
    assert ok is False


# ── validate_account_enumeration ─────────────────────────────────────────────

def test_account_enumeration_no_network_call_with_empty_url():
    """validate_account_enumeration should not raise when URL is unreachable."""
    engine = _make_engine()
    result = _make_result()
    finding = {"valid_username": "admin", "invalid_username": "nosuchuser_oi_test"}
    # This will fail the network call gracefully and return False (not raise)
    ok = engine.validate_account_enumeration(result, finding, "http://127.0.0.1:19999/login", "", "", "POST")
    assert ok is False  # unreachable → False, not exception


# ── _dispatch registration ────────────────────────────────────────────────────

def test_dispatch_csrf_key_registered():
    engine = _make_engine()
    dispatch = engine._get_dispatch()
    assert "csrf" in dispatch
    assert "missing_csrf" in dispatch


def test_dispatch_cookie_attributes_key_registered():
    engine = _make_engine()
    dispatch = engine._get_dispatch()
    assert "cookie_attributes" in dispatch
    assert "insecure_cookie" in dispatch


def test_dispatch_session_fixation_key_registered():
    engine = _make_engine()
    dispatch = engine._get_dispatch()
    assert "session_fixation" in dispatch


def test_dispatch_ldap_injection_key_registered():
    engine = _make_engine()
    dispatch = engine._get_dispatch()
    assert "ldap_injection" in dispatch


def test_dispatch_weak_tls_key_registered():
    engine = _make_engine()
    dispatch = engine._get_dispatch()
    assert "weak_tls" in dispatch


def test_dispatch_ssrf_oob_key_registered():
    engine = _make_engine()
    dispatch = engine._get_dispatch()
    assert "ssrf_oob" in dispatch


def test_dispatch_padding_oracle_key_registered():
    engine = _make_engine()
    dispatch = engine._get_dispatch()
    assert "padding_oracle" in dispatch


def test_dispatch_account_enumeration_key_registered():
    engine = _make_engine()
    dispatch = engine._get_dispatch()
    assert "account_enumeration" in dispatch
