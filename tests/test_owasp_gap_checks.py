"""Unit tests for OWASP gap checks — tests run against mock HTTP responses."""
import sys, os
sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))

from modules.owasp_gap_checks import (
    GapCheckResult,
    check_cookie_attributes,
    check_csrf,
    check_weak_tls,
    check_session_fixation,
    check_account_enumeration_timing,
    check_ldap_injection,
    check_mail_header_injection,
    check_code_injection,
    check_csv_injection,
    check_web_storage,
    check_backup_files,
    check_weak_encryption_patterns,
    check_service_worker,
    check_insecure_rng,
    check_padding_oracle,
    check_grpc_soap,
    check_saml_assertion,
    check_password_policy,
    check_postmessage_hijacking,
    check_webrtc_leak,
    check_tls_cert,
    check_session_timeout,
    gap_check_result_to_finding,
)

# ── GapCheckResult contract ───────────────────────────────────────────────────

def test_gap_check_result_defaults():
    r = GapCheckResult(check_id="WSTG-TEST-01")
    assert r.passive_finding is False
    assert r.active_confirmed is False
    assert r.confidence == 0.0
    assert r.needs_validation is True

def test_gap_check_result_active_confirmed_clears_needs_validation():
    r = GapCheckResult(check_id="X", active_confirmed=True, confidence=0.8)
    assert r.needs_validation is False

def test_gap_check_result_severity_high_requires_active():
    r = GapCheckResult(check_id="X", active_confirmed=True, confidence=0.8)
    f = gap_check_result_to_finding(r, url="http://t.local")
    assert f["severity"] in ("high", "critical")

def test_gap_check_result_passive_only_is_low():
    r = GapCheckResult(check_id="X", passive_finding=True, active_confirmed=False, confidence=0.6)
    f = gap_check_result_to_finding(r, url="http://t.local")
    assert f["severity"] in ("low", "info")

def test_gap_check_result_below_threshold_suppressed():
    r = GapCheckResult(check_id="X", confidence=0.3)
    f = gap_check_result_to_finding(r, url="http://t.local")
    assert f is None

def test_to_finding_includes_check_id():
    r = GapCheckResult(check_id="WSTG-SESS-05", active_confirmed=True, confidence=0.8,
                       evidence="CSRF token absent", passive_finding=True)
    f = gap_check_result_to_finding(r, url="http://t.local/api/users")
    assert f is not None
    assert f["check_id"] == "WSTG-SESS-05"
    assert f["url"] == "http://t.local/api/users"
    assert f["source_type"] == "owasp_gap"

# ── Cookie attribute check ────────────────────────────────────────────────────

def test_cookie_check_flags_missing_httponly():
    headers = {"Set-Cookie": "session=abc123; Path=/; Secure; SameSite=Lax"}
    r = check_cookie_attributes("http://test.local", headers)
    assert r.passive_finding is True
    assert "HttpOnly" in r.evidence

def test_cookie_check_flags_missing_secure():
    headers = {"Set-Cookie": "session=abc123; Path=/; HttpOnly; SameSite=Lax"}
    r = check_cookie_attributes("http://test.local", headers)
    assert r.passive_finding is True
    assert "Secure" in r.evidence

def test_cookie_check_passes_when_all_present():
    headers = {"Set-Cookie": "session=abc123; Path=/; Secure; HttpOnly; SameSite=Strict"}
    r = check_cookie_attributes("http://test.local", headers)
    assert r.passive_finding is False

def test_cookie_check_no_cookie_header_returns_empty():
    r = check_cookie_attributes("http://test.local", {})
    assert r.passive_finding is False
    assert r.confidence == 0.0

# ── Session fixation ──────────────────────────────────────────────────────────

def test_session_fixation_same_id_flags():
    r = check_session_fixation("abc123", "abc123", "http://test.local")
    assert r.passive_finding is True
    assert r.active_confirmed is True
    assert r.confidence >= 0.8

def test_session_fixation_different_id_passes():
    r = check_session_fixation("abc123", "xyz789", "http://test.local")
    assert r.passive_finding is False

def test_session_fixation_empty_ids_passes():
    r = check_session_fixation("", "", "http://test.local")
    assert r.passive_finding is False

# ── CSRF check (passive only — no live server) ────────────────────────────────

def test_csrf_flags_missing_token_on_post():
    r = check_csrf("http://test.local/api", "<form>no token here</form>", {}, method="POST")
    assert r.passive_finding is True

def test_csrf_passes_when_token_present():
    body = '<input name="csrf_token" value="abc"/>'
    r = check_csrf("http://test.local/api", body, {}, method="POST")
    assert r.passive_finding is False

def test_csrf_passes_on_get_method():
    r = check_csrf("http://test.local/api", "<form></form>", {}, method="GET")
    assert r.passive_finding is False

def test_csrf_passes_when_samesite_strict():
    headers = {"Set-Cookie": "session=x; SameSite=Strict"}
    r = check_csrf("http://test.local/api", "<form></form>", headers, method="POST")
    assert r.passive_finding is False

# ── Weak encryption pattern check ────────────────────────────────────────────

def test_weak_encryption_md5_detected():
    body = 'var hash = MD5(password);'
    r = check_weak_encryption_patterns("http://test.local/app.js", body)
    assert r.passive_finding is True
    assert "MD5" in r.evidence

def test_weak_encryption_sha1_detected():
    body = 'var sig = SHA1(data);'
    r = check_weak_encryption_patterns("http://test.local/app.js", body)
    assert r.passive_finding is True

def test_weak_encryption_clean_body_passes():
    body = 'var hash = bcrypt.hash(password, 12);'
    r = check_weak_encryption_patterns("http://test.local/app.js", body)
    assert r.passive_finding is False

# ── Web storage check ─────────────────────────────────────────────────────────

def test_web_storage_detects_sensitive_key():
    js = 'localStorage.setItem("auth_token", userToken);'
    r = check_web_storage("http://test.local", js)
    assert r.passive_finding is True

def test_web_storage_jwt_key_detected():
    js = 'localStorage.setItem("jwt", response.token);'
    r = check_web_storage("http://test.local", js)
    assert r.passive_finding is True

def test_web_storage_non_sensitive_key_passes():
    js = 'localStorage.setItem("ui_theme", "dark");'
    r = check_web_storage("http://test.local", js)
    assert r.passive_finding is False

# ── RNG entropy check ─────────────────────────────────────────────────────────

def test_insecure_rng_sequential_tokens():
    tokens = [f"session_{i:04d}" for i in range(10)]
    r = check_insecure_rng("http://test.local", tokens)
    assert r.passive_finding is True

def test_insecure_rng_random_tokens_passes():
    import secrets
    tokens = [secrets.token_hex(16) for _ in range(10)]
    r = check_insecure_rng("http://test.local", tokens)
    assert r.passive_finding is False

def test_insecure_rng_too_few_tokens_passes():
    tokens = ["abc", "def"]
    r = check_insecure_rng("http://test.local", tokens)
    assert r.passive_finding is False

# ── postMessage check ─────────────────────────────────────────────────────────

def test_postmessage_without_origin_check_flagged():
    js = "window.addEventListener('message', function(event) { doSomething(event.data); });"
    r = check_postmessage_hijacking("http://test.local", js)
    assert r.passive_finding is True

def test_postmessage_with_origin_check_passes():
    js = "window.addEventListener('message', function(event) { if (event.origin !== 'https://trusted.com') return; });"
    r = check_postmessage_hijacking("http://test.local", js)
    assert r.passive_finding is False

def test_postmessage_no_listener_passes():
    js = "var x = 1 + 1;"
    r = check_postmessage_hijacking("http://test.local", js)
    assert r.passive_finding is False

# ── SAML check ────────────────────────────────────────────────────────────────

def test_saml_unsigned_assertion_flagged():
    body = '<samlp:Response><saml:Assertion>unsigned</saml:Assertion></samlp:Response>'
    r = check_saml_assertion("http://test.local/saml", body)
    assert r.passive_finding is True
    assert r.confidence >= 0.7

def test_saml_signed_assertion_passes():
    body = '<samlp:Response><Signature>...</Signature><saml:Assertion>...</saml:Assertion></samlp:Response>'
    r = check_saml_assertion("http://test.local/saml", body)
    assert r.passive_finding is False

def test_saml_non_saml_body_passes():
    body = '<html><body>Hello world</body></html>'
    r = check_saml_assertion("http://test.local", body)
    assert r.passive_finding is False

# ── gRPC/SOAP check ───────────────────────────────────────────────────────────

def test_grpc_content_type_detected():
    r = check_grpc_soap("http://test.local/api", {"Content-Type": "application/grpc"}, "")
    assert r.passive_finding is True

def test_wsdl_body_detected():
    r = check_grpc_soap("http://test.local/service", {}, "<definitions xmlns='...'></definitions>")
    assert r.passive_finding is True

def test_clean_html_passes():
    r = check_grpc_soap("http://test.local", {"Content-Type": "text/html"}, "<html></html>")
    assert r.passive_finding is False

# ── Service worker check ──────────────────────────────────────────────────────

def test_service_worker_root_scope_flagged():
    js = "navigator.serviceWorker.register('/sw.js');"
    r = check_service_worker("http://test.local", js)
    assert r.passive_finding is True

def test_service_worker_no_registration_passes():
    js = "var x = 1;"
    r = check_service_worker("http://test.local", js)
    assert r.passive_finding is False

# ── WebRTC check ──────────────────────────────────────────────────────────────

def test_webrtc_detected():
    js = "var pc = new RTCPeerConnection(config);"
    r = check_webrtc_leak("http://test.local", js)
    assert r.passive_finding is True

def test_webrtc_absent_passes():
    js = "var x = 1;"
    r = check_webrtc_leak("http://test.local", js)
    assert r.passive_finding is False

# ── gap_check_result_to_finding edge cases ────────────────────────────────────

def test_to_finding_medium_severity_active_low_confidence():
    r = GapCheckResult(check_id="X", active_confirmed=True, confidence=0.55)
    f = gap_check_result_to_finding(r, url="http://t.local")
    assert f["severity"] == "medium"

def test_to_finding_none_when_confidence_zero():
    r = GapCheckResult(check_id="X")
    f = gap_check_result_to_finding(r, url="http://t.local")
    assert f is None
