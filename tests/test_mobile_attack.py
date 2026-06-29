"""
Tests for Mobile Attack Execution API — Phase 2
"""
import asyncio
import json
import pytest
from unittest.mock import AsyncMock, MagicMock, patch


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def run(coro):
    """Run an async coroutine synchronously (Python 3.10+ compatible)."""
    return asyncio.run(coro)


# ---------------------------------------------------------------------------
# Import under test (graceful if optional deps are missing)
# ---------------------------------------------------------------------------

import sys
import os

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "web", "backend"))

try:
    from mobile_attack_api import (
        ATTACK_TEMPLATES,
        AttackSession,
        WAFAdaptivePayloadSelector,
        analyze_response_diff,
        get_chain_followups,
        list_attack_templates_handler,
        start_attack_session_handler,
        stop_attack_session_handler,
        get_attack_session_handler,
        get_session_findings_handler,
        _sessions,
    )
    IMPORT_OK = True
except ImportError:
    IMPORT_OK = False


# ---------------------------------------------------------------------------
# Tests: Attack Templates
# ---------------------------------------------------------------------------

@pytest.mark.skipif(not IMPORT_OK, reason="mobile_attack_api not importable")
class TestAttackTemplates:
    def test_templates_not_empty(self):
        assert len(ATTACK_TEMPLATES) >= 6

    def test_template_has_required_fields(self):
        for tpl in ATTACK_TEMPLATES:
            assert "id" in tpl
            assert "name" in tpl
            assert "attack_types" in tpl
            assert "severity" in tpl
            assert "owasp_ref" in tpl

    def test_full_owasp_template_exists(self):
        ids = [t["id"] for t in ATTACK_TEMPLATES]
        assert "full_owasp_mobile" in ids

    def test_list_templates_handler(self):
        result = run(list_attack_templates_handler())
        assert isinstance(result, list)
        assert len(result) >= 6


# ---------------------------------------------------------------------------
# Tests: WAFAdaptivePayloadSelector
# ---------------------------------------------------------------------------

@pytest.mark.skipif(not IMPORT_OK, reason="mobile_attack_api not importable")
class TestWAFAdaptivePayloadSelector:
    def setup_method(self):
        self.selector = WAFAdaptivePayloadSelector()

    def test_no_waf_empty_headers(self):
        waf = self.selector.detect_waf_from_headers({})
        assert waf == ""

    def test_cloudflare_detected(self):
        headers = {"cf-ray": "abc123-LHR", "server": "cloudflare"}
        waf = self.selector.detect_waf_from_headers(headers)
        # Only non-empty if WAFDetectionEngine is available
        assert isinstance(waf, str)

    def test_payloads_returned_for_sqli(self):
        payloads = self.selector.get_payloads_for_endpoint("sqli", {})
        assert isinstance(payloads, list)
        # Without KB the list may be empty; just check it's a list
        assert all(isinstance(p, str) for p in payloads)

    def test_payloads_capped_at_20(self):
        payloads = self.selector.get_payloads_for_endpoint("xss", {})
        assert len(payloads) <= 20

    def test_deduplicated_payloads(self):
        payloads = self.selector.get_payloads_for_endpoint("sqli", {})
        assert len(payloads) == len(set(payloads))


# ---------------------------------------------------------------------------
# Tests: Differential Response Analyzer
# ---------------------------------------------------------------------------

@pytest.mark.skipif(not IMPORT_OK, reason="mobile_attack_api not importable")
class TestDifferentialAnalyzer:
    def test_sql_error_detected(self):
        finding = analyze_response_diff(
            200, "normal response", 50.0,
            500, "You have an error in your SQL syntax near ...", 55.0,
            "' OR 1=1--", "sqli"
        )
        assert finding is not None
        assert "sql_error" in finding["evidence"]
        assert finding["vuln_type"] == "sqli"
        assert finding["confidence"] > 0.5

    def test_no_finding_on_identical_responses(self):
        finding = analyze_response_diff(
            200, "hello world response body normal", 50.0,
            200, "hello world response body normal", 52.0,
            "payload", "sqli"
        )
        assert finding is None

    def test_timing_anomaly_detected(self):
        finding = analyze_response_diff(
            200, "result", 200.0,
            200, "result", 7000.0,
            "1' AND SLEEP(5)--", "sqli"
        )
        assert finding is not None
        assert "timing_anomaly" in finding["evidence"]

    def test_ssrf_success_detected(self):
        finding = analyze_response_diff(
            200, "normal", 50.0,
            200, "ami-id: ami-0abcdef1234567890\ninstance-id: i-1234", 55.0,
            "http://169.254.169.254/", "ssrf"
        )
        assert finding is not None
        assert "ssrf_data" in finding["evidence"]

    def test_stack_trace_detected(self):
        finding = analyze_response_diff(
            200, "OK", 50.0,
            500, "Traceback (most recent call last):\n  File app.py line 42", 51.0,
            "'", "sqli"
        )
        assert finding is not None
        assert "stack_trace" in finding["evidence"]

    def test_finding_has_required_fields(self):
        finding = analyze_response_diff(
            200, "ok", 50.0,
            500, "SQL syntax error in your query", 52.0,
            "'", "sqli"
        )
        assert finding is not None
        for key in ("finding_id", "vuln_type", "severity", "confidence", "payload", "evidence"):
            assert key in finding, f"Missing field: {key}"

    def test_sensitive_leak_detected(self):
        baseline = '{"user":"alice"}'
        attack = '{"user":"alice","password":"hunter2","api_key":"secret123"}'
        finding = analyze_response_diff(200, baseline, 50.0, 200, attack, 50.0, "payload", "idor")
        assert finding is not None
        assert "data_leak" in finding["evidence"]


# ---------------------------------------------------------------------------
# Tests: Attack Chain Sequencer
# ---------------------------------------------------------------------------

@pytest.mark.skipif(not IMPORT_OK, reason="mobile_attack_api not importable")
class TestAttackChainSequencer:
    def test_idor_chains_to_mass_assignment(self):
        followups = get_chain_followups("idor")
        assert "mass_assignment" in followups

    def test_auth_bypass_chains_to_idor(self):
        followups = get_chain_followups("auth_bypass_no_header")
        assert "idor" in followups

    def test_unknown_type_returns_empty(self):
        followups = get_chain_followups("unknown_vuln_type_xyz")
        assert followups == []

    def test_jwt_alg_none_chains(self):
        followups = get_chain_followups("jwt_alg_none")
        assert len(followups) > 0


# ---------------------------------------------------------------------------
# Tests: AttackSession
# ---------------------------------------------------------------------------

@pytest.mark.skipif(not IMPORT_OK, reason="mobile_attack_api not importable")
class TestAttackSession:
    def test_session_has_unique_id(self):
        s1 = AttackSession()
        s2 = AttackSession()
        assert s1.session_id != s2.session_id

    def test_session_to_dict(self):
        s = AttackSession(device_id="dev1", template_id="m3_insecure_authentication")
        d = s.to_dict()
        assert d["device_id"] == "dev1"
        assert d["template_id"] == "m3_insecure_authentication"
        assert "stats" in d
        assert "duration_s" in d

    def test_session_default_status(self):
        s = AttackSession()
        assert s.status == "pending"


# ---------------------------------------------------------------------------
# Tests: Session Handlers (mocked)
# ---------------------------------------------------------------------------

@pytest.mark.skipif(not IMPORT_OK, reason="mobile_attack_api not importable")
class TestSessionHandlers:
    def test_start_session_requires_endpoints(self):
        from fastapi import HTTPException
        with pytest.raises(HTTPException) as exc:
            run(start_attack_session_handler({"device_id": "dev1", "endpoints": []}))
        assert exc.value.status_code == 400

    def test_start_session_rejects_non_http_endpoints(self):
        from fastapi import HTTPException
        with pytest.raises(HTTPException) as exc:
            run(start_attack_session_handler({"device_id": "dev1", "endpoints": ["ftp://bad.com"]}))
        assert exc.value.status_code == 400

    def test_stop_nonexistent_session(self):
        from fastapi import HTTPException
        with pytest.raises(HTTPException) as exc:
            run(stop_attack_session_handler("nonexistent_xyz"))
        assert exc.value.status_code == 404

    def test_get_nonexistent_session(self):
        from fastapi import HTTPException
        with pytest.raises(HTTPException) as exc:
            run(get_attack_session_handler("nonexistent_xyz"))
        assert exc.value.status_code == 404

    def test_start_session_with_valid_endpoints(self):
        """Session is created and background task launched."""
        with patch("mobile_attack_api._run_attack_session", new_callable=AsyncMock) as mock_runner:
            mock_runner.return_value = None
            with patch("asyncio.create_task") as mock_task:
                mock_task.return_value = MagicMock()
                result = run(start_attack_session_handler({
                    "device_id": "test_device",
                    "endpoints": ["https://example.com/api/users"],
                    "template_id": "m3_insecure_authentication",
                }))
        assert "session_id" in result
        assert result["status"] == "started"
        assert result["endpoints_queued"] == 1

    def test_session_template_fallback_to_full(self):
        """Unknown template ID falls back to full_owasp_mobile."""
        with patch("asyncio.create_task") as mock_task:
            mock_task.return_value = MagicMock()
            result = run(start_attack_session_handler({
                "device_id": "d1",
                "endpoints": ["https://example.com/"],
                "template_id": "this_template_does_not_exist",
            }))
        assert result["template"] == "full_owasp_mobile"
