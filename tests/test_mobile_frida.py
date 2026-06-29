"""
Tests for Mobile Frida Integration API — Phase 3
"""
import asyncio
import pytest
from unittest.mock import AsyncMock, MagicMock, patch


def run(coro):
    return asyncio.run(coro)


# ---------------------------------------------------------------------------
# Imports under test
# ---------------------------------------------------------------------------

import sys, os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "web", "backend"))
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

try:
    from mobile_frida_api import (
        FridaSession, FridaFinding,
        _MASTG_SCRIPT_MAP, _ATTACK_TYPE_TO_MASTG, _MASTG_SEQUENCE,
        _enrich_with_mastg, _build_script_library, _generate_ai_hooks,
        _generate_mastg_report, _advance_mastg_sequence,
        list_frida_sessions_handler, get_frida_session_handler,
        stop_frida_session_handler, get_script_library_handler,
        ai_generate_hooks_handler, mastg_report_handler,
        _sessions,
    )
    IMPORT_OK = True
except ImportError:
    IMPORT_OK = False

try:
    from oneinfinity.mobile.frida_wrapper import FridaResult
    FRIDA_OK = True
except ImportError:
    FRIDA_OK = False

try:
    from oneinfinity.mobile.frida_script_generator import frida_script_generator
    GEN_OK = True
except ImportError:
    GEN_OK = False

try:
    from oneinfinity.mobile.mastg_knowledge import MASTG_TESTS
    MASTG_OK = True
except ImportError:
    MASTG_OK = False


# ---------------------------------------------------------------------------
# FridaResult bug fix tests
# ---------------------------------------------------------------------------

@pytest.mark.skipif(not FRIDA_OK, reason="frida_wrapper not importable")
class TestFridaResultFix:
    def test_success_no_error(self):
        r = FridaResult(package="com.test", script_name="test")
        assert r.success is True

    def test_success_with_error(self):
        r = FridaResult(package="com.test", script_name="test", error="crashed")
        assert r.success is False

    def test_execution_time_alias(self):
        r = FridaResult(package="com.test", script_name="test", duration=3.5)
        assert r.execution_time == 3.5

    def test_to_dict_has_success(self):
        r = FridaResult(package="com.test", script_name="test")
        d = r.to_dict()
        assert "success" in d
        assert "execution_time" in d


# ---------------------------------------------------------------------------
# MASTG knowledge tests
# ---------------------------------------------------------------------------

@pytest.mark.skipif(not MASTG_OK, reason="mastg_knowledge not importable")
class TestMastgKnowledge:
    def test_mastg_tests_not_empty(self):
        assert len(MASTG_TESTS) >= 5

    def test_mastg_has_required_fields(self):
        for tid, item in MASTG_TESTS.items():
            assert item.id
            assert item.title
            assert item.category
            assert item.masvs_mapping

    def test_ssl_test_present(self):
        assert "MASTG-TEST-0022" in MASTG_TESTS

    def test_root_test_present(self):
        assert "MASTG-TEST-0045" in MASTG_TESTS

    def test_crypto_tests_present(self):
        assert "MASTG-TEST-0212" in MASTG_TESTS
        assert "MASTG-TEST-0221" in MASTG_TESTS


# ---------------------------------------------------------------------------
# MASTG enrichment tests
# ---------------------------------------------------------------------------

@pytest.mark.skipif(not IMPORT_OK, reason="mobile_frida_api not importable")
class TestMastgEnrichment:
    def test_ssl_pinning_maps_to_mastg(self):
        mastg_ids, masvs_ids = _enrich_with_mastg("ssl_pinning")
        assert len(mastg_ids) > 0
        assert any("0022" in m for m in mastg_ids)

    def test_root_bypass_maps_to_mastg(self):
        mastg_ids, masvs_ids = _enrich_with_mastg("root_bypass")
        assert any("0045" in m for m in mastg_ids)

    def test_weak_crypto_maps_to_mastg(self):
        mastg_ids, masvs_ids = _enrich_with_mastg("weak_crypto")
        assert len(mastg_ids) > 0

    def test_unknown_attack_returns_empty(self):
        mastg_ids, masvs_ids = _enrich_with_mastg("unknown_attack_xyz")
        assert mastg_ids == []
        assert masvs_ids == []

    def test_masvs_ids_returned(self):
        _, masvs_ids = _enrich_with_mastg("ssl_pinning")
        assert any("NETWORK" in m or "MASVS" in m for m in masvs_ids)


# ---------------------------------------------------------------------------
# Script library tests
# ---------------------------------------------------------------------------

@pytest.mark.skipif(not IMPORT_OK or not GEN_OK, reason="dependencies not importable")
class TestScriptLibrary:
    def test_library_not_empty(self):
        lib = _build_script_library()
        assert len(lib) >= 4

    def test_ssl_bypass_in_library(self):
        lib = _build_script_library()
        names = [s["name"] for s in lib]
        assert "ssl_bypass" in names

    def test_root_bypass_in_library(self):
        lib = _build_script_library()
        names = [s["name"] for s in lib]
        assert "root_bypass" in names

    def test_script_has_content(self):
        lib = _build_script_library()
        for script in lib:
            assert script["script_content"], f"Empty script content for {script['name']}"

    def test_script_has_mastg_mapping(self):
        lib = _build_script_library()
        ssl_script = next((s for s in lib if s["name"] == "ssl_bypass"), None)
        assert ssl_script is not None
        assert len(ssl_script["mastg_ids"]) > 0

    def test_library_handler(self):
        result = run(get_script_library_handler("com.test"))
        assert isinstance(result, list)


# ---------------------------------------------------------------------------
# FridaSession tests
# ---------------------------------------------------------------------------

@pytest.mark.skipif(not IMPORT_OK, reason="mobile_frida_api not importable")
class TestFridaSession:
    def test_unique_session_ids(self):
        s1, s2 = FridaSession(), FridaSession()
        assert s1.session_id != s2.session_id

    def test_default_status(self):
        s = FridaSession()
        assert s.status == "pending"

    def test_to_dict(self):
        s = FridaSession(device_id="dev1", package_name="com.test")
        d = s.to_dict()
        assert d["device_id"] == "dev1"
        assert d["package_name"] == "com.test"
        assert "duration_s" in d
        assert "mastg_queue" in d

    def test_output_log_capped(self):
        s = FridaSession()
        s.output_log = [str(i) for i in range(200)]
        d = s.to_dict()
        assert len(d["output_log"]) <= 100  # last 100 lines


# ---------------------------------------------------------------------------
# MASTG sequence tests
# ---------------------------------------------------------------------------

@pytest.mark.skipif(not IMPORT_OK, reason="mobile_frida_api not importable")
class TestMastgSequence:
    def test_ssl_finding_triggers_next(self):
        session = FridaSession(mastg_queue=list(_MASTG_SEQUENCE))
        finding = FridaFinding(attack_type="ssl_pinning")
        session.findings.append(finding)
        _advance_mastg_sequence(session)
        assert "MASTG-TEST-0022" in session.mastg_completed

    def test_completed_not_re_queued(self):
        session = FridaSession(mastg_queue=list(_MASTG_SEQUENCE))
        session.mastg_completed.append("MASTG-TEST-0022")
        finding = FridaFinding(attack_type="ssl_pinning")
        session.findings.append(finding)
        _advance_mastg_sequence(session)
        # Should not be duplicated in completed
        assert session.mastg_completed.count("MASTG-TEST-0022") == 1

    def test_mastg_sequence_not_empty(self):
        assert len(_MASTG_SEQUENCE) >= 5


# ---------------------------------------------------------------------------
# MASTG report tests
# ---------------------------------------------------------------------------

@pytest.mark.skipif(not IMPORT_OK, reason="mobile_frida_api not importable")
class TestMastgReport:
    def test_report_structure(self):
        session = FridaSession(device_id="d1", package_name="com.test")
        report = _generate_mastg_report(session)
        assert "summary" in report
        assert "coverage" in report
        assert report["summary"]["total_tests"] > 0

    def test_report_with_ssl_finding(self):
        session = FridaSession(package_name="com.test")
        session.mastg_completed.append("MASTG-TEST-0022")
        session.findings.append(FridaFinding(attack_type="ssl_pinning", severity="high"))
        report = _generate_mastg_report(session)
        ssl_entry = next((c for c in report["coverage"] if c["mastg_id"] == "MASTG-TEST-0022"), None)
        assert ssl_entry is not None
        assert ssl_entry["status"] == "FAIL"

    def test_coverage_percentage_type(self):
        session = FridaSession()
        report = _generate_mastg_report(session)
        assert isinstance(report["summary"]["coverage_pct"], (int, float))


# ---------------------------------------------------------------------------
# Session handler tests
# ---------------------------------------------------------------------------

@pytest.mark.skipif(not IMPORT_OK, reason="mobile_frida_api not importable")
class TestSessionHandlers:
    def test_list_sessions(self):
        result = run(list_frida_sessions_handler())
        assert isinstance(result, list)

    def test_stop_nonexistent_session(self):
        from fastapi import HTTPException
        with pytest.raises(HTTPException) as exc:
            run(stop_frida_session_handler("nonexistent_xyz"))
        assert exc.value.status_code == 404

    def test_get_nonexistent_session(self):
        from fastapi import HTTPException
        with pytest.raises(HTTPException) as exc:
            run(get_frida_session_handler("nonexistent_xyz"))
        assert exc.value.status_code == 404

    def test_mastg_report_nonexistent_session(self):
        from fastapi import HTTPException
        with pytest.raises(HTTPException) as exc:
            run(mastg_report_handler("nonexistent_xyz"))
        assert exc.value.status_code == 404

    def test_ai_generate_requires_package(self):
        from fastapi import HTTPException
        with pytest.raises(HTTPException) as exc:
            run(ai_generate_hooks_handler({}))
        assert exc.value.status_code == 400

    def test_ai_generate_no_classes_returns_empty(self):
        result = run(ai_generate_hooks_handler({
            "package_name": "com.test",
            "auth_classes": [],
            "crypto_classes": [],
            "network_classes": [],
        }))
        assert result["package_name"] == "com.test"
        assert result["scripts_generated"] == 0
        assert isinstance(result["scripts"], list)


# ---------------------------------------------------------------------------
# Integration: AI hook generation with classes
# ---------------------------------------------------------------------------

@pytest.mark.skipif(not IMPORT_OK or not GEN_OK, reason="dependencies not importable")
class TestAiHookGeneration:
    def test_auth_hooks_generated(self):
        scripts = _generate_ai_hooks("com.test", ["com.test.auth.LoginManager"], [], [])
        assert len(scripts) > 0
        assert any("auth" in s["name"] for s in scripts)

    def test_crypto_hooks_generated(self):
        scripts = _generate_ai_hooks("com.test", [], ["com.test.crypto.AESHelper"], [])
        assert len(scripts) > 0

    def test_network_hooks_generated(self):
        scripts = _generate_ai_hooks("com.test", [], [], ["com.test.net.ApiClient"])
        assert len(scripts) > 0

    def test_hooks_have_content(self):
        scripts = _generate_ai_hooks("com.test", ["com.test.auth.Auth"], [], [])
        for s in scripts:
            assert s["script_content"], "Empty script content"
            assert "Java.perform" in s["script_content"] or "use strict" in s["script_content"]
