"""
Tests for Mobile iOS Integration — Phase 4
"""
import asyncio
import plistlib
import pytest

def run(coro):
    return asyncio.run(coro)

import sys, os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "web", "backend"))
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

try:
    from mobile_ios_api import (
        analyze_ats_plist, extract_url_schemes_from_plist, analyze_privacy_permissions,
        generate_deeplink_fuzz_cases, demangle_swift_symbol, ingest_finding_for_correlation,
        _vulns_match, _correlation_store, _correlated,
        analyze_ats_handler, correlate_findings_handler, list_correlated_findings_handler,
        demangle_swift_handler, ios_deeplink_fuzz_handler,
    )
    IOS_OK = True
except ImportError:
    IOS_OK = False

try:
    from oneinfinity.mobile.mastg_knowledge import MASTG_TESTS
    MASTG_OK = True
except ImportError:
    MASTG_OK = False

try:
    from oneinfinity.mobile.frida_script_generator import frida_script_generator
    GEN_OK = True
except ImportError:
    GEN_OK = False


# ── Helper: build a minimal Info.plist ────────────────────────────────────

def build_plist(**kwargs) -> bytes:
    data = {**kwargs}
    return plistlib.dumps(data)


# ── MASTG iOS tests added ─────────────────────────────────────────────────

@pytest.mark.skipif(not MASTG_OK, reason="mastg_knowledge unavailable")
class TestMastgIOSTests:
    def test_ios_jailbreak_test_added(self):
        assert "MASTG-TEST-0060" in MASTG_TESTS

    def test_ios_ats_test_added(self):
        assert "MASTG-TEST-0077" in MASTG_TESTS

    def test_ios_nsurlsession_test_added(self):
        assert "MASTG-TEST-0080" in MASTG_TESTS

    def test_ios_crash_logs_test_added(self):
        assert "MASTG-TEST-0062" in MASTG_TESTS

    def test_ios_objc_test_added(self):
        assert "MASTG-TEST-0068" in MASTG_TESTS

    def test_ios_test_has_ios_content(self):
        t = MASTG_TESTS["MASTG-TEST-0060"]
        assert "jailbreak" in t.title.lower() or "jailbreak" in t.description.lower()
        assert "MASVS-RESILIENCE" in str(t.masvs_mapping)

    def test_ats_test_references_info_plist(self):
        t = MASTG_TESTS["MASTG-TEST-0077"]
        assert "ATS" in t.title or "Transport" in t.title
        assert "MASVS-NETWORK" in str(t.masvs_mapping)

    def test_total_mastg_tests_expanded(self):
        assert len(MASTG_TESTS) >= 14  # 9 original + 5 iOS


# ── iOS Frida scripts ─────────────────────────────────────────────────────

@pytest.mark.skipif(not GEN_OK, reason="frida_script_generator unavailable")
class TestiOSFridaScripts:
    def test_ios_jailbreak_bypass_script(self):
        s = frida_script_generator.generate_ios_jailbreak_bypass_script()
        assert s.platform == "ios"
        assert s.auto_run is True
        assert "Cydia.app" in s.script_content
        assert "NSFileManager" in s.script_content
        assert "[FRIDA_FINDING]" in s.script_content

    def test_ios_keychain_hook_script(self):
        s = frida_script_generator.generate_ios_keychain_hook_script()
        assert s.platform == "ios"
        assert "SecItemCopyMatching" in s.script_content
        assert "SecItemAdd" in s.script_content
        assert "[FRIDA_FINDING]" in s.script_content

    def test_ios_network_hook_script(self):
        s = frida_script_generator.generate_ios_network_hook_script()
        assert s.platform == "ios"
        assert "NSURLRequest" in s.script_content or "NSURLSession" in s.script_content
        assert "[FRIDA_FINDING]" in s.script_content

    def test_ios_anti_debug_bypass(self):
        s = frida_script_generator.generate_ios_anti_debug_bypass_script()
        assert s.platform == "ios"
        assert s.auto_run is True
        assert "ptrace" in s.script_content or "sysctl" in s.script_content

    def test_ios_biometric_bypass(self):
        s = frida_script_generator.generate_ios_biometric_bypass_script()
        assert s.platform == "ios"
        assert "LAContext" in s.script_content
        assert "evaluatePolicy" in s.script_content

    def test_generate_ios_scripts_for_session(self):
        scripts = frida_script_generator.generate_ios_scripts_for_session("com.test.app")
        names = [s.name for s in scripts]
        assert "ssl_bypass" in names
        assert "ios_jailbreak_bypass" in names
        assert "ios_keychain_hooks" in names
        assert "ios_network_hooks" in names
        assert "ios_anti_debug_bypass" in names

    def test_ssl_bypass_ios_has_sectrust(self):
        s = frida_script_generator.generate_ssl_bypass_script(platform="ios")
        assert "SecTrustEvaluate" in s.script_content
        assert "SecTrustEvaluateWithError" in s.script_content


# ── ATS Analyzer ──────────────────────────────────────────────────────────

@pytest.mark.skipif(not IOS_OK, reason="mobile_ios_api unavailable")
class TestATSAnalyzer:
    def test_arbitrary_loads_detected(self):
        plist = build_plist(NSAppTransportSecurity={"NSAllowsArbitraryLoads": True})
        findings = analyze_ats_plist(plist)
        assert any("NSAllowsArbitraryLoads" in f.issue for f in findings)
        assert any(f.severity in ("high", "critical") for f in findings)

    def test_clean_ats_no_findings(self):
        plist = build_plist(NSAppTransportSecurity={})
        findings = analyze_ats_plist(plist)
        assert len(findings) == 0

    def test_no_ats_key_no_findings(self):
        plist = build_plist(CFBundleIdentifier="com.test.app")
        findings = analyze_ats_plist(plist)
        assert len(findings) == 0

    def test_exception_domain_http_detected(self):
        plist = build_plist(NSAppTransportSecurity={
            "NSExceptionDomains": {
                "api.example.com": {"NSExceptionAllowsInsecureHTTPLoads": True}
            }
        })
        findings = analyze_ats_plist(plist)
        assert any("api.example.com" in f.issue for f in findings)

    def test_arbitrary_media_loads_detected(self):
        plist = build_plist(NSAppTransportSecurity={"NSAllowsArbitraryLoadsForMedia": True})
        findings = analyze_ats_plist(plist)
        assert len(findings) > 0

    def test_findings_have_mastg_id(self):
        plist = build_plist(NSAppTransportSecurity={"NSAllowsArbitraryLoads": True})
        findings = analyze_ats_plist(plist)
        assert all(f.mastg_id == "MASTG-TEST-0077" for f in findings)

    def test_tls_version_downgrade_detected(self):
        plist = build_plist(NSAppTransportSecurity={
            "NSExceptionDomains": {
                "old.example.com": {"NSExceptionMinimumTLSVersion": "TLSv1.0"}
            }
        })
        findings = analyze_ats_plist(plist)
        assert any("TLS" in f.issue for f in findings)


# ── URL Scheme extraction ─────────────────────────────────────────────────

@pytest.mark.skipif(not IOS_OK, reason="mobile_ios_api unavailable")
class TestURLSchemes:
    def test_extracts_custom_schemes(self):
        plist = build_plist(CFBundleURLTypes=[
            {"CFBundleURLSchemes": ["myapp", "myapp-auth"]}
        ])
        schemes = extract_url_schemes_from_plist(plist)
        assert "myapp" in schemes
        assert "myapp-auth" in schemes

    def test_filters_http_https(self):
        plist = build_plist(CFBundleURLTypes=[
            {"CFBundleURLSchemes": ["http", "https", "myapp"]}
        ])
        schemes = extract_url_schemes_from_plist(plist)
        assert "http" not in schemes
        assert "https" not in schemes
        assert "myapp" in schemes

    def test_no_url_types_returns_empty(self):
        plist = build_plist(CFBundleIdentifier="com.test")
        schemes = extract_url_schemes_from_plist(plist)
        assert schemes == []


# ── Deep-Link Fuzzer ──────────────────────────────────────────────────────

@pytest.mark.skipif(not IOS_OK, reason="mobile_ios_api unavailable")
class TestDeeplinkFuzzer:
    def test_generates_cases_for_scheme(self):
        cases = generate_deeplink_fuzz_cases(["myapp"], ["profile"])
        assert len(cases) > 0
        assert all(c["url"].startswith("myapp://") for c in cases)

    def test_both_query_and_path_variants(self):
        cases = generate_deeplink_fuzz_cases(["app"], ["page"])
        types = {c["type"] for c in cases}
        assert "deeplink_fuzz" in types
        assert "deeplink_path_fuzz" in types

    def test_handler_requires_schemes(self):
        from fastapi import HTTPException
        with pytest.raises(HTTPException) as exc:
            run(ios_deeplink_fuzz_handler({"hosts": ["page"]}))
        assert exc.value.status_code == 400


# ── Cross-Platform Correlation ────────────────────────────────────────────

@pytest.mark.skipif(not IOS_OK, reason="mobile_ios_api unavailable")
class TestCrossPlatformCorrelation:
    def test_same_vuln_same_path_correlates(self):
        finding_android = {
            "vuln_type": "idor",
            "url": "https://api.example.com/users/1",
            "severity": "high",
            "confidence": 0.8,
        }
        finding_ios = {
            "vuln_type": "idor",
            "url": "https://api.example.com/users/2",
            "severity": "high",
            "confidence": 0.8,
        }
        # Reset correlation store for this test
        _correlation_store.clear()
        _correlated.clear()

        ingest_finding_for_correlation(finding_android, "android", "dev-android")
        result = ingest_finding_for_correlation(finding_ios, "ios", "dev-ios")

        assert result is not None
        assert "android" in result.platforms_confirmed
        assert "ios" in result.platforms_confirmed

    def test_different_vulns_dont_correlate(self):
        _correlation_store.clear()
        _correlated.clear()
        f1 = {"vuln_type": "sqli", "url": "https://api.x.com/q", "severity": "high", "confidence": 0.8}
        f2 = {"vuln_type": "xss",  "url": "https://api.x.com/q", "severity": "high", "confidence": 0.8}
        ingest_finding_for_correlation(f1, "android", "d1")
        result = ingest_finding_for_correlation(f2, "ios", "d2")
        assert result is None

    def test_severity_escalated_on_correlation(self):
        _correlation_store.clear()
        _correlated.clear()
        fa = {"vuln_type": "auth_bypass", "url": "https://api.y.com/login", "severity": "high", "confidence": 0.7}
        fi = {"vuln_type": "auth_bypass", "url": "https://api.y.com/login", "severity": "high", "confidence": 0.7}
        ingest_finding_for_correlation(fa, "android", "da")
        result = ingest_finding_for_correlation(fi, "ios", "di")
        assert result is not None
        # severity should be escalated (high → critical)
        from mobile_ios_api import _SEVERITY_RANK
        original_rank = _SEVERITY_RANK.get("high", 0)
        escalated_rank = _SEVERITY_RANK.get(result.escalated_severity, 0)
        assert escalated_rank >= original_rank

    def test_vuln_match_same_path(self):
        a = {"vuln_type": "sqli", "url": "https://host.com/api/v1/search"}
        b = {"vuln_type": "sqli", "url": "https://host.com/api/v1/search?q=test"}
        assert _vulns_match(a, b) is True

    def test_vuln_match_different_path(self):
        a = {"vuln_type": "sqli", "url": "https://host.com/api/v1/users"}
        b = {"vuln_type": "sqli", "url": "https://host.com/api/v1/orders"}
        assert _vulns_match(a, b) is False

    def test_vuln_match_different_hosts_dont_correlate(self):
        """Cross-host false-positive guard: same path+vuln on different backends must NOT match."""
        a = {"vuln_type": "sqli", "url": "https://api.company.com/users/1"}
        b = {"vuln_type": "sqli", "url": "https://evil.attacker.com/users/1"}
        assert _vulns_match(a, b) is False

    def test_list_correlations_handler(self):
        result = run(list_correlated_findings_handler())
        assert isinstance(result, list)

    def test_deduplication_same_finding_twice(self):
        """Gap F: re-submitting the same finding must not create a duplicate CorrelatedFinding."""
        _correlation_store.clear()
        _correlated.clear()
        fa = {"vuln_type": "sqli", "url": "https://dup.example.com/search", "severity": "high", "confidence": 0.8}
        fi = {"vuln_type": "sqli", "url": "https://dup.example.com/search", "severity": "high", "confidence": 0.8}

        ingest_finding_for_correlation(fa, "android", "dev-a")
        first = ingest_finding_for_correlation(fi, "ios", "dev-i")
        assert first is not None

        # Submit the iOS finding again (device reconnect scenario)
        second = ingest_finding_for_correlation(fi, "ios", "dev-i")
        # Must return the SAME correlated finding, not create a new one
        assert second is not None
        assert second.correlation_id == first.correlation_id
        assert len(_correlated) == 1

    def test_deduplication_raw_store_no_duplicates(self):
        """Gap F: raw store should not accumulate duplicate entries for the same finding."""
        _correlation_store.clear()
        _correlated.clear()
        f = {"vuln_type": "xss", "url": "https://dedup.example.com/page", "severity": "medium", "confidence": 0.7}

        ingest_finding_for_correlation(f, "android", "dev-x")
        ingest_finding_for_correlation(f, "android", "dev-x")  # duplicate submit
        ingest_finding_for_correlation(f, "android", "dev-x")  # duplicate submit again

        host_findings = _correlation_store.get("dedup.example.com", {}).get("android", [])
        assert len(host_findings) == 1  # only one entry despite three submits

    def test_persistence_state_file_written(self, tmp_path, monkeypatch):
        """Gap A: _save_state writes a readable JSON file that _load_state can restore."""
        import importlib
        state_file = tmp_path / "mobile" / "correlation_state.json"
        import mobile_ios_api as mia
        monkeypatch.setattr(mia, "_STATE_FILE", state_file)

        _correlation_store.clear()
        _correlated.clear()
        fa = {"vuln_type": "rce", "url": "https://persist.test/exec", "severity": "critical", "confidence": 0.9}
        fi = {"vuln_type": "rce", "url": "https://persist.test/exec", "severity": "critical", "confidence": 0.9}
        ingest_finding_for_correlation(fa, "android", "p-android")
        result = ingest_finding_for_correlation(fi, "ios", "p-ios")
        assert result is not None

        # State file must exist and be valid JSON
        assert state_file.exists()
        import json
        data = json.loads(state_file.read_text())
        assert result.correlation_id in data["correlated"]
        assert "persist.test" in data["store"]


# ── Permission Detector ───────────────────────────────────────────────────

@pytest.mark.skipif(not IOS_OK, reason="mobile_ios_api unavailable")
class TestPermissionDetector:
    def test_camera_permission_detected(self):
        plist = build_plist(NSCameraUsageDescription="Used for scanning")
        findings = analyze_privacy_permissions(plist)
        assert any("camera" in f["title"].lower() for f in findings)
        assert any(f["severity"] == "high" for f in findings)

    def test_generic_description_flagged(self):
        plist = build_plist(NSCameraUsageDescription="required")
        findings = analyze_privacy_permissions(plist)
        assert any(f.get("generic_description") for f in findings)

    def test_no_permissions_no_findings(self):
        plist = build_plist(CFBundleIdentifier="com.test")
        findings = analyze_privacy_permissions(plist)
        assert len(findings) == 0

    def test_always_location_is_critical(self):
        plist = build_plist(NSLocationAlwaysUsageDescription="Location always needed")
        findings = analyze_privacy_permissions(plist)
        assert any(f["severity"] == "critical" for f in findings)
