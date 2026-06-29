"""Regression tests for coverage gaps discovered during vulnbank.org pentest council.

Each test validates a root-cause fix. These MUST continue to pass across future code changes.
Target: https://vulnbank.org (live, authorized)
"""
from __future__ import annotations
import asyncio
import sys
import os

import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))


# ─────────────────────────────────────────────────────────────────────────────
# Test Group 1: FindingValidator — application logic types bypass payload cap
# ─────────────────────────────────────────────────────────────────────────────

class TestFindingValidatorApplicationLogic:
    """Bug: business_logic, debug_info_disclosure, werkzeug_debugger were marked false_positive
    because FindingValidator applied a 0.65 confidence cap (no-payload rule) and a strict
    confirmed gate that rejected findings without payload evidence.
    Fix: _APPLICATION_LOGIC_TYPES exempt set + relaxed thresholds (confirmed=0.50, FP=0.10).
    """

    def setup_method(self):
        from oneinfinity.core.finding_validator import FindingValidator
        self.fv = FindingValidator()

    def _validate(self, vuln_type: str, confidence: float, evidence: str = "test",
                  payload: str = "", tool: str = "test_tool") -> object:
        return self.fv.validate({
            "vuln_type": vuln_type, "tool": tool, "severity": "high",
            "confidence": confidence, "evidence": evidence, "payload": payload,
        })

    def test_debug_info_disclosure_not_false_positive(self):
        r = self._validate("debug_info_disclosure", 0.95, "pin: 389 in response", tool="api_version_tester")
        assert r.status == "confirmed", f"Expected confirmed, got {r.status}"
        assert r.confidence >= 0.70

    def test_werkzeug_debugger_not_false_positive(self):
        r = self._validate("werkzeug_debugger", 0.95, "Werkzeug Debugger UI accessible", tool="api_version_tester")
        assert r.status == "confirmed"

    def test_default_credentials_confirmed(self):
        r = self._validate("default_credentials", 0.95, "admin:admin123 accepted",
                           payload="username=admin&password=admin123", tool="credential_probe")
        assert r.status == "confirmed"

    def test_business_logic_not_false_positive(self):
        """business_logic at conf=0.15 was false_positive before fix — should now be unverified."""
        r = self._validate("business_logic", 0.15, "negative amount accepted", tool="business_logic_engine")
        assert r.status != "false_positive", "business_logic findings must not be false_positive"

    def test_idor_confirmed(self):
        r = self._validate("idor", 0.80, "account data returned without auth", tool="authenticated_test_suite")
        assert r.status == "confirmed"

    def test_jwt_none_alg_confirmed(self):
        r = self._validate("jwt_none_alg", 0.90, "alg:none token accepted", tool="jwt_vulnerability_scanner")
        assert r.status == "confirmed"

    def test_unauthenticated_access_confirmed(self):
        r = self._validate("unauthenticated_access", 0.80, "Swagger UI accessible", tool="api_version_tester")
        assert r.status == "confirmed"

    def test_network_layer_still_works(self):
        """Network-layer tools must still bypass payload cap."""
        r = self._validate("http_request_smuggling", 0.95, "TE.CL desync detected", tool="smuggling_engine")
        assert r.status == "confirmed"


# ─────────────────────────────────────────────────────────────────────────────
# Test Group 2: ValidationOrchestrator — new types in STATIC_PATTERNS
# ─────────────────────────────────────────────────────────────────────────────

class TestValidationOrchestratorPatterns:
    """Bug: ValidationOrchestrator lacked STATIC_PATTERNS and TECH_STACK_COMPAT entries
    for new finding types, giving neutral 0.5 static/context scores that caused
    composite confidence to fall below the 0.65 validity threshold.
    Fix: Added entries for debug_info_disclosure, werkzeug_debugger, default_credentials, etc.
    """

    def setup_method(self):
        from oneinfinity.agents.validation_orchestrator import ValidationOrchestrator
        self.vo = ValidationOrchestrator()

    def test_debug_info_disclosure_in_static_patterns(self):
        assert "debug_info_disclosure" in self.vo.STATIC_PATTERNS
        assert len(self.vo.STATIC_PATTERNS["debug_info_disclosure"]) > 0

    def test_werkzeug_debugger_in_static_patterns(self):
        assert "werkzeug_debugger" in self.vo.STATIC_PATTERNS

    def test_default_credentials_in_tech_stack_compat(self):
        assert "default_credentials" in self.vo.TECH_STACK_COMPAT

    def test_business_logic_in_both(self):
        assert "business_logic" in self.vo.STATIC_PATTERNS
        assert "business_logic" in self.vo.TECH_STACK_COMPAT

    def test_new_types_have_no_incompatible_stacks(self):
        """New types are tech-agnostic — must have empty incompatible list."""
        for vtype in ["debug_info_disclosure", "werkzeug_debugger", "default_credentials",
                      "unauthenticated_access", "business_logic"]:
            compat = self.vo.TECH_STACK_COMPAT.get(vtype, {})
            assert "incompatible" not in compat or len(compat.get("incompatible", [])) == 0, \
                f"{vtype} should be tech-agnostic but has incompatible entries"


# ─────────────────────────────────────────────────────────────────────────────
# Test Group 3: api_version_tester — module integrity
# ─────────────────────────────────────────────────────────────────────────────

class TestApiVersionTester:
    """Regression: api_version_tester.py must be importable and structured correctly."""

    def test_module_imports(self):
        from oneinfinity.scan.api_version_tester import (
            scan_api_versions,
            test_password_reset_debug_leak,
            test_werkzeug_debugger,
            test_unauthenticated_api_docs,
            test_api_version_downgrade,
        )
        assert callable(scan_api_versions)

    def test_debug_leak_patterns_nonempty(self):
        from oneinfinity.scan.api_version_tester import _DEBUG_LEAK_PATTERNS
        assert len(_DEBUG_LEAK_PATTERNS) >= 5

    def test_password_reset_paths_coverage(self):
        from oneinfinity.scan.api_version_tester import _PASSWORD_RESET_PATHS
        required = ["/forgot-password", "/api/v1/forgot-password", "/api/v2/forgot-password"]
        for p in required:
            assert p in _PASSWORD_RESET_PATHS, f"Missing path: {p}"

    def test_debug_patterns_match_pin_response(self):
        """Patterns must match the actual vulnbank.org response format."""
        from oneinfinity.scan.api_version_tester import _DEBUG_LEAK_PATTERNS
        sample = '{"debug_info": {"pin": "389", "pin_length": 3, "timestamp": "2026-06-24"}}'
        matched = [p for p, _ in _DEBUG_LEAK_PATTERNS if p.search(sample)]
        assert len(matched) > 0, "No pattern matched the actual vulnbank.org response format"

    def test_debugger_patterns_match_werkzeug_html(self):
        """Patterns must match Werkzeug Debugger HTML."""
        from oneinfinity.scan.api_version_tester import _DEBUGGER_PATTERNS
        sample = '<title>Console // Werkzeug Debugger</title><script>var CONSOLE_MODE = true;</script>'
        matched = [p for p in _DEBUGGER_PATTERNS if p.search(sample)]
        assert len(matched) >= 2, "Less than 2 Werkzeug patterns matched — patterns may have regressed"

    def test_scan_api_versions_is_async(self):
        import inspect
        from oneinfinity.scan.api_version_tester import scan_api_versions
        assert inspect.iscoroutinefunction(scan_api_versions)


# ─────────────────────────────────────────────────────────────────────────────
# Test Group 4: Tool wrappers — naabu port list
# ─────────────────────────────────────────────────────────────────────────────

class TestNaabuPortList:
    """Bug: naabu only scanned ports 80,443,8080,8443,8888 — missed 3306, 5432 entirely.
    Fix: Expanded default port list to include all dangerous service ports.
    """

    def test_database_ports_in_naabu_default(self):
        import inspect
        from oneinfinity.modules import tool_wrappers
        src = inspect.getsource(tool_wrappers.run_naabu)
        assert "3306" in src, "MySQL port 3306 must be in naabu default port list"
        assert "5432" in src, "PostgreSQL port 5432 must be in naabu default port list"

    def test_dangerous_ports_in_naabu_default(self):
        import inspect
        from oneinfinity.modules import tool_wrappers
        src = inspect.getsource(tool_wrappers.run_naabu)
        for port in ["6379", "27017", "1433", "22"]:
            assert port in src, f"Port {port} must be in naabu default port list"


# ─────────────────────────────────────────────────────────────────────────────
# Test Group 5: Unified scan engine — HV endpoint probe and default cred probe
# ─────────────────────────────────────────────────────────────────────────────

class TestScanEngineProbes:
    """Bug: recon phase used only katana crawl — missed unlinked /console, /debug, /admin.
    Bug: credential_spray was dry-run only — never tested admin:admin123.
    Fix: Added _HV_PATHS probe in recon + DEFAULT CREDENTIAL PROBE in credential_spray.
    """

    def test_hv_paths_in_recon_phase(self):
        with open("src/oneinfinity/scan/unified_scan_engine.py") as f:
            src = f.read()
        assert "_HV_PATHS" in src, "High-value endpoint probe must be in unified_scan_engine.py"
        assert '"/console"' in src, "/console must be in the HV_PATHS list"
        assert '"/api/v1/forgot-password"' in src, "/api/v1/forgot-password must be probed"

    def test_default_cred_probe_in_credential_spray(self):
        with open("src/oneinfinity/scan/unified_scan_engine.py") as f:
            src = f.read()
        assert "DEFAULT CREDENTIAL PROBE" in src, "Default cred probe comment must be present"
        assert '"admin"' in src, "admin username must be in default creds"
        assert '"admin123"' in src, "admin123 password must be in default creds"

    def test_api_version_tester_wired_to_scanner_tasks(self):
        with open("src/oneinfinity/scan/unified_scan_engine.py") as f:
            src = f.read()
        assert "_run_api_version_tester" in src, "api_version_tester must be wired to task list"
        assert "tasks.append(self._run_api_version_tester" in src, "Must be appended to tasks"


# ─────────────────────────────────────────────────────────────────────────────
# Test Group 6: Live integration (offline-safe mockable probe)
# ─────────────────────────────────────────────────────────────────────────────

class TestDebugLeakDetectionOffline:
    """Offline test: parse responses from known-vulnerable vulnbank.org endpoints."""

    def test_pin_pattern_matches_vulnbank_response(self):
        """Confirm the regex correctly matches the actual vulnbank.org /api/v1/forgot-password response."""
        import re
        PIN_PAT = re.compile(r'"pin"\s*:\s*"?\d{3,8}"?', re.I)
        real_response = '''
        {
          "debug_info": {
            "pin": "389",
            "pin_length": 3,
            "timestamp": "2026-06-24 03:02:26.442875",
            "username": null
          },
          "message": "Reset PIN has been sent to your email.",
          "status": "success"
        }
        '''
        assert PIN_PAT.search(real_response), "PIN regex must match actual vulnbank response"

    def test_werkzeug_pattern_matches_vulnbank_console(self):
        """Confirm Werkzeug detection matches actual /console response."""
        import re
        WZ_PAT = re.compile(r'Werkzeug Debugger', re.I)
        real_html = '<title>Console // Werkzeug Debugger</title>'
        assert WZ_PAT.search(real_html), "Werkzeug pattern must match /console HTML"

    def test_debug_info_object_pattern(self):
        """Pattern for debug_info JSON object (v2/v3 endpoints)."""
        import re
        DEBUG_PAT = re.compile(r'"debug_info"\s*:\s*\{', re.I)
        response = '{"debug_info": {"timestamp": "2026"}, "status": "success"}'
        assert DEBUG_PAT.search(response)
