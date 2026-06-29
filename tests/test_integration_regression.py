import pytest
from unittest.mock import MagicMock, patch
from oneinfinity.mobile.security_engine import MobileSecurityEngine, MobileSecurityConfig, MobileSecurityReport

def test_forensic_integration_in_dynamic_phase():
    """Verify AegisForensicEngine.run_audit is called during dynamic phase and aggregated."""
    engine = MobileSecurityEngine()
    # Mock _lazy_load to prevent actual imports
    engine._lazy_load = MagicMock()
    
    # Mock the forensic engine class
    mock_forensic_engine_class = MagicMock()
    engine._forensic_engine = mock_forensic_engine_class
    
    # Mock the instance
    mock_instance = mock_forensic_engine_class.return_value
    
    # Mock on_finding callback
    engine._on_finding = MagicMock()
    
    report = MobileSecurityReport(app_id="test_app", package_name="com.test.app")
    config = MobileSecurityConfig(run_dynamic=True, device_id="mock-serial")
    
    # Mock findings from forensic engine
    mock_findings = [
        {"category": "forensics", "type": "sandbox_leak", "description": "Sensitive file found", "severity": "high"}
    ]
    mock_instance.run_audit.return_value = mock_findings
    
    # We need to mock dynamic_analyzer because _phase_dynamic calls it
    engine._dynamic_analyzer = MagicMock()
    engine._dynamic_analyzer.analyze.return_value = MagicMock(all_findings=[])
    
    # Run the dynamic phase
    engine._phase_dynamic(report, "test.apk", "/tmp/extracted", config)
    
    # Verify run_audit was called on the instance
    from unittest.mock import ANY
    mock_instance.run_audit.assert_called_once_with("mock-serial", "com.test.app", on_signal=ANY)    
    # Verify it was added to report.forensics
    data = report.to_dict()
    assert "forensics" in data
    assert "findings" in data["forensics"]
    assert len(data["forensics"]["findings"]) == 1
    
    # Verify aggregation
    engine._aggregate_vulnerabilities(report)
    forensic_vulns = [v for v in report.all_vulnerabilities if v["source"] == "forensics"]
    assert len(forensic_vulns) == 1
    assert forensic_vulns[0]["type"] == "sandbox_leak"
