import pytest
from unittest import mock
from fastapi.testclient import TestClient
from web.backend.main import app
import os
from pathlib import Path

client = TestClient(app)

@pytest.fixture
def mock_pipeline_env():
    """Mock the entire mobile security toolchain."""
    with mock.patch("oneinfinity.mobile.adb_forensics.AegisForensicEngine") as mock_engine_class, \
         mock.patch("web.backend.main._get_package_harvester") as mock_get_harvester:
        
        # Mock Engine Instance
        mock_engine = mock_engine_class.return_value
        
        # Mock Harvester Instance
        mock_harvester = mock_get_harvester.return_value
        
        yield {
            "forensic_engine": mock_engine,
            "harvester": mock_harvester,
        }

def test_master_forensic_pipeline_flow(mock_pipeline_env, tmp_path):
    """
    Verifies the full Plug-Select-Audit flow:
    1. Device connection (mocked via harvester)
    2. Package selection & ingestion
    3. Package extraction/pulling
    4. Forensic audit execution
    5. Findings aggregation
    """
    serial = "emulator-5554"
    package_name = "com.example.app"

    # Mock raw_dir to use tmp_path
    with mock.patch("web.backend.main.raw_dir", return_value=tmp_path):
        # 1. Mock harvester pull_package success
        mock_pipeline_env["harvester"].pull_package.return_value = True

        # 2. Trigger Ingest (Plug & Select simulation)
        # We need to bypass auth for the test client or provide a valid session
        # For simplicity in this master test, we mock auth dependency
        with mock.patch("web.backend.main._require_auth", return_value=True), \
             mock.patch("web.backend.main.BackgroundTasks.add_task") as mock_add_task, \
             mock.patch("oneinfinity.mobile.upload_manager.mobile_upload_manager.upload") as mock_upload:
            
            # Mock upload manager to return a valid app_id
            mock_upload.return_value = mock.MagicMock(id="mob_123", to_dict=lambda: {"id": "mob_123"})
            
            # Simulate physical APK existence after pull
            temp_pulls = tmp_path / "mobile" / "temp_pulls"
            temp_pulls.mkdir(parents=True, exist_ok=True)
            (temp_pulls / f"{package_name}.apk").write_text("fake_apk")

            response = client.post(f"/api/mobile/devices/{serial}/packages/{package_name}/ingest")

            assert response.status_code == 200
            assert response.json()["status"] == "analysis_started"

            # 3. Verify backend calls pull_package with correct package
            mock_pipeline_env["harvester"].pull_package.assert_called_once()
            args, _ = mock_pipeline_env["harvester"].pull_package.call_args
            assert args[0] == package_name
            assert "temp_pulls" in args[1]

            # 4. Verify analysis background task was scheduled
            mock_add_task.assert_called_once()

    # 5. Verify Forensic Audit & Aggregation (Audit simulation)
    from oneinfinity.mobile.security_engine import MobileSecurityEngine, MobileSecurityConfig, MobileSecurityReport

    engine = MobileSecurityEngine()
    # Ensure lazy load is mocked so it doesn't overwrite our mock instance
    engine._forensic_engine = mock.MagicMock(return_value=mock_pipeline_env["forensic_engine"])
    engine._dynamic_analyzer = mock.MagicMock()
    engine._dynamic_analyzer.analyze.return_value = mock.MagicMock(all_findings=[])

    report = MobileSecurityReport(app_id="mob_123", package_name=package_name)
    config = MobileSecurityConfig(run_dynamic=True, device_id=serial)

    # Mock forensic findings
    forensic_findings = [
        {"type": "logcat_leak", "severity": "high", "description": "Secret leaked in logcat"}
    ]
    mock_pipeline_env["forensic_engine"].run_audit.return_value = forensic_findings

    
    # Mock on_finding to prevent AttributeError in _emit_findings
    engine._on_finding = mock.MagicMock()
    
    # Execute dynamic phase which triggers forensic audit
    engine._phase_dynamic(report, "/tmp/app.apk", "/tmp/extracted", config)


    # Verify forensic audit called with correct device and package
    from unittest.mock import ANY
    mock_pipeline_env["forensic_engine"].run_audit.assert_called_once_with(serial, package_name, on_signal=ANY)
    # Verify findings were aggregated into the report
    # The engine uses .forensics = {"findings": [...]}
    # Ensure findings key exists before asserting
    forensics_data = report.to_dict().get("forensics", {})
    assert forensics_data.get("findings") == forensic_findings
    
    # Verify aggregation to all_vulnerabilities
    engine._aggregate_vulnerabilities(report)
    forensic_vulns = [v for v in report.all_vulnerabilities if v["source"] == "forensics"]
    assert len(forensic_vulns) == 1
    assert forensic_vulns[0]["type"] == "logcat_leak"
