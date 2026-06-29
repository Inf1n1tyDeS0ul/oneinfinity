import os
import shutil
import tempfile
import pytest
from unittest.mock import MagicMock
from oneinfinity.mobile.security_engine import MobileSecurityEngine, MobileSecurityConfig, MobileSecurityReport

def test_mobile_security_engine_sdk_scan_integration():
    """Verify that MobileSecurityEngine correctly calls SDKScanner and aggregates findings."""
    engine = MobileSecurityEngine()
    
    # Create a mock extracted directory with a vulnerable SDK pattern
    temp_dir = tempfile.mkdtemp()
    extracted_dir = os.path.join(temp_dir, "extracted")
    os.makedirs(extracted_dir)
    
    okhttp_dir = os.path.join(extracted_dir, "smali", "com", "squareup", "okhttp3")
    os.makedirs(okhttp_dir)
    with open(os.path.join(okhttp_dir, "OkHttpClient.smali"), "w") as f:
        f.write(".class public Lcom/squareup/okhttp3/OkHttpClient;")
    
    # Mock _phase_upload to return our temp_dir
    engine._phase_upload = MagicMock(return_value={
        "app_id": "test_app",
        "app_name": "Test App",
        "package_name": "com.test.app",
        "platform": "android",
        "extracted_dir": extracted_dir
    })
    
    # Disable other phases to keep it fast
    config = MobileSecurityConfig(
        run_static=False,
        run_ai_reverse=False,
        run_frida_gen=False,
        run_secrets=False,
        run_api_discovery=False,
        run_component_testing=False,
        run_dynamic=False,
        run_network_analysis=False,
        run_sdk_scan=True
    )
    
    try:
        report = engine.analyze("dummy.apk", config=config)
        
        # Check if sdk_scan phase was executed
        assert "sdk_scan" in report.phase_timings
        assert report.sdk_scan["status"] == "complete"
        assert report.sdk_scan["total"] > 0
        
        # Check if findings were aggregated
        assert len(report.all_vulnerabilities) > 0
        assert any("OkHttp" in v["type"] for v in report.all_vulnerabilities)
        
        # Check if recommendation was added
        assert "Update or replace vulnerable SDKs identified in the scan" in report.recommendations
        
    finally:
        shutil.rmtree(temp_dir)

if __name__ == "__main__":
    pytest.main([__file__])
