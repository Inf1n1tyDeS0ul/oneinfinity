import pytest
from unittest.mock import MagicMock, patch
from oneinfinity.mobile.security_engine import MobileSecurityEngine, MobileSecurityConfig

@pytest.fixture
def engine():
    return MobileSecurityEngine()

@patch("oneinfinity.mobile.deep_link_fuzzer.DeepLinkFuzzer.fuzz")
@patch("oneinfinity.mobile.upload_manager.mobile_upload_manager.upload")
def test_engine_calls_deep_link_fuzz(mock_upload, mock_fuzz, engine):
    # Mock upload result
    mock_upload.return_value = MagicMock(
        id="test_app",
        filename="test.apk",
        extract_path="/tmp/extracted",
        platform="android",
        package_name="com.example.app"
    )
    
    # Mock findings from fuzzer
    mock_finding = MagicMock()
    mock_finding.to_dict.return_value = {
        "vulnerability": "Deep Link DoS",
        "severity": "medium",
        "evidence": "crash",
        "tool": "deep_link_fuzzer"
    }
    mock_fuzz.return_value = [mock_finding]
    
    # Mock api_discovery to return deep links
    engine._api_discovery = MagicMock()
    engine._api_discovery.discover.return_value.to_dict.return_value = {
        "endpoints": [
            {"url": "example://test", "method": "DEEP_LINK"}
        ]
    }
    
    # Configure to run deep link fuzz
    config = MobileSecurityConfig(
        run_deep_link_fuzz=True,
        run_static=False,
        run_ai_reverse=False,
        run_frida_gen=False,
        run_secrets=False,
        run_api_discovery=True, # Need this for deep links
        run_component_testing=False,
        run_sdk_scan=False,
        run_network_analysis=False
    )
    
    # Run analysis
    report = engine.analyze("test.apk", config=config)
    
    # Verify fuzz was called
    assert mock_fuzz.called
    
    # Verify findings are in the report
    assert any(v["type"] == "Deep Link DoS" for v in report.all_vulnerabilities)
    assert report.deep_link_fuzz["total"] == 1
