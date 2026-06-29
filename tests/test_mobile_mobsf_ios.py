import pytest
import os
from unittest.mock import MagicMock, patch
from oneinfinity.mobile.static_analysis import MobileStaticAnalyzer, StaticAnalysisConfig

def test_analyze_ipa_with_mobsf_integration():
    """
    Test that MobileStaticAnalyzer.analyze calls mobsf_wrapper.scan_file
    when provided with an .ipa file and MobSF is enabled.
    """
    # 1. Setup config with MobSF enabled
    config = StaticAnalysisConfig(use_mobsf=True)
    analyzer = MobileStaticAnalyzer(config=config)
    
    # 2. Define mock finding (as a dict because analyzer converts them)
    mock_finding_dict = {
        "target": "com.test.ios",
        "vulnerability": "Insecure Data Storage",
        "severity": "high",
        "tool": "mobsf",
        "attack_type": "storage",
        "evidence": "Sensitive data found in local storage",
        "file_path": "Info.plist",
        "line_number": 0,
        "confidence": 0.9,
        "cvss": 7.5,
        "remediation": "Encrypt sensitive data",
        "tags": ["ios", "mobsf"]
    }
    
    # 3. Patch dependencies
    with patch("oneinfinity.mobile.static_analysis.mobsf_wrapper") as mock_mobsf, \
         patch("os.path.isfile", return_value=True):
        
        # Mock scan_file to return our mock finding
        # analyzer._finding_list will handle both objects and dicts
        mock_mobsf.scan_file.return_value = [mock_finding_dict]
        
        file_path = "/path/to/app.ipa"
        extracted_dir = "/tmp/extracted"
        
        # 4. Run analysis
        result = analyzer.analyze(
            app_id="com.test.ios",
            file_path=file_path,
            extracted_dir=extracted_dir
        )
        
        # 5. Assertions
        # Verify findings include MobSF results
        finding_vulns = [f["vulnerability"] for f in result.all_findings]
        assert "Insecure Data Storage" in finding_vulns
        
        # Verify MobSF was actually called
        mock_mobsf.scan_file.assert_called_once_with(file_path)
        
        # Verify platform is correctly identified
        assert result.platform == "ios"

def test_analyze_android_fallback_to_mobsf():
    """
    Test that MobileStaticAnalyzer.analyze calls mobsf_wrapper.scan_file
    when APK decompilation fails and MobSF is enabled.
    """
    # 1. Setup config
    config = StaticAnalysisConfig(use_mobsf=True, use_apktool=True, use_jadx=False)
    analyzer = MobileStaticAnalyzer(config=config)
    
    mock_finding = {"vulnerability": "Fallback Finding", "tool": "mobsf"}
    
    # 2. Patch dependencies
    with patch("oneinfinity.mobile.static_analysis.mobsf_wrapper") as mock_mobsf, \
         patch("oneinfinity.mobile.static_analysis.apktool_wrapper") as mock_apktool, \
         patch("os.path.isfile", return_value=True):
        
        # Mock apktool to fail decompilation
        mock_apktool.decompile.side_effect = Exception("Decompile failed")
        mock_mobsf.scan_file.return_value = [mock_finding]
        
        file_path = "/path/to/app.apk"
        
        # 3. Run analysis
        result = analyzer.analyze(
            app_id="com.test.android",
            file_path=file_path,
            extracted_dir="/tmp/extracted"
        )
        
        # 4. Assertions
        assert result.decompile_success is False
        assert any(f["vulnerability"] == "Fallback Finding" for f in result.all_findings)
        mock_mobsf.scan_file.assert_called_once_with(file_path)
