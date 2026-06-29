import pytest
import asyncio
from unittest.mock import AsyncMock, patch, MagicMock
from oneinfinity.scan.sqli_scanner import SQLiScanner
from oneinfinity.scan.ssrf_scanner import SSRFScanner
import oneinfinity.scan.adaptive_mutation_helper as helper

@pytest.fixture(autouse=True)
def reset_mutation_cache():
    """Reset the mutation engine cache before each test."""
    helper._MUTATION_ENGINE = None
    yield
    helper._MUTATION_ENGINE = None

@pytest.mark.asyncio
async def test_sqli_scanner_adaptive_mutation_on_403():
    """
    Test that SQLiScanner attempts a mutated payload when receiving a 403 response.
    """
    scanner = SQLiScanner()
    
    # Mock response objects
    mock_resp_403 = MagicMock()
    mock_resp_403.status_code = 403
    mock_resp_403.text = "Forbidden"
    
    mock_resp_200 = MagicMock()
    mock_resp_200.status_code = 200
    mock_resp_200.text = "SQL syntax error" # To trigger a finding
    
    # Mock get to return 403 first, then 200 for the mutation
    scanner.http_client.get = AsyncMock(side_effect=[mock_resp_403, mock_resp_200, mock_resp_200, mock_resp_200])
    
    # We need to mock PayloadMutationEngine.mutate_payload to return something predictable
    with patch("oneinfinity.scan.adaptive_mutation_helper.PayloadMutationEngine") as MockEngine:
        mock_engine_instance = MockEngine.return_value
        mock_engine_instance.mutate_payload.return_value = ["' OR 1=1 --", "admin' --"]
        
        # Run the test
        # We'll test test_error_based which is one of the methods we want to enhance
        findings = await scanner.test_error_based(
            url="http://example.com/vuln",
            method="GET",
            param_name="id",
            param_value="1"
        )
        
        # Verify findings
        assert findings is not None
        assert findings.injection_type == "error_based"
        
        # Verify that get was called more than the original attempt
        # Original attempt for one payload, plus mutations
        # Since _ERROR_BASED_PAYLOADS has many items, we should see calls for the first one failing and then mutating
        assert scanner.http_client.get.call_count >= 2
        
        # Verify that mutation engine was called
        mock_engine_instance.mutate_payload.assert_called()

@pytest.mark.asyncio
async def test_ssrf_scanner_adaptive_mutation_on_403():
    """
    Test that SSRFScanner attempts a mutated payload when receiving a 403 response.
    """
    scanner = SSRFScanner()
    
    # Mock response objects
    mock_resp_403 = MagicMock()
    mock_resp_403.status_code = 403
    mock_resp_403.text = "Forbidden"
    
    mock_resp_200 = MagicMock()
    mock_resp_200.status_code = 200
    mock_resp_200.text = "ami-id: i-12345678" # AWS metadata indicator
    
    # Mock get to return 403 first, then 200 for the mutation
    scanner.http_client.get = AsyncMock(side_effect=[mock_resp_403, mock_resp_200, mock_resp_200])
    
    with patch("oneinfinity.scan.adaptive_mutation_helper.PayloadMutationEngine") as MockEngine:
        mock_engine_instance = MockEngine.return_value
        mock_engine_instance.mutate_payload.return_value = ["http://169.254.169.254.nip.io/latest/meta-data/"]
        
        # Run the test
        finding = await scanner.test_cloud_metadata(
            url="http://example.com/proxy",
            method="GET",
            param_name="url"
        )
        
        # Verify findings
        assert finding is not None
        assert finding.ssrf_type == "cloud_metadata"
        
        # Verify calls
        assert scanner.http_client.get.call_count >= 2
        
        # Verify that mutation engine was called
        mock_engine_instance.mutate_payload.assert_called()
