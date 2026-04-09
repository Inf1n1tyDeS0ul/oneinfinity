
import logging
import sys
import os
from unittest.mock import patch, MagicMock
import requests

# Add project root to sys.path
sys.path.insert(0, os.getcwd())

from oneinfinity.core.http_client import safe_request, get_http_client

# Configure logging
logging.basicConfig(level=logging.DEBUG)

def test_retry_on_connection_error():
    print("\n[test] Testing retry on ConnectionError...")
    client = get_http_client()
    
    with patch.object(client.session, 'request') as mock_request:
        # Simulate 2 failures then 1 success
        mock_request.side_effect = [
            requests.exceptions.ConnectionError("Simulated Connection Error"),
            requests.exceptions.ConnectionError("Simulated Connection Error"),
            MagicMock(status_code=200, text="Success")
        ]
        
        resp = safe_request("GET", "https://api.github.com/zen")
        
        assert resp is not None
        assert resp.status_code == 200
        # urllib3 Retry should handle this if configured in Adapter, 
        # but since we use Retry object in HTTPAdapter, 
        # we need to be careful about how many times it's actually called.
        print(f"[pass] Got response: {resp.status_code}")

def test_retry_on_503():
    print("\n[test] Testing retry on HTTP 503...")
    client = get_http_client()
    
    with patch.object(client.session, 'request') as mock_request:
        mock_request.side_effect = [
            MagicMock(status_code=503, headers={}),
            MagicMock(status_code=200, headers={}, text="Success")
        ]
        
        resp = safe_request("GET", "https://api.github.com/zen")
        
        assert resp is not None
        assert resp.status_code == 200
        print(f"[pass] Got response: {resp.status_code}")

if __name__ == "__main__":
    try:
        test_retry_on_connection_error()
        test_retry_on_503()
        print("\n[all tests passed]")
    except Exception as e:
        print(f"\n[test failed] {e}")
        sys.exit(1)
