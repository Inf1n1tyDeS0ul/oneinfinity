import pytest
from unittest.mock import patch
from oneinfinity.core.http_client import OneInfinityHTTPClient
from oneinfinity.infra.proxy_manager import proxy_manager

def test_http_client_uses_proxy_when_enabled():
    proxy_manager.configure("http://127.0.0.1:8888")
    proxy_manager.enable()
    
    client = OneInfinityHTTPClient()
    # Reset instance or mock carefully since it is a singleton
    with patch.object(client.session, 'request') as mock_req:
        client.safe_request("GET", "http://example.com")
        args, kwargs = mock_req.call_args
        assert "proxies" in kwargs
        assert kwargs['proxies'] == {"http": "http://127.0.0.1:8888", "https": "http://127.0.0.1:8888"}
    
    proxy_manager.disable()
