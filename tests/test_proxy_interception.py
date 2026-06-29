
import threading
import time
import urllib.request
import pytest
from oneinfinity.infra.proxy_manager import ProxyManager, ProxyScope

@pytest.fixture
def pm():
    """Returns a fresh ProxyManager instance."""
    return ProxyManager()

def test_interception_forward_with_overrides(pm):
    pm.configure("http://127.0.0.1:8080")
    pm.set_intercept(True)
    
    req = urllib.request.Request("http://example.com", headers={"X-Original": "True"})
    
    def background_forwarder():
        # Wait until the request is intercepted
        for _ in range(50):
            intercepted = pm.get_intercepted()
            if intercepted:
                flow = intercepted[0]
                pm.forward_request(flow["id"], {
                    "url": "http://example.org/overridden",
                    "headers": {"X-Overridden": "True"},
                    "method": "POST",
                    "body": "new body"
                })
                return
            time.sleep(0.1)
        raise TimeoutError("Request was never intercepted")

    t = threading.Thread(target=background_forwarder)
    t.start()

    # We expect make_request to block, then once forwarded, it will try to hit example.org/overridden
    # Since we don't have a real proxy running, build_opener might fail OR the request itself might fail.
    # But we can mock build_opener to return a mock response to verify make_request logic.
    
    from unittest.mock import MagicMock, patch
    
    mock_resp = MagicMock()
    mock_resp.getcode.return_value = 200
    mock_resp.read.return_value = b"OK"
    mock_resp.headers = {"Content-Type": "text/plain"}
    mock_resp.__enter__.return_value = mock_resp
    
    with patch("urllib.request.OpenerDirector.open", return_value=mock_resp) as mock_open:
        status, body, headers = pm.make_request(req)
        
        # Verify that the request passed to mock_open was modified
        called_req = mock_open.call_args[0][0]
        assert called_req.full_url == "http://example.org/overridden"
        assert called_req.get_method() == "POST"
        assert called_req.headers["X-overridden"] == "True" # urllib capitalizes
        assert called_req.data == b"new body"
        
    t.join()

def test_interception_drop(pm):
    pm.configure("http://127.0.0.1:8080")
    pm.set_intercept(True)
    
    req = urllib.request.Request("http://example.com")
    
    def background_dropper():
        for _ in range(50):
            intercepted = pm.get_intercepted()
            if intercepted:
                pm.drop_request(intercepted[0]["id"])
                return
            time.sleep(0.1)

    t = threading.Thread(target=background_dropper)
    t.start()

    status, body, headers = pm.make_request(req)
    
    assert status == 403
    assert "dropped" in body
    
    t.join()

def test_interception_timeout_defaults_to_forward(pm):
    # This test might be slow due to timeout, let's use a shorter timeout in ProxyManager if it were configurable
    # For now, let's just mock event.wait to return immediately
    pm.configure("http://127.0.0.1:8080")
    pm.set_intercept(True)
    
    req = urllib.request.Request("http://example.com")
    
    from unittest.mock import MagicMock, patch
    
    mock_resp = MagicMock()
    mock_resp.getcode.return_value = 200
    mock_resp.read.return_value = b"OK"
    mock_resp.headers = {}
    mock_resp.__enter__.return_value = mock_resp
    
    # Mock event.wait to return False (timeout)
    with patch("threading.Event.wait", return_value=False), \
         patch("urllib.request.OpenerDirector.open", return_value=mock_resp):
        
        status, body, headers = pm.make_request(req)
        assert status == 200 # Should proceed normally after timeout
