# tests/test_airt_chainer.py
from oneinfinity.scan.ai_red_teamer.chainer import ExploitChainer
import pytest

def test_extract_urls():
    chainer = ExploitChainer()
    response = "Check http://internal-wiki.local/secrets?id=123 and https://api.corp/v1#top"
    leaks = chainer.analyze_response(response)
    
    assert "urls" in leaks
    assert "http://internal-wiki.local/secrets?id=123" in leaks["urls"]
    assert "https://api.corp/v1#top" in leaks["urls"]

def test_url_cleaning():
    chainer = ExploitChainer()
    response = "Go to http://target.com. Also check (https://corp.internal/)."
    leaks = chainer.analyze_response(response)
    
    assert "http://target.com" in leaks["urls"]
    assert "https://corp.internal/" in leaks["urls"]
    # Ensure no trailing punctuation like '.' or ')'
    assert "http://target.com." not in leaks["urls"]

def test_extract_ips():
    chainer = ExploitChainer()
    response = "DB at 10.0.0.5 and proxy at 192.168.1.1"
    leaks = chainer.analyze_response(response)
    
    assert "10.0.0.5" in leaks["ips"]
    assert "192.168.1.1" in leaks["ips"]

def test_invalid_ip_exclusion():
    chainer = ExploitChainer()
    response = "Fake IP 999.999.999.999 and 1.2.3"
    leaks = chainer.analyze_response(response)
    
    assert "999.999.999.999" not in leaks["ips"]
    assert "1.2.3" not in leaks["ips"]

def test_extract_api_keys():
    chainer = ExploitChainer()
    response = "AWS: AKIAEXAMPLE123456789, Generic: 1234567890abcdef1234567890abcdef"
    leaks = chainer.analyze_response(response)
    
    assert "AKIAEXAMPLE123456789" in leaks["api_keys"]
    assert "1234567890abcdef1234567890abcdef" in leaks["api_keys"]

def test_deduplication():
    chainer = ExploitChainer()
    response = "Check http://target.com and http://target.com again."
    leaks = chainer.analyze_response(response)
    
    assert len(leaks["urls"]) == 1
    assert leaks["urls"][0] == "http://target.com"

def test_extract_emails():
    chainer = ExploitChainer()
    response = "Contact admin@internal.corp or security@internal.corp"
    leaks = chainer.analyze_response(response)
    
    assert "admin@internal.corp" in leaks["emails"]
    assert "security@internal.corp" in leaks["emails"]
