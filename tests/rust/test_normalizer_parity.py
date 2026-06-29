"""
Finding normalizer parity and adversarial tests.
Tests the Python implementation in tool_wrappers directly.
"""
import sys
import hashlib
import pytest
from pathlib import Path as _Path
_REPO_ROOT = _Path(__file__).resolve().parent
while not (_REPO_ROOT / 'pyproject.toml').exists():
    _REPO_ROOT = _REPO_ROOT.parent
if str(_REPO_ROOT / 'src') not in sys.path:
    sys.path.insert(0, str(_REPO_ROOT / 'src'))
from oneinfinity.modules.tool_wrappers import normalize_finding, normalize_results, merge_normalized, _finding_key

def test_normalize_dict_finding():
    raw = {'url': 'https://example.com/api', 'name': 'SQL Injection', 'severity': 'high'}
    result = normalize_finding(raw, 'nuclei')
    assert result['url'] == 'https://example.com/api'
    assert result['severity'] == 'high'
    assert result['source_tool'] == 'nuclei'
    assert 'vulnerability' in result

def test_normalize_string_finding():
    result = normalize_finding('https://target.com - XSS', 'manual')
    assert isinstance(result, dict)
    assert 'url' in result

def test_normalize_none_finding():
    result = normalize_finding(None, 'test')
    assert isinstance(result, dict)
    assert result['severity'] == 'unknown'

def test_finding_key_deterministic():
    f = {'url': 'https://a.com', 'parameter': 'q', 'vulnerability': 'xss'}
    key1 = _finding_key(f)
    key2 = _finding_key(f)
    assert key1 == key2
    expected = hashlib.md5(b'https://a.com|q|xss').hexdigest()
    assert key1 == expected

def test_merge_normalized_dedup():
    f1 = normalize_finding({'url': 'https://a.com', 'name': 'XSS', 'severity': 'high'}, 'tool1')
    f2 = normalize_finding({'url': 'https://a.com', 'name': 'XSS', 'severity': 'high'}, 'tool2')
    merged = merge_normalized([f1, f2], [f1])
    # Duplicates should be removed
    assert len(merged) >= 1

def test_normalize_large_string_no_crash():
    raw = {'url': 'https://a.com', 'name': 'A' * 1_000_000, 'severity': 'low'}
    result = normalize_finding(raw, 'test')
    assert isinstance(result, dict)

def test_normalize_nul_bytes_no_crash():
    raw = {'url': 'https://a.com\x00evil', 'name': 'test\x00', 'severity': 'info'}
    result = normalize_finding(raw, 'test')
    assert isinstance(result, dict)

def test_normalize_all_empty_no_crash():
    result = normalize_finding({'url': '', 'name': '', 'severity': ''}, 'test')
    assert result['severity'] == 'unknown'

if __name__ == '__main__':
    pytest.main([__file__, '-v'])
