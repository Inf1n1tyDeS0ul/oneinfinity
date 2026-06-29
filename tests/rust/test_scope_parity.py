"""
Scope validator parity and adversarial tests.
Tests Python ScopeValidator directly (Rust may not be built).
"""
import sys
import pytest
from pathlib import Path as _Path
_REPO_ROOT = _Path(__file__).resolve().parent
while not (_REPO_ROOT / 'pyproject.toml').exists():
    _REPO_ROOT = _REPO_ROOT.parent
if str(_REPO_ROOT / 'src') not in sys.path:
    sys.path.insert(0, str(_REPO_ROOT / 'src'))
from oneinfinity.core.scope_validator import ScopeValidator

def make_sv(*in_scope, out_of_scope=()):
    sv = ScopeValidator()
    for p in in_scope:
        sv.add_in_scope(p)
    for p in out_of_scope:
        sv.add_out_of_scope(p)
    return sv

def test_exact_domain():
    sv = make_sv('acme.com')
    assert sv.check('acme.com')
    assert not sv.check('evil.com')

def test_wildcard_subdomain():
    sv = make_sv('*.acme.com')
    assert sv.check('api.acme.com')
    assert not sv.check('evil.com')

def test_explicit_deny_overrides_allow():
    sv = make_sv('acme.com', out_of_scope=['admin.acme.com'])
    # admin must be blocked even if acme.com is in scope
    assert not sv.check('admin.acme.com')

def test_always_oos_localhost():
    sv = make_sv('localhost')
    # even if explicitly added, localhost is always OOS
    assert not sv.check('localhost')

def test_always_oos_rfc1918():
    sv = make_sv('10.0.0.1')
    assert not sv.check('10.0.0.1')

def test_url_extraction():
    sv = make_sv('acme.com')
    assert sv.check('https://acme.com/path?q=1')
    assert not sv.check('https://evil.com/path')

def test_no_allow_rules_blocks_everything():
    sv = ScopeValidator()
    assert not sv.check('anyhost.com')

def test_malformed_url_no_crash():
    sv = make_sv('acme.com')
    # Should not crash
    result = sv.check('not a url at all !!!###')
    assert isinstance(result, bool)

def test_very_long_hostname_no_crash():
    sv = make_sv('acme.com')
    result = sv.check('a' * 10_000 + '.acme.com')
    assert isinstance(result, bool)

def test_ipv4_cidr():
    sv = make_sv('192.168.1.0/24')  # this is always OOS, test with non-RFC1918
    # Test with a routable CIDR
    sv2 = ScopeValidator()
    sv2.add_in_scope('10.10.0.0/24')  # still OOS due to RFC1918
    # Just test that CIDR parsing doesn't crash
    result = sv2.check('10.10.0.5')
    assert isinstance(result, bool)

if __name__ == '__main__':
    pytest.main([__file__, '-v'])
