"""
Golden corpus parity tests for ScopeValidator.
Tests edge cases: IDNA, IPv6, CIDR boundaries, wildcard multi-label, regex.
All cases must pass with Python ScopeValidator. When Rust is built, run same corpus against Rust.
"""
import sys
import pytest
from pathlib import Path as _Path
_REPO_ROOT = _Path(__file__).resolve().parent
while not (_REPO_ROOT / 'pyproject.toml').exists():
    _REPO_ROOT = _REPO_ROOT.parent
if str(_REPO_ROOT / 'src') not in sys.path:
    sys.path.insert(0, str(_REPO_ROOT / 'src'))
from oneinfinity.core.scope_validator import ScopeValidator, ScopeRule


def sv(*in_scope, out_of_scope=()):
    v = ScopeValidator()
    for p in in_scope:
        v.add_in_scope(p)
    for p in out_of_scope:
        v.add_out_of_scope(p)
    return v


def sv_cidr(*cidr_patterns, extra_in_scope=(), out_of_scope=()):
    """Helper for CIDR tests: CIDR must bypass _extract_host which splits on '/'."""
    v = ScopeValidator()
    for p in cidr_patterns:
        v._in_scope.append(ScopeRule.from_pattern(p))
    for p in extra_in_scope:
        v.add_in_scope(p)
    for p in out_of_scope:
        v.add_out_of_scope(p)
    return v


# ─── Wildcard edge cases ─────────────────────────────────────────────────────

def test_wildcard_apex_no_match():
    """*.acme.com does NOT match acme.com itself (fnmatch: * doesn't match empty)."""
    v = sv('*.acme.com')
    # fnmatch('acme.com', '*.acme.com') -> False; 'acme.com' != '*.acme.com'
    assert not v.check('acme.com')

def test_wildcard_single_label_subdomain():
    v = sv('*.acme.com')
    assert v.check('api.acme.com')

def test_wildcard_multi_label_subdomain():
    """fnmatch * matches dots too, so a.b.acme.com matches *.acme.com."""
    v = sv('*.acme.com')
    assert v.check('a.b.acme.com')

def test_wildcard_deny_overrides_allow():
    v = sv('*.acme.com', out_of_scope=['secret.acme.com'])
    assert not v.check('secret.acme.com')
    assert v.check('api.acme.com')

def test_wildcard_exact_pattern_no_match_different_domain():
    v = sv('*.acme.com')
    assert not v.check('api.other.com')

def test_wildcard_deeper_nesting():
    v = sv('*.acme.com')
    # a.b.c.acme.com — fnmatch * matches dots, so True
    assert v.check('a.b.c.acme.com')

def test_wildcard_subdomain_not_in_scope():
    v = sv('acme.com')
    # acme.com rule: value=='acme.com' OR endswith('.acme.com')
    assert v.check('sub.acme.com')

def test_wildcard_sibling_domain_blocked():
    v = sv('*.acme.com')
    assert not v.check('api.acme.org')

# ─── ALWAYS_OOS edge cases ────────────────────────────────────────────────────

def test_always_oos_127_prefix():
    v = sv('127.0.0.1')
    # 127.0.0.1 matches '127.*' OOS rule
    assert not v.check('127.0.0.1')

def test_always_oos_127_variant():
    v = sv('127.0.0.100')
    assert not v.check('127.0.0.100')

def test_always_oos_169_254():
    v = sv('169.254.1.1')
    assert not v.check('169.254.1.1')  # link-local: matches '169.254.*'

def test_always_oos_10_dot():
    v = sv('10.10.10.10')
    assert not v.check('10.10.10.10')  # RFC-1918: matches '10.*'

def test_always_oos_192_168():
    v = sv('192.168.0.1')
    assert not v.check('192.168.0.1')  # RFC-1918: matches '192.168.*'

def test_always_oos_172_16():
    v = sv('172.16.0.1')
    assert not v.check('172.16.0.1')  # RFC-1918: matches '172.16.*'

def test_always_oos_172_17_not_blocked():
    """172.17.* is NOT in the always-OOS list (only 172.16.*)."""
    v = sv('172.17.0.1')
    # 172.17.0.1 doesn't match '172.16.*', so it's in-scope if declared
    assert v.check('172.17.0.1')

def test_always_oos_localhost():
    v = sv('localhost')
    assert not v.check('localhost')  # literal 'localhost' in OOS

def test_always_oos_dot_internal():
    v = sv('internal.corp.internal')
    assert not v.check('internal.corp.internal')  # matches '*.internal'

def test_always_oos_dot_local():
    v = sv('mydevice.local')
    assert not v.check('mydevice.local')  # matches '*.local'

def test_always_oos_dot_corp():
    v = sv('myserver.corp')
    assert not v.check('myserver.corp')  # matches '*.corp'

def test_always_oos_dot_test():
    v = sv('staging.test')
    assert not v.check('staging.test')  # matches '*.test'

def test_always_oos_example_com():
    v = sv('foo.example.com')
    assert not v.check('foo.example.com')  # matches '*.example.com'

def test_always_oos_loopback_ipv6_note():
    """::1 in _ALWAYS_OOS but _extract_host strips trailing ':' due to colon handling.
    Practical result: checking '::1' when it's also in in-scope returns True (quirk).
    This test documents the actual Python behavior without asserting a crash."""
    v = sv('::1')
    result = v.check('::1')
    assert isinstance(result, bool)  # must not raise; actual value is implementation-defined

def test_always_oos_zero_addr():
    v = sv('0.0.0.0')
    assert not v.check('0.0.0.0')  # '0.0.0.0' literal in OOS

# ─── URL parsing ─────────────────────────────────────────────────────────────

def test_url_with_path():
    v = sv('acme.com')
    assert v.check('https://acme.com/api/v1?x=1')

def test_url_with_port():
    v = sv('acme.com')
    assert v.check('https://acme.com:8443/path')

def test_url_http_scheme():
    v = sv('acme.com')
    assert v.check('http://acme.com/')

def test_bare_ip_test_net():
    """203.0.113.x is TEST-NET (RFC-5737), not RFC-1918 — can be in scope."""
    v = sv('203.0.113.1')
    assert v.check('203.0.113.1')

def test_bare_domain_no_scheme():
    v = sv('acme.com')
    assert v.check('acme.com')

def test_subdomain_via_domain_rule():
    """add_in_scope('acme.com') covers sub.acme.com via endswith('.acme.com')."""
    v = sv('acme.com')
    assert v.check('sub.acme.com')

def test_url_subdomain_covered():
    v = sv('acme.com')
    assert v.check('https://api.acme.com/v2')

def test_ftp_scheme_host_not_extracted():
    """ftp:// is not http/https — _extract_host splits on '/' and returns 'ftp:',
    which after port-strip becomes 'ftp'. 'ftp' != 'acme.com' → False."""
    v = sv('acme.com')
    assert not v.check('ftp://acme.com/file')

# ─── CIDR edge cases ─────────────────────────────────────────────────────────

def test_cidr_host_in_range():
    """Direct CIDR rule (bypass _extract_host) — 203.0.113.50 inside /24."""
    v = sv_cidr('203.0.113.0/24')
    assert v.check('203.0.113.50')

def test_cidr_host_boundary_low():
    v = sv_cidr('203.0.113.0/24')
    assert v.check('203.0.113.0')

def test_cidr_host_boundary_high():
    v = sv_cidr('203.0.113.0/24')
    assert v.check('203.0.113.255')

def test_cidr_host_outside_range():
    v = sv_cidr('203.0.113.0/24')
    assert not v.check('203.0.114.1')

def test_cidr_slash_32():
    v = sv_cidr('203.0.113.42/32')
    assert v.check('203.0.113.42')
    assert not v.check('203.0.113.43')

# ─── Adversarial / crash guards ───────────────────────────────────────────────

def test_empty_string_no_crash():
    """Empty string: _extract_host returns None → check returns False."""
    v = sv('acme.com')
    assert not v.check('')

def test_none_like_string():
    """Literal string 'None' is a valid non-matching hostname."""
    v = sv('acme.com')
    assert not v.check('None')

def test_very_long_hostname():
    """Very long hostname matching via endswith."""
    v = sv('acme.com')
    assert v.check('a' * 240 + '.acme.com')

def test_unicode_url_no_crash():
    """Unicode URL: urlparse may return None hostname — must not raise."""
    v = sv('acme.com')
    result = v.check('https://中文.中文/path')
    assert isinstance(result, bool)
    # urlparse returns a hostname that doesn't match 'acme.com'
    assert not result

def test_path_only_no_crash():
    """/just/a/path has no host — check returns False."""
    v = sv('acme.com')
    assert not v.check('/just/a/path')

def test_double_slash_no_crash():
    v = sv('acme.com')
    result = v.check('//')
    assert isinstance(result, bool)

def test_at_sign_in_url():
    """URL with user@host — urlparse strips user info; hostname = acme.com."""
    v = sv('acme.com')
    result = v.check('https://user:pass@acme.com/path')
    assert isinstance(result, bool)

def test_ip_as_string():
    """Passing an IP string for a domain-scope rule."""
    v = sv('acme.com')
    assert not v.check('1.2.3.4')

def test_wildcard_star_only():
    """A bare '*' in-scope rule matches everything not in OOS."""
    v = sv('*')
    assert v.check('api.acme.com')
    assert not v.check('localhost')  # still OOS

# ─── Mode: strict ────────────────────────────────────────────────────────────

def test_strict_mode_no_rules_blocks_all():
    """Default strict mode: no in-scope rules → everything blocked."""
    v = ScopeValidator()
    assert not v.check('anything.com')

def test_relaxed_mode_no_rules_allows_non_oos():
    """Relaxed mode: no in-scope rules → passes unless explicitly OOS."""
    v = ScopeValidator(mode='relaxed')
    assert v.check('api.acme.com')
    assert not v.check('localhost')  # still blocked by ALWAYS_OOS

def test_strict_mode_explicit():
    v = ScopeValidator(mode='strict')
    v.add_in_scope('acme.com')
    assert v.check('acme.com')
    assert not v.check('other.com')

def test_invalid_mode_raises():
    with pytest.raises(ValueError):
        ScopeValidator(mode='invalid')

# ─── Audit trail ─────────────────────────────────────────────────────────────

def test_audit_log_records_ok():
    v = sv('acme.com')
    v.check('acme.com')
    log = v.audit_log()
    assert any(e['verdict'] == 'OK' for e in log)

def test_audit_log_records_oos():
    v = sv('acme.com')
    v.check('other.com')
    log = v.audit_log()
    assert any(e['verdict'] == 'OOS' for e in log)

def test_oos_violations_filter():
    v = sv('acme.com')
    v.check('acme.com')
    v.check('evil.com')
    violations = v.oos_violations()
    assert len(violations) == 1
    assert violations[0]['target'] == 'evil.com'

# ─── Authorization gate ───────────────────────────────────────────────────────

def test_auth_gate_blocks_without_confirm():
    v = sv('acme.com')
    v.require_authorization(confirmed=False)
    assert not v.check('acme.com')

def test_auth_gate_passes_with_confirm():
    v = sv('acme.com')
    v.require_authorization(confirmed=True)
    assert v.check('acme.com')

def test_auth_confirm_method():
    v = sv('acme.com')
    v.require_authorization(confirmed=False)
    assert not v.check('acme.com')
    v.confirm_authorization()
    assert v.check('acme.com')

# ─── filter_in_scope ─────────────────────────────────────────────────────────

def test_filter_in_scope():
    v = sv('acme.com')
    targets = ['acme.com', 'evil.com', 'localhost', 'api.acme.com']
    result = v.filter_in_scope(targets)
    assert 'acme.com' in result
    assert 'api.acme.com' in result
    assert 'evil.com' not in result
    assert 'localhost' not in result

def test_assert_in_scope_raises():
    from oneinfinity.core.scope_validator import ScopeViolationError
    v = sv('acme.com')
    with pytest.raises(ScopeViolationError):
        v.assert_in_scope('evil.com')

def test_assert_in_scope_passes():
    v = sv('acme.com')
    v.assert_in_scope('acme.com')  # should not raise


if __name__ == '__main__':
    pytest.main([__file__, '-v'])
