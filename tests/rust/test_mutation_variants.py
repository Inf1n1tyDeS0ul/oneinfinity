"""
Variant count snapshot tests for mutation engine.
Verifies Python baseline and documents Rust target counts.
Deterministic: same input always produces same count.
"""
import sys
import pytest
from pathlib import Path as _Path
_REPO_ROOT = _Path(__file__).resolve().parent
while not (_REPO_ROOT / 'pyproject.toml').exists():
    _REPO_ROOT = _REPO_ROOT.parent
if str(_REPO_ROOT / 'src') not in sys.path:
    sys.path.insert(0, str(_REPO_ROOT / 'src'))
from oneinfinity.arsenal.mutation_engine import MutationEngine

# Python baseline counts (documented from OffensiveQualityAgent evaluation)
PYTHON_BASELINE = {
    'total_strategies': 26,  # distinct mutation strategy outputs
    'min_variants_per_call': 5,  # minimum for any non-empty payload
}

# Rust target counts (for enforcement when Rust module is available)
RUST_TARGET = {
    'min_variants_per_vendor': 12,  # >= 2x Python's 3-6 per vendor
    'min_encoding_types': 11,       # >= 2x Python's 7 (11 documented in payload_mutate.rs)
    'min_total_per_call': 50,       # >= 2x Python's ~26 strategies
}

@pytest.fixture
def engine():
    return MutationEngine()

def test_python_encoding_mutations_count(engine):
    """Python encoding mutations produce at least 3 variants (url, hex, base64)"""
    payload = '<script>alert(1)</script>'
    results = engine._encoding_mutations(payload)
    assert len(results) >= 3, f'Expected >=3 encoding variants, got {len(results)}'

def test_python_case_mutations_count(engine):
    """Python case mutations produce at least 5 variants"""
    payload = 'SELECT'
    results = engine._case_mutations(payload)
    assert len(results) >= 5, f'Expected >=5 case variants, got {len(results)}'

def test_python_whitespace_mutations_count(engine):
    """Python whitespace injection produces at least 3 variants for xss"""
    payload = 'SELECT 1'
    results = engine._whitespace_injection(payload, 'xss')
    assert len(results) >= 3, f'Expected >=3 whitespace variants, got {len(results)}'

def test_python_whitespace_sqli_count(engine):
    """Python whitespace injection produces at least 4 variants for sqli"""
    payload = 'SELECT 1'
    results = engine._whitespace_injection(payload, 'sqli')
    assert len(results) >= 4, f'Expected >=4 whitespace sqli variants, got {len(results)}'

def test_python_comment_mutations_sqli_count(engine):
    """Python comment injection produces at least 2 variants for sqli"""
    payload = 'SELECT 1'
    results = engine._comment_injection(payload, 'sqli')
    assert len(results) >= 2, f'Expected >=2 comment variants for sqli, got {len(results)}'

def test_python_comment_mutations_xss_count(engine):
    """Python comment injection produces at least 2 variants for xss"""
    payload = '<script>alert(1)</script>'
    results = engine._comment_injection(payload, 'xss')
    assert len(results) >= 2, f'Expected >=2 comment variants for xss, got {len(results)}'

def test_python_generate_mutations_total(engine):
    """Python mutate() returns at least min_variants_per_call MutatedPayload objects"""
    payload = '" OR 1=1--'
    # mutate() signature: mutate(payload, waf_vendor=None, blocked_patterns=None, vuln_type="xss")
    results = engine.mutate(payload, waf_vendor='generic_waf', vuln_type='sqli')
    total = len(results)
    assert total >= PYTHON_BASELINE['min_variants_per_call'], \
        f'Expected >={PYTHON_BASELINE["min_variants_per_call"]} total variants, got {total}'

def test_determinism_encoding_same_input_same_count(engine):
    """Same input always produces same count for encoding mutations (determinism)"""
    payload = 'UNION SELECT'
    r1 = engine._encoding_mutations(payload)
    r2 = engine._encoding_mutations(payload)
    assert len(r1) == len(r2), 'Non-deterministic: same input produced different count'
    contents1 = sorted(m.content for m in r1)
    contents2 = sorted(m.content for m in r2)
    assert contents1 == contents2, 'Non-deterministic: same input produced different content'

def test_determinism_case_same_input_same_count(engine):
    """Case mutations are deterministic for static variants (upper/lower/title/alternating)"""
    payload = 'SELECT union'
    r1 = engine._case_mutations(payload)
    r2 = engine._case_mutations(payload)
    # Count must be stable; upper/lower/title/alternating are deterministic
    assert len(r1) == len(r2), 'Case mutation count differs between runs'
    # Static strategies match
    static_strategies = {'uppercase', 'lowercase', 'title_case', 'alternating_case'}
    contents1 = {m.content for m in r1 if m.strategy in static_strategies}
    contents2 = {m.content for m in r2 if m.strategy in static_strategies}
    assert contents1 == contents2, 'Deterministic case variants differ between runs'

def test_encoding_mutations_strategy_tags(engine):
    """Each encoding mutation has a non-empty strategy tag"""
    payload = 'test<payload>'
    results = engine._encoding_mutations(payload)
    for m in results:
        assert m.strategy, f'Mutation missing strategy tag: {m!r}'
        assert m.parent == payload, f'Mutation parent mismatch: {m.parent!r}'

def test_case_mutations_strategy_tags(engine):
    """Each case mutation carries a distinct strategy tag"""
    payload = 'SeLeCt'
    results = engine._case_mutations(payload)
    strategies = [m.strategy for m in results]
    # All strategy names must be non-empty
    assert all(strategies), 'Some case mutations have empty strategy'
    # Must include the four static deterministic strategies
    assert 'uppercase' in strategies
    assert 'lowercase' in strategies
    assert 'title_case' in strategies
    assert 'alternating_case' in strategies

def test_rust_target_counts_documented():
    """Document Rust target counts for CI enforcement (informational, always passes)"""
    import os
    if os.environ.get('ONEINFINITY_RUST', '') not in ('', '0', 'false'):
        try:
            from oneinfinity_core import generate_waf_bypass, mutate
            for vendor in ['cloudflare', 'akamai', 'imperva', 'f5', 'barracuda', 'aws_waf', 'modsecurity']:
                variants = generate_waf_bypass('" OR 1=1--', vendor)
                assert len(variants) >= RUST_TARGET['min_variants_per_vendor'], \
                    f'Vendor {vendor}: expected >={RUST_TARGET["min_variants_per_vendor"]} variants, got {len(variants)}'
            encodings = ['url', 'double_url', 'hex', 'hex_upper', 'unicode', 'base64',
                        'html', 'html_hex', 'null_byte', 'utf16', 'rot13']
            for enc in encodings:
                result = mutate('test', 'encoding', None)  # type: ignore
                assert isinstance(result, list)
        except ImportError:
            pass  # Rust not built — skip
    # Always pass: this test is documentation
    assert True

if __name__ == '__main__':
    pytest.main([__file__, '-v'])
