"""
Payload mutation parity and adversarial tests.
Tests the Python MutationEngine implementation.
"""
import sys
import pytest
from pathlib import Path as _Path
_REPO_ROOT = _Path(__file__).resolve().parent
while not (_REPO_ROOT / 'pyproject.toml').exists():
    _REPO_ROOT = _REPO_ROOT.parent
if str(_REPO_ROOT / 'src') not in sys.path:
    sys.path.insert(0, str(_REPO_ROOT / 'src'))
from oneinfinity.arsenal.mutation_engine import MutationEngine, MutatedPayload


def test_encoding_mutations():
    engine = MutationEngine()
    payload = '<script>alert(1)</script>'
    results = engine.mutate(payload)
    # Should produce multiple variants
    assert len(results) >= 3
    assert all(isinstance(r, MutatedPayload) for r in results)


def test_waf_bypass_cloudflare():
    engine = MutationEngine()
    results = engine.mutate('" OR 1=1--', waf_vendor='cloudflare')
    assert len(results) >= 3


def test_empty_payload_no_crash():
    engine = MutationEngine()
    results = engine.mutate('')
    assert isinstance(results, list)


def test_large_payload_capped():
    engine = MutationEngine()
    payload = 'A' * 10_000
    results = engine.mutate(payload)
    # Should not OOM or return unbounded list
    assert isinstance(results, list)
    assert len(results) <= engine.max_mutations  # bounded by max_mutations


def test_xss_payload_mutations_content():
    engine = MutationEngine()
    payload = '<script>alert(1)</script>'
    results = engine.mutate(payload, waf_vendor='akamai')
    strategies = {r.strategy for r in results}
    # akamai strategy includes whitespace + comment + case
    assert len(strategies) >= 2


def test_sqli_payload_mutations():
    engine = MutationEngine()
    payload = "' OR '1'='1"
    results = engine.mutate(payload, vuln_type='sqli')
    assert len(results) >= 3


def test_blocked_patterns_filtered():
    engine = MutationEngine()
    payload = '<script>alert(1)</script>'
    results = engine.mutate(payload, blocked_patterns=['<script>'])
    # Mutations containing <script> should be filtered
    for r in results:
        assert '<script>' not in r.content.lower()


def test_get_stats():
    engine = MutationEngine()
    engine.mutate('<script>alert(1)</script>')
    stats = engine.get_stats()
    assert isinstance(stats, dict)
    assert 'total_mutations' in stats
    assert stats['total_mutations'] >= 0


def test_record_success_and_genetic():
    engine = MutationEngine()
    parent = '<img src=x onerror=alert(1)>'
    engine.record_success(parent, 'xss', waf='cloudflare')
    results = engine.mutate(parent, waf_vendor='imperva', vuln_type='xss')
    assert isinstance(results, list)


if __name__ == '__main__':
    pytest.main([__file__, '-v'])
