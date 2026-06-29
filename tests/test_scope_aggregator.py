"""tests/test_scope_aggregator.py — Unit tests for bug bounty scope aggregator."""
from __future__ import annotations
import os
import pytest
from unittest.mock import patch, MagicMock


def test_scope_aggregator_imports():
    from oneinfinity.bounty.scope_aggregator import ScopeAggregator
    agg = ScopeAggregator()
    assert agg is not None


def test_aggregate_without_credentials_returns_empty():
    """aggregate() without API credentials should return [] gracefully (not crash)."""
    from oneinfinity.bounty.scope_aggregator import ScopeAggregator
    env_backup = {}
    for key in ("H1_USERNAME", "H1_API_TOKEN", "BUGCROWD_API_TOKEN", "INTIGRITI_TOKEN"):
        env_backup[key] = os.environ.pop(key, None)
    try:
        agg = ScopeAggregator()
        with patch("urllib.request.urlopen", side_effect=Exception("no creds")):
            assets = agg.aggregate([])
        assert isinstance(assets, list)
        assert assets == []
    finally:
        for key, val in env_backup.items():
            if val is not None:
                os.environ[key] = val


def test_aggregate_empty_program_specs():
    """aggregate([]) with empty list should return empty list."""
    from oneinfinity.bounty.scope_aggregator import ScopeAggregator
    agg = ScopeAggregator()
    assets = agg.aggregate([])
    assert isinstance(assets, list)
    assert len(assets) == 0


def test_feed_scope_validator_requires_scope_validator():
    """feed_scope_validator() with wrong type should raise TypeError."""
    from oneinfinity.bounty.scope_aggregator import ScopeAggregator
    agg = ScopeAggregator()
    with pytest.raises(TypeError):
        agg.feed_scope_validator("not_a_validator")


def test_feed_scope_validator_with_scope_validator():
    """feed_scope_validator() with valid ScopeValidator should not crash."""
    from oneinfinity.bounty.scope_aggregator import ScopeAggregator
    from oneinfinity.core.scope_validator import ScopeValidator
    agg = ScopeAggregator()
    sv = ScopeValidator()
    # Should not raise even with empty snapshots
    agg.feed_scope_validator(sv)


def test_diff_with_previous_empty():
    """diff_with_previous() on a new program returns empty diff."""
    from oneinfinity.bounty.scope_aggregator import ScopeAggregator
    import tempfile
    from pathlib import Path
    with tempfile.TemporaryDirectory() as tmp:
        agg = ScopeAggregator(scope_dir=Path(tmp))
        diff = agg.diff_with_previous("hackerone:acme", [])
    assert diff.added == []
    assert diff.removed == []
