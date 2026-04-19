"""Test API key startup enforcement logic extracted from web/backend/main.py."""
import os
import pytest


def _simulate_startup(oi_env: str, api_key: str):
    """Reproduce the startup API key guard from web/backend/main.py."""
    key = api_key
    if not key and oi_env == "prod":
        raise SystemExit(
            "FATAL: ONEINFINITY_API_KEY environment variable must be set in production."
        )
    return key


def test_prod_without_api_key_raises():
    with pytest.raises(SystemExit, match="FATAL"):
        _simulate_startup("prod", "")


def test_prod_with_api_key_passes():
    result = _simulate_startup("prod", "valid-key-abc")
    assert result == "valid-key-abc"


def test_dev_without_api_key_passes():
    result = _simulate_startup("dev", "")
    assert result == ""


def test_dev_with_api_key_passes():
    result = _simulate_startup("dev", "some-key")
    assert result == "some-key"
