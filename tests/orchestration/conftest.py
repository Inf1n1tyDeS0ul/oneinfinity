# tests/orchestration/conftest.py
"""Shared pytest fixtures for orchestration tests."""
import pytest
import oneinfinity.orchestration.backends as _reg


@pytest.fixture(autouse=True)
def clean_backends_registry():
    """Reset the backends registry after each test to prevent cross-test pollution."""
    original = _reg._BACKENDS.copy()
    yield
    _reg._BACKENDS.clear()
    _reg._BACKENDS.update(original)
