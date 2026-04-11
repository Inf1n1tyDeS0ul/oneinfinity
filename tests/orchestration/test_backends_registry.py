"""Tests for orchestration/backends/__init__.py registry."""
import pytest


def test_backendresult_not_failed_when_no_error():
    from oneinfinity.orchestration.backends import BackendResult
    ok = BackendResult(content="hi", input_tokens=5, output_tokens=3, duration_ms=10.0)
    assert not ok.failed


def test_backendresult_failed_when_error_set():
    from oneinfinity.orchestration.backends import BackendResult
    err = BackendResult(content="", input_tokens=0, output_tokens=0, duration_ms=0.0, error="boom")
    assert err.failed


def test_register_and_get_backend():
    from oneinfinity.orchestration.backends import (
        BaseBackend, BackendResult, register_backend, get_backend
    )

    class _Dummy(BaseBackend):
        provider = "dummy_test_abc"
        def is_available(self): return True
        def call(self, model_id, prompt, system, temperature, max_tokens):
            return BackendResult("ok", 1, 1, 0.0)

    b = _Dummy()
    register_backend(b)
    assert get_backend("dummy_test_abc") is b


def test_get_backend_missing_returns_none():
    from oneinfinity.orchestration.backends import get_backend
    assert get_backend("nonexistent_xyz_999") is None


def test_list_backends_includes_registered():
    from oneinfinity.orchestration.backends import (
        BaseBackend, BackendResult, register_backend, list_backends
    )

    class _Dummy2(BaseBackend):
        provider = "dummy_test_xyz"
        def is_available(self): return True
        def call(self, model_id, prompt, system, temperature, max_tokens):
            return BackendResult("ok", 1, 1, 0.0)

    register_backend(_Dummy2())
    assert "dummy_test_xyz" in list_backends()
