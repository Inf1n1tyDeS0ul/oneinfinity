# tests/orchestration/test_ollama_backend.py
"""Tests for OllamaBackend."""
import json
import urllib.error
from unittest.mock import patch, MagicMock

import pytest


def _mock_urlopen(body: dict):
    mock_resp = MagicMock()
    mock_resp.__enter__ = lambda s: s
    mock_resp.__exit__ = MagicMock(return_value=False)
    mock_resp.read.return_value = json.dumps(body).encode()
    return mock_resp


# ── _infer_tier ──────────────────────────────────────────────────────────────

@pytest.mark.parametrize("name,expected", [
    ("llama3.1:70b",        "PREMIUM"),
    ("qwen2.5:72b",         "PREMIUM"),
    ("mixtral:65b",         "PREMIUM"),
    ("llama3.1:13b",        "STANDARD"),
    ("deepseek-coder:14b",  "STANDARD"),
    ("qwen2.5:32b",         "STANDARD"),
    ("llama3.2:3b",         "FAST"),
    ("llama3.2:latest",     "FAST"),
    ("qwen2.5:7b",          "FAST"),
    ("phi3:latest",         "FAST"),
    # reasoning bump: FAST → STANDARD
    ("deepseek-r1:7b",      "STANDARD"),
    # reasoning bump: STANDARD → PREMIUM
    ("deepseek-r1:14b",     "PREMIUM"),
    ("qwq:32b",             "PREMIUM"),
])
def test_infer_tier(name, expected):
    from oneinfinity.orchestration.backends.ollama import _infer_tier
    assert _infer_tier(name) == expected


# ── is_available ─────────────────────────────────────────────────────────────

def test_is_available_true():
    from oneinfinity.orchestration.backends.ollama import OllamaBackend
    with patch("urllib.request.urlopen", return_value=_mock_urlopen({})):
        assert OllamaBackend().is_available() is True


def test_is_available_false_on_connection_refused():
    from oneinfinity.orchestration.backends.ollama import OllamaBackend
    with patch("urllib.request.urlopen", side_effect=OSError("Connection refused")):
        assert OllamaBackend().is_available() is False


# ── call ─────────────────────────────────────────────────────────────────────

def test_call_returns_content_and_tokens():
    from oneinfinity.orchestration.backends.ollama import OllamaBackend
    api_resp = {
        "choices": [{"message": {"content": "exploit payload"}}],
        "usage": {"prompt_tokens": 10, "completion_tokens": 5},
    }
    with patch("urllib.request.urlopen", return_value=_mock_urlopen(api_resp)):
        result = OllamaBackend().call("llama3.2:3b", "hi", "system", 0.2, 512)

    assert result.content == "exploit payload"
    assert result.input_tokens == 10
    assert result.output_tokens == 5
    assert not result.failed


def test_call_returns_failed_result_on_http_404():
    from oneinfinity.orchestration.backends.ollama import OllamaBackend
    err = urllib.error.HTTPError(url="", code=404, msg="Not Found", hdrs={}, fp=MagicMock())
    err.read = lambda: b"model not found"
    with patch("urllib.request.urlopen", side_effect=err):
        result = OllamaBackend().call("nomodel:1b", "hi", "", 0.2, 512)

    assert result.failed
    assert "404" in result.error


def test_call_uses_ollama_host_env(monkeypatch):
    from oneinfinity.orchestration.backends.ollama import OllamaBackend
    monkeypatch.setenv("OLLAMA_HOST", "http://remotehost:11434")
    api_resp = {"choices": [{"message": {"content": "ok"}}], "usage": {}}
    with patch("urllib.request.urlopen", return_value=_mock_urlopen(api_resp)) as mock_open:
        OllamaBackend().call("llama3.2:3b", "hi", "", 0.2, 512)
        url = mock_open.call_args[0][0].full_url
    assert "remotehost" in url


def test_call_uses_per_model_host():
    from oneinfinity.orchestration.backends.ollama import OllamaBackend
    api_resp = {"choices": [{"message": {"content": "ok"}}], "usage": {}}
    with patch("urllib.request.urlopen", return_value=_mock_urlopen(api_resp)) as mock_open:
        OllamaBackend().call("llama3.2:3b", "hi", "", 0.2, 512, host="http://gpu-box:11434")
        url = mock_open.call_args[0][0].full_url
    assert "gpu-box" in url


# ── discover_models ───────────────────────────────────────────────────────────

def test_discover_models_assigns_tiers():
    from oneinfinity.orchestration.backends.ollama import OllamaBackend
    api_resp = {
        "models": [
            {"name": "llama3.2:3b",  "details": {}},
            {"name": "llama3.1:70b", "details": {}},
            {"name": "deepseek-r1:7b", "details": {}},
        ]
    }
    with patch("urllib.request.urlopen", return_value=_mock_urlopen(api_resp)):
        models = OllamaBackend().discover_models()

    tiers = {m.name: m.tier for m in models}
    assert tiers["llama3.2:3b"] == "FAST"
    assert tiers["llama3.1:70b"] == "PREMIUM"
    assert tiers["deepseek-r1:7b"] == "STANDARD"


def test_discover_models_returns_empty_when_ollama_down():
    from oneinfinity.orchestration.backends.ollama import OllamaBackend
    with patch("urllib.request.urlopen", side_effect=OSError("refused")):
        assert OllamaBackend().discover_models() == []


def test_ollama_backend_registered_at_import():
    import importlib
    import oneinfinity.orchestration.backends.ollama
    importlib.reload(oneinfinity.orchestration.backends.ollama)
    from oneinfinity.orchestration.backends import get_backend
    assert get_backend("ollama") is not None
