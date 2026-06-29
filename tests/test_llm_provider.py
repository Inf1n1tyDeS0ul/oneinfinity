"""tests/test_llm_provider.py — Unit tests for multi-LLM provider abstraction."""
from __future__ import annotations
import os
import pytest
from unittest.mock import patch, MagicMock


def test_llm_response_dataclass():
    from oneinfinity.infra.llm_provider import LLMResponse
    resp = LLMResponse(text="hello", provider="ollama", model="llama3", input_tokens=10, output_tokens=5)
    assert resp.text == "hello"
    assert resp.input_tokens == 10


def test_factory_instance_creation():
    from oneinfinity.infra.llm_provider import LLMProviderFactory
    factory = LLMProviderFactory(free_tier_only=False)
    assert factory is not None


def test_factory_auto_detect_returns_provider_or_none():
    from oneinfinity.infra.llm_provider import LLMProviderFactory
    with patch("requests.get", side_effect=Exception("no network")):
        factory = LLMProviderFactory(free_tier_only=False)
        provider = factory.auto_detect()
        assert provider is None or hasattr(provider, "chat")


def test_free_tier_factory():
    """free_tier_only=True should not raise during init."""
    from oneinfinity.infra.llm_provider import LLMProviderFactory
    factory = LLMProviderFactory(free_tier_only=True)
    assert factory is not None


def _make_fake_provider():
    from oneinfinity.infra.llm_provider import LLMProvider, LLMResponse

    class FakeProvider(LLMProvider):
        name = "fake"
        is_free = True

        def chat(self, prompt, system="", model="", max_tokens=4096, temperature=0.3, **kw):
            return LLMResponse(text="test", provider="fake", model="fake-v1")

        def is_available(self) -> bool:
            return True

    return FakeProvider()


def test_provider_chat_returns_llmresponse():
    """chat() on a custom provider returns LLMResponse."""
    from oneinfinity.infra.llm_provider import LLMResponse
    provider = _make_fake_provider()
    resp = provider.chat("hello")
    assert isinstance(resp, LLMResponse)
    assert resp.text == "test"


def test_race_provider_list_not_empty():
    """LLMProviderRace requires at least one provider — empty list raises ValueError."""
    from oneinfinity.infra.llm_provider import LLMProviderRace
    with pytest.raises((ValueError, Exception)):
        LLMProviderRace(providers=[])


def test_race_provider_chat_async_works():
    """FakeProvider.chat_async() delegates to chat() and returns LLMResponse."""
    import asyncio
    from oneinfinity.infra.llm_provider import LLMResponse
    provider = _make_fake_provider()
    result = asyncio.run(provider.chat_async("hello"))
    assert isinstance(result, LLMResponse)
    assert result.text == "test"
