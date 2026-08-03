"""
llm_provider.py — Unified Multi-Provider LLM Abstraction

Priority ordering (free/local first):
  1. Ollama       — fully offline, zero cost
  2. Groq         — cloud free tier (~6 000 req/day on Llama-3.3-70B)
  3. DeepSeek     — very low cost cloud API ($0.014/1M input tokens)
  4. Anthropic    — Claude Sonnet 4.6 (paid)
  5. OpenAI       — GPT-4o (paid)
  6. Grok         — xAI API (paid)

Usage::
    factory = LLMProviderFactory()
    provider = factory.auto_detect()       # best available
    response = provider.chat("Analyse this endpoint for IDOR vulnerabilities.")

    # Task-aware routing
    provider = factory.route(task_type="analysis")   # picks best for task
    response = provider.chat(prompt, system=system_prompt)

    # Racing (first responder wins)
    racer = LLMProviderRace(factory.available_providers())
    response = await racer.race(prompt)
"""
from __future__ import annotations

import asyncio
import json
import logging
import os
import time
import urllib.error
import urllib.parse
import urllib.request
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Tuple

log = logging.getLogger("oneinfinity.llm_provider")

# ---------------------------------------------------------------------------
# Data models
# ---------------------------------------------------------------------------

@dataclass
class LLMResponse:
    text: str
    provider: str
    model: str
    input_tokens: int = 0
    output_tokens: int = 0
    latency_ms: float = 0.0
    cost_usd: float = 0.0
    cached: bool = False

    def __bool__(self) -> bool:
        return bool(self.text and self.text.strip())


@dataclass
class ProviderHealth:
    provider_name: str
    available: bool
    latency_ms: float = 0.0
    error: str = ""
    checked_at: float = field(default_factory=time.time)


# ---------------------------------------------------------------------------
# Abstract base
# ---------------------------------------------------------------------------

class LLMProvider(ABC):
    """Abstract LLM provider. All concrete providers implement this interface."""

    name: str = "base"
    is_free: bool = False
    is_local: bool = False
    default_model: str = ""

    # Cost per 1M tokens (USD); 0.0 for free/local
    cost_per_1m_input: float = 0.0
    cost_per_1m_output: float = 0.0

    @abstractmethod
    def chat(
        self,
        prompt: str,
        system: str = "",
        model: str = "",
        max_tokens: int = 4096,
        temperature: float = 0.3,
        **kwargs: Any,
    ) -> LLMResponse:
        """Synchronous chat completion."""

    async def chat_async(
        self,
        prompt: str,
        system: str = "",
        model: str = "",
        max_tokens: int = 4096,
        temperature: float = 0.3,
        **kwargs: Any,
    ) -> LLMResponse:
        """Async chat — default implementation runs sync in executor."""
        loop = asyncio.get_event_loop()
        return await loop.run_in_executor(
            None,
            lambda: self.chat(prompt, system, model, max_tokens, temperature, **kwargs),
        )

    @abstractmethod
    def is_available(self) -> bool:
        """Return True if provider can be reached and credentials are valid."""

    def health_check(self) -> ProviderHealth:
        t0 = time.monotonic()
        try:
            ok = self.is_available()
            ms = (time.monotonic() - t0) * 1000
            return ProviderHealth(self.name, ok, ms)
        except Exception as exc:
            ms = (time.monotonic() - t0) * 1000
            return ProviderHealth(self.name, False, ms, str(exc))

    def estimate_cost(self, input_tokens: int, output_tokens: int) -> float:
        return (
            input_tokens / 1_000_000 * self.cost_per_1m_input
            + output_tokens / 1_000_000 * self.cost_per_1m_output
        )

    def __repr__(self) -> str:
        return f"<{self.__class__.__name__} model={self.default_model} free={self.is_free}>"


# ---------------------------------------------------------------------------
# Concrete providers
# ---------------------------------------------------------------------------

class OllamaProvider(LLMProvider):
    """Fully offline, zero-cost provider via local Ollama instance."""

    name = "ollama"
    is_free = True
    is_local = True
    cost_per_1m_input = 0.0
    cost_per_1m_output = 0.0

    _PREFERRED_MODELS = [
        "wizardlm-uncensored:13b",
        "deepseek-coder:6.7b",
        "llama3.1:8b",
        "llama3:8b",
        "mistral:7b",
        "gemma2:9b",
        "qwen2.5:7b",
    ]

    def __init__(
        self,
        base_url: str = "",
        model: str = "",
        timeout: int = 120,
    ) -> None:
        self.base_url = (base_url or os.getenv("OLLAMA_BASE_URL", "http://localhost:11434")).rstrip("/")
        self._requested_model = model
        self.default_model = ""  # resolved lazily
        self.timeout = timeout
        self._available_models: List[str] = []
        self._probed = False

    # -- internal -------------------------------------------------------

    def _probe(self) -> bool:
        if self._probed:
            return bool(self._available_models)
        try:
            req = urllib.request.Request(f"{self.base_url}/api/tags", method="GET")
            with urllib.request.urlopen(req, timeout=3) as r:
                data = json.loads(r.read())
            self._available_models = [m["name"] for m in data.get("models", [])]
            self._probed = True
            if self._requested_model:
                self.default_model = self._requested_model
            else:
                for pref in self._PREFERRED_MODELS:
                    if any(pref in m for m in self._available_models):
                        self.default_model = pref
                        break
                if not self.default_model and self._available_models:
                    self.default_model = self._available_models[0]
            return bool(self.default_model)
        except Exception as exc:
            log.debug("Ollama probe failed: %s", exc)
            self._probed = True
            return False

    # -- public ---------------------------------------------------------

    def is_available(self) -> bool:
        self._probed = False  # re-probe on explicit check
        return self._probe()

    def chat(
        self,
        prompt: str,
        system: str = "",
        model: str = "",
        max_tokens: int = 4096,
        temperature: float = 0.3,
        **kwargs: Any,
    ) -> LLMResponse:
        if not self._probe():
            raise RuntimeError("Ollama is not available")

        m = model or self.default_model
        messages = []
        if system:
            messages.append({"role": "system", "content": system})
        messages.append({"role": "user", "content": prompt})

        body = json.dumps({
            "model": m,
            "messages": messages,
            "stream": False,
            "options": {
                "temperature": temperature,
                "num_predict": max_tokens,
            },
        }).encode()

        t0 = time.monotonic()
        req = urllib.request.Request(
            f"{self.base_url}/api/chat",
            data=body,
            headers={"Content-Type": "application/json"},
            method="POST",
        )
        with urllib.request.urlopen(req, timeout=self.timeout) as r:
            data = json.loads(r.read())

        latency = (time.monotonic() - t0) * 1000
        text = data.get("message", {}).get("content", "")
        return LLMResponse(
            text=text,
            provider=self.name,
            model=m,
            latency_ms=latency,
        )


class GroqProvider(LLMProvider):
    """Groq cloud API — free tier with generous daily limits."""

    name = "groq"
    is_free = True
    is_local = False
    cost_per_1m_input = 0.0   # free tier
    cost_per_1m_output = 0.0

    # Free-tier models (as of 2026)
    _FREE_MODELS = [
        "llama-3.3-70b-versatile",
        "llama-3.1-70b-versatile",
        "mixtral-8x7b-32768",
        "gemma2-9b-it",
    ]

    def __init__(self, api_key: str = "", model: str = "") -> None:
        self.api_key = api_key or os.getenv("GROQ_API_KEY", "")
        self.default_model = model or self._FREE_MODELS[0]
        self._base = "https://api.groq.com/openai/v1"

    def is_available(self) -> bool:
        return bool(self.api_key)

    def chat(
        self,
        prompt: str,
        system: str = "",
        model: str = "",
        max_tokens: int = 4096,
        temperature: float = 0.3,
        **kwargs: Any,
    ) -> LLMResponse:
        if not self.api_key:
            raise RuntimeError("GROQ_API_KEY not set")

        m = model or self.default_model
        messages = []
        if system:
            messages.append({"role": "system", "content": system})
        messages.append({"role": "user", "content": prompt})

        body = json.dumps({
            "model": m,
            "messages": messages,
            "max_tokens": max_tokens,
            "temperature": temperature,
        }).encode()

        t0 = time.monotonic()
        req = urllib.request.Request(
            f"{self._base}/chat/completions",
            data=body,
            headers={
                "Content-Type": "application/json",
                "Authorization": f"Bearer {self.api_key}",
            },
            method="POST",
        )
        try:
            with urllib.request.urlopen(req, timeout=60) as r:
                data = json.loads(r.read())
        except urllib.error.HTTPError as exc:
            body_err = exc.read().decode(errors="replace")
            raise RuntimeError(f"Groq API error {exc.code}: {body_err}") from exc

        latency = (time.monotonic() - t0) * 1000
        text = data["choices"][0]["message"]["content"]
        usage = data.get("usage", {})
        return LLMResponse(
            text=text,
            provider=self.name,
            model=m,
            input_tokens=usage.get("prompt_tokens", 0),
            output_tokens=usage.get("completion_tokens", 0),
            latency_ms=latency,
        )


class DeepSeekProvider(LLMProvider):
    """DeepSeek cloud API — very low cost ($0.014/1M input with cache discount)."""

    name = "deepseek"
    is_free = False
    is_local = False
    cost_per_1m_input = 0.014
    cost_per_1m_output = 0.28

    def __init__(self, api_key: str = "", model: str = "") -> None:
        self.api_key = api_key or os.getenv("DEEPSEEK_API_KEY", "")
        self.default_model = model or "deepseek-chat"
        self._base = "https://api.deepseek.com/v1"

    def is_available(self) -> bool:
        return bool(self.api_key)

    def chat(
        self,
        prompt: str,
        system: str = "",
        model: str = "",
        max_tokens: int = 4096,
        temperature: float = 0.3,
        **kwargs: Any,
    ) -> LLMResponse:
        if not self.api_key:
            raise RuntimeError("DEEPSEEK_API_KEY not set")

        m = model or self.default_model
        messages = []
        if system:
            messages.append({"role": "system", "content": system})
        messages.append({"role": "user", "content": prompt})

        body = json.dumps({
            "model": m,
            "messages": messages,
            "max_tokens": max_tokens,
            "temperature": temperature,
        }).encode()

        t0 = time.monotonic()
        req = urllib.request.Request(
            f"{self._base}/chat/completions",
            data=body,
            headers={
                "Content-Type": "application/json",
                "Authorization": f"Bearer {self.api_key}",
            },
            method="POST",
        )
        try:
            with urllib.request.urlopen(req, timeout=90) as r:
                data = json.loads(r.read())
        except urllib.error.HTTPError as exc:
            body_err = exc.read().decode(errors="replace")
            raise RuntimeError(f"DeepSeek API error {exc.code}: {body_err}") from exc

        latency = (time.monotonic() - t0) * 1000
        text = data["choices"][0]["message"]["content"]
        usage = data.get("usage", {})
        cost = self.estimate_cost(
            usage.get("prompt_tokens", 0),
            usage.get("completion_tokens", 0),
        )
        return LLMResponse(
            text=text,
            provider=self.name,
            model=m,
            input_tokens=usage.get("prompt_tokens", 0),
            output_tokens=usage.get("completion_tokens", 0),
            latency_ms=latency,
            cost_usd=cost,
        )


class AnthropicProvider(LLMProvider):
    """Anthropic Claude API."""

    name = "anthropic"
    is_free = False
    is_local = False
    cost_per_1m_input = 3.0
    cost_per_1m_output = 15.0

    _MODEL_PRIORITY = [
        "claude-sonnet-4-6",
        "claude-haiku-4-5-20251001",
        "claude-opus-4-8",
    ]

    def __init__(self, api_key: str = "", model: str = "") -> None:
        self.api_key = api_key or os.getenv("ANTHROPIC_API_KEY", "")
        self.default_model = model or self._MODEL_PRIORITY[0]
        self._base = "https://api.anthropic.com/v1"

    def is_available(self) -> bool:
        return bool(self.api_key)

    def chat(
        self,
        prompt: str,
        system: str = "",
        model: str = "",
        max_tokens: int = 4096,
        temperature: float = 0.3,
        **kwargs: Any,
    ) -> LLMResponse:
        if not self.api_key:
            raise RuntimeError("ANTHROPIC_API_KEY not set")

        m = model or self.default_model
        body: Dict[str, Any] = {
            "model": m,
            "max_tokens": max_tokens,
            "temperature": temperature,
            "messages": [{"role": "user", "content": prompt}],
        }
        if system:
            body["system"] = system

        t0 = time.monotonic()
        req = urllib.request.Request(
            f"{self._base}/messages",
            data=json.dumps(body).encode(),
            headers={
                "Content-Type": "application/json",
                "x-api-key": self.api_key,
                "anthropic-version": "2023-06-01",
            },
            method="POST",
        )
        try:
            with urllib.request.urlopen(req, timeout=120) as r:
                data = json.loads(r.read())
        except urllib.error.HTTPError as exc:
            body_err = exc.read().decode(errors="replace")
            raise RuntimeError(f"Anthropic API error {exc.code}: {body_err}") from exc

        latency = (time.monotonic() - t0) * 1000
        text = data["content"][0]["text"]
        usage = data.get("usage", {})
        cost = self.estimate_cost(
            usage.get("input_tokens", 0),
            usage.get("output_tokens", 0),
        )
        return LLMResponse(
            text=text,
            provider=self.name,
            model=m,
            input_tokens=usage.get("input_tokens", 0),
            output_tokens=usage.get("output_tokens", 0),
            latency_ms=latency,
            cost_usd=cost,
        )


class OpenAIProvider(LLMProvider):
    """OpenAI GPT API."""

    name = "openai"
    is_free = False
    is_local = False
    cost_per_1m_input = 2.5
    cost_per_1m_output = 10.0

    def __init__(self, api_key: str = "", model: str = "", base_url: str = "") -> None:
        self.api_key = api_key or os.getenv("OPENAI_API_KEY", "")
        self.default_model = model or "gpt-4o"
        self._base = (base_url or "https://api.openai.com/v1").rstrip("/")

    def is_available(self) -> bool:
        return bool(self.api_key)

    def chat(
        self,
        prompt: str,
        system: str = "",
        model: str = "",
        max_tokens: int = 4096,
        temperature: float = 0.3,
        **kwargs: Any,
    ) -> LLMResponse:
        if not self.api_key:
            raise RuntimeError("OPENAI_API_KEY not set")

        m = model or self.default_model
        messages = []
        if system:
            messages.append({"role": "system", "content": system})
        messages.append({"role": "user", "content": prompt})

        body = json.dumps({
            "model": m,
            "messages": messages,
            "max_tokens": max_tokens,
            "temperature": temperature,
        }).encode()

        t0 = time.monotonic()
        req = urllib.request.Request(
            f"{self._base}/chat/completions",
            data=body,
            headers={
                "Content-Type": "application/json",
                "Authorization": f"Bearer {self.api_key}",
            },
            method="POST",
        )
        try:
            with urllib.request.urlopen(req, timeout=90) as r:
                data = json.loads(r.read())
        except urllib.error.HTTPError as exc:
            body_err = exc.read().decode(errors="replace")
            raise RuntimeError(f"OpenAI API error {exc.code}: {body_err}") from exc

        latency = (time.monotonic() - t0) * 1000
        text = data["choices"][0]["message"]["content"]
        usage = data.get("usage", {})
        cost = self.estimate_cost(
            usage.get("prompt_tokens", 0),
            usage.get("completion_tokens", 0),
        )
        return LLMResponse(
            text=text,
            provider=self.name,
            model=m,
            input_tokens=usage.get("prompt_tokens", 0),
            output_tokens=usage.get("completion_tokens", 0),
            latency_ms=latency,
            cost_usd=cost,
        )


class GrokProvider(LLMProvider):
    """xAI Grok API."""

    name = "grok"
    is_free = False
    is_local = False
    cost_per_1m_input = 5.0
    cost_per_1m_output = 15.0

    def __init__(self, api_key: str = "", model: str = "") -> None:
        self.api_key = api_key or os.getenv("GROK_API_KEY", os.getenv("XAI_API_KEY", ""))
        self.default_model = model or "grok-beta"
        self._base = "https://api.x.ai/v1"

    def is_available(self) -> bool:
        return bool(self.api_key)

    def chat(
        self,
        prompt: str,
        system: str = "",
        model: str = "",
        max_tokens: int = 4096,
        temperature: float = 0.3,
        **kwargs: Any,
    ) -> LLMResponse:
        if not self.api_key:
            raise RuntimeError("GROK_API_KEY / XAI_API_KEY not set")

        m = model or self.default_model
        messages = []
        if system:
            messages.append({"role": "system", "content": system})
        messages.append({"role": "user", "content": prompt})

        body = json.dumps({
            "model": m,
            "messages": messages,
            "max_tokens": max_tokens,
            "temperature": temperature,
        }).encode()

        t0 = time.monotonic()
        req = urllib.request.Request(
            f"{self._base}/chat/completions",
            data=body,
            headers={
                "Content-Type": "application/json",
                "Authorization": f"Bearer {self.api_key}",
            },
            method="POST",
        )
        try:
            with urllib.request.urlopen(req, timeout=90) as r:
                data = json.loads(r.read())
        except urllib.error.HTTPError as exc:
            body_err = exc.read().decode(errors="replace")
            raise RuntimeError(f"Grok API error {exc.code}: {body_err}") from exc

        latency = (time.monotonic() - t0) * 1000
        text = data["choices"][0]["message"]["content"]
        usage = data.get("usage", {})
        return LLMResponse(
            text=text,
            provider=self.name,
            model=m,
            input_tokens=usage.get("prompt_tokens", 0),
            output_tokens=usage.get("completion_tokens", 0),
            latency_ms=latency,
        )



class BedrockProvider(LLMProvider):
    """
    Amazon Bedrock via boto3 Converse API.
    Credentials read from standard AWS chain:
      AWS_ACCESS_KEY_ID + AWS_SECRET_ACCESS_KEY env vars  (highest priority)
      ~/.aws/credentials                                   (fallback)
      IAM instance role                                    (EC2/ECS)
    Region: AWS_REGION or AWS_DEFAULT_REGION env var, then .env file fallback,
            defaulting to eu-central-1 (where inference profile is confirmed working).

    Model: eu.anthropic.claude-sonnet-4-6 (cross-region inference profile for eu-central-1).
    Override via BEDROCK_DEFAULT_MODEL env var or .env entry.
    """

    name = "bedrock"
    is_free = False
    is_local = False
    cost_per_1m_input  = 3.00   # Claude Sonnet pricing (USD)
    cost_per_1m_output = 15.00

    # Confirmed working inference profile for eu-central-1.
    # Override by setting BEDROCK_DEFAULT_MODEL in .env or environment.
    _DEFAULT_MODEL  = "eu.anthropic.claude-sonnet-4-6"
    _DEFAULT_REGION = "eu-central-1"   # fallback when AWS_REGION not in env

    def __init__(self) -> None:
        self.default_model = (
            os.environ.get("BEDROCK_DEFAULT_MODEL")
            or self._env_file_value("BEDROCK_DEFAULT_MODEL")
            or self._DEFAULT_MODEL
        )
        self._boto3_ok = False
        self._creds_ok: Optional[bool] = None  # cached
        try:
            import boto3  # noqa: F401
            self._boto3_ok = True
        except ImportError:
            log.debug("[bedrock] boto3 not installed — BedrockProvider unavailable")

    def _region(self) -> str:
        """
        Resolve the AWS region for Bedrock API calls.

        Priority:
          1. AWS_REGION environment variable
          2. AWS_DEFAULT_REGION environment variable
          3. AWS_REGION from .env file (handles nohup start without sourcing .env)
          4. Hard default: eu-central-1 (where eu.anthropic.* profiles live)
        """
        return (
            os.environ.get("AWS_REGION")
            or os.environ.get("AWS_DEFAULT_REGION")
            or self._env_file_value("AWS_REGION")
            or self._env_file_value("AWS_DEFAULT_REGION")
            or self._DEFAULT_REGION
        )

    @staticmethod
    def _env_file_value(key: str) -> str:
        """
        Read a single key from the .env file without loading the whole file.
        Used as a last-resort fallback when os.environ doesn't have the key
        (e.g. process started via nohup before .env was sourced).
        Returns empty string if not found — never raises.
        """
        try:
            env_path = Path(__file__).resolve().parent.parent.parent.parent / ".env"
            if env_path.exists():
                for line in env_path.read_text().splitlines():
                    line = line.strip()
                    if line and not line.startswith("#") and "=" in line:
                        k, _, v = line.partition("=")
                        if k.strip() == key:
                            return v.strip().strip('"').strip("'")
        except Exception:
            pass
        return ""


    def is_available(self) -> bool:
        if not self._boto3_ok:
            return False
        if self._creds_ok is not None:
            return self._creds_ok
        try:
            import boto3
            creds = boto3.Session().get_credentials()
            self._creds_ok = creds is not None and bool(creds.access_key)
        except Exception:
            self._creds_ok = False
        return self._creds_ok

    def chat(
        self,
        prompt: str,
        system: str = "",
        model: str = "",
        max_tokens: int = 4096,
        temperature: float = 0.3,
        **kwargs: Any,
    ) -> LLMResponse:
        import boto3
        t0 = time.monotonic()
        mid = model or self.default_model
        client = boto3.client("bedrock-runtime", region_name=self._region())
        messages = [{"role": "user", "content": [{"text": prompt}]}]
        sys_cfg  = [{"text": system}] if system else []
        try:
            resp = client.converse(
                modelId=mid,
                messages=messages,
                system=sys_cfg,
                inferenceConfig={
                    "maxTokens":   max_tokens,
                    "temperature": float(temperature),
                },
            )
            text    = resp["output"]["message"]["content"][0]["text"]
            usage   = resp.get("usage", {})
            in_tok  = usage.get("inputTokens",  0)
            out_tok = usage.get("outputTokens", 0)
            latency = (time.monotonic() - t0) * 1000
            return LLMResponse(
                text=text,
                provider=self.name,
                model=mid,
                input_tokens=in_tok,
                output_tokens=out_tok,
                cost_usd=self.estimate_cost(in_tok, out_tok),
                latency_ms=latency,
            )
        except Exception as exc:
            latency = (time.monotonic() - t0) * 1000
            log.error("[BedrockProvider] chat failed (model=%s): %s", mid, exc)
            return LLMResponse(
                text="",
                provider=self.name,
                model=mid,
                input_tokens=0,
                output_tokens=0,
                latency_ms=latency,
            )

# ---------------------------------------------------------------------------
# Task-to-model routing hints
# ---------------------------------------------------------------------------

_TASK_ROUTING: Dict[str, Tuple[str, str]] = {
    # ── Standard task types ───────────────────────────────────────────────
    "analysis":   ("bedrock", "eu.anthropic.claude-sonnet-4-6"),
    "report":     ("bedrock", "eu.anthropic.claude-sonnet-4-6"),
    "exploit":    ("bedrock", "eu.anthropic.claude-sonnet-4-6"),
    "code":       ("bedrock", "eu.anthropic.claude-sonnet-4-6"),
    "triage":     ("bedrock", "eu.anthropic.claude-sonnet-4-6"),
    "chain":      ("bedrock", "eu.anthropic.claude-sonnet-4-6"),
    "recon":      ("bedrock", "eu.anthropic.claude-sonnet-4-6"),
    "validation": ("bedrock", "eu.anthropic.claude-sonnet-4-6"),
    # ── Phase 0: Verified Finding Architecture ────────────────────────────
    # Judge uses the same provider but is a semantically distinct task type.
    # Routed to the conservative/analytical model (not the attack model) so
    # the judge's confidence is independent from the scan agent's.
    "judge":      ("bedrock", "eu.anthropic.claude-sonnet-4-6"),
}

# ---------------------------------------------------------------------------
# Factory
# ---------------------------------------------------------------------------

class LLMProviderFactory:
    """
    Detects available providers, enforces priority ordering, and routes
    tasks to the optimal provider by cost and capability.

    Priority: Ollama > Groq > DeepSeek > Anthropic > OpenAI > Grok
    """

    _PROVIDER_CLASSES = [
        OllamaProvider,
        BedrockProvider,    # AWS Bedrock — high-capability, available when creds set
        GroqProvider,
        DeepSeekProvider,
        AnthropicProvider,
        OpenAIProvider,
        GrokProvider,
    ]

    def __init__(self, free_tier_only: bool = False) -> None:
        self.free_tier_only = free_tier_only
        self._providers: List[LLMProvider] = self._build_providers()
        self._health_cache: Dict[str, ProviderHealth] = {}

    def _build_providers(self) -> List[LLMProvider]:
        providers = []
        for cls in self._PROVIDER_CLASSES:
            try:
                p = cls()  # type: ignore[call-arg]
                if self.free_tier_only and not p.is_free:
                    continue
                providers.append(p)
            except Exception as exc:
                log.debug("Failed to instantiate %s: %s", cls.__name__, exc)
        return providers

    def auto_detect(self) -> LLMProvider:
        """Return the highest-priority available provider."""
        for p in self._providers:
            try:
                if p.is_available():
                    log.info("Auto-detected LLM provider: %s", p.name)
                    return p
            except Exception as exc:
                log.debug("Provider %s unavailable: %s", p.name, exc)
        raise RuntimeError(
            "No LLM provider available. Install Ollama locally or set one of: "
            "GROQ_API_KEY, DEEPSEEK_API_KEY, ANTHROPIC_API_KEY, OPENAI_API_KEY"
        )

    def available_providers(self) -> List[LLMProvider]:
        """Return all reachable providers, in priority order."""
        result = []
        for p in self._providers:
            try:
                if p.is_available():
                    result.append(p)
            except Exception:
                pass
        return result

    def route(self, task_type: str) -> LLMProvider:
        """
        Return best provider for the given task type.
        Falls back down the priority list when preferred provider unavailable.
        """
        available = {p.name: p for p in self.available_providers()}
        if not available:
            raise RuntimeError("No LLM providers available")

        pref_name, _ = _TASK_ROUTING.get(task_type, ("", ""))
        if pref_name and pref_name in available:
            log.debug("Routing task '%s' → %s", task_type, pref_name)
            return available[pref_name]

        # Fall back to first available in priority order
        for p in self._providers:
            if p.name in available:
                return available[p.name]

        raise RuntimeError("No LLM providers available")

    def cost_aware_route(self, task_type: str, budget_usd: float = 0.01) -> LLMProvider:
        """
        Return best provider that fits within per-call budget estimate.
        Routes to free providers first; paid providers only when free are unavailable.
        """
        available = self.available_providers()

        # 1. Prefer free providers for any task
        for p in available:
            if p.is_free:
                return p

        # 2. Find cheapest paid option within budget
        candidates = sorted(available, key=lambda p: p.cost_per_1m_input)
        for p in candidates:
            # rough estimate: 2K input + 1K output tokens
            est = p.estimate_cost(2000, 1000)
            if est <= budget_usd:
                return p

        return available[0] if available else self.route(task_type)

    def health_report(self) -> List[ProviderHealth]:
        return [p.health_check() for p in self._providers]

    def print_status(self) -> None:
        print("\n  LLM Provider Status")
        print("  " + "─" * 52)
        for p in self._providers:
            h = p.health_check()
            icon = "✓" if h.available else "✗"
            tier = "free " if p.is_free else "paid "
            local = "local " if p.is_local else "cloud "
            lat = f"{h.latency_ms:.0f}ms" if h.available else h.error[:30]
            print(f"  [{icon}] {p.name:<12} {tier}{local} {lat}")
        print()


# ---------------------------------------------------------------------------
# Multi-model racing (T-012)
# ---------------------------------------------------------------------------

class LLMProviderRace:
    """
    Submit the same prompt to N providers concurrently; return the first
    valid response. Cancels remaining tasks on first success.

    Usage::
        factory = LLMProviderFactory()
        racer = LLMProviderRace(factory.available_providers()[:3])
        response = await racer.race("Analyse this endpoint.")
    """

    def __init__(self, providers: List[LLMProvider], timeout: float = 30.0) -> None:
        if not providers:
            raise ValueError("At least one provider required")
        self.providers = providers
        self.timeout = timeout

    async def race(
        self,
        prompt: str,
        system: str = "",
        model: str = "",
        max_tokens: int = 2048,
        temperature: float = 0.3,
    ) -> LLMResponse:
        """Return first non-empty response from any provider."""
        tasks = [
            asyncio.ensure_future(
                p.chat_async(prompt, system, model, max_tokens, temperature)
            )
            for p in self.providers
        ]

        try:
            done, pending = await asyncio.wait(
                tasks,
                timeout=self.timeout,
                return_when=asyncio.FIRST_COMPLETED,
            )
        except Exception:
            for t in tasks:
                t.cancel()
            raise

        for t in pending:
            t.cancel()

        for t in done:
            try:
                result = t.result()
                if result:
                    return result
            except Exception as exc:
                log.debug("Race task failed: %s", exc)

        raise TimeoutError(
            f"All {len(self.providers)} providers failed or timed out in {self.timeout}s"
        )

    def race_sync(self, prompt: str, **kwargs: Any) -> LLMResponse:
        """Synchronous wrapper around race() for non-async callers."""
        import concurrent.futures as _cf
        try:
            loop = asyncio.get_running_loop()
            # Inside a running event loop — offload to a thread to avoid re-entrancy
            with _cf.ThreadPoolExecutor(max_workers=1) as ex:
                fut = ex.submit(asyncio.run, self.race(prompt, **kwargs))
                return fut.result(timeout=self.timeout + 5)
        except RuntimeError:
            # No running loop — safe to use asyncio.run()
            return asyncio.run(self.race(prompt, **kwargs))


# ---------------------------------------------------------------------------
# Module-level singleton factory
# ---------------------------------------------------------------------------

_factory: Optional[LLMProviderFactory] = None


def get_factory(free_tier_only: bool = False) -> LLMProviderFactory:
    """Return a module-level LLMProviderFactory (created once).
    Respects the ONEINFINITY_FREE_TIER env var set by --free-tier CLI flag."""
    global _factory
    env_free = os.getenv("ONEINFINITY_FREE_TIER", "0") not in ("0", "", "false", "False")
    effective_free = free_tier_only or env_free
    if _factory is None or _factory.free_tier_only != effective_free:
        _factory = LLMProviderFactory(free_tier_only=effective_free)
    return _factory


def get_provider(task_type: str = "analysis", free_tier_only: bool = False) -> LLMProvider:
    """Convenience: return the best provider for a task type."""
    return get_factory(free_tier_only).route(task_type)


def chat(
    prompt: str,
    system: str = "",
    task_type: str = "analysis",
    free_tier_only: bool = False,
    **kwargs: Any,
) -> LLMResponse:
    """One-shot chat using auto-routed provider."""
    provider = get_provider(task_type, free_tier_only)
    response = provider.chat(prompt, system=system, **kwargs)
    # Report cost to budget manager (non-fatal)
    if response.cost_usd > 0:
        try:
            from oneinfinity.infra.model_budget_manager import get_budget_manager
            get_budget_manager().record_usage(
                model_id=response.model,
                provider=response.provider,
                input_tokens=response.input_tokens,
                output_tokens=response.output_tokens,
                cost_usd=response.cost_usd,
            )
        except Exception:
            pass
    return response
