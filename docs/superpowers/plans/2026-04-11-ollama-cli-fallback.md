# Ollama + CLI Fallback Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add Ollama local LLM support and CLI fallback (Codex + Claude Code) to the AI Orchestrator, with auto-discovery and per-provider-failure fallback.

**Architecture:** New `backends/` package holds `OllamaBackend`, `CodexCliBackend`, `ClaudeCliBackend` — all implementing `BaseBackend`. `model_orchestrator.py` gets four surgical additions: `ModelConfig.fallback_provider` field, provider routing extension in `_call_with_retry()`, three startup discovery methods, and a CLI fallback clause on auth/quota errors.

**Tech Stack:** Python stdlib only (`urllib`, `subprocess`, `shutil`), PyYAML (already in pyproject.toml), existing psycopg3 pool.

**Spec:** `docs/superpowers/specs/2026-04-11-ollama-cli-fallback-design.md`

---

## File Map

| Action | Path | Responsibility |
|--------|------|---------------|
| Create | `src/oneinfinity/orchestration/backends/__init__.py` | `BaseBackend` ABC, `BackendResult`, global registry |
| Create | `src/oneinfinity/orchestration/backends/ollama.py` | `OllamaBackend` + `discover_models()` |
| Create | `src/oneinfinity/orchestration/backends/cli.py` | `CodexCliBackend`, `ClaudeCliBackend` |
| Create | `tests/orchestration/test_backends_registry.py` | Registry unit tests |
| Create | `tests/orchestration/test_ollama_backend.py` | Ollama backend unit tests |
| Create | `tests/orchestration/test_cli_backends.py` | CLI backend unit tests |
| Create | `tests/orchestration/test_orchestrator_extensions.py` | Integration tests for new orchestrator methods |
| Modify | `src/oneinfinity/orchestration/model_orchestrator.py` | 4 additions (field, routing, discovery, fallback) |
| Modify | `config/models.yaml` | New `ollama:`, `cli_fallback:` sections + example models |

---

## Task 1: `backends/__init__.py` — Base class + registry

**Files:**
- Create: `src/oneinfinity/orchestration/backends/__init__.py`
- Create: `tests/orchestration/test_backends_registry.py`

- [ ] **Step 1: Create the test file**

```python
# tests/orchestration/test_backends_registry.py
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
```

- [ ] **Step 2: Run tests — verify they fail**

```bash
cd /home/devendra-yadav/oneinfinity
python -m pytest tests/orchestration/test_backends_registry.py -v 2>&1 | head -20
```

Expected: `ModuleNotFoundError: No module named 'oneinfinity.orchestration.backends'`

- [ ] **Step 3: Create the backends package**

```python
# src/oneinfinity/orchestration/backends/__init__.py
"""
orchestration/backends — Pluggable AI provider backend registry.

Provides:
  BaseBackend     — abstract base class all backends implement
  BackendResult   — unified result container
  register_backend / get_backend / list_backends — module-level registry
"""
from __future__ import annotations

import logging
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from typing import Optional

log = logging.getLogger(__name__)


@dataclass
class BackendResult:
    """Unified result from any backend call."""
    content: str
    input_tokens: int
    output_tokens: int
    duration_ms: float
    error: str = ""

    @property
    def failed(self) -> bool:
        return bool(self.error)


class BaseBackend(ABC):
    """Abstract base for all AI provider backends."""

    #: Provider identifier — matches ModelConfig.provider values
    provider: str = ""

    @abstractmethod
    def is_available(self) -> bool:
        """Return True if this backend can be used right now."""
        ...

    @abstractmethod
    def call(
        self,
        model_id: str,
        prompt: str,
        system: str,
        temperature: float,
        max_tokens: int,
    ) -> BackendResult:
        """Execute a prompt and return a BackendResult. Never raises — errors go in result.error."""
        ...


# ── Global registry ──────────────────────────────────────────────────────────

_BACKENDS: dict[str, "BaseBackend"] = {}


def register_backend(backend: BaseBackend) -> None:
    """Register a backend instance under its provider name. Idempotent."""
    _BACKENDS[backend.provider] = backend
    log.debug("Backend registered: %s", backend.provider)


def get_backend(provider: str) -> Optional[BaseBackend]:
    """Return the registered backend for the given provider, or None."""
    return _BACKENDS.get(provider)


def list_backends() -> list[str]:
    """Return all registered provider names."""
    return list(_BACKENDS.keys())
```

- [ ] **Step 4: Run tests — verify they pass**

```bash
cd /home/devendra-yadav/oneinfinity
python -m pytest tests/orchestration/test_backends_registry.py -v
```

Expected: 5 tests pass.

- [ ] **Step 5: Commit**

```bash
cd /home/devendra-yadav/oneinfinity
git add src/oneinfinity/orchestration/backends/__init__.py tests/orchestration/test_backends_registry.py
git commit -m "feat(orchestration): add backends package with BaseBackend registry"
```

---

## Task 2: `backends/ollama.py` — Ollama backend

**Files:**
- Create: `src/oneinfinity/orchestration/backends/ollama.py`
- Create: `tests/orchestration/test_ollama_backend.py`

- [ ] **Step 1: Create the test file**

```python
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
    import oneinfinity.orchestration.backends.ollama  # noqa: F401
    from oneinfinity.orchestration.backends import get_backend
    assert get_backend("ollama") is not None
```

- [ ] **Step 2: Run tests — verify they fail**

```bash
cd /home/devendra-yadav/oneinfinity
python -m pytest tests/orchestration/test_ollama_backend.py -v 2>&1 | head -20
```

Expected: `ModuleNotFoundError: No module named 'oneinfinity.orchestration.backends.ollama'`

- [ ] **Step 3: Create `backends/ollama.py`**

```python
# src/oneinfinity/orchestration/backends/ollama.py
"""
orchestration/backends/ollama.py — Ollama local LLM backend.

Uses Ollama's OpenAI-compatible endpoint:
  POST {host}/v1/chat/completions

Environment:
  OLLAMA_HOST — override default http://localhost:11434 (global)

Per-model override: pass host= to call() or discover_models().
"""
from __future__ import annotations

import json
import logging
import os
import time
import urllib.error
import urllib.request
from dataclasses import dataclass
from typing import Optional

from oneinfinity.orchestration.backends import BackendResult, BaseBackend, register_backend

log = logging.getLogger(__name__)

_DEFAULT_HOST = "http://localhost:11434"


def _get_host(per_model_host: Optional[str] = None) -> str:
    return (
        per_model_host
        or os.environ.get("OLLAMA_HOST", "").strip()
        or _DEFAULT_HOST
    ).rstrip("/")


def _infer_tier(name: str) -> str:
    """Heuristic tier assignment based on parameter count in model name."""
    lower = name.lower()
    is_reasoning = any(k in lower for k in ("deepseek-r1", "qwq", ":think"))

    if any(k in lower for k in ("70b", "72b", "65b", "671b")):
        tier = "PREMIUM"
    elif any(k in lower for k in ("27b", "32b", "34b", "13b", "14b")):
        tier = "STANDARD"
    else:
        tier = "FAST"

    if is_reasoning:
        if tier == "FAST":
            tier = "STANDARD"
        elif tier == "STANDARD":
            tier = "PREMIUM"

    return tier


@dataclass
class DiscoveredModel:
    name: str
    tier: str          # "FAST" | "STANDARD" | "PREMIUM"
    context_tokens: int = 8192


class OllamaBackend(BaseBackend):
    provider = "ollama"

    def __init__(self, host: Optional[str] = None, timeout: int = 60):
        self._host = host
        self._timeout = timeout

    def _effective_host(self, per_model_host: Optional[str] = None) -> str:
        return _get_host(per_model_host or self._host)

    def is_available(self, host: Optional[str] = None) -> bool:
        try:
            urllib.request.urlopen(self._effective_host(host) + "/", timeout=2)
            return True
        except Exception:
            return False

    def call(
        self,
        model_id: str,
        prompt: str,
        system: str,
        temperature: float,
        max_tokens: int,
        host: Optional[str] = None,
    ) -> BackendResult:
        effective_host = self._effective_host(host)
        url = f"{effective_host}/v1/chat/completions"

        messages = []
        if system:
            messages.append({"role": "system", "content": system})
        messages.append({"role": "user", "content": prompt})

        payload = json.dumps({
            "model": model_id,
            "messages": messages,
            "temperature": temperature,
            "max_tokens": max_tokens,
            "stream": False,
        }).encode()

        req = urllib.request.Request(
            url,
            data=payload,
            headers={"Content-Type": "application/json"},
            method="POST",
        )
        t0 = time.monotonic()
        try:
            with urllib.request.urlopen(req, timeout=self._timeout) as resp:
                data = json.loads(resp.read())
        except urllib.error.HTTPError as e:
            body = e.read().decode(errors="replace")
            return BackendResult(
                content="", input_tokens=0, output_tokens=0,
                duration_ms=(time.monotonic() - t0) * 1000,
                error=f"HTTP {e.code}: {body[:200]}",
            )
        except Exception as e:
            return BackendResult(
                content="", input_tokens=0, output_tokens=0,
                duration_ms=(time.monotonic() - t0) * 1000,
                error=str(e),
            )

        duration_ms = (time.monotonic() - t0) * 1000
        content = data["choices"][0]["message"]["content"]
        usage = data.get("usage", {})
        return BackendResult(
            content=content,
            input_tokens=usage.get("prompt_tokens", 0),
            output_tokens=usage.get("completion_tokens", 0),
            duration_ms=duration_ms,
        )

    def discover_models(self, host: Optional[str] = None) -> list[DiscoveredModel]:
        """Query /api/tags and return discovered models with tier heuristics."""
        url = self._effective_host(host) + "/api/tags"
        try:
            with urllib.request.urlopen(url, timeout=2) as resp:
                data = json.loads(resp.read())
        except Exception as e:
            log.debug("Ollama discovery failed (%s): %s", url, e)
            return []

        results = []
        for model in data.get("models", []):
            name = model.get("name", "").strip()
            if not name:
                continue
            results.append(DiscoveredModel(
                name=name,
                tier=_infer_tier(name),
                context_tokens=8192,  # conservative default; override in models.yaml
            ))
        return results


# Register singleton at import time so orchestrator can find it by provider name
register_backend(OllamaBackend())
```

- [ ] **Step 4: Run tests — verify they pass**

```bash
cd /home/devendra-yadav/oneinfinity
python -m pytest tests/orchestration/test_ollama_backend.py -v
```

Expected: all 13 tests pass.

- [ ] **Step 5: Commit**

```bash
cd /home/devendra-yadav/oneinfinity
git add src/oneinfinity/orchestration/backends/ollama.py tests/orchestration/test_ollama_backend.py
git commit -m "feat(orchestration): add OllamaBackend with auto-discovery and tier heuristics"
```

---

## Task 3: `backends/cli.py` — Codex + Claude CLI backends

**Files:**
- Create: `src/oneinfinity/orchestration/backends/cli.py`
- Create: `tests/orchestration/test_cli_backends.py`

- [ ] **Step 1: Create the test file**

```python
# tests/orchestration/test_cli_backends.py
"""Tests for CodexCliBackend and ClaudeCliBackend."""
import os
import subprocess
from unittest.mock import patch, MagicMock

import pytest


def _proc(returncode=0, stdout="output text", stderr=""):
    return subprocess.CompletedProcess([], returncode, stdout=stdout, stderr=stderr)


# ── _estimate_tokens ─────────────────────────────────────────────────────────

def test_estimate_tokens_minimum_one():
    from oneinfinity.orchestration.backends.cli import _estimate_tokens
    assert _estimate_tokens("") == 1


def test_estimate_tokens_approximation():
    from oneinfinity.orchestration.backends.cli import _estimate_tokens
    assert _estimate_tokens("hello world") == max(1, len("hello world") // 4)


# ── CodexCliBackend.is_available ─────────────────────────────────────────────

def test_codex_available_when_binary_found():
    from oneinfinity.orchestration.backends.cli import CodexCliBackend
    with patch("shutil.which", return_value="/usr/bin/codex"):
        assert CodexCliBackend().is_available() is True


def test_codex_unavailable_when_binary_missing():
    from oneinfinity.orchestration.backends.cli import CodexCliBackend
    with patch("shutil.which", return_value=None):
        assert CodexCliBackend().is_available() is False


# ── CodexCliBackend.call ─────────────────────────────────────────────────────

def test_codex_call_reads_output_file(tmp_path):
    from oneinfinity.orchestration.backends.cli import CodexCliBackend
    expected_content = "vulnerability analysis result"

    def fake_run(cmd, **kwargs):
        # codex writes to the -o flag path
        o_idx = cmd.index("-o")
        open(cmd[o_idx + 1], "w").write(expected_content)
        return _proc(0, stdout="", stderr="")

    with patch("subprocess.run", side_effect=fake_run):
        result = CodexCliBackend().call("o4-mini", "test prompt", "system", 0.2, 512)

    assert result.content == expected_content
    assert not result.failed
    assert result.input_tokens >= 1


def test_codex_call_returns_failed_on_nonzero_exit():
    from oneinfinity.orchestration.backends.cli import CodexCliBackend
    with patch("subprocess.run", return_value=_proc(1, stdout="", stderr="auth error")):
        result = CodexCliBackend().call("o4-mini", "test", "", 0.2, 512)
    assert result.failed
    assert "exit 1" in result.error


def test_codex_call_returns_failed_on_timeout():
    from oneinfinity.orchestration.backends.cli import CodexCliBackend
    with patch("subprocess.run", side_effect=subprocess.TimeoutExpired([], 120)):
        result = CodexCliBackend().call("o4-mini", "test", "", 0.2, 512)
    assert result.failed
    assert "timed out" in result.error


def test_codex_call_passes_model_arg():
    from oneinfinity.orchestration.backends.cli import CodexCliBackend

    def fake_run(cmd, **kwargs):
        o_idx = cmd.index("-o")
        open(cmd[o_idx + 1], "w").write("ok")
        return _proc()

    with patch("subprocess.run", side_effect=fake_run) as mock_run:
        CodexCliBackend().call("o3-mini", "prompt", "", 0.2, 512)
        cmd = mock_run.call_args[0][0]

    assert "-m" in cmd
    assert "o3-mini" in cmd


# ── ClaudeCliBackend.is_available ────────────────────────────────────────────

def test_claude_available_when_binary_found():
    from oneinfinity.orchestration.backends.cli import ClaudeCliBackend
    with patch("shutil.which", return_value="/usr/local/bin/claude"):
        assert ClaudeCliBackend().is_available() is True


def test_claude_unavailable_when_binary_missing():
    from oneinfinity.orchestration.backends.cli import ClaudeCliBackend
    with patch("shutil.which", return_value=None):
        assert ClaudeCliBackend().is_available() is False


# ── ClaudeCliBackend.call ─────────────────────────────────────────────────────

def test_claude_call_returns_stripped_stdout():
    from oneinfinity.orchestration.backends.cli import ClaudeCliBackend
    with patch("subprocess.run", return_value=_proc(0, stdout="  analysis result  ")):
        result = ClaudeCliBackend().call("claude-opus-4-6", "prompt", "system", 0.3, 512)
    assert result.content == "analysis result"
    assert not result.failed


def test_claude_call_returns_failed_on_nonzero_exit():
    from oneinfinity.orchestration.backends.cli import ClaudeCliBackend
    with patch("subprocess.run", return_value=_proc(1, stdout="", stderr="budget exceeded")):
        result = ClaudeCliBackend().call("claude-opus-4-6", "test", "", 0.3, 512)
    assert result.failed
    assert "exit 1" in result.error


def test_claude_call_returns_failed_on_timeout():
    from oneinfinity.orchestration.backends.cli import ClaudeCliBackend
    with patch("subprocess.run", side_effect=subprocess.TimeoutExpired([], 120)):
        result = ClaudeCliBackend().call("claude-opus-4-6", "test", "", 0.3, 512)
    assert result.failed
    assert "timed out" in result.error


def test_claude_call_passes_model_and_budget():
    from oneinfinity.orchestration.backends.cli import ClaudeCliBackend
    with patch("subprocess.run", return_value=_proc()) as mock_run:
        ClaudeCliBackend(max_budget_usd=0.05).call("claude-sonnet-4-6", "p", "", 0.2, 512)
        cmd = mock_run.call_args[0][0]
    assert "--model" in cmd
    idx_model = cmd.index("--model")
    assert cmd[idx_model + 1] == "claude-sonnet-4-6"
    assert "--max-budget-usd" in cmd
    idx_budget = cmd.index("--max-budget-usd")
    assert cmd[idx_budget + 1] == "0.05"


def test_cli_backends_registered_at_import():
    import oneinfinity.orchestration.backends.cli  # noqa: F401
    from oneinfinity.orchestration.backends import get_backend
    assert get_backend("codex") is not None
    assert get_backend("claude-cli") is not None
```

- [ ] **Step 2: Run tests — verify they fail**

```bash
cd /home/devendra-yadav/oneinfinity
python -m pytest tests/orchestration/test_cli_backends.py -v 2>&1 | head -20
```

Expected: `ModuleNotFoundError: No module named 'oneinfinity.orchestration.backends.cli'`

- [ ] **Step 3: Create `backends/cli.py`**

```python
# src/oneinfinity/orchestration/backends/cli.py
"""
orchestration/backends/cli.py — CLI-based AI backends.

CodexCliBackend  — OpenAI Codex CLI  (`codex exec`)
ClaudeCliBackend — Claude Code CLI   (`claude -p`)

Both record cost=0.0 locally; billed through user's own accounts.
"""
from __future__ import annotations

import logging
import os
import shutil
import subprocess
import tempfile
import time
from typing import Optional

from oneinfinity.orchestration.backends import BackendResult, BaseBackend, register_backend

log = logging.getLogger(__name__)


def _estimate_tokens(text: str) -> int:
    """Rough token estimate: ~4 chars per token, minimum 1."""
    return max(1, len(text) // 4)


class CodexCliBackend(BaseBackend):
    """OpenAI Codex CLI backend. Uses `codex exec` for non-interactive execution."""

    provider = "codex"

    def __init__(self, model: str = "o4-mini"):
        self._model = model

    def is_available(self) -> bool:
        return shutil.which("codex") is not None

    def call(
        self,
        model_id: str,
        prompt: str,
        system: str,
        temperature: float,
        max_tokens: int,
    ) -> BackendResult:
        full_prompt = f"{system}\n\n{prompt}" if system else prompt
        effective_model = model_id or self._model
        t0 = time.monotonic()

        with tempfile.NamedTemporaryFile(suffix=".txt", delete=False) as tmp:
            tmp_path = tmp.name

        try:
            result = subprocess.run(
                [
                    "codex", "exec",
                    "-m", effective_model,
                    "--full-auto",
                    "--dangerously-bypass-approvals-and-sandbox",
                    "-o", tmp_path,
                    full_prompt,
                ],
                capture_output=True,
                text=True,
                timeout=120,
            )
            duration_ms = (time.monotonic() - t0) * 1000

            if result.returncode != 0:
                return BackendResult(
                    content="", input_tokens=0, output_tokens=0,
                    duration_ms=duration_ms,
                    error=f"codex exit {result.returncode}: {result.stderr[:300]}",
                )

            content = ""
            if os.path.exists(tmp_path):
                content = open(tmp_path).read().strip()
            if not content:
                content = result.stdout.strip()

        except subprocess.TimeoutExpired:
            return BackendResult(
                content="", input_tokens=0, output_tokens=0,
                duration_ms=(time.monotonic() - t0) * 1000,
                error="codex CLI timed out after 120s",
            )
        except FileNotFoundError:
            return BackendResult(
                content="", input_tokens=0, output_tokens=0,
                duration_ms=(time.monotonic() - t0) * 1000,
                error="codex binary not found",
            )
        finally:
            if os.path.exists(tmp_path):
                os.unlink(tmp_path)

        return BackendResult(
            content=content,
            input_tokens=_estimate_tokens(full_prompt),
            output_tokens=_estimate_tokens(content),
            duration_ms=duration_ms,
        )


class ClaudeCliBackend(BaseBackend):
    """Claude Code CLI backend. Uses `claude -p` for non-interactive execution."""

    provider = "claude-cli"

    def __init__(self, model: str = "claude-opus-4-6", max_budget_usd: float = 0.10):
        self._model = model
        self._max_budget = max_budget_usd

    def is_available(self) -> bool:
        return shutil.which("claude") is not None

    def call(
        self,
        model_id: str,
        prompt: str,
        system: str,
        temperature: float,
        max_tokens: int,
    ) -> BackendResult:
        full_prompt = f"{system}\n\n{prompt}" if system else prompt
        effective_model = model_id or self._model
        t0 = time.monotonic()
        try:
            result = subprocess.run(
                [
                    "claude", "-p", full_prompt,
                    "--model", effective_model,
                    "--allowed-tools", "",
                    "--max-budget-usd", str(self._max_budget),
                    "--output-format", "text",
                ],
                capture_output=True,
                text=True,
                timeout=120,
            )
            duration_ms = (time.monotonic() - t0) * 1000

            if result.returncode != 0:
                return BackendResult(
                    content="", input_tokens=0, output_tokens=0,
                    duration_ms=duration_ms,
                    error=f"claude exit {result.returncode}: {result.stderr[:300]}",
                )

            content = result.stdout.strip()

        except subprocess.TimeoutExpired:
            return BackendResult(
                content="", input_tokens=0, output_tokens=0,
                duration_ms=(time.monotonic() - t0) * 1000,
                error="claude CLI timed out after 120s",
            )
        except FileNotFoundError:
            return BackendResult(
                content="", input_tokens=0, output_tokens=0,
                duration_ms=(time.monotonic() - t0) * 1000,
                error="claude binary not found",
            )

        return BackendResult(
            content=content,
            input_tokens=_estimate_tokens(full_prompt),
            output_tokens=_estimate_tokens(content),
            duration_ms=duration_ms,
        )


# Register singletons at import time
register_backend(CodexCliBackend())
register_backend(ClaudeCliBackend())
```

- [ ] **Step 4: Run tests — verify they pass**

```bash
cd /home/devendra-yadav/oneinfinity
python -m pytest tests/orchestration/test_cli_backends.py -v
```

Expected: all 14 tests pass.

- [ ] **Step 5: Commit**

```bash
cd /home/devendra-yadav/oneinfinity
git add src/oneinfinity/orchestration/backends/cli.py tests/orchestration/test_cli_backends.py
git commit -m "feat(orchestration): add CodexCliBackend and ClaudeCliBackend"
```

---

## Task 4: `model_orchestrator.py` — `ModelConfig.fallback_provider` + new provider routing

**Files:**
- Modify: `src/oneinfinity/orchestration/model_orchestrator.py` (lines 64–91, 883–887)
- Create: `tests/orchestration/test_orchestrator_extensions.py`

- [ ] **Step 1: Write failing tests**

```python
# tests/orchestration/test_orchestrator_extensions.py
"""Tests for new orchestrator extensions: Ollama routing, CLI fallback, discovery."""
import os
from unittest.mock import patch, MagicMock

import pytest


def _make_orchestrator():
    """Return a fresh ModelOrchestrator with no models loaded."""
    from oneinfinity.orchestration.model_orchestrator import ModelOrchestrator
    orch = ModelOrchestrator.__new__(ModelOrchestrator)
    import threading, collections
    from oneinfinity.infra.model_budget_manager import get_budget_manager
    orch._models = {}
    orch._lock = threading.Lock()
    orch._history = collections.deque(maxlen=500)
    orch._loaded = False
    orch._budget = get_budget_manager()
    from oneinfinity.orchestration.model_orchestrator import RoutingPolicy
    orch._policy = RoutingPolicy()
    return orch


# ── ModelConfig.fallback_provider field ──────────────────────────────────────

def test_modelconfig_has_fallback_provider_field():
    from oneinfinity.orchestration.model_orchestrator import ModelConfig, ModelTier
    cfg = ModelConfig(
        model_id="gpt-4o-mini", provider="openai",
        tier=ModelTier.FAST, cost_per_1k_input=0.0001,
        cost_per_1k_output=0.0004, max_context_tokens=128000,
        latency_class="INTERACTIVE", capabilities={"GENERAL"},
    )
    assert cfg.fallback_provider is None   # default


def test_modelconfig_fallback_provider_can_be_set():
    from oneinfinity.orchestration.model_orchestrator import ModelConfig, ModelTier
    cfg = ModelConfig(
        model_id="gpt-4o-mini", provider="openai",
        tier=ModelTier.FAST, cost_per_1k_input=0.0001,
        cost_per_1k_output=0.0004, max_context_tokens=128000,
        latency_class="INTERACTIVE", capabilities={"GENERAL"},
        fallback_provider="codex",
    )
    assert cfg.fallback_provider == "codex"


# ── Ollama provider routing ───────────────────────────────────────────────────

def test_call_with_retry_routes_ollama_to_ollama_backend():
    from oneinfinity.orchestration.model_orchestrator import ModelConfig, ModelTier
    from oneinfinity.orchestration.backends import get_backend
    from oneinfinity.orchestration.backends.ollama import BackendResult

    cfg = ModelConfig(
        model_id="llama3.2:3b", provider="ollama",
        tier=ModelTier.FAST, cost_per_1k_input=0.0,
        cost_per_1k_output=0.0, max_context_tokens=8192,
        latency_class="INTERACTIVE", capabilities={"GENERAL"},
    )

    mock_result = BackendResult(content="ollama response", input_tokens=10, output_tokens=5, duration_ms=100.0)
    orch = _make_orchestrator()

    with patch.object(get_backend("ollama"), "call", return_value=mock_result) as mock_call:
        from oneinfinity.orchestration.model_orchestrator import TaskClassification, TaskCategory, ComplexityLevel, ImportanceLevel
        classification = TaskClassification(
            category=TaskCategory.GENERAL, complexity=ComplexityLevel.LOW,
            importance=ImportanceLevel.NORMAL, latency_class="INTERACTIVE",
            estimated_tokens=100, reasoning_depth=1, tags=[], classifier_confidence=0.8,
        )
        output = orch._call_with_retry({}, classification, cfg, "test-task-id")

    assert mock_call.called
    assert output is not None
    assert output.content == "ollama response"
```

- [ ] **Step 2: Run tests — verify they fail**

```bash
cd /home/devendra-yadav/oneinfinity
python -m pytest tests/orchestration/test_orchestrator_extensions.py::test_modelconfig_has_fallback_provider_field -v 2>&1 | tail -10
```

Expected: `AttributeError` — `ModelConfig` has no `fallback_provider` field.

- [ ] **Step 3: Add `fallback_provider` to `ModelConfig` (line 75 in model_orchestrator.py)**

Open `src/oneinfinity/orchestration/model_orchestrator.py`. Find `ModelConfig` (line 64). Add one field after `extra`:

```python
    enabled:             bool = True
    api_base:            str  = ""        # override endpoint
    extra:               dict = field(default_factory=dict)
    fallback_provider:   Optional[str] = None   # "codex" | "claude-cli" — tried on auth/quota failure
```

- [ ] **Step 4: Import new backends package in `model_orchestrator.py`**

Near the top of `model_orchestrator.py` (after existing imports, before `_build_backends`), add:

```python
# Import new backends — registers OllamaBackend, CodexCliBackend, ClaudeCliBackend
import oneinfinity.orchestration.backends.ollama  # noqa: F401
import oneinfinity.orchestration.backends.cli     # noqa: F401
import oneinfinity.orchestration.backends as _new_backends
```

- [ ] **Step 5: Extend `_call_with_retry()` to route new providers**

In `_call_with_retry()` around line 883, the code currently reads:
```python
        backend = _BACKENDS.get(model_cfg.provider)

        if backend is None:
            log.error("No backend registered for provider '%s'", model_cfg.provider)
            return None
```

Replace with:
```python
        # Try new pluggable backends first, fall back to legacy _BACKENDS dict
        backend = _new_backends.get_backend(model_cfg.provider) or _BACKENDS.get(model_cfg.provider)

        if backend is None:
            log.error("No backend registered for provider '%s'", model_cfg.provider)
            return None
```

- [ ] **Step 6: Adapt `_call_with_retry()` call site to handle `BackendResult` from new backends**

Currently line 897 reads:
```python
                content, in_tok, out_tok = backend.call(
                    model_id=model_cfg.model_id,
                    system=system,
                    prompt=prompt,
                    temperature=temp,
                    max_tokens=min(4096, model_cfg.max_context_tokens // 4),
                )
```

Replace with:
```python
                _raw = backend.call(
                    model_id=model_cfg.model_id,
                    system=system,
                    prompt=prompt,
                    temperature=temp,
                    max_tokens=min(4096, model_cfg.max_context_tokens // 4),
                )
                # New backends return BackendResult; legacy backends return (content, in, out) tuple
                if hasattr(_raw, "content"):
                    if _raw.failed:
                        raise RuntimeError(_raw.error)
                    content, in_tok, out_tok = _raw.content, _raw.input_tokens, _raw.output_tokens
                else:
                    content, in_tok, out_tok = _raw
```

- [ ] **Step 7: Run all three tests — verify they pass**

```bash
cd /home/devendra-yadav/oneinfinity
python -m pytest tests/orchestration/test_orchestrator_extensions.py::test_modelconfig_has_fallback_provider_field tests/orchestration/test_orchestrator_extensions.py::test_modelconfig_fallback_provider_can_be_set tests/orchestration/test_orchestrator_extensions.py::test_call_with_retry_routes_ollama_to_ollama_backend -v
```

Expected: 3 tests pass.

- [ ] **Step 8: Run full test suite to confirm nothing broken**

```bash
cd /home/devendra-yadav/oneinfinity
python -m pytest tests/ -v --tb=short 2>&1 | tail -20
```

Expected: all existing 34 tests still pass plus the 3 new ones.

- [ ] **Step 9: Commit**

```bash
cd /home/devendra-yadav/oneinfinity
git add src/oneinfinity/orchestration/model_orchestrator.py tests/orchestration/test_orchestrator_extensions.py
git commit -m "feat(orchestration): add ModelConfig.fallback_provider and route new providers via backends package"
```

---

## Task 5: `model_orchestrator.py` — Startup discovery methods

**Files:**
- Modify: `src/oneinfinity/orchestration/model_orchestrator.py` (after `_auto_enable_cli_models`, around line 673)

- [ ] **Step 1: Add tests to `test_orchestrator_extensions.py`**

Append to `tests/orchestration/test_orchestrator_extensions.py`:

```python
# ── _auto_discover_ollama ─────────────────────────────────────────────────────

def test_auto_discover_ollama_registers_new_models():
    from oneinfinity.orchestration.backends.ollama import DiscoveredModel
    orch = _make_orchestrator()

    discovered = [
        DiscoveredModel(name="llama3.2:3b",  tier="FAST",    context_tokens=8192),
        DiscoveredModel(name="llama3.1:70b", tier="PREMIUM", context_tokens=131072),
    ]

    with patch("oneinfinity.orchestration.backends.ollama.OllamaBackend.discover_models",
               return_value=discovered):
        orch._auto_discover_ollama(ollama_cfg={})

    assert "llama3.2:3b"  in orch._models
    assert "llama3.1:70b" in orch._models
    assert orch._models["llama3.2:3b"].provider  == "ollama"
    assert orch._models["llama3.1:70b"].tier.name == "PREMIUM"


def test_auto_discover_ollama_yaml_entry_wins():
    """models.yaml explicit entry is not overwritten by auto-discovery."""
    from oneinfinity.orchestration.model_orchestrator import ModelConfig, ModelTier
    from oneinfinity.orchestration.backends.ollama import DiscoveredModel
    orch = _make_orchestrator()

    # Pre-register explicit YAML entry for llama3.2:3b as STANDARD
    orch._models["llama3.2:3b"] = ModelConfig(
        model_id="llama3.2:3b", provider="ollama", tier=ModelTier.STANDARD,
        cost_per_1k_input=0.0, cost_per_1k_output=0.0, max_context_tokens=131072,
        latency_class="INTERACTIVE", capabilities={"GENERAL"},
    )

    discovered = [DiscoveredModel(name="llama3.2:3b", tier="FAST", context_tokens=8192)]
    with patch("oneinfinity.orchestration.backends.ollama.OllamaBackend.discover_models",
               return_value=discovered):
        orch._auto_discover_ollama(ollama_cfg={})

    # YAML entry tier (STANDARD) must be preserved
    assert orch._models["llama3.2:3b"].tier == ModelTier.STANDARD


def test_auto_discover_ollama_skipped_when_disabled():
    orch = _make_orchestrator()
    with patch("oneinfinity.orchestration.backends.ollama.OllamaBackend.discover_models") as mock_disc:
        orch._auto_discover_ollama(ollama_cfg={"auto_discover": False})
    mock_disc.assert_not_called()


# ── _register_cli_models ──────────────────────────────────────────────────────

def test_register_cli_models_enables_codex_when_binary_found():
    orch = _make_orchestrator()
    with patch("shutil.which", side_effect=lambda x: "/bin/codex" if x == "codex" else None):
        orch._register_cli_models(cli_cfg={"enabled": True, "codex_model": "o4-mini", "claude_model": "claude-opus-4-6", "max_budget_usd": 0.10})
    assert "codex-cli" in orch._models
    assert orch._models["codex-cli"].enabled is True


def test_register_cli_models_enables_claude_when_binary_found():
    orch = _make_orchestrator()
    with patch("shutil.which", side_effect=lambda x: "/bin/claude" if x == "claude" else None):
        orch._register_cli_models(cli_cfg={"enabled": True, "codex_model": "o4-mini", "claude_model": "claude-opus-4-6", "max_budget_usd": 0.10})
    assert "claude-cli" in orch._models
    assert orch._models["claude-cli"].enabled is True


def test_register_cli_models_skips_when_binary_missing():
    orch = _make_orchestrator()
    with patch("shutil.which", return_value=None):
        orch._register_cli_models(cli_cfg={"enabled": True, "codex_model": "o4-mini", "claude_model": "claude-opus-4-6", "max_budget_usd": 0.10})
    assert "codex-cli" not in orch._models
    assert "claude-cli" not in orch._models


# ── _assign_cli_fallbacks ─────────────────────────────────────────────────────

def test_assign_cli_fallbacks_sets_codex_when_no_openai_key(monkeypatch):
    from oneinfinity.orchestration.model_orchestrator import ModelConfig, ModelTier
    monkeypatch.delenv("OPENAI_API_KEY", raising=False)
    orch = _make_orchestrator()
    orch._models["gpt-4o-mini"] = ModelConfig(
        model_id="gpt-4o-mini", provider="openai", tier=ModelTier.FAST,
        cost_per_1k_input=0.00015, cost_per_1k_output=0.0006,
        max_context_tokens=128000, latency_class="INTERACTIVE", capabilities={"GENERAL"},
    )
    with patch("shutil.which", side_effect=lambda x: "/bin/codex" if x == "codex" else None):
        orch._assign_cli_fallbacks(cli_cfg={"enabled": True, "on_errors": ["auth", "quota"]})
    assert orch._models["gpt-4o-mini"].fallback_provider == "codex"


def test_assign_cli_fallbacks_sets_claude_when_no_anthropic_key(monkeypatch):
    from oneinfinity.orchestration.model_orchestrator import ModelConfig, ModelTier
    monkeypatch.delenv("ANTHROPIC_API_KEY", raising=False)
    orch = _make_orchestrator()
    orch._models["claude-haiku-4-5"] = ModelConfig(
        model_id="claude-haiku-4-5", provider="anthropic", tier=ModelTier.FAST,
        cost_per_1k_input=0.0008, cost_per_1k_output=0.004,
        max_context_tokens=200000, latency_class="INTERACTIVE", capabilities={"GENERAL"},
    )
    with patch("shutil.which", side_effect=lambda x: "/bin/claude" if x == "claude" else None):
        orch._assign_cli_fallbacks(cli_cfg={"enabled": True, "on_errors": ["auth", "quota"]})
    assert orch._models["claude-haiku-4-5"].fallback_provider == "claude-cli"


def test_assign_cli_fallbacks_skips_when_disabled():
    from oneinfinity.orchestration.model_orchestrator import ModelConfig, ModelTier
    orch = _make_orchestrator()
    orch._models["gpt-4o-mini"] = ModelConfig(
        model_id="gpt-4o-mini", provider="openai", tier=ModelTier.FAST,
        cost_per_1k_input=0.00015, cost_per_1k_output=0.0006,
        max_context_tokens=128000, latency_class="INTERACTIVE", capabilities={"GENERAL"},
    )
    orch._assign_cli_fallbacks(cli_cfg={"enabled": False})
    assert orch._models["gpt-4o-mini"].fallback_provider is None
```

- [ ] **Step 2: Run new tests — verify they fail**

```bash
cd /home/devendra-yadav/oneinfinity
python -m pytest tests/orchestration/test_orchestrator_extensions.py -k "discover or register_cli or assign_cli" -v 2>&1 | tail -15
```

Expected: `AttributeError: 'ModelOrchestrator' object has no attribute '_auto_discover_ollama'`

- [ ] **Step 3: Add the three discovery methods to `model_orchestrator.py`**

After the `_auto_enable_cli_models` method (around line 673), add the following three methods. Insert before `register_model`:

```python
    def _auto_discover_ollama(self, ollama_cfg: dict) -> None:
        """Query Ollama for running models and register any not already in registry."""
        if not ollama_cfg.get("auto_discover", True):
            return
        import shutil as _shutil
        from oneinfinity.orchestration.backends.ollama import OllamaBackend
        host = ollama_cfg.get("host")
        backend = OllamaBackend(host=host)
        discovered = backend.discover_models()
        if not discovered:
            return
        with self._lock:
            for d in discovered:
                if d.name in self._models:
                    continue   # YAML explicit entry wins
                self._models[d.name] = ModelConfig(
                    model_id=d.name,
                    provider="ollama",
                    tier=ModelTier[d.tier],
                    cost_per_1k_input=0.0,
                    cost_per_1k_output=0.0,
                    max_context_tokens=d.context_tokens,
                    latency_class=LatencyClass.INTERACTIVE,
                    capabilities=set(TaskCategory.__dict__[k] for k in vars(TaskCategory)
                                     if not k.startswith("_")),
                    enabled=True,
                )
                log.info("[Ollama] Auto-registered model '%s' (tier=%s)", d.name, d.tier)

    def _register_cli_models(self, cli_cfg: dict) -> None:
        """Register Codex and Claude CLI as explicit models if their binaries are found."""
        import shutil as _shutil
        if not cli_cfg.get("enabled", True):
            return
        codex_model  = cli_cfg.get("codex_model", "o4-mini")
        claude_model = cli_cfg.get("claude_model", "claude-opus-4-6")
        budget       = float(cli_cfg.get("max_budget_usd", 0.10))

        all_caps = {c for c in vars(TaskCategory).values() if isinstance(c, str)}

        if _shutil.which("codex"):
            from oneinfinity.orchestration.backends.cli import CodexCliBackend
            # Update the registered singleton's default model
            from oneinfinity.orchestration.backends import get_backend as _gb
            b = _gb("codex")
            if b:
                b._model = codex_model
            with self._lock:
                self._models["codex-cli"] = ModelConfig(
                    model_id=codex_model,
                    provider="codex",
                    tier=ModelTier.FAST,
                    cost_per_1k_input=0.0,
                    cost_per_1k_output=0.0,
                    max_context_tokens=128000,
                    latency_class=LatencyClass.INTERACTIVE,
                    capabilities=all_caps,
                    enabled=True,
                )
            log.info("[CLI] Registered codex-cli model (model=%s)", codex_model)

        if _shutil.which("claude"):
            from oneinfinity.orchestration.backends.cli import ClaudeCliBackend
            from oneinfinity.orchestration.backends import get_backend as _gb
            b = _gb("claude-cli")
            if b:
                b._model = claude_model
                b._max_budget = budget
            with self._lock:
                self._models["claude-cli"] = ModelConfig(
                    model_id=claude_model,
                    provider="claude-cli",
                    tier=ModelTier.STANDARD,
                    cost_per_1k_input=0.0,
                    cost_per_1k_output=0.0,
                    max_context_tokens=200000,
                    latency_class=LatencyClass.INTERACTIVE,
                    capabilities=all_caps,
                    enabled=True,
                )
            log.info("[CLI] Registered claude-cli model (model=%s)", claude_model)

    def _assign_cli_fallbacks(self, cli_cfg: dict) -> None:
        """Set fallback_provider on API models when CLI binaries are present and keys are absent."""
        import shutil as _shutil
        import os as _os
        if not cli_cfg.get("enabled", True):
            return
        has_codex     = _shutil.which("codex") is not None
        has_claude    = _shutil.which("claude") is not None
        has_openai    = bool(_os.environ.get("OPENAI_API_KEY", "").strip())
        has_anthropic = bool(_os.environ.get("ANTHROPIC_API_KEY", "").strip())
        on_errors     = set(cli_cfg.get("on_errors", ["auth", "quota"]))

        with self._lock:
            for model in self._models.values():
                if model.provider == "openai" and has_codex and not has_openai:
                    model.fallback_provider = "codex"
                    log.info("[CLI fallback] %s → codex (no OPENAI_API_KEY)", model.model_id)
                elif model.provider == "anthropic" and has_claude and not has_anthropic:
                    model.fallback_provider = "claude-cli"
                    log.info("[CLI fallback] %s → claude-cli (no ANTHROPIC_API_KEY)", model.model_id)
```

- [ ] **Step 4: Wire the three methods into `load_config()`**

In `load_config()`, find the line (around 614):
```python
        self._auto_enable_cli_models()
        self._loaded = True
```

Replace with:
```python
        self._auto_enable_cli_models()

        # New provider discovery
        _ollama_cfg = cfg.get("ollama", {}) if isinstance(cfg, dict) else {}
        _cli_cfg    = cfg.get("cli_fallback", {}) if isinstance(cfg, dict) else {}
        self._auto_discover_ollama(_ollama_cfg)
        self._register_cli_models(_cli_cfg)
        self._assign_cli_fallbacks(_cli_cfg)

        self._loaded = True
```

Also update `_load_defaults()` to call the discovery with empty configs:

```python
    def _load_defaults(self) -> None:
        """Built-in defaults when YAML is unavailable."""
        # ... existing code to register gpt-4o-mini and gpt-4o ...
        self._auto_enable_cli_models()
        self._auto_discover_ollama({})
        self._register_cli_models({})
        self._assign_cli_fallbacks({})
```

Find `_load_defaults` and add those four lines just before `self._loaded = True` at its end.

- [ ] **Step 5: Run new discovery tests — verify they pass**

```bash
cd /home/devendra-yadav/oneinfinity
python -m pytest tests/orchestration/test_orchestrator_extensions.py -k "discover or register_cli or assign_cli" -v
```

Expected: 9 new tests pass.

- [ ] **Step 6: Run full test suite**

```bash
cd /home/devendra-yadav/oneinfinity
python -m pytest tests/ -v --tb=short 2>&1 | tail -20
```

Expected: all tests pass.

- [ ] **Step 7: Commit**

```bash
cd /home/devendra-yadav/oneinfinity
git add src/oneinfinity/orchestration/model_orchestrator.py tests/orchestration/test_orchestrator_extensions.py
git commit -m "feat(orchestration): add Ollama auto-discovery and CLI model registration at startup"
```

---

## Task 6: `model_orchestrator.py` — CLI fallback on auth/quota errors

**Files:**
- Modify: `src/oneinfinity/orchestration/model_orchestrator.py` (inside `_call_with_retry`, around line 946)

- [ ] **Step 1: Add failing tests to `test_orchestrator_extensions.py`**

Append to `tests/orchestration/test_orchestrator_extensions.py`:

```python
# ── CLI fallback in _call_with_retry ─────────────────────────────────────────

def test_cli_fallback_called_on_auth_error():
    """When API raises 401, fallback_provider CLI backend is tried."""
    from oneinfinity.orchestration.model_orchestrator import ModelConfig, ModelTier, TaskClassification, TaskCategory, ComplexityLevel, ImportanceLevel
    from oneinfinity.orchestration.backends import get_backend
    from oneinfinity.orchestration.backends import BackendResult

    cfg = ModelConfig(
        model_id="gpt-4o-mini", provider="openai",
        tier=ModelTier.FAST, cost_per_1k_input=0.00015,
        cost_per_1k_output=0.0006, max_context_tokens=128000,
        latency_class="INTERACTIVE", capabilities={"GENERAL"},
        fallback_provider="codex",
    )

    classification = TaskClassification(
        category=TaskCategory.GENERAL, complexity=ComplexityLevel.LOW,
        importance=ImportanceLevel.NORMAL, latency_class="INTERACTIVE",
        estimated_tokens=100, reasoning_depth=1, tags=[], classifier_confidence=0.8,
    )

    orch = _make_orchestrator()
    codex_result = BackendResult(content="codex fallback response", input_tokens=10, output_tokens=5, duration_ms=200.0)

    # Patch OpenAI backend to raise 401, patch codex backend to succeed
    from oneinfinity.orchestration import model_orchestrator as _mo
    with patch.dict(_mo._BACKENDS, {"openai": MagicMock(call=MagicMock(side_effect=RuntimeError("401 Unauthorized")))}):
        with patch.object(get_backend("codex"), "is_available", return_value=True):
            with patch.object(get_backend("codex"), "call", return_value=codex_result) as mock_codex:
                output = orch._call_with_retry({}, classification, cfg, "task-fallback-test")

    assert mock_codex.called
    assert output is not None
    assert output.content == "codex fallback response"


def test_cli_fallback_not_triggered_on_rate_limit():
    """429 rate limit retries normally — does NOT trigger CLI fallback."""
    from oneinfinity.orchestration.model_orchestrator import ModelConfig, ModelTier, TaskClassification, TaskCategory, ComplexityLevel, ImportanceLevel
    from oneinfinity.orchestration.backends import get_backend

    cfg = ModelConfig(
        model_id="gpt-4o-mini", provider="openai",
        tier=ModelTier.FAST, cost_per_1k_input=0.00015,
        cost_per_1k_output=0.0006, max_context_tokens=128000,
        latency_class="INTERACTIVE", capabilities={"GENERAL"},
        fallback_provider="codex",
    )
    classification = TaskClassification(
        category=TaskCategory.GENERAL, complexity=ComplexityLevel.LOW,
        importance=ImportanceLevel.NORMAL, latency_class="INTERACTIVE",
        estimated_tokens=100, reasoning_depth=1, tags=[], classifier_confidence=0.8,
    )

    orch = _make_orchestrator()
    orch._policy.max_retries_same_model = 0   # no retries

    from oneinfinity.orchestration import model_orchestrator as _mo
    with patch.dict(_mo._BACKENDS, {"openai": MagicMock(call=MagicMock(side_effect=RuntimeError("429 rate limit")))}):
        with patch.object(get_backend("codex"), "call") as mock_codex:
            orch._call_with_retry({}, classification, cfg, "task-ratelimit-test")

    mock_codex.assert_not_called()


def test_cli_fallback_not_triggered_when_unavailable():
    """If CLI binary not found, auth error returns None (escalates)."""
    from oneinfinity.orchestration.model_orchestrator import ModelConfig, ModelTier, TaskClassification, TaskCategory, ComplexityLevel, ImportanceLevel
    from oneinfinity.orchestration.backends import get_backend

    cfg = ModelConfig(
        model_id="gpt-4o-mini", provider="openai",
        tier=ModelTier.FAST, cost_per_1k_input=0.00015,
        cost_per_1k_output=0.0006, max_context_tokens=128000,
        latency_class="INTERACTIVE", capabilities={"GENERAL"},
        fallback_provider="codex",
    )
    classification = TaskClassification(
        category=TaskCategory.GENERAL, complexity=ComplexityLevel.LOW,
        importance=ImportanceLevel.NORMAL, latency_class="INTERACTIVE",
        estimated_tokens=100, reasoning_depth=1, tags=[], classifier_confidence=0.8,
    )

    orch = _make_orchestrator()
    from oneinfinity.orchestration import model_orchestrator as _mo
    with patch.dict(_mo._BACKENDS, {"openai": MagicMock(call=MagicMock(side_effect=RuntimeError("401 Unauthorized")))}):
        with patch.object(get_backend("codex"), "is_available", return_value=False):
            output = orch._call_with_retry({}, classification, cfg, "task-no-cli")

    assert output is None
```

- [ ] **Step 2: Run new tests — verify they fail**

```bash
cd /home/devendra-yadav/oneinfinity
python -m pytest tests/orchestration/test_orchestrator_extensions.py -k "fallback" -v 2>&1 | tail -15
```

Expected: `AssertionError` — `mock_codex.called` is False (fallback not yet implemented).

- [ ] **Step 3: Add CLI fallback clause to `_call_with_retry()`**

In `model_orchestrator.py` find the auth error handler (around line 946):

```python
                elif "401" in err_str or "403" in err_str or "api key" in err_str:
                    log.error("Auth error for %s: %s", model_cfg.model_id, e)
                    return None  # no point retrying
```

Replace with:

```python
                elif "401" in err_str or "403" in err_str or "api key" in err_str:
                    log.error("Auth error for %s: %s", model_cfg.model_id, e)
                    # Try CLI fallback before giving up
                    fb = model_cfg.fallback_provider
                    if fb:
                        fb_backend = _new_backends.get_backend(fb)
                        if fb_backend and fb_backend.is_available():
                            log.info("Auth failure on %s — trying CLI fallback: %s",
                                     model_cfg.model_id, fb)
                            try:
                                _fb_raw = fb_backend.call(
                                    model_id=model_cfg.model_id,
                                    system=system,
                                    prompt=prompt,
                                    temperature=temp,
                                    max_tokens=min(4096, model_cfg.max_context_tokens // 4),
                                )
                                if not _fb_raw.failed:
                                    self._budget.record(
                                        model_id=f"{fb}:{model_cfg.model_id}",
                                        provider=fb,
                                        task_id=task_id,
                                        task_category=classification.category,
                                        input_tokens=_fb_raw.input_tokens,
                                        output_tokens=_fb_raw.output_tokens,
                                        cost_usd=0.0,
                                        duration_ms=_fb_raw.duration_ms,
                                        escalation=(escalated_from is not None),
                                    )
                                    return ModelOutput(
                                        output_id=str(uuid.uuid4())[:12],
                                        task_id=task_id,
                                        model_id=f"{fb}:{model_cfg.model_id}",
                                        tier=model_cfg.tier,
                                        content=_fb_raw.content,
                                        confidence=0.0,
                                        input_tokens=_fb_raw.input_tokens,
                                        output_tokens=_fb_raw.output_tokens,
                                        cost_usd=0.0,
                                        duration_ms=_fb_raw.duration_ms,
                                        escalated_from=escalated_from,
                                        escalation_reason="cli_fallback",
                                        retries=attempt,
                                    )
                            except Exception as fb_exc:
                                log.warning("CLI fallback %s also failed: %s", fb, fb_exc)
                    return None  # no point retrying
```

Also add CLI fallback for quota exhaustion. Find the `BudgetExhaustedError` handler (around line 936):

```python
            except BudgetExhaustedError as e:
                log.warning("Budget exhausted for %s: %s", model_cfg.model_id, e)
                return None
```

Replace with:

```python
            except BudgetExhaustedError as e:
                log.warning("Budget exhausted for %s: %s", model_cfg.model_id, e)
                fb = model_cfg.fallback_provider
                if fb:
                    fb_backend = _new_backends.get_backend(fb)
                    if fb_backend and fb_backend.is_available():
                        log.info("Budget exhausted on %s — trying CLI fallback: %s",
                                 model_cfg.model_id, fb)
                        try:
                            _fb_raw = fb_backend.call(
                                model_id=model_cfg.model_id,
                                system=system,
                                prompt=prompt,
                                temperature=temp,
                                max_tokens=min(4096, model_cfg.max_context_tokens // 4),
                            )
                            if not _fb_raw.failed:
                                return ModelOutput(
                                    output_id=str(uuid.uuid4())[:12],
                                    task_id=task_id,
                                    model_id=f"{fb}:{model_cfg.model_id}",
                                    tier=model_cfg.tier,
                                    content=_fb_raw.content,
                                    confidence=0.0,
                                    input_tokens=_fb_raw.input_tokens,
                                    output_tokens=_fb_raw.output_tokens,
                                    cost_usd=0.0,
                                    duration_ms=_fb_raw.duration_ms,
                                    escalated_from=escalated_from,
                                    escalation_reason="cli_fallback_budget",
                                    retries=attempt,
                                )
                        except Exception as fb_exc:
                            log.warning("CLI fallback %s also failed: %s", fb, fb_exc)
                return None
```

- [ ] **Step 4: Run fallback tests — verify they pass**

```bash
cd /home/devendra-yadav/oneinfinity
python -m pytest tests/orchestration/test_orchestrator_extensions.py -k "fallback" -v
```

Expected: 3 tests pass.

- [ ] **Step 5: Run full test suite**

```bash
cd /home/devendra-yadav/oneinfinity
python -m pytest tests/ -v --tb=short 2>&1 | tail -20
```

Expected: all tests pass.

- [ ] **Step 6: Commit**

```bash
cd /home/devendra-yadav/oneinfinity
git add src/oneinfinity/orchestration/model_orchestrator.py tests/orchestration/test_orchestrator_extensions.py
git commit -m "feat(orchestration): add CLI fallback on auth/quota errors in _call_with_retry"
```

---

## Task 7: `config/models.yaml` — New sections + Ollama example entries

**Files:**
- Modify: `config/models.yaml`

- [ ] **Step 1: Add new sections to `config/models.yaml`**

Append to the end of `/path/to/oneinfinity/config/models.yaml`:

```yaml

# ── Ollama (local) ────────────────────────────────────────────────────────────
# These override auto-discovery defaults. Remove entries to use heuristics.
# Auto-discovered models not listed here get tier assigned by parameter count.

  deepseek-r1:7b:
    provider: ollama
    tier: STANDARD
    cost_per_1k_input: 0.0
    cost_per_1k_output: 0.0
    max_context_tokens: 131072
    latency_class: INTERACTIVE
    enabled: true
    capabilities:
      - VULN_ANALYSIS
      - HYPOTHESIS
      - CODE_ANALYSIS
      - CHAIN_DETECTION
      - GENERAL

  llama3.2:3b:
    provider: ollama
    tier: FAST
    cost_per_1k_input: 0.0
    cost_per_1k_output: 0.0
    max_context_tokens: 131072
    latency_class: INTERACTIVE
    enabled: true
    capabilities:
      - RECON
      - HYPOTHESIS
      - OSINT
      - GENERAL

# ── Ollama configuration ──────────────────────────────────────────────────────

ollama:
  host: "http://localhost:11434"   # override with OLLAMA_HOST env var
  auto_discover: true              # register all models returned by /api/tags
  prefer_over_api: false           # if true, Ollama tried before paid API at same tier
  discovery_timeout_s: 2

# ── CLI fallback configuration ────────────────────────────────────────────────

cli_fallback:
  enabled: true
  codex_model: "o4-mini"           # model passed to: codex exec -m <model>
  claude_model: "claude-opus-4-6"  # model passed to: claude -p --model <model>
  max_budget_usd: 0.10             # --max-budget-usd for claude CLI
  on_errors:
    - auth    # 401/403 from API
    - quota   # budget exhausted
```

- [ ] **Step 2: Verify orchestrator loads the new config cleanly**

```bash
cd /home/devendra-yadav/oneinfinity
python3 -c "
import sys; sys.path.insert(0, 'src')
from oneinfinity.orchestration.model_orchestrator import get_orchestrator
orch = get_orchestrator()
models = orch.list_models()
providers = {m['provider'] for m in models}
print('Providers found:', providers)
print('Total models:', len(models))
ollama_models = [m['model_id'] for m in models if m['provider'] == 'ollama']
print('Ollama models:', ollama_models)
cli_models = [m['model_id'] for m in models if m['provider'] in ('codex','claude-cli')]
print('CLI models:', cli_models)
"
```

Expected output (will vary by what's installed):
```
Providers found: {'openai', 'anthropic', 'ollama', 'codex', 'claude-cli'}  # subset
Total models: 8+
Ollama models: ['deepseek-r1:7b', 'llama3.2:3b']
CLI models: ['o4-mini', 'claude-opus-4-6']  # only if binaries found
```

- [ ] **Step 3: Restart backend and verify API returns new providers**

```bash
fuser -k 8000/tcp 2>/dev/null; sleep 1
cd /home/devendra-yadav/oneinfinity
POSTGRES_URL=postgresql://oneinfinity:oneinfinity@localhost:5432/oneinfinity \
REDIS_URL=redis://localhost:6379/0 \
ONEINFINITY_API_KEY=dev-local \
python3 web/backend/main.py > /tmp/oneinfinity-backend.log 2>&1 &
sleep 3
python3 -c "
import urllib.request, json
token = json.loads(urllib.request.urlopen('http://127.0.0.1:8000/api/auth-token', timeout=5).read())['token']
req = urllib.request.Request('http://127.0.0.1:8000/api/orchestrator/models', headers={'X-API-Key': token})
models = json.loads(urllib.request.urlopen(req, timeout=10).read())
providers = {m['provider'] for m in models}
print('Providers:', providers)
print('Total models:', len(models))
"
```

Expected: `Providers: {'openai', ...}` — at minimum openai. Ollama/CLI providers appear if Ollama is running or binaries are found.

- [ ] **Step 4: Commit**

```bash
cd /home/devendra-yadav/oneinfinity
git add config/models.yaml
git commit -m "feat(config): add ollama and cli_fallback sections to models.yaml"
```

---

## Task 8: Run full test suite + final verification

- [ ] **Step 1: Run complete test suite**

```bash
cd /home/devendra-yadav/oneinfinity
python -m pytest tests/ -v --tb=short
```

Expected: all tests pass including the new ones in `tests/orchestration/`.

- [ ] **Step 2: Verify all backend tests individually**

```bash
cd /home/devendra-yadav/oneinfinity
python -m pytest tests/orchestration/test_backends_registry.py tests/orchestration/test_ollama_backend.py tests/orchestration/test_cli_backends.py tests/orchestration/test_orchestrator_extensions.py -v
```

Expected: 5 + 13 + 14 + 15 = 47 tests pass.

- [ ] **Step 3: Final commit if any loose files**

```bash
cd /home/devendra-yadav/oneinfinity
git status
git log --oneline -8
```

Expected: clean working tree, 7 feature commits visible.
