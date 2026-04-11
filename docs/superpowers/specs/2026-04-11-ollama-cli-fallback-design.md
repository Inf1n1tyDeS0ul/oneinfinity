# AI Orchestrator: Ollama + CLI Fallback Design

**Date:** 2026-04-11  
**Status:** Approved  
**Scope:** `src/oneinfinity/orchestration/` + `config/models.yaml`

---

## 1. Goal

Extend the AI Orchestrator with two new capabilities:

1. **Ollama support** — any locally-running Ollama model can be assigned to any tier (FAST / STANDARD / PREMIUM) via `models.yaml`, with auto-discovery of running models and sensible defaults.
2. **CLI fallback** — when an API key is absent or fails at runtime (auth error, quota exhaustion), the orchestrator automatically tries the equivalent CLI tool (`codex` or `claude`) before escalating to the next tier.

---

## 2. Architecture

No existing code paths are modified. New providers are added via a `backends/` package and three small extension points in `model_orchestrator.py`.

```
src/oneinfinity/orchestration/
├── model_orchestrator.py        ← minimal extensions (see §6)
├── orchestrator_integration.py  ← untouched
└── backends/                    ← NEW
    ├── __init__.py              ← BaseBackend ABC + global registry
    ├── ollama.py                ← OllamaBackend + auto-discovery
    └── cli.py                   ← CodexCliBackend + ClaudeCliBackend
```

**Call flow:**

```
orchestrator.execute(task)
  → _select_model()
  → _call_model_with_retry()
      → _call_model()   ← routes by provider
          openai     → existing _OpenAIBackend     (unchanged)
          anthropic  → existing _AnthropicBackend  (unchanged)
          gemini     → existing _GeminiBackend     (unchanged)
          ollama     → NEW OllamaBackend
          codex      → NEW CodexCliBackend
          claude-cli → NEW ClaudeCliBackend
      → on auth/quota error → CLI fallback for same model (NEW)
```

**Startup sequence additions in `load_config()`:**
1. Load `models.yaml` (existing)
2. `_auto_discover_ollama()` — query `/api/tags`, merge new models
3. `_register_cli_models()` — detect binaries, enable/disable CLI models
4. `_assign_cli_fallbacks()` — set `fallback_provider` on API models

---

## 3. `backends/` Package

### `backends/__init__.py` — Base class and registry

```python
class BaseBackend(ABC):
    provider: str

    @abstractmethod
    def is_available(self) -> bool: ...

    @abstractmethod
    def call(self, model_id, prompt, system, temperature, max_tokens) -> BackendResult: ...

@dataclass
class BackendResult:
    content: str
    input_tokens: int
    output_tokens: int
    duration_ms: float
    error: str = ""

_BACKENDS: dict[str, BaseBackend] = {}

def get_backend(provider: str) -> Optional[BaseBackend]: ...
def register_backend(backend: BaseBackend) -> None: ...
```

### `backends/ollama.py` — OllamaBackend

- **Endpoint:** `POST {OLLAMA_HOST}/v1/chat/completions` (OpenAI-compatible)
- **Auth:** None required
- **Env override:** `OLLAMA_HOST` overrides `http://localhost:11434`
- **Per-model override:** `ollama_host` field in `models.yaml`
- **`is_available()`:** `GET {host}/` with 2s timeout
- **Token counting:** `prompt_eval_count` + `eval_count` from Ollama response
- **`discover_models()`:** `GET {host}/api/tags` → returns list of `{name, tier, context}` dicts

### `backends/cli.py` — CLI backends

**`CodexCliBackend`** (provider: `"codex"`):
- `is_available()` → `shutil.which("codex")`
- Call: `codex exec -m <model> --full-auto --dangerously-bypass-approvals-and-sandbox -o <tmpfile> "<system>\n\n<prompt>"`
- Output read from `<tmpfile>` (last message written by `-o` flag)
- Tokens: estimated from character count (CLI does not return token counts)
- Cost recorded: `0.0`

**`ClaudeCliBackend`** (provider: `"claude-cli"`):
- `is_available()` → `shutil.which("claude")`
- Call: `claude -p "<system>\n\n<prompt>" --model <model> --allowed-tools "" --max-budget-usd <limit> --output-format text`
- Model and budget taken from `cli_fallback` section of `models.yaml`
- Cost recorded: `0.0`

---

## 4. Ollama Auto-Discovery

Runs at startup via `_auto_discover_ollama()`. Silently skipped if Ollama unreachable.

**Tier heuristics (applied when no `models.yaml` entry exists):**

| Name pattern | Tier | Notes |
|---|---|---|
| `70b`, `72b`, `65b`, `671b` | PREMIUM | Large flagship |
| `27b`, `32b`, `34b`, `13b`, `14b` | STANDARD | Mid-size |
| Everything else | FAST | Small / default |
| Contains `deepseek-r1`, `qwq`, `:think` | +1 tier | Reasoning models |

**Auto-registered defaults:**
```yaml
provider: ollama
tier: <heuristic>
cost_per_1k_input: 0.0
cost_per_1k_output: 0.0
capabilities: [all 11 categories]
context_tokens: 8192   # conservative; override in models.yaml
enabled: true
```

`models.yaml` explicit entries override all auto-discovery defaults entirely.

**Priority:** Ollama models participate in the same `_select_model()` registry. Since `cost=0.0`, they are selected last when paid API models are available at the same tier. When API is unavailable or over-budget, they become the preferred option.

---

## 5. CLI Fallback Chain

### Scenario A — API key absent at load time

During `_assign_cli_fallbacks()`:
- OpenAI model + no `OPENAI_API_KEY` + `codex` binary found → `model.fallback_provider = "codex"`
- Anthropic model + no `ANTHROPIC_API_KEY` + `claude` binary found → `model.fallback_provider = "claude-cli"`

The model routes directly to CLI without attempting the API.

### Scenario B — API key present but fails at runtime

Triggered by: `401`, `403`, or `429` with `insufficient_quota` body.

**Not triggered by:** `429` with `retry-after` header (rate limit — still retried with backoff), `5xx` errors (retried as today).

```
API call fails with auth/quota error
  → model.fallback_provider set?
      → CLI backend available?
          → call CLI
          → success: record cost=0, continue
          → failure: escalate tier
      → no CLI: escalate tier (existing behaviour)
```

### Full priority order per task

```
1. Paid API model at selected tier
2. CLI fallback for same provider (if API key missing/dead)
3. Ollama model at same tier (local, free)
4. Escalate to next tier → repeat 1–3
5. Return best result seen
```

---

## 6. `model_orchestrator.py` Changes

Exactly four additions, no deletions:

**1. `ModelConfig` — one new field:**
```python
fallback_provider: Optional[str] = None
```

**2. `load_config()` — three new calls at end:**
```python
self._auto_discover_ollama()
self._register_cli_models()
self._assign_cli_fallbacks()
```

**3. `_call_model()` — provider routing extension:**
```python
elif model.provider == "ollama":
    return backends.get_backend("ollama").call(...)
elif model.provider in ("codex", "claude-cli"):
    return backends.get_backend(model.provider).call(...)
```

**4. `_call_model_with_retry()` — CLI fallback on auth/quota:**
```python
except (AuthError, QuotaError):
    fb = model.fallback_provider
    if fb and backends.get_backend(fb) and backends.get_backend(fb).is_available():
        try:
            return backends.get_backend(fb).call(...)
        except Exception:
            pass
    raise
```

---

## 7. `models.yaml` Schema Additions

### New top-level sections

```yaml
ollama:
  host: "http://localhost:11434"   # OLLAMA_HOST env var overrides
  auto_discover: true
  prefer_over_api: false           # if true, Ollama tried before paid API at same tier
  discovery_timeout_s: 2

cli_fallback:
  enabled: true
  claude_model: "claude-opus-4-6"
  codex_model: "o4-mini"
  max_budget_usd: 0.10             # --max-budget-usd for claude CLI
  on_errors: [auth, quota]         # error classes that trigger CLI fallback
```

### New optional per-model fields

```yaml
context_tokens: 131072             # override auto-detected context window
ollama_host: "http://192.168.1.10:11434"  # per-model remote Ollama host
fallback_provider: codex           # explicit override of auto-detected fallback
```

### New valid `provider` values

- `ollama`
- `codex`
- `claude-cli`

---

## 8. Error Handling

| Error type | Behaviour |
|---|---|
| Ollama not running at startup | Silent skip; no Ollama models registered |
| Ollama model not loaded (404) | `BackendResult.error` set; treated as model failure; escalates tier |
| CLI binary not found | `is_available()` returns False; backend skipped |
| CLI subprocess timeout | Treated as model failure; escalates tier |
| CLI non-zero exit code | `BackendResult.error` set with stderr; escalates tier |
| `OLLAMA_HOST` unreachable | Per-call failure; escalates tier |

---

## 9. Files Changed

| File | Change type |
|---|---|
| `src/oneinfinity/orchestration/backends/__init__.py` | New |
| `src/oneinfinity/orchestration/backends/ollama.py` | New |
| `src/oneinfinity/orchestration/backends/cli.py` | New |
| `src/oneinfinity/orchestration/model_orchestrator.py` | Extended (4 additions) |
| `config/models.yaml` | Extended (new sections + Ollama/CLI model entries) |

No other files change.

---

## 10. Out of Scope

- UI changes to AIModels.jsx (Ollama/CLI models will appear automatically in the existing models table)
- Remote Ollama cluster support beyond single `OLLAMA_HOST`
- Streaming responses
- Ollama model pulling (`ollama pull`) automation
