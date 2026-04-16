# GitHub Publish Cleanup Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Commit all pending changes, scrub the repository of stale local artifacts, and update README.md, ARCHITECTURE.md, and DOCUMENTATION.md to accurately reflect the current state of the codebase (including the new AI model orchestration layer with Ollama + CLI fallback backends).

**Architecture:** No new code is written. All tasks are repository hygiene and documentation updates. Changes are grouped into three commits: (1) gitignore + pending code, (2) README update, (3) docs update.

**Tech Stack:** Git, Markdown (GitHub-flavoured)

---

## File Map

| File | Change |
|---|---|
| `.gitignore` | Add `core/` to keep the local dev workspace out of the repo |
| `README.md` | Architecture diagram, roadmap, project structure section |
| `docs/ARCHITECTURE.md` | Directory structure section (Section 2) + new Section 21 (AI Model Orchestration) |
| `docs/DOCUMENTATION.md` | Architecture overview box + new Section 3.34 (AI Model Orchestration) |

---

### Task 1: Add `core/` to `.gitignore` and commit pending code changes

The `core/` directory is an untracked local development workspace containing a diverged, older copy of the source. It must never be published. Fourteen source files were modified as part of the Ollama/CLI-fallback feature and the web dashboard fixes — commit them now.

**Files:**
- Modify: `.gitignore`
- Commit: `src/oneinfinity/core/db_manager.py`, `src/oneinfinity/core/pg_client.py`, `src/oneinfinity/infra/model_budget_manager.py`, `src/oneinfinity/mobile/upload_manager.py`, `src/oneinfinity/orchestration/model_orchestrator.py`, `tests/orchestration/test_orchestrator_extensions.py`, `web/backend/daemon_api.py`, `web/backend/graph_api.py`, `web/backend/graph_brain_api.py`, `web/backend/main.py`, `web/backend/orchestrator_api.py`, `web/backend/swarm_intel_api.py`, `web/backend/system_evolution_api.py`, `web/frontend/src/pages/AIModels.jsx`

- [ ] **Step 1: Add `core/` to `.gitignore`**

Open `.gitignore`. After the `# ── OneInfinity runtime data` block at the bottom, add:

```
# ── Local development workspaces ─────────────────────────────────────────────
core/
```

- [ ] **Step 2: Verify `core/` is now ignored**

```bash
cd /home/devendra-yadav/oneinfinity
git status --short | grep core
```

Expected: no output (directory is now ignored and gone from untracked list).

- [ ] **Step 3: Stage all modified tracked files**

```bash
git add .gitignore \
  src/oneinfinity/core/db_manager.py \
  src/oneinfinity/core/pg_client.py \
  src/oneinfinity/infra/model_budget_manager.py \
  src/oneinfinity/mobile/upload_manager.py \
  src/oneinfinity/orchestration/model_orchestrator.py \
  tests/orchestration/test_orchestrator_extensions.py \
  web/backend/daemon_api.py \
  web/backend/graph_api.py \
  web/backend/graph_brain_api.py \
  web/backend/main.py \
  web/backend/orchestrator_api.py \
  web/backend/swarm_intel_api.py \
  web/backend/system_evolution_api.py \
  web/frontend/src/pages/AIModels.jsx
```

- [ ] **Step 4: Verify staged files**

```bash
git status --short
```

Expected: all 15 files shown as `M` (staged), no untracked files except `docs/superpowers/plans/2026-04-11-ollama-cli-fallback.md` and this plan file.

- [ ] **Step 5: Commit**

```bash
git commit -m "$(cat <<'EOF'
feat(orchestration): wire Ollama/CLI backends + web dashboard fixes

- model_orchestrator: auto-discover Ollama models, register Codex/Claude CLI
- model_budget_manager: align field names with web UI expectations
- upload_manager: fix mobile upload dedup path
- db_manager / pg_client: minor hardening
- web backend (6 files): fix response shapes for orchestrator/graph/swarm APIs
- AIModels.jsx: fix model/history array handling, budget field names, cost display
- .gitignore: exclude core/ local dev workspace
EOF
)"
```

---

### Task 2: Update README.md — architecture diagram, roadmap, project structure

Three sections need updating:
1. **Architecture ASCII art** (line ~462) — add an `AI MODEL ORCHESTRATION` layer between the AI Decision Engine and Agent Swarm.
2. **Roadmap** (line ~999) — mark "LLM-driven triage" as `[x]` shipped.
3. **Project structure** (line ~767) — replace the stale flat-file listing with the actual `src/oneinfinity/` subpackage layout.

**Files:**
- Modify: `README.md`

- [ ] **Step 1: Update the architecture ASCII diagram**

In `README.md`, find the block that starts with:

```
┌─────────────────────────────────────────────────────────────────────┐
│                          INPUT LAYER                                │
```

Replace the entire ASCII diagram (from that opening box down through the closing `LEARNING LAYER` box) with:

```
┌─────────────────────────────────────────────────────────────────────┐
│                          INPUT LAYER                                │
│  CLI (55 commands)  ·  Web UI (React, 14 pages)  ·  API (54 routes)│
└───────────────────────────┬─────────────────────────────────────────┘
                            │
┌───────────────────────────▼─────────────────────────────────────────┐
│                        RECON LAYER                                  │
│  subfinder · amass · httpx · katana · waybackurls · naabu · dnsx   │
│  OSINT collector · org-intel mapper · ASN/cert-transparency plugins │
└───────────────────────────┬─────────────────────────────────────────┘
                            │ findings → recon assets
┌───────────────────────────▼─────────────────────────────────────────┐
│                     ATTACK GRAPH ENGINE                             │
│  Nodes (subdomains, endpoints, parameters, credentials, services)   │
│  Edges (resolves-to, hosts, param-of, used-by)                      │
│  15 trigger rules · BFS path finder · Risk scorer                  │
│  PathSimulator · ForceGraph2D visualization                         │
└───────────────────────────┬─────────────────────────────────────────┘
                            │ prioritized node queue
┌───────────────────────────▼─────────────────────────────────────────┐
│                   AI DECISION ENGINE                                │
│  AutonomousDecisionEngine · GraphTriggerEngine                      │
│  Scoring: impact × exploitability × novelty / effort × penalty     │
│  Agent outcome feedback loop (EMA per agent)                        │
└───────────────────────────┬─────────────────────────────────────────┘
                            │ AI task requests
┌───────────────────────────▼─────────────────────────────────────────┐
│               AI MODEL ORCHESTRATION                                │
│  ModelOrchestrator · 3-tier routing (FAST → STANDARD → PREMIUM)    │
│  Providers: OpenAI · Anthropic · Google Gemini · Ollama (local)    │
│  CLI fallbacks: Codex CLI · Claude Code CLI                         │
│  Budget guard · cost-aware routing · models.yaml config             │
└───────────────────────────┬─────────────────────────────────────────┘
                            │ (node, agent) dispatch pairs
┌───────────────────────────▼─────────────────────────────────────────┐
│                     AGENT SWARM (8 agents)                          │
│  XSS · SQLi · SSRF · IDOR · Auth · BizLogic · API · Mobile         │
│  Each agent: hypothesis gen → tool execution → result ingest        │
│  Cross-agent collaboration rules (SQLi→IDOR, SSRF→IDOR, XSS→Auth)  │
└───────────────────────────┬─────────────────────────────────────────┘
                            │ raw findings
┌───────────────────────────▼─────────────────────────────────────────┐
│               RESULT INGESTION ENGINE (singleton)                   │
│  Normalize → SHA-256 dedup → atomic check-and-store (WAL SQLite)   │
│  Broadcast to: attack graph · exploit chain engine · web UI (SSE)  │
└───────────┬───────────────────────────┬─────────────────────────────┘
            │                           │
┌───────────▼──────────┐   ┌────────────▼──────────────────────────────┐
│  VALIDATION ENGINE   │   │     EXPLOIT CHAIN ENGINE                  │
│  Per-type active     │   │  6 patterns (SSRF→Cloud, XSS→ATO,         │
│  re-testing          │   │  SQLi→RCE, IDOR→PrivEsc,                  │
│  CVSS gating         │   │  CORS→CredTheft, Redirect→OAuth)          │
│  FP quarantine       │   │  Step-best-match PoC generation           │
└───────────┬──────────┘   └────────────┬──────────────────────────────┘
            │                           │
┌───────────▼───────────────────────────▼─────────────────────────────┐
│                         OUTPUT LAYER                                │
│  Findings DB (SQLite WAL)  ·  JSON / Markdown / HTML / CSV export  │
│  H1 / Bugcrowd / Intigriti reports  ·  CVSS 3.1  ·  Bounty ROI    │
└───────────────────────────┬─────────────────────────────────────────┘
                            │
┌───────────────────────────▼─────────────────────────────────────────┐
│                       LEARNING LAYER                                │
│  KnowledgeBase (SQLite) · AdaptivePlanner · PatternMiner           │
│  EMA success rates · CapabilitySnapshot · MemoryManager            │
│  Auto-updates ARCHITECTURE.md / SKILLS.md on FEATURE_ADDED events  │
└─────────────────────────────────────────────────────────────────────┘
```

- [ ] **Step 2: Mark LLM-driven triage as shipped in the Roadmap**

Find this line in the `## 📈 Roadmap` section:

```
- [ ] **LLM-driven triage** — local LLM (Ollama/llama.cpp) for autonomous finding severity assessment
```

Replace with:

```
- [x] **LLM-driven triage** — Ollama local LLM backend with auto-discovery, parameter-count tier heuristics, and CLI fallbacks to Codex CLI and Claude Code CLI (shipped in v1.3.0)
```

- [ ] **Step 3: Update the Project Structure section**

Find the `## 📂 Project Structure` section (starts with the fenced code block showing `oneinfinity/`). Replace the entire fenced code block with:

```
oneinfinity/
│
├── oneinfinity.py                  # CLI entry point (55 commands)
├── Makefile                        # Docker convenience targets
├── Dockerfile / Dockerfile.worker  # Multi-stage images
├── docker-compose*.yml             # Single-host and distributed stacks
├── pyproject.toml                  # Single source of truth for all deps
│
├── config/
│   ├── models.yaml                 # AI model registry (tiers, costs, capabilities)
│   ├── agents.yaml                 # Agent configuration
│   ├── graph.yaml                  # Attack graph + Neo4j settings
│   └── neo4j.yaml                  # Neo4j connection config
│
├── src/oneinfinity/                # Main Python package
│   │
│   ├── cli/                        # CLI command modules (split from 5237-line run.py)
│   │   └── commands/               # One module per command group
│   │
│   ├── orchestration/              # Scan pipeline & AI orchestration
│   │   ├── model_orchestrator.py   # Cost-aware 3-tier AI routing
│   │   ├── backends/               # Pluggable AI provider backends
│   │   │   ├── ollama.py           # Ollama local LLM (auto-discovery)
│   │   │   └── cli.py              # Codex CLI + Claude Code CLI fallbacks
│   │   ├── autonomous_decision_engine.py
│   │   ├── god_mode_engine.py
│   │   ├── event_bus.py
│   │   └── enforcement_controller.py
│   │
│   ├── recon/                      # Recon & OSINT engines
│   ├── scan/                       # Vulnerability scanning engines
│   ├── attack/                     # Exploit generation & replay
│   ├── attack_graph_core/          # Attack graph (merged attack_graph/ + core)
│   ├── swarm/                      # 8-agent swarm + coordinator
│   ├── intelligence/               # Decision engine, graph triggers, daemon
│   ├── findings/                   # Finding ingestion, dedup, validation
│   ├── exploit_chains/             # 6 chain patterns + PoC generator
│   ├── bounty/                     # Bug bounty hunter, report generator
│   ├── ai_security/                # AI red-team, prompt injection, framework wrappers
│   ├── mobile/                     # 12-phase mobile security pipeline
│   ├── infra/                      # Model budget, task classifier, shared infra
│   ├── learning/                   # AdaptivePlanner, KnowledgeBase, PatternMiner
│   ├── pipeline/                   # 7-phase autonomous scan pipeline
│   ├── agents/                     # Agent base classes + secret intel agent
│   ├── modules/                    # Tool wrappers, payload lib, CVSS, scope
│   ├── core/                       # DB manager, PG client, dedup, cache, profiles
│   ├── framework/                  # OWASP framework orchestrator
│   └── plugins/                    # Hot-reloadable recon + vuln plugins
│
├── web/
│   ├── backend/                    # FastAPI backend (54 routes)
│   └── frontend/                   # React UI (14 pages, SSE live stream)
│
├── tests/                          # Test suite
│   └── orchestration/              # Orchestrator + backend tests
│
├── scripts/                        # Setup scripts (postgres, redis, neo4j)
├── services/                       # Redis, nginx, Prometheus, Grafana configs
├── db/                             # DB schema (schema.sql)
└── docs/                           # All documentation
    ├── ARCHITECTURE.md
    ├── DOCUMENTATION.md
    ├── CHANGELOG.md
    ├── CONTRIBUTING.md
    ├── DOCKER.md
    └── SECURITY.md
```

- [ ] **Step 4: Stage and commit**

```bash
cd /home/devendra-yadav/oneinfinity
git add README.md
git commit -m "docs(readme): update architecture diagram, roadmap, and project structure

- Add AI MODEL ORCHESTRATION layer to architecture ASCII diagram
- Mark LLM-driven triage (Ollama) as shipped [x] in roadmap
- Replace stale flat-file project structure with actual src/oneinfinity/ subpackage layout"
```

---

### Task 3: Update `docs/ARCHITECTURE.md` — directory structure + new AI Model Orchestration section

Two changes:
1. Section 2 (Project Directory Structure) — the current listing shows the old pre-reorg flat files. Replace it with the actual `src/oneinfinity/` subpackage layout.
2. Add **Section 21: AI Model Orchestration** after Section 20.

**Files:**
- Modify: `docs/ARCHITECTURE.md`

- [ ] **Step 1: Replace Section 2 directory structure**

In `docs/ARCHITECTURE.md`, find the fenced code block under `## 2. Project Directory Structure` (starts at line ~50 with `oneinfinity/` and lists flat `.py` files). Replace that entire fenced block with:

```
oneinfinity/
│
├── oneinfinity.py                        # CLI entry point (55 commands, argparse)
├── pyproject.toml                        # Single dependency source (extras: web, ai, mobile)
│
├── ── DOCKER / DISTRIBUTED ──────────────────────────────────────────────────
│
├── Dockerfile                            # 3-stage multi-arch image (go-tools → py-builder → final)
├── Dockerfile.worker                     # Capability-scoped worker image
├── docker-compose.yml                    # Single-host compose (cli, backend, frontend)
├── docker-compose.distributed.yml        # Full distributed stack (15 services)
├── docker-entrypoint.sh                  # Container entrypoint
├── Makefile                              # 30 convenience targets (setup, up, scale, scan, purge)
├── .env.example                          # Template for all environment variables
│
├── config/
│   ├── models.yaml                       # AI model registry (providers, tiers, budget, routing)
│   ├── agents.yaml                       # Agent capability and concurrency config
│   ├── graph.yaml                        # Attack graph settings
│   └── neo4j.yaml                        # Neo4j connection config
│
├── services/                             # Infrastructure service configs
│   ├── redis/redis.conf                  # Hardened Redis config
│   ├── nginx/nginx.conf                  # Reverse proxy + rate limiting
│   └── prometheus/                       # Prometheus + Grafana provisioning
│
├── ── PYTHON PACKAGE ────────────────────────────────────────────────────────
│
├── src/oneinfinity/
│   │
│   ├── cli/                              # CLI command modules (split from 5237-line run.py)
│   │   └── commands/                     # One file per command group
│   │
│   ├── orchestration/                    # Scan pipeline & AI model orchestration
│   │   ├── model_orchestrator.py         # Cost-aware 3-tier AI routing engine
│   │   ├── backends/                     # Pluggable AI provider backends
│   │   │   ├── __init__.py               # BaseBackend registry + BackendResult dataclass
│   │   │   ├── ollama.py                 # Ollama local LLM (auto-discover, tier heuristics)
│   │   │   └── cli.py                    # Codex CLI + Claude Code CLI subprocess backends
│   │   ├── autonomous_decision_engine.py # AI-driven node → agent dispatch
│   │   ├── god_mode_engine.py            # Full-autonomy scan controller
│   │   ├── graph_trigger_engine.py       # 15 rule-based graph triggers
│   │   ├── event_bus.py                  # Async publish/subscribe event bus
│   │   ├── enforcement_controller.py     # Scope + rate-limit enforcement
│   │   └── research_mode_controller.py   # Autonomous research loop
│   │
│   ├── recon/                            # Recon & OSINT engines
│   ├── scan/                             # Vulnerability scanning engines
│   ├── attack/                           # Exploit generation & replay
│   ├── attack_graph_core/                # Attack graph model, builder, analyzer, path simulator
│   ├── swarm/                            # 8-agent swarm + coordinator
│   ├── intelligence/                     # Daemon, swarm controller, attack simulation
│   ├── findings/                         # Result ingestion, dedup, validation, classifier
│   ├── exploit_chains/                   # 6 chain patterns + PoC generator + engine
│   ├── bounty/                           # Bug bounty hunter, ROI engine, report generator
│   ├── ai_security/                      # AI red-team, prompt injection, framework wrappers
│   ├── mobile/                           # 12-phase mobile pipeline + tool wrappers
│   ├── infra/                            # ModelBudgetManager, TaskClassifier, shared infra
│   ├── learning/                         # AdaptivePlanner, KnowledgeBase, PatternMiner
│   ├── pipeline/                         # 7-phase autonomous scan pipeline orchestrator
│   ├── agents/                           # BaseAgent, coordinator, SecretIntelAgent
│   ├── modules/                          # Tool wrappers (40+), payload library, scope, CVSS
│   ├── core/                             # DBManager, PG client, dedup, cache, scan profiles
│   ├── framework/                        # OWASP framework orchestrator
│   └── plugins/                          # Hot-reloadable recon + vuln plugins
│
├── web/
│   ├── backend/                          # FastAPI backend (54 routes)
│   └── frontend/                         # React UI (14 pages, SSE live stream)
│
├── tests/
│   └── orchestration/                    # ModelOrchestrator + backend integration tests
│
├── scripts/                              # Native install scripts (postgres, redis, neo4j)
├── db/                                   # DB schema
└── docs/                                 # Documentation
```

- [ ] **Step 2: Add Section 21 — AI Model Orchestration**

At the very end of `docs/ARCHITECTURE.md`, append:

```markdown
---

## 21. AI Model Orchestration

### Overview

`src/oneinfinity/orchestration/model_orchestrator.py` is the central AI routing engine. Every component that needs an LLM (decision engine, hypothesis generator, report writer, etc.) goes through `ModelOrchestrator.execute()` — never calls a provider API directly.

### Three-Tier Routing

| Tier | Class | Default providers | Use case |
|------|-------|-------------------|----------|
| FAST | 1 | gpt-4o-mini, claude-haiku-4-5, llama3.2:3b (Ollama), Codex CLI | High-volume, low-complexity tasks (RECON, OSINT) |
| STANDARD | 2 | gpt-4o, claude-sonnet-4-6, deepseek-r1:7b (Ollama) | Most tasks (VULN_ANALYSIS, HYPOTHESIS, CHAIN_DETECTION) |
| PREMIUM | 3 | claude-opus-4-6, GPT-o1 | Complex reasoning (EXPLOIT_GEN, BIZ_LOGIC) |

Escalation is automatic: if a FAST model returns confidence below `0.65`, the same task is re-sent to a STANDARD model.

### Provider Backends (`orchestration/backends/`)

All backends implement `BaseBackend`:

```python
class BaseBackend:
    provider: str            # "openai" | "anthropic" | "ollama" | "codex" | "claude-cli"
    def is_available(self) -> bool: ...
    def call(self, model_id, prompt, system, temperature, max_tokens) -> BackendResult: ...
```

| Backend | File | Trigger |
|---------|------|---------|
| `OllamaBackend` | `backends/ollama.py` | `provider: ollama` in models.yaml; auto-registered via `/api/tags` discovery |
| `CodexCliBackend` | `backends/cli.py` | `codex` binary on PATH; registered as `codex-cli` model |
| `ClaudeCliBackend` | `backends/cli.py` | `claude` binary on PATH; registered as `claude-cli` model |

Backends are registered at import time via `@register_backend`. The orchestrator resolves a provider name to its backend at call time.

### Ollama Auto-Discovery

On startup, `ModelOrchestrator._auto_discover_ollama()` queries `GET {OLLAMA_HOST}/api/tags`. Each returned model that is not already in the YAML registry is auto-registered with:
- **Tier** assigned by parameter count heuristic (≥70B → PREMIUM, 27–34B → STANDARD, else FAST)
- **Cost** = $0.00 (local inference)
- **Capabilities** = all TaskCategory values

Explicit YAML entries take precedence over auto-discovered models.

### CLI Fallbacks

`CodexCliBackend` (`codex exec -m <model>`) and `ClaudeCliBackend` (`claude -p --model <model>`) are registered automatically when their binaries are detected on `PATH`. The orchestrator routes to them when:
- The `cli_fallback.on_errors` list in `models.yaml` includes `auth` (HTTP 401/403) or `quota` (budget exhausted)
- No other enabled backend can serve the task

CLI backends record `cost = 0.0` locally (billed through the user's own accounts).

### Configuration (`config/models.yaml`)

```yaml
models:
  gpt-4o-mini:
    provider: openai
    tier: FAST
    cost_per_1k_input: 0.00015
    cost_per_1k_output: 0.00060
    enabled: true
    capabilities: [RECON, HYPOTHESIS, ...]

ollama:
  host: "http://localhost:11434"
  auto_discover: true
  prefer_over_api: false

cli_fallback:
  enabled: true
  codex_model: "o4-mini"
  claude_model: "claude-opus-4-6"
  on_errors: [auth, quota]

budget:
  daily_limit_usd: 5.00
  monthly_limit_usd: 50.00
```

### Budget Tracking

`ModelBudgetManager` (`src/oneinfinity/infra/model_budget_manager.py`) records every call's token counts and cost. The orchestrator checks the daily/monthly budget before dispatching. At 80% of limit, an alert fires. At 100%, the call is redirected to a zero-cost backend (Ollama or CLI) if available, or rejected.

### Web UI

The **AI Models** page (`web/frontend/src/pages/AIModels.jsx`) shows:
- All registered models (ID, tier, capabilities, cost per 1k tokens in+out, enabled status)
- Today's spend, total calls, projected monthly cost
- Live model execution test panel
- Recent execution history

The page reads from `/api/orchestrator/status`, `/api/orchestrator/models`, `/api/orchestrator/budget`, and `/api/orchestrator/history`.
```

- [ ] **Step 3: Stage and commit**

```bash
cd /home/devendra-yadav/oneinfinity
git add docs/ARCHITECTURE.md
git commit -m "docs(architecture): update directory structure + add Section 21 AI Model Orchestration

- Section 2: replace stale flat-file listing with actual src/oneinfinity/ subpackage layout
- Section 21 (new): documents ModelOrchestrator, 3-tier routing, OllamaBackend,
  CodexCliBackend, ClaudeCliBackend, auto-discovery, CLI fallbacks, budget tracking,
  models.yaml config, and web UI"
```

---

### Task 4: Update `docs/DOCUMENTATION.md` — architecture overview + new section 3.34

Two changes:
1. Replace the architecture overview box (around line 86–107) with the updated diagram that includes the AI Model Orchestration layer.
2. Append new **Section 3.34: AI Model Orchestration** after the existing Section 3.33.

**Files:**
- Modify: `docs/DOCUMENTATION.md`

- [ ] **Step 1: Update the architecture overview box**

In `docs/DOCUMENTATION.md`, find the fenced code block under `## Architecture Overview` (the one with `CLI / Web UI`, `Unified Scan Engine`, `Recon Layer`, etc.). Replace the entire fenced block with:

```
┌─────────────────────────────────────────────────────────────────┐
│                        CLI / Web UI                              │
├─────────────────────────────────────────────────────────────────┤
│              Unified Scan Engine (9-phase orchestrator)          │
│  classify → recon → graph → agent → vuln → exploit →            │
│  ingest → report → done                                          │
├──────────────┬──────────────┬──────────────┬────────────────────┤
│ Recon Layer  │ Vuln Layer   │ Exploit Layer│ Intelligence Layer  │
│ subfinder    │ nuclei       │ ExploitChain │ AttackGraphBrain    │
│ httpx        │ dalfox       │ PocGenerator │ LearningSystem      │
│ katana       │ sqlmap       │ AttackReplay │ ResearchMode        │
│ waybackurls  │ custom tests │ ZeroDay      │ KnowledgeBase       │
├──────────────┴──────────────┴──────────────┴────────────────────┤
│           Agents Layer (BaseAgent threads, coordinator)          │
│  ReconAgent │ ScanAgent │ ExploitAgent │ ValidationAgent        │
│  ReportAgent │ SecretIntelAgent                                  │
├─────────────────────────────────────────────────────────────────┤
│              AI Model Orchestration                              │
│  ModelOrchestrator · 3-tier routing (FAST → STANDARD → PREMIUM) │
│  OpenAI · Anthropic · Gemini · Ollama · Codex CLI · Claude CLI  │
│  Budget guard · cost-aware escalation · models.yaml config      │
├─────────────────────────────────────────────────────────────────┤
│            Persistence (SQLite · PostgreSQL · JSON)              │
│  findings.db · recon_cache.db · knowledge_base.db · raw/         │
└─────────────────────────────────────────────────────────────────┘
```

- [ ] **Step 2: Find the end of Section 3.33 and append Section 3.34**

Locate the end of Section 3.33 (Continuous Learning System). After it, add:

```markdown
### 3.34 AI Model Orchestration

OneInfinity routes all AI calls through a central `ModelOrchestrator` that selects the cheapest capable model, escalates on low confidence, enforces a daily spend budget, and falls back to free local providers when API keys are unavailable or quota is exhausted.

#### Providers

| Provider | How it's used | Cost |
|---|---|---|
| OpenAI (gpt-4o-mini, gpt-4o) | API via `OPENAI_API_KEY` | Paid per token |
| Anthropic (Haiku/Sonnet/Opus) | API via `ANTHROPIC_API_KEY` | Paid per token |
| Google Gemini | OAuth via Gemini CLI | Free tier |
| Ollama (local) | HTTP at `OLLAMA_HOST` (default `localhost:11434`) | Free |
| Codex CLI | `codex exec` subprocess | Billed to user's OpenAI account |
| Claude Code CLI | `claude -p` subprocess | Billed to user's Anthropic account |

#### Using Ollama (free local LLM)

1. Install Ollama: https://ollama.com/download
2. Pull a model: `ollama pull deepseek-r1:7b`
3. Start Ollama (it runs as a background service automatically)
4. Set env (optional, defaults to localhost): `export OLLAMA_HOST=http://localhost:11434`

OneInfinity auto-discovers all running Ollama models at startup — no config file changes needed. You can override defaults in `config/models.yaml` under the `ollama:` key.

#### Using CLI fallbacks

If `codex` or `claude` are on your PATH, they are automatically registered as zero-cost fallback backends. They activate on API auth errors (401/403) or when the daily budget is exhausted.

```bash
# Install Codex CLI
npm install -g @openai/codex

# Install Claude Code CLI
npm install -g @anthropic-ai/claude-code
```

#### Budget control (`config/models.yaml`)

```yaml
budget:
  daily_limit_usd: 5.00       # hard stop at this amount per day
  monthly_limit_usd: 50.00    # soft cap for monitoring
  alert_threshold: 0.80       # notify at 80% of daily limit
  per_model_daily_limit:
    gpt-4o: 2.00              # per-model cap
```

When the daily budget is exhausted, all tasks are re-routed to Ollama or CLI backends. If no zero-cost backend is available, the call is rejected with a clear error.

#### Checking model status

```bash
python3 oneinfinity.py doctor
# Look for: [ModelOrchestrator] N models loaded (X enabled)

# Or check the web UI → AI Models page
```

#### Routing tiers

| Tier | Models | Used for |
|---|---|---|
| FAST | gpt-4o-mini, llama3.2:3b, claude-haiku-4-5 | Recon, OSINT, hypothesis generation |
| STANDARD | gpt-4o, deepseek-r1:7b, claude-sonnet-4-6 | Vuln analysis, chain detection, payload mutation |
| PREMIUM | claude-opus-4-6 | Exploit generation, business logic, complex reasoning |

The orchestrator escalates automatically when a model returns low-confidence output (threshold configurable in `models.yaml`).
```

- [ ] **Step 3: Update the Table of Contents entry count and add 3.34**

In `docs/DOCUMENTATION.md`, find the Table of Contents entry for `3.33 Continuous Learning System`. After it, add:

```
   - [3.34 AI Model Orchestration](#334-ai-model-orchestration)
```

- [ ] **Step 4: Stage and commit**

```bash
cd /home/devendra-yadav/oneinfinity
git add docs/DOCUMENTATION.md
git commit -m "docs(documentation): update arch overview + add Section 3.34 AI Model Orchestration

- Architecture overview box: add AI Model Orchestration layer
- Section 3.34 (new): Ollama setup, CLI fallbacks, budget control, routing tiers, CLI reference"
```

---

### Task 5: Stage plan files and push

- [ ] **Step 1: Stage both plan files**

```bash
cd /home/devendra-yadav/oneinfinity
git add docs/superpowers/plans/2026-04-11-ollama-cli-fallback.md \
        docs/superpowers/plans/2026-04-16-github-publish-cleanup.md
git commit -m "docs: add ollama/cli-fallback and publish-cleanup plan files"
```

- [ ] **Step 2: Verify the repo is clean**

```bash
git status
```

Expected:
```
On branch main
nothing to commit, working tree clean
```

- [ ] **Step 3: Final review — check nothing sensitive is staged**

```bash
git log --oneline -6
git diff origin/main --stat
```

Confirm no `.env`, secrets, or database files appear in the diff.

- [ ] **Step 4: Push to GitHub**

```bash
git push origin main
```

Expected: push completes with no errors. Verify at `https://github.com/Inf1n1tyDeS0ul/oneinfinity`.
