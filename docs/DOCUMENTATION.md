# OneInfinity — Complete Documentation

> **AI-Powered Offensive Security Research Framework**
> Autonomous vulnerability discovery, exploit chaining, mobile security, AI pentesting, web3 security, and bug bounty automation — all from a single tool.
> **Version 2.0.0 — 2026-06-29**

---

## Table of Contents

1. [Introduction](#1-introduction)
2. [Installation & Setup](#2-installation--setup)
   - [2a. One-Click Installer](#2a-one-click-installer)
   - [2b. AI-Assisted Setup](#2b-ai-assisted-setup)
   - [2c. Docker Installation](#2c-docker-installation)
   - [2d. Native Python Installation](#2d-native-python-installation)
3. [Feature Documentation](#3-feature-documentation)
   - [3.1 Workspace Management](#31-workspace-management)
   - [3.2 Recon & Enumeration](#32-recon--enumeration)
   - [3.3 Adaptive Recon](#33-adaptive-recon)
   - [3.4 Vulnerability Scanning](#34-vulnerability-scanning)
   - [3.5 Secret Scanning](#35-secret-scanning)
   - [3.6 Secret Intel Agent (GitHub)](#36-secret-intel-agent-github)
   - [3.7 Directory & Content Fuzzing](#37-directory--content-fuzzing)
   - [3.8 Application Intelligence](#38-application-intelligence)
   - [3.9 Vulnerability Theory Engine](#39-vulnerability-theory-engine)
   - [3.10 Custom Attack Tests](#310-custom-attack-tests)
   - [3.11 Zero-Day Anomaly Detection](#311-zero-day-anomaly-detection)
   - [3.12 Exploit Chain Detection & PoC Generation](#312-exploit-chain-detection--poc-generation)
   - [3.13 Attack Graph Engine](#313-attack-graph-engine)
   - [3.14 Autonomous Research Mode](#314-autonomous-research-mode)
   - [3.15 Multi-Agent Autonomous Pentest](#315-multi-agent-autonomous-pentest)
   - [3.16 Swarm Intelligence](#316-swarm-intelligence)
   - [3.17 Attack Simulation (Monte Carlo)](#317-attack-simulation-monte-carlo)
   - [3.18 AI Security Testing](#318-ai-security-testing)
   - [3.19 AI Red Team Campaigns](#319-ai-red-team-campaigns)
   - [3.20 AI Agent Pentesting](#320-ai-agent-pentesting)
   - [3.21 Mobile Security Analysis](#321-mobile-security-analysis)
   - [3.22 Traffic Capture & Replay](#322-traffic-capture--replay)
   - [3.23 Bug Bounty Hunter (Autonomous)](#323-bug-bounty-hunter-autonomous)
   - [3.24 Scan Profiles](#324-scan-profiles)
   - [3.25 Findings Management](#325-findings-management)
   - [3.26 Reporting](#326-reporting)
   - [3.27 Payload Library & WAF Bypass](#327-payload-library--waf-bypass)
   - [3.28 CVSS Calculator](#328-cvss-calculator)
   - [3.29 Workflow Orchestration](#329-workflow-orchestration)
   - [3.30 CI/CD Integration](#330-cicd-integration)
   - [3.31 Plugin System](#331-plugin-system)
   - [3.32 Recon Cache](#332-recon-cache)
   - [3.33 Continuous Learning System](#333-continuous-learning-system)
   - [3.34 AI Model Orchestration](#334-ai-model-orchestration)
   - [3.35 Web3 / Smart Contract Security](#335-web3--smart-contract-security)
   - [3.36 Nim Payload Arsenal](#336-nim-payload-arsenal)
   - [3.37 Authenticated Testing Suite](#337-authenticated-testing-suite)
   - [3.38 Android Companion App](#338-android-companion-app)
   - [3.39 iOS Companion App](#339-ios-companion-app)
   - [3.40 MCP Integration](#340-mcp-integration)
   - [3.41 God Mode](#341-god-mode)
   - [3.42 CI/CD Vulnerability Scanner](#342-cicd-vulnerability-scanner)
4. [Target Setup Guides](#4-target-setup-guides)
5. [Advanced Features](#5-advanced-features)
6. [CLI Reference](#6-cli-reference)
7. [Web UI Guide](#7-web-ui-guide)
8. [Troubleshooting](#8-troubleshooting)
9. [Roadmap](#9-roadmap)

---

# 1. Introduction

## What is OneInfinity?

OneInfinity is a production-grade, AI-powered offensive security research framework designed for bug bounty hunters, penetration testers, and security engineers. It orchestrates the full vulnerability lifecycle — from subdomain enumeration and recon through exploit chain generation and report filing — with minimal human intervention.

Unlike point tools (Nuclei, Burp Suite, MobSF), OneInfinity is a **unified platform** that connects every phase of a security assessment into an autonomous, self-improving pipeline.

## Key Capabilities

| Capability | Description |
|---|---|
| **Autonomous Recon** | Subdomain discovery, HTTP probing, JS endpoint extraction, cloud asset mapping |
| **Intelligent Scanning** | 80+ vulnerability engines orchestrated by an AI capability map |
| **Secret Intelligence** | GitHub dork-based secret hunting with AI validation and live testing |
| **AI Security Testing** | Prompt injection, jailbreaks, RAG attacks, LLM DoS, supply chain scanning |
| **Mobile Security** | Full APK/IPA pipeline: static, dynamic, secrets, ADB forensics, deep-link fuzzing |
| **Web3 Security** | 14 EVM vulnerability classes, Solana scanner, Foundry PoC generation |
| **Nim Arsenal** | SHA-256 verified Nim binaries: shell gen, bypass gen, fuzzer, privesc |
| **Authenticated Testing** | Session recording, multi-account IDOR, credential spraying, auth replay |
| **MCP Integration** | HackerOne scope + program discovery via MCP tools |
| **Attack Graph** | BFS-based attack path modeling — NetworkX + optional Neo4j backend |
| **Exploit Chaining** | 6 predefined chain patterns with PoC script generation |
| **Autonomous Research** | Iterative research loop: theorize → test → confirm → report |
| **Bug Bounty Hunter** | Fully autonomous: discovers programs, prioritizes targets, scans, files reports |
| **God Mode** | 6-stage maximum-autonomy cascade covering all subsystems |
| **Web UI** | React dashboard (43 pages) with live WebSocket updates |

## Architecture Overview

```
┌─────────────────────────────────────────────────────────────────┐
│                   CLI / Web UI (43 pages)                        │
├─────────────────────────────────────────────────────────────────┤
│              Unified Scan Engine (17-phase orchestrator)         │
│  classify → recon → graph → agent → vuln → exploit →            │
│  ingest → report → done                                          │
├──────────────┬──────────────┬──────────────┬────────────────────┤
│ Recon Layer  │ Vuln Layer   │ Exploit Layer│ Intelligence Layer  │
│ subfinder    │ nuclei       │ ExploitChain │ AttackGraphBrain    │
│ httpx/katana │ dalfox/sqlmap│ PocGenerator │ LearningSystem      │
│ adaptive     │ 80+ engines  │ AttackReplay │ KnowledgeBase       │
├──────────────┴──────────────┴──────────────┴────────────────────┤
│  Web3 Layer  │ Auth Layer   │ Mobile Layer │ Nim Arsenal Layer   │
│ SlitherWrap  │ SessionMgr   │ 12+ phases   │ 6 Nim binaries      │
│ FoundryPoC   │ IDOR engine  │ ADB forensics│ SHA-256 verified    │
├──────────────┴──────────────┴──────────────┴────────────────────┤
│              AI Model Orchestration                              │
│  3-tier (FAST/STANDARD/PREMIUM) · Ollama auto-discovery         │
│  Budget guard · CLI fallbacks (codex exec, claude -p)           │
├─────────────────────────────────────────────────────────────────┤
│         Persistence (SQLite · PostgreSQL · Neo4j · Redis)        │
└─────────────────────────────────────────────────────────────────┘
```

---

# 2. Installation & Setup

## 2a. One-Click Installer

The fastest way to get started on any supported platform:

```bash
git clone https://github.com/Inf1n1tyDeS0ul/oneinfinity.git
cd oneinfinity
bash install.sh
```

`install.sh` handles:
- Python 3.10+ check and pip installation
- `pip install -e ".[ai,mobile,web,distributed]"`
- Go toolchain installation (if not present)
- All Go security tools (`subfinder`, `httpx`, `katana`, `nuclei`, `dalfox`, etc.)
- Optional: PostgreSQL, Redis, Neo4j setup (prompted)
- Nim binary SHA-256 verification
- Web UI dependency installation (Node.js + npm)

**Flags:**
```bash
bash install.sh --no-go-tools     # Skip Go tool installation
bash install.sh --no-ui           # Skip web UI setup
bash install.sh --docker-only     # Only set up Docker environment
bash install.sh --minimal         # Python package only
```

Supported platforms: Linux (Debian/Ubuntu/Arch), macOS (Intel/Apple Silicon), WSL2.

---

## 2b. AI-Assisted Setup

If you have Claude Code or Gemini CLI installed, you can use AI-assisted setup:

```bash
# With Claude Code CLI
claude -p "Set up OneInfinity in this directory. Run install.sh, configure .env, verify the doctor check passes."

# With Gemini CLI
gemini "Set up the OneInfinity offensive security framework in the current directory."
```

The AI will guide through credential setup, tool installation, and initial configuration.

---

## 2c. Docker Installation

Docker is the recommended method for isolated deployments. All Go tools, Python dependencies, and system packages are baked into the image.

### Prerequisites

- Docker 24+ and Docker Compose v2
- 8 GB RAM (16 GB recommended for full stack with monitoring)

### Quick Start

```bash
git clone https://github.com/Inf1n1tyDeS0ul/oneinfinity.git
cd oneinfinity

# Create .env and data directories
make setup

# Edit .env — at minimum set ONEINFINITY_API_KEY
nano .env

# Build images (~5 min on first run)
make build

# Start the full distributed stack
make up
# Dashboard: http://localhost
# Grafana:   http://localhost:3001
# API docs:  http://localhost/api/docs
```

### Running a Scan via Docker

```bash
make scan T=example.com
make recon T=example.com
make vuln-scan T=example.com
make scale-recon N=4    # scale recon workers
make scale-vuln N=3     # scale vuln workers
make findings
```

### Single-Container CLI

```bash
docker run --rm \
  -v ~/.oneinfinity:/data \
  -e ONEINFINITY_API_KEY=<key> \
  ghcr.io/inf1n1tydes0ul/oneinfinity:latest \
  scan example.com --yes
```

### Docker Image Variants

| Tag | Contents | Use case |
|---|---|---|
| `latest` | Core tools + Python stack | Standard scanning |
| `latest-ai` | Core + AI/ML libraries | AI red teaming |

---

## 2d. Native Python Installation

### Requirements

| Requirement | Version | Notes |
|---|---|---|
| Python | 3.10+ | Required |
| Node.js | 18+ | For Web UI only |
| npm | 9+ | For Web UI only |
| Git | Any | Required |
| Linux/macOS | — | Windows: WSL2 recommended |

### Install

```bash
git clone https://github.com/Inf1n1tyDeS0ul/oneinfinity.git
cd oneinfinity

# Install all extras
pip install -e ".[ai,mobile,web,distributed]"

# Or minimal install
pip install -e "."

# Or specific extras
pip install -e ".[ai]"          # AI/ML libraries for AI red teaming
pip install -e ".[mobile]"      # Frida, MobSF, mobile tooling
pip install -e ".[web]"         # Web UI backend dependencies
pip install -e ".[distributed]" # Redis, Celery, PostgreSQL client
```

### Optional External Security Tools

```bash
# Recon
go install github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest
go install github.com/projectdiscovery/httpx/cmd/httpx@latest
go install github.com/projectdiscovery/katana/cmd/katana@latest
go install github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest
go install github.com/projectdiscovery/naabu/v2/cmd/naabu@latest
go install github.com/projectdiscovery/dnsx/cmd/dnsx@latest
go install github.com/lc/gau/v2/cmd/gau@latest
go install github.com/tomnomnom/waybackurls@latest

# Web Vuln
go install github.com/hahwul/dalfox/v2@latest
pip install sqlmap

# Secrets
pip install trufflehog
go install github.com/zricethezav/gitleaks/v8@latest

# Content Discovery
go install github.com/ffuf/ffuf/v2@latest

# Mobile
pip install mobsf frida-tools objection

# Smart contracts
pip install slither-analyzer
```

### Configure Environment Variables

```bash
export GITHUB_TOKEN="ghp_your_token_here"
export OPENAI_API_KEY="sk-your-key-here"
export ANTHROPIC_API_KEY="sk-ant-your-key-here"
export ONEINFINITY_API_KEY="your-stable-key"
export OOB_DOMAIN="your-collaborator.burpcollaborator.net"
export HACKERONE_API_TOKEN="your-h1-token"
export HACKERONE_USERNAME="your-h1-username"

# Optional: distributed storage
export POSTGRES_URL="postgresql://user:pass@localhost:5432/oneinfinity"
export REDIS_URL="redis://localhost:6379"

# Optional: Neo4j graph backend
export NEO4J_ENABLED=1
export NEO4J_URI="bolt://localhost:7687"
```

### Verify Installation

```bash
python run.py doctor
python run.py toolcheck
```

### Start the Web UI

```bash
# Terminal 1 — Backend API
cd web/backend
uvicorn main:app --host 0.0.0.0 --port 8000

# Terminal 2 — Frontend
cd web/frontend
npm install
npm run dev
```

Open `http://localhost:3000`.

---

# 3. Feature Documentation

---

## 3.1 Workspace Management

### What It Does

Creates a structured workspace with a `scope.yaml` file defining in-scope targets, out-of-scope exclusions, and engagement metadata. All subsequent commands respect this scope automatically.

### How to Use (CLI)

```bash
# Bug bounty mode
python run.py setup <workspace-name> [--target <domain>]

# Pentest mode
python run.py setup <workspace-name> --pentest --target <domain>
```

**Flags:**

| Flag | Description |
|---|---|
| `<name>` | Workspace name (required) |
| `--target` | Add a target domain (repeatable) |
| `--pentest` | Engagement mode — disables platform-specific report formatting |

### Real Example

```bash
python run.py setup vulnbank-bounty --target vulnbank.org
```

**Expected Output:**
```
[*] Workspace created: vulnbank-bounty/
[*] scope.yaml written with 1 target(s)
[*] Run: python run.py scan vulnbank.org --yes
```

### System Health Check

```bash
python run.py doctor [--quick] [--deep] [--json]
```

---

## 3.2 Recon & Enumeration

### What It Does

Runs a comprehensive passive/active recon pipeline: subdomain discovery → HTTP probing → URL crawling → content enumeration.

### Pipeline

1. **Subdomain Discovery** — `subfinder`, `amass`, `assetfinder`, `findomain`, `chaos`, `crtsh` in parallel
2. **DNS Resolution** — `dnsx` resolves and filters dead hosts
3. **HTTP Probing** — `httpx` captures status codes, titles, tech headers
4. **URL Crawling** — `katana`, `hakrawler`, `gauplus`, `waybackurls`
5. **Content Discovery** — `paramspider` and `arjun` extract parameters

### How to Use (CLI)

```bash
python run.py recon <domain> [options]
```

**Flags:**

| Flag | Default | Description |
|---|---|---|
| `--output DIR` | `~/.oneinfinity/raw/<domain>/` | Output directory |
| `--rate N` | 30 | Requests per minute |
| `--no-ports` | false | Skip port scanning |
| `--no-crawl` | false | Skip URL crawling |

### Real Example

```bash
python run.py recon vulnbank.org --output ./vulnbank-recon
```

**Output Files:**
```
vulnbank-recon/recon/
├── subdomains.json
├── alive_hosts.json
├── urls.json
├── tech_profile.json
└── api_map.json
```

---

## 3.3 Adaptive Recon

### What It Does

Tech-stack-aware reconnaissance that selects probes based on detected technologies: JS endpoint extraction for SPAs, cloud asset enumeration for AWS-hosted targets, GraphQL introspection for API-heavy applications.

### How to Use (CLI)

```bash
python run.py adaptive-recon <domain> [--depth quick|standard|deep] [--json] [--no-graph]
```

### Real Example

```bash
python run.py adaptive-recon vulnbank.org --depth deep --json
```

---

## 3.4 Vulnerability Scanning

### What It Does

Orchestrates 80+ vulnerability scanning engines across discovered targets, coordinated by a capability map that selects the right tool for each vulnerability class.

### Default Tool Set

- **Nuclei** — 9000+ templates (CVEs, misconfigs, exposures)
- **Dalfox** — XSS detection with reflection analysis
- **SQLMap** — SQL injection detection and exploitation
- **KXSS** — Blind/DOM XSS parameter reflection
- **CRLFuzz** — CRLF injection
- **Nikto** — Web server misconfiguration
- **XSStrike** — Advanced XSS
- **Commix** — Command injection

### How to Use (CLI)

```bash
python run.py vuln-scan <domain> [options]
```

**Flags:**

| Flag | Default | Description |
|---|---|---|
| `--rate N` | 150 | Nuclei rate limit (req/sec) |
| `--severity SEV` | `medium,high,critical` | Severity filter |
| `--oob URL` | — | OOB callback URL |

---

## 3.5 Secret Scanning

### What It Does

Scans filesystems, Git repositories, GitHub organizations, S3 buckets, and Docker images for exposed secrets using `trufflehog` and `gitleaks`.

### How to Use (CLI)

```bash
python run.py secrets <target> [--type filesystem|git|github|s3|gcs|docker]
```

---

## 3.6 Secret Intel Agent (GitHub)

### What It Does

AI-validated GitHub secret intelligence: 50+ dorks, 150+ regex patterns, live validation, ownership attribution, risk scoring, multi-token rotation.

### How to Use (CLI)

```bash
python run.py secrets-scan --target <org> [options]
```

**Flags:**

| Flag | Default | Description |
|---|---|---|
| `--target ORG` | required | GitHub org name or domain |
| `--github-token TOKEN` | `$GITHUB_TOKEN` | GitHub API token |
| `--github-token-file FILE` | — | File with multiple tokens (one per line) |
| `--mode fast|balanced|thorough` | `balanced` | Scan thoroughness |
| `--max-dorks N` | 50 | Maximum dorks to execute |
| `--adaptive-throttle` | false | Auto-adjust rate |

---

## 3.7 Directory & Content Fuzzing

### What It Does

Discovers hidden directories, files, backup files, admin panels, API endpoints using wordlist-based fuzzing via `ffuf`, `gobuster`, `dirsearch`.

### How to Use (CLI)

```bash
python run.py fuzz <domain|url> [--extensions php,html,js,json] [--threads 50]
```

---

## 3.8 Application Intelligence

### What It Does

Builds a structural model of the application: authentication mechanisms, API routes, user roles, sensitive endpoints, file upload points.

### How to Use (CLI)

```bash
python run.py analyze-app <domain> [--output DIR]
```

---

## 3.9 Vulnerability Theory Engine

### What It Does

Generates a ranked list of vulnerability hypotheses from the AppModel — 23 built-in rules, confidence-scored, filtered by threshold.

### How to Use (CLI)

```bash
python run.py generate-theories <domain>
```

---

## 3.10 Custom Attack Tests

### What It Does

Translates vulnerability theories into concrete HTTP attack tests with tailored payloads (130+ across 12 vuln types) and executes them against the live target.

### How to Use (CLI)

```bash
python run.py run-custom-tests <domain> [--min-severity medium] [--oob URL] [--rate 1.0]
```

---

## 3.11 Zero-Day Anomaly Detection

### What It Does

Probes for behavioral anomalies: timing anomalies, status code deviations, reflection anomalies, data leakage, behavioral inconsistencies.

### How to Use (CLI)

```bash
python run.py zero-day <domain> [--rate 1.0] [--timeout 3600]
```

---

## 3.12 Exploit Chain Detection & PoC Generation

### What It Does

Detects exploit chains from confirmed findings (6 patterns) and generates ready-to-run Python PoC scripts.

### Chain Patterns

| Chain Pattern | Example Combination |
|---|---|
| Account Takeover | XSS + Session Cookie |
| Privilege Escalation | IDOR + Auth Bypass |
| RCE via File Upload | File Upload + Path Traversal |
| SSRF to Internal | SSRF + Internal Service |
| SQL Dump | SQLi + Unauthenticated endpoint |
| CORS + Auth Token | CORS Misconfig + Auth Bearer |

### How to Use (CLI)

```bash
python run.py chains <domain> [--output DIR] [--no-poc]
```

---

## 3.13 Attack Graph Engine

### What It Does

Builds and visualizes a directed attack graph with BFS-based attack path analysis. Dual backend: NetworkX (default) + Neo4j (when `NEO4J_ENABLED=1`).

### How to Use (CLI)

```bash
python run.py attack-graph <domain>
python run.py graph verify           # Verify graph integrity
python run.py graph stats            # Show graph statistics
python run.py graph neo4j-status     # Check Neo4j connectivity
```

---

## 3.14 Autonomous Research Mode

### What It Does

Iterative AI-driven research loop: application analysis → theory generation → custom tests → anomaly detection → finding confirmation. Builds institutional knowledge across sessions.

### How to Use (CLI)

```bash
python run.py research <domain> [options]
```

**Flags:**

| Flag | Default | Description |
|---|---|---|
| `--iterations N` | `3` | Research loop cycles |
| `--timeout SECS` | `3600` | Maximum total run time |
| `--active` | false | Enable destructive/active tests |
| `--oob URL` | — | OOB callback for blind vulnerabilities |
| `--min-confidence F` | `0.60` | Minimum theory confidence threshold |
| `--stats` | false | Show KB stats instead of running |

### Real Example

```bash
python run.py recon vulnbank.org
python run.py research vulnbank.org --yes --active --iterations 5 \
  --oob https://your-collaborator.burpcollaborator.net
```

---

## 3.15 Multi-Agent Autonomous Pentest

### What It Does

Coordinated team of 5+ specialized agents running in parallel: ReconAgent, ScanAgent, ExploitAgent, ValidationAgent, ReportAgent, SecretIntelAgent.

### How to Use (CLI)

```bash
python run.py agents run <domain> [--platform HackerOne|Bugcrowd|generic] [--yes]
python run.py agents status
```

---

## 3.16 Swarm Intelligence

### What It Does

Scales testing across targets with 8 specialized security agents (XSS, SQLi, SSRF, IDOR, Auth, BizLogic, Mobile, API) running concurrently via asyncio.

### How to Use (CLI)

```bash
# Multi-target swarm
python run.py swarm <targets-file> [--workers N] [--yes]

# Single-target swarm scan
python run.py swarm-scan <target> [--agents TYPES] [--concurrency N]
```

---

## 3.17 Attack Simulation (Monte Carlo)

### What It Does

Monte Carlo probability modeling of attacker paths. Runs N simulations (default: 1000), computes which attack paths are most likely to succeed.

### How to Use (CLI)

```bash
python run.py simulate-attacks <target> [--tech STACK] [--waf] [--top N]
python run.py simulate-workflow <workflow>
```

**Workflows:** `checkout_flow` / `login_flow` / `password_reset_flow` / `fund_transfer_flow` / `all`

---

## 3.18 AI Security Testing

### What It Does

Tests AI/LLM endpoints: prompt injection, jailbreaking, data leakage, RAG poisoning, model manipulation. Integrates Garak, PyRIT, Giskard, PurpleLlama, Rebuff, ART.

New in v2.0.0: adversarial WAF engine, LLM DoS testing, supply chain scanning, multi-turn chaining, RAG poisoning engine.

### How to Use (CLI)

```bash
python run.py ai-test <target> [options]
```

**Flags:**

| Flag | Default | Description |
|---|---|---|
| `--all` | false | Run all integrated frameworks |
| `--garak` | false | Run Garak only |
| `--pyrit` | false | Run PyRIT only |
| `--auth HEADER` | — | Authorization header value |
| `--model NAME` | — | Model name/identifier |
| `--endpoint PATH` | `/v1/chat/completions` | API endpoint path |
| `--yes` | false | Auto-run without confirmation |

---

## 3.19 AI Red Team Campaigns

### What It Does

Adversarial prompt campaigns at scale with genetic algorithm evolution. Hundreds to thousands of prompts per campaign.

### Campaign Types

| Campaign | Attack Goal |
|---|---|
| `prompt_injection` | Override system instructions |
| `jailbreak` | Bypass safety filters |
| `data_leak` | Extract training data or system prompt |
| `rag_attack` | Poison retrieval-augmented generation |
| `tool_abuse` | Manipulate function/tool calls |
| `output_manipulation` | Control downstream output |
| `full` | All campaigns sequentially |

### How to Use (CLI)

```bash
python run.py ai-redteam <target> [--campaign full] [--prompts 100] \
  [--parallel 5] [--evolve] [--endpoint PATH]
```

---

## 3.20 AI Agent Pentesting

### What It Does

Tests AI agent systems for agent-specific vulnerabilities: tool abuse, API abuse, data exfiltration.

### How to Use (CLI)

```bash
python run.py ai-agent-test <target> [--all] [--tool-abuse] \
  [--api-abuse] [--data-exfiltration] [--oob-domain DOMAIN]
```

---

## 3.21 Mobile Security Analysis

### What It Does

Comprehensive 12+ phase security analysis of Android APK and iOS IPA files. New in v2.0.0: ADB forensics, deep-link fuzzing, SDK scanning, intent fuzzing, MASTG knowledge base.

### Phase Summary

| Phase | Module | Description |
|---|---|---|
| 0 | Tool registry | Auto-discover 12+ tools |
| 1 | Upload & extract | SHA-256 dedup, metadata |
| 2 | Static analysis | APKTool + JADX + MobSF |
| 3 | AI reverse engineering | Hidden endpoints, auth flaws |
| 4 | Frida script generation | SSL pinning, root bypass hooks |
| 5 | Secret detection | 32 regex + TruffleHog + Gitleaks |
| 6 | API discovery | Retrofit/OkHttp/URLSession/GraphQL |
| 7 | Component testing | Drozer, exported components |
| 8 | Dynamic analysis | Frida + Objection + RMS |
| 9 | Network analysis | Burp integration, cleartext |
| 10 | API attack & fuzzing | IDOR, auth bypass, mass assignment |
| 11 | ADB forensics (v2.0.0) | Device data extraction, logcat |
| 12 | Deep-link/intent fuzzing (v2.0.0) | Deep link enum, intent fuzzing, SDK scan |

### How to Use (CLI)

```bash
# Full analysis
python run.py mobile-analyze <file.apk> [--dynamic] [--device SERIAL] \
  [--proxy-host HOST] [--proxy-port PORT] [--output DIR]

# Static analysis only
python run.py mobile-static <file.apk>

# Dynamic analysis (requires connected device)
python run.py mobile-dynamic <file.apk> <package.name>

# API discovery + fuzzing
python run.py mobile-api-scan <file.apk> [--fuzz]

# Generate report
python run.py mobile-report <app-id> [--format json|markdown|html]
```

### Real Example — DIVA APK

```bash
adb install diva.apk
python run.py mobile-analyze diva.apk \
  --dynamic \
  --device emulator-5554 \
  --output ./diva-analysis
```

---

## 3.22 Traffic Capture & Replay

### What It Does

Captures all HTTP requests made during scans to SQLite. Supports review, filter, replay, fuzzing, differential scanning, and race condition testing.

### How to Use (CLI)

```bash
# List captured traffic
python run.py traffic-list [--target DOMAIN] [--source MODULE] \
  [--method METHOD] [--status CODE] [--flagged] [--limit N]

# Export traffic
python run.py traffic-export [--format json|csv|har]

# Replay a request
python run.py replay-request <request-id> [--fuzz PARAM] \
  [--fuzz-values LIST] [--proxy URL]

# Replay an attack pattern
python run.py replay-attack <attack-id> [--target TARGET]
```

---

## 3.23 Bug Bounty Hunter (Autonomous)

### What It Does

Fully autonomous end-to-end bug bounty operation: discovers programs from HackerOne/Bugcrowd/Intigriti, prioritizes targets by expected yield (bounty value × scope × freshness / competition), runs scans, generates submission-ready reports.

### How to Use (CLI)

```bash
python run.py hunter-start [--platforms LIST] [--max-targets N] \
  [--auto-exploit] [--strategy aggressive|stealthy|high-value] \
  [--benchmark-ref FILE] [--yes]

python run.py hunter-scan <target>
python run.py hunter-status [--watch]
python run.py hunter-report <session-id> [--format markdown|json|html]
```

Combined hunter command:
```bash
python run.py hunter <target> [--full-auto]
```

---

## 3.24 Scan Profiles

### Built-in Profiles

| Profile | Duration | Description |
|---|---|---|
| `quick` | 15–20 min | Passive recon + critical/high nuclei only |
| `deep` | 60–90 min | Full recon + all scanners + exploit chains |
| `research` | Variable | Iterative AI-driven research mode |
| `swarm` | Variable | Distributed broad coverage, minimal depth |
| `stealth` | Variable | Passive-only, no active probes, production-safe |

### How to Use (CLI)

```bash
python run.py profile list
python run.py profile show <name>
python run.py profile run <domain> <profile> [--yes]
```

---

## 3.25 Findings Management

### How to Use (CLI)

```bash
python run.py findings list [critical|high|medium|low|info]
python run.py findings show <id>
python run.py findings log <title> --severity high --url <url>
python run.py findings update <id> status confirmed
python run.py findings stats
python run.py findings export [json|csv|md]
python run.py dedup "Reflected XSS in search parameter"
```

---

## 3.26 Reporting

### What It Does

Generates publication-ready vulnerability reports formatted for HackerOne, Bugcrowd, Intigriti, or generic markdown/JSON/HTML. Includes CVSS scoring, PoC steps, and remediation.

### How to Use (CLI)

```bash
python run.py report --finding F-001
python run.py report --chain F-001 F-002
python run.py report --all
```

---

## 3.27 Payload Library & WAF Bypass

### How to Use (CLI)

```bash
python run.py payloads <vuln_type> [<context>]
python run.py waf-bypass <waf> <vuln_type>
```

**Vulnerability Types:** `xss`, `sqli`, `ssrf`, `lfi`, `rce`, `ssti`, `xxe`, `redirect`

**WAF Options:** `Cloudflare`, `ModSecurity`, `AWS WAF`, `Akamai`

---

## 3.28 CVSS Calculator

```bash
python run.py cvss "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N"
python run.py cvss --describe "Reflected XSS, unauthenticated, requires victim click"
```

---

## 3.29 Workflow Orchestration

```bash
python run.py workflow <domain> [--phases LIST] [--plan-only] \
  [--rate N] [--workers N]
```

**Available Phases:** `passive`, `subdomain`, `dns`, `http`, `fingerprint`, `ports`, `crawl`, `content`, `api`, `triage`, `vuln`, `cloud`, `secrets`

---

## 3.30 CI/CD Integration

### What It Does

Generates CI/CD pipeline configurations (GitHub Actions, GitLab CI, Jenkinsfile) that integrate OneInfinity scans into development workflows.

### Generated Pipeline (GitHub Actions)

```yaml
name: OneInfinity Security Scan
on:
  pull_request:
    branches: [main]
jobs:
  security-scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - name: Install OneInfinity
        run: pip install -e ".[ai,mobile,web,distributed]"
      - name: Run Quick Scan
        run: python run.py profile run ${{ github.repository }} quick --yes
      - name: Check for Critical Findings
        run: |
          CRITICAL=$(python run.py findings list critical | wc -l)
          if [ "$CRITICAL" -gt "0" ]; then
            echo "Critical findings detected — blocking merge"
            exit 1
          fi
```

---

## 3.31 Plugin System

### Built-in Plugins

| Plugin | Description |
|---|---|
| `recon/crtsh_monitor` | Certificate transparency subdomain enumeration |
| `recon/asn_enum` | ASN/BGP IP range enumeration |
| `vuln/api_security` | GraphQL introspection, BOLA, mass assignment, rate limit testing |
| `vuln/cloud_misconfig` | S3, Elasticsearch, K8s, credential leakage detection |

### How to Use (CLI)

```bash
python run.py plugins list
python run.py plugins run api_security vulnbank.org
```

### Writing a Custom Plugin

```python
# plugins/vuln/my_plugin.py
class MyPlugin:
    name = "my_plugin"
    description = "Custom vulnerability check"
    vuln_types = ["custom_vuln"]

    def run(self, target: str, urls: list, **kwargs) -> list:
        findings = []
        for url in urls:
            if self.check(url):
                findings.append({
                    "type": "custom_vuln",
                    "severity": "high",
                    "url": url,
                    "evidence": "..."
                })
        return findings
```

---

## 3.32 Recon Cache

### How to Use (CLI)

```bash
python run.py cache stats
python run.py cache sweep
python run.py cache invalidate <domain>
python run.py cache clear
```

---

## 3.33 Continuous Learning System

### How It Works

- `learning/knowledge_base.py` — SQLite KB: sessions, findings, tool_runs, vuln_patterns, target_insights
- `learning/pattern_miner.py` — Extracts VulnPattern and TargetInsight
- `learning/adaptive_planner.py` — Recommends highest-yield scan plan for new targets
- `learning/persistent_memory.py` — JSON-backed cross-run intelligence store

**Data stored in persistent memory:**
- Successful payloads (ranked by hit count) → injected into future scans
- Failed payloads → avoided in future scans
- High-value hosts with severity history
- Successful exploit chains → replayed first on matching targets

### How to Use (CLI)

```bash
python run.py learn stats
python run.py learn plan vulnbank.org
python run.py learn show <pattern-id>
python run.py learn backfill          # Backfill from existing findings
```

---

## 3.34 AI Model Orchestration

### What It Does

Routes all AI calls through a central `ModelOrchestrator` with 3-tier routing (FAST/STANDARD/PREMIUM), budget guard, daily spend limits, and automatic fallback to Ollama or CLI backends.

### Providers

| Provider | How it's used | Cost |
|---|---|---|
| OpenAI (gpt-4o-mini, gpt-4o) | API via `OPENAI_API_KEY` | Paid per token |
| Anthropic (Haiku/Sonnet/Opus) | API via `ANTHROPIC_API_KEY` | Paid per token |
| Google Gemini | Gemini CLI | Free tier |
| Ollama (local) | HTTP at `OLLAMA_HOST` (default `localhost:11434`) | Free |
| Codex CLI | `codex exec` subprocess | User's OpenAI account |
| Claude Code CLI | `claude -p` subprocess | User's Anthropic account |

### Using Ollama

```bash
# Install and pull a model
curl -fsSL https://ollama.com/install.sh | sh
ollama pull deepseek-r1:7b

# OneInfinity auto-discovers all running Ollama models at startup
# Tier assignment: >=70B → PREMIUM, 27-34B → STANDARD, else FAST
```

### Budget Control

```yaml
# config/models.yaml
budget:
  daily_limit_usd: 5.00
  monthly_limit_usd: 50.00
  alert_threshold: 0.80
  per_model_daily_limit:
    gpt-4o: 2.00
```

### CLI Commands

```bash
python run.py ai-status       # Show model status and availability
python run.py ai-budget       # Show current spend and limits
python run.py ai-models       # List all registered models with tiers
```

---

## 3.35 Web3 / Smart Contract Security

### What It Does

Scans Ethereum smart contracts for 14 vulnerability classes using Slither static analysis and custom detectors. Supports EVM (mainnet, testnets, L2s) and Solana programs. Generates Foundry PoC test files for confirmed findings.

### Prerequisites

```bash
pip install slither-analyzer
# Install Foundry for PoC generation
curl -L https://foundry.paradigm.xyz | bash
foundryup
```

### How to Use (CLI)

```bash
# Scan a local Solidity file
python run.py web3 scan --contract ./contracts/Token.sol

# Scan a deployed contract by address
python run.py web3 scan --address 0x1234...abcd --network mainnet

# Scan a Hardhat/Foundry project directory
python run.py web3 scan --project ./my-defi-project/

# Scan Solana program
python run.py web3 scan --solana --program <program-id>

# Generate Foundry PoC for a finding
python run.py web3 poc --finding WEB3-001 --output ./poc/

# Full scan with PoC generation
python run.py web3 full-scan --project ./my-project/ --generate-poc
```

**Flags:**

| Flag | Description |
|---|---|
| `--contract FILE` | Path to .sol file |
| `--address ADDR` | Deployed contract address |
| `--network NAME` | mainnet / goerli / polygon / arbitrum / solana |
| `--project DIR` | Hardhat/Foundry project root |
| `--generate-poc` | Auto-generate Foundry test files for findings |
| `--slither-args ARGS` | Pass extra args to Slither |
| `--output DIR` | Output directory for findings and PoC files |

### Vulnerability Classes Detected

| Class | CVSS Range | Description |
|---|---|---|
| `reentrancy` | 7.5–9.8 | Classic and cross-function re-entrancy |
| `integer_overflow` | 7.5–9.0 | Unchecked arithmetic (pre-0.8.x) |
| `access_control` | 6.5–9.8 | Missing `onlyOwner` / `onlyRole` |
| `tx_origin` | 8.0–9.5 | `tx.origin` authentication |
| `price_manipulation` | 8.0–9.8 | Oracle manipulation, spot price reliance |
| `flash_loan_attack` | 8.5–9.8 | Flash loan-enabled attack vectors |
| `front_running` | 5.0–8.0 | MEV / sandwich attack exposure |
| `selfdestruct` | 7.0–9.0 | Forced Ether via selfdestruct |
| `delegatecall` | 7.5–9.5 | Unsafe delegatecall storage collision |
| `unchecked_return` | 5.0–8.5 | Unchecked low-level call returns |
| `timestamp_dependence` | 3.5–7.0 | Block timestamp manipulation |
| `denial_of_service` | 5.0–8.0 | Gas limit DoS, unbounded loops |
| `signature_replay` | 7.0–9.0 | Missing nonce / chainId |
| `logic_error` | Variable | Custom business logic rules |

### Expected Output

```
[*] Web3 Security Scan — ./Token.sol
[*] Running Slither analysis...
[*] Running custom EVM detectors...

[CRITICAL] Reentrancy — withdraw()
  File: Token.sol:142
  Description: State update after external call allows re-entrancy
  Impact: Complete token drain
  PoC generated: poc/reentrancy_withdraw.t.sol

[HIGH] Missing Access Control — mint()
  File: Token.sol:89
  Description: mint() has no onlyOwner guard
  Impact: Unlimited token minting

[*] Scan complete — 2 findings
[*] Foundry PoC: run `forge test --match-test testReentrancy`
```

---

## 3.36 Nim Payload Arsenal

### What It Does

Six Nim-compiled high-performance payload generation binaries. All executions are SHA-256 verified against `checksums.json` before running. Covers shell generation, WAF bypass, post-exploitation, fuzzing, and privilege escalation.

### Prerequisites

The Nim binaries are pre-compiled and included in `bin/`. They are verified automatically at runtime via `nim_runner.py`. No Nim installation is required to use the compiled binaries.

To rebuild from source (developers only):
```bash
# Install Nim
curl https://nim-lang.org/choosenim/init.sh -sSf | sh
# Rebuild
cd src/nim/oi-shell-gen && nim compile --opt:speed -o:../../../bin/oi-shell-gen main.nim
# Update checksums after rebuild
python run.py arsenal update-checksums
```

### How to Use (CLI)

```bash
# Generate reverse shell
python run.py arsenal shell --ip 10.0.0.1 --port 4444 --lang python3

# Generate WAF bypass payload
python run.py arsenal bypass --technique unicode --target-waf cloudflare

# Generate payloads for a vuln type
python run.py arsenal payloads --type xss --context html-body

# Post-exploitation command sequence
python run.py arsenal post-exploit --os linux --phase persistence

# High-speed fuzzing
python run.py arsenal fuzz --wordlist /usr/share/wordlists/dirb/common.txt \
  --target https://example.com/FUZZ --threads 100 --rate 5000

# Privilege escalation payloads
python run.py arsenal privesc --os linux --technique suid
```

**Available Binaries:**

| Binary | CLI Alias | Key Options |
|---|---|---|
| `oi-shell-gen` | `arsenal shell` | `--lang bash|python3|php|powershell|...` (20+ languages) |
| `oi-bypass-gen` | `arsenal bypass` | `--technique unicode|base64|homoglyph|...` |
| `oi-payloads` | `arsenal payloads` | `--type xss|sqli|ssrf|ssti|...` |
| `oi-post-exploit` | `arsenal post-exploit` | `--phase recon|persist|exfil|...` |
| `oi-fuzzer` | `arsenal fuzz` | `--rate N` (millions of req/sec capable) |
| `oi-privesc-gen` | `arsenal privesc` | `--technique suid|sudo|cron|service|...` |

### Integrity Verification

Every binary execution verifies SHA-256 against `checksums.json`:
```
NimIntegrityError: Integrity check failed for oi-shell-gen:
  got 3f9a8b2c... expected 7d4e1f8a...
```

If this error appears, the binary has been modified. Re-download from the official repository or rebuild from source.

Set `OI_NIM_SKIP_VERIFY=1` only for local development when rebuilding binaries. Never use in production.

---

## 3.37 Authenticated Testing Suite

### What It Does

Records login sessions, manages multi-account session pools, and runs comprehensive authenticated tests: cross-account IDOR, privilege escalation, business logic bypass, session replay. Integrates with God Mode via `--auth-session`.

### Prerequisites

```bash
# Playwright for session recording
pip install playwright
playwright install chromium
```

### How to Use (CLI)

```bash
# Step 1: Detect login form
python run.py auth detect-form https://target.com/login

# Step 2: Record a session (opens browser, you log in manually)
python run.py auth record --url https://target.com/login \
  --username user@example.com --password yourpassword \
  --output user_session.json

# Step 3: Record admin session
python run.py auth record --url https://target.com/login \
  --username admin@example.com --password adminpass \
  --role admin --output admin_session.json

# Step 4: Run authenticated test suite
python run.py auth test-suite --target https://target.com \
  --session user_session.json --admin-session admin_session.json

# Step 5: Multi-account IDOR testing
python run.py auth idor --target https://target.com/api \
  --session-a user_a_session.json --session-b user_b_session.json

# Credential spraying
python run.py auth spray --target https://target.com/login \
  --userlist users.txt --passlist passwords.txt \
  --rate 0.5 --lockout-threshold 5
```

**auth test-suite Flags:**

| Flag | Description |
|---|---|
| `--target URL` | Target base URL |
| `--session FILE` | Primary user session file |
| `--admin-session FILE` | Admin session file (for privilege escalation tests) |
| `--idor-only` | Run IDOR tests only |
| `--priv-esc-only` | Run privilege escalation tests only |
| `--biz-logic-only` | Run business logic bypass tests only |
| `--output DIR` | Output directory for findings |

### Session File Format

```json
{
  "session_id": "sess_abc123",
  "target": "https://target.com",
  "user_role": "user",
  "username": "user@example.com",
  "cookies": {"session": "abc123def456"},
  "headers": {"Authorization": "Bearer eyJ..."},
  "tokens": {"csrf": "xyz789"},
  "login_url": "https://target.com/login",
  "active": true
}
```

### Integration with God Mode

```bash
# Record session first
python run.py auth record --url https://target.com/login \
  --username user@example.com --password pass --output session.json

# Use in God Mode
python run.py god-mode target.com --auth-session session.json
```

---

## 3.38 Android Companion App

### What It Does

Kotlin Android application that uses Android's VPN service to capture all device traffic and forward it to OneInfinity on your desktop. Enables testing of any app on the device without requiring ADB proxying or per-app proxy configuration.

### Prerequisites

- Android device (API 21+) or emulator
- ADB installed
- USB debugging enabled on device (or emulator)

### Installation

```bash
# Option A: Build from source
cd android-companion
./gradlew assembleDebug
adb install app/build/outputs/apk/debug/app-debug.apk

# Option B: Install pre-built APK (if available in releases)
adb install oneinfinity-companion.apk
```

### Setup and Usage

1. **Start OneInfinity capture listener on desktop:**
   ```bash
   python run.py companion-server --port 9999
   ```

2. **Open OneInfinity Companion on device**

3. **Connect to desktop:**
   - **QR Code**: Run `python run.py companion-qr` on desktop, scan with the app
   - **mDNS Auto-Discovery**: Tap "Auto-Discover" — finds OneInfinity on local network automatically
   - **Manual**: Enter desktop IP:port manually

4. **Enable VPN Capture:**
   - Tap "Start Capture"
   - Accept the Android VPN permission dialog
   - All device traffic now flows through OneInfinity capture

5. **View captured traffic in OneInfinity:**
   ```bash
   python run.py traffic-list --source android_companion
   ```

### What Gets Captured

- All HTTP/HTTPS traffic from all apps on the device (when VPN active)
- WebSocket connections
- GraphQL over HTTP
- Certificate pinning bypass is NOT automatic — use Frida scripts for that

---

## 3.39 iOS Companion App

### What It Does

Swift iOS application using Network Extension framework (NEPacketTunnelProvider) to capture device traffic, plus optional Frida gadget integration for targeted app analysis.

### Prerequisites

- iOS device running iOS 16+
- Xcode 15+
- Valid Apple Developer account (Network Extension requires a paid developer account with entitlement)
- Provisioning profile with `com.apple.developer.networking.networkextension` entitlement

### Building and Installation

```bash
cd ios-companion

# Open in Xcode
open OneInfinityCapture.xcodeproj

# Configure signing:
# 1. Select your Team in Signing & Capabilities
# 2. Ensure Network Extension entitlement is enabled
# 3. Build and run on device (not simulator — Network Extension requires real device)
```

### Setup and Usage

1. **Start OneInfinity capture listener on desktop:**
   ```bash
   python run.py companion-server --port 9999
   ```

2. **Open OneInfinity Capture on iOS device**

3. **Connect:** QR code scan / mDNS auto-discover / manual entry

4. **Enable capture:**
   - Tap "Start VPN Capture"
   - Accept iOS VPN permission prompt
   - Traffic flows through the Network Extension

5. **Optional Frida integration** (jailbroken device or Frida gadget re-packaged app):
   - Enable Frida hooks in the companion app settings
   - Select target app bundle ID
   - Companion injects Frida scripts from `frida_scripts/` directory

### Limitations

- Network Extension entitlement requires Apple Developer Program membership
- Not available on iOS Simulator (requires physical device)
- Frida gadget injection requires either a jailbroken device or re-packaging the target app

---

## 3.40 MCP Integration

### What It Does

Exposes OneInfinity capabilities as MCP (Model Context Protocol) tools consumable by Claude Code, Cursor, or any MCP-compatible AI assistant. Current tools: HackerOne scope lookup and program discovery. Human approval is required for any submission actions.

### Setup

```bash
# Start the MCP server
python run.py mcp-server

# Or configure in Claude Code settings
# Add to ~/.claude/settings.json:
```

```json
{
  "mcpServers": {
    "oneinfinity": {
      "command": "python",
      "args": ["/path/to/oneinfinity/run.py", "mcp-server"],
      "env": {
        "HACKERONE_API_TOKEN": "your-token",
        "HACKERONE_USERNAME": "your-username"
      }
    }
  }
}
```

Alternatively, use `mcp-config.json` at the project root — it is pre-configured.

### Available MCP Tools

| Tool | Description | Returns |
|---|---|---|
| `get_hackerone_scope` | Fetch in-scope/out-of-scope assets for a H1 program | `{in_scope, out_of_scope, bounty_table}` |
| `list_hackerone_programs` | List programs matching a query | List of programs with bounty ranges |

### Usage from Claude Code

```
# In Claude Code conversation:
"What is in scope for the example program on HackerOne?"
# Claude calls get_hackerone_scope("example") and returns the scope

"List HackerOne programs with web scope and $1000+ bounties"
# Claude calls list_hackerone_programs("web high bounty")
```

### Human Approval

Any action that submits data to external platforms requires explicit human approval. The MCP server returns `requires_approval: true` for such actions and will not proceed without confirmation. This is enforced at the server middleware layer — it cannot be bypassed by the AI.

---

## 3.41 God Mode

### What It Does

Maximum-autonomy 6-stage cascade that chains all platform capabilities: full recon → swarm vuln scan → exploit chaining → authenticated testing → AI/Web3 testing → report generation. Designed for hands-off comprehensive assessments.

### How to Use (CLI)

```bash
python run.py god-mode <target> [options]
```

**Flags:**

| Flag | Description |
|---|---|
| `--auth-session FILE` | Load pre-recorded SessionContext for authenticated testing |
| `--background` | Run in background as daemon |
| `--no-swarm` | Disable swarm intelligence stage |
| `--no-research` | Skip autonomous research iterations |
| `--report-fmt FORMAT` | Output format: `markdown` (default) / `json` / `html` |

### Stages

| Stage | Duration | What Happens |
|---|---|---|
| 1: Recon & Intelligence | 10–30 min | Full recon + OSINT + adaptive recon + attack graph initialization |
| 2: Vulnerability Scan | 20–60 min | 8-agent swarm + 80+ scan engines + GraphQL/gRPC/HTTP2/smuggling |
| 3: Exploit & Chain | 10–30 min | Autonomous validation + chain detection + Nim payload generation |
| 4: Authenticated Testing | 10–20 min | Auth suite (only if `--auth-session` provided) |
| 5: AI & Web3 | 5–20 min | AI security testing (if AI endpoint) + smart contract scan (if web3) |
| 6: Report & Submit | 2–5 min | Report generation + MCP scope check + [human approval for submission] |

### Real Example

```bash
# Basic God Mode
python run.py god-mode target.com

# With authenticated testing
python run.py auth record --url https://target.com/login \
  --username user@example.com --password pass --output session.json
python run.py god-mode target.com --auth-session session.json \
  --report-fmt html

# Background mode
python run.py god-mode target.com --background
python run.py god-mode-status   # Check progress
```

### Expected Output

```
[*] God Mode — target.com
[*] Stage 1/6: Recon & Intelligence
    subfinder: 23 subdomains | httpx: 18 live | katana: 1,247 URLs
    AttackGraph initialized: 42 nodes
[*] Stage 2/6: Vulnerability Scan
    Swarm(8 agents) running...
    nuclei: 47 findings | dalfox: 3 HIGH XSS | sqlmap: 1 CRITICAL SQLi
[*] Stage 3/6: Exploit & Chain
    Validated: 8 confirmed, 12 unverified
    Chains detected: 2 (XSS→ATO, SQLi→RCE)
    Nim payloads generated for 2 confirmed critical findings
[*] Stage 4/6: Authenticated Testing (skipped — no --auth-session)
[*] Stage 5/6: AI & Web3 (no AI endpoint or contract detected)
[*] Stage 6/6: Report & Submit
    report.html written — 8 confirmed findings, 2 exploit chains

[*] God Mode complete — 8h 23m
```

---

## 3.42 CI/CD Vulnerability Scanner

### What It Does

Scans CI/CD pipelines and infrastructure for security vulnerabilities: exposed secrets in pipeline configs, insecure Docker base images, dependency confusion risks, supply chain attack vectors, OIDC/JWT misconfigurations.

### How to Use (CLI)

```bash
# Scan a GitHub Actions workflow directory
python run.py cicd-scan --dir .github/workflows/

# Scan a GitLab CI config
python run.py cicd-scan --file .gitlab-ci.yml

# Scan Docker files
python run.py cicd-scan --dockerfile Dockerfile

# Full CI/CD audit
python run.py cicd-scan --full --repo .
```

### What Gets Detected

| Category | Examples |
|---|---|
| Secret exposure | Hardcoded API keys, passwords in YAML |
| Insecure Docker images | Using `latest`, running as root |
| Supply chain risks | Unpinned GitHub Actions, unverified third-party actions |
| OIDC misconfiguration | Overly broad OIDC token claims |
| Build artifact tampering | Missing artifact signing |
| Dependency confusion | Internal package names that could be squatted |

### Web UI

Access the CI/CD security dashboard at `http://localhost:3000/cicd-center`.

---

(Continued in sections 4–9 below)

---

# 4. Target Setup Guides

---

## 4.1 Web — vulnbank.org

### Overview

`vulnbank.org` is a public intentionally vulnerable banking application. No local setup required.

### Recommended Scan Sequence

```bash
python run.py setup vulnbank-engagement --target vulnbank.org
python run.py recon vulnbank.org
python run.py analyze-app vulnbank.org
python run.py research vulnbank.org --yes --active --iterations 5
python run.py chains vulnbank.org
python run.py report --all
```

---

## 4.2 Mobile — DIVA APK

### Setup Steps

```bash
# Start emulator
emulator -avd Pixel_6_API_30

# Download and install DIVA
wget https://github.com/payatu/diva-android/raw/master/DivaApplication.apk -O diva.apk
adb install diva.apk

# Install frida-server on device
pip install frida-tools
FRIDA_VERSION=$(python3 -c "import frida; print(frida.__version__)")
wget "https://github.com/frida/frida/releases/download/${FRIDA_VERSION}/frida-server-${FRIDA_VERSION}-android-x86_64.xz"
xz -d frida-server-*.xz
adb push frida-server /data/local/tmp/frida-server
adb shell chmod 755 /data/local/tmp/frida-server
adb shell /data/local/tmp/frida-server &
```

### Run OneInfinity Mobile Analysis

```bash
python run.py mobile-analyze diva.apk \
  --dynamic \
  --device emulator-5554 \
  --output ./diva-results
```

---

## 4.3 AI Chatbot — Vulnerable AI Chatbot

### Setup Steps

```bash
git clone https://github.com/aira-security/Vulnerable-AI-Chatbot.git
cd Vulnerable-AI-Chatbot
pip install -r requirements.txt
export OPENAI_API_KEY="sk-your-key-here"
python app.py
# Running at http://localhost:5000
```

### Run OneInfinity AI Security Tests

```bash
python run.py ai-test http://localhost:5000 --all --endpoint /api/chat --yes
python run.py ai-redteam http://localhost:5000 --campaign full \
  --prompts 300 --parallel 5 --evolve --endpoint /api/chat
```

---

## 4.4 API — DVAPI

### Setup Steps

```bash
git clone https://github.com/payatu/DVAPI.git
cd DVAPI
pip install -r requirements.txt
python app.py  # or: docker-compose up -d
# API at http://localhost:8888
```

### Run OneInfinity API Tests

```bash
python run.py analyze-app localhost
python run.py generate-theories localhost
python run.py research localhost --yes --active --iterations 3
python run.py plugins run api_security localhost
```

---

## 4.5 Smart Contract — Hardhat Local Testnet

### Setup Steps

```bash
# Install Hardhat
npm install -g hardhat

# Create test project with known-vulnerable contracts
mkdir vuln-contracts && cd vuln-contracts
npx hardhat init

# Add a vulnerable contract (example)
cat > contracts/VulnToken.sol << 'EOF'
// SPDX-License-Identifier: MIT
pragma solidity ^0.7.6;

contract VulnToken {
    mapping(address => uint256) public balances;

    function deposit() public payable {
        balances[msg.sender] += msg.value;
    }

    function withdraw() public {
        uint256 bal = balances[msg.sender];
        require(bal > 0);
        (bool sent, ) = msg.sender.call{value: bal}("");
        require(sent);
        balances[msg.sender] = 0; // State update AFTER external call — reentrancy!
    }
}
EOF

# Start local Hardhat node
npx hardhat node
# Local RPC at http://localhost:8545
```

### Run OneInfinity Web3 Scan

```bash
# Scan the local project
python run.py web3 scan --project ./vuln-contracts/ --generate-poc

# Or deploy to local node first and scan by address
python run.py web3 scan --address <deployed-address> \
  --network localhost --rpc http://localhost:8545 \
  --generate-poc
```

### Expected Output

```
[*] Web3 Security Scan — ./vuln-contracts/
[CRITICAL] Reentrancy — VulnToken.withdraw()
  contracts/VulnToken.sol:10
  State update at line 12 occurs after external call at line 10
  PoC: test/reentrancy_withdraw.t.sol

[*] Run PoC: cd vuln-contracts && forge test --match-test testReentrancy -vvv
```

---

# 5. Advanced Features

## Intelligence Daemon

The `intelligence_daemon.py` runs a background worker pool with 9 specialized workers:

| Worker | Function |
|---|---|
| `hypothesis` | Continuously generates new vulnerability hypotheses |
| `graph_expansion` | Expands the attack graph with new paths |
| `exploit_chain` | Attempts exploitation of queued vulnerabilities |
| `payload_mutation` | Mutates failed payloads to bypass WAFs |
| `traffic_replay` | Replays captured traffic with variations |
| `business_logic` | Analyzes business logic for workflow flaws |
| `osint_expand` | Runs OSINT queries for additional context |
| `swarm` | Coordinates swarm agent activities |
| `learning` | Processes session outcomes into KB patterns |

```bash
python run.py daemon-start target.com
python run.py daemon-status
```

**Access via Web UI:** `http://localhost:3000/live-intelligence`

## Web3 Advanced Features

**Flash loan attack simulation:**
```bash
python run.py web3 simulate-flash-loan --contract 0xABCD... \
  --amount 1000000 --network mainnet
```

**Token economics analysis:**
```bash
python run.py web3 token-scan --address 0xABCD... --network mainnet
```

**Multi-contract dependency graph:**
```bash
python run.py web3 dep-graph --project ./contracts/
```

## Nim Integrity Bypass for Development

When rebuilding Nim binaries from source locally, the checksums will differ from the shipped `checksums.json`. To skip verification during development:

```bash
export OI_NIM_SKIP_VERIFY=1
python run.py arsenal shell --ip 10.0.0.1 --port 4444 --lang bash

# After rebuilding, update checksums:
python run.py arsenal update-checksums
unset OI_NIM_SKIP_VERIFY
```

Do NOT set `OI_NIM_SKIP_VERIFY=1` in production or shared environments.

## Multi-Account IDOR Testing

For advanced IDOR testing across multiple user accounts:

```bash
# Record sessions for multiple accounts
python run.py auth record --url https://target.com/login \
  --username user_a@example.com --password passA --output session_a.json
python run.py auth record --url https://target.com/login \
  --username user_b@example.com --password passB --output session_b.json

# Run cross-account IDOR tests
python run.py auth idor \
  --target https://target.com/api \
  --session-a session_a.json \
  --session-b session_b.json \
  --endpoints /api/users/{id} /api/orders/{id} /api/messages/{id}
```

## RAG Attack System

```bash
python run.py ai-redteam <target> --campaign rag_attack
```

Tests: prompt poisoning, context manipulation, indirect injection.

## Exploit Validation Engine

Finding validation runs in two stages:

**Stage 1** — Active re-testing: canary injection, response comparison, endpoint liveness, CVSS calculation, duplicate detection.

**Stage 2** — Confidence classification:

| Status | Threshold | Description |
|--------|-----------|-------------|
| `confirmed` | ≥ 0.70 + evidence | Tool-confirmed — included in report |
| `unverified` | 0.35–0.69 | Plausible — included in report (flagged) |
| `false_positive` | < 0.35 | Low-confidence — excluded from report |
| `simulated` | `source_type=simulated` | Monte Carlo/workflow — excluded |

## GitHub Org Intelligence

```bash
python run.py org-intel <github-org> [--github-token TOKEN] [--max-repos N]
```

Maps a GitHub organization to its external domains via README files, CNAME, package.json homepage, CI/CD configs.

---

# 6. CLI Reference

## Usage

```bash
python run.py <command> [subcommand] [options]
```

## Complete Command Index

| Command | Description |
|---|---|
| `adaptive-recon` | Tech-stack-aware recon |
| `agents run` | Launch multi-agent autonomous pentest |
| `agents status` | Show agent status |
| `ai` | AI analysis (alias for ai-test) |
| `ai-agent-test` | Test AI agents for tool/API abuse |
| `ai-budget` | Show AI model spend and limits |
| `ai-models` | List all registered AI models |
| `ai-redteam` | Adversarial prompt campaigns at scale |
| `ai-status` | Show AI model availability |
| `ai-test` | Test AI endpoints with integrated frameworks |
| `analyze` | Analyze recon data files |
| `analyze-app` | Build structural application model |
| `arch-events` | Show architecture event log |
| `arch-insights` | Show generated architecture insights |
| `arch-status` | Show self-evolving architecture status |
| `arch-emit` | Emit a manual architecture event |
| `arsenal` | Nim payload arsenal (shell, bypass, fuzz, privesc) |
| `attack-graph` | Build and analyze attack graph |
| `auth` | Authenticated testing suite (detect-form, record, test-suite, idor, spray) |
| `benchmark` | Run performance benchmark |
| `brain-decide` | Generate decision plan from attack graph |
| `brain-start` | Start autonomous graph brain loop |
| `brain-status` | Show brain status and queue |
| `brain-stop` | Stop brain and event-driven engine |
| `brain-triggers` | List and evaluate graph trigger rules |
| `cache` | Recon cache management (stats, sweep, invalidate, clear) |
| `capmap` | Show capability map |
| `chains` | Detect exploit chains |
| `cicd-scan` | CI/CD pipeline vulnerability scanner |
| `cvss` | CVSS 3.1 calculator |
| `daemon-add-target` | Add target to running daemon |
| `daemon-start` | Start intelligence daemon |
| `daemon-status` | Show daemon worker status |
| `daemon-stop` | Stop intelligence daemon |
| `debug` | System integrity check |
| `dedup` | Check finding for duplicates |
| `distributed` | Manage distributed worker stack |
| `doctor` | Full QA + audit + regression |
| `exploit` | Run exploit chain detection |
| `findings` | Findings database management (list, log, show, update, stats, export) |
| `full-scan` | Full-coverage scan (all phases) |
| `fuzz` | Directory/content fuzzing |
| `generate-theories` | Generate vulnerability theories |
| `god-mode` | 6-stage maximum-autonomy scan |
| `graph` | Attack graph management (verify, stats, neo4j-status) |
| `graphql-scan` | GraphQL-specific security scan |
| `browser-scan` | Browser-based scanning (Playwright) |
| `smuggling-scan` | HTTP request smuggling detection |
| `hunter` | Combined bug bounty hunter (discover + scan + report) |
| `hunter-report` | Generate hunter session report |
| `hunter-scan` | Scan a specific target via hunter pipeline |
| `hunter-start` | Start autonomous bug bounty hunter |
| `hunter-status` | Show hunter session status |
| `learn` | Continuous learning system (stats, plan, show, backfill) |
| `mcp-server` | Start MCP server |
| `methodology` | Step-by-step testing methodologies |
| `mobile-analyze` | Full mobile security analysis |
| `mobile-api-scan` | Mobile API discovery + fuzzing |
| `mobile-dynamic` | Mobile dynamic analysis |
| `mobile-report` | Generate mobile security report |
| `mobile-static` | Mobile static analysis |
| `org-intel` | GitHub org to domain mapping |
| `parity-check` | Check scan parity against baseline |
| `payloads` | Context-aware payload library |
| `plan` | Generate prioritized hunt plan |
| `plugins` | Plugin management (list, run) |
| `profile` | Scan profiles (list, show, run) |
| `proxy-set` | Configure proxy |
| `proxy-status` | Show proxy configuration |
| `recon` | Full recon pipeline |
| `replay` | Replay a captured HTTP request |
| `replay-attack` | Replay a registered attack pattern |
| `report` | Generate bug bounty reports |
| `research` | Autonomous vulnerability research |
| `run` | Autonomous framework (full pipeline) |
| `run-custom-tests` | Execute custom attack tests |
| `scan` | Generate/run full recon+vuln script |
| `scope` | Show current program scope |
| `script` | Generate test scripts |
| `secrets` | Secrets discovery |
| `secrets-scan` | Secret Intel Agent (GitHub) |
| `setup` | Create workspace |
| `simulate-attacks` | Monte Carlo attack simulation |
| `simulate-workflow` | Business logic workflow simulation |
| `swarm` | Multi-target swarm scan |
| `swarm-scan` | Single-target swarm intelligence scan |
| `tool` | Run any registered tool directly |
| `toolcheck` | Show installed tools |
| `traffic-export` | Export captured traffic |
| `traffic-list` | List captured traffic |
| `vuln-scan` | Vulnerability scan pipeline |
| `waf-bypass` | WAF-specific bypass payloads |
| `web3` | Web3 / smart contract security (scan, poc, token-scan, full-scan) |
| `workflow` | Build and execute optimal workflow |
| `zero-day` | Zero-day anomaly detection |

### Worker-Related Internal Commands

| Command | Description |
|---|---|
| `worker-start` | Start a distributed worker process |
| `worker-stop` | Stop a worker process |
| `worker-status` | Show worker health and task queue depth |
| `worker-list` | List all connected workers |

---

# 7. Web UI Guide

## Starting the Web UI

```bash
# Backend (FastAPI, port 8000)
cd web/backend
uvicorn main:app --host 0.0.0.0 --port 8000

# Frontend (React/Vite, port 3000)
cd web/frontend
npm install
npm run dev
```

Open `http://localhost:3000`.

> **Authentication:** Set `ONEINFINITY_API_KEY` before starting the backend for a stable key. The frontend reads it from `localStorage` (set via Settings page on first use).

## All 43 Pages

| Page | URL | Description |
|---|---|---|
| Dashboard | `/` | Real-time summary: scan activity, severity distribution, 7-day trends |
| Targets | `/targets` | Target management, scan launcher, status badges |
| Results | `/results` | Findings browser with severity filter tabs and detail panel |
| Attack Graph | `/attack-graph` | Interactive force-directed graph, path highlighting |
| Exploit Chain Viewer | `/exploit-chains` | Chain list, step visualization, PoC download |
| Bounty Hunter | `/bounty-hunter` | Program discovery, session control, live log stream |
| Brain Dashboard | `/graph-brain` | Graph brain: nodes, queue, decisions, triggers, fabric |
| Live Intelligence | `/live-intelligence` | Daemon control, event stream, worker monitor, OSINT |
| System Evolution | `/system-evolution` | Architecture changelog, capability snapshots |
| Orchestrator Panel | `/orchestrator` | Agent coordination, task assignment, status grid |
| Traffic Explorer | `/traffic-explorer` | HTTP capture table, filter, replay, diff |
| Mobile Security | `/mobile-security` | APK/IPA upload, 12-phase status, findings |
| Mobile Agent | `/mobile-agent` | Mobile companion agent status and control |
| Mobile Workspace | `/mobile-workspace` | Multi-app workspace for mobile testing |
| Swarm Intelligence | `/swarm-intelligence` | 8-agent swarm, simulation, workflow, history |
| AI Red Team | `/ai-redteam` | Campaign launcher, generation stats, results |
| Arsenal | `/arsenal` | Nim payload generation UI, binary selector |
| Web3 Center | `/web3-center` | Smart contract scanner, EVM/Solana selector |
| God Mode | `/god-mode` | 6-stage cascade launcher and progress monitor |
| MCP Control | `/mcp-control` | MCP server status, tool list, execution log |
| IDOR Center | `/idor-center` | Multi-account IDOR testing workspace |
| Fuzzer | `/fuzzer` | Interactive fuzzer with wordlist management |
| Payload Library | `/payload-library` | Browse and generate payloads by type/context |
| Learning | `/learning` | KB statistics, pattern viewer, adaptive plan |
| Settings | `/settings` | API key, proxy, notifications, model config |
| Reports | `/reports` | All generated reports with download links |
| Report Preview | `/report-preview` | Rendered markdown/HTML report viewer |
| Research | `/research` | Research mode control and iteration history |
| Secret Dashboard | `/secret-dashboard` | Secret list, LIVE/EXPIRED badges, risk scores |
| Queue Monitor | `/queue-monitor` | Task queue depth, worker utilization |
| System Control | `/system-control` | Tool status, proxy config, cache management |
| System Health | `/system-health` | Doctor results, QA scores, regression status |
| Simulation | `/simulation` | Monte Carlo simulation results and path visualization |
| Tools | `/tools` | Tool registry: installed (green) / missing (red) |
| Tool Analytics | `/tool-analytics` | Per-tool success rate, duration, finding yield |
| Infrastructure | `/infrastructure` | Docker service status, worker scaling |
| CICD Center | `/cicd-center` | CI/CD vulnerability scan results |
| Utilities | `/utilities` | CVSS calculator, dedup checker, scope validator |
| Unified Scan | `/unified-scan` | Single-target full-pipeline launcher |
| AI Models | `/ai-models` | Model registry, tier status, spend tracker |
| Adaptive Planning | `/adaptive-planning` | Visual pipeline builder, adaptive plan recommendations |
| Correlation Matrix | `/correlation-matrix` | Cross-finding correlation and chain probability |
| ExploitChainViewer | `/exploit-chain-viewer` | Detailed exploit chain reconstruction from evidence |

---

# 8. Troubleshooting

## Docker Troubleshooting

| Symptom | Likely Cause | Fix |
|---|---|---|
| `make up` fails with "port 80 already in use" | Another web server on port 80 | Set `HTTP_PORT=8080` in `.env` |
| Workers never pick up tasks | Orchestrator not healthy yet | `make status` — wait for healthy, then `make scan` |
| `WARN: ONEINFINITY_API_KEY not set` | `.env` missing the key | `make setup` then edit `.env` |
| Worker containers restart in a loop | Redis not ready | `make logs` — workers retry 10 times with 3s backoff |
| `No space left on device` during build | Docker disk full | `docker system prune -f` |
| Nuclei templates not found | First-run sync incomplete | Set `NUCLEI_UPDATE=1` in `.env` and restart worker-vuln |
| Grafana shows no data | Monitoring profile not started | Use `make up` not `make up-min` |
| Plugin not loading after hot-drop | plugin-watcher not running | `make status` — ensure `plugin-watcher` is up |

## Common Issues

### `Auth: none | Paths: 0` in Research Mode

**Fix:**
```bash
ls ~/.oneinfinity/raw/<target>/recon/
python run.py recon <target>
```

### `Generated 0 theories`

**Fix:**
```bash
python run.py adaptive-recon <target> --depth deep
python run.py analyze-app <target>
```

### GitHub Token Rate Limit

**Fix:**
```bash
python run.py secrets-scan --target <org> \
  --github-token-file ~/tokens.txt --adaptive-throttle --delay 1.0
```

### Frida Not Connecting

**Fix:**
```bash
adb shell ps | grep frida
adb shell /data/local/tmp/frida-server &
frida --version  # must match frida-server --version
```

### Web UI `403 Invalid or missing X-API-Key`

**Fix:**
```bash
export ONEINFINITY_API_KEY="my-stable-key-here"
uvicorn main:app --host 0.0.0.0 --port 8000
# Open UI → Settings → API Key → enter same key
```

### `nuclei: command not found`

**Fix:**
```bash
go install github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest
export PATH=$PATH:$(go env GOPATH)/bin
python run.py toolcheck | grep nuclei
```

### Web3: Slither Not Found

**Fix:**
```bash
pip install slither-analyzer
# Verify
slither --version
python run.py web3 scan --contract ./test.sol
```

If Slither is installed but not found, check that the virtualenv/path where it is installed is active.

### Nim Binary Integrity Error

**Symptom:** `NimIntegrityError: Integrity check failed for oi-shell-gen`

**Cause:** The binary in `bin/` does not match the SHA-256 in `checksums.json`. Either the binary was corrupted during download, or you rebuilt from source without updating checksums.

**Fix (standard use):**
```bash
# Re-download the repository or run install.sh to restore original binaries
git checkout bin/oi-shell-gen
# Or re-run installer
bash install.sh
```

**Fix (after rebuilding from source):**
```bash
python run.py arsenal update-checksums
```

### Android Companion Not Connecting

**Symptom:** Companion app shows "Connection failed" or "Host not found"

**Fixes:**
1. Ensure `python run.py companion-server --port 9999` is running on desktop
2. Ensure device and desktop are on the same WiFi network
3. Check firewall: port 9999 must be open on desktop
4. Try manual IP entry instead of mDNS discovery
5. For USB connection: `adb forward tcp:9999 tcp:9999` then use `localhost:9999` in the app

### iOS Companion VPN Permission

**Symptom:** VPN activation fails silently or "Permission denied" error

**Fixes:**
1. Ensure the app has Network Extension entitlement in your provisioning profile
2. Go to iOS Settings → VPN & Device Management → verify OneInfinity is listed
3. If the VPN profile is missing, delete and reinstall the app
4. Check that the certificate used to sign the app matches the device's provisioning profile

### MCP Server Not Registering

**Symptom:** Claude Code does not see OneInfinity MCP tools

**Fixes:**
1. Verify `mcp-config.json` is at the project root and properly formatted
2. Check that `python run.py mcp-server` runs without error
3. Restart Claude Code after adding the MCP server configuration
4. Check env vars: `HACKERONE_API_TOKEN` and `HACKERONE_USERNAME` must be set
5. Check Claude Code logs: `~/.claude/logs/` for MCP connection errors

## Debug Flags

```bash
python run.py debug --self-heal
python run.py doctor --deep --json
python run.py cache stats
```

---

# 9. Roadmap

## Shipped in v2.0.0

| Feature | Status |
|---|---|
| Web3 / Smart Contract Security (14 EVM classes, Solana, Foundry PoC) | Shipped |
| Nim Payload Arsenal (6 binaries, SHA-256 integrity) | Shipped |
| Authenticated Testing Suite (session recording, multi-account IDOR) | Shipped |
| Android Companion App (VPN capture, QR/mDNS discovery) | Shipped |
| iOS Companion App (Network Extension, Frida gadget) | Shipped |
| MCP Integration (HackerOne scope, program discovery) | Shipped |
| God Mode (6-stage autonomous cascade) | Shipped |
| New mobile phases (ADB forensics, deep-link fuzzing, SDK scanner) | Shipped |
| AI security extras (LLM DoS, supply chain, multi-turn chainer, RAG poisoning) | Shipped |
| Adversarial WAF engine | Shipped |
| 43-page Web UI | Shipped |
| 75+ CLI commands | Shipped |
| Attack graph Neo4j backend | Shipped |
| Differential scanner + race condition engine | Shipped |

## Shipped in v1.2.0

| Feature | Status |
|---|---|
| Distributed Scanning (Docker 15-service stack, Redis workers) | Shipped |
| Plugin hot-reload | Shipped |

## Planned / Near-Term

| Feature | Description |
|---|---|
| **Nuclei Template Auto-Generation** | AI generates Nuclei YAML templates from confirmed findings |
| **Burp Suite Plugin** | Native Burp extension to sync findings bidirectionally |
| **SOAP/XML API Testing** | Extend API security to SOAP services and XML injection |
| **Platform API Filing** | Direct HackerOne/Bugcrowd report submission via API |
| **Custom AI Model** | Fine-tuned security LLM for more accurate theory generation |
| **Collaborative Mode** | Multi-user shared workspace with real-time collaboration |
| **CVE Correlation** | Auto-correlation of findings to known CVEs and public exploits |
| **Patch Validation** | Re-test confirmed findings after remediation |

## Known Gaps

| Gap | Impact | Workaround |
|---|---|---|
| JS-heavy SPAs | Recon may miss JS-only routes | Use Burp Suite for manual crawling, import traffic |
| OAuth flows | Auth detection doesn't fully trace OAuth 2.0 | Manual AppModel enrichment |
| 2FA-protected login | Cannot test post-login without session tokens | Provide `--auth-session` with pre-authenticated session |
| Private GitHub repos | Secret scanning covers public repos only | Use `trufflehog` directly with full org token |

---

*Documentation v2.0.0 — 2026-06-29*
*GitHub: https://github.com/Inf1n1tyDeS0ul/oneinfinity*
*Contact: infosec.dev.367@gmail.com*
