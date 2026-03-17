# One&Infinity — Autonomous Penetration Testing Assistant

> **AI-Powered Offensive Security Research Framework**
>
> _This project was previously known as **bounty-assistant**._

An autonomous, AI-driven platform for offensive security research, bug bounty automation, mobile security testing, AI security testing, swarm-intelligence–driven vulnerability discovery, and attack graph analysis.

---

## 🚀 Quick Start (3 Steps)

1. **Setup:** `python3 -m venv venv && source venv/bin/activate && pip install -r requirements.txt`
2. **Config:** Copy `.env.example` to `.env` and add your API keys.
3. **Launch:** `oneinfinity scan example.com --yes`

---

## 🛠️ Features

### 💻 CLI Features
- **Full Autonomous Scan:** `oneinfinity scan <target>` runs the entire 7-phase pipeline.
- **Swarm Intelligence:** `oneinfinity swarm-scan <target>` parallelizes 8 specialized security agents.
- **Mobile Analysis:** `oneinfinity mobile-analyze app.apk` runs a comprehensive 12-phase mobile pipeline.
- **AI Security:** `oneinfinity ai-test <target> --all` orchestrates LLM/AI vulnerability scanners.
- **Attack Graph:** `oneinfinity attack-graph <target>` builds and prioritizes lateral movement paths.

### 🌐 Web UI Features
- **Dashboard:** Real-time visualization of findings, scans, and system health.
- **Graph Explorer:** Interactive ForceGraph2D for exploring attack paths and risk.
- **Bounty Hunter:** Dashboard for managing autonomous bug bounty programs and auto-reports.
- **Traffic Explorer:** Intercept and replay HTTP traffic with mutation fuzzing.
- **AI Red Team:** Build and track adversarial prompt campaigns.

### 🔌 API Features
- **FastAPI Backend:** 54+ routes exposing all core engines for external integration.
- **Event Bus:** Asynchronous inter-module communication for decentralized intelligence.
- **Intelligence Daemon:** Always-on background scanner for continuous monitoring.

---

## 🏗️ Architecture Summary

One&Infinity is built on a **multi-layer, event-driven intelligence fabric**. 

- **Core Engines:** Recon, Application Intelligence, Theory Generation, Exploit Generator.
- **Autonomous Layer:** Scan Pipeline, Swarm Coordinator, Attack Graph Brain.
- **Intelligence Layer:** EMA Learning System, Decision Engine, Graph Trigger Engine.
- **Presentation Layer:** React 18 + Vite + Zustand + Recharts dashboard.

---

## CLI

Primary command: `oneinfinity` (55 top-level commands)

```bash
# Core scanning
oneinfinity scan <target>                        # full autonomous pentest
oneinfinity adaptive-recon <target>              # tech detect + JS + cloud assets
oneinfinity research <target> --yes              # autonomous research loop

# Swarm Intelligence
oneinfinity swarm-scan <target> [--agents xss,sqli,ssrf] [--yes]
oneinfinity simulate-attacks <target>            # Monte Carlo path simulation
oneinfinity simulate-workflow <target> [--workflow checkout|login|password_reset|fund_transfer]

# Mobile
oneinfinity mobile-analyze app.apk               # full 12-phase mobile pipeline
oneinfinity mobile-static app.apk                # static analysis only
oneinfinity mobile-secrets app.apk               # secret/credential scanning

# AI Security
oneinfinity ai-test <target> --all               # all AI security tools
oneinfinity ai-redteam <target> --campaign jailbreak --prompts 5000 --parallel 20

# Autonomous Hunter
oneinfinity hunter-start                         # discover programs + auto-scan
oneinfinity hunter-scan <target>                 # single-target pipeline

# Attack Graph
oneinfinity attack-graph <target>                # build + view attack graph
oneinfinity agents run <target> --yes            # multi-agent pentest (legacy)

# Utilities
oneinfinity toolcheck                            # check tool availability
oneinfinity learn stats                          # learning system stats
oneinfinity profile list                         # list scan profiles
oneinfinity cache stats                          # recon cache statistics
```

Legacy compatibility: `python3 bounty.py ...` still works but is deprecated.

---

## Web UI

Start backend + frontend:

```bash
./web/start.sh
```

| Service | URL |
|---------|-----|
| React dashboard | `http://localhost:3000` |
| FastAPI REST | `http://localhost:8000` |
| OpenAPI docs | `http://localhost:8000/docs` |

### Pages

| Page | Route | Description |
|------|-------|-------------|
| Dashboard | `/dashboard` | Overview metrics, recent findings |
| Targets | `/targets` | Target management |
| Results | `/results` | Scan history and live progress |
| Attack Graph | `/attack-graph` | Graph visualization and paths |
| Exploit Chains | `/chains` | Step-by-step chain viewer with I/O and WAF feedback |
| Traffic Explorer | `/traffic` | HTTP capture, replay, WAF intelligence |
| Brain Dashboard | `/brain` | Central intelligence node, priority queue, decisions |
| Live Intelligence | `/intelligence` | Real-time monitoring of triggers and alerts |
| Swarm Intelligence | `/swarm` | Parallel agent execution, workflow simulation |
| System Evolution | `/evolution` | EMA learning system, success rates, payloads |
| Orchestrator | `/orchestrator` | AI Model budget management and routing |
| Mobile Security | `/mobile` | 12-phase mobile pipeline analysis |
| Bounty Hunter | `/hunter` | Autonomous hacker pipelines |
| System Control | `/system` | Platform telemetry and daemon configuration |

---

## Architecture

```
oneinfinity.py (CLI, 55 commands)
    │
    ├── Swarm Intelligence Layer (NEW)
    │   ├── swarm_intelligence_engine.py   — 8 specialized agents + EMA learning
    │   ├── agent_swarm_coordinator.py     — parallel orchestration + event bus
    │   ├── attack_simulation_engine.py    — Monte Carlo N=200 simulations
    │   └── workflow_simulation_engine.py  — business logic attack simulation
    │
    ├── Core Agents
    │   ├── agents/coordinator.py          — orchestrator, sequential phases
    │   ├── agents/recon_agent.py          — subfinder/httpx/katana/waybackurls
    │   ├── agents/scan_agent.py           — nuclei/dalfox/sqlmap/trufflehog
    │   ├── agents/exploit_agent.py        — exploit chain detection
    │   └── agents/report_agent.py         — HackerOne/Bugcrowd reports
    │
    ├── Intelligence Engines
    │   ├── adaptive_recon_engine.py       — tech detect, JS endpoints, cloud
    │   ├── application_intelligence.py    — AppModel: auth flows, API structure
    │   ├── vulnerability_theory_engine.py — 23 rule-based vuln theories
    │   ├── zero_day_engine.py             — anomaly detection
    │   └── attack_graph_core/             — graph engine, risk analyzer, planner
    │
    ├── Mobile Security
    │   ├── mobile_security_engine.py      — 12-phase pipeline
    │   ├── mobile_static_analysis.py      — APKTool + JADX + MobSF
    │   ├── mobile_ai_reverse_engineer.py  — AI-driven analysis
    │   ├── frida_script_generator.py      — auto-generate Frida JS
    │   └── mobile_dynamic_analysis.py     — Frida + Objection runtime
    │
    ├── AI Security
    │   └── ai_security/                   — Garak, PyRIT, prompt injection, campaigns
    │
    └── Web Layer
        ├── web/backend/main.py            — FastAPI, 54+ routes, WebSocket
        └── web/frontend/src/              — React 18, Tailwind, Recharts, Zustand
```

---

## Data Directory

Default: `~/.oneinfinity`

Backward compatibility: if `~/.bounty_assistant` exists and `~/.oneinfinity` does not, the legacy directory is used.

Override: `ONEINFINITY_HOME` or `ONEINFINITY_DATA_DIR` environment variables.

---

## Tool Requirements

**Go tools** (`~/go/bin/`): dalfox, crlfuzz, kxss, dnsx, naabu, gobuster, ffuf, anew, gf, qsreplace, httpx, waybackurls, gauplus, katana, hakrawler, subfinder, assetfinder, amass, nuclei

**Binaries** (`~/.local/bin/`): trufflehog, gitleaks, findomain

**Git clones** (`~/.local/`): sqlmap, xssstrike, jwt_tool, commix, paramspider, dirsearch

**Python packages**: arjun, s3scanner, sublist3r, whatweb, nikto, garak, pyrit
