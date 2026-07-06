# AI-Powered Offensive Security Research Framework : One&Infinity — Complete Platform Architecture

> Autonomous Bug Bounty & AI Security Platform
> Architecture v2.0.0 — covers 200+ files, 30+ packages, 54+ API routes, 75+ CLI commands

---

## Table of Contents

1. [System Overview](#1-system-overview)
2. [Project Directory Structure](#2-project-directory-structure)
3. [Architecture Layers](#3-architecture-layers)
4. [Core Engines](#4-core-engines)
5. [Adaptive Testing System](#5-adaptive-testing-system)
6. [Adaptive Attack Strategy AI](#6-adaptive-attack-strategy-ai)
7. [Autonomous Exploit Engine](#7-autonomous-exploit-engine)
8. [AI Security Testing](#8-ai-security-testing)
9. [Mobile Security Engine](#9-mobile-security-engine)
10. [Web3 / Smart Contract Security](#10-web3--smart-contract-security)
11. [Nim Payload Arsenal](#11-nim-payload-arsenal)
12. [Authenticated Testing Suite](#12-authenticated-testing-suite)
13. [Proxy and Traffic System](#13-proxy-and-traffic-system)
14. [Attack Graph Engine](#14-attack-graph-engine)
15. [Security Copilot](#15-security-copilot)
16. [Data Models](#16-data-models)
17. [Execution Pipeline](#17-execution-pipeline)
18. [Inter-Module Communication](#18-inter-module-communication)
19. [Scalability Design](#19-scalability-design)
20. [Docker Distributed Architecture](#20-docker-distributed-architecture)
21. [MCP Integration](#21-mcp-integration)
22. [God Mode Architecture](#22-god-mode-architecture)
23. [Architecture Diagrams](#23-architecture-diagrams)
24. [Swarm Intelligence Engine](#24-swarm-intelligence-engine)
25. [Self-Evolving Architecture System](#25-self-evolving-architecture-system)
26. [Event-Driven Intelligence Daemon](#26-event-driven-intelligence-daemon)
27. [Graph-Centric Autonomous Architecture](#27-graph-centric-autonomous-architecture)
28. [AI Model Orchestration](#28-ai-model-orchestration)
29. [Diagnostics and Audit Modes](#29-diagnostics-and-audit-modes)
30. [Module Summary](#30-module-summary)

---

## 1. System Overview

The platform is a **multi-layer, event-driven security testing system** organized around five execution modes:

| Mode | Entry Point | Description |
|------|------------|-------------|
| **Autonomous** | `python run.py hunter-start` | Discovers programs, prioritizes targets, runs full pipeline unattended |
| **Directed** | `python run.py scan <target>` | User-specified target through full pipeline |
| **Interactive** | Web UI at `http://localhost:3000` | Manual control of all subsystems via React dashboard (43 pages) |
| **Distributed** | `make scan T=<target>` / API | Redis-backed worker swarm; recon, vuln, exploit, AI, and secrets workers scale independently |
| **God Mode** | `python run.py god-mode <target>` | 6-stage maximum-autonomy cascade with full auth-session support |

The system detects the application type (web/mobile/AI/API/web3) and dynamically selects the OWASP-aligned test suite, learns from historical results, and escalates validated findings into structured bug bounty reports.

> **v2.0.0 note:** The monolithic `oneinfinity.py` entry point has been replaced by `run.py` → `src/oneinfinity/cli/main.py`. All 75+ commands are organized into per-group modules under `src/oneinfinity/cli/commands/`. The old `oneinfinity.py` no longer exists.

---

## 2. Project Directory Structure

```
oneinfinity/
│
├── run.py                                # CLI entry point (delegates to src/oneinfinity/cli/main.py)
├── pyproject.toml                        # Single dependency source (extras: ai, mobile, web, distributed)
├── install.sh                            # One-click installer (all platforms)
├── checksums.json                        # SHA-256 hashes for Nim binaries in bin/
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
│   ├── cli/                              # CLI command modules
│   │   ├── main.py                       # Argparse root; 75+ command dispatcher
│   │   └── commands/                     # One file per command group
│   │
│   ├── orchestration/                    # Scan pipeline & AI model orchestration
│   │   ├── model_orchestrator.py         # Cost-aware 3-tier AI routing engine
│   │   ├── backends/                     # Pluggable AI provider backends
│   │   │   ├── __init__.py               # BaseBackend registry + BackendResult dataclass
│   │   │   ├── ollama.py                 # Ollama local LLM (auto-discover, tier heuristics)
│   │   │   └── cli.py                    # Codex CLI + Claude Code CLI subprocess backends
│   │   ├── autonomous_decision_engine.py # AI-driven node → agent dispatch
│   │   ├── god_mode_engine.py            # 6-stage full-autonomy scan controller
│   │   ├── graph_trigger_engine.py       # 15 rule-based graph triggers
│   │   ├── event_bus.py                  # Async publish/subscribe event bus
│   │   ├── enforcement_controller.py     # Scope + rate-limit enforcement
│   │   └── research_mode_controller.py   # Autonomous research loop
│   │
│   ├── recon/                            # Recon & OSINT engines
│   ├── scan/                             # 80+ vulnerability scanning engines
│   │   ├── blind_xss_engine.py
│   │   ├── cache_deception_scanner.py
│   │   ├── captcha_bypass_engine.py
│   │   ├── cicd_vuln_scanner.py
│   │   ├── container_escape_scanner.py
│   │   ├── deserialization_scanner.py
│   │   ├── differential_scanner.py
│   │   ├── dns_rebinding_scanner.py
│   │   ├── dns_security_scanner.py
│   │   ├── go_idor_engine.py
│   │   ├── go_oob_listener.py
│   │   ├── go_ssrf_engine.py
│   │   ├── go_service_cve_mapper.py
│   │   ├── grpc_scanner.py
│   │   ├── h2c_scanner.py
│   │   ├── http2_attack_engine.py
│   │   ├── js_chunk_enumerator.py
│   │   ├── js_source_map_reconstructor.py
│   │   ├── jwt_vulnerability_scanner.py
│   │   ├── mass_assignment_scanner.py
│   │   ├── nosql_injection_scanner.py
│   │   ├── oauth_token_leak_scanner.py
│   │   ├── oob_engine.py
│   │   ├── prototype_pollution_scanner.py
│   │   ├── race_condition_engine.py
│   │   ├── rust_jwt_crack.py
│   │   ├── smuggling_engine.py
│   │   ├── supply_chain_attack_engine.py
│   │   ├── traffic_capture_engine.py
│   │   ├── traffic_correlation_engine.py
│   │   ├── traffic_replay_engine.py
│   │   ├── waf_detection_engine.py
│   │   ├── websocket_scanner.py
│   │   ├── xxe_scanner.py
│   │   └── ... (50+ additional engines)
│   │
│   ├── attack/                           # Exploit generation & replay
│   ├── attack_graph_core/                # Attack graph model, builder, analyzer, path simulator
│   ├── swarm/                            # 8-agent swarm + coordinator
│   ├── intelligence/                     # Daemon, swarm controller, attack simulation
│   ├── findings/                         # Result ingestion, dedup, validation, classifier
│   ├── exploit_chains/                   # 6 chain patterns + PoC generator + engine
│   ├── bounty/                           # Bug bounty hunter, ROI engine, report generator
│   │
│   ├── ai_security/                      # AI red-team, prompt injection, framework wrappers
│   │   ├── adversarial_waf_engine.py     # Adversarial WAF bypass generation
│   │   ├── llm_dos_engine.py             # LLM denial-of-service testing
│   │   ├── llm_supply_chain_scanner.py   # Supply chain attack surface for LLM pipelines
│   │   ├── multi_turn_chainer.py         # Multi-turn conversation attack chaining
│   │   ├── rag_poisoning_engine.py       # RAG poisoning and indirect injection
│   │   └── ... (existing AI security modules)
│   │
│   ├── mobile/                           # 12-phase mobile pipeline + new phase modules
│   │   ├── adb_forensics.py              # ADB-based forensic extraction
│   │   ├── deep_link_fuzzer.py           # Deep link fuzzing and abuse
│   │   ├── sdk_scanner.py                # Third-party SDK vulnerability scanner
│   │   ├── intent_fuzzer.py              # Android Intent fuzzer
│   │   ├── mastg_knowledge.py            # OWASP MASTG knowledge base
│   │   ├── android_studio_integration.py # AVD launch, APK install, Burp cert push
│   │   └── ... (original 12 phase modules)
│   │
│   ├── web3/                             # Smart contract & blockchain security
│   │   ├── smart_contract_scanner.py     # 14 EVM vulnerability classes
│   │   ├── evm_token_scanner.py          # ERC-20/721/1155 token security
│   │   ├── foundry_poc_generator.py      # Foundry-based PoC generation
│   │   ├── slither_wrapper.py            # Slither static analysis wrapper
│   │   └── solana_scanner.py             # Solana program security scanner
│   │
│   ├── arsenal/                          # Nim payload generation arsenal
│   │   ├── bypass/                       # WAF/AV bypass payloads
│   │   ├── chains/                       # Exploit chain payloads
│   │   └── shells/                       # Shell payload templates
│   │
│   ├── auth/                             # Authenticated testing suite
│   │   ├── login_form_detector.py        # Automatic login form detection
│   │   ├── login_session_recorder.py     # Session recording with browser automation
│   │   ├── auth_session_context.py       # Session context dataclass + serialization
│   │   ├── session_manager.py            # Multi-session management + cookie jar
│   │   ├── session_replay.py             # Authenticated request replay engine
│   │   ├── multi_account_idor_engine.py  # Cross-account IDOR testing
│   │   ├── go_credential_spray.py        # Go-based credential spraying
│   │   └── authenticated_test_suite.py   # Orchestrates all auth-aware tests
│   │
│   ├── mcp/                              # MCP server integration
│   │   ├── server.py                     # FastMCP server registration + tool routing
│   │   └── hackerone_mcp_tool.py         # h1_get_scope, h1_list_programs tools
│   │
│   ├── infra/                            # ModelBudgetManager, TaskClassifier, shared infra
│   ├── learning/                         # AdaptivePlanner, KnowledgeBase, PatternMiner
│   ├── pipeline/                         # 7-phase autonomous scan pipeline orchestrator
│   ├── agents/                           # BaseAgent, coordinator, SecretIntelAgent
│   ├── modules/                          # Tool wrappers (40+), payload library, scope, CVSS
│   ├── core/                             # DBManager, PG client, dedup, cache, scan profiles
│   ├── framework/                        # OWASP framework orchestrator
│   ├── plugins/                          # Hot-reloadable recon + vuln plugins
│   ├── utils/                            # Shared utilities
│   ├── worker/                           # Distributed worker task handlers
│   └── casl/                             # Authorization/capability definitions
│
├── src/nim/                              # Nim source for compiled payload binaries
│   ├── oi-shell-gen/
│   ├── oi-bypass-gen/
│   ├── oi-payloads/
│   ├── oi-post-exploit/
│   ├── oi-fuzzer/
│   └── oi-privesc-gen/
│
├── bin/                                  # Compiled Nim binaries (SHA-256 verified)
│   ├── oi-shell-gen
│   ├── oi-bypass-gen
│   ├── oi-payloads
│   ├── oi-post-exploit
│   ├── oi-fuzzer
│   └── oi-privesc-gen
│
├── android-companion/                    # Android VPN-capture companion app (Kotlin)
│   ├── app/src/main/
│   │   ├── vpn/                          # VpnService implementation
│   │   ├── discovery/                    # QR code + mDNS + manual discovery
│   │   └── transport/                    # Traffic forwarding to OneInfinity
│   └── README.md
│
├── ios-companion/                        # iOS Network Extension companion app (Swift)
│   ├── OneInfinityCapture/
│   │   ├── NetworkExtension/             # NEPacketTunnelProvider
│   │   ├── Frida/                        # Frida gadget integration
│   │   └── Discovery/                    # QR/mDNS/manual discovery
│   └── README.md
│
├── web/
│   ├── backend/                          # FastAPI backend (54+ routes)
│   └── frontend/                         # React UI (43 pages)
│
├── tests/                                # 130+ test files
├── frida_scripts/                        # Pre-built Frida scripts
├── scripts/                              # Native install scripts
├── db/                                   # DB schema
├── missions/                             # Saved mission configurations
├── plugins/                              # User/community plugins
└── docs/                                 # Documentation
```

---

## 3. Architecture Layers

```
┌─────────────────────────────────────────────────────────────────────────┐
│                          PRESENTATION LAYER                              │
│  React 18 + Vite + Zustand + Recharts + ForceGraph2D                    │
│  43 pages: Dashboard / Targets / Results / AttackGraph / Chains /       │
│             BrainDashboard / LiveIntelligence / SystemEvolution /        │
│             OrchestratorPanel / TrafficExplorer / MobileSecurity /      │
│             MobileAgent / MobileWorkspace / SwarmIntelligence /         │
│             AIRedTeam / Arsenal / Web3Center / GodMode / MCPControl /   │
│             BountyHunter / IDORCenter / Fuzzer / PayloadLibrary /       │
│             Learning / Settings / Reports / ReportPreview / Research /  │
│             SecretDashboard / QueueMonitor / SystemControl /            │
│             SystemHealth / SystemEvolution / Simulation / Tools /       │
│             ToolAnalytics / Infrastructure / CICDCenter / Utilities /   │
│             UnifiedScan / AIModels / AdaptivePlanning / ExploitChainViewer│
└─────────────────────────┬───────────────────────────────────────────────┘
                          │  HTTP/WebSocket  (Vite proxy: /api → :8000)
┌─────────────────────────▼───────────────────────────────────────────────┐
│                           API GATEWAY LAYER                              │
│  FastAPI (main.py) — 54+ routes + WS /ws/logs                          │
│  Spawns run.py subprocesses for long-running scans                     │
└──────────┬──────────────────────────────────┬───────────────────────────┘
           │ subprocess / import              │ import
┌──────────▼──────────────┐        ┌──────────▼──────────────────────────┐
│      CLI LAYER          │        │      ORCHESTRATION LAYER             │
│  run.py → cli/main.py   │        │  autonomous_scan_pipeline.py         │
│  75+ argparse commands  │        │  bounty_hunter_engine.py             │
│  per-group command files│        │  god_mode_engine.py                  │
└──────────┬──────────────┘        └──────────┬──────────────────────────┘
           │                                  │
┌──────────▼──────────────────────────────────▼──────────────────────────┐
│                        INTELLIGENCE LAYER                                │
│  adaptive_recon_engine     application_intelligence    zero_day_engine  │
│  vulnerability_theory_engine    research_mode_controller                │
│  learning/adaptive_planner    learning/knowledge_base                   │
└──────────────────────────────┬──────────────────────────────────────────┘
                               │
┌──────────────────────────────▼──────────────────────────────────────────┐
│                         SECURITY ENGINE LAYER                            │
│  Web Engine (scan/ 80+)   AI Engine (ai_security/)   Mobile (mobile/)   │
│  Exploit Engine            Web3 Engine (web3/)        Auth (auth/)       │
│  Attack Graph              Proxy/Traffic              Nim Arsenal (bin/) │
│  MCP Server (mcp/)         Copilot                   Plugin System      │
└──────────────────────────────┬──────────────────────────────────────────┘
                               │
┌──────────────────────────────▼──────────────────────────────────────────┐
│                          TOOL WRAPPER LAYER                              │
│  modules/tool_wrappers.py — ToolRegistry — 40+ tool wrappers            │
│  subfinder amass httpx naabu katana nuclei dalfox sqlmap trufflehog     │
│  gitleaks jwt_tool arjun s3scanner dnsx gf ffuf gobuster dirsearch      │
│  slither foundry hardhat  adb frida objection drozer MobSF              │
└──────────────────────────────┬──────────────────────────────────────────┘
                               │
┌──────────────────────────────▼──────────────────────────────────────────┐
│                    EXTERNAL TOOLS & STORAGE LAYER                        │
│  Go binaries (~/go/bin/)    Nim binaries (bin/) SHA-256 verified        │
│  SQLite: findings.db  knowledge_base.db  research.db  recon_cache.db    │
│  PostgreSQL (POSTGRES_URL)  Neo4j (NEO4J_ENABLED=1)  Redis              │
└─────────────────────────────────────────────────────────────────────────┘
```

---

## 4. Core Engines

### 4.1 `framework/recon_engine.py` — ReconEngine

```python
@dataclass
class HostInfo:
    domain: str
    ip_addresses: list[str]
    open_ports: list[PortInfo]
    subdomains: list[str]
    live_hosts: list[str]
    web_servers: list[str]
    tls_info: dict
    cdn: Optional[str]
    waf: Optional[str]
    technologies: list[str]

@dataclass
class ReconResult:
    target: str
    hosts: list[HostInfo]
    urls: list[str]
    endpoints: list[str]
    js_endpoints: list[str]
    parameters: list[str]
    secrets_found: list[dict]
    started_at: str
    duration_s: float
    tool_results: dict[str, ToolResult]

class ReconEngine:
    def run(self, target: str, profile: ScanProfile) -> ReconResult: ...
    def _run_subdomain_enum(self, target) -> list[str]: ...
    def _run_http_probe(self, hosts) -> list[HostInfo]: ...
    def _run_crawl(self, live_hosts) -> list[str]: ...
    def _extract_js_endpoints(self, urls) -> list[str]: ...
    def _run_parameter_discovery(self, urls) -> list[str]: ...
```

### 4.2 `framework/vuln_scanner.py` — VulnScanner

```python
@dataclass
class VulnCandidate:
    vuln_type: str
    url: str
    parameter: str
    payload: str
    evidence: str
    severity: str
    tool: str
    raw_output: str
    confidence: float
    cvss_score: float

class VulnScanner:
    OWASP_TOP10_MAP = {
        "A01": ["idor", "bac", "auth_bypass"],
        "A02": ["default_creds", "weak_password", "missing_mfa"],
        "A03": ["sqli", "xss", "ssti", "xxe", "cmdi"],
        "A04": ["insecure_design", "missing_rate_limit"],
        "A05": ["misconfig", "debug_enabled", "cors_misconfiguration"],
        "A06": ["outdated_component", "known_cve"],
        "A07": ["missing_auth", "broken_session"],
        "A08": ["deserialization", "unsafe_upload"],
        "A09": ["missing_logging", "log_injection"],
        "A10": ["ssrf", "request_smuggling"],
    }
```

### 4.3 `adaptive_recon_engine.py` — AdaptiveReconEngine

```python
@dataclass
class TechProfile:
    frameworks: list[str]
    languages: list[str]
    databases: list[str]
    cloud: list[str]
    cdn: Optional[str]
    waf: Optional[str]
    cms: Optional[str]
    api_style: str            # rest / graphql / grpc / soap
    mobile_api: bool
    authentication: list[str]

class AdaptiveReconEngine:
    def run(self, target: str) -> ReconIntelligence: ...
    def _detect_technologies(self, target) -> TechProfile: ...
    def _extract_js_endpoints(self, target, tech) -> list[str]: ...
    def _recommend_tests(self, tech: TechProfile) -> list[str]: ...
```

### 4.4 `application_intelligence.py` — ApplicationIntelligence

```python
@dataclass
class AppModel:
    target: str
    auth_flows: list[AuthFlow]
    api_endpoints: list[APIEndpoint]
    sensitive_features: list[SensitiveFeature]
    user_roles: list[str]
    privileged_endpoints: list[str]
    data_entities: list[str]
    business_logic_flows: list[dict]

class ApplicationIntelligence:
    def build_model(self, target: str, recon: ReconResult) -> AppModel: ...
    def identify_auth_flows(self, urls: list[str]) -> list[AuthFlow]: ...
    def map_api_surface(self, urls: list[str]) -> list[APIEndpoint]: ...
    def infer_roles(self, endpoints: list[APIEndpoint]) -> list[str]: ...
```

---

## 5. Adaptive Testing System

### 5.1 `security_test_orchestrator.py` — SecurityTestOrchestrator

```python
class SecurityTestOrchestrator:
    def __init__(self):
        self.detector = ApplicationDetector()
        self.tech_detector = TechnologyDetector()
        self.selector = TestSelectionEngine()
        self.vuln_scanner = VulnScanner(...)

    def orchestrate(self, target: str, recon: ReconResult) -> TestPlan:
        app_type = self.detector.detect(target, recon)
        tech = self.tech_detector.fingerprint(target, recon)
        model = ApplicationIntelligence().build_model(target, recon)
        tests = self.selector.select(app_type, tech, model)
        return TestPlan(target=target, app_type=app_type, tech=tech,
                        tests=tests, priority_order=tests.prioritized())

    def execute(self, plan: TestPlan) -> list[VulnCandidate]:
        results = []
        for test in plan.tests:
            if test.prerequisites_met(results):
                findings = self.vuln_scanner.run_test(test, plan)
                results.extend(findings)
                self.selector.update_priority(test, findings)
        return results
```

### 5.2 `application_detector.py` — ApplicationDetector

```python
class AppType(str, Enum):
    WEB         = "web"
    MOBILE_API  = "mobile_api"
    GRAPHQL     = "graphql"
    GRPC        = "grpc"
    AI_ENDPOINT = "ai_endpoint"
    MICROSERVICE= "microservice"

class ApplicationDetector:
    SIGNALS = {
        AppType.GRAPHQL:     ["/graphql", "/api/graphql", "__schema"],
        AppType.AI_ENDPOINT: ["/v1/chat/completions", "/api/generate", "/predict"],
        AppType.GRPC:        ["application/grpc", ":50051", "proto"],
        AppType.MOBILE_API:  ["/api/v", "/mobile/", "X-App-Version:"],
    }
```

### 5.3 `technology_detector.py` — TechnologyDetector

```python
class TechnologyDetector:
    TECH_SIGNATURES = {
        "django":    ["csrfmiddlewaretoken", "django"],
        "rails":     ["_rails_", "rack.", "X-Powered-By: Phusion Passenger"],
        "spring":    ["JSESSIONID", "X-Application-Context"],
        "wordpress": ["/wp-content/", "/wp-admin/", "wp-json"],
        "graphql":   ["__typename", "graphql", "ApolloServer"],
        "jwt":       ["eyJ", "Authorization: Bearer"],
        "aws":       ["s3.amazonaws.com", "cloudfront.net", "X-Amz-"],
    }
```

### 5.4 `test_selection_engine.py` — TestSelectionEngine

```python
@dataclass
class SecurityTest:
    test_id: str
    owasp_category: str
    priority: int
    tool: str
    requires: list[str]
    applicable_to: list[AppType]
    tech_triggers: list[str]

class TestSelectionEngine:
    TEST_CATALOG = {
        "sqli_error":         SecurityTest("sqli_error",   "A03", 1, "sqlmap", [], ...),
        "xss_reflected":      SecurityTest("xss_reflected","A03", 1, "dalfox", [], ...),
        "ssrf_basic":         SecurityTest("ssrf_basic",   "A10", 1, "nuclei", [], ...),
        "idor_sequential":    SecurityTest("idor_sequential","A01",1, "custom_test_engine", ...),
        "jwt_alg_none":       SecurityTest("jwt_alg_none", "A02", 1, "jwt_tool", ...),
        "ai_prompt_inject":   SecurityTest("ai_prompt_inject","A03",1,"ai_security_engine",...),
        "graphql_introspect": SecurityTest("graphql_introspect","A05",1,"nuclei",...),
    }

    def select(self, app_type, tech, model) -> list[SecurityTest]: ...
    def update_priority(self, test, findings): ...
```

**Interaction Flow:**
```
AdaptiveReconEngine → TechProfile
                    ↓
ApplicationIntelligence → AppModel
                    ↓
ApplicationDetector → AppType
                    ↓
TestSelectionEngine.select(AppType, TechProfile, AppModel) → [SecurityTest]
                    ↓
SecurityTestOrchestrator.execute([SecurityTest]) → [VulnCandidate]
```

---

## 6. Adaptive Attack Strategy AI

### 6.1 `adaptive_attack_strategy.py`

```python
@dataclass
class AttackStrategy:
    target: str
    tech_stack: list[str]
    phase_order: list[str]
    tool_overrides: dict[str, str]
    skip_phases: list[str]
    focus_vuln_types: list[str]
    confidence: float
    rationale: str

class AdaptiveAttackStrategy:
    def get_strategy(self, target: str, tech_stack: list[str]) -> AttackStrategy: ...
    def record_result(self, target, vuln_type, tool, success, duration_s): ...
```

### 6.2 `attack_strategy_learning.py`

```python
class AttackStrategyLearning:
    TABLES = {
        "tool_runs":      "(target, tool, vuln_type, success, duration_s, timestamp)",
        "findings":       "(target, vuln_type, severity, tool, tech_stack, timestamp)",
        "tech_patterns":  "(tech_stack, vuln_type, success_rate, sample_count)",
        "target_profiles":"(domain, tech_hash, last_scan, scan_count, finding_count)",
    }

    def best_tool_for_vuln(self, vuln_type: str, tech_stack: list[str]) -> str: ...
    def predict_vulns(self, tech_stack: list[str]) -> list[tuple[str, float]]: ...
    def get_successful_payloads(self, vuln_type: str, tech: str) -> list[str]: ...
```

### 6.3 `attack_strategy_planner.py`

```python
class AttackStrategyPlanner:
    BASELINE_PHASES = [
        "recon", "scan_nuclei", "triage",
        "scan_xss", "scan_sqli", "scan_ssrf",
        "scan_secrets", "exploit", "validate", "report"
    ]

    PHASE_VULN_MAP = {
        "scan_xss":     ["xss", "ssti", "template_injection"],
        "scan_sqli":    ["sqli", "nosqli"],
        "scan_ssrf":    ["ssrf", "lfi", "rfi", "xxe"],
        "scan_secrets": ["hardcoded_secret", "exposed_config", "api_key_leak"],
        "triage":       ["idor", "bac", "missing_auth"],
    }

    def plan(self, target: str, tech_stack: list[str],
             quick_mode: bool = False) -> AdaptivePlan: ...
```

---

## 7. Autonomous Exploit Engine

### 7.1 `exploit_generator.py` — ExploitGenerator

```python
@dataclass
class ExploitPayload:
    vuln_type: str
    payload: str
    encoding: str
    context: str
    canary: str
    description: str

class ExploitGenerator:
    SQLI_PAYLOADS    = {"error_based": [...], "union": [...], "blind_boolean": [...],
                        "blind_time": [...], "auth_bypass": [...]}
    XSS_PAYLOADS     = {"reflected": [...], "dom": [...], "stored": [...],
                        "csp_bypass": [...], "canary": [...]}
    SSRF_PAYLOADS    = {"internal": [...], "cloud_metadata": [...],
                        "protocol_smuggling": [...], "ip_bypass": [...]}
    SSTI_PAYLOADS    = {"jinja2": [...], "freemarker": [...], "velocity": [...],
                        "twig": [...], "smarty": [...]}
    CMDI_PAYLOADS    = {"unix": [...], "windows": [...], "blind": [...]}
    IDOR_PAYLOADS    = {"sequential": [...], "uuid_predict": [...], "type_juggling": [...]}

    def generate(self, vuln_type: str, context: dict) -> list[ExploitPayload]: ...
    def _apply_waf_bypass(self, payloads, waf: str) -> list[str]: ...
```

### 7.2 `autonomous_exploit_engine.py` — AutonomousExploitEngine

```python
@dataclass
class ExploitResult:
    finding_id: str
    vuln_type: str
    url: str
    parameter: str
    successful_payload: str
    evidence: str
    impact: str
    cvss_score: float
    validated: bool
    poc_steps: list[str]

class AutonomousExploitEngine:
    CVSS_BASE = {
        "sqli": 9.8, "cmdi": 9.8, "rce": 9.8, "ssti": 9.8,
        "ssrf": 8.6, "auth_bypass": 9.1,
        "xss": 6.1, "idor": 6.5, "lfi": 7.5,
    }

    def exploit_target(self, target: str, candidates: list[VulnCandidate]) -> ExploitSession: ...
    def _exploit_candidate(self, c: VulnCandidate) -> Optional[ExploitResult]: ...
```

### 7.3 `finding_validation_engine.py` — FindingValidationEngine

```python
class FindingValidationEngine:
    EVIDENCE_PATTERNS = {
        "sqli":  [r"SQL syntax", r"mysql_fetch", r"ORA-\d+", r"SQLite"],
        "ssti":  [r"49", r"7777777"],
        "lfi":   [r"root:x:0:0", r"\[boot loader\]"],
        "xxe":   [r"root:x:0:0", r"SYSTEM"],
        "rce":   [r"uid=\d+", r"root", r"Windows IP"],
    }

    def validate(self, vuln_type: str, url: str, parameter: str,
                 payload: str) -> ValidationResult: ...
    def _validate_xss(self, url, param, payload) -> ValidationResult: ...
    def _validate_sqli(self, url, param, payload) -> ValidationResult: ...
    def _validate_oob(self, url, param, payload, vuln_type) -> ValidationResult: ...
```

---

## 8. AI Security Testing

### 8.1 `ai_security_engine.py` — AISecurityEngine

```python
@dataclass
class AISecurityScanConfig:
    target_url: str
    model_id: str
    api_key: Optional[str]
    attack_types: list[str]
    use_garak: bool
    use_pyrit: bool
    use_evolution: bool
    parallel_workers: int

class AISecurityEngine:
    def scan(self, config: AISecurityScanConfig) -> AISecurityScanResult: ...
```

### 8.2 `ai_redteam_engine.py` — AIRedTeamEngine

```python
class AIRedTeamEngine:
    CAMPAIGN_TYPES = {
        "jailbreak":        JailbreakCampaign,
        "rag_attack":       RAGPoisoningCampaign,
        "tool_abuse":       ToolAbuseCampaign,
        "model_extraction": ModelExtractionCampaign,
        "data_exfil":       DataExfiltrationCampaign,
        "prompt_injection": PromptInjectionCampaign,
    }

    def run_campaign(self, target, campaign_type, num_prompts=1000, parallel=10): ...
```

### 8.3 AI Security Extras (v2.0.0)

| Module | Description |
|--------|-------------|
| `adversarial_waf_engine.py` | Generates adversarial inputs to bypass ML-based WAFs using transferability-based attack strategies |
| `llm_dos_engine.py` | Tests LLM endpoints for resource exhaustion via long context, token flooding, and repetitive looping prompts |
| `llm_supply_chain_scanner.py` | Scans LLM pipelines for supply chain risks: model file tampering, poisoned datasets, malicious plugins |
| `multi_turn_chainer.py` | Builds multi-turn conversation attack sequences; accumulates context across turns to defeat per-turn filters |
| `rag_poisoning_engine.py` | Poisons RAG pipelines via document injection, context window overflow, and indirect prompt injection |

### 8.4 Prompt Generation and Mutation

```python
class PromptGenerator:
    ATTACK_TEMPLATES = {
        "jailbreak":        [...],  # 200+ DAN / roleplay / academic variants
        "prompt_injection": [...],  # HTML comment, semicolon, newline injection
        "data_exfil":       [...],
        "tool_abuse":       [...],
    }

class PayloadMutator:
    STRATEGIES = [
        "synonym_replacement", "base64_encode", "homoglyph_substitution",
        "rot13", "leetspeak", "whitespace_injection", "language_switch",
        "role_play_framing", "academic_framing", "reverse_instruction",
        "token_splitting", "json_injection", "markdown_escape",
        "unicode_escape", "prompt_chaining", "suffix_attack",
        "few_shot_override", "context_overflow",
    ]
```

---

## 9. Mobile Security Engine

### 9.1 Extended Phase Pipeline

```
APK/IPA Upload
     │
Phase 0: TOOL REGISTRY — auto-discover 12+ tools
Phase 1: UPLOAD & EXTRACT — SHA-256 dedup, metadata
Phase 2: STATIC ANALYSIS — APKTool + JADX + MobSF
Phase 3: AI REVERSE ENGINEERING — AppModel, auth/crypto detection
Phase 4: FRIDA SCRIPT GENERATION — SSL pinning, root, auth hooks
Phase 5: SECRET DETECTION — 32+ regex + TruffleHog + Gitleaks
Phase 6: API DISCOVERY — Retrofit/OkHttp/URLSession/GraphQL
Phase 7: ANDROID COMPONENT TESTING — Drozer + intent analysis
Phase 8: DYNAMIC ANALYSIS — Frida + Objection + RMS
Phase 9: NETWORK TRAFFIC ANALYSIS — Burp integration, cleartext detection
Phase 10: API ATTACK & FUZZING — IDOR, auth bypass, mass assignment
Phase 11: ADB FORENSICS (v2.0.0)
  adb_forensics.py — device data extraction, shared prefs, logcat history
Phase 12: DEEP-LINK / INTENT FUZZING (v2.0.0)
  deep_link_fuzzer.py — enumerate and fuzz all deep link schemes
  intent_fuzzer.py — fuzz Android intents with malformed data
  sdk_scanner.py — identify vulnerable third-party SDK versions
  mastg_knowledge.py — OWASP MASTG control checklist overlay
     │
MobileSecurityReport
  - risk_score, all_vulnerabilities, severity_counts, frida_scripts
```

### 9.2 Tool Integration Matrix

| Tool | Phase | Mode | Availability |
|------|-------|------|-------------|
| APKTool | Static | Automatic | Optional (apt install apktool) |
| JADX | Static | Automatic | Optional (brew/snap install jadx) |
| MobSF | Static+Dynamic | API | Optional (Docker or pip) |
| TruffleHog | Secrets | Automatic | Installed (~/.local/bin) |
| Gitleaks | Secrets | Automatic | Optional |
| Frida | Dynamic | Script injection | Optional (pip install frida-tools) |
| Objection | Dynamic | Runtime | Optional (pip install objection) |
| RMS | Dynamic | Runtime | Optional (npm) |
| Drozer | Components | ADB-based | Optional |
| ADB | Dynamic | Device bridge | Optional |
| strings | Secrets | Binary | Usually pre-installed |

### 9.3 Android Companion App

```
Android Device
     │
OneInfinity Companion App (VpnService, Kotlin)
  ├── VPN-mode traffic capture (all app traffic intercepted)
  ├── Discovery: QR code / mDNS auto-discovery / manual IP:port
  └── Forwards captured packets → OneInfinity desktop instance
         │
traffic_capture_engine.py → traffic.db → TrafficExplorer UI
```

Install workflow:
```bash
cd android-companion
./gradlew assembleDebug
adb install app/build/outputs/apk/debug/app-debug.apk
```

### 9.4 iOS Companion App

```
iOS Device (iOS 16+, Xcode 15+)
     │
OneInfinity iOS Companion (Swift)
  ├── NEPacketTunnelProvider (Network Extension entitlement required)
  ├── Frida gadget injection for targeted app analysis
  ├── Discovery: QR / mDNS / manual
  └── Streams captured traffic → OneInfinity desktop
```

**Requirements:** iOS 16+, Xcode 15+, valid Apple Developer account.

---

## 10. Web3 / Smart Contract Security

### 10.1 Architecture Flow

```
Target: contract address / project source / Hardhat project
         │
SmartContractScanner (smart_contract_scanner.py)
  ├── Slither static analysis (slither_wrapper.py)
  ├── 14 EVM vulnerability pattern detectors
  ├── Source fetching (Etherscan API / local)
  └── Findings → Web3Finding
         │
EVMTokenScanner (evm_token_scanner.py)
  ├── ERC-20/721/1155 compliance checks
  ├── permit() signature abuse
  └── Approval front-running analysis
         │
SolanaScanner (solana_scanner.py)
  ├── Anchor framework audit
  ├── Account validation checks
  └── CPI safety checks
         │
FoundryPocGenerator (foundry_poc_generator.py)
  ├── Generates *.t.sol Foundry test files per finding
  ├── Flash loan PoC templates
  └── Re-entrancy PoC scaffolding
```

### 10.2 SmartContractScanner — 14 EVM Vulnerability Classes

| Class | Description |
|-------|-------------|
| `reentrancy` | Classic and cross-function re-entrancy |
| `integer_overflow` | Unchecked arithmetic (pre-0.8.x) |
| `access_control` | Missing `onlyOwner` / `onlyRole` guards |
| `tx_origin` | `tx.origin` authentication |
| `price_manipulation` | Oracle price manipulation, spot price reliance |
| `flash_loan_attack` | Flash loan-enabled attack vectors |
| `front_running` | MEV / sandwich attack exposure |
| `selfdestruct` | Forced Ether via selfdestruct |
| `delegatecall` | Unsafe delegatecall storage collision |
| `unchecked_return` | Unchecked low-level call return values |
| `timestamp_dependence` | Block timestamp manipulation |
| `denial_of_service` | Gas limit DoS, unbounded loops |
| `signature_replay` | Missing nonce / chainId in signatures |
| `logic_error` | Business logic flaws (custom rule engine) |

### 10.3 SlitherWrapper

```python
class SlitherWrapper:
    """Requires: pip install slither-analyzer"""

    def analyze(self, contract_path: str,
                target_contract: Optional[str] = None) -> SlitherResult:
        """Runs: slither <path> --json - and parses detector output."""

    def analyze_remote(self, address: str,
                       network: str = "mainnet") -> SlitherResult:
        """Fetches verified source from Etherscan then analyzes."""
```

---

## 11. Nim Payload Arsenal

### 11.1 Compiled Binaries

| Binary | Purpose | Key Flags |
|--------|---------|-----------|
| `oi-shell-gen` | Reverse shell payloads in 20+ languages | `--lang`, `--ip`, `--port`, `--encode` |
| `oi-bypass-gen` | WAF/EDR/AV bypass variants | `--technique`, `--target-waf`, `--obfuscation` |
| `oi-payloads` | 200+ payload templates | `--type`, `--context`, `--encode` |
| `oi-post-exploit` | Post-exploitation command sequences | `--os`, `--phase`, `--lolbins` |
| `oi-fuzzer` | High-speed input fuzzer | `--wordlist`, `--threads`, `--rate` |
| `oi-privesc-gen` | Privilege escalation payload chains | `--os`, `--technique`, `--check` |

### 11.2 Integrity Verification (`nim_runner.py`)

```python
class NimIntegrityError(Exception):
    """Raised when a Nim binary fails SHA-256 verification."""

class NimExecutionError(Exception):
    """Raised when a Nim binary returns non-zero exit code."""

class NimRunner:
    CHECKSUMS_FILE = "checksums.json"

    def _verify(self, binary: str) -> None:
        """Compute SHA-256 of bin/<binary>, compare against checksums.json."""
        path = self.bin_dir / binary
        digest = hashlib.sha256(path.read_bytes()).hexdigest()
        expected = self._checksums.get(binary)
        if digest != expected:
            raise NimIntegrityError(
                f"Integrity check failed for {binary}: "
                f"got {digest[:16]}... expected {expected[:16]}..."
            )

    def run(self, binary: str, args: list[str],
            timeout: int = 30) -> subprocess.CompletedProcess:
        """Verify then execute. Raises NimIntegrityError or NimExecutionError."""
        self._verify(binary)
        result = subprocess.run(
            [str(self.bin_dir / binary)] + args,
            capture_output=True, text=True, timeout=timeout
        )
        if result.returncode != 0:
            raise NimExecutionError(result.stderr)
        return result
```

### 11.3 `nim_payload_engine.py` — High-Level Wrapper

```python
class NimPayloadEngine:
    def __init__(self):
        self.runner = NimRunner()

    def shell(self, ip: str, port: int, lang: str = "bash",
              encode: str = "none") -> str:
        result = self.runner.run(
            "oi-shell-gen",
            ["--ip", ip, "--port", str(port), "--lang", lang, "--encode", encode]
        )
        return result.stdout

    def bypass(self, technique: str, waf: str = "generic") -> str:
        result = self.runner.run("oi-bypass-gen",
                                 ["--technique", technique, "--target-waf", waf])
        return result.stdout
```

### 11.4 Environment Variables

| Variable | Default | Description |
|----------|---------|-------------|
| `OI_NIM_BIN_DIR` | `bin/` | Path to compiled Nim binaries |
| `OI_NIM_CHECKSUMS` | `checksums.json` | Path to SHA-256 checksum file |
| `OI_NIM_SKIP_VERIFY` | `0` | Set to `1` to skip integrity checks (dev only — never production) |
| `OI_NIM_TIMEOUT` | `30` | Per-binary execution timeout in seconds |

---

## 12. Authenticated Testing Suite

### 12.1 Architecture

```
LoginFormDetector.detect(target_url)
        → LoginFields{username_sel, password_sel, submit_sel, csrf_field}

LoginSessionRecorder.record(fields, credentials)
        → AuthSessionContext{cookies, headers, tokens, role="user"}

SessionManager.add_session(ctx)       # user session
SessionManager.add_session(ctx_admin) # admin session

MultiAccountIDOREngine(session_manager).run(endpoints)
        → For each endpoint with {id} param:
            cross_check = GET /api/resource/456 (user A session)
            if cross_check.data == resource_owner_B.data: IDOR_CONFIRMED

GoCredentialSpray.spray(target, wordlist)
        → Rate-limit aware, account lockout detection

AuthenticatedTestSuite.run(session_manager, app_model)
        → IDOR, privilege escalation, business logic bypass
```

### 12.2 Key Data Models

```python
@dataclass
class AuthSessionContext:
    session_id: str
    target: str
    user_role: str
    username: str
    cookies: dict[str, str]
    headers: dict[str, str]
    tokens: dict[str, str]
    session_expires: Optional[datetime]
    login_url: str
    last_refreshed: datetime
    active: bool

    def to_requests_session(self) -> requests.Session: ...
    def serialize(self) -> dict: ...

    @classmethod
    def deserialize(cls, data: dict) -> "AuthSessionContext": ...
```

---

## 13. Proxy and Traffic System

### 13.1 Unified Capture Architecture

```
Browser / Tool / Scanner / Mobile Companion
         │
         │  HTTP/HTTPS or VPN capture
         ▼
┌──────────────────────────────────┐
│      Unified Capture Layer       │
│  proxy_manager.py (mitmproxy /   │
│    Burp upstream)                │
│  eBPF capture (kernel-level)     │
│  tcpdump capture (passive pcap)  │
│  Mobile VPN capture (companion)  │
└──────────┬───────────────────────┘
           ▼
traffic_capture_engine.py → traffic.db (SQLite)
           │
     ┌─────┴──────────────────────┐
     ▼                            ▼
traffic_replay_engine      differential_scanner
     │                            │
     ▼                            ▼
ReplayResult               DifferentialResult
                                  │
                            race_condition_engine
```

### 13.2 Module Responsibilities

```python
class TrafficCaptureEngine:
    def capture(self, request: dict) -> CapturedRequest: ...
    def list_requests(self, filter: dict) -> list[CapturedRequest]: ...
    def export(self, format: str) -> bytes: ...   # json / har / csv

class TrafficReplayEngine:
    def replay(self, request_id: str, modifications: dict) -> ReplayResult: ...
    def fuzz(self, request_id: str, fuzz_config: dict) -> list[ReplayResult]: ...

class DifferentialScanner:
    """Compares responses across parameter variants to detect auth/logic flaws."""
    def scan(self, request_id: str, variants: list[dict]) -> DifferentialResult: ...

class RaceConditionEngine:
    """Concurrent request racing for TOCTOU and limit bypass."""
    def race(self, request_id: str, concurrency: int = 20,
             rounds: int = 5) -> RaceResult: ...
```

---

## 14. Attack Graph Engine

### 14.1 Graph Data Model

```python
class NodeType(Enum):
    TARGET    = "target"
    SUBDOMAIN = "subdomain"
    URL       = "url"
    PARAM     = "parameter"
    VULN      = "vulnerability"
    SERVICE   = "service"
    CREDENTIAL= "credential"
    IMPACT    = "impact"

class EdgeType(Enum):
    HOSTS    = "hosts"
    EXPOSES  = "exposes"
    HAS_VULN = "has_vuln"
    LEADS_TO = "leads_to"
    ENABLES  = "enables"
    REQUIRES = "requires"
```

### 14.2 Dual Backend (NetworkX + Neo4j)

```python
class AttackGraphBrain:
    """
    Default: NetworkX in-memory + SQLite persistence.
    When NEO4J_ENABLED=1: mirrors all writes to Neo4j for Cypher queries.
    """
    def __init__(self):
        self._nx_graph = networkx.DiGraph()
        if os.getenv("NEO4J_ENABLED") == "1":
            self._neo4j = Neo4jClient(
                uri=os.getenv("NEO4J_URI", "bolt://localhost:7687"),
                auth=(os.getenv("NEO4J_USER", "neo4j"),
                      os.getenv("NEO4J_PASSWORD", ""))
            )

    def integrate_node(self, node: GraphNode) -> str: ...
    def integrate_finding(self, finding: VulnCandidate) -> None: ...
    def make_decision(self, target: str) -> Optional[BrainAction]: ...
```

Neo4j enables Cypher-based graph queries:
```cypher
MATCH path = (t:TARGET)-[*..6]->(i:IMPACT)
WHERE t.domain = 'example.com'
RETURN path ORDER BY length(path) ASC LIMIT 10
```

---

## 15. Security Copilot

```python
class SecurityCopilot:
    SYSTEM_PROMPT = """You are an expert offensive security engineer and bug bounty hunter.
Provide actionable, specific security analysis. Never fabricate findings.
Focus on: impact, exploitation steps, and remediation."""

    def chat(self, user_message: str, scan_context: dict) -> str: ...

    QUICK_ACTIONS = {
        "summarize_critical": "Summarize all critical vulnerabilities and their business impact.",
        "generate_poc":       "Generate a step-by-step PoC for the most critical finding.",
        "attack_path":        "Describe the highest-impact attack path in the attack graph.",
        "hackerone_report":   "Write a HackerOne bug report for the most critical finding.",
        "ssl_bypass":         "Provide Frida script for SSL pinning bypass for this app.",
    }
```

---

## 16. Data Models

### 16.1 Core Target Model

```python
@dataclass
class Target:
    id: str
    name: str
    domain: str
    program: str
    platform: str              # hackerone / bugcrowd / intigriti
    scope: list[str]
    out_of_scope: list[str]
    max_bounty: int
    priority: str
    tech_stack: list[str]
    last_scanned: Optional[str]
    scan_count: int
    finding_count: int
    status: str                # active / paused / resolved
    created_at: str
```

### 16.2 Vulnerability Model

```python
@dataclass
class Vulnerability:
    id: str
    scan_id: str
    target: str
    title: str
    vuln_type: str
    owasp_category: str
    severity: str
    cvss_score: float
    cvss_vector: str
    url: str
    parameter: str
    payload: str
    evidence: str
    poc_steps: list[str]
    impact: str
    remediation: str
    validated: bool
    confirmed: bool
    status: str                # new / confirmed / false_positive / fixed
    bounty_estimate: int
    reported_at: Optional[str]
    report_url: Optional[str]
    created_at: str
    tool: str
    raw_output: str
```

### 16.3 Web3Finding Model (v2.0.0)

```python
@dataclass
class Web3Finding:
    id: str
    contract_address: Optional[str]
    contract_source: Optional[str]
    network: str               # mainnet / goerli / polygon / solana
    vuln_class: str            # from 14 EVM classes or Solana classes
    severity: str
    title: str
    description: str
    affected_function: Optional[str]
    line_number: Optional[int]
    code_snippet: Optional[str]
    exploit_scenario: str
    poc_foundry_test: Optional[str]  # .t.sol content
    remediation: str
    tool: str
    discovered_at: str
```

### 16.4 NimPayloadResult Model (v2.0.0)

```python
@dataclass
class NimPayloadResult:
    binary: str
    args: list[str]
    payload: str
    encoding: str
    context: str               # shell / web / mobile / network
    checksum_verified: bool    # always True (NimRunner verifies before exec)
    duration_ms: float
    generated_at: str
```

### 16.5 SessionContext Model (v2.0.0)

```python
@dataclass
class SessionContext:
    session_id: str
    target: str
    user_role: str
    username: str
    cookies: dict[str, str]
    headers: dict[str, str]
    tokens: dict[str, str]
    session_expires: Optional[datetime]
    login_url: str
    last_refreshed: datetime
    active: bool

    def to_requests_session(self) -> requests.Session: ...
```

### 16.6 Mobile Finding Model

```python
@dataclass
class MobileFinding:
    id: str
    app_id: str
    phase: str
    finding_type: str
    severity: str
    title: str
    description: str
    file_path: Optional[str]
    line_number: Optional[int]
    code_snippet: Optional[str]
    remediation: str
    cwe_id: Optional[str]
    owasp_mobile_category: str   # M1-M10
```

### 16.7 AI Security Finding Model

```python
@dataclass
class AIVulnFinding:
    id: str
    target: str
    attack_type: str
    title: str
    description: str
    severity: str
    evidence: str
    successful_prompt: str
    mutation_applied: str
    compliance_score: float
    refusal_score: float
    tool: str
    campaign_id: Optional[str]
    owasp_llm_category: str      # LLM01-LLM10
    remediation: str
```

---

## 17. Execution Pipeline

### `run.py scan <target>` End-to-End Flow

```
User: python run.py scan example.com --profile deep

run.py → cli/main.py → cmd_scan(args) → UnifiedScanEngine.scan("example.com")

Phase 1:  CLASSIFY  — web / api / mobile / ai / web3

Phase 2:  RECON
  ├─ AdaptiveReconEngine.run()
  ├─ ResultIngestionEngine.ingest_recon_asset()
  ├─ KnowledgeBase.start_session()
  └─ PatternMiner.predict_for_target()

Phase 3:  GRAPH UPDATE
  └─ AttackGraphBrain.integrate_node() → SUBDOMAIN + URL nodes

Phase 4:  AGENT TRIGGER
  ├─ Rule-based agent selection
  ├─ AutonomousDecisionEngine (optional override)
  └─ AI reasoning → attack plan injected into ctx["agent_plan"]

Phase 5:  OOB INIT
  └─ OOBEngine.start() → returns oob_domain

Phase 6:  AUTH SETUP
  └─ AuthSessionManager → loads SessionContext if --auth-session provided

Phase 7:  VULN SCAN
  ├─ nuclei (tags from agent_plan)
  ├─ dalfox (XSS on param URLs)
  ├─ sqlmap (SQLi on parametered URLs)
  └─ Boosted payloads from persistent_memory

Phase 8:  GRAPHQL SCAN
  └─ introspection, BOLA, injection, batch query abuse

Phase 9:  BROWSER ANALYSIS
  └─ Playwright: DOM XSS, JS sinks, rendered endpoint extraction

Phase 10: SMUGGLING TEST
  └─ CL.TE, TE.CL, TE.TE patterns

Phase 11: EXPLOIT VALIDATION
  ├─ confirmed   (confidence ≥ 0.70 + evidence)
  ├─ unverified  (0.35–0.69)
  ├─ false_positive (< 0.35) — excluded
  └─ simulated   — excluded

Phase 12: EXPLOIT CHAINING
  └─ 6 patterns: SSRF→Cloud, XSS→ATO, SQLi→RCE, IDOR→PrivEsc, CORS→Cred, Redirect→OAuth

Phase 13: RESULT INGEST
  └─ Deduplicator + ResultIngestionEngine → WAL SQLite + SSE broadcast

Phase 14: SEVERITY FOLLOWUP
  └─ Re-scan high/critical with deeper tools

Phase 15: GRAPH VULN UPDATE
  └─ AttackGraphBrain.integrate_vuln() → vulnerability nodes + risk edges

Phase 16: REPORT
  └─ report.md + report.json (CVSS, evidence, reproduction_cmd, poc_steps)

Phase 17: DONE
  ├─ PersistentMemory.update_from_ctx() + save()
  └─ Session persisted to metadata.db
```

---

## 18. Inter-Module Communication

### 18.1 Direct Python Calls (Same Process)

```python
recon_result = ReconEngine(registry, cache).run(target, profile)
model = ApplicationIntelligence().build_model(target, recon_result)
plan = AdaptivePlanner().plan(target, model.tech_stack)
findings = VulnScanner(registry, profile).scan(surface, recon_result)
```

### 18.2 Agent Message Queues

```python
@dataclass
class Message:
    type: MessageType      # TASK / RESULT / STATUS / ERROR / STOP
    sender: str
    recipient: str
    payload: dict
    timestamp: str
    msg_id: str

class BaseAgent(threading.Thread):
    def send(self, recipient: str, payload: dict): ...
    def receive(self, timeout: float = 30.0) -> Message: ...
```

### 18.3 WebSocket Events (Frontend ↔ Backend)

Log entry format:
```json
{
  "type": "log",
  "level": "info",
  "message": "[+] Found subdomain: api.example.com",
  "timestamp": "2026-06-29T12:30:00Z",
  "source": "recon_agent",
  "scan_id": "scan_abc123"
}
```

### 18.4 Background Tasks (FastAPI)

```python
@app.post("/api/scans")
async def launch_scan(data: ScanRequest, background_tasks: BackgroundTasks):
    def _run():
        result = autonomous_scan_pipeline.run(data.target)
        SCANS[scan_id].update({"status": "complete", "findings": result.findings})
    background_tasks.add_task(_run)
```

### 18.5 Event-Driven Progress

```python
class AutonomousScanPipeline:
    def _emit_progress(self, phase: str, status: str, msg: str):
        self.progress_cb(phase, status, msg)
        WS_LOG_QUEUE.put({"type": "log", "message": msg, "source": phase})
```

---

## 19. Scalability Design

### 19.1 Parallel Scan Engine

```python
class ParallelScanEngine:
    def __init__(self, max_workers: int = 4):
        self.executor = ThreadPoolExecutor(max_workers=max_workers)
        self.semaphore = asyncio.Semaphore(max_workers)
        self._active_domains: set[str] = set()
```

### 19.2 Storage Tiers

| Mode | Trigger | Storage |
|------|---------|---------|
| SQLite (default) | No env vars set | `findings.db` local file |
| PostgreSQL | `POSTGRES_URL` env set | Full PostgreSQL instance |
| Distributed | `POSTGRES_URL` + `REDIS_URL` | PG + Redis task queue |
| Neo4j (graph) | `NEO4J_ENABLED=1` | Neo4j for attack graph Cypher queries |

### 19.3 Distributed Architecture (Shipped v1.2.0)

```
┌─────────────────────────────────────────────────────────┐
│                    COORDINATOR NODE                      │
│  FastAPI + SwarmMaster + EventBus                       │
└──────────┬──────────────────────────────────────────────┘
           │  Redis queues
     ┌─────┼──────┬────────────────┐
     ▼     ▼      ▼                ▼
 worker  worker worker          worker
 -recon  -vuln  -exploit        -ai
                                -secrets
```

| Current | Distributed |
|---------|-------------|
| `SCANS: dict` in main.py | PostgreSQL `scans` table |
| `BackgroundTasks` | Redis worker tasks |
| `ThreadPoolExecutor` | Redis queues + worker processes |
| SQLite findings.db | PostgreSQL with partitioning |
| WebSocket in single process | Redis pub/sub → multiple FastAPI instances |

---

## 20. Docker Distributed Architecture

### 20.1 Service Topology

```
Internet
    │
nginx (port 80) ←── rate limit 60 req/min
  ├── /api/*  →  orchestrator:8000
  ├── /ws     →  orchestrator:8000 (WebSocket)
  └── /*      →  frontend:3000
```

### 20.2 Component Summary

| Service | Image | Profiles | Purpose |
|---------|-------|----------|---------|
| `redis` | redis:7.2-alpine | default | Task queue, worker registry, pub/sub |
| `orchestrator` | oneinfinity:latest | default | FastAPI API, SwarmMaster, EventBus |
| `worker-recon` | oneinfinity-worker | default | Subdomain/URL discovery (scalable) |
| `worker-vuln` | oneinfinity-worker | default | Nuclei/Dalfox/SQLMap (scalable) |
| `worker-exploit` | oneinfinity-worker | default | Exploit chain + zero-day |
| `worker-ai` | oneinfinity-worker:latest-ai | ai | AI red team (GPU-optional) |
| `worker-secrets` | oneinfinity-worker | secrets | TruffleHog/Gitleaks scanning |
| `nginx` | nginx:1.25-alpine | default | Public entrypoint, rate limiting |
| `frontend` | node:20-alpine | default | React dashboard (43 pages) |
| `plugin-watcher` | alpine:3.19 | default | inotify → POST /api/plugins/reload |
| `update-manager` | oneinfinity:latest | updater | Nuclei/plugin/container auto-update |
| `watchtower` | containrrr/watchtower | watchtower | Container image auto-update |
| `redis-exporter` | oliver006/redis_exporter | monitoring | Redis → Prometheus metrics |
| `prometheus` | prom/prometheus | monitoring | Metrics aggregation |
| `grafana` | grafana/grafana | monitoring | Dashboards (port 3001) |

### 20.3 Plugin Hot-Reload

```
Developer drops plugin.py into ./plugins/community/<name>/
    │
plugin-watcher (inotifywait) → POST /api/plugins/reload
    │
PluginRegistry.reload() → new plugin available (no container restart)
```

---

## 21. MCP Integration

### 21.1 Architecture

```
Claude Code / MCP Client
     │  MCP protocol (stdio)
     ▼
src/oneinfinity/mcp/server.py  (FastMCP)
  ├── Human-approval middleware (required for submissions)
  └── hackerone_mcp_tool.py
       ├── h1_get_scope(program_handle) → scope data
       └── h1_list_programs(query, platform) → program list
```

### 21.2 `mcp/server.py` Registration Pattern

```python
from fastmcp import FastMCP
from oneinfinity.mcp.hackerone_mcp_tool import h1_get_scope, h1_list_programs

mcp = FastMCP("oneinfinity-mcp")

@mcp.tool()
def get_hackerone_scope(program_handle: str) -> dict:
    """
    Fetch in-scope and out-of-scope assets for a HackerOne program.
    REQUIRES human approval — never submit without explicit researcher confirmation.
    """
    return h1_get_scope(program_handle)

@mcp.tool()
def list_hackerone_programs(query: str = "", platform: str = "hackerone") -> list:
    """List bug bounty programs matching query on the specified platform."""
    return h1_list_programs(query, platform)

if __name__ == "__main__":
    mcp.run()
```

### 21.3 Available Tools

| Tool | Signature | Returns |
|------|-----------|---------|
| `h1_get_scope` | `(program_handle: str)` | `{in_scope: [...], out_of_scope: [...], bounty_table: {...}}` |
| `h1_list_programs` | `(query: str, platform: str)` | `list[dict]` with bounty ranges and scope sizes |

### 21.4 Human Approval Requirement

All MCP tool calls that interact with external platforms require an explicit human approval gate. The server returns `requires_approval: true` in response metadata. The MCP client must confirm before the tool function executes. Enforced at the middleware layer in `server.py`.

### 21.5 MCP Registration (`mcp-config.json`)

```json
{
  "mcpServers": {
    "oneinfinity": {
      "command": "python",
      "args": ["run.py", "mcp-server"],
      "env": {
        "HACKERONE_API_TOKEN": "${HACKERONE_API_TOKEN}",
        "HACKERONE_USERNAME": "${HACKERONE_USERNAME}"
      }
    }
  }
}
```

---

## 22.0 Phase 0 Hardening — Council-Approved Fixes (v2.2.0)

The following changes were made based on a 5-council review and are now active in all god mode runs:

| Component | Change | Impact |
|-----------|--------|--------|
| `canonical.py` active_testing | Added `cors`, `jwt` to `--agents` swarm-scan CLI args | CORSAgent + JWTAgent now fire in pipeline mode |
| `cli/main.py` + `cli/commands/swarm.py` | Added `cors`, `jwt` to `--agents` choices | Both agent types now reachable via CLI |
| `GodModeConductor._setup_logging()` | Added `_TokenRedactFilter` — redacts `Bearer <token>` patterns | Bearer tokens no longer written to DEBUG log files |
| `JWTAgent` (swarm_intelligence_engine.py) | Stripped `original_token` from hypothesis contexts; aligned 4 vuln_type strings to canonical scanner names | No raw JWT credentials in findings; dedup fingerprint collapses near-duplicates |
| `unified_scan_engine._AGENT_TO_TOOL` | `xssstrike` → `xss_strike_agent`, `commix` → `commix_agent` | XSSStrike + Commix route correctly; no dict-key collision with existing `cmdi_agent: nuclei` |
| `Bypass403Engine` | Added `max_requests=100` cap, `ScopeValidator` guard, `_request_count` counter in `test()` | Request budget capped; scope enforcement added; findings actually collected (`.test()` was previously uncalled) |
| `FullScanMission._run()` | Calls `_bypass_engine.test(session.target)`, stores `BypassReport` in `waf_profile` | 403-bypass results flow into pipeline when WAF is detected |
| `AISecurityEngine._load_wrappers()` | Added `AIRTWrapper` with guarded `try/except ImportError` import | AIR-T autonomous red-teamer registered; startup does not fail if `ai_red_teamer` absent |
| `AIRTWrapper.run()` | Added `allow_data_exfil_objective=False` gate, `asyncio.wait_for(120s)` per objective, evidence sanitization | Data exfiltration requires explicit opt-in; hung Ollama can no longer block indefinitely; raw exfiltrated data not stored in findings |

---


## 22.1 Phases 1–5 Wiring Summary (v2.2.0)

### Active Canonical Pipeline (18 phases as of v2.2.0)

```
target_registration → deep_recon → vuln_scan → advanced_scan* → active_testing
→ auth_session → business_logic → exploit_validation → exploit_chains
→ attack_graph → ai_theory → graphql_scan → cicd_scan* → container_scan*
→ grpc_scan* → browser_analysis → smuggling_test → oob_check
```
`*` = new phases added in v2.2.0 (all non-mandatory)

### Engine Wirings Added in Existing Phases

| Phase | Added Engine | Condition |
|-------|-------------|-----------|
| `deep_recon` | `DNSSecurityScanner` | Always (async bridge via asyncio.run) |
| `active_testing` | `CORSScanner` + `JWTVulnerabilityScanner` + `BlindXSSEngine` | Always (gathered async) |
| `business_logic` | `LLMBusinessLogicAnalyzer` | LLM API key present (silent skip if absent) |
| `exploit_validation` | `DifferentialScanner` | Auth headers present only (mandatory guard) |
| `browser_analysis` | `BrowserReasoningAgent` | Always (triple fallback: Playwright→BS4→empty) |

### God Mode Missions (as of v2.2.0)

| Mission | Trigger | Engine |
|---------|---------|--------|
| `full_scan` | Always | `run_canonical_pipeline` (18 phases) |
| `advanced_scan_mission` | Always (parallel) | `UnifiedAdvancedScanner.run_full_scan()` |
| `zero_hypothesis` | Post-FullScan | `ZeroDayHypothesisEngine.generate()` |
| `ai_red_team` | AI target detected OR AI endpoint event | MultiTurnChainer + RAGPoison + LLMDoS + LLMSupplyChain + AgentHijack |
| `research` | ≥1 vuln found | `ResearchModeController` (now authenticated via P1.1) |
| `swarm` | ≥5 endpoints | `run_swarm` (16 agents incl. cors + jwt added in P0) |
| `auth_test` | Credential acquired | `AuthenticatedTestSuite` |
| `chains` | findings > 0 | `ExploitChainEngine` |
| `report` | Always | `Reporter` |

### Foundation Mission Steps (as of v2.2.0)

```
Step 1: DoctorOrchestrator --quick
Step 2: AdaptiveReconEngine --depth deep
Step 3: ApplicationIntelligenceEngine.analyze_application_structure()
Step 4: WAF detection + AdversarialWAFEngine bypass payload generation (6 vuln types)
         + Bypass403Engine.test() [active if WAF detected, gated + capped]
```
Note: GitHub OSINT is a UI-feature with a dedicated page — not part of god mode automated scan.

### Security Controls Added (v2.2.0)

- `_TokenRedactFilter` on god mode file log handler — Bearer tokens redacted before disk write
- `JWTAgent` strips `original_token` from hypothesis contexts — no raw credentials in findings
- `Bypass403Engine.test()` has scope validation (ScopeValidator) + max_requests=100 cap
- `AIRTWrapper.run()` gates data-exfiltration objective behind `allow_data_exfil_objective=False`
## 22. God Mode Architecture

### 22.1 Overview

God Mode chains all platform capabilities into a 6-stage cascade with no manual intervention required between stages.

```bash
python run.py god-mode <target> [--auth-session FILE] [--background]
                                [--no-swarm] [--no-research]
                                [--report-fmt markdown|json|html]
```

### 22.2 GodModeEngine — 6 Stages

```python
class GodModeEngine:
    STAGES = [
        "recon_and_intelligence",   # Stage 1: full recon + OSINT + graph init
        "vulnerability_scan",       # Stage 2: swarm + 80+ scan engines
        "exploit_and_chain",        # Stage 3: validation + chain + Nim payloads
        "authenticated_testing",    # Stage 4: auth suite (if --auth-session)
        "ai_and_web3_testing",      # Stage 5: AI/LLM + smart contract (if applicable)
        "report_and_submit",        # Stage 6: reports + MCP scope check
    ]

    def run(self, target: str, config: GodModeConfig) -> GodModeResult: ...
```

### 22.3 Stage Flow

```
python run.py god-mode target.com --auth-session session.json

Stage 1: RECON & INTELLIGENCE (10-30 min)
  subfinder → httpx → katana → AdaptiveReconEngine → AppModel → graph init
         ↓
Stage 2: VULNERABILITY SCAN (20-60 min)
  Swarm(8 agents) || nuclei || dalfox || sqlmap || 80+ engines
         ↓
Stage 3: EXPLOIT & CHAIN (10-30 min)
  ExploitChainEngine → PoC → NimPayloadEngine (for confirmed findings)
         ↓
Stage 4: AUTHENTICATED TESTING (10-20 min, if --auth-session)
  AuthenticatedTestSuite → MultiAccountIDOREngine → PrivEsc testing
         ↓
Stage 5: AI & WEB3 (5-20 min, if applicable)
  AISecurityEngine || SmartContractScanner || FoundryPocGenerator
         ↓
Stage 6: REPORT & SUBMIT (2-5 min)
  Reporter → report.md/json/html → MCP scope check → [human approval]
         ↓
GodModeResult { findings: N, chains: M, reports: [...], duration_s: float }
```

Non-fatal stage failures are logged and skipped (resilient cascade).

---

## 23. Architecture Diagrams

### 23.1 Module Dependency Graph

```
run.py (CLI)
    ├── autonomous_scan_pipeline
    │       ├── adaptive_recon_engine ──── modules/tool_wrappers (40+)
    │       ├── application_intelligence
    │       ├── framework/vuln_scanner
    │       ├── autonomous_exploit_engine
    │       │       ├── exploit_generator
    │       │       └── finding_validation_engine
    │       ├── attack_graph/builder ───── exploit_chains/engine
    │       └── bounty_report_generator
    │
    ├── god_mode_engine
    │       ├── autonomous_scan_pipeline
    │       ├── authenticated_test_suite
    │       ├── ai_security_engine
    │       └── web3/smart_contract_scanner
    │
    ├── bounty_hunter_engine
    │       ├── program_discovery_engine
    │       ├── target_prioritization_engine
    │       └── autonomous_scan_pipeline
    │
    ├── mobile_security_engine
    │       ├── mobile_static_analysis
    │       ├── mobile_ai_reverse_engineer
    │       ├── adb_forensics (v2.0.0)
    │       ├── deep_link_fuzzer (v2.0.0)
    │       └── intent_fuzzer (v2.0.0)
    │
    ├── web3/smart_contract_scanner
    │       ├── slither_wrapper
    │       ├── evm_token_scanner
    │       ├── foundry_poc_generator
    │       └── solana_scanner
    │
    ├── auth/authenticated_test_suite
    │       ├── login_form_detector
    │       ├── login_session_recorder
    │       ├── session_manager
    │       └── multi_account_idor_engine
    │
    └── learning/ (cross-cutting)
            ├── knowledge_base   ─── SQLite
            ├── pattern_miner
            └── adaptive_planner ──── all orchestrators
```

### 23.2 Data Flow for `run.py scan example.com`

```
[User Input: "example.com"]
         ↓
[target_prioritization_engine]  → priority: HIGH, score: 7.2
         ↓
[adaptive_recon_engine]         → TechProfile: {django, postgres, jwt, cloudfront}
         ↓
[application_intelligence]      → AppModel: {auth_flows, 47 endpoints, 3 roles}
         ↓
[test_selection_engine]         → 23 SecurityTests selected
[adaptive_planner]              → scan_sqli moved to priority #1 (django+postgres)
         ↓
[framework/vuln_scanner]
  nuclei  → 12 findings (info: headers, tls)
  sqlmap  → 1 finding (CRITICAL: UNION-based SQLi)
  dalfox  → 2 findings (HIGH: reflected XSS)
  custom  → 1 finding (HIGH: IDOR)
         ↓
[autonomous_exploit_engine]     → 3 confirmed + validated
         ↓
[attack_graph/builder]
  Nodes: 69 total, Edges: 89, Paths: SSRF→IDOR→ATO (score: 8.7)
         ↓
[deduplicator] → [cvss_calculator] → [learning/knowledge_base]
         ↓
[bounty_report_generator] → report.md / report.html / report.json
```

---

## 24. Swarm Intelligence Engine

### Architecture

```
┌─────────────────────────────────────────────────────────────────┐
│                    AgentSwarmCoordinator                        │
│  SharedSwarmState{findings, chains, dedup_hashes}               │
│  Event Bus (asyncio.Queue) — finding_emitted → collaboration    │
│                                                                 │
│  XSSAgent  SQLiAgent  SSRFAgent  IDORAgent                      │
│  AuthAgent BizLogicAgent MobileAgent APISecAgent                │
└─────────────────────────────────────────────────────────────────┘
```

### Agent Lifecycle (5 phases)

```
analyze_graph → generate_hypotheses → execute_tests → report_findings → learn_from_results
      │                │                   │               │                  │
  AttackGraph     KnowledgeBase        ToolRegistry   graph add_node/edge   EMA α=0.30
```

### Collaboration Rules

| Trigger Vuln | Notifies Agent | Priority Boost |
|---|---|---|
| `sqli_*` | IDOR Agent | +0.3 |
| `ssrf_*` | IDOR Agent | +0.2 |
| `xss_*` | AUTH Agent | +0.2 |
| `idor_*` | BUSINESS_LOGIC Agent | +0.25 |
| `auth_*` | XSS Agent | +0.15 |

### Monte Carlo Attack Simulation

```
AttackSimulationEngine.simulate_all_paths(target, context)
  ├── 23 attack path catalog entries (type, base_cvss, ease, tech affinity)
  └── Per path: N=200 Bernoulli trials → success_probability, expected_value
      factors: KB history, tech match (+0.15), WAF penalty (-0.20),
               graph depth, cloud bonus (+0.10), exploitation ease
```

### Key Files

| File | Purpose |
|------|---------|
| `swarm_intelligence_engine.py` | 8 specialized agents, EMA learning, graph integration |
| `agent_swarm_coordinator.py` | Parallel orchestration, event bus, dedup, chain detection |
| `attack_simulation_engine.py` | Monte Carlo simulation, 23-path catalog |
| `workflow_simulation_engine.py` | 4 workflow factories, 9 attack categories |
| `web/backend/swarm_intel_api.py` | FastAPI router, 10 endpoints under `/api/swarm-intel/` |
| `web/frontend/src/pages/SwarmIntelligence.jsx` | 4-tab React UI |

---

## 25. Self-Evolving Architecture System

### Core Modules

| Module | Role |
|--------|------|
| `auto_architecture_engine.py` | Event dispatcher — 13 `EventType` values, 9 built-in handlers |
| `memory_manager.py` | SQLite knowledge base (`evolution.db`) — 6 tables, EMA α=0.3 |
| `skills_tracker.py` | Parses and atomically rewrites `SKILLS.md` |
| `architecture_updater.py` | Parses `ARCHITECTURE.md`; `add_component()`, `add_section()` |
| `readme_generator.py` | Full `README.md` generation from structured feature/CLI/UI model |

### Event Flow

```
Platform action (scan complete, exploit found, tool added)
     ↓
AutoArchitectureEngine.emit(ArchEvent)
  ├─► _on_scan_completed()          → MemoryManager.store_scan_summary()
  ├─► _on_vulnerability_discovered() → MemoryManager.upsert_attack_pattern()
  ├─► _on_exploit_chain_detected()   → MemoryManager.store_exploit_chain()
  ├─► _on_feature_added()            → ArchitectureUpdater + SkillsTracker + ReadmeGenerator
  └─► _on_insight_generated()        → MemoryManager.store_insight()
```

### MemoryManager Tables (evolution.db)

| Table | Purpose |
|-------|---------|
| `attack_patterns` | Per-vuln-type success rate (EMA α=0.3) |
| `exploit_chains` | Stored chain sequences with CVSS |
| `learning_insights` | Distilled findings with confidence scores |
| `scan_summaries` | Per-target scan history |
| `capability_snapshots` | Platform capability over time |
| `architecture_changelog` | Component add/update history |

---

## 26. Event-Driven Intelligence Daemon

### Architecture Overview

```
┌─────────────────────────────────────────────────────────────────┐
│                    IntelligenceDaemon                           │
│  asyncio event loop (daemon thread)                             │
│  9 workers: Hypothesis | GraphExpansion | ExploitChain          │
│             PayloadMutation | TrafficReplay | BusinessLogic     │
│             OSINTExpansion | Swarm | Learning                   │
└───────────────────────┬─────────────────────────────────────────┘
                        ↓
              ┌─────────────────┐
              │    EventBus     │
              │  PriorityQueue  │
              │  Ring buffer: 2000 events
              │  SQLite persist │
              │  WebSocket/SSE  │
              └─────────────────┘
```

### EventBus

| Feature | Detail |
|---------|--------|
| Transport | `queue.PriorityQueue` (thread-safe), async dispatch loop |
| Priority levels | `HIGH=0`, `NORMAL=1`, `LOW=2` |
| Ring buffer | Latest 2000 events (in-memory) |
| Persistence | SQLite (`event_bus.db`) |
| Live streaming | WebSocket (`/api/events/ws`) + SSE (`/api/events/stream`) |
| Dead-letter queue | Failed handlers stored (max 200) |

### Worker Engines

| Worker | Subscribes To | Core Logic |
|--------|--------------|-----------|
| `HypothesisWorker` | `NEW_TARGET`, `NEW_ENDPOINT`, `NEW_PARAMETER` | AppModel → VulnTheory |
| `GraphExpansionWorker` | `NEW_TARGET`, `NEW_ENDPOINT`, `OSINT_RESULT` | Updates AttackGraphEngine |
| `ExploitChainWorker` | `NEW_VULNERABILITY` | Checks 16 chain patterns |
| `PayloadMutationWorker` | `EXPLOIT_ATTEMPTED` | 8 mutation strategies |
| `TrafficReplayWorker` | `NEW_VULNERABILITY`, `EXPLOIT_ATTEMPTED` | Replay with variations |
| `BusinessLogicWorker` | `NEW_API`, `WORKFLOW_DETECTED` | Business logic tests |
| `OSINTExpansionWorker` | `NEW_TARGET` | OSINT + target discovery |
| `SwarmWorker` | `NEW_TARGET`, `NEW_VULNERABILITY` | AgentSwarmCoordinator dispatch |
| `LearningWorker` | Multiple | KnowledgeBase + MemoryManager updates |

### DaemonConfig (default cooldowns)

| Worker key | Default cooldown | Max concurrent |
|-----------|-----------------|----------------|
| `hypothesis` | 120s | 3 |
| `graph_expand` | 30s | 5 |
| `exploit_chain` | 10s | 10 |
| `payload_mutate` | 5s | 5 |
| `traffic_replay` | 60s | 3 |
| `biz_logic` | 300s | 2 |
| `osint_expand` | 600s | 2 |
| `swarm` | 180s | 2 |
| `learning` | 0s | 10 |

### WorkerEngine Base Pattern

```python
class WorkerEngine(ABC):
    SUBSCRIPTIONS: list[EventType] = []
    _config: WorkerConfig
    _semaphore: asyncio.Semaphore
    _cooldowns: dict[str, float]

    def _throttled(self, target: str) -> bool:
        return time.time() - self._cooldowns.get(target, 0.0) < self._config.cooldown_s

    async def _guarded_handle(self, event: BusEvent):
        if not self._config.enabled: return
        if self._throttled(event.data.get("target", "")): return
        async with self._semaphore:
            await self.handle(event)
```

### CLI Commands

```bash
python run.py daemon-start <target> [target2 ...]
python run.py daemon-stop
python run.py daemon-status
python run.py daemon-add-target <target>
```

---

## 27. Graph-Centric Autonomous Architecture

### Design Principle

```
OLD:  CLI command → pipeline (recon→scan→exploit→report)
NEW:  Graph state → Brain scores nodes → Decision engine ranks actions
                  → Trigger rules fire agents → Findings feed back to graph
                  → Graph updates → new actions emerge → repeat
```

### Core Modules

| Module | File | Role |
|--------|------|------|
| **AttackGraphBrain** | `attack_graph_brain.py` | Central hub — scores nodes, queues actions, integrates findings |
| **EventDrivenEngine** | `event_driven_engine.py` | Routes bus events to brain; drives continuous dispatch loop |
| **GraphTriggerEngine** | `graph_trigger_engine.py` | 15 declarative trigger rules |
| **AutonomousDecisionEngine** | `autonomous_decision_engine.py` | Ranks (node, agent) pairs |
| **AgentExecutionFabric** | `agent_execution_fabric.py` | ThreadPoolExecutor (8 workers) + 12 GraphAgent subclasses |

### Decision Engine Scoring Formula

```python
score = (impact × exploitability × novelty) / (effort × (1 + tested_penalty))

# With agent feedback loop:
historical_rate = agent_successes / agent_attempts  (if >= 5 samples)
exploitability  = 0.6 × pattern_match_score + 0.4 × historical_rate
```

### Node Priority Scoring

```
priority = base_type_weight[node_type]
         × (1 + min(connections / 10, 1.0) × 0.5)   # connectivity bonus
         × (1 + 0.5 if exploitable else 0)            # vuln bonus
         × (1 + severity_weight)                       # critical/high boost
         × (1 - tested_ratio × 0.7)                   # tested discount

Node type weights:
  CREDENTIAL: 9.8   AUTH_FLOW: 10.0   IMPACT: 10.0
  VULN: 9.5         API_ENDPOINT: 8.5  PARAMETER: 7.0
  URL: 5.5          SUBDOMAIN: 5.0     TECHNOLOGY: 3.0
```

### 15 Graph Trigger Rules

| Pattern | Agents Triggered |
|---------|-----------------|
| `PARAMETER` | xss, sqli, ssrf, ssti, open_redirect |
| `API_ENDPOINT` | idor, auth, biz_logic |
| `AUTH_FLOW` | auth, biz_logic |
| `SUBDOMAIN` | recon |
| `VULNERABILITY(H/C)` | exploit |
| `CREDENTIAL` | auth, exploit |
| `admin_endpoint` | auth, idor, biz_logic |
| `upload_endpoint` | xss, sqli |
| `graphql_endpoint` | sqli, idor, auth |
| `jwt_detected` | auth |
| `open_redirect_param` | open_redirect, ssrf |
| `ssrf_sink` | ssrf |
| `high_risk_node` | xss, sqli, ssrf, idor, auth |
| `web3_contract` | web3_scanner |
| `ai_endpoint` | ai_security |

### Continuous Execution Loop

```
1. brain.start(targets) → add TARGET nodes, initial rescore
2. EDE._bus_subscriber_loop → receive events → brain.integrate_node()
3. EDE._main_loop → brain.make_decision() → fabric.submit_task(decision.action)
4. fabric._run_task(agent) → agent.execute(task) → FabricResult
5. result → brain.integrate_finding() → graph updated, neighbours rescored
6. New findings emit NEW_VULNERABILITY → new trigger firings
7. goto 3 (until idle_timeout or max_iterations)
```

### API Endpoints

#### Brain (`/api/brain/`)

| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | `/api/brain/status` | Brain status + queue/decision counters |
| POST | `/api/brain/start` | Start brain for target(s) |
| POST | `/api/brain/stop` | Stop brain + EDE |
| GET | `/api/brain/queue` | Current action queue snapshot |
| GET | `/api/brain/priorities` | Top-priority nodes |
| GET | `/api/brain/decisions` | Decision history |
| GET | `/api/brain/attack-paths/{target}` | BFS attack paths |
| GET | `/api/brain/risk-report/{target}` | Full risk analysis |

### CLI Commands

```bash
python run.py brain-start <target> [target2 ...]
python run.py brain-stop
python run.py brain-status
python run.py brain-decide <target>
python run.py brain-triggers [--evaluate]
```

---

## 28. AI Model Orchestration

### Three-Tier Routing

| Tier | Class | Default Providers | Use Case |
|------|-------|------------------|---------|
| FAST | 1 | gpt-4o-mini, claude-haiku-4-5, llama3.2:3b (Ollama), Codex CLI | RECON, OSINT, hypothesis |
| STANDARD | 2 | gpt-4o, claude-sonnet-4-6, deepseek-r1:7b (Ollama) | VULN_ANALYSIS, CHAIN_DETECTION |
| PREMIUM | 3 | claude-opus-4-6, GPT-o1 | EXPLOIT_GEN, BIZ_LOGIC |

Escalation is automatic: FAST model returning confidence below 0.65 triggers re-send to STANDARD.

### Provider Backends

```python
class BaseBackend:
    provider: str
    def is_available(self) -> bool: ...
    def call(self, model_id, prompt, system, temperature, max_tokens) -> BackendResult: ...
```

| Backend | File | Trigger |
|---------|------|---------|
| `OllamaBackend` | `backends/ollama.py` | `provider: ollama`; auto-registered via `/api/tags` |
| `CodexCliBackend` | `backends/cli.py` | `codex` binary on PATH |
| `ClaudeCliBackend` | `backends/cli.py` | `claude` binary on PATH |

### Ollama Auto-Discovery

On startup, queries `GET {OLLAMA_HOST}/api/tags`. Tier by parameter count: ≥70B → PREMIUM, 27–34B → STANDARD, else FAST. Cost = $0.00.

### Configuration (`config/models.yaml`)

```yaml
models:
  gpt-4o-mini:
    provider: openai
    tier: FAST
    cost_per_1k_input: 0.00015
    cost_per_1k_output: 0.00060
    enabled: true

ollama:
  host: "http://localhost:11434"
  auto_discover: true

cli_fallback:
  enabled: true
  codex_model: "o4-mini"
  claude_model: "claude-opus-4-6"
  on_errors: [auth, quota]

budget:
  daily_limit_usd: 5.00
  monthly_limit_usd: 50.00
  alert_threshold: 0.80
  per_model_daily_limit:
    gpt-4o: 2.00
```

At 100% budget: all calls re-routed to Ollama or CLI backends. If no zero-cost backend: call rejected with clear error.

### CLI Commands

```bash
python run.py ai-status
python run.py ai-budget
python run.py ai-models
```

### Web UI — AI Models Page

Shows: all registered models, today's spend, total calls, projected monthly cost, live model test panel, recent execution history.

---

## 29. Diagnostics and Audit Modes

| Engine | Mode | What It Checks |
|--------|------|----------------|
| **QAEngine** | Real | 7 functional scenarios: scan engine, agent router, ingestion pipeline, API endpoint, tool registry (real tool probes), findings DB init, unified scan engine import |
| **AuditEngine** | Simulate | Discovers 99 classes matching `*Engine`, `*Agent`, `*Manager` patterns; heuristic pass/fail |
| **RegressionEngine** | State diff | Compares against `.doctor_state.json` to detect regressions |

```bash
python run.py doctor [--quick] [--deep] [--json]
```

**Health score formula:**
```
score = 10.0
score -= regressions × 2.0
score -= QA_FAIL × 0.5 + QA_PARTIAL × 0.2
score -= broken_features × 0.5 + partial_features × 0.2
score = clamp(score, 0.0, 10.0)
```

### Recon Asset Persistence

Adaptive recon persists subdomains, URLs, and technologies into the findings database as recon assets, enabling attack graph enrichment and consistent asset tracking across scans.

---

## 30. Module Summary

| Layer | Files | Notes |
|-------|-------|-------|
| cli/ | 15+ | Per-group command modules |
| orchestration/ | 10 | God mode, event bus, decision engine |
| scan/ | 80+ | All vulnerability scan engines |
| recon/ | 10+ | Recon and OSINT |
| attack/ + exploit_chains/ | 10 | Exploit generation and chaining |
| attack_graph_core/ | 6 | Graph model, builder, analyzer |
| swarm/ + intelligence/ | 8 | Swarm agents, daemon workers |
| ai_security/ | 15+ | AI red team + 5 new v2.0.0 modules |
| mobile/ | 20+ | 12 phases + v2.0.0 phases |
| web3/ | 5 | Smart contract scanning |
| auth/ | 8 | Authenticated testing suite |
| mcp/ | 2 | MCP server + HackerOne tools |
| arsenal/ + src/nim/ | 10+ | Nim payload arsenal |
| agents/ | 7 | BaseAgent, coordinator, SecretIntelAgent |
| modules/ | 15 | Tool wrappers (40+), payload library |
| core/ | 8 | DBManager, dedup, cache, profiles |
| learning/ | 5 | Adaptive planner, knowledge base |
| findings/ | 5 | Ingestion, dedup, classification |
| bounty/ | 5 | Hunter engine, ROI, report generator |
| infra/ | 5 | Budget manager, task classifier |
| plugins/ + worker/ + casl/ + utils/ | 10+ | Supporting infrastructure |
| web/backend | 1 | FastAPI — 54+ routes |
| web/frontend/src | 43 pages | React UI |
| tests/ | 130+ | Test files |
| **Total** | **200+** | |

**Tools integrated:** 40+ external tools

**API routes:** 54+ (HTTP + WebSocket)

**CLI commands:** 75+ across all command groups

**Vulnerability types covered:** SQLi, XSS, SSRF, LFI/RFI, XXE, SSTI, CMDi, RCE, IDOR, Auth Bypass, CORS, Open Redirect, Deserialization, JWT attacks, GraphQL injection, BOLA, Mass Assignment, Rate Limit bypass, Cloud misconfig, AI prompt injection, Jailbreak, RAG poisoning, Tool abuse, Model extraction, Data exfiltration, HTTP/2 attacks, Request Smuggling, WebSocket injection, Race Conditions, Prototype Pollution, NoSQL injection, Cache Deception, DNS Rebinding, Container Escape, Supply Chain, Web3 (14 EVM classes + Solana), Mobile M1-M10, Business Logic

---
---

## 31. Auth-Tiered Surface Expansion

### Overview

Auth-tiered surface expansion is an event-driven feedback loop that converts each discovered credential into a new recon pass scoped to the authenticated surface. The loop runs concurrently with the credential spray rather than waiting for spray completion.

### Event Flow

```
GoCredentialSpray.run()
  │  (per valid credential, inside streaming loop)
  ├─ builds LoginSession → saves to SessionManager
  └─ emits CREDENTIAL_ACQUIRED {session_id, target, service, username, auth_tier, login_endpoint, scan_id}
           │
           ▼
GodModeConductor._on_credential_acquired()
  ├─ dedup guard (_spawned_auth_tiers)
  ├─ copies tier-0 artifacts (subdomains, alive_hosts, gau URLs)
  ├─ feeds MultiAccountIDOREngine.add_account_from_session()
  └─ spawns _run_scoped_auth_recon() in daemon thread
           │
           ▼
AdaptiveReconEngine(auth_context=AuthSessionContext)
  ├─ HeadlessBrowserEngine: injects session into Playwright BrowserContext + requests.Session
  ├─ SPA pushState/replaceState route interception
  ├─ XHR response body scanning (JWT/API key patterns in JSON responses)
  └─ emits RECON_CONFIDENCE every 30s {score, subdomains, apis, urls, authenticated}
           │
           ▼
GodModeConductor._run_scoped_auth_recon()
  ├─ computes delta URLs (new_urls = auth_urls - tier0_surface)
  ├─ emits SURFACE_ENRICHED {target, auth_tier, new_urls, scan_id, auth_context_id, source_session_id}
  └─ emits AUTH_TIER_UNLOCKED
           │
           ▼
GodModeConductor._run_auth_test_suite()
  ├─ runs AuthenticatedTestSuite on SURFACE_ENRICHED endpoints
  └─ anti-retesting via _tested_endpoints {session_id → set[endpoint]}
```

### New GodModeConductor State Fields (v2.1.0)

| Field | Type | Purpose |
|---|---|---|
| `_auth_ctx_registry` | `dict[str, AuthSessionContext]` | session_id → context, for replay and IDOR |
| `_spawned_auth_tiers` | `set[str]` | dedup guard — prevents double-spawn per credential |
| `_tested_endpoints` | `dict[str, set[str]]` | anti-retesting per session |
| `_idor_engine` | `MultiAccountIDOREngine` | accumulates accounts across all credentials |
| `_idor_accounts` | `list` | account list for cross-account IDOR |

### New Event Types (event_bus.py)

| EventType | Payload Fields | Emitter |
|---|---|---|
| `CREDENTIAL_ACQUIRED` | `session_id, target, service, username, auth_tier, login_endpoint, scan_id` | `GoCredentialSpray.run()` |
| `SURFACE_ENRICHED` | `target, auth_tier, new_urls, scan_id, auth_context_id, source_session_id` | `GodModeConductor._run_scoped_auth_recon()` |
| `RECON_CONFIDENCE` | `score, subdomains, apis, urls, authenticated, scan_duration_s` | `AdaptiveReconEngine.run()` |
| `AUTH_TIER_UNLOCKED` | `auth_tier, scan_id` | `GodModeConductor._run_scoped_auth_recon()` |

### Parallel Foundation (Phase D)

`AdaptiveReconEngine.run()` executes phases in dependency-ordered waves using `ThreadPoolExecutor`:

```
Wave 1 (parallel):  subdomain_enum  ||  gau
Wave 2 (sequential): http_probe          (needs wave-1 subdomains)
Wave 3 (parallel):  katana  ||  tech_detection  ||  cloud_intel    (need alive_hosts)
Wave 4 (parallel):  api_intelligence  ||  js_intelligence          (need _all_urls)
Wave 5 (sequential): strategy + scoring + attack_graph             (fast, needs all above)
```

`_phase_url_discovery` reuses pre-fetched gau URLs from wave 1 to avoid double-running gau.

### Validation Pipeline (Phase E)

`ResultIngestionEngine.ingest()` applies a two-tier validation strategy:

| Tier | Types | Mechanism | Blocking? |
|---|---|---|---|
| Synchronous pre-filter | xss, sqli, ssti, lfi, open_redirect, xxe | `FindingValidationEngine.validate()` called inline | Yes — confirmed FPs suppressed before storage |
| Async fire-and-forget | ssrf, cmdi, rce, auth_bypass, idor | Background task updates status after validation | No — finding stored immediately |

URL normalization: `_normalize_url_for_dedup()` strips numeric, UUID, and hex path segments before dedup hashing. `/users/123/orders/abc-def-456` → `/users/{id}/orders/{uuid}`. Fail-open: a validation exception lets the finding through to preserve true positives.

---

## 32. Multi-Language Architecture

One&Infinity uses the best language for each job. The rule is: use Python for orchestration, ML, and AI; reach for other languages when Python's runtime model is a constraint.

| Language | Role | Components |
|---|---|---|
| **Python** | Orchestration, ML/AI, recon logic, pipeline, event bus | All of `src/oneinfinity/`; `adaptive_recon_engine`, `god_mode_engine`, `result_ingestion_engine`, `event_bus` |
| **Go** | Performance-critical network tools, gRPC sidecars | `go_credential_spray.py` (wraps `oi-credential-spray` gRPC sidecar), `go_ssrf_engine.py`, `go_idor_engine.py`, `go_oob_listener.py`, `go_service_cve_mapper.py` |
| **Rust** | CPU-intensive scanners, JWT cracking, payload mutation | `rust_jwt_crack.py` (wraps Rust binary), future payload mutation engine |
| **Nim** | Payload generation, compiled offensive binaries | `src/nim/` — 6 binaries: oi-shell-gen, oi-bypass-gen, oi-payloads, oi-post-exploit, oi-fuzzer, oi-privesc-gen |
| **eBPF** | Kernel-level traffic capture, syscall monitoring | `mobile_ebpf_capture.py` |
| **TypeScript** | Web frontend (React + Vite) | `web/frontend/` — 43-page React dashboard |
| **Kotlin** | Android VPN capture companion | `android-companion/` |
| **Swift** | iOS Network Extension companion | `ios-companion/` |

### Adding a New Language Component

1. Implement the binary/sidecar with its native build system.
2. Add a thin Python wrapper in the appropriate `src/oneinfinity/` subpackage (pattern: `subprocess.run` or gRPC stub; return `list[dict]` or dataclass).
3. Add install steps to `install.sh` under the appropriate platform guard.
4. Add the component to the table above in this section and to Section 30 Module Summary.
5. SHA-256 integrity verification is required for compiled binaries placed in `bin/` — update `checksums.json`.


*Architecture v2.1.0 — 2026-06-30*
*GitHub: https://github.com/Inf1n1tyDeS0ul/oneinfinity*
*Contact: infosec.dev.367@gmail.com*
