# One&Infinity — Skills Reference

A complete reference of all capabilities (skills) the platform provides, organized by domain.

---

## 1. Reconnaissance & Discovery

| Skill | Command | Engine | Tools Used |
|-------|---------|--------|-----------|
| Subdomain enumeration | `oneinfinity scan <target>` (phase 1) | `autonomous_scan_pipeline.py` | subfinder, amass, assetfinder, findomain, dnsx |
| Certificate transparency monitoring | `oneinfinity plugins run crtsh_monitor` | `plugins/recon/crtsh_monitor.py` | crt.sh API |
| ASN / IP range enumeration | `oneinfinity plugins run asn_enum` | `plugins/recon/asn_enum.py` | BGP / ASN APIs |
| HTTP probing & fingerprinting | `oneinfinity scan <target>` (phase 2) | `modules/tool_wrappers.py` | httpx, naabu, whatweb |
| Technology detection | `oneinfinity adaptive-recon <target>` | `adaptive_recon_engine.py` | httpx, Wappalyzer heuristics |
| JS endpoint extraction | `oneinfinity adaptive-recon <target>` | `adaptive_recon_engine.py` | katana, regex on JS |
| Cloud asset discovery | `oneinfinity adaptive-recon <target>` | `adaptive_recon_engine.py` | DNS patterns, CIDR matching |
| Web crawling | `oneinfinity scan <target>` (phase 3) | `autonomous_scan_pipeline.py` | katana, hakrawler, gauplus, waybackurls |
| OSINT collection | `oneinfinity attack-graph <target>` | `osint_collector.py` | HackerTarget, DNSDumpster, URLScan, Wayback, GitHub dorks, Shodan |
| Asset correlation | `oneinfinity attack-graph <target>` | `asset_correlator.py` | Cloud CIDR detection, IP↔domain linking |
| Port scanning | `oneinfinity scan <target>` | `modules/tool_wrappers.py` | naabu, nmap |

---

## 2. Vulnerability Scanning

| Skill | Command | Engine | Tools Used |
|-------|---------|--------|-----------|
| Template-based vuln scan | `oneinfinity scan <target>` (phase 4) | `agents/scan_agent.py` | nuclei (v3, `-jsonl -tags`) |
| XSS detection | `oneinfinity scan <target>` | `modules/tool_wrappers.py` | dalfox, kxss, XSStrike |
| SQL injection | `oneinfinity scan <target>` | `modules/tool_wrappers.py` | sqlmap, commix |
| CRLF injection | `oneinfinity scan <target>` | `modules/tool_wrappers.py` | crlfuzz |
| Secret/credential scanning | `oneinfinity scan <target>` | `modules/tool_wrappers.py` | trufflehog, gitleaks, jwt_tool |
| S3 bucket misconfiguration | `oneinfinity scan <target>` | `modules/tool_wrappers.py` | s3scanner |
| Directory/path fuzzing | `oneinfinity scan <target>` | `modules/tool_wrappers.py` | ffuf, gobuster, dirsearch |
| Parameter discovery | `oneinfinity scan <target>` | `modules/tool_wrappers.py` | arjun, gf |
| API security testing | `oneinfinity plugins run api_security` | `plugins/vuln/api_security.py` | Custom HTTP (GraphQL, BOLA, mass assignment, rate limit, version bypass) |
| Cloud misconfiguration | `oneinfinity plugins run cloud_misconfig` | `plugins/vuln/cloud_misconfig.py` | S3, Elasticsearch, K8s, credential leakage checks |
| Web application scan | `oneinfinity scan <target>` | `modules/tool_wrappers.py` | nikto, whatweb |

---

## 3. Autonomous Research & Theorizing

| Skill | Command | Engine | Description |
|-------|---------|--------|-------------|
| App model building | `oneinfinity analyze-app <target>` | `application_intelligence.py` | Maps auth flows, API structure, roles, sensitive endpoints |
| Vulnerability theory generation | `oneinfinity generate-theories <target>` | `vulnerability_theory_engine.py` | 23 rules → hypothesis set from AppModel |
| Custom attack test design | `oneinfinity run-custom-tests <target>` | `custom_test_engine.py` | Context-aware payload generation + HTTP execution |
| Anomaly / zero-day detection | `oneinfinity zero-day <target>` | `zero_day_engine.py` | Timing fingerprints, status changes, data leakage, reflection |
| Full research loop | `oneinfinity research <target> --yes` | `research_mode_controller.py` | analyze → theorize → test → report (SQLite KB) |
| Business logic attacks | `oneinfinity scan <target>` | `business_logic_attack_engine.py` | LLM + rule-based: price manipulation, workflow bypass, race conditions |

---

## 4. Exploitation & Chains

| Skill | Command | Engine | Description |
|-------|---------|--------|-------------|
| Exploit chain detection | `oneinfinity exploit <domain>` | `exploit_chains/engine.py` | 16 ChainPatterns (SSRF→Cloud, XSS→ATO, SQLi→RCE, etc.) with step-by-step UI tracking |
| PoC generation | `oneinfinity exploit <domain>` | `exploit_chains/poc_generator.py` | Produces executable PoC scripts per chain |
| Auto-Reporting | `oneinfinity exploit <domain> --report` | `bounty_report_generator.py` | Generates HackerOne/Bugcrowd markdown reports automatically |
| Bounty ROI Ranking | (automatic) | `core/reporter.py` | Ranks findings by payout potential (0-100 score + $$ estimate) |
| Attacker Path Simulation | `oneinfinity attack-graph <target>` | `attack_path_planner.py` | Simulates and prioritizes multi-step lateral movement paths |
| Payload generation | `oneinfinity payloads <type>` | `modules/payloads.py` + `exploit_generator.py` | 130+ payloads across 12 vuln types |
| WAF bypass techniques | `oneinfinity waf-bypass <waf> <vuln>` | `modules/payloads.py` | Per-WAF bypass payload sets and dynamic encoding |
| WAF feedback loop | `oneinfinity replay-attack <id>` | `attack_replay_engine.py` | Automatically detects WAF block, records WAF type, and tracks retry attempts with mutations |
| Browser-based attacks | `oneinfinity scan <target>` | `browser_attack_engine.py` | Playwright/Selenium; XSS, login bypass, form testing |
| Attack path planning (BFS) | `oneinfinity attack-graph <target>` | `attack_graph_core/attack_planner.py` | Prioritized AttackActions from graph state |
| Exploit session management | `oneinfinity hunter-scan <target>` | `autonomous_exploit_engine.py` | Severity-sorted exploitation with session persistence |
| Attack replay + fuzzing | `oneinfinity replay-attack <id>` | `attack_replay_engine.py` | Replay with payload permutations and parameter fuzzing |

---

## 5. Validation & Deduplication

| Skill | Command | Engine | Description |
|-------|---------|--------|-------------|
| Finding validation | `oneinfinity scan <target>` (phase 6) | `finding_validation_engine.py` | Canary XSS, time-based blind, type-specific validators |
| False positive filtering | `oneinfinity scan <target>` | `agents/validation_agent.py` | CVSS calculation, endpoint liveness checks |
| Deduplication | `oneinfinity dedup <title>` | `core/deduplicator.py` | SHA-256 fingerprints + 20+ canonical vuln-type aliases |
| Result aggregation | Automatic (during scan) | `result_aggregator.py` | Merges findings, detects chains, updates attack graph |

---

## 6. Attack Graph

| Skill | Command | Engine | Description |
|-------|---------|--------|-------------|
| Build attack graph | `oneinfinity attack-graph <target>` | `attack_graph_core/graph_engine.py` | Nodes (assets/vulns) + Edges (relationships) |
| Find attack paths | `oneinfinity attack-graph <target>` | `attack_graph_core/graph_query_engine.py` | BFS from entry nodes to high-impact targets |
| Exploit chain detection | `oneinfinity attack-graph <target>` | `attack_graph_core/exploit_chain_engine.py` | 12 chain patterns (XSS→ATO, SQLi→RCE, SSRF→Cloud, etc.) |
| Risk scoring | `oneinfinity attack-graph <target>` | `attack_graph_core/risk_analyzer.py` | `(base_cvss + exploitability + chain_bonus) × impact_multiplier` |
| Export graph | `oneinfinity attack-graph-export <target> [json\|dot\|svg]` | `attack_graph_core/graph_store.py` | JSON, DOT, SVG formats |
| Visual exploration | Web UI `/graph-explorer` | `web/frontend/src/pages/AttackGraphExplorer.jsx` | ForceGraph2D with glow/pulse, NodeInfoPanel, RiskPanel |

---

## 7. Reporting

| Skill | Command | Engine | Description |
|-------|---------|--------|-------------|
| HackerOne report | `oneinfinity report --finding <id>` | `agents/report_agent.py` | H1-format Markdown |
| Bugcrowd report | `oneinfinity report --finding <id>` | `bounty_report_generator.py` | Bugcrowd-format Markdown |
| Intigriti report | `oneinfinity report --finding <id>` | `bounty_report_generator.py` | Intigriti-format Markdown |
| Multi-format export | `oneinfinity findings export [json\|csv\|md]` | `core/reporter.py` | Markdown + JSON + HTML |
| Exploit chain report | `oneinfinity report chain <id1> <id2>` | `bounty_report_generator.py` | Combined chain PoC report |
| CVSS calculation | `oneinfinity cvss <vector>` | `modules/cvss.py` | CVSS 3.1 score from vector string |
| Bounty estimation | Included in reports | `bounty_report_generator.py` | Estimated payout range per vuln type |

---

## 8. Mobile Security

| Skill | Command | Engine | Tools Used |
|-------|---------|--------|-----------|
| Upload APK/IPA | `oneinfinity mobile-upload <file>` | `mobile_upload_manager.py` | SHA-256 dedup, SQLite metadata |
| Full 12-phase analysis | `oneinfinity mobile-analyze <apk_id>` | `mobile_security_engine.py` | All tools below |
| Static analysis | `oneinfinity mobile-static <apk_id>` | `mobile_static_analysis.py` | APKTool, JADX, MobSF |
| Manifest vuln scan | Part of static | `apktool_wrapper.py` | APKTool, 24 dangerous permissions check |
| Java source analysis | Part of static | `jadx_wrapper.py` | JADX, 14 vuln patterns (WebView, crypto, SQL, storage) |
| AI-driven reverse engineering | Part of analysis | `mobile_ai_reverse_engineer.py` | 14 rule patterns + Claude/GPT analysis |
| Frida script generation | Part of analysis | `frida_script_generator.py` | Auto-generates SSL bypass, root bypass, auth/crypto/network hooks |
| Secret detection | Part of analysis | `mobile_secret_detection.py` | TruffleHog, Gitleaks, DEX binary string scanning |
| API endpoint discovery | `oneinfinity mobile-api <apk_id>` | `mobile_api_discovery.py` | Retrofit, OkHttp, URLSession, GraphQL patterns |
| Exported component testing | Part of analysis | `android_component_testing.py` | Drozer, androguard, XML manifest parsing |
| Dynamic analysis | `oneinfinity mobile-dynamic <apk_id>` | `mobile_dynamic_analysis.py` | Frida, Objection (SSL bypass, root bypass, keystore) |
| Network traffic analysis | Part of analysis | `mobile_network_analysis.py` | Static URL scan + Burp proxy integration |
| Mobile API attack testing | Part of analysis | `mobile_api_attack_engine.py` | IDOR, auth bypass, mass assignment, injection |
| Android emulator setup | Utility | `android_studio_integration.py` | AVD launch, APK install, Burp cert injection |
| Runtime monitoring | Part of dynamic | `rms_wrapper.py` | Crypto/network/storage/intent monitoring |

---

## 9. AI Security Testing

| Skill | Command | Engine | Description |
|-------|---------|--------|-------------|
| Full AI security scan | `oneinfinity ai-test <target> --all` | `ai_security_engine.py` | Orchestrates all tools in parallel |
| Garak scan | `oneinfinity ai-test <target> --garak` | `ai_security/tool_wrappers/garak_wrapper.py` | LLM vulnerability probing |
| PyRIT scan | `oneinfinity ai-test <target> --pyrit` | `ai_security/tool_wrappers/pyrit_wrapper.py` | Microsoft red team framework |
| Giskard scan | `oneinfinity ai-test <target>` | `ai_security/tool_wrappers/giskard_wrapper.py` | AI model testing |
| Purple Llama | `oneinfinity ai-test <target>` | `ai_security/tool_wrappers/purple_llama_wrapper.py` | Meta safety benchmarks |
| Rebuff | `oneinfinity ai-test <target>` | `ai_security/tool_wrappers/rebuff_wrapper.py` | Prompt injection detection |
| ART (Adversarial Robustness) | `oneinfinity ai-test <target>` | `ai_security/tool_wrappers/art_wrapper.py` | IBM ART adversarial attacks |
| Red team campaign | `oneinfinity ai-redteam <target>` | `ai_redteam_engine.py` | Genetic algorithm prompt evolution, 800+ templates, 18 mutation strategies |
| Jailbreak campaign | `oneinfinity ai-redteam <target> --campaign jailbreak --prompts 5000` | `ai_security/adversarial_prompt_evolution.py` | Evolutionary prompt optimization |
| RAG attack campaign | `oneinfinity ai-redteam <target> --campaign rag_attack` | `ai_redteam_engine.py` | Knowledge base poisoning tests |
| AI agent pentesting | `oneinfinity ai-agent-test <target> --all` | `ai_agent_pentest_engine.py` | Tool abuse, API abuse, data exfiltration on agentic systems |
| Prompt injection testing | Part of agent pentest | `ai_security/agent_prompt_generator.py` | Agentic system prompt injection vectors |

---

## 10. Autonomous Bounty Hunting

| Skill | Command | Engine | Description |
|-------|---------|--------|-------------|
| Program discovery | `oneinfinity hunter-start` | `program_discovery_engine.py` | Fetches live H1/Bugcrowd/Intigriti programs |
| Target prioritization | `oneinfinity hunter-start` | `target_prioritization_engine.py` | 6-dimension weighted scoring (tech risk, cloud, sensitive paths, etc.) |
| Autonomous multi-target scan | `oneinfinity hunter-start` | `bounty_hunter_engine.py` | discover → prioritize → scan → report |
| Single target scan | `oneinfinity hunter-scan <target>` | `autonomous_scan_pipeline.py` | Full 7-phase pipeline |
| Program scope validation | Automatic | `program_scope_analyzer.py` | H1/Bugcrowd/Intigriti scope fetch, wildcard/CIDR match |
| Parallel scanning | `oneinfinity swarm <targets_file>` | `parallel_scan_engine.py` | asyncio + ThreadPoolExecutor, rate limiting per domain |
| Distributed cluster scan | `oneinfinity swarm <targets_file>` | `swarm_scan_cluster.py` | Redis-backed master-worker (auto-fallback to threading) |

---

## 11. Traffic Capture & Replay

| Skill | Command | Engine | Description |
|-------|---------|--------|-------------|
| Start traffic capture | `oneinfinity traffic-capture` | `traffic_capture_engine.py` | SQLite-backed HTTP request/response capture |
| Replay request | `oneinfinity replay-request <id>` | `traffic_replay_engine.py` | Exact replay of captured HTTP request |
| Fuzz parameters | `oneinfinity replay-request <id> --param <name> --fuzz` | `traffic_replay_engine.py` | Mutate specific parameter with payload set |
| Replay attack | `oneinfinity replay-attack <id>` | `attack_replay_engine.py` | Replay known attack with permutations |
| Custom payload replay | `oneinfinity replay-attack <id> --payload '...'` | `attack_replay_engine.py` | Inject custom payload into attack template |
| Proxy integration | Automatic (per-module) | `proxy_manager.py` | Burp/ZAP/mitmproxy; per-module enable/disable, SSL bypass |

---

## 12. Scan Profiles & Configuration

| Skill | Command | Profile | Description |
|-------|---------|---------|-------------|
| Quick scan | `oneinfinity profile run quick` | `core/scan_profiles.py` | Fast surface-level scan |
| Deep scan | `oneinfinity profile run deep` | `core/scan_profiles.py` | Full tool suite, longer timeout |
| Research scan | `oneinfinity profile run research` | `core/scan_profiles.py` | Research mode + theory generation |
| Swarm scan | `oneinfinity profile run swarm` | `core/scan_profiles.py` | Multi-target distributed scan |
| Stealth scan | `oneinfinity profile run stealth` | `core/scan_profiles.py` | Low-noise, rate-limited scan |
| Scope management | `oneinfinity scope` | `core/scope_validator.py` | Wildcard/CIDR rules, always-OOS list, audit log |
| Cache management | `oneinfinity cache stats\|sweep\|invalidate` | `core/cache.py` | Per-tool TTL SQLite cache |
| Plugin management | `oneinfinity plugins list\|run` | `core/plugin_registry.py` | Auto-discover and run plugins |

---

## 13. Learning & Adaptive Planning

| Skill | Command | Engine | Description |
|-------|---------|--------|-------------|
| Adaptive recon strategy | Automatic | `learning/adaptive_planner.py` | Adjusts scan approach based on past results |
| Learning stats | `oneinfinity research stats` | `learning/knowledge_base.py` | Show sessions, findings, patterns in SQLite KB |
| Vulnerability pattern mining | Automatic | `learning/pattern_miner.py` | Extracts VulnPattern/TargetInsight from KB |

---

## 14. Source Code Analysis

| Skill | Command | Engine | Description |
|-------|---------|--------|-------------|
| Static source analysis | `oneinfinity scan <target>` | `source_analysis_engine.py` | Python/JS/Java/Go; route extraction, taint tracking via AST |
| HTML form/link crawling | `oneinfinity scan <target>` | `application_crawler.py` | HTML forms, links, API call detection (fetch/axios/XHR) |
| CI/CD pipeline generation | Utility | `cicd_integration_engine.py` | GitHub Actions, GitLab CI, Jenkinsfile generators |

---

## 15. Web UI Capabilities

All capabilities above are also available via the React web interface at `http://localhost:3000`.

| Page | Route | Description |
|------|-------|-------------|
| Dashboard | `/` | Overview metrics, recent findings |
| Targets | `/targets` | Target management |
| Scans | `/scans` | Scan history and live progress |
| Vulnerabilities | `/vulnerabilities` | Finding browser with filters |
| Attack Graph | `/graph` | Graph visualization |
| Graph Explorer | `/graph-explorer` | ForceGraph2D with attack paths and risk |
| AI Red Team | `/ai-redteam` | Campaign builder and results |
| AI Security | `/ai-security` | AI test console |
| AI Agent Pentest | `/ai-agent` | Agentic system tester |
| Mobile Security | `/mobile` | 14-tab mobile analysis UI |
| Bounty Hunter | `/hunter` | Autonomous hunter (5-tab) |
| Traffic Explorer | `/traffic` | HTTP capture and replay |
| Attack Replay | `/replay` | Attack replay builder |
| Reports | `/reports` | Report viewer |

---

---

## 16. Swarm Intelligence

| Skill | Command | Engine | Description |
|-------|---------|--------|-------------|
| Multi-agent parallel scan | `oneinfinity swarm-scan <target>` | `swarm_intelligence_engine.py` + `agent_swarm_coordinator.py` | 8 specialized agents (XSS, SQLi, SSRF, IDOR, Auth, BizLogic, Mobile, API) run in parallel with agent competition and collaboration |
| XSS swarm agent | (part of swarm-scan) | `XSSAgent` in `swarm_intelligence_engine.py` | Generates XSS hypotheses, uses dalfox/kxss, EMA learning |
| SQLi swarm agent | (part of swarm-scan) | `SQLiAgent` in `swarm_intelligence_engine.py` | Generates SQLi hypotheses, uses sqlmap/commix |
| SSRF swarm agent | (part of swarm-scan) | `SSRFAgent` in `swarm_intelligence_engine.py` | SSRF + cloud metadata endpoint probing |
| IDOR swarm agent | (part of swarm-scan) | `IDORAgent` in `swarm_intelligence_engine.py` | Object reference manipulation, sequential ID enumeration |
| Auth bypass swarm agent | (part of swarm-scan) | `AuthBypassAgent` in `swarm_intelligence_engine.py` | JWT abuse, session fixation, token prediction |
| Business logic swarm agent | (part of swarm-scan) | `BusinessLogicAgent` in `swarm_intelligence_engine.py` | Price manipulation, coupon stacking, race conditions |
| API security swarm agent | (part of swarm-scan) | `APISecAgent` in `swarm_intelligence_engine.py` | GraphQL introspection, BOLA, mass assignment, rate limit |
| Monte Carlo attack simulation | `oneinfinity simulate-attacks <target>` | `attack_simulation_engine.py` | N=200 Bernoulli trials, 23-path catalog, 6 probability factors, strategy recommendation |
| Business logic workflow simulation | `oneinfinity simulate-workflow <target>` | `workflow_simulation_engine.py` | 4 workflow factories (checkout/login/reset/transfer), 9 attack categories |
| Agent collaboration rules | (automatic in swarm-scan) | `AgentSwarmCoordinator` | SQLi finding → triggers IDOR; SSRF finding → triggers IDOR; XSS → triggers Auth agent |
| Exploit chain detection | (automatic in swarm-scan) | `AgentSwarmCoordinator._detect_chains()` | Cross-references 10 multi-step chain patterns (XSS→ATO, SQLi→RCE, SSRF→Cloud, etc.) |
| Swarm learning & Decision visibility | (continuous) | `SwarmAgent.learn_from_results()` | EMA (α=0.30) per-agent pattern success rate persistence. Decision logic and priority scoring are tracked and displayed on the Brain and Swarm UI dashboards |

---

## Tool Inventory (34/40 installed)

| Category | Tools |
|----------|-------|
| Go binaries (`~/go/bin/`) | dalfox, crlfuzz, kxss, dnsx, naabu, gobuster, ffuf, anew, gf, qsreplace, httpx, waybackurls, gauplus, katana, hakrawler, subfinder, assetfinder, amass, nuclei |
| System binaries (`~/.local/bin/`) | trufflehog, gitleaks, findomain, httpx (symlink) |
| Git clones (`~/.local/`) | sqlmap, xssstrike, jwt_tool, commix, paramspider, dirsearch |
| Python packages | arjun, s3scanner, sublist3r, whatweb, nikto |
| **Missing** | kiterunner, cloudbrute, wfuzz, rustscan, paramspider (pip), findomain |

---

## 17. Self-Evolving Architecture

| Skill | CLI Command | Module | Details |
|---|---|---|---|
| Platform event emission | `bounty arch-emit <type> [--name N --desc D]` | `auto_architecture_engine.py` | Emit 13 EventType values: FEATURE_ADDED, SCAN_COMPLETED, VULNERABILITY_DISCOVERED, etc. |
| Architecture status | `bounty arch-status` | `auto_architecture_engine.py` | Show engine state, recent changelog, active capabilities |
| Recent events log | `bounty arch-events [--limit N]` | `auto_architecture_engine.py` | List recent ArchEvents from the evolution engine |
| Learning insights | `bounty arch-insights [--type T]` | `memory_manager.py` | Query distilled learning insights with confidence scores |
| Attack pattern EMA | (automatic) | `memory_manager.py` | Track per-vuln-type success rate with exponential moving average (α=0.3) |
| Exploit chain storage | (automatic) | `memory_manager.py` | Persist multi-step chains with CVSS scores to `evolution.db` |
| Auto-update ARCHITECTURE.md | (automatic on FEATURE_ADDED) | `architecture_updater.py` | Parse into `ArchSection` objects, add components, atomic rewrite |
| Auto-update SKILLS.md | (automatic on SKILL_REGISTERED) | `skills_tracker.py` | 55 builtin skills, 7 categories, 5s write throttle |
| Auto-update README.md | (automatic on FEATURE_ADDED) | `readme_generator.py` | Full README from `FeatureEntry`/`CLICommand`/`UIPage` model |
| Capability snapshot | (automatic on ARCHITECTURE_UPDATED) | `memory_manager.py` | Persist version, module_count, skill_count over time |
| Architecture changelog | (automatic) | `architecture_updater.py` | Every `add_component()` call logged to `architecture_changelog` table |
| Attack graph integration | (hook) | `auto_architecture_engine.py` | `attach_attack_graph()` bridges graph events to platform events |
| Knowledge base integration | (hook) | `auto_architecture_engine.py` | `attach_knowledge_base()` bridges KB findings to platform events |
| Swarm coordinator integration | (hook) | `auto_architecture_engine.py` | `attach_swarm_coordinator()` bridges swarm results to platform events |

---

## 18. Event-Driven Intelligence Daemon

| Skill | CLI Command | Module | Details |
|---|---|---|---|
| Start daemon | `bounty daemon-start <target> [...]` | `intelligence_daemon.py` | Start always-on daemon, subscribe 9 workers to event bus |
| Stop daemon | `bounty daemon-stop` | `intelligence_daemon.py` | Graceful shutdown — cancel all worker tasks, flush event bus |
| Daemon status | `bounty daemon-status` | `intelligence_daemon.py` | Worker table (runs/findings/errors), bus stats, uptime |
| Add live target | `bounty daemon-add-target <target>` | `intelligence_daemon.py` | Add target to running daemon without restart |
| Vulnerability hypothesis | (automatic) | `HypothesisWorker` | On NEW_TARGET/NEW_ENDPOINT → AppModel → VulnTheory via theory engine |
| Attack graph expansion | (automatic) | `GraphExpansionWorker` | On NEW_ENDPOINT/OSINT_RESULT → add nodes/edges to AttackGraphEngine |
| Exploit chain detection | (automatic) | `ExploitChainWorker` | On NEW_VULNERABILITY → check 16 chain patterns, publish CHAIN_DETECTED |
| Payload mutation | (automatic) | `PayloadMutationWorker` | On failed EXPLOIT_ATTEMPTED → 8 mutation strategies (base64, unicode, HTML entity, etc.) |
| Traffic replay | (automatic) | `TrafficReplayWorker` | On NEW_VULNERABILITY → replay stored traffic with header/param variation |
| Business logic testing | (automatic) | `BusinessLogicWorker` | On NEW_API → invoke business_logic_engine tests, track workflow patterns |
| OSINT target expansion | (automatic) | `OSINTExpansionWorker` | On NEW_TARGET → run osint_collector + target_discovery_engine |
| Swarm agent dispatch | (automatic) | `SwarmWorker` | On NEW_TARGET/NEW_VULNERABILITY → dispatch to AgentSwarmCoordinator |
| Continuous learning | (automatic) | `LearningWorker` | On all finding events → update KnowledgeBase + MemoryManager, publish LEARNING_UPDATE |
| Live event stream (SSE) | (API) | `daemon_api.py` | `/api/events/stream` — Server-Sent Events with keepalive |
| Live event stream (WS) | (API) | `daemon_api.py` | `/api/events/ws` — WebSocket stream with per-type filter |
| Worker config hot-patch | (API) | `daemon_api.py` | `PATCH /api/daemon/config` — update cooldown/max_concurrent without restart |
| Dead-letter queue | (automatic) | `event_bus.py` | Failed handler payloads stored (max 200) for post-mortem debugging |
| Per-target cooldown | (automatic) | `WorkerEngine._throttled()` | Each worker tracks last-run per target, skips if within cooldown window |

---

## 19. Graph-Centric Autonomous System

| Skill | CLI Command | Module | Details |
|---|---|---|---|
| Start graph brain | `bounty brain-start <target> [...]` | `attack_graph_brain.py` | Start AttackGraphBrain + EDE + AgentFabric in one shot |
| Stop graph brain | `bounty brain-stop` | `attack_graph_brain.py` | Graceful shutdown of all components |
| Brain status | `bounty brain-status` | `attack_graph_brain.py` | Priority node table, queue depth, EDE/fabric counters |
| Generate decision plan | `bounty brain-decide <target>` | `autonomous_decision_engine.py` | Ranked (node, agent) decisions with scoring rationale |
| Trigger engine | `bounty brain-triggers [--evaluate]` | `graph_trigger_engine.py` | List rules or evaluate all graph nodes |
| Node priority scoring | (automatic) | `AttackGraphBrain._score_node()` | type_weight × connectivity × vuln_bonus × tested_discount |
| Graph-event routing | (automatic) | `EventDrivenEngine._route_event()` | Routes 8 bus event types into brain node/finding integration |
| Trigger rules (15) | (automatic on graph update) | `GraphTriggerEngine` | PARAMETER→inject, API→IDOR, AUTH→bypass, CRED→ATO, admin→priv, SSRF sink, redirect param, etc. |
| Decision scoring | (automatic) | `AutonomousDecisionEngine._score_pair()` | Impact × exploitability × novelty / effort × tested_penalty |
| Outcome feedback | (automatic) | `AutonomousDecisionEngine.record_outcome()` | Agent success rate EMA feeds future exploitability estimates |
| Recon agent | (fabric-triggered) | `ReconAgent` | subfinder + httpx probing + nuclei tech detection |
| XSS agent | (fabric-triggered) | `XSSAgent` | dalfox + kxss fallback |
| SQLi agent | (fabric-triggered) | `SQLiAgent` | sqlmap + nuclei sqli templates |
| IDOR agent | (fabric-triggered) | `IDORAgent` | nuclei IDOR templates + ffuf ID enumeration |
| SSRF agent | (fabric-triggered) | `SSRFAgent` | nuclei SSRF templates |
| Auth bypass agent | (fabric-triggered) | `AuthAgent` | nuclei auth/login/panel templates + jwt_tool |
| Business logic agent | (fabric-triggered) | `BusinessLogicAgent` | BusinessLogicEngine + nuclei logic/rate-limit |
| SSTI agent | (fabric-triggered) | `SSTIAgent` | nuclei ssti/template-injection templates |
| Open redirect agent | (fabric-triggered) | `OpenRedirectAgent` | nuclei redirect templates |
| Exploit chain agent | (fabric-triggered) | `ExploitAgent` | chain_patterns match + nuclei CVE templates |
| Mobile security agent | (fabric-triggered) | `MobileSecurityAgent` | MobileSecurityEngine 12-phase pipeline |
| AI security agent | (fabric-triggered) | `AISecurityAgent` | AISecurityEngine endpoint scan |
| Brain API | (backend) | `graph_brain_api.py` | 5 routers (brain/ede/triggers/decisions/fabric) + 21 endpoints |
| Live graph dashboard | `/graph-brain` | `GraphBrainDashboard.jsx` | 5-tab UI: Overview/AttackGraph/Decisions/Triggers/AgentFabric |
