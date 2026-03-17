# System Memory and Intelligence Architecture

This document outlines the mechanisms for learning, adaptation, and intelligence persistence within the One&Infinity platform.

## 1. Learning System (EMA & Experience)
The platform uses an Exponential Moving Average (EMA) learning system across Swarm Agents and the Adaptive Attack Strategy.
- **Agent Success Rates**: Agents adjust their likelihood of being selected based on previous successes against specific technology stacks and target shapes. 
- **Learning Feedback Loop**: Every exploit attempt (success or failure) is recorded via `record_outcome()`. Successes boost the `exploitability_estimate` for the agent-vector pair, while failures decay it (α=0.30).
- **Bounty Optimization**: The system tracks the financial impact (ROI) of successful exploits, updating the priority weighting of attack paths that historically lead to higher payout chains.
- **Pattern Mining**: The system continuously analyzes successful vulnerability triggers and correlates them with detected technologies (e.g., `django` + `postgres` → `sqli` probability increases).
- **Knowledge Base (KB)**: All learned intelligence is persisted in a localized SQLite database (`knowledge_base.db`), keeping a persistent record of tool runs, payload efficacy, and target profiles.

## 2. Mutation Strategies & WAF Evasion
The `ExploitGenerator` and `PayloadMutator` apply dynamically scaled mutations when Web Application Firewalls (WAF) are detected or when testing AI boundaries.
- **AI Mutations**: 18 specific AI mutation strategies exist (synonym replacement, leetspeak, homoglyphs, json injection, etc.) to evade LLM safety filters.
- **WAF Mutations**: Standard payloads are automatically wrapped in encoding chains (Base64, URL encoding, Double URL encoding) or obfuscated to bypass identified WAF rules.
- **Feedback Loop**: When an exploit fails or triggers a WAF, the ExploitChainEngine marks the strategy as ineffective for that target and switches to alternate permutations (e.g. whitespace injection, comment obfuscation).

## 3. Execution Context & Decision Making
- **Graph Brain**: The `AttackGraphBrain` centrally orchestrates execution by maintaining an active priority queue of test nodes.
- **Priority Boosting**: Nodes receive priority boosts based on connectivity (more connections = +0.5x), vulnerability status (exploitable = +0.5x), and severity (critical/high boost).
- **Decisions**: Decisions (which agent to deploy, which payload to try) are ranked by the `AutonomousDecisionEngine` using a `Score = Impact × Exploitability × Novelty / Effort` formula. These are fully visible via the UI (e.g., `BrainDashboard`, `SwarmIntelligence`).
- **Chain Execution**: Complex multi-step attacks are executed via the `ChainExecutor` using a structured `ExecutionContext` to pass tokens, credentials, and state between steps.
- **Attack Paths**: Attack paths and exploit chains are derived from a real-time `AttackGraphData` structure, bridging the gap between isolated findings and multi-step exploitation.

## 4. Safety Guard
- **Enforcement**: The `SafetyGuard` is enabled by default to prevent destructive actions (reboot, format, destructive deletion) during autonomous execution.
- **Pattern Filtering**: It filters all outgoing payloads and shell commands against a list of dangerous patterns before they reach the target. 
- **Manual Override**: Safety restrictions can be adjusted in the `config/` but require explicit acknowledgement for high-risk operations.