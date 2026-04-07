# Neo4j Learning Enhancement Design

**Date:** 2026-04-07
**Status:** Approved

## Overview

Replace the learning module's SQLite store (`learning/knowledge_base.py`) with a Neo4j graph backend. Neo4j becomes the single store for all learning intelligence — EMA scores, tool performance, target profiles, tech→vuln correlations, payload history, and exploit chains. PostgreSQL remains the findings ledger (unchanged). The learning module reads confirmed findings from PostgreSQL via `ResultIngestionEngine` events and writes graph intelligence into Neo4j.

---

## Decision Log

| Question | Decision | Rationale |
|---|---|---|
| What happens to learning SQLite? | Migrate to PostgreSQL + Neo4j | Eliminates fragmentation; learning module reads real findings |
| How do findings enter the graph? | Real-time events + one-time backfill (Option C) | Real-time keeps graph current; backfill handles historical data |
| What is Neo4j's role? | Graph-first learning store (Option B) | Richest intelligence; single store for all learning data |
| Primary graph queries | Both prediction + chain intelligence | Tech-stack predictions at scan-start; chain lookup during exploitation |

---

## Graph Schema

### Node Types

| Label | Key Properties | Purpose |
|---|---|---|
| `(:Target)` | `domain`, `last_scanned`, `scan_count`, `waf_detected`, `scope_notes` | One node per unique domain scanned |
| `(:Tech)` | `name` (e.g. `wordpress`, `nginx`, `php`) | Technology stack fingerprints |
| `(:VulnType)` | `name`, `ema_score`, `total_findings`, `last_seen` | Vuln type registry; EMA scores live here |
| `(:Tool)` | `name`, `runs_total`, `runs_success`, `avg_duration_s` | Tool performance stats |
| `(:Payload)` | `value`, `hits`, `fails`, `vuln_type` | Replaces `persistent_memory.json` payload store |
| `(:ExploitChain)` | `chain_id`, `success_count`, `last_seen`, `severity` | Learned chains from real scan outcomes |
| `(:Meta)` | `key`, `value` | Internal metadata (e.g. backfill checkpoint) |

### Relationship Types

| Relationship | Properties | Purpose |
|---|---|---|
| `(:Target)-[:HAS_TECH]→(:Tech)` | — | Tech stack detected on target |
| `(:Target)-[:EXPOSED]→(:VulnType)` | `severity`, `discovered_at` | Confirmed vuln on target |
| `(:Tech)-[:CORRELATES_WITH]→(:VulnType)` | `probability`, `hits`, `total_seen` | Learned tech→vuln probability |
| `(:VulnType)-[:EXPLOITED_BY]→(:Tool)` | `success_rate`, `hits`, `misses` | Best tool per vuln type |
| `(:Tool)-[:USES]→(:Payload)` | — | Payload genealogy per tool |
| `(:VulnType)-[:CHAINS_TO]→(:ExploitChain)` | — | Exploit chain paths from real scans |

### Example Prediction Query

```cypher
MATCH (tech:Tech)-[r:CORRELATES_WITH]->(v:VulnType)-[:EXPLOITED_BY]->(t:Tool)
WHERE tech.name IN ['wordpress', 'php']
RETURN v.name, avg(r.probability) AS confidence, t.name AS best_tool
ORDER BY confidence DESC
LIMIT 3
```

---

## Architecture

### Storage Responsibilities

| Store | Role |
|---|---|
| **PostgreSQL** | Findings ledger — `scan_sessions`, `findings`, `agents`, `events`, `recon_assets`. Unchanged. |
| **Neo4j** | All learning intelligence — EMA scores, tool performance, target profiles, tech→vuln correlations, payload history, exploit chains. |

### Components

**Rewritten (same interface, Neo4j backend):**
- `learning/knowledge_base.py` → `Neo4jKnowledgeBase` — replaces SQLite KnowledgeBase; same public interface so callers are unaffected
- `learning/pattern_miner.py` — SQLite queries replaced with Cypher traversal queries
- `learning/persistent_memory.py` — JSON file store replaced with `(:Payload)` nodes in Neo4j

**New files:**
- `learning/graph_learning_writer.py` — async writer; receives events from `ResultIngestionEngine`, upserts nodes/edges into Neo4j in a background thread pool
- `learning/backfill.py` — one-time idempotent script; reads `findings_history` from PostgreSQL in batches of 500 and populates Neo4j; resumable via `(:Meta {key:'backfill_last_id'})` checkpoint node
- `learning/graph_schema.py` — bootstraps Neo4j constraints and indexes on first connect

**Minimally changed:**
- `result_ingestion_engine.py` — small hook added: after saving finding to PG, fires async call to `GraphLearningWriter` (fire-and-forget, non-blocking)

**Unchanged:**
- `learning/adaptive_planner.py` — interface preserved; consumes `PatternMiner` output as before
- `core/neo4j_engine.py` — reused as-is; attack graph and learning graph use the same engine
- Web frontend Learning page — unchanged
- Web backend learning API endpoints — unchanged

---

## Data Flow

### Per-Finding Write Path (real-time)

Each confirmed finding triggers one Neo4j transaction with 7 idempotent MERGE operations:

1. `MERGE (:Target {domain})` — create or match target node
2. For each tech in target's tech stack: `MERGE (:Tech {name})`, `MERGE Target-[:HAS_TECH]→Tech`
3. `MERGE (:VulnType {name})` — update EMA score: `new_ema = 0.3 * 1.0 + 0.7 * old_ema` (α=0.3)
4. `MERGE (:Tool {name})` — update `EXPLOITED_BY` edge hit count and success rate
5. Update `CORRELATES_WITH` edge probability: `hits / total_seen` per Tech→VulnType pair
6. If finding has payload: `MERGE (:Payload {value, vuln_type})`, increment `hits`
7. `MERGE Target-[:EXPOSED {severity, discovered_at}]→VulnType`

### Backfill

- Triggered by: `oneinfinity learning backfill` CLI command
- Reads `findings_history` from PostgreSQL in batches of 500
- All writes are MERGE — idempotent, safe to re-run
- Tracks progress in `(:Meta {key:'backfill_last_id'})` — resumable after interruption

---

## Error Handling

| Failure | Behaviour |
|---|---|
| Neo4j unavailable at startup | `Neo4jKnowledgeBase` sets `_available=False`; all write methods no-op; `PatternMiner` returns seed-pattern-based `TargetInsight`; no exception propagated |
| Neo4j disconnects mid-scan | `GraphLearningWriter` catches `ServiceUnavailable`, logs error with finding ID, drops the write (finding is safe in PG); reconnect attempted on next write; missed findings recoverable via backfill |
| Cypher query fails | `PatternMiner` catches `Neo4jError`, logs + returns empty `TargetInsight`; `AdaptivePlanner` falls back to default phase order; scan continues |
| Backfill interrupted | Resume from `(:Meta {key:'backfill_last_id'})` checkpoint; re-run command |

---

## Testing

### New Test Files

**`tests/test_graph_learning_writer.py`** (unit, mocked Neo4j)
- Upserts correct nodes/edges for a confirmed finding
- EMA formula correctness (numerical verification)
- Tech→VulnType probability increments correctly on repeat findings
- No-op and no exception when Neo4j unavailable
- Drops write + logs error on `ServiceUnavailable` mid-call

**`tests/test_neo4j_knowledge_base.py`** (unit, mocked Neo4j)
- `record_finding()` calls correct Cypher MERGEs
- `get_vuln_type_stats()` returns EMA scores from node properties
- `get_tool_performance()` returns stats from `EXPLOITED_BY` edge properties
- All methods no-op gracefully when `_available=False`

**`tests/test_pattern_miner_neo4j.py`** (integration, real Neo4j)
- Seed 3 targets with known tech stacks + findings → verify predicted vulns match expected order
- Multi-tech query returns higher-confidence predictions than single-tech
- Empty graph returns seed-pattern-based `TargetInsight` (not empty/crash)
- Exploit chain traversal returns correct chain for known vuln sequence

**`tests/test_learning_backfill.py`** (integration)
- Backfill from 10 PG findings → correct node/edge count in Neo4j
- Idempotent — running twice produces same graph state
- Interrupted backfill resumes from checkpoint

### Existing Tests (must keep passing)
- `AdaptivePlanner` produces valid `AdaptivePlan` (interface preserved)
- `PatternMiner.get_insight()` returns `TargetInsight` with required fields
- `ResultIngestionEngine` tests unaffected (hook is fire-and-forget)
- `test_neo4j_integration.py` (attack graph tests) unaffected

**Test isolation:** Integration tests use the existing Neo4j test DB (`config/neo4j.yaml`). Each test tears down its own nodes via `MATCH (n) DETACH DELETE`.
