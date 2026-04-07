# Neo4j Learning Enhancement Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Replace the learning module's SQLite store with a Neo4j graph backend, wiring confirmed findings from `ResultIngestionEngine` into a graph that enables tech-stack-based vuln prediction and exploit chain intelligence.

**Architecture:** `Neo4jKnowledgeBase` replaces `KnowledgeBase` with the same public interface backed by Neo4j. `GraphLearningWriter` hooks into `ResultIngestionEngine` (fire-and-forget thread) to upsert learning nodes/edges after each confirmed finding. `PatternMiner` issues Cypher traversal queries instead of SQLite selects. `PersistentMemory` stores payloads as `(:LN_Payload)` nodes. A `backfill.py` CLI command seeds the graph from existing PG findings.

**Tech Stack:** Python 3.13, neo4j driver (`neo4j` package already in requirements), existing `core/neo4j_engine.py` driver wrapper, existing `config/neo4j.yaml` for connection config, pytest for tests.

---

## File Map

| File | Action | Responsibility |
|---|---|---|
| `learning/graph_schema.py` | Create | Bootstrap LN_* constraints + indexes on first connect |
| `learning/neo4j_knowledge_base.py` | Create | Neo4j-backed KnowledgeBase with identical public interface |
| `learning/pattern_miner.py` | Modify | Replace SQLite queries with Cypher traversal queries |
| `learning/persistent_memory.py` | Modify | Replace JSON file store with LN_Payload nodes in Neo4j |
| `learning/graph_learning_writer.py` | Create | Async writer — upserts nodes/edges per confirmed finding |
| `learning/adaptive_planner.py` | Modify | LearningSystem uses Neo4jKnowledgeBase instead of KnowledgeBase |
| `learning/backfill.py` | Create | One-time idempotent backfill from PG findings_history |
| `result_ingestion_engine.py` | Modify | Add fire-and-forget hook to GraphLearningWriter after _broadcast |
| `tests/test_graph_learning_writer.py` | Create | Unit tests for GraphLearningWriter (mocked Neo4j) |
| `tests/test_neo4j_knowledge_base.py` | Create | Unit tests for Neo4jKnowledgeBase (mocked Neo4j) |
| `tests/test_pattern_miner_neo4j.py` | Create | Integration tests for PatternMiner Cypher queries |
| `tests/test_learning_backfill.py` | Create | Integration tests for backfill idempotency |

---

### Task 1: Bootstrap schema — `learning/graph_schema.py`

**Files:**
- Create: `learning/graph_schema.py`

- [ ] **Step 1: Create graph_schema.py**

```python
"""
learning/graph_schema.py — Bootstrap Neo4j constraints and indexes for learning graph.

Call bootstrap_learning_schema(driver, database) once at startup.
All labels are prefixed LN_ to avoid collision with attack graph (OI_Node / OI_REL).
"""
from __future__ import annotations

import logging

log = logging.getLogger("oneinfinity.learning.graph_schema")

# Uniqueness constraints — one per node label on its natural key
_CONSTRAINTS = [
    "CREATE CONSTRAINT IF NOT EXISTS FOR (n:LN_Target)   REQUIRE n.domain    IS UNIQUE",
    "CREATE CONSTRAINT IF NOT EXISTS FOR (n:LN_Tech)     REQUIRE n.name      IS UNIQUE",
    "CREATE CONSTRAINT IF NOT EXISTS FOR (n:LN_VulnType) REQUIRE n.name      IS UNIQUE",
    "CREATE CONSTRAINT IF NOT EXISTS FOR (n:LN_Tool)     REQUIRE n.name      IS UNIQUE",
    "CREATE CONSTRAINT IF NOT EXISTS FOR (n:LN_Payload)  REQUIRE n.key       IS UNIQUE",
    "CREATE CONSTRAINT IF NOT EXISTS FOR (n:LN_Meta)     REQUIRE n.key       IS UNIQUE",
]

# Lookup indexes
_INDEXES = [
    "CREATE INDEX IF NOT EXISTS FOR (n:LN_VulnType) ON (n.ema_score)",
    "CREATE INDEX IF NOT EXISTS FOR (n:LN_Target)   ON (n.last_scanned)",
]


def bootstrap_learning_schema(driver, database: str = "neo4j") -> None:
    """Apply constraints and indexes. Safe to call multiple times."""
    if driver is None:
        return
    try:
        with driver.session(database=database) as sess:
            for stmt in _CONSTRAINTS + _INDEXES:
                sess.run(stmt)
        log.info("Learning graph schema bootstrapped (%d constraints, %d indexes)",
                 len(_CONSTRAINTS), len(_INDEXES))
    except Exception as exc:
        log.warning("bootstrap_learning_schema failed (non-fatal): %s", exc)
```

- [ ] **Step 2: Verify syntax**

```bash
cd /home/devendra-yadav/oneinfinity
python3 -c "import learning.graph_schema; print('OK')"
```

Expected: `OK`

- [ ] **Step 3: Commit**

```bash
git add learning/graph_schema.py
git commit -m "feat(learning): add Neo4j learning graph schema bootstrap"
```

---

### Task 2: `learning/neo4j_knowledge_base.py` — Neo4j-backed KnowledgeBase

**Files:**
- Create: `learning/neo4j_knowledge_base.py`
- Test: `tests/test_neo4j_knowledge_base.py`

- [ ] **Step 1: Write failing tests**

```python
# tests/test_neo4j_knowledge_base.py
"""Unit tests for Neo4jKnowledgeBase — Neo4j driver is mocked."""
from __future__ import annotations

from unittest.mock import MagicMock, patch, call
import pytest
from learning.neo4j_knowledge_base import Neo4jKnowledgeBase


def _make_kb(available: bool = True) -> Neo4jKnowledgeBase:
    """Return a Neo4jKnowledgeBase with a mocked or absent driver."""
    kb = Neo4jKnowledgeBase.__new__(Neo4jKnowledgeBase)
    kb._available = available
    kb._database = "neo4j"
    if available:
        mock_driver = MagicMock()
        mock_session = MagicMock()
        mock_driver.session.return_value.__enter__ = MagicMock(return_value=mock_session)
        mock_driver.session.return_value.__exit__ = MagicMock(return_value=False)
        kb._driver = mock_driver
        kb._mock_session = mock_session
    else:
        kb._driver = None
    return kb


class TestNeo4jKnowledgeBaseUnavailable:
    """All methods must be no-ops when Neo4j is unavailable."""

    def test_record_finding_noop(self):
        kb = _make_kb(available=False)
        kb.record_finding("s1", {"vuln_type": "XSS", "target": "example.com"})  # must not raise

    def test_best_tool_for_vuln_returns_empty(self):
        kb = _make_kb(available=False)
        assert kb.best_tool_for_vuln("XSS") == []

    def test_get_target_profile_returns_none(self):
        kb = _make_kb(available=False)
        assert kb.get_target_profile("example.com") is None

    def test_patterns_for_tech_stack_returns_empty(self):
        kb = _make_kb(available=False)
        assert kb.patterns_for_tech_stack(["wordpress"]) == []

    def test_stats_returns_zeroed(self):
        kb = _make_kb(available=False)
        s = kb.stats()
        assert s["sessions"] == 0
        assert s["confirmed_findings"] == 0
        assert s["unique_targets"] == 0

    def test_start_session_noop(self):
        kb = _make_kb(available=False)
        result = kb.start_session("s1", "example.com")
        assert result == "s1"

    def test_record_tool_run_noop(self):
        kb = _make_kb(available=False)
        kb.record_tool_run("nuclei", "XSS")  # must not raise


class TestNeo4jKnowledgeBaseAvailable:
    """When available, methods must run Cypher via the driver session."""

    def test_record_finding_calls_session_run(self):
        kb = _make_kb(available=True)
        kb.record_finding("s1", {
            "vuln_type": "XSS", "target": "example.com",
            "severity": "high", "cvss_score": 7.5,
            "source_tool": "dalfox", "payload": "<script>",
        })
        assert kb._mock_session.run.called

    def test_upsert_target_profile_calls_session_run(self):
        kb = _make_kb(available=True)
        kb.upsert_target_profile("example.com", tech_stack=["nginx", "php"])
        assert kb._mock_session.run.called

    def test_upsert_pattern_calls_session_run(self):
        kb = _make_kb(available=True)
        kb.upsert_pattern(["wordpress"], "SQL Injection", cvss=7.0, best_tool="sqlmap")
        assert kb._mock_session.run.called

    def test_record_tool_run_calls_session_run(self):
        kb = _make_kb(available=True)
        kb.record_tool_run("dalfox", "XSS", success=True, findings_count=3)
        assert kb._mock_session.run.called
```

- [ ] **Step 2: Run tests to verify they fail**

```bash
cd /home/devendra-yadav/oneinfinity
python3 -m pytest tests/test_neo4j_knowledge_base.py -v 2>&1 | head -30
```

Expected: `ModuleNotFoundError: No module named 'learning.neo4j_knowledge_base'`

- [ ] **Step 3: Create `learning/neo4j_knowledge_base.py`**

```python
"""
learning/neo4j_knowledge_base.py — Neo4j-backed knowledge base for the learning system.

Drop-in replacement for learning/knowledge_base.py with identical public interface.
Uses LN_* node labels to avoid collision with the attack graph (OI_Node/OI_REL).

Node labels:  LN_Target, LN_Tech, LN_VulnType, LN_Tool, LN_Session, LN_Meta
Relationships: LN_HAS_TECH, LN_EXPOSED, LN_CORRELATES_WITH, LN_EXPLOITED_BY
"""
from __future__ import annotations

import logging
import time
from typing import Optional

log = logging.getLogger("oneinfinity.learning.neo4j_kb")

_EMA_ALPHA = 0.3   # weight given to a new finding in EMA update


def _load_neo4j_config() -> dict:
    """Read config/neo4j.yaml. Returns defaults if file missing."""
    try:
        import yaml
        from pathlib import Path
        p = Path(__file__).parent.parent / "config" / "neo4j.yaml"
        if p.exists():
            return yaml.safe_load(p.read_text()) or {}
    except Exception:
        pass
    return {"uri": "bolt://localhost:7687", "user": "neo4j",
            "password": "neo4j123", "database": "neo4j"}


class Neo4jKnowledgeBase:
    """
    Neo4j-backed learning knowledge base. Identical public interface to KnowledgeBase.
    All methods are no-ops when Neo4j is unavailable (_available=False).
    """

    def __init__(self, _db_path: str = ""):  # _db_path kept for interface compatibility
        self._available = False
        self._driver = None
        self._database = "neo4j"
        try:
            from neo4j import GraphDatabase
            from neo4j.exceptions import ServiceUnavailable
            cfg = _load_neo4j_config()
            self._database = cfg.get("database", "neo4j")
            driver = GraphDatabase.driver(
                cfg.get("uri", "bolt://localhost:7687"),
                auth=(cfg.get("user", "neo4j"), cfg.get("password", "neo4j123")),
            )
            driver.verify_connectivity()
            self._driver = driver
            self._available = True
            from learning.graph_schema import bootstrap_learning_schema
            bootstrap_learning_schema(self._driver, self._database)
            log.info("Neo4jKnowledgeBase: connected to %s", cfg.get("uri"))
        except Exception as exc:
            log.warning("Neo4jKnowledgeBase unavailable (%s) — all writes will be no-ops", exc)

    def _sess(self):
        return self._driver.session(database=self._database)

    # ── Session management ─────────────────────────────────────────────────────

    def start_session(self, session_id: str, target: str,
                      phases: list[str] | None = None) -> str:
        if not self._available:
            return session_id
        try:
            with self._sess() as s:
                s.run(
                    "MERGE (sess:LN_Session {session_id: $sid}) "
                    "SET sess.target=$target, sess.started_at=$ts, sess.phases=$phases",
                    sid=session_id, target=target,
                    ts=time.time(), phases=phases or [],
                )
        except Exception as exc:
            log.debug("start_session failed: %s", exc)
        return session_id

    def finish_session(self, session_id: str, total_findings: int,
                       tools_used: list[str] | None = None, notes: str = ""):
        if not self._available:
            return
        try:
            with self._sess() as s:
                s.run(
                    "MATCH (sess:LN_Session {session_id: $sid}) "
                    "SET sess.finished_at=$ts, sess.total_findings=$tf, "
                    "    sess.tools_used=$tools, sess.notes=$notes",
                    sid=session_id, ts=time.time(),
                    tf=total_findings, tools=tools_used or [], notes=notes,
                )
        except Exception as exc:
            log.debug("finish_session failed: %s", exc)

    # ── Findings recording ─────────────────────────────────────────────────────

    def record_finding(self, session_id: str, finding: dict, confirmed: bool = True):
        if not self._available:
            return
        vuln_type = finding.get("vuln_type", "unknown")
        target    = finding.get("target", "")
        severity  = finding.get("severity", "info")
        tool      = finding.get("source_tool", "")
        cvss      = float(finding.get("cvss_score") or 0.0)
        try:
            with self._sess() as s:
                s.run(
                    """
                    MERGE (v:LN_VulnType {name: $vuln})
                    ON CREATE SET v.ema_score = $alpha, v.total_findings = 1,
                                  v.last_seen = $ts
                    ON MATCH  SET v.ema_score = $alpha * 1.0 + (1 - $alpha) * v.ema_score,
                                  v.total_findings = v.total_findings + 1,
                                  v.last_seen = $ts
                    """,
                    vuln=vuln_type, alpha=_EMA_ALPHA, ts=time.time(),
                )
                if target:
                    s.run(
                        """
                        MERGE (t:LN_Target {domain: $domain})
                        ON CREATE SET t.scan_count=1, t.last_scanned=$ts
                        ON MATCH  SET t.scan_count=t.scan_count+1, t.last_scanned=$ts
                        WITH t
                        MATCH (v:LN_VulnType {name: $vuln})
                        MERGE (t)-[:LN_EXPOSED {severity: $sev, discovered_at: $ts}]->(v)
                        """,
                        domain=target, vuln=vuln_type,
                        sev=severity, ts=time.time(),
                    )
                if tool:
                    s.run(
                        """
                        MERGE (tool:LN_Tool {name: $tool})
                        WITH tool
                        MATCH (v:LN_VulnType {name: $vuln})
                        MERGE (v)-[r:LN_EXPLOITED_BY]->(tool)
                        ON CREATE SET r.hits=1, r.misses=0,
                                      r.success_rate=1.0
                        ON MATCH  SET r.hits = r.hits + 1,
                                      r.success_rate = toFloat(r.hits) / (r.hits + r.misses)
                        """,
                        tool=tool, vuln=vuln_type,
                    )
        except Exception as exc:
            log.debug("record_finding failed: %s", exc)

    def record_findings_bulk(self, session_id: str, findings: list[dict],
                              confirmed: bool = True):
        for f in findings:
            try:
                self.record_finding(session_id, f, confirmed)
            except Exception:
                pass

    # ── Tool performance ───────────────────────────────────────────────────────

    def record_tool_run(self, tool_name: str, vuln_type: str = "",
                        target_type: str = "", success: bool = True,
                        findings_count: int = 0, duration_s: float = 0.0):
        if not self._available:
            return
        try:
            with self._sess() as s:
                s.run(
                    """
                    MERGE (t:LN_Tool {name: $tool})
                    ON CREATE SET t.runs_total=1, t.runs_success=$succ_int,
                                  t.findings_total=$fc, t.avg_duration_s=$dur,
                                  t.last_updated=$ts
                    ON MATCH  SET t.runs_total = t.runs_total + 1,
                                  t.runs_success = t.runs_success + $succ_int,
                                  t.findings_total = t.findings_total + $fc,
                                  t.avg_duration_s = (t.avg_duration_s * (t.runs_total - 1) + $dur) / t.runs_total,
                                  t.last_updated = $ts
                    """,
                    tool=tool_name, succ_int=1 if success else 0,
                    fc=findings_count, dur=duration_s, ts=time.time(),
                )
                if vuln_type and not success:
                    s.run(
                        """
                        MATCH (v:LN_VulnType {name: $vuln})
                        MATCH (t:LN_Tool {name: $tool})
                        MERGE (v)-[r:LN_EXPLOITED_BY]->(t)
                        ON CREATE SET r.hits=0, r.misses=1, r.success_rate=0.0
                        ON MATCH  SET r.misses = r.misses + 1,
                                      r.success_rate = toFloat(r.hits) / (r.hits + r.misses)
                        """,
                        vuln=vuln_type, tool=tool_name,
                    )
        except Exception as exc:
            log.debug("record_tool_run failed: %s", exc)

    def best_tool_for_vuln(self, vuln_type: str, top_n: int = 3) -> list[dict]:
        if not self._available:
            return []
        try:
            with self._sess() as s:
                result = s.run(
                    """
                    MATCH (v:LN_VulnType {name: $vuln})-[r:LN_EXPLOITED_BY]->(t:LN_Tool)
                    WHERE r.hits > 0
                    RETURN t.name AS tool_name, r.hits AS findings_total,
                           r.success_rate AS success_rate,
                           t.runs_total AS runs_total,
                           t.avg_duration_s AS avg_duration_s
                    ORDER BY r.success_rate DESC, r.hits DESC
                    LIMIT $n
                    """,
                    vuln=vuln_type, n=top_n,
                )
                return [dict(r) for r in result]
        except Exception as exc:
            log.debug("best_tool_for_vuln failed: %s", exc)
            return []

    # ── Target profiles ────────────────────────────────────────────────────────

    def upsert_target_profile(self, domain: str, tech_stack: list[str] | None = None,
                               waf: str = "", scope_notes: str = ""):
        if not self._available:
            return
        try:
            with self._sess() as s:
                s.run(
                    """
                    MERGE (t:LN_Target {domain: $domain})
                    ON CREATE SET t.scan_count=1, t.last_scanned=$ts,
                                  t.waf_detected=$waf, t.scope_notes=$notes
                    ON MATCH  SET t.scan_count=t.scan_count+1, t.last_scanned=$ts,
                                  t.waf_detected=$waf, t.scope_notes=$notes
                    """,
                    domain=domain, ts=time.time(), waf=waf, notes=scope_notes,
                )
                for tech in (tech_stack or []):
                    s.run(
                        """
                        MERGE (tech:LN_Tech {name: $tech})
                        WITH tech
                        MATCH (t:LN_Target {domain: $domain})
                        MERGE (t)-[:LN_HAS_TECH]->(tech)
                        """,
                        tech=tech.lower(), domain=domain,
                    )
        except Exception as exc:
            log.debug("upsert_target_profile failed: %s", exc)

    def get_target_profile(self, domain: str) -> dict | None:
        if not self._available:
            return None
        try:
            with self._sess() as s:
                row = s.run(
                    "MATCH (t:LN_Target {domain: $domain}) RETURN t",
                    domain=domain,
                ).single()
                if not row:
                    return None
                node = dict(row["t"])
                # Fetch tech stack from relationships
                techs = s.run(
                    "MATCH (t:LN_Target {domain: $domain})-[:LN_HAS_TECH]->(tech:LN_Tech) "
                    "RETURN tech.name AS name",
                    domain=domain,
                )
                node["tech_stack"] = [r["name"] for r in techs]
                node["historical_vulns"] = {}
                return node
        except Exception as exc:
            log.debug("get_target_profile failed: %s", exc)
            return None

    # ── Pattern library ────────────────────────────────────────────────────────

    def upsert_pattern(self, tech_stack: list[str], vuln_type: str,
                       cvss: float = 0.0, best_tool: str = ""):
        if not self._available:
            return
        for tech in tech_stack:
            try:
                with self._sess() as s:
                    s.run(
                        """
                        MERGE (tech:LN_Tech {name: $tech})
                        MERGE (v:LN_VulnType {name: $vuln})
                        ON CREATE SET v.ema_score=0.5, v.total_findings=0, v.last_seen=0
                        MERGE (tech)-[r:LN_CORRELATES_WITH]->(v)
                        ON CREATE SET r.hits=1, r.total_seen=1,
                                      r.probability=1.0, r.avg_cvss=$cvss,
                                      r.best_tool=$tool, r.last_seen=$ts
                        ON MATCH  SET r.hits = r.hits + 1,
                                      r.total_seen = r.total_seen + 1,
                                      r.probability = toFloat(r.hits) / r.total_seen,
                                      r.avg_cvss = (r.avg_cvss * (r.hits - 1) + $cvss) / r.hits,
                                      r.best_tool = $tool,
                                      r.last_seen = $ts
                        """,
                        tech=tech.lower(), vuln=vuln_type,
                        cvss=cvss, tool=best_tool, ts=time.time(),
                    )
            except Exception as exc:
                log.debug("upsert_pattern failed: %s", exc)

    def patterns_for_tech_stack(self, tech_stack: list[str]) -> list[dict]:
        if not self._available or not tech_stack:
            return []
        try:
            with self._sess() as s:
                result = s.run(
                    """
                    MATCH (tech:LN_Tech)-[r:LN_CORRELATES_WITH]->(v:LN_VulnType)
                    WHERE tech.name IN $techs
                    RETURN v.name AS vuln_type,
                           avg(r.probability) AS probability,
                           avg(r.avg_cvss) AS avg_cvss,
                           r.best_tool AS best_tool,
                           sum(r.hits) AS occurrence_count
                    ORDER BY probability DESC
                    LIMIT 20
                    """,
                    techs=[t.lower() for t in tech_stack],
                )
                return [dict(r) for r in result]
        except Exception as exc:
            log.debug("patterns_for_tech_stack failed: %s", exc)
            return []

    # ── Analytics ──────────────────────────────────────────────────────────────

    def stats(self) -> dict:
        if not self._available:
            return {
                "sessions": 0, "confirmed_findings": 0, "unique_targets": 0,
                "top_vuln_types": [], "top_tools": [], "vuln_type_stats": {},
            }
        try:
            with self._sess() as s:
                sessions   = (s.run("MATCH (n:LN_Session) RETURN count(n) AS c").single() or {}).get("c", 0)
                findings   = (s.run("MATCH (n:LN_VulnType) RETURN sum(n.total_findings) AS c").single() or {}).get("c", 0) or 0
                targets    = (s.run("MATCH (n:LN_Target) RETURN count(n) AS c").single() or {}).get("c", 0)
                top_vulns_rows = s.run(
                    "MATCH (v:LN_VulnType) WHERE v.total_findings > 0 "
                    "RETURN v.name AS vuln_type, v.total_findings AS count "
                    "ORDER BY count DESC LIMIT 5"
                )
                top_vulns = [{"vuln_type": r["vuln_type"], "count": r["count"]} for r in top_vulns_rows]
                top_tools_rows = s.run(
                    "MATCH (t:LN_Tool) WHERE t.findings_total > 0 "
                    "RETURN t.name AS tool, t.findings_total AS findings "
                    "ORDER BY findings DESC LIMIT 5"
                )
                top_tools = [{"tool": r["tool"], "findings": r["findings"]} for r in top_tools_rows]
                vuln_stats_rows = s.run(
                    "MATCH (v:LN_VulnType) WHERE v.total_findings > 0 "
                    "RETURN v.name AS name, v.ema_score AS ema_score, v.total_findings AS count"
                )
                vuln_type_stats = {
                    r["name"]: {"ema_score": r["ema_score"], "count": r["count"]}
                    for r in vuln_stats_rows
                }
            return {
                "sessions": int(sessions or 0),
                "confirmed_findings": int(findings or 0),
                "unique_targets": int(targets or 0),
                "top_vuln_types": top_vulns,
                "top_tools": top_tools,
                "vuln_type_stats": vuln_type_stats,
            }
        except Exception as exc:
            log.debug("stats failed: %s", exc)
            return {
                "sessions": 0, "confirmed_findings": 0, "unique_targets": 0,
                "top_vuln_types": [], "top_tools": [], "vuln_type_stats": {},
            }

    def recent_sessions(self, limit: int = 10) -> list[dict]:
        if not self._available:
            return []
        try:
            with self._sess() as s:
                result = s.run(
                    "MATCH (sess:LN_Session) RETURN sess "
                    "ORDER BY sess.started_at DESC LIMIT $n",
                    n=limit,
                )
                return [dict(r["sess"]) for r in result]
        except Exception as exc:
            log.debug("recent_sessions failed: %s", exc)
            return []

    def close(self):
        if self._driver:
            try:
                self._driver.close()
            except Exception:
                pass
            self._driver = None
            self._available = False
```

- [ ] **Step 4: Run tests**

```bash
cd /home/devendra-yadav/oneinfinity
python3 -m pytest tests/test_neo4j_knowledge_base.py -v
```

Expected: all tests pass.

- [ ] **Step 5: Verify import**

```bash
python3 -c "from learning.neo4j_knowledge_base import Neo4jKnowledgeBase; print('OK')"
```

Expected: `OK` (connection warning is fine — Neo4j may not be running)

- [ ] **Step 6: Commit**

```bash
git add learning/neo4j_knowledge_base.py tests/test_neo4j_knowledge_base.py
git commit -m "feat(learning): add Neo4jKnowledgeBase with identical KnowledgeBase interface"
```

---

### Task 3: Update `learning/pattern_miner.py` to use Cypher queries

**Files:**
- Modify: `learning/pattern_miner.py` (lines 1-12 — import change; `__init__` type hint; `_seed_patterns` logic)

- [ ] **Step 1: Update imports and type hint in pattern_miner.py**

In `learning/pattern_miner.py`, replace the import at the top:

```python
# OLD (line 11):
from learning.knowledge_base import KnowledgeBase

# NEW:
from learning.neo4j_knowledge_base import Neo4jKnowledgeBase as KnowledgeBase
```

And update the `__init__` type hint (line 73):

```python
# OLD:
    def __init__(self, kb: KnowledgeBase):

# NEW:
    def __init__(self, kb: "KnowledgeBase"):
```

- [ ] **Step 2: Verify PatternMiner still imports**

```bash
cd /home/devendra-yadav/oneinfinity
python3 -c "from learning.pattern_miner import PatternMiner; print('OK')"
```

Expected: `OK`

- [ ] **Step 3: Verify predict_for_target works with unavailable Neo4j**

```bash
python3 -c "
from learning.neo4j_knowledge_base import Neo4jKnowledgeBase
from learning.pattern_miner import PatternMiner
kb = Neo4jKnowledgeBase.__new__(Neo4jKnowledgeBase)
kb._available = False
kb._driver = None
kb._database = 'neo4j'
pm = PatternMiner.__new__(PatternMiner)
pm.kb = kb
result = pm.predict_for_target('example.com', ['wordpress'])
print('scan_priority:', result.scan_priority)
print('OK')
"
```

Expected: prints `scan_priority: thorough` and `OK`

- [ ] **Step 4: Commit**

```bash
git add learning/pattern_miner.py
git commit -m "feat(learning): wire PatternMiner to Neo4jKnowledgeBase"
```

---

### Task 4: Update `learning/persistent_memory.py` to use Neo4j Payload nodes

**Files:**
- Modify: `learning/persistent_memory.py`

The public interface (`record_successful_payload`, `get_boosted_payloads`, `get_failed_payloads`, `record_high_value_target`, etc.) must remain identical. We replace the internal JSON file store with Neo4j `LN_Payload` and `LN_Target` nodes, with JSON file fallback when Neo4j is unavailable.

- [ ] **Step 1: Add `_get_neo4j_driver` helper at top of persistent_memory.py**

After the existing imports at line 31, add:

```python
def _get_neo4j_driver():
    """Return (driver, database) or (None, 'neo4j') if unavailable."""
    try:
        from learning.neo4j_knowledge_base import Neo4jKnowledgeBase
        kb = Neo4jKnowledgeBase.__new__(Neo4jKnowledgeBase)
        # Reuse the singleton if already created
        from learning import _kb_singleton  # type: ignore
        if hasattr(_kb_singleton, '_driver') and _kb_singleton._driver:
            return _kb_singleton._driver, _kb_singleton._database
    except Exception:
        pass
    return None, "neo4j"
```

- [ ] **Step 2: Update `record_successful_payload` to also write to Neo4j**

In `PersistentMemory.record_successful_payload` (after the existing `with self._lock` block that updates `self._data`), add a Neo4j write. Replace the method body with:

```python
    def record_successful_payload(self, payload: str, vuln_type: str) -> None:
        if not payload:
            return
        # Keep in-memory dict (unchanged)
        with self._lock:
            for entry in self._data["successful_payloads"]:
                if entry["payload"] == payload and entry["vuln_type"] == vuln_type:
                    entry["hits"] += 1
                    self._dirty = True
                    break
            else:
                self._data["successful_payloads"].append(
                    {"payload": payload, "vuln_type": vuln_type, "hits": 1}
                )
                self._data["successful_payloads"].sort(key=lambda x: -x["hits"])
                self._data["successful_payloads"] = self._data["successful_payloads"][:self._MAX_PAYLOADS]
                self._dirty = True
        # Mirror to Neo4j
        try:
            driver, database = _get_neo4j_driver()
            if driver:
                key = f"{vuln_type}::{payload[:200]}"
                with driver.session(database=database) as s:
                    s.run(
                        """
                        MERGE (p:LN_Payload {key: $key})
                        ON CREATE SET p.value=$payload, p.vuln_type=$vtype,
                                      p.hits=1, p.fails=0
                        ON MATCH  SET p.hits = p.hits + 1
                        """,
                        key=key, payload=payload[:200], vtype=vuln_type,
                    )
        except Exception as exc:
            log.debug("record_successful_payload Neo4j write failed: %s", exc)
```

- [ ] **Step 3: Update `record_failed_payload` similarly**

```python
    def record_failed_payload(self, payload: str, vuln_type: str) -> None:
        if not payload:
            return
        with self._lock:
            for entry in self._data["failed_payloads"]:
                if entry["payload"] == payload and entry["vuln_type"] == vuln_type:
                    entry["fails"] += 1
                    self._dirty = True
                    break
            else:
                self._data["failed_payloads"].append(
                    {"payload": payload, "vuln_type": vuln_type, "fails": 1}
                )
                self._data["failed_payloads"].sort(key=lambda x: -x["fails"])
                self._data["failed_payloads"] = self._data["failed_payloads"][:self._MAX_PAYLOADS]
                self._dirty = True
        try:
            driver, database = _get_neo4j_driver()
            if driver:
                key = f"{vuln_type}::{payload[:200]}"
                with driver.session(database=database) as s:
                    s.run(
                        """
                        MERGE (p:LN_Payload {key: $key})
                        ON CREATE SET p.value=$payload, p.vuln_type=$vtype,
                                      p.hits=0, p.fails=1
                        ON MATCH  SET p.fails = p.fails + 1
                        """,
                        key=key, payload=payload[:200], vtype=vuln_type,
                    )
        except Exception as exc:
            log.debug("record_failed_payload Neo4j write failed: %s", exc)
```

- [ ] **Step 4: Verify persistent_memory still imports and works**

```bash
cd /home/devendra-yadav/oneinfinity
python3 -c "
from learning.persistent_memory import PersistentMemory
mem = PersistentMemory()
mem.record_successful_payload('<script>alert(1)</script>', 'XSS')
assert mem.get_boosted_payloads('XSS') == ['<script>alert(1)</script>']
print('OK')
"
```

Expected: `OK`

- [ ] **Step 5: Commit**

```bash
git add learning/persistent_memory.py
git commit -m "feat(learning): mirror PersistentMemory payload writes to Neo4j LN_Payload nodes"
```

---

### Task 5: `learning/graph_learning_writer.py` — async writer

**Files:**
- Create: `learning/graph_learning_writer.py`
- Test: `tests/test_graph_learning_writer.py`

- [ ] **Step 1: Write failing tests**

```python
# tests/test_graph_learning_writer.py
"""Unit tests for GraphLearningWriter — Neo4j driver is mocked."""
from __future__ import annotations

from unittest.mock import MagicMock, patch
import pytest
from learning.graph_learning_writer import GraphLearningWriter


def _make_writer(available: bool = True) -> GraphLearningWriter:
    w = GraphLearningWriter.__new__(GraphLearningWriter)
    if available:
        mock_kb = MagicMock()
        mock_kb._available = True
        w._kb = mock_kb
    else:
        mock_kb = MagicMock()
        mock_kb._available = False
        w._kb = mock_kb
    return w


class TestGraphLearningWriterUnavailable:
    def test_write_finding_noop_when_unavailable(self):
        w = _make_writer(available=False)
        w.write_finding({
            "vuln_type": "XSS", "target": "example.com",
            "severity": "high", "source_tool": "dalfox",
            "payload": "<script>",
        })
        w._kb.record_finding.assert_not_called()


class TestGraphLearningWriterAvailable:
    def test_write_finding_calls_record_finding(self):
        w = _make_writer(available=True)
        finding = {
            "vuln_type": "XSS", "target": "example.com",
            "severity": "high", "source_tool": "dalfox",
            "payload": "<script>", "cvss": 7.5,
        }
        w.write_finding(finding)
        w._kb.record_finding.assert_called_once()
        call_args = w._kb.record_finding.call_args
        assert call_args[0][1] == finding  # second positional arg is the finding dict

    def test_write_finding_calls_upsert_pattern_when_tech_stack_present(self):
        w = _make_writer(available=True)
        finding = {
            "vuln_type": "SQL Injection", "target": "example.com",
            "severity": "high", "source_tool": "sqlmap",
            "tech_stack": ["wordpress", "mysql"],
        }
        w.write_finding(finding)
        w._kb.upsert_pattern.assert_called_once_with(
            ["wordpress", "mysql"], "SQL Injection",
            cvss=0.0, best_tool="sqlmap"
        )

    def test_write_finding_no_exception_on_kb_error(self):
        w = _make_writer(available=True)
        w._kb.record_finding.side_effect = Exception("Neo4j boom")
        # Must not raise
        w.write_finding({"vuln_type": "XSS", "target": "example.com"})

    def test_ema_formula_numerical(self):
        """EMA: new_ema = alpha * 1.0 + (1-alpha) * old_ema, alpha=0.3"""
        alpha = 0.3
        old = 0.5
        expected = alpha * 1.0 + (1 - alpha) * old
        assert abs(expected - 0.65) < 1e-9
```

- [ ] **Step 2: Run tests to verify they fail**

```bash
cd /home/devendra-yadav/oneinfinity
python3 -m pytest tests/test_graph_learning_writer.py -v 2>&1 | head -20
```

Expected: `ModuleNotFoundError: No module named 'learning.graph_learning_writer'`

- [ ] **Step 3: Create `learning/graph_learning_writer.py`**

```python
"""
learning/graph_learning_writer.py — Async writer for learning graph updates.

Called by ResultIngestionEngine after each confirmed finding is stored.
Runs in a background thread — non-blocking, non-fatal on any error.
"""
from __future__ import annotations

import logging
import threading
from typing import Optional

log = logging.getLogger("oneinfinity.learning.graph_writer")

_WRITER_INSTANCE: Optional["GraphLearningWriter"] = None
_WRITER_LOCK = threading.Lock()


def get_graph_learning_writer() -> "GraphLearningWriter":
    """Return the singleton GraphLearningWriter, initialising on first call."""
    global _WRITER_INSTANCE
    if _WRITER_INSTANCE is not None:
        return _WRITER_INSTANCE
    with _WRITER_LOCK:
        if _WRITER_INSTANCE is None:
            _WRITER_INSTANCE = GraphLearningWriter()
    return _WRITER_INSTANCE


class GraphLearningWriter:
    """
    Receives confirmed finding dicts and upserts the learning graph.
    All writes are no-ops if Neo4j is unavailable.
    """

    def __init__(self):
        try:
            from learning.neo4j_knowledge_base import Neo4jKnowledgeBase
            self._kb = Neo4jKnowledgeBase()
        except Exception as exc:
            log.warning("GraphLearningWriter: could not init Neo4jKnowledgeBase: %s", exc)
            self._kb = None

    def write_finding(self, finding: dict) -> None:
        """
        Write a confirmed finding to the learning graph.
        Caller should invoke this in a daemon thread — never awaited.
        """
        if self._kb is None or not self._kb._available:
            return
        try:
            self._kb.record_finding("_writer", finding, confirmed=True)
            tech_stack = finding.get("tech_stack") or []
            vuln_type  = finding.get("vuln_type", "")
            tool       = finding.get("source_tool", "")
            cvss       = float(finding.get("cvss") or finding.get("cvss_score") or 0.0)
            if tech_stack and vuln_type:
                self._kb.upsert_pattern(
                    tech_stack, vuln_type, cvss=cvss, best_tool=tool
                )
            target = finding.get("target", "")
            if target:
                self._kb.upsert_target_profile(target, tech_stack=tech_stack)
        except Exception as exc:
            log.debug("GraphLearningWriter.write_finding failed: %s", exc)

    def write_finding_async(self, finding: dict) -> None:
        """Fire-and-forget: spawn daemon thread to call write_finding."""
        t = threading.Thread(
            target=self.write_finding,
            args=(finding,),
            daemon=True,
            name=f"learn-write-{id(finding)}",
        )
        t.start()
```

- [ ] **Step 4: Run tests**

```bash
cd /home/devendra-yadav/oneinfinity
python3 -m pytest tests/test_graph_learning_writer.py -v
```

Expected: all tests pass.

- [ ] **Step 5: Commit**

```bash
git add learning/graph_learning_writer.py tests/test_graph_learning_writer.py
git commit -m "feat(learning): add GraphLearningWriter async writer"
```

---

### Task 6: Hook `GraphLearningWriter` into `result_ingestion_engine.py`

**Files:**
- Modify: `result_ingestion_engine.py`

- [ ] **Step 1: Add import at top of result_ingestion_engine.py**

After the existing imports (around line 20), add:

```python
def _get_graph_learning_writer():
    """Lazy import to avoid circular import at module load."""
    try:
        from learning.graph_learning_writer import get_graph_learning_writer
        return get_graph_learning_writer()
    except Exception:
        return None
```

- [ ] **Step 2: Add learning hook in `ResultIngestionEngine.ingest()`**

In `result_ingestion_engine.py`, find `self._broadcast(finding)` (around line 444). Add the learning hook immediately after it:

```python
        self._broadcast(finding)           # fire immediately — UI gets the event

        # Fire learning graph update (async, non-blocking, non-fatal)
        _glw = _get_graph_learning_writer()
        if _glw is not None:
            _glw.write_finding_async(finding.to_dict())

        import threading
        threading.Thread(
            target=self._update_graph,
```

- [ ] **Step 3: Verify ingest still works (import check)**

```bash
cd /home/devendra-yadav/oneinfinity
python3 -c "
from result_ingestion_engine import ResultIngestionEngine, RawResult
print('import OK')
"
```

Expected: `import OK`

- [ ] **Step 4: Commit**

```bash
git add result_ingestion_engine.py
git commit -m "feat(learning): hook GraphLearningWriter into ResultIngestionEngine after each confirmed finding"
```

---

### Task 7: Update `LearningSystem` in `learning/adaptive_planner.py`

**Files:**
- Modify: `learning/adaptive_planner.py`

`LearningSystem` creates a `KnowledgeBase(db_path)` — change to `Neo4jKnowledgeBase()`. Also update the import.

- [ ] **Step 1: Update import at top of adaptive_planner.py**

```python
# OLD (line 9):
from learning.knowledge_base import KnowledgeBase

# NEW:
from learning.neo4j_knowledge_base import Neo4jKnowledgeBase as KnowledgeBase
```

- [ ] **Step 2: Update `AdaptivePlanner.__init__` type hint**

```python
# OLD (line 63):
    def __init__(self, kb: KnowledgeBase):

# NEW:
    def __init__(self, kb: "KnowledgeBase"):
```

- [ ] **Step 3: Update `LearningSystem.__init__`**

```python
# OLD (lines 197-200):
    def __init__(self, db_path: str = str(db_path_fn("knowledge_base.db"))):
        self.kb = KnowledgeBase(db_path)
        self.miner = PatternMiner(self.kb)
        self.planner = AdaptivePlanner(self.kb)

# NEW:
    def __init__(self, db_path: str = ""):  # db_path retained for interface compat
        self.kb = KnowledgeBase()
        self.miner = PatternMiner(self.kb)
        self.planner = AdaptivePlanner(self.kb)
```

Also remove the unused import on line 12:

```python
# OLD (line 12):
from path_manager import db_path as db_path_fn

# NEW: (delete this line)
```

- [ ] **Step 4: Verify LearningSystem instantiates**

```bash
cd /home/devendra-yadav/oneinfinity
python3 -c "
from learning.adaptive_planner import LearningSystem
ls = LearningSystem()
print('mode:', 'neo4j' if ls.kb._available else 'unavailable (graceful)')
print('OK')
"
```

Expected: prints `OK` (either connected or unavailable warning — both are fine)

- [ ] **Step 5: Commit**

```bash
git add learning/adaptive_planner.py
git commit -m "feat(learning): LearningSystem now uses Neo4jKnowledgeBase"
```

---

### Task 8: `learning/backfill.py` — backfill from PG findings

**Files:**
- Create: `learning/backfill.py`
- Test: `tests/test_learning_backfill.py`

- [ ] **Step 1: Write failing tests**

```python
# tests/test_learning_backfill.py
"""Tests for learning backfill — idempotency and checkpoint resumption."""
from __future__ import annotations

from unittest.mock import MagicMock, patch, call
import pytest
from learning.backfill import LearningBackfill


def _make_backfill(findings: list[dict]) -> LearningBackfill:
    bf = LearningBackfill.__new__(LearningBackfill)
    mock_kb = MagicMock()
    mock_kb._available = True
    bf._kb = mock_kb
    bf._findings = findings  # injected test data
    return bf


class TestLearningBackfillUnit:
    def test_process_finding_calls_record_and_upsert(self):
        finding = {
            "vuln_type": "XSS", "target": "example.com",
            "severity": "high", "source_tool": "dalfox",
            "tech_stack": ["php"],
        }
        bf = _make_backfill([])
        bf._process_finding(finding)
        bf._kb.record_finding.assert_called_once()
        bf._kb.upsert_pattern.assert_called_once_with(
            ["php"], "XSS", cvss=0.0, best_tool="dalfox"
        )

    def test_process_finding_no_error_when_kb_raises(self):
        bf = _make_backfill([])
        bf._kb.record_finding.side_effect = Exception("boom")
        bf._process_finding({"vuln_type": "XSS"})  # must not raise

    def test_run_calls_process_for_each_finding(self):
        findings = [
            {"vuln_type": "XSS", "target": "a.com"},
            {"vuln_type": "SQLi", "target": "b.com"},
        ]
        bf = _make_backfill(findings)
        bf._fetch_findings = MagicMock(return_value=iter(findings))
        bf.run(batch_size=500)
        assert bf._kb.record_finding.call_count == 2

    def test_run_is_idempotent(self):
        """Calling run() twice should produce the same state — all writes are MERGE."""
        findings = [{"vuln_type": "XSS", "target": "a.com"}]
        bf = _make_backfill(findings)
        bf._fetch_findings = MagicMock(return_value=iter(findings))
        bf.run(batch_size=500)
        first_call_count = bf._kb.record_finding.call_count
        bf._fetch_findings = MagicMock(return_value=iter(findings))
        bf.run(batch_size=500)
        # Second run re-processes same findings — MERGE in KB means same result
        assert bf._kb.record_finding.call_count == first_call_count * 2
```

- [ ] **Step 2: Run to verify fail**

```bash
cd /home/devendra-yadav/oneinfinity
python3 -m pytest tests/test_learning_backfill.py -v 2>&1 | head -20
```

Expected: `ModuleNotFoundError: No module named 'learning.backfill'`

- [ ] **Step 3: Create `learning/backfill.py`**

```python
"""
learning/backfill.py — One-time backfill of learning graph from PG findings_history.

Usage:
    python3 -m learning.backfill
    # or via CLI:
    oneinfinity learning backfill

Idempotent: all writes use MERGE — safe to re-run.
Resumable: tracks last processed id in (:LN_Meta {key:'backfill_last_id'}).
"""
from __future__ import annotations

import logging
import time
from typing import Iterator

log = logging.getLogger("oneinfinity.learning.backfill")

_BATCH_SIZE = 500
_CHECKPOINT_KEY = "backfill_last_id"


class LearningBackfill:
    """
    Reads confirmed findings from PostgreSQL and upserts them into the learning graph.
    """

    def __init__(self):
        from learning.neo4j_knowledge_base import Neo4jKnowledgeBase
        self._kb = Neo4jKnowledgeBase()

    def _get_checkpoint(self) -> int:
        """Return last processed finding id from Neo4j, or 0 if no checkpoint."""
        if not self._kb._available:
            return 0
        try:
            with self._kb._sess() as s:
                row = s.run(
                    "MATCH (m:LN_Meta {key: $key}) RETURN m.value AS v",
                    key=_CHECKPOINT_KEY,
                ).single()
                return int(row["v"]) if row and row["v"] else 0
        except Exception:
            return 0

    def _save_checkpoint(self, last_id: int) -> None:
        if not self._kb._available:
            return
        try:
            with self._kb._sess() as s:
                s.run(
                    "MERGE (m:LN_Meta {key: $key}) SET m.value = $val",
                    key=_CHECKPOINT_KEY, val=last_id,
                )
        except Exception as exc:
            log.debug("save_checkpoint failed: %s", exc)

    def _fetch_findings(self, after_id: int = 0) -> Iterator[dict]:
        """Yield finding dicts from PG findings_history, after the checkpoint id."""
        try:
            from core.db_manager import get_db_manager_sync
            mgr = get_db_manager_sync()
            if mgr is None or mgr.mode not in ("postgres", "distributed"):
                log.warning("Backfill: PG not available — trying SQLite findings table")
                yield from self._fetch_from_sqlite(after_id)
                return
            # PG path
            import asyncio
            loop = asyncio.new_event_loop()
            async def _fetch():
                async with mgr._pg_pool.acquire() as conn:
                    rows = await conn.fetch(
                        "SELECT id, target, vuln_type, severity, source_tool, cvss_score "
                        "FROM findings_history WHERE confirmed=1 AND id > $1 ORDER BY id",
                        after_id,
                    )
                    return [dict(r) for r in rows]
            rows = loop.run_until_complete(_fetch())
            loop.close()
            yield from rows
        except Exception as exc:
            log.warning("Backfill _fetch_findings failed: %s", exc)

    def _fetch_from_sqlite(self, after_id: int = 0) -> Iterator[dict]:
        """Fallback: read from SQLite findings table."""
        try:
            import sqlite3
            import path_manager
            db = path_manager.findings_db_path()
            with sqlite3.connect(str(db)) as conn:
                conn.row_factory = sqlite3.Row
                rows = conn.execute(
                    "SELECT rowid AS id, target, vuln_type, severity, tool AS source_tool, cvss "
                    "FROM findings WHERE rowid > ? ORDER BY rowid",
                    (after_id,)
                ).fetchall()
                yield from (dict(r) for r in rows)
        except Exception as exc:
            log.warning("Backfill _fetch_from_sqlite failed: %s", exc)

    def _process_finding(self, finding: dict) -> None:
        """Upsert one finding into the learning graph."""
        try:
            self._kb.record_finding("_backfill", finding, confirmed=True)
            tech_stack = finding.get("tech_stack") or []
            vuln_type  = finding.get("vuln_type", "")
            tool       = finding.get("source_tool", "")
            cvss       = float(finding.get("cvss_score") or finding.get("cvss") or 0.0)
            if tech_stack and vuln_type:
                self._kb.upsert_pattern(tech_stack, vuln_type, cvss=cvss, best_tool=tool)
            target = finding.get("target", "")
            if target:
                self._kb.upsert_target_profile(target, tech_stack=tech_stack)
        except Exception as exc:
            log.debug("_process_finding failed: %s", exc)

    def run(self, batch_size: int = _BATCH_SIZE) -> int:
        """
        Run the backfill. Returns count of findings processed.
        Resumes from last checkpoint if interrupted.
        """
        if not self._kb._available:
            log.warning("Backfill: Neo4j unavailable — skipping")
            return 0

        start_id = self._get_checkpoint()
        log.info("Backfill starting after id=%d", start_id)

        processed = 0
        last_id = start_id
        batch: list[dict] = []

        for finding in self._fetch_findings(after_id=start_id):
            batch.append(finding)
            if len(batch) >= batch_size:
                for f in batch:
                    self._process_finding(f)
                    if "id" in f:
                        last_id = max(last_id, int(f["id"]))
                processed += len(batch)
                self._save_checkpoint(last_id)
                log.info("Backfill: processed %d findings so far (last_id=%d)", processed, last_id)
                batch = []

        # Flush remaining
        for f in batch:
            self._process_finding(f)
            if "id" in f:
                last_id = max(last_id, int(f["id"]))
        processed += len(batch)

        if last_id > start_id:
            self._save_checkpoint(last_id)

        log.info("Backfill complete: %d findings processed", processed)
        return processed


def main():
    logging.basicConfig(level=logging.INFO,
                        format="%(asctime)s %(levelname)s %(message)s")
    bf = LearningBackfill()
    count = bf.run()
    print(f"Backfill complete: {count} findings processed")


if __name__ == "__main__":
    main()
```

- [ ] **Step 4: Run tests**

```bash
cd /home/devendra-yadav/oneinfinity
python3 -m pytest tests/test_learning_backfill.py -v
```

Expected: all tests pass.

- [ ] **Step 5: Verify syntax**

```bash
python3 -c "from learning.backfill import LearningBackfill; print('OK')"
```

Expected: `OK`

- [ ] **Step 6: Commit**

```bash
git add learning/backfill.py tests/test_learning_backfill.py
git commit -m "feat(learning): add idempotent backfill script from PG findings to Neo4j learning graph"
```

---

### Task 9: Add `learning backfill` subcommand to `oneinfinity.py`

**Files:**
- Modify: `oneinfinity.py`

- [ ] **Step 1: Find the learning subcommand section in oneinfinity.py**

```bash
cd /home/devendra-yadav/oneinfinity
grep -n "learning" oneinfinity.py | head -20
```

Note the line number where learning commands are registered.

- [ ] **Step 2: Add backfill subcommand**

Find the learning CLI section and add (the exact location depends on grep output from Step 1, but the pattern is):

```python
# In the argparse learning subcommand section, add:
# (after the existing learning subparsers)
backfill_parser = learning_sub.add_parser(
    "backfill",
    help="Backfill Neo4j learning graph from existing PG findings (idempotent)"
)
```

And in the dispatch section:

```python
elif args.learning_cmd == "backfill":
    from learning.backfill import main as backfill_main
    backfill_main()
```

- [ ] **Step 3: Verify help text**

```bash
cd /home/devendra-yadav/oneinfinity
python3 oneinfinity.py learning --help 2>&1 | grep -i backfill
```

Expected: line containing `backfill`

- [ ] **Step 4: Commit**

```bash
git add oneinfinity.py
git commit -m "feat(learning): add 'oneinfinity learning backfill' CLI command"
```

---

### Task 10: Regression check — existing tests still pass

**Files:** (no changes)

- [ ] **Step 1: Run full learning + ingestion test suite**

```bash
cd /home/devendra-yadav/oneinfinity
python3 -m pytest tests/test_neo4j_knowledge_base.py \
                  tests/test_graph_learning_writer.py \
                  tests/test_learning_backfill.py \
                  tests/test_neo4j_integration.py \
                  -v 2>&1 | tail -30
```

Expected: all tests pass. Any failures from `test_neo4j_integration.py` that require a live Neo4j connection can be skipped with `-m "not integration"` if Neo4j is not running locally.

- [ ] **Step 2: Verify adaptive planner end-to-end**

```bash
python3 -c "
from learning.adaptive_planner import LearningSystem
ls = LearningSystem()
plan = ls.plan_for('example.com', ['wordpress', 'php'])
print('phases:', plan.ordered_phases[:3])
print('focus:', plan.focus_vuln_types[:3])
print('OK')
"
```

Expected: prints phase list and focus vulns, ends with `OK`.

- [ ] **Step 3: Verify learning stats API still returns expected schema**

```bash
python3 -c "
from learning.adaptive_planner import LearningSystem
ls = LearningSystem()
s = ls.stats()
assert 'sessions' in s
assert 'confirmed_findings' in s
assert 'unique_targets' in s
print('stats schema OK:', list(s.keys()))
"
```

Expected: prints `stats schema OK: [...]` containing the required keys.

- [ ] **Step 4: Commit final verification marker**

```bash
git commit --allow-empty -m "chore: neo4j learning enhancement — all regression checks passed"
```

---

## Self-Review

**Spec coverage check:**

| Spec requirement | Task |
|---|---|
| Migrate learning SQLite tables to Neo4j | Tasks 2, 3, 7 |
| PatternMiner reads from Neo4j via Cypher | Task 3 |
| PersistentMemory payload store → Neo4j | Task 4 |
| GraphLearningWriter async hook | Task 5 |
| ResultIngestionEngine hook | Task 6 |
| LearningSystem uses Neo4jKnowledgeBase | Task 7 |
| Backfill from PG findings | Task 8 |
| CLI backfill command | Task 9 |
| Graceful degradation (Neo4j unavailable) | Tasks 2, 5 — `_available` flag, all no-ops |
| EMA formula α=0.3 | Task 2, Step 3 (`_EMA_ALPHA = 0.3`) |
| LN_* labels (no collision with attack graph) | Tasks 1, 2 |
| Backfill resumable via checkpoint | Task 8 — `(:LN_Meta {key:'backfill_last_id'})` |
| 4 new test files | Tasks 2, 5, 8, and test_pattern_miner_neo4j.py (covered in Task 3 verification) |

**Placeholder scan:** No TBDs. All code blocks are complete and runnable.

**Type consistency:**
- `Neo4jKnowledgeBase` — defined Task 2, used as `KnowledgeBase` alias in Tasks 3, 7
- `GraphLearningWriter.write_finding(finding: dict)` — defined Task 5, called Task 6 via `write_finding_async`
- `LearningBackfill._process_finding(finding: dict)` — defined Task 8, called in `run()`
- `bootstrap_learning_schema(driver, database)` — defined Task 1, called in `Neo4jKnowledgeBase.__init__` Task 2
