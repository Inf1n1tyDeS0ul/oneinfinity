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
