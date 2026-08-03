"""
src/oneinfinity/learning/knowledge_distiller.py
Phase 3 — Self-Improvement: Cross-Target Attack Graph Knowledge Distillation (Pillar 5.3)

After each completed scan, distill its attack graph and findings into the global
knowledge base so future scans of similar targets (same tech stack, same framework)
start with a prioritised attack plan based on what has historically been productive.

Integration: called from ReportMission Step 5 in god_mode_engine.py.

The learning loop:
  Scan 1 (React + JWT, IDOR found) → distill to KB
  Scan 2 (React + JWT target) → KB suggests IDOR as first priority
  Over time: later scans reach high-severity findings faster.
"""
from __future__ import annotations

import logging
import time
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional

log = logging.getLogger("oneinfinity.knowledge_distiller")


@dataclass
class DistillationResult:
    """Summary of one distillation run."""
    scan_id: str
    target: str
    patterns_written: int = 0
    tool_records_updated: int = 0
    tech_stack: List[str] = field(default_factory=list)
    top_vuln_types: List[str] = field(default_factory=list)
    elapsed_s: float = 0.0

    def to_dict(self) -> dict:
        return {
            "scan_id":              self.scan_id,
            "target":               self.target,
            "patterns_written":     self.patterns_written,
            "tool_records_updated": self.tool_records_updated,
            "tech_stack":           self.tech_stack,
            "top_vuln_types":       self.top_vuln_types,
            "elapsed_s":            round(self.elapsed_s, 2),
        }


class CrossTargetKnowledgeDistiller:
    """
    Distills completed scan knowledge into the global cross-target knowledge base.

    What it writes:
      1. Neo4j pattern_library: (tech_stack, vuln_type) → occurrence_count, avg_cvss, best_tool
         Enables future scans to prioritise vuln types that have historically
         been found on the same tech stack.

      2. Postgres tool_performance table: (tool_name, vuln_type, target_type) → success rates
         Enables model router to assign the best tool for each vuln type.

      3. Target profile: (domain) → tech_stack, historical_vulns
         Enables recognition of previously scanned targets.

    Usage:
        distiller = CrossTargetKnowledgeDistiller()
        result = distiller.distill(scan_id, target, findings, app_model_dict)
    """

    def distill(
        self,
        scan_id: str,
        target: str,
        findings: List[dict],
        app_model_dict: Optional[dict] = None,
        scan_duration_s: float = 0.0,
    ) -> DistillationResult:
        """
        Distill scan results into the global knowledge base.

        Args:
            scan_id:          completed scan ID
            target:           scan target URL
            findings:         all findings from the scan
            app_model_dict:   AppModel.to_dict() — tech stack, auth, endpoints
            scan_duration_s:  total scan duration (for tool_performance EMA)

        Returns:
            DistillationResult — summary of what was written.
        """
        t0 = time.monotonic()
        result = DistillationResult(scan_id=scan_id, target=target)

        if not findings:
            log.info("CrossTargetKnowledgeDistiller: no findings to distill for %s", scan_id)
            return result

        # Extract tech stack from app_model or findings
        tech_stack = self._extract_tech_stack(app_model_dict, findings)
        result.tech_stack = tech_stack

        # Aggregate findings by vuln_type
        vuln_stats = self._aggregate_vuln_stats(findings)
        result.top_vuln_types = [
            vt for vt, _ in sorted(
                vuln_stats.items(),
                key=lambda x: x[1]["count"],
                reverse=True,
            )[:10]
        ]

        # Write to Neo4j knowledge base
        result.patterns_written = self._write_to_neo4j(tech_stack, vuln_stats, target)

        # Update tool_performance in postgres
        result.tool_records_updated = self._update_tool_performance(
            vuln_stats, tech_stack, scan_duration_s
        )

        # Update target profile
        self._update_target_profile(target, tech_stack, vuln_stats)

        result.elapsed_s = time.monotonic() - t0
        log.info(
            "CrossTargetKnowledgeDistiller: %s — %d patterns, %d tool records, %.1fs",
            scan_id, result.patterns_written, result.tool_records_updated, result.elapsed_s,
        )
        return result

    def get_scan_priorities(
        self,
        target: str,
        tech_stack: List[str],
        top_n: int = 10,
    ) -> List[dict]:
        """
        Query the knowledge base for the most productive attack patterns
        for a given tech stack.

        Returns a ranked list of {vuln_type, avg_cvss, occurrence_count, best_tool}
        to guide scan phase prioritisation.
        """
        try:
            from oneinfinity.learning.neo4j_knowledge_base import Neo4jKnowledgeBase
            kb = Neo4jKnowledgeBase()
            if hasattr(kb, "patterns_for_tech_stack") and tech_stack:
                patterns = kb.patterns_for_tech_stack(tech_stack)
                return sorted(
                    patterns[:top_n],
                    key=lambda p: (
                        float(p.get("avg_cvss") or 0) * float(p.get("occurrence_count") or 0)
                    ),
                    reverse=True,
                )
        except Exception as exc:
            log.debug("CrossTargetKnowledgeDistiller.get_scan_priorities failed: %s", exc)
        return []

    # ── Internal ─────────────────────────────────────────────────────────────

    @staticmethod
    def _extract_tech_stack(app_model: Optional[dict], findings: List[dict]) -> List[str]:
        """Extract tech stack from AppModel or fall back to finding metadata."""
        if app_model:
            tech = list(app_model.get("tech_stack") or [])
            frameworks = list(app_model.get("frameworks") or [])
            combined = list(dict.fromkeys(tech + frameworks))  # deduplicated, ordered
            if combined:
                return combined[:10]
        # Fall back to finding source_tool hints
        tools = list({f.get("tool", "") for f in findings if f.get("tool")})
        return tools[:5]

    @staticmethod
    def _aggregate_vuln_stats(findings: List[dict]) -> Dict[str, dict]:
        """Aggregate findings into per-vuln-type stats."""
        stats: Dict[str, dict] = {}
        for f in findings:
            vt = str(f.get("vuln_type") or f.get("type") or "").lower().strip()
            if not vt:
                continue
            if vt not in stats:
                stats[vt] = {
                    "count":     0,
                    "cvss_sum":  0.0,
                    "tools":     set(),
                    "confirmed": 0,
                }
            stats[vt]["count"] += 1
            stats[vt]["cvss_sum"] += float(f.get("cvss") or 0)
            tool = f.get("tool") or ""
            if tool:
                stats[vt]["tools"].add(tool)
            if f.get("confirmed_tier") == "CONFIRMED":
                stats[vt]["confirmed"] += 1
        # Compute averages
        for vt, s in stats.items():
            s["avg_cvss"]  = round(s["cvss_sum"] / max(s["count"], 1), 2)
            s["best_tool"] = max(s["tools"], default="")
            del s["cvss_sum"]
            s["tools"] = list(s["tools"])
        return stats

    def _write_to_neo4j(
        self,
        tech_stack: List[str],
        vuln_stats: Dict[str, dict],
        target: str,
    ) -> int:
        """Write vuln patterns to Neo4j pattern_library. Returns count written."""
        if not tech_stack:
            return 0
        written = 0
        try:
            from oneinfinity.learning.neo4j_knowledge_base import Neo4jKnowledgeBase
            kb = Neo4jKnowledgeBase()
            if not hasattr(kb, "upsert_pattern"):
                return 0
            for vt, stats in vuln_stats.items():
                try:
                    kb.upsert_pattern(
                        tech_stack=tech_stack,
                        vuln_type=vt,
                        cvss=stats["avg_cvss"],
                        best_tool=stats["best_tool"],
                    )
                    written += 1
                except Exception as exc:
                    log.debug("KB upsert_pattern failed [%s]: %s", vt, exc)
        except Exception as exc:
            log.debug("_write_to_neo4j failed: %s", exc)
        return written

    def _update_tool_performance(
        self,
        vuln_stats: Dict[str, dict],
        tech_stack: List[str],
        duration_s: float,
    ) -> int:
        """Update tool_performance table in postgres. Returns rows updated."""
        updated = 0
        target_type = "web"  # default; could be refined from tech stack
        if any("mobile" in t.lower() or "android" in t.lower() or "ios" in t.lower()
               for t in tech_stack):
            target_type = "mobile"
        elif any("api" in t.lower() or "graphql" in t.lower() for t in tech_stack):
            target_type = "api"

        try:
            from oneinfinity.core.db_manager import get_db_manager_sync
            db = get_db_manager_sync()
            if db is None or db.mode not in ("distributed", "postgres"):
                return 0

            per_vuln_duration = duration_s / max(len(vuln_stats), 1)

            for vt, stats in vuln_stats.items():
                tool = stats["best_tool"] or "god_mode"
                try:
                    db.sync_pg_execute_write(
                        """
                        INSERT INTO tool_performance
                            (tool_name, vuln_type, target_type, runs_total, runs_success,
                             findings_total, avg_duration_s, last_updated)
                        VALUES (%s, %s, %s, 1, %s, %s, %s, %s)
                        ON CONFLICT (tool_name, vuln_type, target_type) DO UPDATE SET
                            runs_total     = tool_performance.runs_total + 1,
                            runs_success   = tool_performance.runs_success + EXCLUDED.runs_success,
                            findings_total = tool_performance.findings_total + EXCLUDED.findings_total,
                            avg_duration_s = CASE
                                WHEN EXCLUDED.avg_duration_s > 0
                                THEN (tool_performance.avg_duration_s * tool_performance.runs_total
                                      + EXCLUDED.avg_duration_s) / (tool_performance.runs_total + 1)
                                ELSE tool_performance.avg_duration_s
                            END,
                            last_updated   = EXCLUDED.last_updated
                        """,
                        (
                            tool, vt, target_type,
                            1 if stats["count"] > 0 else 0,
                            stats["count"],
                            round(per_vuln_duration, 2),
                            time.time(),
                        ),
                    )
                    updated += 1
                except Exception as exc:
                    log.debug("tool_performance upsert failed [%s/%s]: %s", tool, vt, exc)
        except Exception as exc:
            log.debug("_update_tool_performance failed: %s", exc)
        return updated

    def _update_target_profile(
        self,
        target: str,
        tech_stack: List[str],
        vuln_stats: Dict[str, dict],
    ) -> None:
        """Update Neo4j target profile with fresh tech stack and vuln history."""
        try:
            from urllib.parse import urlparse
            domain = urlparse(target).netloc or target
            from oneinfinity.learning.neo4j_knowledge_base import Neo4jKnowledgeBase
            kb = Neo4jKnowledgeBase()
            if hasattr(kb, "upsert_target_profile"):
                historical = {vt: s["count"] for vt, s in vuln_stats.items()}
                kb.upsert_target_profile(domain, tech_stack=tech_stack,
                                         historical_vulns=historical)
        except Exception as exc:
            log.debug("_update_target_profile failed: %s", exc)


# ── Module-level API ──────────────────────────────────────────────────────────

_distiller: Optional[CrossTargetKnowledgeDistiller] = None


def get_distiller() -> CrossTargetKnowledgeDistiller:
    """Return the module-level CrossTargetKnowledgeDistiller singleton."""
    global _distiller
    if _distiller is None:
        _distiller = CrossTargetKnowledgeDistiller()
    return _distiller
