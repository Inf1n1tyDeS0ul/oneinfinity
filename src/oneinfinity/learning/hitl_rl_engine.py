"""
hitl_rl_engine.py — Human-in-Loop Reinforcement Learning Engine

When a researcher marks a finding as True Positive or False Positive in the UI,
that signal flows here to:
1. Update ValidationAgent confidence thresholds per vuln type
2. Store the feedback pattern in SQLite for future reference
3. Build few-shot example libraries for LLM validation prompts
4. Track FP rate per vuln type and endpoint pattern
5. Tighten or loosen validation thresholds based on accumulated evidence

This is the highest-leverage self-improvement mechanism in God Mode:
researchers are already triaging findings — this captures their expertise.

Council Sprint 3 — NEW capability.
"""
from __future__ import annotations

import hashlib
import json
import logging
import sqlite3
import threading
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional

import oneinfinity.infra.path_manager as _path_manager

log = logging.getLogger("oneinfinity.learning.hitl_rl")

_DB_PATH = _path_manager.db_path("hitl_feedback")


# ---------------------------------------------------------------------------
# Schema
# ---------------------------------------------------------------------------

_SCHEMA = """
CREATE TABLE IF NOT EXISTS hitl_feedback (
    id              TEXT PRIMARY KEY,
    finding_id      TEXT NOT NULL,
    vuln_type       TEXT NOT NULL,
    endpoint_pattern TEXT NOT NULL,
    payload_hash    TEXT NOT NULL,
    is_tp           INTEGER NOT NULL,   -- 1 = true positive, 0 = false positive
    notes           TEXT DEFAULT '',
    confidence      REAL DEFAULT 0.5,
    timestamp       REAL NOT NULL,
    severity        TEXT DEFAULT 'medium'
);

CREATE INDEX IF NOT EXISTS idx_hitl_vuln_type ON hitl_feedback(vuln_type);
CREATE INDEX IF NOT EXISTS idx_hitl_endpoint ON hitl_feedback(endpoint_pattern);

CREATE TABLE IF NOT EXISTS vuln_type_stats (
    vuln_type   TEXT PRIMARY KEY,
    tp_count    INTEGER DEFAULT 0,
    fp_count    INTEGER DEFAULT 0,
    threshold   REAL DEFAULT 0.7,   -- minimum confidence to confirm
    updated_at  REAL NOT NULL
);
"""


# ---------------------------------------------------------------------------
# Data classes
# ---------------------------------------------------------------------------

@dataclass
class FeedbackRecord:
    finding_id: str
    vuln_type: str
    endpoint_pattern: str
    payload_hash: str
    is_tp: bool
    notes: str = ""
    confidence: float = 0.5
    severity: str = "medium"


# ---------------------------------------------------------------------------
# Engine
# ---------------------------------------------------------------------------

class HITLRLEngine:
    """
    Human-in-Loop Reinforcement Learning Engine.

    Captures researcher TP/FP feedback and uses it to:
    - Build few-shot examples for LLM validation
    - Adjust per-vuln-type confidence thresholds
    - Provide negative learning signals (what NOT to flag)
    """

    _singleton: Optional["HITLRLEngine"] = None
    _singleton_lock = threading.Lock()

    def __init__(self, db_path: Path | str = _DB_PATH) -> None:
        self._db_path = Path(db_path)
        self._db_path.parent.mkdir(parents=True, exist_ok=True)
        self._lock = threading.Lock()
        self._init_db()

    @classmethod
    def get_singleton(cls) -> "HITLRLEngine":
        if cls._singleton is None:
            with cls._singleton_lock:
                if cls._singleton is None:
                    cls._singleton = cls()
        return cls._singleton

    # ── DB init ───────────────────────────────────────────────────────────────

    def _init_db(self) -> None:
        try:
            with self._connect() as conn:
                conn.executescript(_SCHEMA)
        except Exception as exc:
            log.warning("[HITL] DB init failed: %s", exc)

    def _connect(self) -> sqlite3.Connection:
        conn = sqlite3.connect(str(self._db_path), timeout=10)
        conn.row_factory = sqlite3.Row
        return conn

    # ── Core feedback recording ───────────────────────────────────────────────

    def record_feedback(
        self,
        finding: dict,
        is_true_positive: bool,
        researcher_notes: str = "",
    ) -> None:
        """
        Record researcher TP/FP verdict for a finding.
        Triggers threshold recalibration and KB update.
        """
        try:
            vuln_type = finding.get("vuln_type", finding.get("type", "unknown")).lower()
            url = finding.get("url", "")
            payload = finding.get("payload", "")
            severity = finding.get("severity", "medium")
            confidence = float(finding.get("confidence", 0.5))
            finding_id = finding.get("id", finding.get("finding_id", "unknown"))

            # Normalize endpoint to a pattern
            endpoint_pattern = self._normalize_endpoint(url)
            payload_hash = hashlib.sha256(payload.encode()).hexdigest()[:16]

            rec_id = hashlib.sha256(f"{finding_id}:{time.time()}".encode()).hexdigest()[:16]

            with self._lock, self._connect() as conn:
                conn.execute(
                    "INSERT OR REPLACE INTO hitl_feedback "
                    "(id, finding_id, vuln_type, endpoint_pattern, payload_hash, is_tp, notes, confidence, timestamp, severity) "
                    "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                    (rec_id, finding_id, vuln_type, endpoint_pattern, payload_hash,
                     1 if is_true_positive else 0, researcher_notes, confidence,
                     time.time(), severity),
                )
                conn.commit()

            log.info(
                "[HITL] Feedback recorded — finding=%s vuln=%s is_tp=%s",
                finding_id, vuln_type, is_true_positive,
            )

            # Recalibrate threshold for this vuln type
            self._update_validation_thresholds(vuln_type)

            # Push to Neo4j KB
            self._store_in_kb(finding, is_true_positive, researcher_notes)

        except Exception as exc:
            log.warning("[HITL] record_feedback failed: %s", exc)

    # ── Threshold management ──────────────────────────────────────────────────

    def _update_validation_thresholds(self, vuln_type: str) -> None:
        """
        Recalculate the confidence threshold for a vuln type based on FP rate.
        - FP rate > 50%: raise threshold to 0.9 (be very conservative)
        - FP rate 30-50%: raise threshold to 0.8
        - FP rate 10-30%: keep default 0.7
        - FP rate < 10%: lower threshold to 0.6 (more aggressive)
        """
        try:
            fp_rate = self.get_fp_rate(vuln_type)
            if fp_rate > 0.5:
                threshold = 0.9
            elif fp_rate > 0.3:
                threshold = 0.8
            elif fp_rate > 0.1:
                threshold = 0.7
            else:
                threshold = 0.6

            tp_count, fp_count = self._get_counts(vuln_type)

            with self._lock, self._connect() as conn:
                conn.execute(
                    "INSERT OR REPLACE INTO vuln_type_stats (vuln_type, tp_count, fp_count, threshold, updated_at) "
                    "VALUES (?, ?, ?, ?, ?)",
                    (vuln_type, tp_count, fp_count, threshold, time.time()),
                )
                conn.commit()

            log.info(
                "[HITL] Threshold updated — vuln=%s fp_rate=%.1f%% threshold=%.2f tp=%d fp=%d",
                vuln_type, fp_rate * 100, threshold, tp_count, fp_count,
            )
        except Exception as exc:
            log.debug("[HITL] Threshold update failed: %s", exc)

    def get_validation_threshold(self, vuln_type: str) -> float:
        """Get the current validation confidence threshold for a vuln type."""
        try:
            with self._connect() as conn:
                row = conn.execute(
                    "SELECT threshold FROM vuln_type_stats WHERE vuln_type = ?",
                    (vuln_type,),
                ).fetchone()
                if row:
                    return float(row["threshold"])
        except Exception:
            pass
        return 0.7  # default

    def get_fp_rate(self, vuln_type: str) -> float:
        """Return FP rate for a vuln type (0.0 = no FPs, 1.0 = all FPs)."""
        tp, fp = self._get_counts(vuln_type)
        total = tp + fp
        return fp / total if total > 0 else 0.0

    def _get_counts(self, vuln_type: str) -> tuple[int, int]:
        try:
            with self._connect() as conn:
                row = conn.execute(
                    "SELECT "
                    "  SUM(CASE WHEN is_tp = 1 THEN 1 ELSE 0 END) as tp, "
                    "  SUM(CASE WHEN is_tp = 0 THEN 1 ELSE 0 END) as fp "
                    "FROM hitl_feedback WHERE vuln_type = ?",
                    (vuln_type,),
                ).fetchone()
                if row:
                    return (int(row["tp"] or 0), int(row["fp"] or 0))
        except Exception:
            pass
        return 0, 0

    # ── Few-shot examples for LLM ─────────────────────────────────────────────

    def get_few_shot_examples(
        self,
        vuln_type: str,
        is_tp: bool,
        limit: int = 5,
    ) -> list[dict]:
        """
        Return recent confirmed TP or FP examples for a vuln type.
        These are used to build few-shot prompts for LLM validation.
        """
        try:
            with self._connect() as conn:
                rows = conn.execute(
                    "SELECT finding_id, endpoint_pattern, payload_hash, notes, confidence "
                    "FROM hitl_feedback "
                    "WHERE vuln_type = ? AND is_tp = ? "
                    "ORDER BY timestamp DESC LIMIT ?",
                    (vuln_type, 1 if is_tp else 0, limit),
                ).fetchall()
                return [dict(r) for r in rows]
        except Exception as exc:
            log.debug("[HITL] Few-shot fetch failed: %s", exc)
            return []

    def build_few_shot_prompt_section(self, vuln_type: str) -> str:
        """
        Build a few-shot example section for LLM validation prompts.
        Returns a formatted string describing known TP/FP patterns.
        """
        tp_examples = self.get_few_shot_examples(vuln_type, is_tp=True, limit=3)
        fp_examples = self.get_few_shot_examples(vuln_type, is_tp=False, limit=3)

        if not tp_examples and not fp_examples:
            return ""

        lines = [f"\nLearned patterns for {vuln_type} from researcher feedback:"]
        if tp_examples:
            lines.append("Known TRUE POSITIVES (confirmed real vulnerabilities):")
            for ex in tp_examples:
                lines.append(f"  - Endpoint pattern: {ex['endpoint_pattern']} | Notes: {ex.get('notes', '') or 'confirmed'}")
        if fp_examples:
            lines.append("Known FALSE POSITIVES (confirmed noise):")
            for ex in fp_examples:
                lines.append(f"  - Endpoint pattern: {ex['endpoint_pattern']} | Notes: {ex.get('notes', '') or 'false alarm'}")

        return "\n".join(lines)

    # ── Neo4j KB integration ──────────────────────────────────────────────────

    def _store_in_kb(self, finding: dict, is_tp: bool, notes: str) -> None:
        """Push HITL feedback to Neo4j knowledge base."""
        try:
            from oneinfinity.learning.neo4j_knowledge_base import Neo4jKnowledgeBase
            kb = Neo4jKnowledgeBase()
            pattern = {
                "vuln_type": finding.get("vuln_type", "unknown"),
                "endpoint": finding.get("url", ""),
                "is_true_positive": is_tp,
                "source": "hitl_feedback",
                "notes": notes,
            }
            if hasattr(kb, "store_pattern"):
                kb.store_pattern(pattern)
            elif hasattr(kb, "record_outcome"):
                kb.record_outcome(finding.get("vuln_type", "unknown"), is_tp)
        except Exception as exc:
            log.debug("[HITL] Neo4j KB store failed: %s", exc)

    # ── Stats ─────────────────────────────────────────────────────────────────

    def get_stats(self) -> dict:
        """Return aggregated HITL feedback statistics."""
        try:
            with self._connect() as conn:
                rows = conn.execute(
                    "SELECT vuln_type, tp_count, fp_count, threshold FROM vuln_type_stats"
                ).fetchall()
                total_row = conn.execute(
                    "SELECT COUNT(*) as total, "
                    "SUM(CASE WHEN is_tp=1 THEN 1 ELSE 0 END) as tp, "
                    "SUM(CASE WHEN is_tp=0 THEN 1 ELSE 0 END) as fp "
                    "FROM hitl_feedback"
                ).fetchone()

                return {
                    "total_feedback": int(total_row["total"] or 0),
                    "total_tp": int(total_row["tp"] or 0),
                    "total_fp": int(total_row["fp"] or 0),
                    "per_vuln_type": [
                        {
                            "vuln_type": r["vuln_type"],
                            "tp": r["tp_count"],
                            "fp": r["fp_count"],
                            "threshold": r["threshold"],
                            "fp_rate": r["fp_count"] / max(r["tp_count"] + r["fp_count"], 1),
                        }
                        for r in rows
                    ],
                }
        except Exception as exc:
            log.debug("[HITL] Stats failed: %s", exc)
            return {}

    # ── Utility ───────────────────────────────────────────────────────────────

    def _normalize_endpoint(self, url: str) -> str:
        """Normalize URL to a pattern by replacing IDs with placeholders."""
        import re
        try:
            # Remove scheme and host
            import urllib.parse
            parsed = urllib.parse.urlparse(url)
            path = parsed.path or "/"
            # Replace numeric IDs
            path = re.sub(r"/\d+", "/{id}", path)
            # Replace UUIDs
            path = re.sub(
                r"/[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}",
                "/{uuid}", path, flags=re.I,
            )
            return path
        except Exception:
            return url


# ---------------------------------------------------------------------------
# Module-level singleton accessor
# ---------------------------------------------------------------------------

def get_hitl_engine() -> HITLRLEngine:
    return HITLRLEngine.get_singleton()
