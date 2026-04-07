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
