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
