"""
learning/persistent_memory.py — Cross-Run Persistent Intelligence Store

Maintains a lightweight JSON-backed memory that survives individual scan runs.
Complements KnowledgeBase (session/tool/pattern level) with payload-level
intelligence: what worked, what failed, what was missed.

Storage layout  (under raw_dir() / "memory"):
    persistent_memory.json   — main payload + pattern store
    run_history.json         — summary of past runs (ring-buffer, 100 entries)

Usage::
    from oneinfinity.learning.persistent_memory import get_memory

    mem = get_memory()
    ctx["persistent_memory"] = mem.to_ctx()   # inject at scan start

    # … after scan …
    mem.update_from_ctx(ctx)
    mem.save()
"""
from __future__ import annotations

import json
import logging
import os
import threading
import time
from copy import deepcopy
from pathlib import Path
from typing import Dict, List, Optional

log = logging.getLogger("oneinfinity.learning.persistent_memory")

# ---------------------------------------------------------------------------
# Storage paths
# ---------------------------------------------------------------------------

def _memory_dir() -> Path:
    try:
        from oneinfinity.infra.path_manager import raw_dir
        d = raw_dir() / "memory"
    except ImportError:
        d = Path(os.environ.get("ONEINFINITY_DATA", "/tmp/oneinfinity")) / "memory"
    d.mkdir(parents=True, exist_ok=True)
    return d


_MEMORY_FILE    = None   # lazily resolved
_HISTORY_FILE   = None
_HISTORY_LIMIT  = 100    # keep last N run summaries


def _get_neo4j_driver():
    """Return (driver, database) or (None, 'neo4j') if unavailable.
    Reads from the Neo4jKnowledgeBase singleton if already initialised."""
    try:
        from oneinfinity.learning.neo4j_knowledge_base import _load_neo4j_config
        from neo4j import GraphDatabase
        cfg = _load_neo4j_config()
        driver = GraphDatabase.driver(
            cfg.get("uri", "bolt://localhost:7687"),
            auth=(cfg.get("user", "neo4j"), cfg.get("password", "neo4j123")),
        )
        driver.verify_connectivity()
        return driver, cfg.get("database", "neo4j")
    except Exception:
        return None, "neo4j"


def _mem_path() -> Path:
    global _MEMORY_FILE
    if _MEMORY_FILE is None:
        _MEMORY_FILE = _memory_dir() / "persistent_memory.json"
    return _MEMORY_FILE


def _hist_path() -> Path:
    global _HISTORY_FILE
    if _HISTORY_FILE is None:
        _HISTORY_FILE = _memory_dir() / "run_history.json"
    return _HISTORY_FILE


# ---------------------------------------------------------------------------
# Default schema
# ---------------------------------------------------------------------------

def _empty_memory() -> dict:
    return {
        "version":             1,
        "successful_payloads": [],   # {"payload": str, "vuln_type": str, "hits": int}
        "failed_payloads":     [],   # {"payload": str, "vuln_type": str, "fails": int}
        "vulnerable_patterns": [],   # {"pattern": str, "vuln_type": str, "count": int}
        "high_value_targets":  [],   # {"host": str, "severity": str, "last_seen": float}
        "missed_vuln_types":   [],   # {"vuln_type": str, "count": int}
        "missed_patterns":     [],   # {"pattern": str, "reference_tool": str, "count": int}
        "successful_chains":   [],   # {"chain": [str], "impact": str, "count": int}
        "program_intel":       {},   # {host: {"category": str, "roi_score": float}}
        "stats": {
            "total_runs":         0,
            "total_findings":     0,
            "total_confirmed":    0,
            "last_run_ts":        0.0,
        },
    }


# ---------------------------------------------------------------------------
# Core class
# ---------------------------------------------------------------------------

class PersistentMemory:
    """
    Thread-safe cross-run intelligence store.

    External code should not mutate the internal dict directly; use the
    provided helper methods so deduplication and capping are applied.
    """

    # Hard caps to prevent unbounded growth
    _MAX_PAYLOADS  = 500
    _MAX_PATTERNS  = 200
    _MAX_TARGETS   = 200
    _MAX_MISSED    = 200
    _MAX_CHAINS    = 100

    def __init__(self) -> None:
        self._lock   = threading.Lock()
        self._data   = _empty_memory()
        self._dirty  = False

    # ── Persistence ──────────────────────────────────────────────────────────

    def load(self) -> "PersistentMemory":
        """Load from disk. Safe to call even if file doesn't exist yet."""
        p = _mem_path()
        if p.exists():
            try:
                raw = json.loads(p.read_text(encoding="utf-8"))
                with self._lock:
                    # Merge: keep keys from schema that may be missing in old files
                    base = _empty_memory()
                    base.update(raw)
                    # Merge nested stats
                    base["stats"] = {**_empty_memory()["stats"], **raw.get("stats", {})}
                    self._data = base
                log.info("[memory] Loaded: %d successful payloads, %d patterns",
                         len(self._data["successful_payloads"]),
                         len(self._data["vulnerable_patterns"]))
            except Exception as exc:
                log.warning("[memory] Load failed (%s) — starting fresh", exc)
        else:
            log.info("[memory] No existing memory — starting fresh")
        return self

    def save(self) -> None:
        """Persist to disk atomically."""
        p = _mem_path()
        tmp = p.with_suffix(".tmp")
        try:
            with self._lock:
                payload = json.dumps(self._data, indent=2, ensure_ascii=False)
            tmp.write_text(payload, encoding="utf-8")
            tmp.replace(p)
            self._dirty = False
            log.info("[memory] Saved to %s", p)
        except Exception as exc:
            log.error("[memory] Save failed: %s", exc)

    # ── Payload intelligence ──────────────────────────────────────────────────

    def record_successful_payload(self, payload: str, vuln_type: str) -> None:
        if not payload:
            return
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
                # Sort by hits desc, cap
                self._data["successful_payloads"].sort(key=lambda x: -x["hits"])
                self._data["successful_payloads"] = self._data["successful_payloads"][:self._MAX_PAYLOADS]
                self._dirty = True
        # Mirror to Neo4j (non-fatal)
        try:
            driver, database = _get_neo4j_driver()
            if driver:
                key = f"{vuln_type}::{payload[:200]}"
                with driver.session(database=database) as s:
                    s.run(
                        "MERGE (p:LN_Payload {key: $key}) "
                        "ON CREATE SET p.value=$payload, p.vuln_type=$vtype, p.hits=1, p.fails=0 "
                        "ON MATCH  SET p.hits = p.hits + 1",
                        key=key, payload=payload[:200], vtype=vuln_type,
                    )
                driver.close()
        except Exception as exc:
            log.debug("record_successful_payload Neo4j mirror failed: %s", exc)

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
        # Mirror to Neo4j (non-fatal)
        try:
            driver, database = _get_neo4j_driver()
            if driver:
                key = f"{vuln_type}::{payload[:200]}"
                with driver.session(database=database) as s:
                    s.run(
                        "MERGE (p:LN_Payload {key: $key}) "
                        "ON CREATE SET p.value=$payload, p.vuln_type=$vtype, p.hits=0, p.fails=1 "
                        "ON MATCH  SET p.fails = p.fails + 1",
                        key=key, payload=payload[:200], vtype=vuln_type,
                    )
                driver.close()
        except Exception as exc:
            log.debug("record_failed_payload Neo4j mirror failed: %s", exc)

    def get_payload_boost(self, payload: str) -> float:
        """
        Return a score boost [0.0, 1.0] for a payload based on past success.
        Returns negative value if payload is known to consistently fail.
        """
        with self._lock:
            for entry in self._data["successful_payloads"]:
                if entry["payload"] == payload:
                    return min(1.0, entry["hits"] * 0.1)
            for entry in self._data["failed_payloads"]:
                if entry["payload"] == payload:
                    return -min(1.0, entry["fails"] * 0.1)
        return 0.0

    def get_boosted_payloads(self, vuln_type: str, top_n: int = 10) -> List[str]:
        """Return top-N known-good payloads for a vuln type."""
        with self._lock:
            matches = [
                e for e in self._data["successful_payloads"]
                if e["vuln_type"].lower() == vuln_type.lower()
            ]
        matches.sort(key=lambda x: -x["hits"])
        return [e["payload"] for e in matches[:top_n]]

    def get_failed_payloads(self, vuln_type: str = "") -> List[str]:
        """Return payloads that have consistently failed (to skip)."""
        with self._lock:
            pool = self._data["failed_payloads"]
            if vuln_type:
                pool = [e for e in pool if e["vuln_type"].lower() == vuln_type.lower()]
            # Only filter out payloads that have failed 3+ times
            return [e["payload"] for e in pool if e["fails"] >= 3]

    # ── Target intelligence ───────────────────────────────────────────────────

    def record_high_value_target(self, host: str, severity: str) -> None:
        with self._lock:
            for entry in self._data["high_value_targets"]:
                if entry["host"] == host:
                    # upgrade severity if higher
                    _sev_order = ["info", "low", "medium", "high", "critical"]
                    old_idx = _sev_order.index(entry.get("severity", "info"))
                    new_idx = _sev_order.index(severity) if severity in _sev_order else 0
                    if new_idx > old_idx:
                        entry["severity"] = severity
                    entry["last_seen"] = time.time()
                    self._dirty = True
                    return
            self._data["high_value_targets"].append(
                {"host": host, "severity": severity, "last_seen": time.time()}
            )
            self._data["high_value_targets"] = self._data["high_value_targets"][:self._MAX_TARGETS]
            self._dirty = True

    def is_high_value(self, host: str) -> bool:
        with self._lock:
            return any(e["host"] == host for e in self._data["high_value_targets"])

    def high_value_hosts(self) -> List[str]:
        with self._lock:
            return [e["host"] for e in self._data["high_value_targets"]]

    # ── Pattern intelligence ──────────────────────────────────────────────────

    def record_vulnerable_pattern(self, pattern: str, vuln_type: str) -> None:
        if not pattern:
            return
        with self._lock:
            for entry in self._data["vulnerable_patterns"]:
                if entry["pattern"] == pattern and entry["vuln_type"] == vuln_type:
                    entry["count"] += 1
                    self._dirty = True
                    return
            self._data["vulnerable_patterns"].append(
                {"pattern": pattern, "vuln_type": vuln_type, "count": 1}
            )
            self._data["vulnerable_patterns"].sort(key=lambda x: -x["count"])
            self._data["vulnerable_patterns"] = self._data["vulnerable_patterns"][:self._MAX_PATTERNS]
            self._dirty = True

    def record_missed_pattern(self, pattern: str, reference_tool: str = "") -> None:
        if not pattern:
            return
        with self._lock:
            for entry in self._data["missed_patterns"]:
                if entry["pattern"] == pattern:
                    entry["count"] += 1
                    self._dirty = True
                    return
            self._data["missed_patterns"].append(
                {"pattern": pattern, "reference_tool": reference_tool, "count": 1}
            )
            self._data["missed_patterns"].sort(key=lambda x: -x["count"])
            self._data["missed_patterns"] = self._data["missed_patterns"][:self._MAX_MISSED]
            self._dirty = True

    def record_missed_vuln_type(self, vuln_type: str) -> None:
        with self._lock:
            for entry in self._data["missed_vuln_types"]:
                if entry["vuln_type"] == vuln_type:
                    entry["count"] += 1
                    self._dirty = True
                    return
            self._data["missed_vuln_types"].append({"vuln_type": vuln_type, "count": 1})
            self._data["missed_vuln_types"].sort(key=lambda x: -x["count"])
            self._dirty = True

    def priority_vuln_types(self, top_n: int = 5) -> List[str]:
        """Returns vuln types most often missed — focus for next run."""
        with self._lock:
            return [e["vuln_type"] for e in self._data["missed_vuln_types"][:top_n]]

    # ── Chain intelligence ────────────────────────────────────────────────────

    def record_successful_chain(self, chain: List[str], impact: str = "") -> None:
        """chain = list of vuln types in order, e.g. ['xss', 'auth_bypass', 'idor']"""
        chain_key = " → ".join(chain)
        with self._lock:
            for entry in self._data["successful_chains"]:
                if entry["chain_key"] == chain_key:
                    entry["count"] += 1
                    self._dirty = True
                    return
            self._data["successful_chains"].append(
                {"chain_key": chain_key, "chain": chain, "impact": impact, "count": 1}
            )
            self._data["successful_chains"].sort(key=lambda x: -x["count"])
            self._data["successful_chains"] = self._data["successful_chains"][:self._MAX_CHAINS]
            self._dirty = True

    def top_chains(self, top_n: int = 5) -> List[dict]:
        with self._lock:
            return deepcopy(self._data["successful_chains"][:top_n])

    # ── Run stats ─────────────────────────────────────────────────────────────

    def record_run(self, total_findings: int, confirmed: int, targets: int) -> None:
        with self._lock:
            s = self._data["stats"]
            s["total_runs"]      += 1
            s["total_findings"]  += total_findings
            s["total_confirmed"] += confirmed
            s["last_run_ts"]     = time.time()
            self._dirty = True

        # Append to run history (ring-buffer)
        self._append_run_history({
            "ts":        time.time(),
            "findings":  total_findings,
            "confirmed": confirmed,
            "targets":   targets,
        })

    def _append_run_history(self, entry: dict) -> None:
        p = _hist_path()
        try:
            history = json.loads(p.read_text()) if p.exists() else []
            history.append(entry)
            history = history[-_HISTORY_LIMIT:]
            p.write_text(json.dumps(history, indent=2))
        except Exception as exc:
            log.debug("[memory] History append failed: %s", exc)

    def run_history(self, limit: int = 10) -> List[dict]:
        p = _hist_path()
        try:
            if p.exists():
                return json.loads(p.read_text())[-limit:]
        except Exception:
            pass
        return []

    # ── ctx integration ───────────────────────────────────────────────────────

    def to_ctx(self) -> dict:
        """Return a snapshot suitable for injection into scan ctx."""
        with self._lock:
            return {
                "boosted_payloads_xss":    self.get_boosted_payloads("xss"),
                "boosted_payloads_sqli":   self.get_boosted_payloads("sqli"),
                "boosted_payloads_ssrf":   self.get_boosted_payloads("ssrf"),
                "failed_payloads":         self.get_failed_payloads(),
                "high_value_hosts":        self.high_value_hosts(),
                "priority_vuln_types":     self.priority_vuln_types(),
                "top_chains":              self.top_chains(),
                "total_runs":              self._data["stats"]["total_runs"],
            }

    def update_from_ctx(self, ctx: dict) -> None:
        """
        Extract findings/chain/missed data from the post-scan ctx and record
        them so they are available on the next run.

        ctx keys consumed (all optional):
          findings         — list of finding dicts
          successful_chains — list of chain dicts from exploit_chain_executor
          focus_targets    — from BenchmarkFeedbackLoop (missed hosts)
          priority_vuln_types — from BenchmarkFeedbackLoop (missed vuln types)
        """
        findings = ctx.get("findings", [])
        for f in findings:
            if not isinstance(f, dict):
                try:
                    f = f.to_dict()
                except Exception:
                    continue
            vuln = f.get("vuln_type") or f.get("type") or ""
            payload = f.get("payload") or ""
            host = _extract_host(f.get("url") or f.get("target") or "")
            severity = f.get("severity", "info")
            confirmed = f.get("confirmed", False) or f.get("exploited", False)

            if confirmed and payload:
                self.record_successful_payload(payload, vuln)
            if payload and not confirmed:
                self.record_failed_payload(payload, vuln)
            if confirmed and host:
                self.record_high_value_target(host, severity)
            if confirmed and vuln:
                self.record_vulnerable_pattern(host or vuln, vuln)

        # Missed patterns from benchmark feedback loop
        for vt in ctx.get("priority_vuln_types", []):
            self.record_missed_vuln_type(vt)

        for ft in ctx.get("focus_targets", []):
            self.record_missed_pattern(ft)

        # Successful chains from exploit_chain_executor
        for chain_info in ctx.get("successful_chains", []):
            if isinstance(chain_info, dict):
                chain_steps = chain_info.get("chain", [])
                impact = chain_info.get("impact", "")
                if chain_steps:
                    self.record_successful_chain(chain_steps, impact)

        # Run-level stats
        total = len(findings)
        confirmed_count = sum(
            1 for f in findings
            if (f if isinstance(f, dict) else {}).get("confirmed") or
               (f if isinstance(f, dict) else {}).get("exploited")
        )
        targets = len({
            _extract_host((f if isinstance(f, dict) else {}).get("url") or
                          (f if isinstance(f, dict) else {}).get("target") or "")
            for f in findings
        })
        self.record_run(total, confirmed_count, targets)

    # ── Queries for strategy engine ───────────────────────────────────────────

    def was_vulnerable(self, host: str) -> bool:
        return self.is_high_value(host)

    def stats(self) -> dict:
        with self._lock:
            return deepcopy(self._data["stats"])

    def summary(self) -> str:
        s = self.stats()
        return (
            f"PersistentMemory: {s['total_runs']} runs, "
            f"{s['total_findings']} findings ({s['total_confirmed']} confirmed), "
            f"{len(self._data['successful_payloads'])} good payloads, "
            f"{len(self._data['vulnerable_patterns'])} patterns"
        )


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _extract_host(url: str) -> str:
    if not url:
        return ""
    try:
        from urllib.parse import urlparse
        parsed = urlparse(url if "://" in url else f"https://{url}")
        return parsed.netloc or parsed.path.split("/")[0]
    except Exception:
        return url.split("/")[0]


# ---------------------------------------------------------------------------
# Singleton
# ---------------------------------------------------------------------------

_instance: Optional[PersistentMemory] = None
_lock = threading.Lock()


def get_memory() -> PersistentMemory:
    global _instance
    with _lock:
        if _instance is None:
            _instance = PersistentMemory().load()
    return _instance


def load_memory() -> PersistentMemory:
    """Alias for get_memory() — explicit about intent at scan start."""
    return get_memory()


def save_memory() -> None:
    """Save current memory to disk. Call at end of every scan run."""
    get_memory().save()


def update_memory(ctx: dict) -> None:
    """Update memory from a completed scan context dict, then save."""
    mem = get_memory()
    mem.update_from_ctx(ctx)
    mem.save()
