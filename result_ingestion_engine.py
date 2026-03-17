"""
result_ingestion_engine.py — Fixes the tool→output→parser→database→graph→UI result chain.

Every tool result (nuclei, dalfox, sqlmap, subfinder, httpx, etc.) must flow through here.
No silent failures — every error is logged with the source.
"""
from __future__ import annotations

import json
import logging
import sqlite3
import threading
import time
import uuid
from dataclasses import dataclass, field
from datetime import datetime
from typing import Callable, List, Optional

import path_manager

log = logging.getLogger("oneinfinity.result_ingestion")

# ---------------------------------------------------------------------------
# Dataclasses
# ---------------------------------------------------------------------------

@dataclass
class RawResult:
    scan_id: str
    source: str  # "nuclei", "dalfox", "sqlmap", "subfinder", "httpx", etc.
    raw: dict    # raw tool output as dict
    timestamp: float = field(default_factory=time.time)


@dataclass
class NormalizedFinding:
    scan_id: str
    target: str
    title: str
    severity: str         # critical/high/medium/low/info
    vuln_type: str
    evidence: str
    tool: str
    finding_id: str = field(default_factory=lambda: str(uuid.uuid4())[:12])
    payload: str = ""
    url: str = ""
    confidence: float = 0.8
    cvss: float = 0.0
    status: str = "new"   # new/confirmed/false_positive
    created_at: str = field(default_factory=lambda: datetime.utcnow().isoformat())
    raw: dict = field(default_factory=dict)

    def to_dict(self) -> dict:
        return {
            "finding_id": self.finding_id,
            "scan_id": self.scan_id,
            "target": self.target,
            "title": self.title,
            "severity": self.severity,
            "vuln_type": self.vuln_type,
            "evidence": self.evidence,
            "payload": self.payload,
            "url": self.url,
            "tool": self.tool,
            "confidence": self.confidence,
            "cvss": self.cvss,
            "status": self.status,
            "created_at": self.created_at,
            "raw": self.raw,
        }


# ---------------------------------------------------------------------------
# Parsers
# ---------------------------------------------------------------------------

def _parse_nuclei(raw: dict, scan_id: str) -> Optional[NormalizedFinding]:
    """Parse a nuclei JSONL result dict into a NormalizedFinding."""
    try:
        template_id = raw.get("template-id") or raw.get("template_id")
        if not template_id:
            raise ValueError("nuclei finding missing template_id/template-id")
        title = raw.get("name") or template_id or "nuclei-finding"
        severity = (raw.get("info", {}).get("severity") or raw.get("severity") or "info").lower()
        matched_at = raw.get("matched-at") or raw.get("matched_at") or ""
        url = matched_at or raw.get("host") or raw.get("url") or ""
        vuln_type = raw.get("type") or template_id or "nuclei"
        target = raw.get("host") or url
        evidence = raw.get("extracted-results", "")
        if isinstance(evidence, list):
            evidence = "; ".join(str(e) for e in evidence)
        evidence = evidence or raw.get("matcher-name", "") or ""
        # CVSS from severity
        cvss_map = {"critical": 9.5, "high": 7.5, "medium": 5.0, "low": 2.5, "info": 0.0}
        cvss = cvss_map.get(severity, 0.0)
        return NormalizedFinding(
            scan_id=scan_id,
            target=target,
            title=str(title),
            severity=severity,
            vuln_type=str(vuln_type),
            evidence=str(evidence),
            tool=f"nuclei:{template_id}",
            url=str(url),
            confidence=0.85,
            cvss=cvss,
            raw=raw,
        )
    except Exception as exc:
        log.error("_parse_nuclei failed: %s | raw=%s", exc, raw)
        return None


def _parse_dalfox(raw: dict, scan_id: str) -> Optional[NormalizedFinding]:
    """Parse a dalfox result dict.
    dalfox outputs: {"type":"V","poc":"...","param":"...","evidence":"..."}
    """
    try:
        poc = raw.get("poc") or raw.get("PoC") or ""
        param = raw.get("param") or raw.get("parameter") or ""
        evidence = raw.get("evidence") or raw.get("message") or poc
        url = raw.get("url") or raw.get("URL") or poc.split("?")[0] if poc else ""
        target = url.split("/")[2] if url.startswith("http") else url
        result_type = raw.get("type") or raw.get("Type") or "V"
        severity = "high" if result_type in ("V", "G") else "medium"
        title = "Reflected XSS" if result_type == "V" else "Potential XSS"
        return NormalizedFinding(
            scan_id=scan_id,
            target=target,
            title=title,
            severity=severity,
            vuln_type="xss",
            evidence=str(evidence),
            payload=str(poc),
            url=str(url),
            tool="dalfox",
            confidence=0.9 if result_type == "V" else 0.6,
            cvss=8.0 if severity == "high" else 5.0,
            raw=raw,
        )
    except Exception as exc:
        log.error("_parse_dalfox failed: %s | raw=%s", exc, raw)
        return None


def _parse_sqlmap(raw: dict, scan_id: str) -> Optional[NormalizedFinding]:
    """Parse a sqlmap result dict."""
    try:
        url = raw.get("url") or raw.get("target") or ""
        target = url.split("/")[2] if url.startswith("http") else url
        param = raw.get("parameter") or raw.get("param") or ""
        technique = raw.get("technique") or raw.get("type") or "SQL Injection"
        dbms = raw.get("dbms") or raw.get("backend") or ""
        evidence = raw.get("payload") or raw.get("evidence") or ""
        payload = raw.get("payload") or ""
        title = f"SQL Injection ({technique})" if technique else "SQL Injection"
        if dbms:
            title += f" [{dbms}]"
        return NormalizedFinding(
            scan_id=scan_id,
            target=target,
            title=title,
            severity="high",
            vuln_type="sqli",
            evidence=str(evidence),
            payload=str(payload),
            url=str(url),
            tool="sqlmap",
            confidence=0.95,
            cvss=8.8,
            raw=raw,
        )
    except Exception as exc:
        log.error("_parse_sqlmap failed: %s | raw=%s", exc, raw)
        return None


def _parse_subfinder(raw: dict, scan_id: str) -> Optional[NormalizedFinding]:
    """Parse a subfinder result dict. Subdomains are info-severity 'subdomain-discovered' findings."""
    try:
        subdomain = raw.get("host") or raw.get("subdomain") or raw.get("value") or ""
        if not subdomain:
            # plain string passed as dict key
            subdomain = next(iter(raw.values()), "")
        target = subdomain
        return NormalizedFinding(
            scan_id=scan_id,
            target=target,
            title=f"Subdomain Discovered: {subdomain}",
            severity="info",
            vuln_type="subdomain-discovered",
            evidence=f"Subdomain: {subdomain}",
            url=f"https://{subdomain}",
            tool="subfinder",
            confidence=0.9,
            cvss=0.0,
            raw=raw,
        )
    except Exception as exc:
        log.error("_parse_subfinder failed: %s | raw=%s", exc, raw)
        return None


def _parse_httpx(raw: dict, scan_id: str) -> Optional[NormalizedFinding]:
    """Parse an httpx result dict. Live hosts are info-severity 'live-host' findings."""
    try:
        url = raw.get("url") or raw.get("input") or ""
        host = raw.get("host") or (url.split("/")[2] if url.startswith("http") else url)
        status_code = raw.get("status-code") or raw.get("status_code") or 0
        title_text = raw.get("title") or raw.get("webserver") or ""
        tech = raw.get("tech") or raw.get("technologies") or []
        if isinstance(tech, list):
            tech = ", ".join(tech)
        evidence = f"status={status_code} title={title_text} tech={tech}"
        return NormalizedFinding(
            scan_id=scan_id,
            target=host,
            title=f"Live Host: {host}",
            severity="info",
            vuln_type="live-host",
            evidence=evidence,
            url=str(url),
            tool="httpx",
            confidence=1.0,
            cvss=0.0,
            raw=raw,
        )
    except Exception as exc:
        log.error("_parse_httpx failed: %s | raw=%s", exc, raw)
        return None


def _parse_generic(raw: dict, scan_id: str, source: str) -> Optional[NormalizedFinding]:
    """Fallback parser using raw.get fields."""
    try:
        title = (
            raw.get("title")
            or raw.get("name")
            or raw.get("type")
            or raw.get("vuln_type")
            or f"{source}-finding"
        )
        severity = (raw.get("severity") or raw.get("risk") or "info").lower()
        if severity not in ("critical", "high", "medium", "low", "info"):
            severity = "info"
        target = (
            raw.get("target")
            or raw.get("host")
            or raw.get("url")
            or raw.get("domain")
            or ""
        )
        url = raw.get("url") or raw.get("matched-at") or ""
        evidence = (
            raw.get("evidence")
            or raw.get("output")
            or raw.get("details")
            or raw.get("description")
            or ""
        )
        if isinstance(evidence, (dict, list)):
            evidence = json.dumps(evidence)
        vuln_type = (
            raw.get("vuln_type")
            or raw.get("type")
            or raw.get("category")
            or source
        )
        payload = raw.get("payload") or raw.get("poc") or ""
        cvss_map = {"critical": 9.5, "high": 7.5, "medium": 5.0, "low": 2.5, "info": 0.0}
        cvss = float(raw.get("cvss") or raw.get("cvss_score") or cvss_map.get(severity, 0.0))
        return NormalizedFinding(
            scan_id=scan_id,
            target=str(target),
            title=str(title),
            severity=severity,
            vuln_type=str(vuln_type),
            evidence=str(evidence),
            payload=str(payload),
            url=str(url),
            tool=source,
            confidence=float(raw.get("confidence", 0.7)),
            cvss=cvss,
            raw=raw,
        )
    except Exception as exc:
        log.error("_parse_generic failed (source=%s): %s | raw=%s", source, exc, raw)
        return None


# ---------------------------------------------------------------------------
# ResultIngestionEngine
# ---------------------------------------------------------------------------

_PARSER_MAP: dict[str, Callable[[dict, str], Optional[NormalizedFinding]]] = {
    "nuclei": _parse_nuclei,
    "dalfox": _parse_dalfox,
    "sqlmap": _parse_sqlmap,
    "subfinder": _parse_subfinder,
    "httpx": _parse_httpx,
}

_CREATE_FINDINGS_TABLE = """
CREATE TABLE IF NOT EXISTS findings (
    finding_id  TEXT PRIMARY KEY,
    scan_id     TEXT NOT NULL,
    target      TEXT,
    title       TEXT,
    severity    TEXT,
    vuln_type   TEXT,
    evidence    TEXT,
    payload     TEXT,
    url         TEXT,
    tool        TEXT,
    confidence  REAL,
    cvss        REAL,
    status      TEXT DEFAULT 'new',
    created_at  TEXT,
    raw_json    TEXT
);
"""

_CREATE_RECON_ASSETS_TABLE = """
CREATE TABLE IF NOT EXISTS recon_assets (
    asset_id      TEXT PRIMARY KEY,
    scan_id       TEXT NOT NULL,
    asset_type    TEXT,
    value         TEXT,
    metadata_json TEXT,
    created_at    TEXT
);
"""

_CREATE_RAW_FINDINGS_TABLE = """
CREATE TABLE IF NOT EXISTS raw_findings (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    tool TEXT,
    raw_json TEXT,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);
"""


class ResultIngestionEngine:
    """Central funnel for all tool results → SQLite → attack graph → UI broadcast."""

    def __init__(self) -> None:
        self._db_path = path_manager.findings_db_path()   # canonical: ~/.oneinfinity/databases/findings.db
        self._lock = threading.Lock()
        self._broadcast_cb: Optional[Callable[[dict], None]] = None
        self._init_db()

    # ------------------------------------------------------------------
    # Setup
    # ------------------------------------------------------------------

    def _init_db(self) -> None:
        try:
            with sqlite3.connect(str(self._db_path), timeout=30) as conn:
                conn.execute("PRAGMA journal_mode=WAL;")
                conn.execute("PRAGMA synchronous=FULL;")
                conn.execute(_CREATE_FINDINGS_TABLE)
                conn.execute(_CREATE_RECON_ASSETS_TABLE)
                conn.execute(_CREATE_RAW_FINDINGS_TABLE)
                conn.commit()
            log.debug("ResultIngestionEngine: DB initialised at %s", self._db_path)
        except Exception as exc:
            log.error("ResultIngestionEngine: DB init failed: %s", exc)
            raise RuntimeError("ResultIngestionEngine DB init failed") from exc

    def set_broadcast_callback(self, cb: Callable[[dict], None]) -> None:
        """Register a callback(finding_dict) called for each new finding."""
        self._broadcast_cb = cb

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def ingest(self, result: RawResult, confidence_threshold: float = 0.5) -> Optional[NormalizedFinding]:
        """Parse → filter → dedup → store → graph → broadcast."""
        try:
            finding = self._parse(result)
        except Exception as exc:
            log.error("ingest: parse error [source=%s scan=%s]: %s", result.source, result.scan_id, exc)
            return None

        if finding is None:
            return None

        # 1. Confidence Filtering (Noise Reduction)
        if finding.confidence < confidence_threshold:
            log.info("ingest: suppressing low-confidence finding (%.2f < %.2f) [%s]",
                     finding.confidence, confidence_threshold, finding.vuln_type)
            return None

        # 2. Enhanced Deduplication
        if self._is_duplicate(finding):
            log.debug("ingest: duplicate skipped [%s @ %s]", finding.vuln_type, finding.url)
            return None

        try:
            self._store_finding(finding)
            self._update_graph(finding)
            self._broadcast(finding)
            return finding
        except Exception as exc:
            log.error("ingest: DB write failed: %s", exc)
            return None

    def _is_duplicate(self, finding: NormalizedFinding) -> bool:
        """Robust deduplication: check scan_id OR global duplicate (same url + type)."""
        try:
            with sqlite3.connect(str(self._db_path), timeout=10) as conn:
                # Check for identical finding in same scan OR globally identical within 24h
                row = conn.execute(
                    "SELECT 1 FROM findings "
                    "WHERE (scan_id=? AND vuln_type=? AND url=?) "
                    "OR (vuln_type=? AND url=? AND created_at > datetime('now', '-1 day')) "
                    "LIMIT 1",
                    (finding.scan_id, finding.vuln_type, finding.url, 
                     finding.vuln_type, finding.url),
                ).fetchone()
                return row is not None
        except Exception:
            return False

    def ingest_batch(self, results: List[RawResult]) -> List[NormalizedFinding]:
        """Ingest a list of RawResults; returns list of successfully parsed findings."""
        findings: List[NormalizedFinding] = []
        for result in results:
            f = self.ingest(result)
            if f is not None:
                findings.append(f)
        return findings

    def ingest_recon_asset(
        self,
        scan_id: str,
        asset_type: str,
        value: str,
        metadata: dict = {},
    ) -> None:
        """Store a recon asset (subdomain, endpoint, service, technology) into SQLite."""
        asset_id = str(uuid.uuid4())[:12]
        created_at = datetime.utcnow().isoformat()
        try:
            with self._lock:
                with sqlite3.connect(str(self._db_path)) as conn:
                    conn.execute(
                        "INSERT OR REPLACE INTO recon_assets "
                        "(asset_id, scan_id, asset_type, value, metadata_json, created_at) "
                        "VALUES (?, ?, ?, ?, ?, ?)",
                        (asset_id, scan_id, asset_type, value, json.dumps(metadata), created_at),
                    )
                    conn.commit()
        except Exception as exc:
            log.error("ingest_recon_asset: DB error [scan=%s asset_type=%s value=%s]: %s",
                      scan_id, asset_type, value, exc)

    def store_raw_findings(self, findings: List[dict]) -> int:
        """Store raw findings before validation."""
        inserted = 0
        try:
            with self._lock:
                with sqlite3.connect(str(self._db_path), timeout=30) as conn:
                    conn.execute("PRAGMA journal_mode=WAL;")
                    conn.execute("PRAGMA synchronous=FULL;")
                    for f in findings:
                        tool = f.get("tool") or f.get("source_tool") or "unknown"
                        conn.execute(
                            "INSERT INTO raw_findings (tool, raw_json) VALUES (?, ?)",
                            (tool, json.dumps(f, default=str)),
                        )
                        inserted += 1
                    conn.commit()
        except Exception as exc:
            log.error("store_raw_findings: DB error: %s", exc)
        return inserted

    def persist_finding(self, finding: dict) -> None:
        """Persist an already-normalised finding dict to the findings table."""
        nf = NormalizedFinding(
            finding_id  = finding.get("finding_id") or finding.get("id") or str(uuid.uuid4())[:12],
            scan_id     = finding.get("scan_id", ""),
            target      = finding.get("target", ""),
            title       = finding.get("title", ""),
            severity    = finding.get("severity", "info"),
            vuln_type   = finding.get("vuln_type") or finding.get("attack_type", ""),
            evidence    = finding.get("evidence", ""),
            payload     = finding.get("payload", ""),
            url         = finding.get("url", ""),
            tool        = finding.get("tool", ""),
            confidence  = float(finding.get("confidence", 0.8)),
            cvss        = float(finding.get("cvss", 0.0)),
            status      = finding.get("status", "new"),
            created_at  = finding.get("created_at", datetime.utcnow().isoformat()),
            raw         = finding,
        )
        self._store_finding(nf)
        self._broadcast(nf)

    def get_findings(
        self,
        scan_id: str = None,
        target: str = None,
        severity: str = None,
    ) -> List[dict]:
        """Query findings with optional filters."""
        clauses: List[str] = []
        params: List = []
        if scan_id:
            clauses.append("scan_id = ?")
            params.append(scan_id)
        if target:
            clauses.append("target = ?")
            params.append(target)
        if severity:
            clauses.append("severity = ?")
            params.append(severity)
        where = ("WHERE " + " AND ".join(clauses)) if clauses else ""
        sql = f"SELECT * FROM findings {where} ORDER BY created_at DESC"
        try:
            with sqlite3.connect(str(self._db_path)) as conn:
                conn.row_factory = sqlite3.Row
                rows = conn.execute(sql, params).fetchall()
                results = []
                for row in rows:
                    d = dict(row)
                    try:
                        d["raw"] = json.loads(d.pop("raw_json", "{}") or "{}")
                    except Exception:
                        d["raw"] = {}
                    results.append(d)
                return results
        except Exception as exc:
            log.error("get_findings: DB error: %s", exc)
            return []

    def get_recon_assets(
        self,
        scan_id: str = None,
        asset_type: str = None,
    ) -> List[dict]:
        """Query recon assets with optional filters."""
        clauses: List[str] = []
        params: List = []
        if scan_id:
            clauses.append("scan_id = ?")
            params.append(scan_id)
        if asset_type:
            clauses.append("asset_type = ?")
            params.append(asset_type)
        where = ("WHERE " + " AND ".join(clauses)) if clauses else ""
        sql = f"SELECT * FROM recon_assets {where} ORDER BY created_at DESC"
        try:
            with sqlite3.connect(str(self._db_path)) as conn:
                conn.row_factory = sqlite3.Row
                rows = conn.execute(sql, params).fetchall()
                results = []
                for row in rows:
                    d = dict(row)
                    try:
                        d["metadata"] = json.loads(d.pop("metadata_json", "{}") or "{}")
                    except Exception:
                        d["metadata"] = {}
                    results.append(d)
                return results
        except Exception as exc:
            log.error("get_recon_assets: DB error: %s", exc)
            return []

    def finding_count(self, scan_id: str) -> int:
        """Return number of findings for a given scan_id."""
        try:
            with sqlite3.connect(str(self._db_path)) as conn:
                row = conn.execute(
                    "SELECT COUNT(*) FROM findings WHERE scan_id = ?", (scan_id,)
                ).fetchone()
                return row[0] if row else 0
        except Exception as exc:
            log.error("finding_count: DB error [scan=%s]: %s", scan_id, exc)
            return 0

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _parse(self, result: RawResult) -> Optional[NormalizedFinding]:
        source = (result.source or "").lower()
        parser = _PARSER_MAP.get(source)
        if parser:
            return parser(result.raw, result.scan_id)
        return _parse_generic(result.raw, result.scan_id, source)

    def _store_finding(self, finding: NormalizedFinding) -> None:
        last_exc: Optional[Exception] = None
        for attempt in range(3):
            try:
                with self._lock:
                    with sqlite3.connect(str(self._db_path), timeout=30) as conn:
                        conn.execute("PRAGMA journal_mode=WAL;")
                        conn.execute("PRAGMA synchronous=FULL;")
                        conn.execute(
                            "INSERT OR REPLACE INTO findings "
                            "(finding_id, scan_id, target, title, severity, vuln_type, "
                            " evidence, payload, url, tool, confidence, cvss, status, "
                            " created_at, raw_json) "
                            "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                            (
                                finding.finding_id,
                                finding.scan_id,
                                finding.target,
                                finding.title,
                                finding.severity,
                                finding.vuln_type,
                                finding.evidence,
                                finding.payload,
                                finding.url,
                                finding.tool,
                                finding.confidence,
                                finding.cvss,
                                finding.status,
                                finding.created_at,
                                json.dumps(finding.raw),
                            ),
                        )
                        conn.commit()
                return
            except sqlite3.OperationalError as exc:
                last_exc = exc
                if "locked" in str(exc).lower() and attempt < 2:
                    time.sleep(0.2 * (2 ** attempt))
                    continue
                raise
            except Exception as exc:
                last_exc = exc
                raise

        log.error("_store_finding: DB error [finding=%s scan=%s]: %s",
                  finding.finding_id, finding.scan_id, last_exc)
        if last_exc:
            raise RuntimeError("Failed to store finding in DB") from last_exc

    def _update_graph(self, finding: NormalizedFinding) -> None:
        """Push finding into AttackGraphBrain as a VULNERABILITY node."""
        try:
            from attack_graph_brain import get_brain
            get_brain().integrate_vuln(finding.to_dict())
        except Exception as exc:
            log.error("_update_graph: graph update failed [finding=%s]: %s",
                      finding.finding_id, exc)

    def _broadcast(self, finding: NormalizedFinding) -> None:
        if self._broadcast_cb is None:
            return
        try:
            self._broadcast_cb(finding.to_dict())
        except Exception as exc:
            log.error("_broadcast: callback raised [finding=%s]: %s",
                      finding.finding_id, exc)


# ---------------------------------------------------------------------------
# Module-level singleton
# ---------------------------------------------------------------------------

_engine: Optional[ResultIngestionEngine] = None
_engine_lock = threading.Lock()


def get_ingestion_engine() -> ResultIngestionEngine:
    """Return the module-level ResultIngestionEngine singleton (created on first call)."""
    global _engine
    if _engine is None:
        with _engine_lock:
            if _engine is None:
                _engine = ResultIngestionEngine()
    return _engine
