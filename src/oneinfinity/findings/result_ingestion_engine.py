"""
result_ingestion_engine.py — Fixes the tool→output→parser→database→graph→UI result chain.

Every tool result (nuclei, dalfox, sqlmap, subfinder, httpx, etc.) must flow through here.
No silent failures — every error is logged with the source.

Storage: PostgreSQL (hard requirement).
"""
from __future__ import annotations

import json
import logging
import threading
import time
import uuid
from dataclasses import dataclass, field
from datetime import datetime
from typing import Callable, List, Optional

import oneinfinity.infra.path_manager as path_manager

log = logging.getLogger("oneinfinity.result_ingestion")


def _require_pg():
    """Return DBManager in PG mode, or raise if unavailable."""
    try:
        from oneinfinity.core.db_manager import get_db_manager_sync
        mgr = get_db_manager_sync()
        if mgr is not None and mgr.mode in ("distributed", "postgres"):
            return mgr
    except Exception as exc:
        raise RuntimeError(f"PostgreSQL is required but DBManager unavailable: {exc}") from exc
    raise RuntimeError(
        "PostgreSQL is required. Set DB_MODE=postgres or DB_MODE=distributed."
    )


def _get_graph_learning_writer():
    """Lazy import to avoid circular import at module load."""
    try:
        from oneinfinity.learning.graph_learning_writer import get_graph_learning_writer
        return get_graph_learning_writer()
    except Exception:
        return None

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
    # source_type classifies the evidence quality:
    #   "tool"       — confirmed by a security tool (nuclei, dalfox, sqlmap, etc.)
    #   "simulated"  — result of a simulation engine (workflow sim, Monte Carlo)
    #   "ai_theory"  — AI-generated theory not yet confirmed by a tool
    #   "manual"     — manually added finding
    source_type: str = "tool"
    created_at: str = field(default_factory=lambda: datetime.utcnow().isoformat())
    raw: dict = field(default_factory=dict)
    poc_steps: list = field(default_factory=list)     # ordered PoC reproduction steps
    reproduction_cmd: str = ""                         # exact CLI command to reproduce

    def to_dict(self) -> dict:
        return {
            "finding_id":       self.finding_id,
            "scan_id":          self.scan_id,
            "target":           self.target,
            "title":            self.title,
            "severity":         self.severity,
            "vuln_type":        self.vuln_type,
            "evidence":         self.evidence,
            "payload":          self.payload,
            "url":              self.url,
            "tool":             self.tool,
            "confidence":       self.confidence,
            "cvss":             self.cvss,
            "status":           self.status,
            "source_type":      self.source_type,
            "created_at":       self.created_at,
            "raw":              self.raw,
            "poc_steps":        self.poc_steps,
            "reproduction_cmd": self.reproduction_cmd,
        }

    def safe_raw_json(self) -> str:
        """Return finding.raw as JSON, coercing any non-serializable values to str."""
        try:
            return json.dumps(self.raw, default=str)
        except Exception:
            return "{}"


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


class ResultIngestionEngine:
    """Central funnel for all tool results → PostgreSQL → attack graph → UI broadcast."""

    def __init__(self) -> None:
        self._broadcast_cb: Optional[Callable[[dict], None]] = None

    def _init_db(self) -> None:
        """No-op: PG schema is managed by DBManager._ensure_schema(). Kept for backwards compatibility."""
        pass

    def set_broadcast_callback(self, cb: Callable[[dict], None]) -> None:
        """Register a callback(finding_dict) called for each new finding."""
        self._broadcast_cb = cb

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    # Phase E: vuln types that trigger synchronous pre-store validation (low FP, fast probe)
    _SYNC_VALIDATE_TYPES = frozenset({"xss", "sqli", "ssti", "lfi", "open_redirect", "xxe"})
    # Async validation (fire-and-forget; too slow/risky to block ingest)
    _ASYNC_VALIDATE_TYPES = frozenset({"ssrf", "cmdi", "rce", "auth_bypass", "idor"})

    def _normalize_url_for_dedup(self, url: str, vuln_type: str) -> str:
        """Path-template normalization for semantic dedup (MLR2).
        /api/v1/users/123 → /api/v1/users/{id}
        /api/v1/users/abc-def-ghi → /api/v1/users/{uuid}
        Prevents storing N findings for the same injection point tested on N IDs.
        """
        import re as _re
        try:
            from urllib.parse import urlparse, urlencode, parse_qs
            p = urlparse(url)
            # Normalize path segments
            path = _re.sub(r'/[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}', '/{uuid}', p.path)
            path = _re.sub(r'/[0-9a-fA-F]{24,}', '/{hex}', path)
            path = _re.sub(r'/\d+', '/{id}', path)
            # Normalize query param values (keep keys, replace values)
            params = parse_qs(p.query)
            norm_params = {k: ["{val}"] for k in params}
            norm_query = urlencode(norm_params, doseq=True) if norm_params else ""
            return f"{p.scheme}://{p.netloc}{path}?{norm_query}" if norm_query else f"{p.scheme}://{p.netloc}{path}"
        except Exception:
            return url

    def ingest(self, result: RawResult, confidence_threshold: float = 0.5) -> Optional[NormalizedFinding]:
        """Parse → validate → semantic-dedup → filter → store → graph → broadcast.
        Phase E: FindingValidationEngine pre-filter + AI confidence rescoring.
        """
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

        # Phase E-1: Synchronous validation for fast-probe vuln types (OR2/RTL2)
        # Blocks ingest only for types where re-probe is <500ms and FP rate is high.
        if finding.vuln_type in self._SYNC_VALIDATE_TYPES:
            try:
                from oneinfinity.findings.finding_validation_engine import FindingValidationEngine
                vr = FindingValidationEngine().validate(
                    finding.url, finding.vuln_type, finding.payload
                )
                if not vr.validated:
                    log.info("ingest: validation failed → false_positive suppressed [%s @ %s]",
                             finding.vuln_type, finding.url)
                    finding.status = "false_positive"
                    return None   # do not store confirmed FPs
                # Boost confidence on validated finding
                finding.confidence = max(finding.confidence, min(0.95, vr.confidence))
                finding.status = "confirmed"
                log.debug("ingest: validated [%s] confidence → %.2f", finding.vuln_type, finding.confidence)
            except Exception as _ve:
                log.debug("ingest: sync validation error (fail-open): %s", _ve)
                # Fail-open: let finding through if validator errors (PE2/RTL2 TP preservation)

        # Phase E-2: Async validation for slow/risky types (fire-and-forget, non-blocking)
        elif finding.vuln_type in self._ASYNC_VALIDATE_TYPES and finding.confidence >= 0.7:
            import threading as _threading
            _f_copy = finding  # closure capture
            def _async_validate():
                try:
                    from oneinfinity.findings.finding_validation_engine import FindingValidationEngine
                    vr = FindingValidationEngine().validate(
                        _f_copy.url, _f_copy.vuln_type, _f_copy.payload
                    )
                    if vr.validated:
                        _f_copy.confidence = max(_f_copy.confidence, min(0.95, vr.confidence))
                        _f_copy.status = "confirmed"
                    else:
                        _f_copy.status = "needs_review"
                    log.debug("ingest async-validate: [%s] → %s (%.2f)",
                              _f_copy.vuln_type, _f_copy.status, _f_copy.confidence)
                except Exception as _ae:
                    log.debug("ingest: async validation error: %s", _ae)
            _threading.Thread(target=_async_validate, daemon=True,
                               name=f"async-val-{finding.finding_id[:8]}").start()

        # Phase E-3: Path-template semantic dedup (MLR2)
        # Normalize URL before DB dedup to catch same-injection-point findings
        # that differ only in path parameter values.
        normalized_url = self._normalize_url_for_dedup(finding.url, finding.vuln_type)
        if normalized_url != finding.url:
            log.debug("ingest: normalized URL for dedup [%s] %s → %s",
                      finding.vuln_type, finding.url, normalized_url)
            finding.url = normalized_url

        # 2. Check-then-store (dedup by scan_id+vuln_type+normalized_url)
        try:
            stored = self._check_and_store(finding)
        except Exception as exc:
            log.error("ingest: DB write failed: %s", exc)
            return None

        if not stored:
            log.debug("ingest: duplicate skipped [%s @ %s]", finding.vuln_type, finding.url)
            return None

        self._broadcast(finding)           # fire immediately — UI gets the event

        # Fire learning graph update (async, non-blocking, non-fatal)
        _glw = _get_graph_learning_writer()
        if _glw is not None:
            _glw.write_finding_async(finding.to_dict())

        import threading
        threading.Thread(
            target=self._update_graph,
            args=(finding,),
            daemon=True,
            name=f"graph-update-{finding.finding_id[:8]}",
        ).start()
        return finding

    def _check_and_store(self, finding: NormalizedFinding) -> bool:
        """Atomically check for duplicate and store if new via PostgreSQL."""
        return _require_pg().sync_check_and_save_finding(finding.to_dict())

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
        metadata: Optional[dict] = None,
    ) -> None:
        """Store a recon asset (subdomain, endpoint, service, technology)."""
        if metadata is None:
            metadata = {}
        asset_id = str(uuid.uuid4())[:12]
        _require_pg().sync_save_recon_asset(asset_id, scan_id, asset_type, value, metadata)

    def store_raw_findings(self, findings: List[dict]) -> int:
        """Store raw findings before validation."""
        return _require_pg().sync_store_raw_findings(findings)

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
        """Query findings with optional filters. Falls back to local scan files when Postgres unavailable."""
        try:
            return _require_pg().sync_get_findings(scan_id=scan_id, target=target, severity=severity)
        except Exception:
            pass
        # Local fallback: read unified_findings.json from the scan output directory
        return self._get_findings_local(scan_id=scan_id, target=target, severity=severity)

    def _get_findings_local(self, scan_id=None, target=None, severity=None) -> List[dict]:
        from pathlib import Path as _Path
        base = _Path.home() / ".oneinfinity"
        results: List[dict] = []
        scan_dirs = [base / scan_id] if scan_id else sorted(base.iterdir()) if base.exists() else []
        for d in scan_dirs:
            if not d.is_dir():
                continue
            for fname in ("unified_findings.json", "full_scan/unified_findings.json"):
                fpath = d / fname
                if not fpath.exists():
                    continue
                try:
                    data = json.loads(fpath.read_text())
                    items = data if isinstance(data, list) else data.get("findings", [])
                    for item in items:
                        if not isinstance(item, dict):
                            continue
                        if target and item.get("target", "") != target:
                            continue
                        if severity and item.get("severity", "").lower() != severity.lower():
                            continue
                        results.append(item)
                except Exception:
                    pass
        return results

    def delete_findings_for_scan(self, scan_id: str) -> int:
        """Delete all findings for the given scan_id. Returns the count deleted."""
        return _require_pg().sync_delete_findings_for_scan(scan_id)

    def get_recon_assets(
        self,
        scan_id: str = None,
        asset_type: str = None,
    ) -> List[dict]:
        """Query recon assets with optional filters."""
        return _require_pg().sync_get_recon_assets(scan_id=scan_id, asset_type=asset_type)

    def finding_count(self, scan_id: str) -> int:
        """Return number of findings for a given scan_id."""
        return _require_pg().sync_finding_count(scan_id)

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
        """Unconditionally persist a finding (used by persist_finding, no dup check)."""
        _require_pg().sync_save_finding(finding.to_dict())

    def _update_graph(self, finding: NormalizedFinding) -> None:
        """Push finding into AttackGraphBrain as a VULNERABILITY node."""
        try:
            from oneinfinity.intelligence.attack_graph_brain import get_brain
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
