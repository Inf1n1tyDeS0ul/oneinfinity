"""SQLite findings database wrapper — delegates to ResultIngestionEngine."""

import json
import csv
import logging
import sqlite3
import uuid
from datetime import datetime, timezone
from result_ingestion_engine import get_ingestion_engine
from modules.utils import (banner, section, ok, info, warn, err, ask,
                           table, sev, bold, green, yellow, red, cyan, now_str)

log = logging.getLogger("oneinfinity.findings")

SEVERITY_ORDER = ["critical", "high", "medium", "low", "info"]

class FindingsDB:
    def __init__(self, db_path=None):
        # We use the unified ingestion engine for findings storage
        self.engine = get_ingestion_engine()
        # Ensure db is initialized
        self.engine._init_db()
        # Store db_path for the audit table; fall back to engine's DB path if not given
        if db_path is not None:
            self._audit_db_path = str(db_path)
        else:
            self._audit_db_path = str(self.engine._db_path)
        self._audit_conn: sqlite3.Connection | None = None

    def _get_audit_conn(self) -> sqlite3.Connection:
        """Return a lazily-opened SQLite connection for the audit table."""
        if self._audit_conn is None:
            self._audit_conn = sqlite3.connect(self._audit_db_path, timeout=30)
        return self._audit_conn

    def close(self):
        """Close the audit DB connection gracefully."""
        if self._audit_conn is not None:
            try:
                self._audit_conn.close()
            except Exception as exc:
                log.warning("FindingsDB.close(): error closing audit connection: %s", exc)
            finally:
                self._audit_conn = None

    def log_action(self, phase: str, action=None, result: str = ""):
        """Persist an audit event to findings_audit.

        Supports two call styles:
          log_action(phase, action_str, result_str)   — original 3-arg style
          log_action(action_str, metadata_dict)       — test-compatible 2-arg style
        """
        try:
            conn = self._get_audit_conn()
            conn.execute(
                """
                CREATE TABLE IF NOT EXISTS findings_audit (
                    id        INTEGER PRIMARY KEY AUTOINCREMENT,
                    action    TEXT    NOT NULL,
                    metadata  TEXT    NOT NULL DEFAULT '{}',
                    timestamp TEXT    NOT NULL
                )
                """
            )
            # Normalise arguments so both call styles work
            if isinstance(action, dict):
                # Called as log_action("action_name", {"key": "val"})
                action_str = phase
                metadata_str = json.dumps(action, default=str)
            else:
                # Called as log_action(phase, action_str, result_str)
                action_str = phase
                metadata_str = json.dumps(
                    {"action": action, "result": result} if action else {},
                    default=str,
                )
            ts = datetime.now(timezone.utc).isoformat()
            conn.execute(
                "INSERT INTO findings_audit (action, metadata, timestamp) VALUES (?, ?, ?)",
                (action_str, metadata_str, ts),
            )
            conn.commit()
        except Exception as exc:
            log.warning("FindingsDB.log_action(): failed to write audit record: %s", exc)

    def add(self, **kwargs) -> str:
        finding = {
            "finding_id": kwargs.get("finding_id", str(uuid.uuid4())[:12]),
            "scan_id": kwargs.get("scan_id", "manual"),
            "target": kwargs.get("target", kwargs.get("endpoint", "")),
            "title": kwargs.get("title", ""),
            "severity": kwargs.get("severity", "info"),
            "vuln_type": kwargs.get("vuln_type", ""),
            "evidence": kwargs.get("evidence", kwargs.get("description", "")),
            "payload": kwargs.get("payload", kwargs.get("poc", "")),
            "url": kwargs.get("url", kwargs.get("endpoint", "")),
            "tool": kwargs.get("tool", "manual"),
            "confidence": kwargs.get("confidence", 1.0),
            "cvss": kwargs.get("cvss", kwargs.get("cvss_score", 0.0)),
            "status": kwargs.get("status", "new"),
            "created_at": kwargs.get("created_at", datetime.utcnow().isoformat()),
        }
        # Include all other kwargs in raw_json to not lose manual data
        finding["raw"] = kwargs
        
        self.engine.persist_finding(finding)
        return finding["finding_id"]

    def interactive_add(self) -> str:
        """Walk the user through logging a new finding."""
        banner("Log New Finding")

        title    = ask("Title (e.g. IDOR in /api/users/{id}): ").strip()
        if not title:
            err("Title is required.")
            return ""

        print("  Vulnerability types: SQLi, XSS, IDOR, SSRF, SSTI, RCE, LFI, CSRF,")
        print("                       Open Redirect, CORS, Auth Bypass, Info Disclosure, Other")
        vuln_type = ask("Vuln type: ").strip()

        print("  Severities: critical / high / medium / low / info")
        severity = ask("Severity: ").strip().lower()
        while severity not in SEVERITY_ORDER:
            severity = ask("  Invalid. Enter critical/high/medium/low/info: ").strip().lower()

        cvss_score  = ask("CVSS score (e.g. 8.5, or blank): ").strip()
        endpoint    = ask("Endpoint URL: ").strip()
        method      = ask("HTTP method (GET/POST/...): ").strip().upper() or "GET"
        description = ask("Short description: ").strip()
        poc         = ask("PoC / curl command (or blank): ").strip()

        fid = self.add(
            title=title,
            vuln_type=vuln_type,
            severity=severity,
            cvss=float(cvss_score) if cvss_score else 0.0,
            endpoint=endpoint,
            method=method,
            description=description,
            poc=poc or "",
        )
        ok(f"Finding #{fid} logged: {title}")
        return fid

    def get(self, fid: str) -> dict | None:
        findings = self.engine.get_findings()
        for f in findings:
            if f.get("finding_id") == fid or str(f.get("finding_id")) == str(fid):
                return f
        return None

    def all(self, severity: str = None, status: str = None) -> list[dict]:
        findings = self.engine.get_findings(severity=severity)
        if status:
            findings = [f for f in findings if f.get("status") == status]
        return findings

    def update(self, fid: str, **kwargs):
        if not kwargs:
            return
        # Find the existing finding
        f = self.get(fid)
        if not f:
            err(f"Finding #{fid} not found.")
            return
        
        # We need a proper SQL UPDATE through the engine for v2.
        # However, the engine lacks an `update_finding` method.
        # Let's add it via a raw query here for simplicity, or we can just replace the finding.
        # Since persist_finding uses INSERT OR REPLACE, we can just update the dict and persist again.
        f.update(kwargs)
        if "raw" in f:
            f["raw"].update(kwargs)
        self.engine.persist_finding(f)
        ok(f"Finding #{fid} updated.")

    def list_findings(self, severity: str = None, status: str = None):
        findings = self.all(severity=severity, status=status)
        if not findings:
            info("No findings yet.")
            return

        banner("Findings")
        rows = []
        for f in findings:
            rows.append({
                "ID":       str(f.get("finding_id", "")),
                "SEV":      sev(f.get("severity", "info"), (f.get("severity", "info")).upper()[:4]),
                "CVSS":     str(f.get("cvss", "0.0")),
                "STATUS":   (f.get("status", "new"))[:10],
                "TITLE":    (f.get("title", ""))[:50],
                "TARGET":   (f.get("target", ""))[:40],
            })
        table(rows, ["ID", "SEV", "CVSS", "STATUS", "TITLE", "TARGET"])
        print()
        self._print_stats(findings)

    def show_finding(self, fid: str):
        f = self.get(fid)
        if not f:
            err(f"Finding #{fid} not found.")
            return
        banner(f"Finding #{fid} — {f.get('title', '')}")
        fields = [
            ("Severity",    sev(f.get("severity", "info"))),
            ("CVSS",        str(f.get("cvss", "0.0"))),
            ("Vuln Type",   f.get("vuln_type", "—")),
            ("Target",      f.get("target", "—")),
            ("URL",         f.get("url", "—")),
            ("Tool",        f.get("tool", "—")),
            ("Confidence",  str(f.get("confidence", "—"))),
            ("Status",      f.get("status", "—")),
            ("Created",     f.get("created_at", "—")),
        ]
        for k, v in fields:
            print(f"  {bold(k+':'):<22} {v}")
        
        raw = f.get("raw", {})
        if "description" in raw or f.get("evidence"):
            section("Description / Evidence")
            print(f"  {raw.get('description', f.get('evidence'))}")
        if f.get("payload"):
            section("Payload / PoC")
            print(f"  {f.get('payload')}")
        print()

    def _print_stats(self, findings: list[dict]):
        section("Summary")
        counts = {}
        for f in findings:
            s = f.get("severity", "info")
            counts[s] = counts.get(s, 0) + 1
        for s in SEVERITY_ORDER:
            if counts.get(s):
                print(f"  {sev(s, s.upper()):<20} {counts[s]}")
        print()

    def stats(self):
        findings = self.all()
        banner("Findings Statistics")
        total = len(findings)
        info(f"Total findings: {total}")
        self._print_stats(findings)
        status_counts = {}
        for f in findings:
            s = f.get("status", "new")
            status_counts[s] = status_counts.get(s, 0) + 1
        section("By Status")
        for s, c in status_counts.items():
            print(f"  {s:<20} {c}")
        print()

    def export_json(self, path: str):
        findings = self.all()
        with open(path, "w") as f:
            json.dump(findings, f, indent=2, default=str)
        ok(f"Exported {len(findings)} findings → {path}")

    def export_csv(self, path: str):
        findings = self.all()
        if not findings:
            warn("No findings to export.")
            return
        with open(path, "w", newline="") as f:
            # Union of all keys, sorted for deterministic column ordering
            keys: set = set()
            for finding in findings:
                keys.update(finding.keys())
            writer = csv.DictWriter(f, fieldnames=sorted(keys))
            writer.writeheader()
            writer.writerows(findings)
        ok(f"Exported {len(findings)} findings → {path}")

    def export_markdown(self, path: str):
        findings = self.all()
        lines = ["# Findings Export\n"]
        for f in findings:
            lines.append(f"## #{f.get('finding_id')} — {f.get('title')}\n")
            lines.append(f"**Severity:** {(f.get('severity', 'info')).upper()}  ")
            lines.append(f"**CVSS:** {f.get('cvss', '0.0')}  ")
            lines.append(f"**Status:** {f.get('status', 'new')}\n")
            if f.get("evidence"):
                lines.append(f"{f.get('evidence')}\n")
            if f.get("target"):
                lines.append(f"**Target:** `{f.get('target')}`\n")
            lines.append("---\n")
        with open(path, "w") as f:
            f.write("\n".join(lines))
        ok(f"Exported {len(findings)} findings → {path}")
