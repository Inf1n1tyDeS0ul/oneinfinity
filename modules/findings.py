"""SQLite findings database — track, log, query, and export findings."""

import sqlite3
import json
import csv
import os
from pathlib import Path
from datetime import datetime
from modules.utils import (banner, section, ok, info, warn, err, ask,
                           table, sev, bold, green, yellow, red, cyan, now_str)

SCHEMA = """
CREATE TABLE IF NOT EXISTS findings (
    id                INTEGER PRIMARY KEY AUTOINCREMENT,
    title             TEXT NOT NULL,
    vuln_type         TEXT NOT NULL,
    severity          TEXT CHECK(severity IN ('critical','high','medium','low','info')),
    cvss_score        REAL,
    cvss_vector       TEXT,
    endpoint          TEXT,
    method            TEXT,
    parameter         TEXT,
    description       TEXT,
    steps_to_reproduce TEXT,
    impact            TEXT,
    poc               TEXT,
    why_selected      TEXT,
    how_exploited     TEXT,
    data_exposed      TEXT,
    attacker_gains    TEXT,
    impact_score      TEXT,
    suggested_fix     TEXT,
    status            TEXT DEFAULT 'discovered'
                          CHECK(status IN ('discovered','verified','false_positive',
                                           'reported','duplicate','paid')),
    platform          TEXT,
    report_file       TEXT,
    bounty_amount     REAL,
    bounty_score      REAL,
    estimated_payout  TEXT,
    priority_rank     INTEGER,
    created_at        DATETIME DEFAULT CURRENT_TIMESTAMP,
    reported_at       DATETIME,
    notes             TEXT
);

CREATE TABLE IF NOT EXISTS hunt_log (
    id         INTEGER PRIMARY KEY AUTOINCREMENT,
    phase      TEXT,
    action     TEXT,
    result     TEXT,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP
);
"""

SEVERITY_ORDER = ["critical", "high", "medium", "low", "info"]


class FindingsDB:
    def __init__(self, db_path: str):
        self.db_path = db_path
        os.makedirs(os.path.dirname(db_path) if os.path.dirname(db_path) else ".", exist_ok=True)
        self.conn = sqlite3.connect(db_path)
        self.conn.row_factory = sqlite3.Row
        self.conn.executescript(SCHEMA)
        self.conn.commit()

    def close(self):
        self.conn.close()

    # ── Logging ───────────────────────────────────────────────────────────────

    def log_action(self, phase: str, action: str, result: str = ""):
        self.conn.execute(
            "INSERT INTO hunt_log (phase, action, result) VALUES (?,?,?)",
            (phase, action, result)
        )
        self.conn.commit()

    # ── Add finding ───────────────────────────────────────────────────────────

    def add(self, **kwargs) -> int:
        cols = [c for c in kwargs if kwargs[c] is not None]
        placeholders = ", ".join("?" * len(cols))
        col_str = ", ".join(cols)
        vals = [kwargs[c] for c in cols]
        cur = self.conn.execute(
            f"INSERT INTO findings ({col_str}) VALUES ({placeholders})", vals
        )
        self.conn.commit()
        return cur.lastrowid

    def interactive_add(self) -> int:
        """Walk the user through logging a new finding."""
        banner("Log New Finding")

        title    = ask("Title (e.g. IDOR in /api/users/{id}): ").strip()
        if not title:
            err("Title is required.")
            return -1

        print("  Vulnerability types: SQLi, XSS, IDOR, SSRF, SSTI, RCE, LFI, CSRF,")
        print("                       Open Redirect, CORS, Auth Bypass, Info Disclosure, Other")
        vuln_type = ask("Vuln type: ").strip()

        print("  Severities: critical / high / medium / low / info")
        severity = ask("Severity: ").strip().lower()
        while severity not in SEVERITY_ORDER:
            severity = ask("  Invalid. Enter critical/high/medium/low/info: ").strip().lower()

        cvss_score  = ask("CVSS score (e.g. 8.5, or blank): ").strip()
        cvss_vector = ask("CVSS vector (or blank): ").strip()
        endpoint    = ask("Endpoint URL: ").strip()
        method      = ask("HTTP method (GET/POST/...): ").strip().upper() or "GET"
        parameter   = ask("Vulnerable parameter (or blank): ").strip()
        description = ask("Short description: ").strip()
        impact      = ask("Impact: ").strip()
        poc         = ask("PoC / curl command (or blank): ").strip()
        notes       = ask("Notes (or blank): ").strip()

        fid = self.add(
            title=title,
            vuln_type=vuln_type,
            severity=severity,
            cvss_score=float(cvss_score) if cvss_score else None,
            cvss_vector=cvss_vector or None,
            endpoint=endpoint,
            method=method,
            parameter=parameter or None,
            description=description,
            impact=impact,
            poc=poc or None,
            notes=notes or None,
        )
        ok(f"Finding #{fid} logged: {title}")
        return fid

    # ── Query ─────────────────────────────────────────────────────────────────

    def get(self, fid: int) -> dict | None:
        row = self.conn.execute("SELECT * FROM findings WHERE id=?", (fid,)).fetchone()
        return dict(row) if row else None

    def all(self, severity: str = None, status: str = None) -> list[dict]:
        query = "SELECT * FROM findings WHERE 1=1"
        params = []
        if severity:
            query += " AND severity=?"
            params.append(severity.lower())
        if status:
            query += " AND status=?"
            params.append(status.lower())
        query += " ORDER BY CASE severity " \
                 "WHEN 'critical' THEN 1 WHEN 'high' THEN 2 " \
                 "WHEN 'medium' THEN 3 WHEN 'low' THEN 4 ELSE 5 END, id"
        rows = self.conn.execute(query, params).fetchall()
        return [dict(r) for r in rows]

    def update(self, fid: int, **kwargs):
        if not kwargs:
            return
        sets = ", ".join(f"{k}=?" for k in kwargs)
        vals = list(kwargs.values()) + [fid]
        self.conn.execute(f"UPDATE findings SET {sets} WHERE id=?", vals)
        self.conn.commit()
        ok(f"Finding #{fid} updated.")

    # ── Display ───────────────────────────────────────────────────────────────

    def list_findings(self, severity: str = None, status: str = None):
        findings = self.all(severity=severity, status=status)
        if not findings:
            info("No findings yet.")
            return

        banner("Findings")
        rows = []
        for f in findings:
            rows.append({
                "ID":       str(f["id"]),
                "SEV":      sev(f["severity"] or "info", (f["severity"] or "info").upper()[:4]),
                "CVSS":     str(f["cvss_score"] or "—"),
                "STATUS":   (f["status"] or "discovered")[:10],
                "TITLE":    (f["title"] or "")[:50],
                "ENDPOINT": (f["endpoint"] or "")[:40],
            })
        table(rows, ["ID", "SEV", "CVSS", "STATUS", "TITLE", "ENDPOINT"])
        print()
        self._print_stats(findings)

    def show_finding(self, fid: int):
        f = self.get(fid)
        if not f:
            err(f"Finding #{fid} not found.")
            return
        banner(f"Finding #{fid} — {f['title']}")
        fields = [
            ("Severity",    sev(f["severity"] or "info")),
            ("CVSS Score",  str(f["cvss_score"] or "—")),
            ("CVSS Vector", f["cvss_vector"] or "—"),
            ("Vuln Type",   f["vuln_type"] or "—"),
            ("Endpoint",    f["endpoint"] or "—"),
            ("Method",      f["method"] or "—"),
            ("Parameter",   f["parameter"] or "—"),
            ("Status",      f["status"] or "—"),
            ("Platform",    f["platform"] or "—"),
            ("Bounty",      f"${f['bounty_amount']}" if f["bounty_amount"] else "—"),
            ("Bounty Score", f"{f['bounty_score'] or '—'}"),
            ("Est. Payout", f"{f['estimated_payout'] or '—'}"),
            ("Priority Rank", f"{f['priority_rank'] or '—'}"),
            ("Created",     f["created_at"] or "—"),
            ("Reported",    f["reported_at"] or "—"),
        ]
        for k, v in fields:
            print(f"  {bold(k+':'):<22} {v}")
        if f["description"]:
            section("Description")
            print(f"  {f['description']}")
        if f["impact"]:
            section("Impact")
            print(f"  {f['impact']}")
        if f["poc"]:
            section("PoC")
            print(f"  {f['poc']}")
        if f["steps_to_reproduce"]:
            section("Steps to Reproduce")
            print(f["steps_to_reproduce"])
        if f["notes"]:
            section("Notes")
            print(f"  {f['notes']}")
        print()

    def _print_stats(self, findings: list[dict]):
        section("Summary")
        counts = {}
        for f in findings:
            s = f["severity"] or "info"
            counts[s] = counts.get(s, 0) + 1
        for s in SEVERITY_ORDER:
            if counts.get(s):
                print(f"  {sev(s, s.upper()):<20} {counts[s]}")
        total_bounty = sum(f["bounty_amount"] or 0 for f in findings if f["status"] == "paid")
        if total_bounty:
            print(f"\n  {bold('Total earned:')} ${total_bounty:.2f}")
        print()

    def stats(self):
        findings = self.all()
        banner("Findings Statistics")
        total = len(findings)
        info(f"Total findings: {total}")
        self._print_stats(findings)
        status_counts = {}
        for f in findings:
            s = f["status"] or "discovered"
            status_counts[s] = status_counts.get(s, 0) + 1
        section("By Status")
        for s, c in status_counts.items():
            print(f"  {s:<20} {c}")
        print()

    # ── Export ────────────────────────────────────────────────────────────────

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
            writer = csv.DictWriter(f, fieldnames=findings[0].keys())
            writer.writeheader()
            writer.writerows(findings)
        ok(f"Exported {len(findings)} findings → {path}")

    def export_markdown(self, path: str):
        findings = self.all()
        lines = ["# Findings Export\n"]
        for f in findings:
            lines.append(f"## #{f['id']} — {f['title']}\n")
            lines.append(f"**Severity:** {(f['severity'] or 'info').upper()}  ")
            lines.append(f"**CVSS:** {f['cvss_score'] or '—'}  ")
            lines.append(f"**Status:** {f['status'] or '—'}\n")
            if f["description"]:
                lines.append(f"{f['description']}\n")
            if f["endpoint"]:
                lines.append(f"**Endpoint:** `{f['endpoint']}`\n")
            lines.append("---\n")
        with open(path, "w") as f:
            f.write("\n".join(lines))
        ok(f"Exported {len(findings)} findings → {path}")
