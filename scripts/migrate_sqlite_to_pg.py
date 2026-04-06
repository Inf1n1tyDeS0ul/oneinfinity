#!/usr/bin/env python3
"""
scripts/migrate_sqlite_to_pg.py — One-time hard-cutover migration from SQLite to PostgreSQL.

EXECUTION FLOW:
  1. Stop system
  2. Run: python3 scripts/migrate_sqlite_to_pg.py
  3. If success: start system in Postgres mode (POSTGRES_URL set)
  4. If failure: Postgres untouched, system continues on SQLite

TRANSACTION MODEL:
  All inserts run inside a single Postgres transaction.
  On ANY error, the entire transaction rolls back.
  Postgres is either fully migrated or completely untouched.

USAGE:
  POSTGRES_URL=postgresql://user:pass@localhost/oneinfinity python3 scripts/migrate_sqlite_to_pg.py
  POSTGRES_URL=... python3 scripts/migrate_sqlite_to_pg.py --dry-run
"""
from __future__ import annotations

import argparse
import json
import logging
import os
import sqlite3
import sys
import uuid
from pathlib import Path
from typing import Optional

# Allow importing from project root
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

log = logging.getLogger("oneinfinity.migrate")
logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")


# ── Extract ───────────────────────────────────────────────────────────────────

def extract_findings(db_path: str) -> list[dict]:
    """Read all rows from SQLite findings table."""
    conn = sqlite3.connect(db_path, check_same_thread=False)
    conn.row_factory = sqlite3.Row
    try:
        rows = conn.execute(
            "SELECT finding_id, scan_id, target, title, severity, vuln_type, evidence, "
            "payload, url, tool, confidence, cvss, status, source_type, created_at, raw_json "
            "FROM findings ORDER BY rowid"
        ).fetchall()
        return [dict(r) for r in rows]
    except sqlite3.OperationalError:
        log.warning("No 'findings' table in %s — skipping", db_path)
        return []
    finally:
        conn.close()


def extract_recon_assets(db_path: str) -> list[dict]:
    conn = sqlite3.connect(db_path, check_same_thread=False)
    conn.row_factory = sqlite3.Row
    try:
        rows = conn.execute(
            "SELECT asset_id, scan_id, asset_type, value, metadata_json, created_at "
            "FROM recon_assets ORDER BY rowid"
        ).fetchall()
        return [dict(r) for r in rows]
    except sqlite3.OperationalError:
        return []
    finally:
        conn.close()


def extract_events(db_path: str) -> list[dict]:
    conn = sqlite3.connect(db_path, check_same_thread=False)
    conn.row_factory = sqlite3.Row
    try:
        rows = conn.execute(
            "SELECT event_id, event_type, source, data, timestamp, correlation_id "
            "FROM events ORDER BY rowid"
        ).fetchall()
        return [dict(r) for r in rows]
    except sqlite3.OperationalError:
        return []
    finally:
        conn.close()


# ── Transform ─────────────────────────────────────────────────────────────────

def transform_finding(row: dict) -> dict:
    """Map SQLite finding row to Postgres findings schema."""
    data = {
        "evidence":         row.get("evidence", ""),
        "payload":          row.get("payload", ""),
        "reproduction_cmd": "",
        "poc_steps":        [],
        "raw":              {},
    }
    try:
        raw_json = row.get("raw_json") or "{}"
        data["raw"] = json.loads(raw_json) if isinstance(raw_json, str) else raw_json
    except Exception:
        pass
    return {
        "finding_id":  row["finding_id"],
        "scan_id":     row.get("scan_id", ""),
        "target":      row.get("target", ""),
        "title":       row.get("title", ""),
        "severity":    row.get("severity", "info"),
        "vuln_type":   row.get("vuln_type", ""),
        "url":         row.get("url", ""),
        "tool":        row.get("tool", ""),
        "confidence":  float(row.get("confidence") or 0.8),
        "cvss":        float(row.get("cvss") or 0.0),
        "status":      row.get("status", "new"),
        "source_type": row.get("source_type", "tool"),
        "created_at":  row.get("created_at", "NOW()"),
        "data":        json.dumps(data, default=str),
    }


def transform_recon_asset(row: dict) -> dict:
    try:
        meta = json.loads(row.get("metadata_json") or "{}")
    except Exception:
        meta = {}
    return {
        "asset_id":   row["asset_id"],
        "scan_id":    row.get("scan_id", ""),
        "asset_type": row.get("asset_type", ""),
        "value":      row.get("value", ""),
        "created_at": row.get("created_at", "NOW()"),
        "data":       json.dumps(meta, default=str),
    }


def transform_event(row: dict) -> dict:
    try:
        data = json.loads(row.get("data") or "{}")
    except Exception:
        data = {}
    return {
        "event_id":   row.get("event_id", str(uuid.uuid4())),
        "event_type": row.get("event_type", "UNKNOWN"),
        "scan_id":    row.get("correlation_id"),
        "source":     row.get("source", "platform"),
        "data":       json.dumps(data, default=str),
    }


# ── Load ──────────────────────────────────────────────────────────────────────

_APPLY_SCHEMA_SQL = Path(__file__).resolve().parent.parent / "db" / "schema.sql"


def run_migration(
    postgres_url: str,
    sqlite_paths: dict,  # {"findings": path, "events": path}
    dry_run: bool = False,
) -> dict:
    """
    Execute hard-cutover migration.

    All inserts happen inside ONE transaction.
    On any failure: transaction rolls back, Postgres untouched.
    Returns: {"findings": n, "recon_assets": n, "events": n}

    Raises on failure — caller must treat any exception as ABORT.
    """
    import psycopg

    log.info("Connecting to Postgres: %s", _safe_url(postgres_url))
    conn = psycopg.connect(postgres_url, autocommit=False)

    try:
        # Apply schema first (idempotent — CREATE TABLE IF NOT EXISTS)
        if _APPLY_SCHEMA_SQL.exists():
            log.info("Applying schema...")
            conn.execute(_APPLY_SCHEMA_SQL.read_text())

        counts = {"findings": 0, "recon_assets": 0, "events": 0}

        # ── Findings ─────────────────────────────────────────────────────────
        findings_path = sqlite_paths.get("findings")
        if findings_path and Path(findings_path).exists():
            rows = extract_findings(findings_path)
            log.info("Migrating %d findings...", len(rows))
            for row in rows:
                pg = transform_finding(row)
                if not dry_run:
                    conn.execute(
                        """
                        INSERT INTO findings
                            (finding_id,scan_id,target,title,severity,vuln_type,
                             url,tool,confidence,cvss,status,source_type,data)
                        VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s)
                        ON CONFLICT (finding_id) DO NOTHING
                        """,
                        (
                            pg["finding_id"], pg["scan_id"], pg["target"],
                            pg["title"], pg["severity"], pg["vuln_type"],
                            pg["url"], pg["tool"], pg["confidence"], pg["cvss"],
                            pg["status"], pg["source_type"], pg["data"],
                        ),
                    )
                counts["findings"] += 1

            # Recon assets
            assets = extract_recon_assets(findings_path)
            log.info("Migrating %d recon assets...", len(assets))
            for row in assets:
                pg = transform_recon_asset(row)
                if not dry_run:
                    conn.execute(
                        """
                        INSERT INTO recon_assets (asset_id,scan_id,asset_type,value,data)
                        VALUES (%s,%s,%s,%s,%s)
                        ON CONFLICT (asset_id) DO NOTHING
                        """,
                        (pg["asset_id"], pg["scan_id"], pg["asset_type"], pg["value"], pg["data"]),
                    )
                counts["recon_assets"] += 1

        # ── Events ────────────────────────────────────────────────────────────
        events_path = sqlite_paths.get("events")
        if events_path and Path(events_path).exists():
            rows = extract_events(events_path)
            log.info("Migrating %d events...", len(rows))
            for row in rows:
                pg = transform_event(row)
                if not dry_run:
                    conn.execute(
                        """
                        INSERT INTO events (event_id,event_type,scan_id,source,data)
                        VALUES (%s,%s,%s,%s,%s)
                        ON CONFLICT (event_id) DO NOTHING
                        """,
                        (pg["event_id"], pg["event_type"], pg["scan_id"], pg["source"], pg["data"]),
                    )
                counts["events"] += 1

        # ── Validate ──────────────────────────────────────────────────────────
        if not dry_run:
            _validate(conn, sqlite_paths, counts)
            conn.commit()
            log.info("Migration committed. Counts: %s", counts)
        else:
            conn.rollback()
            log.info("DRY RUN complete (rolled back). Would migrate: %s", counts)

        return counts

    except Exception as exc:
        conn.rollback()
        log.error("Migration FAILED — rolled back. Postgres untouched. Error: %s", exc)
        raise
    finally:
        conn.close()


def _validate(conn, sqlite_paths: dict, expected: dict) -> None:
    """Verify Postgres row counts match expected."""
    errors = []
    if expected["findings"] > 0:
        pg_count = conn.execute("SELECT COUNT(*) FROM findings").fetchone()[0]
        if pg_count < expected["findings"]:
            errors.append(f"findings: expected >={expected['findings']}, got {pg_count}")
    if errors:
        raise ValueError(f"Validation failed: {'; '.join(errors)}")
    log.info("Validation passed: %s", expected)


def _safe_url(url: str) -> str:
    try:
        from urllib.parse import urlparse
        p = urlparse(url)
        return f"postgresql://{p.hostname}{(':' + str(p.port)) if p.port else ''}{p.path}"
    except Exception:
        return "postgresql://***"


def _resolve_sqlite_paths() -> dict:
    """Locate all SQLite DBs using path_manager."""
    try:
        import path_manager
        return {
            "findings": str(path_manager.findings_db_path()),
            "events":   str(path_manager.db_path("event_bus.db")),
        }
    except Exception:
        home = Path.home() / ".oneinfinity" / "databases"
        return {
            "findings": str(home / "findings.db"),
            "events":   str(home / "event_bus.db"),
        }


# ── CLI entrypoint ────────────────────────────────────────────────────────────

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Migrate OneInfinity SQLite → PostgreSQL")
    parser.add_argument("--dry-run", action="store_true", help="Preview without writing")
    parser.add_argument("--postgres-url", default=os.environ.get("POSTGRES_URL", ""),
                        help="Postgres connection string")
    parser.add_argument(
        "--check",
        action="store_true",
        default=False,
        help="Dry-run: report SQLite row counts and Postgres connectivity. No writes.",
    )
    args = parser.parse_args()

    if args.check:
        import sys as _sys
        print("\n=== Migration Check Mode (read-only) ===\n")
        # Find SQLite databases
        try:
            import path_manager as _pm
            dbs = {
                "findings.db": str(_pm.findings_db_path()),
                "metadata.db": str(_pm.db_path("metadata.db")),
            }
        except Exception:
            dbs = {}
            print("  WARNING: path_manager unavailable, cannot locate SQLite files")
        for label, db_path in dbs.items():
            if Path(db_path).exists():
                try:
                    conn = sqlite3.connect(db_path)
                    for table in ("findings", "scan_history"):
                        try:
                            count = conn.execute(f"SELECT COUNT(*) FROM {table}").fetchone()[0]
                            print(f"  {label} / {table}: {count} rows")
                        except sqlite3.OperationalError:
                            print(f"  {label} / {table}: table not found")
                    conn.close()
                except Exception as e:
                    print(f"  {label}: error reading — {e}")
            else:
                print(f"  {label}: not found at {db_path}")
        # Check Postgres connectivity
        pg_url = os.environ.get("POSTGRES_URL", "")
        if pg_url:
            try:
                import psycopg
                with psycopg.connect(pg_url) as conn:
                    conn.execute("SELECT 1")
                print(f"\n  PostgreSQL: reachable at {pg_url[:50]}...")
            except Exception as exc:
                print(f"\n  PostgreSQL: UNREACHABLE — {exc}")
        else:
            print("\n  PostgreSQL: POSTGRES_URL not set")
        print("\n=== End Check ===\n")
        _sys.exit(0)

    if not args.postgres_url:
        log.error("POSTGRES_URL not set. Set via env or --postgres-url flag.")
        sys.exit(1)

    sqlite_paths = _resolve_sqlite_paths()
    log.info("SQLite sources: %s", sqlite_paths)

    try:
        counts = run_migration(
            postgres_url=args.postgres_url,
            sqlite_paths=sqlite_paths,
            dry_run=args.dry_run,
        )
        print(f"\n{'DRY RUN' if args.dry_run else 'MIGRATION'} COMPLETE: {counts}")
    except Exception as exc:
        print(f"\nMIGRATION FAILED: {exc}")
        sys.exit(1)
