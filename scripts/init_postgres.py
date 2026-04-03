#!/usr/bin/env python3
"""
scripts/init_postgres.py — Apply db/schema.sql to Postgres.

Run before starting the system for the first time with POSTGRES_URL set.
Idempotent — uses CREATE TABLE IF NOT EXISTS.

USAGE:
  POSTGRES_URL=postgresql://user:pass@localhost/oneinfinity python3 scripts/init_postgres.py
"""
import os, sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

SCHEMA = Path(__file__).resolve().parent.parent / "db" / "schema.sql"


def init_postgres(postgres_url: str) -> None:
    import psycopg
    sql = SCHEMA.read_text()
    with psycopg.connect(postgres_url, autocommit=True) as conn:
        conn.execute(sql)
    print("✅ Schema applied successfully")


if __name__ == "__main__":
    url = os.environ.get("POSTGRES_URL", "")
    if not url:
        print("❌ POSTGRES_URL not set")
        sys.exit(1)
    init_postgres(url)
