# Database Migrations

**OneInfinity Schema Evolution**  
Current Version: 2.0 (2026-05-26)

---

## Automatic Migrations (Phase 8 Implementation)

As of version 2.0, **manual migration application is no longer required**. The `UnifiedScanEngine` and the web backend automatically detect and apply missing migrations at startup and before scan execution.

- **Storage**: Migration state is tracked in the `migrations_registry` table.
- **Conflict Handling**: The system uses advisory locks to ensure only one process applies a migration at a time.
- **Rollback**: Manual rollbacks still require `psql`, but the system will never auto-apply a migration that has been explicitly marked as failed.

---

## Historical Migrations (Reference Only)

### Migration 001: Content-Based Deduplication (Phase 4 Fix)

**Date:** 2026-05-26  
**Version:** 1.0.0 → 1.0.1  
**Required:** Yes (for PostgreSQL users)  
**Breaking:** No

**What Changed:**
- Added `content_hash` generated column to `findings` table
- Changed dedup index from `(scan_id, vuln_type, url)` to `(content_hash)`
- Prevents data loss for multi-parameter vulnerabilities

**Apply Migration:**

```bash
psql $POSTGRES_URL -f db/migrations/001_add_content_hash.sql
```

**Migration Script:**

```sql
-- Add content_hash column
ALTER TABLE findings ADD COLUMN IF NOT EXISTS content_hash TEXT
    GENERATED ALWAYS AS (
        encode(
            sha256(
                (COALESCE(scan_id, '') || '|' ||
                 COALESCE(vuln_type, '') || '|' ||
                 COALESCE(url, '') || '|' ||
                 COALESCE(data->>'payload', '') || '|' ||
                 COALESCE(data->>'param', '') || '|' ||
                 COALESCE(data->>'evidence', ''))::bytea
            ),
            'hex'
        )
    ) STORED;

-- Drop old index
DROP INDEX IF EXISTS idx_findings_dedup;

-- Create new index
CREATE UNIQUE INDEX idx_findings_dedup ON findings(content_hash);
```

**Verification:**

```sql
-- Check column exists
SELECT column_name, data_type, is_generated 
FROM information_schema.columns 
WHERE table_name = 'findings' AND column_name = 'content_hash';

-- Check index exists
SELECT indexname FROM pg_indexes 
WHERE tablename = 'findings' AND indexname = 'idx_findings_dedup';

-- Test deduplication
INSERT INTO findings (finding_id, scan_id, vuln_type, url, data) 
VALUES ('test1', 'scan1', 'xss', '/api', '{"param": "id"}');

INSERT INTO findings (finding_id, scan_id, vuln_type, url, data) 
VALUES ('test2', 'scan1', 'xss', '/api', '{"param": "name"}');
-- Should succeed (different params = different hash)
```

**Rollback:**

```sql
DROP INDEX IF EXISTS idx_findings_dedup;
ALTER TABLE findings DROP COLUMN IF EXISTS content_hash;
CREATE UNIQUE INDEX idx_findings_dedup ON findings(scan_id, vuln_type, url);
```

**Downtime:** None (online migration)

---
### Migration 002: Three-Tier Confidence System (Phase 0 — Verified Finding Architecture)

**Date:** 2026-08-03
**Version:** 2.0 → 3.0
**Required:** Yes (for PostgreSQL users)
**Breaking:** No (all new columns are nullable / have defaults)

**What Changed:**
- Added `confirmed_tier VARCHAR(12)` column: `CONFIRMED` | `INFERRED` | `CANDIDATE` | `NULL`
- Added `discovered_by TEXT[]` column: model IDs that independently discovered this finding
- Added `judge_ran_at TIMESTAMPTZ` column: timestamp of last judge evaluation
- Added `migrations_registry` table (if not exists) for tracking applied migrations
- `judge_verdict` dict is stored inside the existing `data JSONB` column (no separate column)

**Apply Migration:**

```bash
psql $POSTGRES_URL -f db/migrations/002_add_confirmed_tier.sql
```

**Verification:**

```sql
SELECT column_name, data_type
FROM information_schema.columns
WHERE table_name = 'findings'
  AND column_name IN ('confirmed_tier', 'discovered_by', 'judge_ran_at');
-- Must return 3 rows

SELECT * FROM migrations_registry WHERE migration_id = '002_add_confirmed_tier';
-- Must return 1 row
```

**Rollback:** See bottom of `db/migrations/002_add_confirmed_tier.sql`.

**Downtime:** None (online migration — all columns are additive).

---


## Migration History

| Version | Date | Description | Required |
|---------|------|-------------|----------|
| 3.0 | 2026-08-03 | Three-tier confidence (confirmed_tier, discovered_by, judge_ran_at) | ✅ Yes |
| 2.0 | 2026-05-26 | Content-based dedup | ✅ Yes |
| 1.0 | 2026-04-01 | Initial schema | N/A |

---

## SQLite Users

**No Migration Required**

SQLite users use in-memory deduplication. Schema changes only affect PostgreSQL.

---

## Applying Multiple Migrations

```bash
# Apply all pending migrations
for f in db/migrations/*.sql; do
    echo "Applying $f..."
    psql $POSTGRES_URL -f "$f"
done
```

---

## Pre-Migration Checklist

- [ ] Backup database
- [ ] Test on staging first
- [ ] Verify disk space (minimal needed)
- [ ] Check PostgreSQL version (9.6+)
- [ ] Note current schema version
- [ ] Plan rollback window

---

## Post-Migration Validation

```bash
# Run tests
python -m pytest tests/ -k "db" -v

# Check finding counts
psql $POSTGRES_URL -c "SELECT COUNT(*) FROM findings;"

# Verify dedup working
# (Run same scan twice, count should stay same)
```

---

**Questions?** See [PHASE4_5_COMBINED_FIX_EVIDENCE.md](../PHASE4_5_COMBINED_FIX_EVIDENCE.md)
