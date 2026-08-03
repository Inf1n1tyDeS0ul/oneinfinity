-- db/migrations/002_add_confirmed_tier.sql
-- Phase 0 — Verified Finding Architecture
--
-- Adds the three-tier confidence system to the findings table.
--
-- confirmed_tier  VARCHAR(12)  — CONFIRMED | INFERRED | CANDIDATE | NULL (not yet judged)
--   CONFIRMED  — PoC replayed and judge verified exploitation
--   INFERRED   — Multiple strong corroborating signals, no replay
--   CANDIDATE  — Single pattern match, needs review
--
-- judge_verdict is stored inside the existing data JSONB column (no new column needed;
-- the data column is already read and merged into every API response by _pg_get_findings).
--
-- discovered_by  TEXT[]   — model IDs that independently found this finding.
--   When multiple models find the same finding, confidence auto-promotes to CONFIRMED.
--
-- Apply:  psql $POSTGRES_URL -f db/migrations/002_add_confirmed_tier.sql
-- Rollback: see bottom of this file

BEGIN;

-- 1. Add confirmed_tier column (idempotent)
ALTER TABLE findings
    ADD COLUMN IF NOT EXISTS confirmed_tier VARCHAR(12) DEFAULT NULL;

-- 2. Add discovered_by column — tracks which models found this finding
ALTER TABLE findings
    ADD COLUMN IF NOT EXISTS discovered_by TEXT[] DEFAULT '{}';

-- 3. Add judge_ran_at — timestamp so we can see when the judge last evaluated
ALTER TABLE findings
    ADD COLUMN IF NOT EXISTS judge_ran_at TIMESTAMPTZ DEFAULT NULL;

-- 4. Index on confirmed_tier for fast filtering in the dashboard
--    (e.g. "show me only CONFIRMED findings")
CREATE INDEX IF NOT EXISTS idx_findings_confirmed_tier
    ON findings(confirmed_tier);

-- 5. Index on discovered_by using GIN for array containment queries
--    (e.g. "findings that Claude found: WHERE 'claude-opus' = ANY(discovered_by)")
CREATE INDEX IF NOT EXISTS idx_findings_discovered_by
    ON findings USING GIN(discovered_by);

-- 6. Track migration in registry (auto-created if not exists)
CREATE TABLE IF NOT EXISTS migrations_registry (
    migration_id   TEXT PRIMARY KEY,
    applied_at     TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    description    TEXT NOT NULL DEFAULT ''
);

INSERT INTO migrations_registry (migration_id, description)
VALUES ('002_add_confirmed_tier',
        'Add confirmed_tier, discovered_by, judge_ran_at to findings table')
ON CONFLICT (migration_id) DO NOTHING;

COMMIT;

-- ── Verification ─────────────────────────────────────────────────────────────
-- SELECT column_name, data_type
-- FROM information_schema.columns
-- WHERE table_name = 'findings'
--   AND column_name IN ('confirmed_tier', 'discovered_by', 'judge_ran_at');
--
-- SELECT indexname FROM pg_indexes
-- WHERE tablename = 'findings'
--   AND indexname IN ('idx_findings_confirmed_tier', 'idx_findings_discovered_by');

-- ── Rollback ─────────────────────────────────────────────────────────────────
-- BEGIN;
-- DROP INDEX IF EXISTS idx_findings_confirmed_tier;
-- DROP INDEX IF EXISTS idx_findings_discovered_by;
-- ALTER TABLE findings DROP COLUMN IF EXISTS confirmed_tier;
-- ALTER TABLE findings DROP COLUMN IF EXISTS discovered_by;
-- ALTER TABLE findings DROP COLUMN IF EXISTS judge_ran_at;
-- DELETE FROM migrations_registry WHERE migration_id = '002_add_confirmed_tier';
-- COMMIT;
