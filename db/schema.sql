-- db/schema.sql
-- OneInfinity PostgreSQL Schema
-- Apply: psql $POSTGRES_URL -f db/schema.sql

CREATE EXTENSION IF NOT EXISTS "pgcrypto";

-- ── Scans ─────────────────────────────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS scans (
    id           UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    scan_id      TEXT UNIQUE NOT NULL,
    target       TEXT NOT NULL,
    scan_type    TEXT NOT NULL DEFAULT 'full',
    status       TEXT NOT NULL DEFAULT 'pending',
    created_at   TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    completed_at TIMESTAMPTZ,
    data         JSONB NOT NULL DEFAULT '{}'
);
CREATE INDEX IF NOT EXISTS idx_scans_target     ON scans(target);
CREATE INDEX IF NOT EXISTS idx_scans_status     ON scans(status);
CREATE INDEX IF NOT EXISTS idx_scans_created_at ON scans(created_at);
CREATE INDEX IF NOT EXISTS idx_scans_data       ON scans USING GIN(data);

-- ── Findings ─────────────────────────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS findings (
    id           UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    finding_id   TEXT UNIQUE NOT NULL,
    scan_id      TEXT,
    target       TEXT,
    title        TEXT,
    severity     TEXT NOT NULL DEFAULT 'info',
    vuln_type    TEXT,
    url          TEXT,
    tool         TEXT,
    confidence   DOUBLE PRECISION DEFAULT 0.8,
    cvss         DOUBLE PRECISION DEFAULT 0.0,
    status       TEXT NOT NULL DEFAULT 'new',
    source_type  TEXT DEFAULT 'tool',
    created_at   TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    data         JSONB NOT NULL DEFAULT '{}'
);
CREATE INDEX IF NOT EXISTS idx_findings_scan_id    ON findings(scan_id);
CREATE INDEX IF NOT EXISTS idx_findings_severity   ON findings(severity);
CREATE INDEX IF NOT EXISTS idx_findings_target     ON findings(target);
CREATE INDEX IF NOT EXISTS idx_findings_created_at ON findings(created_at);
CREATE INDEX IF NOT EXISTS idx_findings_data       ON findings USING GIN(data);

-- ── Agents (historical execution records) ────────────────────────────────────
CREATE TABLE IF NOT EXISTS agents (
    id          UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    scan_id     TEXT,
    agent_type  TEXT NOT NULL,
    status      TEXT NOT NULL DEFAULT 'running',
    started_at  TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    ended_at    TIMESTAMPTZ,
    data        JSONB NOT NULL DEFAULT '{}'
);
CREATE INDEX IF NOT EXISTS idx_agents_scan_id ON agents(scan_id);

-- ── Events (audit log / bus persistence) ─────────────────────────────────────
CREATE TABLE IF NOT EXISTS events (
    id          BIGSERIAL PRIMARY KEY,
    event_id    TEXT UNIQUE NOT NULL,
    event_type  TEXT NOT NULL,
    scan_id     TEXT,
    source      TEXT,
    created_at  TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    data        JSONB NOT NULL DEFAULT '{}'
);
CREATE INDEX IF NOT EXISTS idx_events_event_type ON events(event_type);
CREATE INDEX IF NOT EXISTS idx_events_scan_id    ON events(scan_id);
CREATE INDEX IF NOT EXISTS idx_events_created_at ON events(created_at);

-- ── Knowledge Base (fingerprints, CVE mappings, tool outputs) ────────────────
CREATE TABLE IF NOT EXISTS knowledge_base (
    id          UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    category    TEXT NOT NULL,
    key         TEXT NOT NULL,
    created_at  TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at  TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    data        JSONB NOT NULL DEFAULT '{}'
);
CREATE UNIQUE INDEX IF NOT EXISTS idx_kb_category_key ON knowledge_base(category, key);
CREATE INDEX IF NOT EXISTS idx_kb_category            ON knowledge_base(category);

-- ── Recon Assets (subdomains, IPs, endpoints) ─────────────────────────────────
CREATE TABLE IF NOT EXISTS recon_assets (
    id          UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    asset_id    TEXT UNIQUE NOT NULL,
    scan_id     TEXT,
    asset_type  TEXT,
    value       TEXT,
    created_at  TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    data        JSONB NOT NULL DEFAULT '{}'
);
CREATE INDEX IF NOT EXISTS idx_recon_assets_scan_id ON recon_assets(scan_id);
CREATE INDEX IF NOT EXISTS idx_recon_assets_type    ON recon_assets(asset_type);
