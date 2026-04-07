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
-- Dedup constraint: same (scan_id, vuln_type, url) is a duplicate within a scan.
-- Enables ON CONFLICT (scan_id, vuln_type, url) DO NOTHING RETURNING finding_id.
CREATE UNIQUE INDEX IF NOT EXISTS idx_findings_dedup
    ON findings(scan_id, vuln_type, url);

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

-- ── Targets ──────────────────────────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS targets (
    target_id       TEXT PRIMARY KEY,
    target_value    TEXT NOT NULL,
    target_type     TEXT NOT NULL DEFAULT 'web',
    name            TEXT NOT NULL DEFAULT '',
    platform        TEXT NOT NULL DEFAULT 'hackerone',
    scope           JSONB NOT NULL DEFAULT '[]',
    status          TEXT NOT NULL DEFAULT 'pending',
    created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    last_scan_time  TIMESTAMPTZ,
    vuln_count      INTEGER NOT NULL DEFAULT 0,
    severity_counts JSONB NOT NULL DEFAULT '{}'
);
CREATE INDEX IF NOT EXISTS idx_targets_status     ON targets(status);
CREATE INDEX IF NOT EXISTS idx_targets_created_at ON targets(created_at);

-- ── Research Sessions ────────────────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS research_sessions (
    session_id         TEXT PRIMARY KEY,
    target             TEXT NOT NULL,
    output_dir         TEXT NOT NULL DEFAULT '',
    platform           TEXT NOT NULL DEFAULT '',
    started_at         DOUBLE PRECISION,
    ended_at           DOUBLE PRECISION,
    status             TEXT NOT NULL DEFAULT 'running',
    iteration          INTEGER NOT NULL DEFAULT 0,
    theories_generated INTEGER NOT NULL DEFAULT 0,
    tests_executed     INTEGER NOT NULL DEFAULT 0,
    anomalies_found    INTEGER NOT NULL DEFAULT 0,
    confirmed_vulns    INTEGER NOT NULL DEFAULT 0
);
CREATE INDEX IF NOT EXISTS idx_research_sessions_target ON research_sessions(target);

-- ── Vulnerability Theories ───────────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS vuln_theories (
    theory_id   TEXT PRIMARY KEY,
    session_id  TEXT NOT NULL,
    target      TEXT NOT NULL,
    endpoint    TEXT NOT NULL DEFAULT '',
    vuln_type   TEXT NOT NULL,
    severity    TEXT NOT NULL DEFAULT 'medium',
    confidence  DOUBLE PRECISION NOT NULL DEFAULT 0.0,
    reasoning   TEXT NOT NULL DEFAULT '',
    status      TEXT NOT NULL DEFAULT 'pending',
    created_at  DOUBLE PRECISION,
    updated_at  DOUBLE PRECISION
);
CREATE INDEX IF NOT EXISTS idx_vuln_theories_session ON vuln_theories(session_id);
CREATE INDEX IF NOT EXISTS idx_vuln_theories_target  ON vuln_theories(target);

-- ── Test Outcomes ────────────────────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS test_outcomes (
    id               BIGSERIAL PRIMARY KEY,
    session_id       TEXT NOT NULL,
    theory_id        TEXT,
    target           TEXT NOT NULL,
    endpoint         TEXT NOT NULL DEFAULT '',
    vuln_type        TEXT NOT NULL,
    payload          TEXT NOT NULL DEFAULT '',
    status_code      INTEGER,
    response_size    INTEGER,
    response_time_ms DOUBLE PRECISION,
    anomaly_score    DOUBLE PRECISION NOT NULL DEFAULT 0.0,
    confirmed        INTEGER NOT NULL DEFAULT 0,
    evidence         TEXT NOT NULL DEFAULT '',
    tested_at        DOUBLE PRECISION
);
CREATE INDEX IF NOT EXISTS idx_test_outcomes_session ON test_outcomes(session_id);
CREATE INDEX IF NOT EXISTS idx_test_outcomes_theory  ON test_outcomes(theory_id);

-- ── Research Discoveries ─────────────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS research_discoveries (
    report_id     TEXT PRIMARY KEY,
    session_id    TEXT NOT NULL,
    target        TEXT NOT NULL,
    vuln_type     TEXT NOT NULL,
    title         TEXT NOT NULL DEFAULT '',
    severity      TEXT NOT NULL DEFAULT 'medium',
    confidence    DOUBLE PRECISION NOT NULL DEFAULT 0.0,
    endpoint      TEXT NOT NULL DEFAULT '',
    description   TEXT NOT NULL DEFAULT '',
    impact        TEXT NOT NULL DEFAULT '',
    steps         JSONB NOT NULL DEFAULT '[]',
    poc           TEXT NOT NULL DEFAULT '',
    remediation   TEXT NOT NULL DEFAULT '',
    evidence      TEXT NOT NULL DEFAULT '',
    cvss_score    DOUBLE PRECISION NOT NULL DEFAULT 0.0,
    discovered_at DOUBLE PRECISION,
    reported      INTEGER NOT NULL DEFAULT 0
);
CREATE INDEX IF NOT EXISTS idx_research_discoveries_session ON research_discoveries(session_id);
CREATE INDEX IF NOT EXISTS idx_research_discoveries_target  ON research_discoveries(target);

-- ── Cross-Target Patterns ────────────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS cross_target_patterns (
    id                BIGSERIAL PRIMARY KEY,
    vuln_type         TEXT NOT NULL,
    endpoint_pattern  TEXT NOT NULL DEFAULT '',
    parameter_pattern TEXT NOT NULL DEFAULT '',
    success_count     INTEGER NOT NULL DEFAULT 1,
    last_seen         DOUBLE PRECISION,
    notes             TEXT NOT NULL DEFAULT '',
    UNIQUE(vuln_type, endpoint_pattern, parameter_pattern)
);

-- ── Endpoint Insights (schema present; no active write path) ─────────────────
CREATE TABLE IF NOT EXISTS endpoint_insights (
    id                BIGSERIAL PRIMARY KEY,
    session_id        TEXT NOT NULL,
    target            TEXT NOT NULL,
    endpoint          TEXT NOT NULL DEFAULT '',
    method            TEXT NOT NULL DEFAULT 'GET',
    parameters        JSONB NOT NULL DEFAULT '[]',
    auth_required     INTEGER NOT NULL DEFAULT 0,
    sensitivity_score DOUBLE PRECISION NOT NULL DEFAULT 0.0,
    tags              JSONB NOT NULL DEFAULT '[]',
    tested_at         DOUBLE PRECISION
);
CREATE INDEX IF NOT EXISTS idx_endpoint_insights_session ON endpoint_insights(session_id);

-- ── Learning Scan Sessions ───────────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS learning_scan_sessions (
    session_id      TEXT PRIMARY KEY,
    target          TEXT NOT NULL,
    started_at      DOUBLE PRECISION NOT NULL DEFAULT 0,
    finished_at     DOUBLE PRECISION,
    phases          JSONB NOT NULL DEFAULT '[]',
    total_findings  INTEGER NOT NULL DEFAULT 0,
    tools_used      JSONB NOT NULL DEFAULT '[]',
    notes           TEXT NOT NULL DEFAULT ''
);
CREATE INDEX IF NOT EXISTS idx_learning_sessions_target ON learning_scan_sessions(target);

-- ── Learning Findings History ────────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS learning_findings (
    id            BIGSERIAL PRIMARY KEY,
    session_id    TEXT NOT NULL,
    target        TEXT NOT NULL,
    vuln_type     TEXT NOT NULL,
    severity      TEXT NOT NULL DEFAULT 'info',
    cvss_score    DOUBLE PRECISION,
    endpoint      TEXT NOT NULL DEFAULT '',
    parameter     TEXT NOT NULL DEFAULT '',
    source_tool   TEXT NOT NULL DEFAULT '',
    confirmed     INTEGER NOT NULL DEFAULT 1,
    chain_id      TEXT NOT NULL DEFAULT '',
    discovered_at DOUBLE PRECISION NOT NULL DEFAULT 0
);
CREATE INDEX IF NOT EXISTS idx_learning_findings_session ON learning_findings(session_id);
CREATE INDEX IF NOT EXISTS idx_learning_findings_target  ON learning_findings(target);
CREATE INDEX IF NOT EXISTS idx_learning_findings_vuln    ON learning_findings(vuln_type);

-- ── Tool Performance ─────────────────────────────────────────────────────────
-- Composite PK enables atomic ON CONFLICT DO UPDATE for EMA accumulation.
CREATE TABLE IF NOT EXISTS tool_performance (
    tool_name      TEXT NOT NULL,
    vuln_type      TEXT NOT NULL DEFAULT '',
    target_type    TEXT NOT NULL DEFAULT '',
    runs_total     INTEGER NOT NULL DEFAULT 0,
    runs_success   INTEGER NOT NULL DEFAULT 0,
    findings_total INTEGER NOT NULL DEFAULT 0,
    avg_duration_s DOUBLE PRECISION NOT NULL DEFAULT 0.0,
    last_updated   DOUBLE PRECISION,
    PRIMARY KEY (tool_name, vuln_type, target_type)
);

-- ── Target Profiles ──────────────────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS target_profiles (
    domain           TEXT PRIMARY KEY,
    tech_stack       JSONB NOT NULL DEFAULT '[]',
    waf_detected     TEXT NOT NULL DEFAULT '',
    scope_notes      TEXT NOT NULL DEFAULT '',
    historical_vulns JSONB NOT NULL DEFAULT '{}',
    last_scanned     DOUBLE PRECISION,
    scan_count       INTEGER NOT NULL DEFAULT 0
);

-- ── Pattern Library ──────────────────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS pattern_library (
    tech_stack_key   TEXT NOT NULL,
    vuln_type        TEXT NOT NULL,
    occurrence_count INTEGER NOT NULL DEFAULT 1,
    avg_cvss         DOUBLE PRECISION NOT NULL DEFAULT 0.0,
    best_tool        TEXT NOT NULL DEFAULT '',
    last_seen        DOUBLE PRECISION,
    PRIMARY KEY (tech_stack_key, vuln_type)
);

-- ── Raw Findings (pre-validation staging) ────────────────────────────────────
CREATE TABLE IF NOT EXISTS raw_findings (
    id         BIGSERIAL PRIMARY KEY,
    tool       TEXT NOT NULL DEFAULT '',
    raw_json   JSONB NOT NULL DEFAULT '{}',
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
CREATE INDEX IF NOT EXISTS idx_raw_findings_tool       ON raw_findings(tool);
CREATE INDEX IF NOT EXISTS idx_raw_findings_created_at ON raw_findings(created_at);
