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
    source_tool  TEXT DEFAULT '',
    confidence   DOUBLE PRECISION DEFAULT 0.8,
    cvss         DOUBLE PRECISION DEFAULT 0.0,
    status       TEXT NOT NULL DEFAULT 'new',
    source_type  TEXT DEFAULT 'tool',
    chain_id     TEXT DEFAULT '',
    evidence     TEXT DEFAULT '',
    created_at   TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    data         JSONB NOT NULL DEFAULT '{}'
);
CREATE INDEX IF NOT EXISTS idx_findings_scan_id    ON findings(scan_id);
CREATE INDEX IF NOT EXISTS idx_findings_severity   ON findings(severity);
CREATE INDEX IF NOT EXISTS idx_findings_target     ON findings(target);
CREATE INDEX IF NOT EXISTS idx_findings_created_at ON findings(created_at);
CREATE INDEX IF NOT EXISTS idx_findings_chain_id   ON findings(chain_id);
CREATE INDEX IF NOT EXISTS idx_findings_source_tool ON findings(source_tool);
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

-- ── Graph Nodes and Edges (attack_graph_core) ─────────────────────────────────
CREATE TABLE IF NOT EXISTS graph_nodes (
    id              TEXT PRIMARY KEY,
    node_type       TEXT NOT NULL,
    label           TEXT NOT NULL,
    properties_json TEXT DEFAULT '{}',
    severity        TEXT,
    risk_score      DOUBLE PRECISION DEFAULT 0.0,
    exploitable     BOOLEAN DEFAULT FALSE,
    validated       BOOLEAN DEFAULT FALSE,
    discovered_at   TEXT,
    updated_at      TEXT,
    source          TEXT DEFAULT '',
    tags_json       TEXT DEFAULT '[]'
);
CREATE INDEX IF NOT EXISTS idx_graph_nodes_type  ON graph_nodes(node_type);
CREATE INDEX IF NOT EXISTS idx_graph_nodes_label ON graph_nodes(label);

CREATE TABLE IF NOT EXISTS graph_edges (
    id              TEXT PRIMARY KEY,
    source_id       TEXT NOT NULL,
    target_id       TEXT NOT NULL,
    edge_type       TEXT NOT NULL,
    label           TEXT DEFAULT '',
    properties_json TEXT DEFAULT '{}',
    probability     DOUBLE PRECISION DEFAULT 1.0,
    weight          DOUBLE PRECISION DEFAULT 1.0,
    requires_auth   BOOLEAN DEFAULT FALSE,
    created_at      TEXT,
    source_engine   TEXT DEFAULT ''
);
CREATE INDEX IF NOT EXISTS idx_graph_edges_src ON graph_edges(source_id);
CREATE INDEX IF NOT EXISTS idx_graph_edges_dst ON graph_edges(target_id);

-- ── Traffic Capture ───────────────────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS captured_requests (
    id               TEXT PRIMARY KEY,
    method           TEXT NOT NULL,
    url              TEXT NOT NULL,
    headers          TEXT DEFAULT '{}',
    body             TEXT DEFAULT '',
    response_status  INTEGER DEFAULT 0,
    response_headers TEXT DEFAULT '{}',
    response_body    TEXT DEFAULT '',
    source           TEXT DEFAULT 'unknown',
    target_domain    TEXT DEFAULT '',
    proxied          BOOLEAN DEFAULT FALSE,
    proxy_address    TEXT DEFAULT '',
    timestamp        TEXT NOT NULL,
    duration_ms      INTEGER DEFAULT 0,
    tags             TEXT DEFAULT '[]',
    vuln_id          TEXT DEFAULT '',
    attack_type      TEXT DEFAULT '',
    flagged          BOOLEAN DEFAULT FALSE,
    flag_reason      TEXT DEFAULT ''
);
CREATE INDEX IF NOT EXISTS idx_cap_url       ON captured_requests(url);
CREATE INDEX IF NOT EXISTS idx_cap_target    ON captured_requests(target_domain);
CREATE INDEX IF NOT EXISTS idx_cap_source    ON captured_requests(source);
CREATE INDEX IF NOT EXISTS idx_cap_timestamp ON captured_requests(timestamp);
CREATE INDEX IF NOT EXISTS idx_cap_flagged   ON captured_requests(flagged);

-- ── Memory Manager ────────────────────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS attack_patterns (
    id               TEXT PRIMARY KEY,
    vuln_type        TEXT NOT NULL,
    target_tech      TEXT DEFAULT '',
    payload          TEXT DEFAULT '',
    endpoint_pattern TEXT DEFAULT '',
    cvss             DOUBLE PRECISION DEFAULT 0,
    success_rate     DOUBLE PRECISION DEFAULT 0,
    occurrences      INTEGER DEFAULT 1,
    last_seen        DOUBLE PRECISION NOT NULL,
    agent_source     TEXT DEFAULT '',
    meta             TEXT DEFAULT '{}'
);
CREATE INDEX IF NOT EXISTS idx_attack_patterns_vuln ON attack_patterns(vuln_type);
CREATE INDEX IF NOT EXISTS idx_attack_patterns_tech ON attack_patterns(target_tech);

CREATE TABLE IF NOT EXISTS exploit_chain_records (
    id               TEXT PRIMARY KEY,
    chain_name       TEXT NOT NULL,
    steps            TEXT NOT NULL,
    target           TEXT DEFAULT '',
    cvss_combined    DOUBLE PRECISION DEFAULT 0,
    confirmed        BOOLEAN DEFAULT FALSE,
    session_id       TEXT DEFAULT '',
    discovered_at    DOUBLE PRECISION NOT NULL,
    description      TEXT DEFAULT '',
    remediation      TEXT DEFAULT ''
);
CREATE INDEX IF NOT EXISTS idx_exploit_chain_records_name ON exploit_chain_records(chain_name);

CREATE TABLE IF NOT EXISTS learning_insights (
    id               TEXT PRIMARY KEY,
    category         TEXT NOT NULL,
    title            TEXT NOT NULL,
    body             TEXT DEFAULT '',
    confidence       DOUBLE PRECISION DEFAULT 0.5,
    source_event     TEXT DEFAULT '',
    tags             TEXT DEFAULT '[]',
    created_at       DOUBLE PRECISION NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_learning_insights_cat ON learning_insights(category);
CREATE INDEX IF NOT EXISTS idx_learning_insights_ts  ON learning_insights(created_at);

CREATE TABLE IF NOT EXISTS scan_summaries (
    session_id           TEXT PRIMARY KEY,
    target               TEXT NOT NULL,
    started_at           DOUBLE PRECISION NOT NULL,
    finished_at          DOUBLE PRECISION NOT NULL,
    phases               TEXT DEFAULT '[]',
    total_findings       INTEGER DEFAULT 0,
    confirmed_findings   INTEGER DEFAULT 0,
    critical_count       INTEGER DEFAULT 0,
    high_count           INTEGER DEFAULT 0,
    tools_used           TEXT DEFAULT '[]',
    new_patterns         INTEGER DEFAULT 0,
    new_chains           INTEGER DEFAULT 0,
    insights_generated   INTEGER DEFAULT 0
);

CREATE TABLE IF NOT EXISTS capability_snapshots (
    id               BIGSERIAL PRIMARY KEY,
    snapshot_at      DOUBLE PRECISION NOT NULL,
    capabilities     TEXT NOT NULL,
    total_count      INTEGER DEFAULT 0,
    delta_from_prev  INTEGER DEFAULT 0,
    trigger_event    TEXT DEFAULT ''
);

CREATE TABLE IF NOT EXISTS architecture_changelog (
    id               BIGSERIAL PRIMARY KEY,
    changed_at       DOUBLE PRECISION NOT NULL,
    change_type      TEXT NOT NULL,
    section          TEXT DEFAULT '',
    summary          TEXT NOT NULL,
    trigger_event    TEXT DEFAULT '',
    meta             TEXT DEFAULT '{}'
);

-- ── Model Budget ──────────────────────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS model_usage (
    id             BIGSERIAL PRIMARY KEY,
    model_id       TEXT             NOT NULL,
    provider       TEXT             NOT NULL DEFAULT '',
    task_id        TEXT             NOT NULL DEFAULT '',
    task_category  TEXT             NOT NULL DEFAULT 'GENERAL',
    input_tokens   INTEGER          NOT NULL DEFAULT 0,
    output_tokens  INTEGER          NOT NULL DEFAULT 0,
    cost_usd       DOUBLE PRECISION NOT NULL DEFAULT 0.0,
    duration_ms    DOUBLE PRECISION NOT NULL DEFAULT 0.0,
    escalation     BOOLEAN          NOT NULL DEFAULT FALSE,
    timestamp      DOUBLE PRECISION NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_model_usage_ts    ON model_usage(timestamp);
CREATE INDEX IF NOT EXISTS idx_model_usage_model ON model_usage(model_id, timestamp);

-- ── Recon Cache ───────────────────────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS recon_cache (
    cache_key   TEXT             PRIMARY KEY,
    tool        TEXT             NOT NULL,
    target      TEXT             NOT NULL,
    extra       TEXT             DEFAULT '',
    data        TEXT             NOT NULL,
    created_at  DOUBLE PRECISION NOT NULL,
    expires_at  DOUBLE PRECISION NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_recon_cache_tool_target ON recon_cache(tool, target);
CREATE INDEX IF NOT EXISTS idx_recon_cache_expires     ON recon_cache(expires_at);

-- ── Adversarial Prompt Evolution ─────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS prompt_genes (
    prompt_id           TEXT             PRIMARY KEY,
    text                TEXT             NOT NULL,
    attack_type         TEXT             NOT NULL,
    source              TEXT             NOT NULL,
    parent_ids          TEXT             DEFAULT '[]',
    generation          INTEGER          DEFAULT 0,
    mutation_type       TEXT             DEFAULT '',
    times_tested        INTEGER          DEFAULT 0,
    times_succeeded     INTEGER          DEFAULT 0,
    last_success_score  DOUBLE PRECISION DEFAULT 0.0,
    fitness             DOUBLE PRECISION DEFAULT 0.0,
    created_at          DOUBLE PRECISION NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_prompt_genes_attack ON prompt_genes(attack_type);

CREATE TABLE IF NOT EXISTS test_results (
    result_id       TEXT             PRIMARY KEY,
    prompt_id       TEXT             NOT NULL,
    target          TEXT             NOT NULL,
    response_hash   TEXT             NOT NULL,
    success         BOOLEAN          NOT NULL,
    score           DOUBLE PRECISION NOT NULL,
    attack_type     TEXT             NOT NULL,
    mutation_type   TEXT             DEFAULT '',
    tested_at       DOUBLE PRECISION NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_test_results_prompt ON test_results(prompt_id);

CREATE TABLE IF NOT EXISTS strategy_stats (
    strategy        TEXT             NOT NULL,
    attack_type     TEXT             NOT NULL,
    total_attempts  INTEGER          DEFAULT 0,
    total_successes INTEGER          DEFAULT 0,
    avg_score       DOUBLE PRECISION DEFAULT 0.0,
    PRIMARY KEY(strategy, attack_type)
);

-- ── Mobile Apps ───────────────────────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS mobile_apps (
    id               TEXT    PRIMARY KEY,
    filename         TEXT,
    platform         TEXT,
    package_name     TEXT,
    app_name         TEXT,
    version_name     TEXT,
    version_code     TEXT,
    min_sdk          TEXT,
    target_sdk       TEXT,
    file_size        INTEGER DEFAULT 0,
    sha256           TEXT,
    upload_path      TEXT,
    extract_path     TEXT,
    uploaded_at      TEXT,
    analysis_status  TEXT    DEFAULT 'uploaded',
    metadata         TEXT    DEFAULT '{}'
);
CREATE INDEX IF NOT EXISTS idx_mobile_apps_package  ON mobile_apps(package_name);
CREATE INDEX IF NOT EXISTS idx_mobile_apps_platform ON mobile_apps(platform);

-- ── Framework / Orchestrator tables (ExtendedDB) ────────────────────────────
CREATE TABLE IF NOT EXISTS scan_sessions (
    id            BIGSERIAL PRIMARY KEY,
    target        TEXT,
    auth_type     TEXT,
    auth_ref      TEXT,
    phase_reached INTEGER DEFAULT 0,
    status        TEXT DEFAULT 'running',
    started_at    TIMESTAMPTZ DEFAULT NOW(),
    completed_at  TIMESTAMPTZ
);
CREATE INDEX IF NOT EXISTS idx_scan_sessions_target ON scan_sessions(target);

CREATE TABLE IF NOT EXISTS fw_recon_assets (
    id           BIGSERIAL PRIMARY KEY,
    session_id   BIGINT,
    asset_type   TEXT,
    value        TEXT NOT NULL,
    source       TEXT,
    status_code  INTEGER,
    tech_stack   TEXT,
    is_in_scope  INTEGER DEFAULT 1,
    created_at   TIMESTAMPTZ DEFAULT NOW()
);
CREATE INDEX IF NOT EXISTS idx_fw_recon_assets_session ON fw_recon_assets(session_id);

CREATE TABLE IF NOT EXISTS surface_items (
    id           BIGSERIAL PRIMARY KEY,
    session_id   BIGINT,
    item_type    TEXT,
    host         TEXT,
    value        TEXT,
    method       TEXT,
    extra        JSONB,
    created_at   TIMESTAMPTZ DEFAULT NOW()
);
CREATE INDEX IF NOT EXISTS idx_surface_items_session ON surface_items(session_id);

CREATE TABLE IF NOT EXISTS vuln_candidates (
    id           BIGSERIAL PRIMARY KEY,
    session_id   BIGINT,
    vuln_type    TEXT,
    host         TEXT,
    endpoint     TEXT,
    parameter    TEXT,
    method       TEXT,
    payload      TEXT,
    evidence     TEXT,
    confidence   TEXT,
    validated    INTEGER DEFAULT 0,
    finding_id   BIGINT,
    created_at   TIMESTAMPTZ DEFAULT NOW()
);
CREATE INDEX IF NOT EXISTS idx_vuln_candidates_session ON vuln_candidates(session_id);

-- ============================================================
-- Council Runs: stores outputs from AICouncilMission
-- ============================================================
CREATE TABLE IF NOT EXISTS council_runs (
    id SERIAL PRIMARY KEY,
    scan_id VARCHAR(64) NOT NULL,
    target TEXT NOT NULL,
    created_at TIMESTAMPTZ DEFAULT NOW(),
    completed_at TIMESTAMPTZ,
    surface_profile JSONB,
    exploit_plan JSONB,
    exploit_trace JSONB,
    mutation_report JSONB,
    post_exploit_report JSONB,
    validated_finding JSONB,
    overall_success BOOLEAN DEFAULT FALSE,
    objective_artifact TEXT,
    finding_count INTEGER DEFAULT 0
);

CREATE INDEX IF NOT EXISTS idx_council_runs_scan_id ON council_runs(scan_id);
CREATE INDEX IF NOT EXISTS idx_council_runs_target ON council_runs(target);
CREATE INDEX IF NOT EXISTS idx_council_runs_success ON council_runs(overall_success);

-- Council findings: individual findings from council run, links to main findings table
CREATE TABLE IF NOT EXISTS council_findings (
    id SERIAL PRIMARY KEY,
    council_run_id INTEGER REFERENCES council_runs(id) ON DELETE CASCADE,
    scan_id VARCHAR(64) NOT NULL,
    finding_id VARCHAR(64),
    vuln_type VARCHAR(64),
    severity VARCHAR(16),
    owasp_llm_category TEXT,
    mitre_atlas_technique TEXT,
    cvss_score FLOAT,
    cvss_vector TEXT,
    ai_impact_statement TEXT,
    reproduction_steps JSONB,
    confirmed BOOLEAN DEFAULT FALSE,
    created_at TIMESTAMPTZ DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_council_findings_scan_id ON council_findings(scan_id);
CREATE INDEX IF NOT EXISTS idx_council_findings_confirmed ON council_findings(confirmed);
