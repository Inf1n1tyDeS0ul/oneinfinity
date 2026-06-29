"""
pipeline/phase_timeouts.py — Single source of truth for phase-level timeouts.

Both execution paths import from here:
  - unified_scan_engine.py  (21 phases, Python-native phase functions)
  - pipeline/canonical.py   (17 phases, CLI-subprocess execution via executor.py)

The two paths have different phase NAMES because they evolved independently.
PHASE_EQUIVALENTS maps unified → canonical for operations that cover the same
security work, so timeout divergences are immediately visible in one place.

NEVER hard-code timeout values anywhere else.  Add a new phase here first,
then reference it from the appropriate pipeline; both paths validate at
import time and raise ValueError for any unlisted phase.
"""
from __future__ import annotations

# ---------------------------------------------------------------------------
# Unified scan engine — 21 phases  (unified_scan_engine.py)
# ---------------------------------------------------------------------------
UNIFIED_PHASE_TIMEOUT_S: dict[str, int] = {
    "classify":            60,
    "recon":               900,   # 15 min — enough for thorough recon
    "graph_update":        120,
    "agent_trigger":       120,
    "oob_init":             60,   # interactsh needs ≥15 s to bind + poll thread
    "auth_setup":          120,
    "github_recon":        300,   # hard outer ceiling; non-fatal
    "port_scan":           180,   # P1: naabu/rustscan + Shodan InternetDB
    "param_discovery":     300,   # P2: headless form extraction + Arjun
    "credential_spray":    120,   # P3: dry-run credential intelligence
    # ── Parallel group ────────────────────────────────────────────────────
    "vuln_scan":          1200,   # 20 min — reduced from 5400 (90 min)
    "graphql_scan":        600,
    "browser_analysis":    600,
    "js_intelligence":     600,
    "smuggling_test":      300,
    "cicd_scan":           600,
    "web3_scan":           600,
    "mobile_scan":         600,   # MobSF upload+scan+apkleaks (APK may be large)
    # ── Post-parallel sequential ──────────────────────────────────────────
    "authenticated_tests": 600,   # P5: AuthenticatedTestSuite post vuln_scan
    "post_exploit":        300,
    "business_logic":      600,
    "exploit_validation":  600,   # reduced from 1800
    "exploit_chaining":    300,
    "ssrf_pivot":          120,
    "result_ingest":       300,
    "severity_followup":   300,
    "graph_vuln_update":   300,
    "zero_day_hypothesis": 120,
    "report":              180,
    "done":                 60,
}

# ---------------------------------------------------------------------------
# Canonical executor — 17 phases  (pipeline/canonical.py + executor.py)
# PhaseConfig.timeout_s values are patched from here at module load time.
# ---------------------------------------------------------------------------
CANONICAL_PHASE_TIMEOUT_S: dict[str, int] = {
    "target_registration":  30,
    "deep_recon":          900,
    "vuln_scan":          1800,
    "active_testing":     3600,
    "auth_session":        600,
    # P1-P5 canonical equivalents
    "port_scan":           180,
    "param_discovery":     300,
    "credential_spray":    120,
    "authenticated_tests": 600,
    "post_exploit":        300,
    "business_logic":      900,
    "exploit_validation":  600,
    "exploit_chains":      300,
    "attack_graph":        120,
    "ai_theory":           300,
    "graphql_scan":        300,
    "browser_analysis":    300,
    "smuggling_test":      120,
    "oob_check":            60,
    "directory_fuzz":      300,
    "secrets_scan":        240,
    "custom_tests":        600,
}

# ---------------------------------------------------------------------------
# Cross-path equivalence (unified → canonical)
# Used to surface timeout divergences between the two executors at a glance.
# ---------------------------------------------------------------------------
PHASE_EQUIVALENTS: dict[str, str] = {
    "oob_init":            "oob_check",
    "auth_setup":          "auth_session",
    "vuln_scan":           "vuln_scan",
    "business_logic":      "business_logic",
    "graphql_scan":        "graphql_scan",
    "browser_analysis":    "browser_analysis",
    "smuggling_test":      "smuggling_test",
    "exploit_validation":  "exploit_validation",
    "exploit_chaining":    "exploit_chains",
    # P1-P5 new phases mapped to nearest canonical equivalents
    "port_scan":           "deep_recon",       # P1: port scanning folded into deep_recon in canonical
    "param_discovery":     "active_testing",   # P2: form extraction + Arjun = active parameter testing
    "credential_spray":    "auth_session",     # P3: credential intelligence = auth_session scope
    "authenticated_tests": "auth_session",     # P5: post-login test suite = auth_session scope
    "post_exploit":        "exploit_chains",   # post-exploitation feeds exploit chain generation
}
