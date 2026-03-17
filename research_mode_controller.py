"""
Research Mode Controller
==========================
Orchestrates the full Autonomous Vulnerability Research loop.

Loop:
  analyze_application()
  → generate_vulnerability_theories()
  → design_attack_tests()
  → execute_tests()
  → detect_anomalies()
  → confirm / reject theories
  → update knowledge base
  → repeat until timeout or convergence

Integrates with: attack graph, exploit chains, continuous learning,
multi-agent architecture, and payload mutation engine.
"""

from __future__ import annotations

import json
import sqlite3
import time
import uuid
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Optional

from path_manager import research_db_path, resolve_output_dir

# ── Data models ───────────────────────────────────────────────────────────────

@dataclass
class ResearchSession:
    """Tracks one research run against a target."""
    session_id: str
    target: str
    output_dir: str
    platform: str = "HackerOne"
    started_at: float = field(default_factory=time.time)
    ended_at: float = 0.0
    status: str = "running"          # running | completed | aborted | error
    iteration: int = 0
    max_iterations: int = 5
    theories_generated: int = 0
    tests_executed: int = 0
    anomalies_found: int = 0
    confirmed_vulns: int = 0

    def elapsed(self) -> float:
        return (self.ended_at or time.time()) - self.started_at


@dataclass
class DiscoveryReport:
    """Structured vulnerability discovery report."""
    report_id: str
    session_id: str
    target: str
    vuln_type: str
    title: str
    severity: str
    confidence: float
    endpoint: str
    description: str
    impact: str
    steps_to_reproduce: list[str]
    proof_of_concept: str
    remediation: str
    evidence: str
    cvss_score: float = 0.0
    discovered_at: float = field(default_factory=time.time)
    platform: str = "HackerOne"

    def to_dict(self) -> dict:
        return {
            "report_id": self.report_id,
            "session_id": self.session_id,
            "target": self.target,
            "vuln_type": self.vuln_type,
            "title": self.title,
            "severity": self.severity,
            "confidence": round(self.confidence, 2),
            "endpoint": self.endpoint,
            "description": self.description,
            "impact": self.impact,
            "steps_to_reproduce": self.steps_to_reproduce,
            "proof_of_concept": self.proof_of_concept,
            "remediation": self.remediation,
            "evidence": self.evidence,
            "cvss_score": self.cvss_score,
            "discovered_at": self.discovered_at,
        }

    def to_markdown(self) -> str:
        steps = "\n".join(f"{i+1}. {s}" for i, s in enumerate(self.steps_to_reproduce))
        return f"""# {self.title}

**Severity:** {self.severity.upper()}
**Endpoint:** `{self.endpoint}`
**Confidence:** {self.confidence:.0%}
**CVSS Score:** {self.cvss_score}

## Description

{self.description}

## Impact

{self.impact}

## Steps to Reproduce

{steps}

## Proof of Concept

```
{self.proof_of_concept}
```

## Evidence

{self.evidence}

## Remediation

{self.remediation}

---
*Discovered by Autonomous Vulnerability Research — {self.target}*
"""


# ── Knowledge Base ────────────────────────────────────────────────────────────

class ResearchKnowledgeBase:
    """
    SQLite-backed store for research sessions, tested endpoints,
    confirmed vulnerabilities, and cross-session insights.
    """
    DB_PATH = research_db_path()

    def __init__(self, db_path: str | Path | None = None):
        self.path = Path(db_path or self.DB_PATH)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self._conn: Optional[sqlite3.Connection] = None
        self._init_schema()

    def _connect(self) -> sqlite3.Connection:
        if self._conn is None:
            self._conn = sqlite3.connect(str(self.path), check_same_thread=False)
            self._conn.row_factory = sqlite3.Row
        return self._conn

    def _init_schema(self):
        conn = self._connect()
        conn.executescript("""
        CREATE TABLE IF NOT EXISTS research_sessions (
            session_id   TEXT PRIMARY KEY,
            target       TEXT NOT NULL,
            output_dir   TEXT,
            platform     TEXT DEFAULT 'HackerOne',
            started_at   REAL NOT NULL,
            ended_at     REAL DEFAULT 0,
            status       TEXT DEFAULT 'running',
            iteration    INTEGER DEFAULT 0,
            theories_generated INTEGER DEFAULT 0,
            tests_executed INTEGER DEFAULT 0,
            anomalies_found INTEGER DEFAULT 0,
            confirmed_vulns INTEGER DEFAULT 0
        );

        CREATE TABLE IF NOT EXISTS endpoint_insights (
            id           INTEGER PRIMARY KEY AUTOINCREMENT,
            session_id   TEXT NOT NULL,
            target       TEXT NOT NULL,
            endpoint     TEXT NOT NULL,
            method       TEXT DEFAULT 'GET',
            parameters   TEXT DEFAULT '[]',
            auth_required INTEGER DEFAULT 0,
            sensitivity_score REAL DEFAULT 0,
            tags         TEXT DEFAULT '[]',
            tested_at    REAL DEFAULT 0,
            FOREIGN KEY (session_id) REFERENCES research_sessions(session_id)
        );

        CREATE TABLE IF NOT EXISTS vuln_theories (
            theory_id    TEXT PRIMARY KEY,
            session_id   TEXT NOT NULL,
            target       TEXT NOT NULL,
            endpoint     TEXT NOT NULL,
            vuln_type    TEXT NOT NULL,
            severity     TEXT NOT NULL,
            confidence   REAL DEFAULT 0,
            reasoning    TEXT DEFAULT '',
            status       TEXT DEFAULT 'pending',
            created_at   REAL NOT NULL,
            updated_at   REAL DEFAULT 0,
            FOREIGN KEY (session_id) REFERENCES research_sessions(session_id)
        );

        CREATE TABLE IF NOT EXISTS test_outcomes (
            id           INTEGER PRIMARY KEY AUTOINCREMENT,
            session_id   TEXT NOT NULL,
            theory_id    TEXT,
            target       TEXT NOT NULL,
            endpoint     TEXT NOT NULL,
            vuln_type    TEXT,
            payload      TEXT DEFAULT '',
            status_code  INTEGER DEFAULT 0,
            response_size INTEGER DEFAULT 0,
            response_time_ms REAL DEFAULT 0,
            anomaly_score REAL DEFAULT 0,
            confirmed    INTEGER DEFAULT 0,
            evidence     TEXT DEFAULT '',
            tested_at    REAL NOT NULL,
            FOREIGN KEY (session_id) REFERENCES research_sessions(session_id)
        );

        CREATE TABLE IF NOT EXISTS discoveries (
            report_id    TEXT PRIMARY KEY,
            session_id   TEXT NOT NULL,
            target       TEXT NOT NULL,
            vuln_type    TEXT NOT NULL,
            title        TEXT NOT NULL,
            severity     TEXT NOT NULL,
            confidence   REAL DEFAULT 0,
            endpoint     TEXT NOT NULL,
            description  TEXT DEFAULT '',
            impact       TEXT DEFAULT '',
            steps        TEXT DEFAULT '[]',
            poc          TEXT DEFAULT '',
            remediation  TEXT DEFAULT '',
            evidence     TEXT DEFAULT '',
            cvss_score   REAL DEFAULT 0,
            discovered_at REAL NOT NULL,
            reported     INTEGER DEFAULT 0,
            FOREIGN KEY (session_id) REFERENCES research_sessions(session_id)
        );

        CREATE TABLE IF NOT EXISTS cross_target_patterns (
            id           INTEGER PRIMARY KEY AUTOINCREMENT,
            vuln_type    TEXT NOT NULL,
            endpoint_pattern TEXT NOT NULL,
            parameter_pattern TEXT DEFAULT '',
            success_count INTEGER DEFAULT 1,
            last_seen    REAL NOT NULL,
            notes        TEXT DEFAULT ''
        );
        """)
        conn.commit()

    def save_session(self, session: ResearchSession):
        conn = self._connect()
        conn.execute("""
        INSERT OR REPLACE INTO research_sessions VALUES (
            :session_id, :target, :output_dir, :platform, :started_at,
            :ended_at, :status, :iteration, :theories_generated,
            :tests_executed, :anomalies_found, :confirmed_vulns
        )
        """, {
            "session_id": session.session_id,
            "target": session.target,
            "output_dir": session.output_dir,
            "platform": session.platform,
            "started_at": session.started_at,
            "ended_at": session.ended_at,
            "status": session.status,
            "iteration": session.iteration,
            "theories_generated": session.theories_generated,
            "tests_executed": session.tests_executed,
            "anomalies_found": session.anomalies_found,
            "confirmed_vulns": session.confirmed_vulns,
        })
        conn.commit()

    def record_theory(self, session_id: str, theory, target: str):
        conn = self._connect()
        conn.execute("""
        INSERT OR IGNORE INTO vuln_theories VALUES (
            :theory_id, :session_id, :target, :endpoint, :vuln_type,
            :severity, :confidence, :reasoning, :status, :created_at, :updated_at
        )
        """, {
            "theory_id": theory.theory_id,
            "session_id": session_id,
            "target": target,
            "endpoint": theory.endpoint,
            "vuln_type": theory.vuln_type,
            "severity": theory.severity,
            "confidence": theory.confidence,
            "reasoning": theory.reasoning,
            "status": theory.status,
            "created_at": time.time(),
            "updated_at": 0.0,
        })
        conn.commit()

    def update_theory_status(self, theory_id: str, status: str):
        conn = self._connect()
        conn.execute(
            "UPDATE vuln_theories SET status=?, updated_at=? WHERE theory_id=?",
            (status, time.time(), theory_id)
        )
        conn.commit()

    def record_test_outcome(self, session_id: str, result, target: str):
        conn = self._connect()
        conn.execute("""
        INSERT INTO test_outcomes (
            session_id, theory_id, target, endpoint, vuln_type, payload,
            status_code, response_size, response_time_ms, anomaly_score,
            confirmed, evidence, tested_at
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """, (
            session_id,
            result.theory_id,
            target,
            result.endpoint,
            result.vuln_type,
            result.payload_used,
            result.status_code,
            result.response_size,
            result.response_time_ms,
            result.anomaly_score,
            int(result.confirmed),
            result.evidence,
            time.time(),
        ))
        conn.commit()

    def save_discovery(self, report: DiscoveryReport):
        conn = self._connect()
        conn.execute("""
        INSERT OR REPLACE INTO discoveries VALUES (
            :report_id, :session_id, :target, :vuln_type, :title, :severity,
            :confidence, :endpoint, :description, :impact, :steps, :poc,
            :remediation, :evidence, :cvss_score, :discovered_at, :reported
        )
        """, {
            "report_id": report.report_id,
            "session_id": report.session_id,
            "target": report.target,
            "vuln_type": report.vuln_type,
            "title": report.title,
            "severity": report.severity,
            "confidence": report.confidence,
            "endpoint": report.endpoint,
            "description": report.description,
            "impact": report.impact,
            "steps": json.dumps(report.steps_to_reproduce),
            "poc": report.proof_of_concept,
            "remediation": report.remediation,
            "evidence": report.evidence,
            "cvss_score": report.cvss_score,
            "discovered_at": report.discovered_at,
            "reported": 0,
        })
        conn.commit()
        # Update cross-target pattern table
        self._update_pattern(report.vuln_type, report.endpoint)

    def _update_pattern(self, vuln_type: str, endpoint: str):
        import re
        pattern = re.sub(r"\d+", "{id}", endpoint)
        conn = self._connect()
        row = conn.execute(
            "SELECT id, success_count FROM cross_target_patterns WHERE vuln_type=? AND endpoint_pattern=?",
            (vuln_type, pattern)
        ).fetchone()
        if row:
            conn.execute(
                "UPDATE cross_target_patterns SET success_count=?, last_seen=? WHERE id=?",
                (row["success_count"] + 1, time.time(), row["id"])
            )
        else:
            conn.execute(
                "INSERT INTO cross_target_patterns (vuln_type, endpoint_pattern, last_seen) VALUES (?,?,?)",
                (vuln_type, pattern, time.time())
            )
        conn.commit()

    def get_known_patterns(self, min_count: int = 2) -> list[dict]:
        conn = self._connect()
        rows = conn.execute(
            "SELECT * FROM cross_target_patterns WHERE success_count >= ? ORDER BY success_count DESC",
            (min_count,)
        ).fetchall()
        return [dict(r) for r in rows]

    def get_session_history(self, target: str) -> list[dict]:
        conn = self._connect()
        rows = conn.execute(
            "SELECT * FROM research_sessions WHERE target=? ORDER BY started_at DESC LIMIT 10",
            (target,)
        ).fetchall()
        return [dict(r) for r in rows]

    def get_confirmed_discoveries(self) -> list[dict]:
        conn = self._connect()
        rows = conn.execute(
            "SELECT * FROM discoveries ORDER BY discovered_at DESC"
        ).fetchall()
        result = []
        for r in rows:
            d = dict(r)
            try:
                d["steps"] = json.loads(d.get("steps", "[]"))
            except Exception:
                d["steps"] = []
            result.append(d)
        return result

    def close(self):
        if self._conn:
            self._conn.close()
            self._conn = None


# ── Report Generator ──────────────────────────────────────────────────────────

class ResearchReportGenerator:
    """Generates structured bug bounty reports from confirmed discoveries."""

    _IMPACT_MAP: dict[str, str] = {
        "IDOR": (
            "An attacker can access, modify, or delete data belonging to other users "
            "by manipulating resource identifiers. This can lead to complete account takeover, "
            "data theft, and privacy violations."
        ),
        "SQL Injection": (
            "SQL injection can allow an attacker to read sensitive data from the database, "
            "modify or delete data, execute administrative operations, and in some cases "
            "achieve remote code execution on the database server."
        ),
        "Cross-Site Scripting (XSS)": (
            "XSS allows attackers to inject malicious scripts that execute in victims' browsers. "
            "Impact includes session hijacking, credential theft, defacement, and "
            "redirection to phishing pages."
        ),
        "Server-Side Request Forgery (SSRF)": (
            "SSRF allows an attacker to make the server perform requests to internal systems. "
            "On cloud platforms, this can expose IAM credentials and instance metadata, "
            "leading to cloud account compromise."
        ),
        "Authentication Bypass": (
            "Authentication bypass allows unauthenticated users to access protected resources. "
            "This can lead to unauthorized data access, privilege escalation, and "
            "complete account takeover."
        ),
        "Privilege Escalation": (
            "An attacker can elevate their privileges from a standard user to administrator, "
            "gaining access to sensitive admin functions, other users' data, and system configuration."
        ),
        "Local File Inclusion (LFI)": (
            "LFI allows attackers to read arbitrary files from the server, including "
            "configuration files containing credentials, SSH keys, and source code. "
            "In some cases, LFI can be chained to RCE."
        ),
        "Business Logic Flaw": (
            "Business logic vulnerabilities allow attackers to abuse the application's "
            "intended workflow to gain financial advantage, bypass controls, or "
            "access unauthorized functionality."
        ),
        "JWT Algorithm Confusion": (
            "JWT algorithm confusion allows forging authentication tokens, enabling "
            "attackers to impersonate any user including administrators without knowing the secret key."
        ),
        "CORS Misconfiguration": (
            "CORS misconfiguration with credentials enabled allows malicious sites to make "
            "authenticated cross-origin requests, stealing sensitive data and performing "
            "actions on behalf of victims."
        ),
        "Unrestricted File Upload": (
            "Unrestricted file upload can lead to Cross-Site Scripting via malicious files, "
            "Remote Code Execution if server-side scripts are executed, or "
            "server storage exhaustion."
        ),
        "Mass Assignment": (
            "Mass assignment allows attackers to set internal model fields that should not "
            "be user-controllable, such as admin status, role, email verification, or account balance."
        ),
        "Laravel Debug Mode Disclosure": (
            "Laravel debug mode exposes full stack traces, environment variables, and "
            "application configuration. Combined with the APP_KEY, this can lead to "
            "Remote Code Execution via PHP object deserialization."
        ),
        "Laravel .env File Exposure": (
            "The .env file contains highly sensitive credentials including database passwords, "
            "application encryption key (APP_KEY), mail server credentials, and third-party API keys. "
            "The APP_KEY can be used to decrypt data and forge signed cookies."
        ),
        "Spring Boot Actuator Exposure": (
            "Exposed Spring Boot Actuator endpoints can reveal environment variables containing "
            "secrets, allow heap dump downloads for offline analysis, and in some configurations "
            "enable Remote Code Execution via JMX or logging endpoints."
        ),
        "GraphQL Introspection / Injection": (
            "GraphQL introspection exposes the complete API schema, enabling targeted attacks. "
            "Without proper authorization at the resolver level, attackers can access other "
            "users' data or perform unauthorized mutations."
        ),
        "Server-Side Template Injection (SSTI)": (
            "SSTI allows attackers to inject template expressions that execute on the server, "
            "typically leading to Remote Code Execution and full server compromise."
        ),
        "PHP Object Injection": (
            "PHP Object Injection via unserialize() can trigger POP gadget chains in "
            "popular frameworks (Laravel, Symfony, Yii) leading to Remote Code Execution, "
            "arbitrary file write, or file deletion."
        ),
    }

    _REMEDIATION_MAP: dict[str, str] = {
        "IDOR": (
            "Implement server-side authorization checks that verify the authenticated user "
            "owns or has permission to access the requested resource. Do not rely on client-supplied "
            "IDs alone. Use indirect object references or cryptographic tokens."
        ),
        "SQL Injection": (
            "Use parameterized queries / prepared statements for all database interactions. "
            "Never concatenate user input into SQL strings. Apply the principle of least privilege "
            "to database accounts. Consider using an ORM."
        ),
        "Cross-Site Scripting (XSS)": (
            "Output-encode all user-supplied data before rendering in HTML context. "
            "Implement a strict Content Security Policy (CSP). Use the 'HttpOnly' flag on "
            "session cookies. Validate and sanitize input on the server side."
        ),
        "Server-Side Request Forgery (SSRF)": (
            "Implement a whitelist of allowed protocols and destinations. Block requests to "
            "private IP ranges (RFC 1918) and cloud metadata endpoints. Use a network-layer "
            "firewall to prevent outbound requests from the application server."
        ),
        "Authentication Bypass": (
            "Ensure all sensitive endpoints enforce authentication checks. Apply authentication "
            "middleware globally and whitelist public endpoints explicitly. Implement integration "
            "tests that verify 401/403 responses on protected routes."
        ),
        "JWT Algorithm Confusion": (
            "Explicitly specify and enforce the allowed algorithm in JWT verification. "
            "Reject 'none' algorithm. For RS256, verify using the public key only — "
            "never accept an HMAC-signed token where RSA is expected."
        ),
        "CORS Misconfiguration": (
            "Do not dynamically reflect the Origin header without validation. Maintain an explicit "
            "allowlist of trusted origins. Never combine Access-Control-Allow-Origin: * with "
            "Access-Control-Allow-Credentials: true."
        ),
        "Local File Inclusion (LFI)": (
            "Do not pass user-supplied input to filesystem functions (include, require, fopen). "
            "If file paths are needed, validate against a strict allowlist. Disable allow_url_include "
            "and allow_url_fopen in PHP configuration."
        ),
        "Business Logic Flaw": (
            "Validate all business rules on the server side. Enforce minimum price/quantity "
            "constraints. Verify workflow state transitions server-side. Implement idempotency "
            "keys to prevent duplicate operations."
        ),
        "Laravel .env File Exposure": (
            "Configure your web server to deny access to dot-files. Add 'deny from all' "
            "to .htaccess or 'location ~ /\\. { deny all; }' to Nginx config. "
            "Rotate all credentials in the exposed .env file immediately."
        ),
        "Spring Boot Actuator Exposure": (
            "Restrict actuator endpoints to authenticated, authorized users only. "
            "Disable sensitive endpoints (heapdump, env, trace) in production. "
            "Configure management.endpoints.web.exposure.include explicitly."
        ),
        "Mass Assignment": (
            "Use form objects or DTOs to control which fields can be mass-assigned. "
            "In Laravel, define $fillable arrays explicitly. In Rails, use strong parameters. "
            "Never expose ORM models directly to user input."
        ),
        "Server-Side Template Injection (SSTI)": (
            "Never pass user-supplied input to template rendering functions. "
            "If templates must be dynamic, use a sandboxed template engine with "
            "a strict allowlist of permitted operations."
        ),
        "PHP Object Injection": (
            "Never pass user-supplied data to unserialize(). Use JSON for data serialization. "
            "If you must use PHP serialization, implement HMAC signatures on serialized data. "
            "Update all framework dependencies to patch known gadget chains."
        ),
        "Unrestricted File Upload": (
            "Validate file type using magic bytes (not extension or MIME type alone). "
            "Store uploaded files outside the web root or in an isolated storage service (S3). "
            "Rename uploaded files to random strings. Serve files through a proxy that sets "
            "Content-Disposition: attachment."
        ),
    }

    _CVSS_MAP: dict[str, float] = {
        "SQL Injection": 8.8,
        "IDOR": 7.5,
        "Cross-Site Scripting (XSS)": 6.1,
        "Server-Side Request Forgery (SSRF)": 9.0,
        "Authentication Bypass": 9.8,
        "Privilege Escalation": 8.8,
        "JWT Algorithm Confusion": 9.1,
        "Local File Inclusion (LFI)": 8.2,
        "Server-Side Template Injection (SSTI)": 9.8,
        "PHP Object Injection": 9.8,
        "Business Logic Flaw": 8.0,
        "CORS Misconfiguration": 7.4,
        "Mass Assignment": 8.1,
        "Laravel Debug Mode Disclosure": 9.8,
        "Laravel .env File Exposure": 9.8,
        "Spring Boot Actuator Exposure": 7.5,
        "GraphQL Introspection / Injection": 7.5,
        "Unrestricted File Upload": 9.0,
        "Missing Rate Limiting": 5.3,
        "Open Redirect": 6.1,
        "CRLF Injection": 6.1,
        "Excessive Data Exposure": 5.3,
        "Debug Information Disclosure": 5.3,
        "Unauthorized Data Export": 7.5,
    }

    def generate(
        self,
        session: ResearchSession,
        theory,
        test_result,
        anomaly=None,
    ) -> DiscoveryReport:
        """Generate a DiscoveryReport from a confirmed test result + theory."""
        vuln_type = theory.vuln_type
        impact = self._IMPACT_MAP.get(vuln_type, f"Successful exploitation of {vuln_type}.")
        remediation = self._REMEDIATION_MAP.get(
            vuln_type, "Review and harden the affected endpoint. Apply input validation."
        )
        cvss = self._CVSS_MAP.get(vuln_type, 5.0)

        # Build PoC
        poc = self._build_poc(theory, test_result)

        # Build steps to reproduce
        steps = self._build_steps(theory, test_result)

        title = f"{vuln_type} in {theory.endpoint}"
        if len(title) > 80:
            title = title[:77] + "..."

        evidence_parts = [test_result.evidence]
        if anomaly:
            evidence_parts.append(f"Anomaly: {anomaly.evidence}")

        return DiscoveryReport(
            report_id=str(uuid.uuid4())[:8],
            session_id=session.session_id,
            target=session.target,
            vuln_type=vuln_type,
            title=title,
            severity=theory.severity,
            confidence=test_result.anomaly_score or theory.confidence,
            endpoint=theory.endpoint,
            description=(
                f"{vuln_type} was discovered at `{theory.endpoint}`. "
                f"{theory.reasoning}"
            ),
            impact=impact,
            steps_to_reproduce=steps,
            proof_of_concept=poc,
            remediation=remediation,
            evidence="\n".join(evidence_parts),
            cvss_score=cvss,
            platform=session.platform,
        )

    def _build_poc(self, theory, test_result) -> str:
        lines = [f"# Target: {theory.endpoint}"]
        if test_result.payload_used:
            lines.append(f"# Payload: {test_result.payload_used}")
        lines.append("")
        lines.append(f"curl -sk '{theory.endpoint}' \\")
        if test_result.payload_used and theory.parameters:
            param = theory.parameters[0]
            lines.append(f"  --data-urlencode '{param}={test_result.payload_used}' \\")
        lines.append(f"  -o /tmp/response.txt && cat /tmp/response.txt")
        if test_result.response_snippet:
            lines.append("")
            lines.append("# Expected response snippet:")
            lines.append(f"# {test_result.response_snippet[:200]}")
        return "\n".join(lines)

    def _build_steps(self, theory, test_result) -> list[str]:
        steps = [
            f"Navigate to or send a request to: {theory.endpoint}",
        ]
        if test_result.payload_used and theory.parameters:
            steps.append(
                f"Modify the '{theory.parameters[0]}' parameter to: {test_result.payload_used[:80]}"
            )
        steps.append("Observe the response for the following indicator:")
        steps.append(f"  {test_result.evidence or theory.attack_hints[0]}")
        if test_result.status_code:
            steps.append(f"The server returned HTTP {test_result.status_code}")
        steps.extend(theory.attack_hints[:2])
        return steps


# ── Research Mode Controller ──────────────────────────────────────────────────

class ResearchModeController:
    """
    Autonomous Vulnerability Research orchestrator.

    Runs the research loop:
      AppModel → Theories → Tests → ZeroDay → Confirm → Report → Loop
    """

    def __init__(
        self,
        target: str,
        output_dir: str = "",
        platform: str = "HackerOne",
        max_iterations: int = 3,
        timeout: int = 3600,
        rate_limit: float = 1.0,
        oob_url: str = "",
        attack_graph=None,
        learning_system=None,
        passive_only: bool = True,
        tool_registry=None,
        min_confidence: float = 0.60,
    ):
        # Strip scheme from target if present
        _t = target
        for scheme in ("https://", "http://"):
            if _t.startswith(scheme):
                _t = _t[len(scheme):]
                break
        self.target = _t.split("/")[0]
        self.output_dir = resolve_output_dir(output_dir, self.target)
        self.platform = platform
        self.max_iterations = max_iterations
        self.timeout = timeout
        self.rate_limit = rate_limit
        self.oob_url = oob_url
        self.passive_only = passive_only
        self.tool_registry = tool_registry
        self.min_confidence = min_confidence

        # Sub-engines (lazy-initialized)
        self._app_engine = None
        self._theory_engine = None
        self._test_engine = None
        self._zd_engine = None
        self._report_gen = ResearchReportGenerator()
        self._kb = ResearchKnowledgeBase()

        # Integration
        self.attack_graph = attack_graph
        self.learning_system = learning_system

        # Session
        self._session = ResearchSession(
            session_id=str(uuid.uuid4())[:8],
            target=self.target,
            output_dir=str(self.output_dir),
            platform=platform,
            max_iterations=max_iterations,
        )
        self._discoveries: list[DiscoveryReport] = []
        self._aborted = False
        self._start_time = 0.0

    # ── Main entry point ──────────────────────────────────────────────────────

    def run_research(self) -> list[DiscoveryReport]:
        """
        Execute the full autonomous research loop.
        Returns all confirmed discoveries.
        """
        self._start_time = time.time()
        self._log(f"Research session {self._session.session_id} started — target: {self.target}")
        self._kb.save_session(self._session)
        self.output_dir.mkdir(parents=True, exist_ok=True)

        # Seed from prior session history
        prior = self._kb.get_session_history(self.target)
        if prior:
            self._log(f"Prior sessions for {self.target}: {len(prior)} (leveraging institutional knowledge)")

        # Seed from cross-target patterns (global KB)
        patterns = self._kb.get_known_patterns(min_count=1)
        if patterns:
            self._log(f"Cross-target patterns available: {len(patterns)} historical successes")

        try:
            while (
                self._session.iteration < self._session.max_iterations
                and not self._aborted
                and not self._timed_out()
            ):
                self._session.iteration += 1
                self._log(
                    f"═══ Iteration {self._session.iteration}/{self._session.max_iterations} ═══"
                )
                self._run_iteration()
                self._kb.save_session(self._session)

                # Early convergence: stop if discoveries are accumulating
                if self._session.confirmed_vulns >= 10:
                    self._log("10+ confirmed vulnerabilities found — ending research loop early")
                    break

        except KeyboardInterrupt:
            self._log("Research interrupted by user")
            self._aborted = True
        except Exception as exc:
            self._log(f"Research error: {exc}", "error")
            self._session.status = "error"
        finally:
            self._session.ended_at = time.time()
            self._session.status = "completed" if not self._aborted else "aborted"
            self._kb.save_session(self._session)
            self._finalize()

        return self._discoveries

    def abort(self):
        self._aborted = True

    # ── Research iteration ────────────────────────────────────────────────────

    def _run_iteration(self):
        """One full pass of the research loop."""
        deadline = min(
            self._start_time + self.timeout,
            time.time() + (self.timeout // max(self._session.max_iterations, 1)) + 300
        )

        # ── Phase 1: Application Analysis ─────────────────────────────────────
        self._log("Phase 1: Application structure analysis...")
        from application_intelligence import ApplicationIntelligenceEngine
        self._app_engine = ApplicationIntelligenceEngine(
            self.target, str(self.output_dir)
        )
        app_model = self._app_engine.analyze_application_structure()
        self._log(
            f"  Auth: {app_model.auth_system} | "
            f"Paths: {len(app_model.api_structure)} | "
            f"Roles: {app_model.user_roles or ['unknown']}"
        )
        self._update_attack_graph_from_model(app_model)

        if time.time() > deadline:
            self._log("Deadline reached after Phase 1 — skipping remaining phases")
            return

        # ── Phase 2: Vulnerability Theory Generation ───────────────────────────
        self._log("Phase 2: Generating vulnerability theories...")
        from vulnerability_theory_engine import VulnTheoryEngine
        self._theory_engine = VulnTheoryEngine()
        theory_set = self._theory_engine.generate_vulnerability_theories(app_model)

        # Apply confidence boosting from cross-target patterns
        patterns = self._kb.get_known_patterns()
        pattern_map: dict[str, int] = {p["vuln_type"]: p["success_count"] for p in patterns}
        for theory in theory_set.theories:
            if theory.vuln_type in pattern_map:
                boost = min(pattern_map[theory.vuln_type] * 0.05, 0.20)
                theory.confidence = min(theory.confidence + boost, 0.98)

        self._session.theories_generated += len(theory_set.theories)
        self._log(f"  Generated {len(theory_set.theories)} theories")

        # Store theories in KB
        for t in theory_set.theories:
            self._kb.record_theory(self._session.session_id, t, self.target)

        # Filter by confidence threshold
        viable = [t for t in theory_set.theories if t.confidence >= self.min_confidence]
        self._log(f"  {len(viable)} theories meet confidence threshold ({self.min_confidence:.0%})")

        if not viable or time.time() > deadline:
            return

        # ── Phase 3: Custom Test Design & Execution ────────────────────────────
        self._log("Phase 3: Designing and executing custom attack tests...")
        base_url = self._detect_base_url()
        from custom_test_engine import CustomTestEngine
        self._test_engine = CustomTestEngine(
            target=self.target,
            output_dir=str(self.output_dir),
            base_url=base_url,
            tool_registry=self.tool_registry,
            rate_limit=self.rate_limit,
            oob_url=self.oob_url,
        )

        all_tests = []
        for theory in viable[:20]:  # cap per iteration
            if time.time() > deadline:
                break
            tests = self._test_engine.generate_attack_tests(theory)
            if self.passive_only:
                tests = [t for t in tests if t.passive]
            all_tests.extend(tests)

        self._log(f"  Executing {len(all_tests)} tests...")
        results = self._test_engine.execute_attack_tests(all_tests)
        self._session.tests_executed += len(results)

        # Store outcomes in KB
        for r in results:
            self._kb.record_test_outcome(self._session.session_id, r, self.target)

        # ── Phase 4: Zero-Day Anomaly Detection ────────────────────────────────
        if time.time() < deadline:
            self._log("Phase 4: Zero-day anomaly detection...")
            from zero_day_engine import ZeroDayEngine
            self._zd_engine = ZeroDayEngine(
                target=self.target,
                output_dir=str(self.output_dir),
                base_url=base_url,
                rate_limit=self.rate_limit,
            )
            test_result_dicts = [r.to_dict() for r in results]
            anomalies = self._zd_engine.detect_anomalies(test_results=test_result_dicts)
            self._session.anomalies_found += len(anomalies)
            self._log(f"  {len(anomalies)} anomalies detected")
        else:
            anomalies = []

        # ── Phase 5: Confirmation & Reporting ─────────────────────────────────
        self._log("Phase 5: Confirming findings and generating reports...")
        confirmed_results = [r for r in results if r.confirmed]
        self._log(f"  {len(confirmed_results)} confirmed, {len(results) - len(confirmed_results)} unconfirmed")

        for r in confirmed_results:
            # Find matching theory
            theory = next(
                (t for t in viable if t.theory_id == r.theory_id), None
            )
            if not theory:
                continue

            self._kb.update_theory_status(theory.theory_id, "confirmed")
            theory.status = "confirmed"

            # Find matching anomaly if any
            matching_anomaly = next(
                (a for a in anomalies if theory.endpoint in a.endpoint), None
            )

            # Generate discovery report
            report = self._report_gen.generate(
                self._session, theory, r, matching_anomaly
            )
            self._discoveries.append(report)
            self._session.confirmed_vulns += 1
            self._kb.save_discovery(report)

            # Save report to disk
            report_path = self.output_dir / f"report_{report.report_id}.md"
            report_path.write_text(report.to_markdown())
            self._log(f"  ✓ {report.vuln_type} — {report.endpoint} → {report_path.name}")

            # Feed into attack graph
            self._update_attack_graph_from_discovery(report)

            # Feed into exploit chain engine if available
            self._try_exploit_chain(report)

        # Update learning system
        if self.learning_system and confirmed_results:
            self._update_learning_system(confirmed_results)

    # ── Integration helpers ───────────────────────────────────────────────────

    def _update_attack_graph_from_model(self, app_model):
        if not self.attack_graph:
            return
        try:
            from attack_graph.graph import Node, NodeType, Edge, EdgeType
            for ep in app_model.sensitive_endpoints[:10]:
                node_id = f"ep:{ep}"
                self.attack_graph.add_node(Node(
                    node_id=node_id,
                    node_type=NodeType.ENDPOINT,
                    label=ep,
                    properties={"sensitive": True, "auth": app_model.auth_system},
                ))
        except Exception:
            pass

    def _update_attack_graph_from_discovery(self, report: DiscoveryReport):
        if not self.attack_graph:
            return
        try:
            self.attack_graph.add_vulnerability(
                vuln_id=f"research_{report.report_id}",
                vuln_type=report.vuln_type,
                host=self.target,
                endpoint=report.endpoint,
                severity=report.severity,
                evidence=report.evidence,
                confidence="high" if report.confidence > 0.80 else "medium",
            )
        except Exception:
            pass

    def _try_exploit_chain(self, report: DiscoveryReport):
        """Attempt to chain newly confirmed vuln with existing findings."""
        try:
            from exploit_chains import ExploitChainEngine
            existing = [r.to_dict() for r in self._discoveries if r.report_id != report.report_id]
            if not existing:
                return
            engine = ExploitChainEngine(self.target)
            finding_dict = {
                "vuln_type": report.vuln_type,
                "severity": report.severity,
                "endpoint": report.endpoint,
                "matched_at": report.endpoint,
            }
            chains = engine.detect_chains(existing + [finding_dict])
            if chains:
                self._log(f"  ⛓  {len(chains)} exploit chain(s) detected!")
                chains_file = self.output_dir / "research_chains.json"
                chains_file.write_text(json.dumps([c.to_dict() for c in chains], indent=2))
        except Exception:
            pass

    def _update_learning_system(self, confirmed_results):
        """Persist confirmed findings to the continuous learning system."""
        try:
            for r in confirmed_results:
                self.learning_system.record_tool_use(
                    tool=r.vuln_type,
                    target=self.target,
                    outcome="confirmed",
                )
        except Exception:
            pass

    def _detect_base_url(self) -> str:
        """Load base URL from alive_hosts.json or fallback to https://target."""
        alive_f = self.output_dir / "alive_hosts.json"
        if alive_f.exists():
            try:
                data = json.loads(alive_f.read_text())
                hosts = data.get("hosts", data) if isinstance(data, dict) else data
                if hosts:
                    h = hosts[0]
                    return (h.get("url", "") if isinstance(h, dict) else h) or f"https://{self.target}"
            except Exception:
                pass
        return f"https://{self.target}"

    def _timed_out(self) -> bool:
        return time.time() - self._start_time >= self.timeout

    def _log(self, msg: str, level: str = "info"):
        colors = {"info": "\033[0;36m[*]\033[0m",
                  "ok":   "\033[0;32m[+]\033[0m",
                  "warn": "\033[0;33m[!]\033[0m",
                  "error":"\033[0;31m[!]\033[0m"}
        prefix = colors.get(level, "[*]")
        print(f"  {prefix} {msg}", flush=True)

    def _finalize(self):
        """Write session summary and all discoveries to disk."""
        summary = {
            "session_id": self._session.session_id,
            "target": self._session.target,
            "duration_s": round(self._session.elapsed(), 1),
            "iterations": self._session.iteration,
            "theories_generated": self._session.theories_generated,
            "tests_executed": self._session.tests_executed,
            "anomalies_found": self._session.anomalies_found,
            "confirmed_vulns": self._session.confirmed_vulns,
            "discoveries": [d.to_dict() for d in self._discoveries],
        }
        summary_path = self.output_dir / "research_summary.json"
        summary_path.write_text(json.dumps(summary, indent=2))
        self._log(f"Research complete — {self._session.confirmed_vulns} confirmed findings")
        self._log(f"Summary: {summary_path}")


# ── Statistics / history ──────────────────────────────────────────────────────

def show_research_stats():
    """Print cross-session research statistics from the knowledge base."""
    kb = ResearchKnowledgeBase()
    discoveries = kb.get_confirmed_discoveries()
    patterns = kb.get_known_patterns(min_count=1)

    from modules.utils import banner, section, ok, info
    banner("Research Knowledge Base")
    ok(f"Confirmed discoveries: {len(discoveries)}")
    ok(f"Cross-target patterns : {len(patterns)}")
    print()

    if discoveries:
        section("Recent Discoveries")
        for d in discoveries[:10]:
            print(f"  [{d['severity'].upper()}] {d['vuln_type']} — {d['endpoint']}")
            print(f"    {d['target']} (confidence: {d['confidence']:.0%})")
        print()

    if patterns:
        section("High-Value Patterns (cross-target)")
        for p in patterns[:10]:
            print(f"  [{p['success_count']}x] {p['vuln_type']} → {p['endpoint_pattern']}")
    print()
    kb.close()


# ── CLI entry point ───────────────────────────────────────────────────────────

def main_cli(args):
    from modules.utils import banner, section, ok, info, warn

    cmd = getattr(args, "subcommand", "run")
    target = getattr(args, "domain", "")

    if cmd == "stats":
        show_research_stats()
        return

    if not target:
        warn("Specify a target: bounty research <domain>")
        return

    output = resolve_output_dir(getattr(args, "output", None), target)
    platform = getattr(args, "platform", "HackerOne") or "HackerOne"
    max_iter = getattr(args, "iterations", 3) or 3
    timeout = getattr(args, "timeout", 3600) or 3600
    passive = not getattr(args, "active", False)
    oob = getattr(args, "oob", "") or ""

    banner(f"Autonomous Vulnerability Research — {target}")
    warn("This mode performs active probing. Ensure written authorization.")
    print()
    if not getattr(args, "yes", False):
        ans = input("  [?] Confirm written authorization to test? (yes/no): ").strip().lower()
        if ans != "yes":
            print("  Aborted.")
            return

    # Optional integrations
    attack_graph = None
    if not getattr(args, "no_graph", False):
        try:
            from attack_graph import AttackGraph, AttackGraphBuilder
            out_path = Path(output)
            if out_path.exists():
                builder = AttackGraphBuilder(target)
                attack_graph = builder.from_recon_dir(str(out_path))
            else:
                from attack_graph import AttackGraph
                attack_graph = AttackGraph(target)
            info("Attack graph: enabled")
        except Exception:
            pass

    learning_system = None
    if not getattr(args, "no_learn", False):
        try:
            from learning import LearningSystem
            learning_system = LearningSystem()
            info("Learning system: enabled")
        except Exception:
            pass

    info(f"Mode     : {'passive' if passive else 'active (destructive tests enabled)'}")
    info(f"Iterations: {max_iter} | Timeout: {timeout}s | Platform: {platform}")
    print()

    controller = ResearchModeController(
        target=target,
        output_dir=output,
        platform=platform,
        max_iterations=max_iter,
        timeout=timeout,
        passive_only=passive,
        oob_url=oob,
        attack_graph=attack_graph,
        learning_system=learning_system,
    )

    discoveries = controller.run_research()

    # ── Summary ──
    print()
    section(f"Research Complete — {len(discoveries)} finding(s)")
    _sev_colors = {
        "critical": "\033[0;31m", "high": "\033[0;33m",
        "medium": "\033[0;36m",   "low":  "\033[0;37m",
    }
    _reset = "\033[0m"
    for d in discoveries:
        col = _sev_colors.get(d.severity, "")
        print(f"  {col}[{d.severity.upper()}]{_reset} {d.vuln_type}")
        print(f"    Endpoint   : {d.endpoint}")
        print(f"    Confidence : {d.confidence:.0%}")
        print(f"    Report     : {output}/report_{d.report_id}.md")
        print()

    if not discoveries:
        info("No confirmed findings in this session.")
        info("Try: --active flag for destructive test coverage")
        info("Or:  bounty zero-day <domain> for anomaly analysis")

    if learning_system:
        learning_system.close()
    print()
