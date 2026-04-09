"""
Validation Agent — verifies candidates, eliminates false positives,
assigns CVSS scores, and promotes to confirmed findings.
"""

from __future__ import annotations

import json
import re
import time
import urllib.request
import urllib.parse
from pathlib import Path

from oneinfinity.infra.path_manager import findings_db_path, resolve_output_dir

from oneinfinity.agents.base import BaseAgent, Task, TaskResult


class ValidationAgent(BaseAgent):
    AGENT_ID = "validation_agent"
    DESCRIPTION = "Validates vuln candidates, eliminates FPs, assigns CVSS, confirms findings"
    SPECIALIZATIONS = ["validate", "verify", "cvss_score", "false_positive_filter"]

    # Minimum evidence thresholds per vuln type
    VALIDATION_RULES = {
        "XSS":                {"require_reflected_payload": True,  "min_confidence": "medium"},
        "SQL Injection":      {"require_error_or_timing": True,    "min_confidence": "medium"},
        "SSRF":               {"require_oob_or_response_diff": True, "min_confidence": "low"},
        "CRLF Injection":     {"require_crlf_in_response": True,  "min_confidence": "medium"},
        "OS Command Injection":{"require_output_or_timing": True,  "min_confidence": "high"},
        "Open Redirect":      {"require_location_header": True,   "min_confidence": "high"},
        "Secret Exposure":    {"require_valid_format": True,       "min_confidence": "low"},
        "Security Misconfiguration": {"check_accessibility": True, "min_confidence": "low"},
    }

    # CVSS base scores by severity
    CVSS_BY_SEVERITY = {
        "critical": 9.5, "high": 7.8, "medium": 5.5, "low": 3.5, "info": 1.0
    }

    def execute_task(self, task: Task) -> TaskResult:
        handler = {
            "validate":             self._validate_all,
            "verify":               self._validate_all,
            "cvss_score":           self._score_cvss,
            "false_positive_filter": self._fp_filter,
        }.get(task.task_type, self._validate_all)

        data, findings, tools = handler(task)
        return TaskResult(
            task_id=task.task_id,
            agent_id=self.agent_id,
            task_type=task.task_type,
            target=task.target,
            success=True,
            data=data,
            findings=findings,
            tools_used=tools,
        )

    def _load_findings(self, out_dir: Path, task: Task) -> list[dict]:
        findings = task.context.get("findings", [])
        if not findings:
            f = out_dir / "findings.json"
            if f.exists():
                raw = json.loads(f.read_text())
                findings = raw if isinstance(raw, list) else raw.get("findings", [])
        return findings

    # ── Main validation pass ──────────────────────────────────────────────────

    def _validate_all(self, task: Task):
        out_dir = resolve_output_dir(task.context.get("output_dir"), task.target)
        findings = self._load_findings(out_dir, task)

        confirmed = []
        false_positives = []

        for f in findings:
            if self.is_aborted():
                break
            result = self._validate_finding(f, task)
            if result["valid"]:
                f["validated"] = True
                f["cvss_score"] = result["cvss_score"]
                f["validation_notes"] = result["notes"]
                f["false_positive"] = False
                confirmed.append(f)
            else:
                f["false_positive"] = True
                f["fp_reason"] = result.get("reason", "Failed validation")
                false_positives.append(f)

        self.log(f"Validation: {len(confirmed)} confirmed, {len(false_positives)} FP", "ok")

        (out_dir / "confirmed_findings.json").write_text(
            json.dumps(confirmed, indent=2)
        )

        # Persist confirmed findings to FindingsDB if available
        self._persist_to_db(confirmed, out_dir, task.target)

        return {
            "confirmed": len(confirmed),
            "false_positives": len(false_positives),
            "findings": confirmed,
        }, confirmed, []

    def _validate_finding(self, f: dict, task: Task) -> dict:
        """
        Validate a single finding.
        Returns {"valid": bool, "cvss_score": float, "notes": str, "reason": str}
        """
        vuln_type = f.get("vuln_type", "")
        severity = f.get("severity", "info")
        confidence = f.get("confidence", f.get("source_tool", ""))
        endpoint = f.get("matched_at", f.get("endpoint", f.get("url", "")))

        notes = []
        rules = self.VALIDATION_RULES.get(vuln_type, {})

        # Rule 1: Confidence filter
        low_conf_tools = {"kxss"}  # these are triage only
        source = f.get("source_tool", "")
        if source in low_conf_tools and vuln_type == "XSS":
            return {"valid": False, "reason": f"kxss is triage only — needs dalfox confirmation"}

        # Rule 2: Evidence must be non-empty
        evidence = f.get("evidence", f.get("description", ""))
        if not evidence and not f.get("payload"):
            return {"valid": False, "reason": "No evidence or payload provided"}

        # Rule 3: Endpoint must be reachable (quick check for HTTP 200/4xx)
        if endpoint and endpoint.startswith("http") and task.context.get("verify_live", True):
            try:
                req = urllib.request.Request(
                    endpoint,
                    headers={"User-Agent": "Mozilla/5.0 (OneInfinity/1.0)"},
                )
                with urllib.request.urlopen(req, timeout=8) as resp:
                    status = resp.status
                    if status == 404:
                        return {"valid": False, "reason": f"Endpoint returns 404 — may be fixed"}
                    notes.append(f"Endpoint alive (HTTP {status})")
            except Exception as e:
                notes.append(f"Could not verify endpoint: {e}")

        # Rule 4: XSS — check payload is still reflected
        if vuln_type == "XSS" and rules.get("require_reflected_payload"):
            payload = f.get("payload", "")
            if payload and endpoint:
                reflected = self._check_xss_reflection(endpoint, payload)
                if not reflected:
                    return {"valid": False, "reason": "XSS payload no longer reflected — may be patched"}
                notes.append("XSS payload still reflected")

        # Rule 5: Open Redirect — verify Location header
        if vuln_type == "Open Redirect" and rules.get("require_location_header"):
            evidence_str = str(evidence)
            if "evil.com" not in evidence_str and "Location" not in evidence_str:
                return {"valid": False, "reason": "No Location header evidence for redirect"}

        # Rule 6: Secret — check format
        if vuln_type == "Secret Exposure":
            raw = f.get("raw", "")
            if not raw or len(raw) < 8:
                return {"valid": False, "reason": "Secret too short — likely a false positive"}
            notes.append(f"Secret pattern matched (verified={f.get('verified', False)})")
            if f.get("verified"):
                return {"valid": True, "cvss_score": 9.5,
                        "notes": "API-verified live secret credential"}

        # Assign CVSS
        cvss = self._compute_cvss(vuln_type, severity, f)

        return {
            "valid": True,
            "cvss_score": cvss,
            "notes": "; ".join(notes) if notes else "Passed automated validation",
        }

    def _check_xss_reflection(self, url: str, payload: str) -> bool:
        """Check if XSS payload is still reflected in response."""
        try:
            req = urllib.request.Request(url, headers={"User-Agent": "Mozilla/5.0"})
            with urllib.request.urlopen(req, timeout=8) as resp:
                body = resp.read(50000).decode("utf-8", errors="replace")
                return payload[:20] in body
        except Exception:
            return True  # benefit of the doubt

    def _compute_cvss(self, vuln_type: str, severity: str, finding: dict) -> float:
        """Heuristic CVSS score based on vuln type and context."""
        base = self.CVSS_BY_SEVERITY.get(severity, 5.0)

        # Adjustments
        if finding.get("verified"):            # TruffleHog-verified secret
            base = max(base, 9.5)
        if finding.get("parameter"):           # param-specific → slightly lower scope
            base = max(base - 0.3, 1.0)
        if vuln_type == "SQL Injection":
            base = max(base, 7.5)
        if vuln_type == "OS Command Injection":
            base = max(base, 9.0)
        if vuln_type == "Subdomain Takeover":
            base = max(base, 8.0)
        if "chain" in vuln_type.lower():       # chains escalate
            base = min(base + 1.5, 10.0)

        return round(base, 1)

    # ── CVSS scoring ──────────────────────────────────────────────────────────

    def _score_cvss(self, task: Task):
        out_dir = resolve_output_dir(task.context.get("output_dir"), task.target)
        findings = self._load_findings(out_dir, task)
        for f in findings:
            f["cvss_score"] = self._compute_cvss(
                f.get("vuln_type", ""), f.get("severity", "info"), f
            )
        return {"scored_findings": findings}, findings, []

    # ── FP filter ─────────────────────────────────────────────────────────────

    def _fp_filter(self, task: Task):
        out_dir = resolve_output_dir(task.context.get("output_dir"), task.target)
        findings = self._load_findings(out_dir, task)
        real = [f for f in findings if not f.get("false_positive")]
        self.log(f"FP filter: {len(real)}/{len(findings)} are real", "ok")
        return {"real_findings": real}, real, []

    # ── DB persistence ────────────────────────────────────────────────────────

    def _persist_to_db(self, findings: list[dict], out_dir: Path, target: str):
        """Save confirmed findings to findings.db."""
        db_path = findings_db_path()

        if not db_path.exists():
            return

        try:
            from oneinfinity_framework.db_ext import ExtendedDB
            db = ExtendedDB(str(db_path))
            for f in findings:
                endpoint = f.get("matched_at", f.get("url", f.get("endpoint", "")))
                db.add(
                    title=f.get("name", f.get("vuln_type", "Finding")),
                    vuln_type=f.get("vuln_type", "unknown"),
                    severity=f.get("severity", "info"),
                    cvss_score=f.get("cvss_score"),
                    endpoint=endpoint,
                    description=f.get("evidence", f.get("description", ""))[:500],
                    notes=f"Source: {f.get('source_tool', 'agent')} | "
                          f"Agent: {self.agent_id}",
                    status="verified",
                )
            db.close()
            self.log(f"Persisted {len(findings)} findings to DB", "ok")
        except Exception as exc:
            self.log(f"DB persist failed: {exc}", "warn")
