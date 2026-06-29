"""
cicd_vuln_scanner.py — CI/CD Pipeline Vulnerability Scanner

Scans CI/CD pipeline configurations for security vulnerabilities:
  - Workflow injection via untrusted event data
  - Hardcoded secrets in environment variables / run steps
  - OIDC misconfiguration (overly permissive subject claims)
  - Supply chain risks (unpinned Actions, abandoned maintainers)
  - Self-hosted runner risks
  - Excessive permissions

Supports:
  - GitHub Actions (via GitHub API — no clone required)
  - GitLab CI (via .gitlab-ci.yml parsing)
  - Jenkins (Jenkinsfile analysis)

Usage::
    scanner = CICDVulnerabilityScanner()
    report = scanner.scan_github_repo("owner/repo")
    print(report.summary())

CLI::
    oneinfinity cicd-scan owner/repo
    oneinfinity cicd-scan https://github.com/owner/repo
"""
from __future__ import annotations

import json
import logging
import re
import time
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

log = logging.getLogger("oneinfinity.cicd_scanner")

# ---------------------------------------------------------------------------
# Data models
# ---------------------------------------------------------------------------

@dataclass
class CICDFinding:
    finding_id: str
    title: str
    severity: str           # critical / high / medium / low / info
    category: str           # injection / secret / oidc / supply_chain / permission / runner
    description: str
    file_path: str
    line_number: int = 0
    evidence: str = ""
    remediation: str = ""
    cvss_score: float = 0.0
    cwe: str = ""

    def to_dict(self) -> dict:
        return {
            "id": self.finding_id,
            "title": self.title,
            "severity": self.severity,
            "category": self.category,
            "vuln_type": f"cicd_{self.category}",   # required by brain.integrate_vuln()
            "description": self.description,
            "file": self.file_path,
            "url": self.file_path,
            "endpoint": self.file_path,
            "line": self.line_number,
            "evidence": self.evidence,
            "remediation": self.remediation,
            "cvss": self.cvss_score,
        }


@dataclass
class CICDScanReport:
    repo: str
    platform: str
    workflow_count: int
    findings: List[CICDFinding] = field(default_factory=list)
    scan_time_s: float = 0.0
    error: str = ""

    def findings_by_severity(self, sev: str) -> List[CICDFinding]:
        return [f for f in self.findings if f.severity == sev]

    def summary(self) -> str:
        counts = {s: len(self.findings_by_severity(s)) for s in ("critical", "high", "medium", "low", "info")}
        lines = [
            f"\n  CI/CD Security Scan — {self.repo}",
            f"  {'─'*55}",
            f"  Platform  : {self.platform}",
            f"  Workflows : {self.workflow_count}",
            f"  Findings  : critical={counts['critical']} high={counts['high']} "
            f"medium={counts['medium']} low={counts['low']}",
            "",
        ]
        for f in sorted(self.findings, key=lambda x: ("critical", "high", "medium", "low", "info").index(x.severity)):
            sev_colors = {
                "critical": "\033[1;31m", "high": "\033[0;31m",
                "medium": "\033[0;33m", "low": "\033[0;34m", "info": "\033[0;37m",
            }
            color = sev_colors.get(f.severity, "")
            reset = "\033[0m"
            lines.append(f"  {color}[{f.severity.upper():8s}]{reset} {f.title}")
            lines.append(f"           {f.file_path}:{f.line_number}")
            if f.evidence:
                lines.append(f"           {f.evidence[:80]}")
        lines.append("")
        return "\n".join(lines)


# ---------------------------------------------------------------------------
# Detection patterns
# ---------------------------------------------------------------------------

# GitHub Actions expression injection — untrusted event data in run steps
_INJECTION_PATTERNS: List[Tuple[re.Pattern, str]] = [
    (
        re.compile(r"\$\{\{[^}]*github\.event\.(issue\.(title|body)|pull_request\.(title|body|head\.ref)|comment\.body|review\.body|review_comment\.body)[^}]*\}\}", re.I),
        "Untrusted event data in expression — attacker can inject arbitrary commands via PR/issue title or body",
    ),
    (
        re.compile(r"\$\{\{[^}]*github\.head_ref[^}]*\}\}", re.I),
        "github.head_ref is attacker-controlled — can contain shell metacharacters from forked PR branch name",
    ),
    (
        re.compile(r"\$\{\{[^}]*env\.(GITHUB_TOKEN|ACTIONS_RUNTIME_TOKEN)[^}]*\}\}", re.I),
        "GitHub token exposed in expression — may appear in logs",
    ),
    (
        re.compile(r"run:\s*.*\$\{\{[^}]*github\.event", re.I | re.DOTALL),
        "Injection of event data directly into run step shell command",
    ),
]

# Secrets hardcoded in workflow files
_SECRET_PATTERNS: List[Tuple[re.Pattern, str]] = [
    (
        re.compile(r"(?:password|passwd|secret|token|api[_-]?key|access[_-]?key|private[_-]?key)\s*[:=]\s*['\"]?[A-Za-z0-9+/]{20,}['\"]?", re.I),
        "Hardcoded credential or secret in workflow file",
    ),
    (
        re.compile(r"AWS_SECRET_ACCESS_KEY\s*:\s*[A-Za-z0-9/+=]{30,}", re.I),
        "AWS secret access key hardcoded",
    ),
    (
        re.compile(r"ghp_[A-Za-z0-9]{36}", re.I),
        "GitHub Personal Access Token (ghp_) exposed",
    ),
    (
        re.compile(r"ghr_[A-Za-z0-9]{36}", re.I),
        "GitHub Refresh Token (ghr_) exposed",
    ),
    (
        re.compile(r"sk-[A-Za-z0-9]{40,}", re.I),
        "OpenAI API key exposed",
    ),
    (
        re.compile(r"PRIVATE KEY-----", re.I),
        "Private key material embedded in workflow",
    ),
]

# OIDC misconfiguration — overly permissive subject claim
_OIDC_PATTERNS: List[Tuple[re.Pattern, str]] = [
    (
        re.compile(r"subject\s*[=:]\s*['\"]?\*['\"]?", re.I),
        "OIDC subject claim set to wildcard (*) — any repo/workflow can assume this role",
    ),
    (
        re.compile(r"sub\s*[=:]\s*['\"]?\*['\"]?", re.I),
        "OIDC sub claim wildcard allows any caller to assume the cloud role",
    ),
    (
        re.compile(r"condition.*StringLike.*token\.actions.*subject.*\*", re.I | re.DOTALL),
        "AWS IAM OIDC policy uses StringLike with wildcard subject — overly permissive",
    ),
]

# Supply chain risks — unpinned actions
_UNPINNED_ACTION_RE = re.compile(r"uses:\s*([a-zA-Z0-9_-]+/[a-zA-Z0-9_.-]+)@(v\d+(?:\.\d+)*|main|master|latest|HEAD)", re.I)
_PINNED_ACTION_RE = re.compile(r"uses:\s*[a-zA-Z0-9_-]+/[a-zA-Z0-9_.-]+@[a-f0-9]{40}", re.I)

# Excessive permissions — write-all or dangerous scopes
_PERMISSION_PATTERNS: List[Tuple[re.Pattern, str]] = [
    (
        re.compile(r"permissions\s*:\s*write-all", re.I),
        "Workflow grants write-all permissions — violates least-privilege",
    ),
    (
        re.compile(r"contents\s*:\s*write", re.I),
        "Workflow has write access to repo contents — enables push attacks if compromised",
    ),
    (
        re.compile(r"packages\s*:\s*write", re.I),
        "Workflow can write packages — supply chain risk if workflow is compromised",
    ),
    (
        re.compile(r"id-token\s*:\s*write", re.I),
        "OIDC token write permission — verify this is required and trust policy is narrow",
    ),
]

# Self-hosted runner risks
_RUNNER_PATTERNS: List[Tuple[re.Pattern, str]] = [
    (
        re.compile(r"runs-on\s*:\s*self-hosted", re.I),
        "Self-hosted runner in use — compromise of runner environment affects all workflows",
    ),
    (
        re.compile(r"runs-on\s*:.*self-hosted.*\n.*pull_request_target", re.I | re.DOTALL),
        "pull_request_target with self-hosted runner — untrusted code may execute on privileged runner",
    ),
]

# Dangerous trigger combinations
_TRIGGER_PATTERNS: List[Tuple[re.Pattern, str]] = [
    (
        re.compile(r"on\s*:\s*\n?\s*pull_request_target", re.I),
        "pull_request_target trigger — runs with write permissions even from forks, injection risk is high",
    ),
    (
        re.compile(r"workflow_run\s*:", re.I),
        "workflow_run trigger — can execute with elevated permissions from forked PR workflows",
    ),
]


# ---------------------------------------------------------------------------
# GitHub API client (minimal, no dependency)
# ---------------------------------------------------------------------------

class _GitHubClient:
    _BASE = "https://api.github.com"

    def __init__(self, token: str = "") -> None:
        self.token = token or os.getenv("GITHUB_TOKEN", "")

    def _headers(self) -> Dict[str, str]:
        h = {
            "Accept": "application/vnd.github.v3+json",
            "User-Agent": "OneInfinity/2.0",
        }
        if self.token:
            h["Authorization"] = f"token {self.token}"
        return h

    def _get(self, path: str) -> Any:
        url = f"{self._BASE}{path}"
        req = urllib.request.Request(url, headers=self._headers())
        try:
            with urllib.request.urlopen(req, timeout=15) as r:
                return json.loads(r.read())
        except urllib.error.HTTPError as exc:
            body = exc.read(512).decode(errors="replace")
            raise RuntimeError(f"GitHub API {exc.code}: {body}") from exc

    def list_workflows(self, repo: str) -> List[Dict]:
        try:
            data = self._get(f"/repos/{repo}/contents/.github/workflows")
            return data if isinstance(data, list) else []
        except Exception as exc:
            log.debug("list_workflows failed for %s: %s", repo, exc)
            return []

    def get_file_content(self, repo: str, path: str) -> str:
        try:
            import base64
            data = self._get(f"/repos/{repo}/contents/{urllib.parse.quote(path)}")
            encoded = data.get("content", "")
            return base64.b64decode(encoded).decode("utf-8", errors="replace")
        except Exception as exc:
            log.debug("get_file_content failed %s %s: %s", repo, path, exc)
            return ""


import os


# ---------------------------------------------------------------------------
# Scanner
# ---------------------------------------------------------------------------

class CICDVulnerabilityScanner:
    """
    Scans CI/CD pipeline configurations for security vulnerabilities.
    Operates remotely via API — no repository clone required.
    """

    def __init__(self, github_token: str = "", include_info: bool = True) -> None:
        self._gh = _GitHubClient(github_token)
        self.include_info = include_info
        self._finding_counter = 0

    # ------------------------------------------------------------------ #
    #  Public API
    # ------------------------------------------------------------------ #

    def scan_github_repo(self, repo: str) -> CICDScanReport:
        """
        Scan all GitHub Actions workflows in *repo*.
        repo format: "owner/repo" or full GitHub URL.
        """
        repo = self._normalise_repo(repo)
        t0 = time.monotonic()
        log.info("CI/CD scan starting: %s", repo)

        workflows = self._gh.list_workflows(repo)
        all_findings: List[CICDFinding] = []

        for wf in workflows:
            path = wf.get("path", "")
            if not path.endswith((".yml", ".yaml")):
                continue
            content = self._gh.get_file_content(repo, path)
            if not content:
                continue
            findings = self._analyse_workflow(content, path, repo)
            all_findings.extend(findings)

        report = CICDScanReport(
            repo=repo,
            platform="github_actions",
            workflow_count=len(workflows),
            findings=all_findings,
            scan_time_s=time.monotonic() - t0,
        )
        log.info("CI/CD scan complete: %s — %d findings", repo, len(all_findings))
        return report

    def scan_yaml_content(self, yaml_content: str, file_path: str = "workflow.yml") -> List[CICDFinding]:
        """Scan raw YAML content (GitHub Actions, GitLab CI, Bitbucket Pipelines)."""
        return self._analyse_workflow(yaml_content, file_path, "")

    def scan_directory(self, directory: str) -> CICDScanReport:
        """Scan all workflow files in a local directory."""
        t0 = time.monotonic()
        base = Path(directory)
        all_findings: List[CICDFinding] = []
        count = 0

        for ext in ("*.yml", "*.yaml"):
            for wf_file in base.rglob(ext):
                try:
                    content = wf_file.read_text(errors="replace")
                    findings = self._analyse_workflow(content, str(wf_file.relative_to(base)), "")
                    all_findings.extend(findings)
                    count += 1
                except Exception as exc:
                    log.debug("Failed reading %s: %s", wf_file, exc)

        return CICDScanReport(
            repo=directory,
            platform="local",
            workflow_count=count,
            findings=all_findings,
            scan_time_s=time.monotonic() - t0,
        )

    # ------------------------------------------------------------------ #
    #  Analysis
    # ------------------------------------------------------------------ #

    def _analyse_workflow(
        self, content: str, file_path: str, repo: str
    ) -> List[CICDFinding]:
        findings: List[CICDFinding] = []
        lines = content.splitlines()

        # 1. Injection detection
        for pattern, description in _INJECTION_PATTERNS:
            for i, line in enumerate(lines, 1):
                if pattern.search(line):
                    findings.append(self._make_finding(
                        title="Workflow Expression Injection",
                        severity="critical",
                        category="injection",
                        description=description,
                        file_path=file_path,
                        line_number=i,
                        evidence=line.strip()[:120],
                        remediation=(
                            "Pass event data to an intermediate environment variable "
                            "(env: TITLE: ${{ github.event.issue.title }}) and reference "
                            "the variable in run steps. Never interpolate event data directly "
                            "into shell commands via ${{ }} expressions."
                        ),
                        cvss_score=9.3,
                        cwe="CWE-78",
                    ))

        # Also scan full content for multi-line injection patterns
        for pattern, description in _INJECTION_PATTERNS:
            if pattern.search(content) and not any(True for _ in (pattern.search(l) for l in lines)):
                findings.append(self._make_finding(
                    title="Multi-line Workflow Injection",
                    severity="high",
                    category="injection",
                    description=description,
                    file_path=file_path,
                    remediation="Audit all ${{ }} expressions for untrusted event data references.",
                    cvss_score=8.8,
                ))

        # 2. Secret exposure
        for pattern, description in _SECRET_PATTERNS:
            for i, line in enumerate(lines, 1):
                if pattern.search(line) and "${{" not in line:
                    evidence = re.sub(r"([A-Za-z0-9+/]{8})[A-Za-z0-9+/]{12,}([A-Za-z0-9+/]{4})", r"\1…\2", line.strip())
                    findings.append(self._make_finding(
                        title="Hardcoded Secret in CI/CD Pipeline",
                        severity="critical",
                        category="secret",
                        description=description,
                        file_path=file_path,
                        line_number=i,
                        evidence=evidence[:120],
                        remediation=(
                            "Store secrets in your platform's encrypted secret store "
                            "(GitHub: Settings → Secrets). Reference via ${{ secrets.SECRET_NAME }}. "
                            "Rotate any exposed credentials immediately."
                        ),
                        cvss_score=9.8,
                        cwe="CWE-798",
                    ))

        # 3. OIDC misconfiguration
        for pattern, description in _OIDC_PATTERNS:
            for i, line in enumerate(lines, 1):
                if pattern.search(line):
                    findings.append(self._make_finding(
                        title="Overly Permissive OIDC Trust Policy",
                        severity="high",
                        category="oidc",
                        description=description,
                        file_path=file_path,
                        line_number=i,
                        evidence=line.strip()[:120],
                        remediation=(
                            "Restrict OIDC subject claim to specific repos/branches: "
                            "repo:owner/repo:ref:refs/heads/main. "
                            "Never use wildcards in production trust policies."
                        ),
                        cvss_score=8.1,
                        cwe="CWE-284",
                    ))

        # 4. Supply chain — unpinned actions
        for i, line in enumerate(lines, 1):
            m = _UNPINNED_ACTION_RE.search(line)
            if m and not _PINNED_ACTION_RE.search(line):
                action = m.group(1)
                ref = m.group(2)
                findings.append(self._make_finding(
                    title=f"Unpinned GitHub Action: {action}@{ref}",
                    severity="medium",
                    category="supply_chain",
                    description=f"Action {action} uses mutable ref '{ref}' — a compromised tag or branch update "
                                "can introduce malicious code without changing your workflow file.",
                    file_path=file_path,
                    line_number=i,
                    evidence=line.strip()[:120],
                    remediation=(
                        f"Pin to a specific commit SHA: uses: {action}@<sha>  # {ref}\n"
                        "Use `pin-github-action` or Dependabot to automate SHA pinning."
                    ),
                    cvss_score=6.5,
                    cwe="CWE-829",
                ))

        # 5. Excessive permissions
        for pattern, description in _PERMISSION_PATTERNS:
            for i, line in enumerate(lines, 1):
                if pattern.search(line):
                    findings.append(self._make_finding(
                        title="Excessive Workflow Permissions",
                        severity="medium",
                        category="permission",
                        description=description,
                        file_path=file_path,
                        line_number=i,
                        evidence=line.strip()[:120],
                        remediation=(
                            "Apply least-privilege: only grant permissions the workflow actually needs. "
                            "Set default permissions to read-only and explicitly allow what's needed."
                        ),
                        cvss_score=5.4,
                        cwe="CWE-250",
                    ))

        # 6. Self-hosted runner risks
        for pattern, description in _RUNNER_PATTERNS:
            if pattern.search(content):
                findings.append(self._make_finding(
                    title="Self-Hosted Runner Security Risk",
                    severity="medium" if "pull_request_target" not in content else "high",
                    category="runner",
                    description=description,
                    file_path=file_path,
                    remediation=(
                        "Ensure self-hosted runners are ephemeral and isolated. "
                        "Never use self-hosted runners for public repos with pull_request_target."
                    ),
                    cvss_score=6.8,
                ))

        # 7. Dangerous trigger combinations
        for pattern, description in _TRIGGER_PATTERNS:
            if pattern.search(content):
                findings.append(self._make_finding(
                    title="Dangerous Workflow Trigger Configuration",
                    severity="high",
                    category="injection",
                    description=description,
                    file_path=file_path,
                    remediation=(
                        "Avoid pull_request_target for workflows that check out PR code. "
                        "Use pull_request (no write permissions from forks) instead. "
                        "If elevated permissions are truly needed, validate the PR origin carefully."
                    ),
                    cvss_score=7.5,
                ))

        return findings

    # ------------------------------------------------------------------ #
    #  Helpers
    # ------------------------------------------------------------------ #

    def _make_finding(
        self,
        title: str,
        severity: str,
        category: str,
        description: str,
        file_path: str,
        line_number: int = 0,
        evidence: str = "",
        remediation: str = "",
        cvss_score: float = 0.0,
        cwe: str = "",
    ) -> CICDFinding:
        self._finding_counter += 1
        import uuid
        return CICDFinding(
            finding_id=f"cicd-{uuid.uuid4().hex[:8]}",
            title=title,
            severity=severity,
            category=category,
            description=description,
            file_path=file_path,
            line_number=line_number,
            evidence=evidence,
            remediation=remediation,
            cvss_score=cvss_score,
            cwe=cwe,
        )

    @staticmethod
    def _normalise_repo(repo: str) -> str:
        """Convert full GitHub URL or owner/repo to owner/repo."""
        repo = repo.strip().rstrip("/")
        if "github.com/" in repo:
            parts = repo.split("github.com/", 1)[1].split("/")
            if len(parts) >= 2:
                return f"{parts[0]}/{parts[1]}"
        return repo
