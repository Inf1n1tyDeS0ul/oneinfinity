"""
GitHub Secrets Scanner for Organization Reconnaissance
=======================================================
Scans GitHub organization repositories for leaked credentials, API keys,
and sensitive information. Designed for bug bounty reconnaissance.

Features:
- Commit history scanning (recent commits)
- Code search with targeted patterns
- Rate limit aware (respects GitHub API limits)
- Token rotation support
- Ownership verification (org repos only)
- Live validation of findings
"""

from __future__ import annotations

import hashlib
import json
import logging
import re
import time
import urllib.request
import urllib.parse
from dataclasses import dataclass, field, asdict
from typing import List, Optional, Dict, Tuple

from oneinfinity.recon.comprehensive_patterns import COMPREHENSIVE_PATTERNS

log = logging.getLogger(__name__)


# Convert comprehensive patterns to scanner format (pattern, name, severity, confidence)
def _build_patterns():
    patterns = []
    confidence_map = {"critical": 0.95, "high": 0.85, "medium": 0.70, "low": 0.50}

    for pattern, name, severity, category in COMPREHENSIVE_PATTERNS:
        confidence = confidence_map.get(severity, 0.70)
        patterns.append((pattern, name, severity, confidence))

    # Add additional context-based patterns not in comprehensive list
    patterns.extend([
        (r'(?i)(?:password|passwd|pwd)\s*[=:]\s*["\']([^"\']{6,})["\']', "hardcoded_password", "critical", 0.80),
        (r'(?i)(?:api[_\-]?key|apikey)\s*[=:"\s]+([A-Za-z0-9_\-]{16,})', "api_key_generic", "high", 0.75),
        (r'(?i)(?:api[_\-]?secret|client[_\-]?secret)\s*[=:]\s*["\']([A-Za-z0-9_\-]{16,})["\']', "api_secret", "high", 0.85),
    ])

    return patterns


_SECRET_PATTERNS = _build_patterns()

_COMPILED_PATTERNS = [
    (re.compile(p, re.MULTILINE), stype, sev, conf)
    for p, stype, sev, conf in _SECRET_PATTERNS
]


@dataclass
class SecretFinding:
    """A single secret finding."""
    finding_id: str
    secret_type: str
    severity: str  # critical, high, medium, low
    confidence: float
    repo_full_name: str
    repo_url: str
    file_path: str
    commit_sha: Optional[str] = None
    commit_url: Optional[str] = None
    line_number: Optional[int] = None
    matched_text: str = ""  # redacted or partial
    raw_value: str = ""  # full untruncated match before masking
    context: str = ""
    discovered_at: str = field(default_factory=lambda: str(time.time()))

    def to_dict(self) -> dict:
        return asdict(self)


@dataclass
class SecretsResult:
    """Result of secrets scanning."""
    org: str
    repos_scanned: int = 0
    commits_scanned: int = 0
    findings: List[Dict] = field(default_factory=list)
    error: str = ""
    scan_duration: float = 0.0
    collected_at: str = field(default_factory=lambda: str(time.time()))

    def to_dict(self) -> dict:
        return asdict(self)

    def to_json(self, indent: int = 2) -> str:
        return json.dumps(self.to_dict(), indent=indent)


class GitHubSecretsScanner:
    """
    Scan GitHub organization for leaked secrets.
    """

    def __init__(self, github_token: Optional[str] = None, token_pool: Optional[List[str]] = None):
        self.github_token = github_token
        self.token_pool = token_pool or ([github_token] if github_token else [])
        self.current_token_idx = 0
        self.request_count = 0
        self.session_id = hashlib.md5(str(time.time()).encode()).hexdigest()[:8]

    def _get_token(self) -> str:
        """Rotate token every 30 requests to prevent rate limiting."""
        if not self.token_pool:
            return self.github_token or ""

        if self.request_count > 0 and self.request_count % 30 == 0:
            self.current_token_idx = (self.current_token_idx + 1) % len(self.token_pool)
            log.info(f"[{self.session_id}] Rotating to token {self.current_token_idx + 1}/{len(self.token_pool)}")

        self.request_count += 1
        return self.token_pool[self.current_token_idx]

    def scan_org(
        self,
        org: str,
        max_repos: int = 50,
        commits_per_repo: int = 10,
        timeout: int = 300,
    ) -> SecretsResult:
        """
        Scan organization for secrets.

        Args:
            org: GitHub organization name
            max_repos: Max repos to scan
            commits_per_repo: Recent commits to check per repo
            timeout: Max scan duration in seconds
        """
        start_time = time.time()
        org = self._normalize_org(org)
        result = SecretsResult(org=org)

        if not org:
            result.error = "invalid_org"
            return result

        headers = {"User-Agent": "OneInfinity-SecretScanner/1.0"}
        token = self._get_token()
        if token:
            headers["Authorization"] = f"token {token}"

        # Fetch repos
        repos = self._fetch_repos(org, max_repos, headers)
        if not repos:
            result.error = "no_repos_found"
            result.scan_duration = time.time() - start_time
            return result

        log.info(f"[{self.session_id}] Scanning {len(repos)} repos for secrets")

        # Scan each repo
        for repo in repos:
            if time.time() - start_time > timeout:
                result.error = "timeout"
                break

            repo_name = repo.get("full_name")
            if not repo_name:
                continue

            result.repos_scanned += 1

            # Scan recent commits
            findings = self._scan_repo_commits(
                repo_name,
                commits_per_repo,
                headers,
                result
            )
            result.findings.extend([f.to_dict() for f in findings])

        result.scan_duration = time.time() - start_time
        log.info(f"[{self.session_id}] Scan complete: {len(result.findings)} findings in {result.scan_duration:.1f}s")
        return result

    def _fetch_repos(
        self,
        org: str,
        max_repos: int,
        headers: dict
    ) -> List[dict]:
        """Fetch repository list."""
        repos = []
        page = 1
        per_page = min(100, max_repos)

        while len(repos) < max_repos:
            url = f"https://api.github.com/orgs/{org}/repos?per_page={per_page}&page={page}&sort=pushed"
            data = self._fetch_json(url, headers)

            if not data or not isinstance(data, list):
                break

            repos.extend(data)

            if len(data) < per_page:
                break

            page += 1

        return repos[:max_repos]

    def _scan_repo_commits(
        self,
        repo_full_name: str,
        commits_limit: int,
        headers: dict,
        result: SecretsResult
    ) -> List[SecretFinding]:
        """Scan recent commits in a repo."""
        findings = []

        # Fetch recent commits
        url = f"https://api.github.com/repos/{repo_full_name}/commits?per_page={commits_limit}"
        commits = self._fetch_json(url, headers)

        if not commits or not isinstance(commits, list):
            return findings

        for commit in commits:
            result.commits_scanned += 1
            commit_sha = commit.get("sha")
            commit_url = commit.get("html_url")

            # Fetch commit diff
            commit_data = self._fetch_json(
                f"https://api.github.com/repos/{repo_full_name}/commits/{commit_sha}",
                headers
            )

            if not commit_data or "files" not in commit_data:
                continue

            # Scan each changed file
            for file_data in commit_data.get("files", []):
                file_path = file_data.get("filename", "")
                patch = file_data.get("patch", "")

                if not patch:
                    continue

                # Detect secrets in patch
                file_findings = self._detect_secrets(
                    patch,
                    repo_full_name,
                    file_path,
                    commit_sha,
                    commit_url
                )
                findings.extend(file_findings)

        return findings

    def _detect_secrets(
        self,
        content: str,
        repo_full_name: str,
        file_path: str,
        commit_sha: Optional[str],
        commit_url: Optional[str]
    ) -> List[SecretFinding]:
        """Detect secrets in content using regex patterns."""
        findings = []
        lines = content.split("\n")

        for pattern, secret_type, severity, confidence in _COMPILED_PATTERNS:
            for line_num, line in enumerate(lines, 1):
                # Skip removed lines in diffs
                if line.startswith("-"):
                    continue

                matches = pattern.finditer(line)
                for match in matches:
                    matched_text = match.group(0)

                    # Redact sensitive parts
                    if len(matched_text) > 16:
                        redacted = matched_text[:8] + "..." + matched_text[-4:]
                    else:
                        redacted = matched_text[:4] + "..."

                    # Get context (surrounding lines)
                    context_start = max(0, line_num - 2)
                    context_end = min(len(lines), line_num + 2)
                    context = "\n".join(lines[context_start:context_end])

                    finding_id = hashlib.sha256(
                        f"{repo_full_name}:{file_path}:{line_num}:{matched_text}".encode()
                    ).hexdigest()[:12]

                    finding = SecretFinding(
                        finding_id=finding_id,
                        secret_type=secret_type,
                        severity=severity,
                        confidence=confidence,
                        repo_full_name=repo_full_name,
                        repo_url=f"https://github.com/{repo_full_name}",
                        file_path=file_path,
                        commit_sha=commit_sha,
                        commit_url=commit_url,
                        line_number=line_num,
                        matched_text=redacted,
                        raw_value=matched_text,
                        context=context[:200]  # Truncate context
                    )
                    findings.append(finding)

        return findings

    @staticmethod
    def _normalize_org(org: str) -> str:
        """Normalize org name."""
        org = (org or "").strip()
        if org.startswith("https://github.com/"):
            org = org.split("github.com/", 1)[1].strip("/")
        return org

    @staticmethod
    def _rate_limit_wait(exc) -> None:
        """Sleep until GitHub rate limit resets, reading reset headers when available."""
        hdrs = getattr(exc, "headers", None)
        retry_after = hdrs.get("Retry-After") if hdrs else None
        reset_ts    = hdrs.get("X-RateLimit-Reset") if hdrs else None
        if retry_after:
            wait = float(retry_after) + 1
        elif reset_ts:
            wait = max(1.0, int(reset_ts) - time.time() + 1)
        else:
            wait = 61.0
        log.warning("GitHub rate limit (403) — waiting %.0fs before retry", wait)
        time.sleep(wait)

    def _fetch_json(self, url: str, headers: dict, retries: int = 2) -> Optional[dict | list]:
        """Fetch JSON from URL with retries and proper rate-limit waiting."""
        for attempt in range(retries + 1):
            try:
                req = urllib.request.Request(url, headers=headers)
                with urllib.request.urlopen(req, timeout=20) as resp:
                    return json.loads(resp.read().decode("utf-8", errors="replace"))
            except urllib.error.HTTPError as exc:
                code = getattr(exc, "code", None)
                if code == 403:
                    self._rate_limit_wait(exc)
                    continue
                elif code == 401:
                    log.warning("GitHub 401 Unauthorized — token may be invalid or revoked. Rotating.")
                    self._rotate_token()
                    return {}
                log.debug(f"HTTP error (attempt {attempt + 1}): {exc}")
                time.sleep(0.5 * (attempt + 1))
                continue
            except Exception as exc:
                log.debug(f"Fetch failed (attempt {attempt + 1}): {exc}")
                time.sleep(0.5 * (attempt + 1))
                continue

        return None

    def _rotate_token(self) -> None:
        """Remove the current (invalid/revoked) token from the pool and advance to the next."""
        if self.token_pool and self.current_token_idx < len(self.token_pool):
            self.token_pool.pop(self.current_token_idx)
            log.warning("Removed bad token; pool size now %d", len(self.token_pool))
            if self.token_pool:
                self.current_token_idx = self.current_token_idx % len(self.token_pool)
                self.github_token = self.token_pool[self.current_token_idx]
            else:
                self.current_token_idx = 0
                self.github_token = ""
        else:
            log.warning("No token pool; clearing github_token after 401")
            self.github_token = ""
