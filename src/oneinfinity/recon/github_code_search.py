"""
GitHub Code Search Scanner
===========================
Uses GitHub Code Search API with advanced dorks to find secrets.
Based on InfoSec Writeups GitHub Recon methodology.
"""

from __future__ import annotations

import json
import logging
import time
import urllib.request
import urllib.parse
from dataclasses import dataclass, field, asdict
from typing import List, Optional, Dict

from oneinfinity.recon.github_advanced_dorks import (
    get_high_priority_dorks,
    KEYWORDS,
    HIGH_VALUE_EXTENSIONS,
)
from oneinfinity.recon.github_dorks_comprehensive import get_domain_dork_set
from oneinfinity.recon.github_dorks_gitdorker import get_comprehensive_dork_set

log = logging.getLogger(__name__)


@dataclass
class CodeSearchResult:
    """Single code search finding."""
    search_id: str
    dork_used: str
    repository: str
    file_path: str
    file_url: str
    html_url: str
    matches: List[str] = field(default_factory=list)
    confidence: float = 0.0
    severity: str = "medium"

    def to_dict(self) -> dict:
        return asdict(self)


@dataclass
class CodeSearchScanResult:
    """Result of code search scan."""
    domain: str
    org: Optional[str] = None
    dorks_executed: int = 0
    total_results: int = 0
    findings: List[Dict] = field(default_factory=list)
    error: str = ""
    scan_duration: float = 0.0
    collected_at: str = field(default_factory=lambda: str(time.time()))

    def to_dict(self) -> dict:
        return asdict(self)


class GitHubCodeSearchScanner:
    """
    Scan GitHub using Code Search API with advanced dorks.
    Supports token rotation for rate limit management.
    """

    def __init__(self, github_token: str, token_pool: Optional[List[str]] = None):
        self.github_token = github_token
        self.token_pool = token_pool or [github_token] if github_token else []
        self.current_token_idx = 0
        self.request_count = 0
        self.session_id = str(time.time())[:10]
        self.base_url = "https://api.github.com/search/code"

    def _get_token(self) -> str:
        """Get next token from pool (rotate every 30 requests)."""
        if not self.token_pool:
            return self.github_token or ""

        if self.request_count > 0 and self.request_count % 30 == 0:
            self.current_token_idx = (self.current_token_idx + 1) % len(self.token_pool)
            log.info(f"[{self.session_id}] Rotating to token {self.current_token_idx + 1}/{len(self.token_pool)}")

        return self.token_pool[self.current_token_idx]

    def scan_domain(
        self,
        domain: str,
        org: Optional[str] = None,
        max_dorks: int = 20,
        max_results_per_dork: int = 10,
        timeout: int = 300,
    ) -> CodeSearchScanResult:
        """
        Scan domain using GitHub Code Search with prioritized dorks.

        Args:
            domain: Target domain
            org: GitHub organization (optional)
            max_dorks: Max dorks to execute
            max_results_per_dork: Results per dork
            timeout: Max scan duration
        """
        start_time = time.time()
        result = CodeSearchScanResult(domain=domain, org=org)

        if not self.github_token:
            result.error = "GitHub token required for code search"
            return result

        # Get enhanced dork set with quoted patterns, language filters, NOT operators
        dorks = get_comprehensive_dork_set(
            domain=domain,
            org=org,
            include_keywords=True,
            include_filenames=True,
            include_extensions=True,
            include_languages=False,  # Skip for now (adds too many)
            limit=max_dorks
        )
        log.info(f"[{self.session_id}] Executing {len(dorks)} enhanced dorks")

        findings = []

        for dork, name, priority in dorks:
            if time.time() - start_time > timeout:
                result.error = "timeout"
                break

            result.dorks_executed += 1

            # Execute search
            search_results = self._search_code(dork, max_results_per_dork)

            if not search_results:
                continue

            # Process results
            for item in search_results:
                finding = self._process_search_result(item, dork, priority)
                if finding:
                    findings.append(finding.to_dict())

        result.findings = findings
        result.total_results = len(findings)
        result.scan_duration = time.time() - start_time

        log.info(f"[{self.session_id}] Scan complete: {result.total_results} findings")
        return result

    def _search_code(
        self,
        query: str,
        per_page: int = 10,
    ) -> Optional[List[dict]]:
        """Execute GitHub Code Search with token rotation."""
        token = self._get_token()
        self.request_count += 1

        headers = {
            "User-Agent": "OneInfinity-CodeSearch/1.0",
            "Authorization": f"token {token}",
            "Accept": "application/vnd.github+json",
            "Accept": "application/vnd.github.text-match+json",  # Get text matches
        }

        encoded_query = urllib.parse.quote(query)
        url = f"{self.base_url}?q={encoded_query}&per_page={per_page}"

        try:
            req = urllib.request.Request(url, headers=headers)
            with urllib.request.urlopen(req, timeout=20) as resp:
                data = json.loads(resp.read().decode("utf-8"))
                return data.get("items", [])
        except urllib.error.HTTPError as exc:
            if getattr(exc, "code", None) == 403:
                hdrs = getattr(exc, "headers", None)
                retry_after = hdrs.get("Retry-After") if hdrs else None
                reset_ts    = hdrs.get("X-RateLimit-Reset") if hdrs else None
                if retry_after:
                    wait = float(retry_after) + 1
                elif reset_ts:
                    wait = max(1.0, int(reset_ts) - time.time() + 1)
                else:
                    wait = 61.0
                log.warning("[%s] GitHub rate limit (403) — waiting %.0fs", self.session_id, wait)
                time.sleep(wait)
            return None
        except Exception as exc:
            log.debug(f"[{self.session_id}] Search failed: {exc}")
            return None

    def _process_search_result(
        self,
        item: dict,
        dork: str,
        priority: int
    ) -> Optional[CodeSearchResult]:
        """Process single search result item."""
        try:
            repo = item.get("repository", {})
            repo_full_name = repo.get("full_name", "unknown")
            file_path = item.get("path", "")
            html_url = item.get("html_url", "")
            file_url = item.get("url", "")

            # Extract text matches
            matches = []
            for match in item.get("text_matches", []):
                fragment = match.get("fragment", "")
                if fragment:
                    matches.append(fragment[:200])  # Truncate

            # Determine severity based on dork priority
            severity = "critical" if priority >= 9 else "high" if priority >= 7 else "medium"

            # Calculate confidence
            confidence = min(1.0, priority / 10.0)

            # Create unique ID
            search_id = f"cs-{hash(f'{repo_full_name}:{file_path}:{dork}') & 0xffffffff:08x}"

            return CodeSearchResult(
                search_id=search_id,
                dork_used=dork,
                repository=repo_full_name,
                file_path=file_path,
                file_url=file_url,
                html_url=html_url,
                matches=matches,
                confidence=confidence,
                severity=severity,
            )
        except Exception as exc:
            log.debug(f"[{self.session_id}] Failed to process result: {exc}")
            return None
