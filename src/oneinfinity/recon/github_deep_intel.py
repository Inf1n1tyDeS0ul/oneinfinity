"""
GitHub Deep Intelligence Scanner
=================================
Comprehensive GitHub OSINT for bug bounty reconnaissance.

Extracts:
- Email addresses (commits, profiles)
- Technology stack (languages, frameworks, dependencies)
- Repository metadata (activity, visibility, features)
- Infrastructure leaks (S3, domains, IPs, APIs)
- Configuration samples (.env, docker, k8s)
- GitHub Pages sites
- Organization members
- Sensitive patterns in code
"""

from __future__ import annotations

import json
import logging
import re
import threading
import time
import urllib.request
import urllib.parse
from collections import Counter, defaultdict
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass, field, asdict
from typing import List, Optional, Dict, Set

log = logging.getLogger(__name__)


# Additional secret/sensitive patterns
_ADDITIONAL_PATTERNS = [
    # Cloud providers
    (r'AZURE[A-Z0-9_-]{10,}', "azure_key", "high"),
    (r'[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}', "uuid_or_api_key", "medium"),
    (r'dop_v1_[a-f0-9]{64}', "digitalocean_token", "critical"),
    (r'(?:cloudflare|cf)[_-]?(?:api|token)[_-]?key["\']?\s*[:=]\s*["\']?([a-zA-Z0-9_-]{37,})', "cloudflare_key", "high"),

    # SaaS tokens
    (r'SG\.[a-zA-Z0-9_-]{22}\.[a-zA-Z0-9_-]{43}', "sendgrid_key", "critical"),
    (r'key-[a-f0-9]{32}', "mailgun_key", "high"),
    (r'AC[a-f0-9]{32}', "twilio_account_sid", "high"),
    (r'npm_[a-zA-Z0-9]{36}', "npm_token", "high"),
    (r'pypi-[A-Za-z0-9_-]{43,}', "pypi_token", "high"),

    # Firebase
    (r'"apiKey"\s*:\s*"(AIza[0-9A-Za-z_\-]{35})"', "firebase_api_key", "high"),
    (r'"project_id"\s*:\s*"([a-z0-9-]+)"', "gcp_project_id", "medium"),

    # Infrastructure
    (r's3://[a-z0-9.-]+', "s3_bucket_url", "medium"),
    (r'[a-z0-9.-]+\.s3\.amazonaws\.com', "s3_bucket_domain", "medium"),
    (r'[a-z0-9.-]+\.s3-[a-z0-9-]+\.amazonaws\.com', "s3_bucket_regional", "medium"),

    # Internal domains/IPs
    (r'(?:https?://)?(?:staging|dev|test|internal|admin|api)[.-][a-z0-9.-]+\.[a-z]{2,}', "staging_domain", "medium"),
    (r'10\.\d{1,3}\.\d{1,3}\.\d{1,3}', "private_ip_10", "low"),
    (r'172\.(?:1[6-9]|2[0-9]|3[01])\.\d{1,3}\.\d{1,3}', "private_ip_172", "low"),
    (r'192\.168\.\d{1,3}\.\d{1,3}', "private_ip_192", "low"),

    # API endpoints
    (r'(?:https?://)?[a-z0-9.-]+/api/v[0-9]/[a-z0-9/_-]+', "api_endpoint", "low"),

    # Database hosts
    (r'(?:db|database|postgres|mysql|mongo)[.-][a-z0-9.-]+\.[a-z]{2,}', "database_host", "medium"),
]

_COMPILED_ADDITIONAL = [
    (re.compile(p, re.IGNORECASE), stype, sev)
    for p, stype, sev in _ADDITIONAL_PATTERNS
]


@dataclass
class EmailIntel:
    """Email intelligence."""
    email: str
    name: Optional[str] = None
    github_username: Optional[str] = None
    commit_count: int = 0
    repos: List[str] = field(default_factory=list)


@dataclass
class TechStackInfo:
    """Technology stack information."""
    languages: Dict[str, int] = field(default_factory=dict)  # language: bytes
    frameworks: Set[str] = field(default_factory=set)
    package_managers: Set[str] = field(default_factory=set)
    ci_platforms: Set[str] = field(default_factory=set)


@dataclass
class InfrastructureIntel:
    """Infrastructure intelligence."""
    s3_buckets: Set[str] = field(default_factory=set)
    internal_domains: Set[str] = field(default_factory=set)
    api_endpoints: Set[str] = field(default_factory=set)
    database_hosts: Set[str] = field(default_factory=set)
    private_ips: Set[str] = field(default_factory=set)


@dataclass
class DeepIntelResult:
    """Comprehensive GitHub intelligence."""
    org: str
    repos_scanned: int = 0

    # Basic intel
    domains: List[str] = field(default_factory=list)
    urls: List[str] = field(default_factory=list)

    # Email/People intel
    emails: List[Dict] = field(default_factory=list)
    contributors: List[str] = field(default_factory=list)

    # Tech stack
    languages: Dict[str, int] = field(default_factory=dict)
    frameworks: List[str] = field(default_factory=list)

    # Infrastructure
    s3_buckets: List[str] = field(default_factory=list)
    internal_domains: List[str] = field(default_factory=list)
    api_endpoints: List[str] = field(default_factory=list)
    staging_urls: List[str] = field(default_factory=list)

    # GitHub-specific
    github_pages_sites: List[str] = field(default_factory=list)
    has_actions: bool = False
    public_repos: int = 0
    private_repos: int = 0

    # Metadata
    error: str = ""
    scan_duration: float = 0.0
    collected_at: str = field(default_factory=lambda: str(time.time()))

    def to_dict(self) -> dict:
        return asdict(self)

    def to_json(self, indent: int = 2) -> str:
        return json.dumps(self.to_dict(), indent=indent)


class GitHubDeepIntel:
    """Comprehensive GitHub intelligence scanner."""

    def __init__(self, github_token: Optional[str] = None, token_pool: Optional[List[str]] = None):
        self.github_token = github_token
        self.token_pool = token_pool or ([github_token] if github_token else [])
        self.current_token_idx = 0
        self.request_count = 0
        self.session_id = str(time.time())[:10]
        self._token_lock = threading.Lock()

    def _get_token(self) -> str:
        """Rotate token every 30 requests to prevent rate limiting (thread-safe)."""
        with self._token_lock:
            if not self.token_pool:
                return self.github_token or ""
            if self.request_count > 0 and self.request_count % 30 == 0:
                self.current_token_idx = (self.current_token_idx + 1) % len(self.token_pool)
                log.info(f"[{self.session_id}] Rotating to token {self.current_token_idx + 1}/{len(self.token_pool)}")
            self.request_count += 1
            return self.token_pool[self.current_token_idx]

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

    def scan_org(
        self,
        org: str,
        max_repos: int = 200,
        deep_scan: bool = True,
        timeout: int = 600
    ) -> DeepIntelResult:
        """
        Deep scan organization.

        Args:
            org: GitHub organization name
            max_repos: Max repos to scan
            deep_scan: Fetch commit/contributor data
            timeout: Max scan duration
        """
        start_time = time.time()
        org = self._normalize_org(org)
        result = DeepIntelResult(org=org)

        if not org:
            result.error = "invalid_org"
            return result

        headers = {"User-Agent": "OneInfinity-DeepIntel/1.0"}
        token = self._get_token()
        if token:
            headers["Authorization"] = f"token {token}"

        try:
            # Fetch repos
            repos = self._fetch_repos(org, max_repos, headers)
            if not repos:
                # Check if it's a rate limit issue
                if not self.github_token:
                    result.error = "rate_limit_or_no_repos (use GitHub token for higher limits: 60→5000/hr)"
                else:
                    result.error = "no_repos_found_or_rate_limit"
                result.scan_duration = time.time() - start_time
                return result

            log.info(f"[{self.session_id}] Deep scanning {len(repos)} repos (parallel)")
            result.repos_scanned = len(repos)

            # Thread-safe accumulators
            _lock = threading.Lock()
            contributors_set: Set[str] = set()
            languages_counter: Counter = Counter()
            frameworks_set: Set[str] = set()
            infra = InfrastructureIntel()

            def _process_repo(repo: dict) -> Optional[dict]:
                """Process one repo; returns partial metadata or None on timeout."""
                if time.time() - start_time > timeout:
                    return None
                repo_name = repo.get("full_name")
                token = self._get_token()
                hdrs = {"User-Agent": "OneInfinity-DeepIntel/1.0"}
                if token:
                    hdrs["Authorization"] = f"token {token}"

                partial: dict = {
                    "private":   repo.get("private", False),
                    "has_pages": repo.get("has_pages", False),
                    "name":      repo.get("name", ""),
                    "homepage":  repo.get("homepage", ""),
                    "has_actions": False,
                    "langs":     {},
                    "contributors": [],
                    "findings":  [],
                }
                # Workflows: check actual API field or .github directory in tree
                wf_data = self._fetch_json(
                    f"https://api.github.com/repos/{repo_name}/contents/.github/workflows",
                    hdrs,
                )
                if isinstance(wf_data, list) and wf_data:
                    partial["has_actions"] = True

                # Languages
                lang_data = self._fetch_json(
                    f"https://api.github.com/repos/{repo_name}/languages", hdrs
                )
                if isinstance(lang_data, dict):
                    partial["langs"] = lang_data

                if deep_scan:
                    # Framework / infra files
                    _tmp_fw: Set[str] = set()
                    _tmp_infra = InfrastructureIntel()
                    _tmp_result = DeepIntelResult(org=org)
                    self._scan_repo_files(repo_name, hdrs, _tmp_fw, _tmp_infra, _tmp_result)
                    partial["frameworks"] = _tmp_fw
                    partial["infra"] = _tmp_infra
                    partial["findings"].extend(_tmp_result.findings if hasattr(_tmp_result, "findings") else [])

                    # Contributors
                    contributors = self._fetch_json(
                        f"https://api.github.com/repos/{repo_name}/contributors?per_page=10",
                        hdrs,
                    )
                    if isinstance(contributors, list):
                        partial["contributors"] = [c.get("login") for c in contributors if c.get("login")]

                return partial

            with ThreadPoolExecutor(max_workers=10) as pool:
                futures = {pool.submit(_process_repo, r): r for r in repos}
                for fut in as_completed(futures):
                    partial = fut.result()
                    if partial is None:
                        continue
                    with _lock:
                        if partial["private"]:
                            result.private_repos += 1
                        else:
                            result.public_repos += 1
                        if partial["has_pages"]:
                            pages_url = f"https://{org}.github.io/{partial['name']}"
                            result.github_pages_sites.append(pages_url)
                        if partial["has_actions"]:
                            result.has_actions = True
                        homepage = partial["homepage"]
                        if homepage:
                            result.urls.append(homepage)
                            domain = self._extract_domain(homepage)
                            if domain and domain not in result.domains:
                                result.domains.append(domain)
                        for lang, bc in partial["langs"].items():
                            languages_counter[lang] += bc
                        for u in partial.get("contributors", []):
                            contributors_set.add(u)
                        if "frameworks" in partial:
                            frameworks_set.update(partial["frameworks"])
                        if "infra" in partial:
                            _pi = partial["infra"]
                            infra.s3_buckets.update(_pi.s3_buckets)
                            infra.internal_domains.update(_pi.internal_domains)
                            infra.api_endpoints.update(_pi.api_endpoints)

            # Aggregate results
            result.languages = dict(languages_counter.most_common(20))
            result.frameworks = sorted(frameworks_set)
            result.contributors = sorted(contributors_set)[:50]
            result.s3_buckets = sorted(infra.s3_buckets)
            result.internal_domains = sorted(infra.internal_domains)
            result.api_endpoints = sorted(infra.api_endpoints)[:50]

        except Exception as exc:
            result.error = str(exc)
            log.error(f"[{self.session_id}] Scan failed: {exc}")

        result.scan_duration = time.time() - start_time
        return result

    def _fetch_repos(self, org: str, max_repos: int, headers: dict) -> List[dict]:
        """Fetch repository list."""
        repos = []
        page = 1
        per_page = min(100, max_repos)

        while len(repos) < max_repos:
            url = f"https://api.github.com/orgs/{org}/repos?per_page={per_page}&page={page}&sort=pushed"
            data = self._fetch_json(url, headers, retries=3)

            if data is None:
                # API failed - likely rate limit
                log.warning(f"[{self.session_id}] Failed to fetch repos page {page}, stopping")
                break

            if not isinstance(data, list):
                log.warning(f"[{self.session_id}] Unexpected response type: {type(data)}")
                break

            if not data:  # Empty list = no more repos
                break

            repos.extend(data)

            if len(data) < per_page:
                break

            page += 1
            time.sleep(0.2)  # Rate limit safety

        return repos[:max_repos]

    def _scan_repo_files(
        self,
        repo_name: str,
        headers: dict,
        frameworks: Set[str],
        infra: InfrastructureIntel,
        result: DeepIntelResult
    ):
        """Scan repository files for intel."""
        # Check for common framework indicators
        indicators = [
            "package.json", "requirements.txt", "go.mod", "Cargo.toml",
            "composer.json", "Gemfile", ".dockerignore", "Dockerfile",
            ".env.example", "docker-compose.yml", "kubernetes.yaml"
        ]

        for filename in indicators:
            content_url = f"https://api.github.com/repos/{repo_name}/contents/{filename}"
            file_data = self._fetch_json(content_url, headers)

            if not file_data or "content" not in file_data:
                continue

            # Decode base64 content
            try:
                import base64
                content = base64.b64decode(file_data["content"]).decode("utf-8", errors="ignore")
            except:
                continue

            # Framework detection
            if "package.json" in filename and "react" in content.lower():
                frameworks.add("React")
            if "react-native" in content.lower():
                frameworks.add("React Native")
            if "django" in content.lower():
                frameworks.add("Django")
            if "flask" in content.lower():
                frameworks.add("Flask")
            if "express" in content.lower():
                frameworks.add("Express")

            # Infrastructure patterns
            for pattern, secret_type, severity in _COMPILED_ADDITIONAL:
                matches = pattern.findall(content)
                for match in matches:
                    if "s3" in secret_type:
                        infra.s3_buckets.add(match if isinstance(match, str) else match[0])
                    elif "staging" in secret_type or "internal" in secret_type:
                        infra.internal_domains.add(match if isinstance(match, str) else match[0])
                    elif "api_endpoint" in secret_type:
                        infra.api_endpoints.add(match if isinstance(match, str) else match[0])
                    elif "database" in secret_type:
                        infra.database_hosts.add(match if isinstance(match, str) else match[0])

    @staticmethod
    def _extract_domain(url: str) -> str:
        """Extract domain from URL."""
        try:
            parsed = urllib.parse.urlparse(url)
            host = parsed.hostname or ""
            if host.startswith("www."):
                host = host[4:]
            return host
        except:
            return ""

    @staticmethod
    def _normalize_org(org: str) -> str:
        """Normalize org name."""
        org = (org or "").strip()
        if org.startswith("https://github.com/"):
            org = org.split("github.com/", 1)[1].strip("/")
        return org

    def _fetch_json(self, url: str, headers: dict, retries: int = 1):
        """Fetch JSON from URL with retry logic and proper rate-limit waiting."""
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
                    log.warning("[%s] GitHub 401 Unauthorized — token may be invalid or revoked. Rotating.", self.session_id)
                    self._rotate_token()
                    return {}
                elif code == 404:
                    return None
                elif attempt < retries:
                    time.sleep(1.0 * (attempt + 1))
            except Exception as e:
                log.debug(f"[{self.session_id}] Fetch error: {e}")
                if attempt < retries:
                    time.sleep(0.5 * (attempt + 1))

        return None

    def _rotate_token(self) -> None:
        """Remove the current (invalid/revoked) token from the pool and advance to the next."""
        with self._token_lock:
            if self.token_pool and self.current_token_idx < len(self.token_pool):
                bad_token = self.token_pool.pop(self.current_token_idx)
                log.warning("[%s] Removed bad token (idx %d); pool size now %d",
                            self.session_id, self.current_token_idx, len(self.token_pool))
                if self.token_pool:
                    self.current_token_idx = self.current_token_idx % len(self.token_pool)
                    self.github_token = self.token_pool[self.current_token_idx]
                else:
                    self.current_token_idx = 0
                    self.github_token = ""
            else:
                # No pool — just clear the single token
                log.warning("[%s] No token pool; clearing github_token after 401", self.session_id)
                self.github_token = ""
