"""
GitHub User Enumeration
Find developers associated with organization for individual repository scanning.
"""

from __future__ import annotations

import json
import logging
import time
import urllib.request
import urllib.error
from dataclasses import dataclass, field, asdict
from typing import List, Optional

log = logging.getLogger(__name__)


@dataclass
class GitHubUser:
    """GitHub user profile."""
    login: str
    name: Optional[str] = None
    email: Optional[str] = None
    company: Optional[str] = None
    location: Optional[str] = None
    bio: Optional[str] = None
    public_repos: int = 0
    followers: int = 0
    html_url: str = ""
    avatar_url: str = ""


@dataclass
class UserEnumResult:
    """Result of user enumeration."""
    org: str
    users: List[GitHubUser] = field(default_factory=list)
    total_users: int = 0
    error: str = ""
    collected_at: str = field(default_factory=lambda: str(time.time()))

    def to_dict(self) -> dict:
        return {
            "org": self.org,
            "users": [asdict(u) for u in self.users],
            "total_users": self.total_users,
            "error": self.error,
            "collected_at": self.collected_at,
        }


class GitHubUserEnumerator:
    """
    Enumerate GitHub users associated with organization.
    Useful for finding individual developer repositories.
    """

    def __init__(self, github_token: Optional[str] = None, token_pool: Optional[List[str]] = None):
        self.github_token = github_token
        self.token_pool = token_pool or ([github_token] if github_token else [])
        self.current_token_idx = 0
        self.request_count = 0
        self.session_id = str(time.time())[:10]

    def _get_token(self) -> str:
        """Rotate token every 30 requests to prevent rate limiting."""
        if not self.token_pool:
            return self.github_token or ""

        if self.request_count > 0 and self.request_count % 30 == 0:
            self.current_token_idx = (self.current_token_idx + 1) % len(self.token_pool)
            log.info(f"[{self.session_id}] Rotating to token {self.current_token_idx + 1}/{len(self.token_pool)}")

        self.request_count += 1
        return self.token_pool[self.current_token_idx]

    def enumerate_org_members(
        self,
        org: str,
        max_users: int = 100,
    ) -> UserEnumResult:
        """
        Enumerate organization members.
        Returns list of GitHub users associated with org.
        """
        result = UserEnumResult(org=org)

        if not self.github_token:
            result.error = "GitHub token required for user enumeration"
            return result

        headers = {
            "User-Agent": "OneInfinity-UserEnum/1.0",
            "Authorization": f"token {self._get_token()}",
            "Accept": "application/vnd.github+json",
        }

        try:
            # Get org members
            url = f"https://api.github.com/orgs/{org}/members?per_page={min(max_users, 100)}"
            req = urllib.request.Request(url, headers=headers)

            with urllib.request.urlopen(req, timeout=20) as resp:
                members = json.loads(resp.read().decode())

                for member in members:
                    user = self._fetch_user_details(member["login"], headers)
                    if user:
                        result.users.append(user)

                result.total_users = len(result.users)

        except urllib.error.HTTPError as exc:
            if exc.code == 404:
                result.error = "Organization not found or no public members"
            elif exc.code == 403:
                hdrs = getattr(exc, "headers", None)
                retry_after = hdrs.get("Retry-After") if hdrs else None
                reset_ts    = hdrs.get("X-RateLimit-Reset") if hdrs else None
                if retry_after:
                    wait = float(retry_after) + 1
                elif reset_ts:
                    wait = max(1.0, int(reset_ts) - time.time() + 1)
                else:
                    wait = 61.0
                log.warning("GitHub rate limit (403) — waiting %.0fs", wait)
                result.error = f"Rate limit — reset in {wait:.0f}s"
            else:
                result.error = f"HTTP {exc.code}"
        except Exception as exc:
            result.error = str(exc)

        log.info(f"[{self.session_id}] Enumerated {result.total_users} users for {org}")
        return result

    def _fetch_user_details(self, username: str, headers: dict) -> Optional[GitHubUser]:
        """Fetch detailed user profile."""
        try:
            url = f"https://api.github.com/users/{username}"
            req = urllib.request.Request(url, headers=headers)

            with urllib.request.urlopen(req, timeout=10) as resp:
                data = json.loads(resp.read().decode())

                return GitHubUser(
                    login=data.get("login", ""),
                    name=data.get("name"),
                    email=data.get("email"),
                    company=data.get("company"),
                    location=data.get("location"),
                    bio=data.get("bio"),
                    public_repos=data.get("public_repos", 0),
                    followers=data.get("followers", 0),
                    html_url=data.get("html_url", ""),
                    avatar_url=data.get("avatar_url", ""),
                )

        except Exception as exc:
            log.debug(f"[{self.session_id}] Failed to fetch user {username}: {exc}")
            return None

    def scan_user_repos(
        self,
        username: str,
        max_repos: int = 50,
    ) -> List[dict]:
        """
        Get list of user's public repositories.
        Useful for scanning individual developer repos.
        """
        if not self.github_token:
            return []

        headers = {
            "User-Agent": "OneInfinity-UserEnum/1.0",
            "Authorization": f"token {self._get_token()}",
            "Accept": "application/vnd.github+json",
        }

        repos = []

        try:
            url = f"https://api.github.com/users/{username}/repos?per_page={min(max_repos, 100)}&sort=updated"
            req = urllib.request.Request(url, headers=headers)

            with urllib.request.urlopen(req, timeout=20) as resp:
                data = json.loads(resp.read().decode())

                for repo in data:
                    repos.append({
                        "name": repo.get("name"),
                        "full_name": repo.get("full_name"),
                        "private": repo.get("private", True),
                        "html_url": repo.get("html_url"),
                        "description": repo.get("description"),
                        "language": repo.get("language"),
                        "updated_at": repo.get("updated_at"),
                        "size": repo.get("size", 0),
                    })

        except Exception as exc:
            log.debug(f"[{self.session_id}] Failed to fetch repos for {username}: {exc}")

        return repos
