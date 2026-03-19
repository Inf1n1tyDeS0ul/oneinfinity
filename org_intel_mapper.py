"""
Org-Domain Intelligence Mapper
==============================
Maps a GitHub organization to likely domains by inspecting repo metadata.

Sources:
  - repo homepage URLs
  - URLs in repo descriptions

No external dependencies; uses GitHub public API with optional token.
"""

from __future__ import annotations

import json
import logging
import re
import time
import urllib.request
import urllib.parse
from dataclasses import dataclass, field, asdict
from typing import List, Optional

log = logging.getLogger(__name__)

_URL_RE = re.compile(r"https?://[^\s\)\"'>]+")


@dataclass
class OrgDomainResult:
    org: str
    repos_scanned: int = 0
    domains: List[str] = field(default_factory=list)
    urls: List[str] = field(default_factory=list)
    error: str = ""
    collected_at: str = field(default_factory=lambda: str(time.time()))

    def to_dict(self) -> dict:
        return asdict(self)

    def to_json(self, indent: int = 2) -> str:
        return json.dumps(self.to_dict(), indent=indent)


class OrgDomainMapper:
    """
    Map GitHub org → probable domains using repo metadata.
    """

    def map_org(
        self,
        org: str,
        github_token: Optional[str] = None,
        max_repos: int = 200,
    ) -> OrgDomainResult:
        org = self._normalize_org(org)
        result = OrgDomainResult(org=org)
        if not org:
            result.error = "invalid_org"
            return result

        per_page = 100
        page = 1
        headers = {"User-Agent": "OneInfinity/1.0"}
        if github_token:
            headers["Authorization"] = f"token {github_token}"

        urls: List[str] = []
        domains: set[str] = set()

        while result.repos_scanned < max_repos:
            api = f"https://api.github.com/orgs/{org}/repos?per_page={per_page}&page={page}"
            page += 1
            data = self._fetch_json(api, headers=headers, timeout=20, retries=2)
            if data is None:
                result.error = "request_failed"
                break

            if not isinstance(data, list) or not data:
                break

            for repo in data:
                if result.repos_scanned >= max_repos:
                    break
                result.repos_scanned += 1

                homepage = (repo.get("homepage") or "").strip()
                desc = (repo.get("description") or "").strip()

                for src in (homepage, desc):
                    for u in _URL_RE.findall(src):
                        urls.append(u)
                        d = self._extract_domain(u)
                        if d:
                            domains.add(d)

            if len(data) < per_page:
                break

        result.urls = sorted(set(urls))
        result.domains = sorted(domains)
        return result

    @staticmethod
    def _extract_domain(url: str) -> str:
        try:
            parsed = urllib.parse.urlparse(url)
            host = parsed.hostname or ""
            if host.startswith("www."):
                host = host[4:]
            return host
        except Exception:
            return ""

    @staticmethod
    def _normalize_org(org: str) -> str:
        org = (org or "").strip()
        if org.startswith("https://github.com/"):
            org = org.split("github.com/", 1)[1].strip("/")
        return org

    @staticmethod
    def _fetch_json(url: str, headers: dict, timeout: int = 20, retries: int = 2):
        for attempt in range(retries + 1):
            try:
                req = urllib.request.Request(url, headers=headers)
                with urllib.request.urlopen(req, timeout=timeout) as resp:
                    return json.loads(resp.read().decode("utf-8", errors="replace"))
            except urllib.error.HTTPError as exc:
                # Rate limit handling
                if getattr(exc, "code", None) == 403:
                    log.debug("GitHub rate limit (attempt %d): %s", attempt + 1, exc)
                    time.sleep(2.0 * (attempt + 1))
                    continue
                log.debug("GitHub HTTPError (attempt %d): %s", attempt + 1, exc)
                time.sleep(0.3 * (attempt + 1))
                continue
            except urllib.error.URLError as exc:
                log.debug("GitHub URLError (attempt %d): %s", attempt + 1, exc)
                time.sleep(0.3 * (attempt + 1))
                continue
            except Exception as exc:
                log.debug("GitHub fetch failed (attempt %d): %s", attempt + 1, exc)
                time.sleep(0.3 * (attempt + 1))
                continue
        return None
