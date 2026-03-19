"""
OrgGraph — builds and caches a domain ↔ GitHub org ↔ repo relationship graph
for the duration of a scan run.

Graph model
-----------
    Domain → Org → Repo → File → Secret

Data sources
------------
  * GitHub API /orgs/{org}      — org metadata (name, description, homepage)
  * GitHub API /users/{user}    — fallback for user accounts
  * GitHub API /orgs/{org}/repos and /users/{org}/repos — repo index

Usage
-----
    graph = OrgGraph(github_token="ghp_...")
    domain_data = graph.build_for_domain("stripe.com")
    # domain_data = {"domain": "stripe.com", "orgs": [...], "org_logins": ["stripe"], "repos": [...]}

    is_owned = graph.is_repo_in_graph("stripe/stripe-python", "stripe.com")
    # True

One instance per scan run is the recommended pattern; build_for_domain() caches
results so repeated calls for the same domain are free.
"""

import json
import logging
import urllib.request
import urllib.error
from typing import Any, Dict, List, Optional

from agents.secret_intel.ownership_engine import map_domain_to_orgs

logger = logging.getLogger(__name__)

_GH_API   = "https://api.github.com"
_TIMEOUT  = 5   # seconds per API call
_REPO_CAP = 30  # max repos indexed per org (first page, sorted by recently updated)


class OrgGraph:
    """
    Domain-to-GitHub-org relationship graph with per-run caching.

    Thread safety: build_for_domain() and is_repo_in_graph() are safe to call
    from multiple threads; the internal dicts are built under a single-threaded
    construction phase (called once per domain before parallel work begins).
    """

    def __init__(self, github_token: Optional[str] = None):
        self._token  = github_token
        self._graph: Dict[str, Any]  = {}   # domain → graph node
        self._cache: Dict[str, Any]  = {}   # org login → GitHub API metadata
        self._headers = {
            "Accept":     "application/vnd.github.v3+json",
            "User-Agent": "OneInfinity-OrgGraph/1.0",
        }
        if github_token:
            self._headers["Authorization"] = f"token {github_token}"

    # ── Public interface ───────────────────────────────────────────────────────

    def build_for_domain(self, domain: str) -> Dict[str, Any]:
        """
        Build (or return cached) org graph for *domain*.

        Returns
        -------
        {
            "domain":     str,
            "orgs":       [{"login", "name", "description", "homepage", "type",
                            "public_repos"}, ...],
            "org_logins": [str, ...],   # lowercased; used for fast membership check
            "repos":      [{"full_name", "description", "homepage", "owner"}, ...],
        }
        """
        if domain in self._graph:
            return self._graph[domain]

        candidate_orgs = map_domain_to_orgs(domain, github_token=self._token)
        verified_orgs: List[Dict[str, Any]] = []
        repos:         List[Dict[str, Any]] = []

        for org in candidate_orgs:
            meta = self._fetch_org_or_user(org)
            if not meta:
                continue

            verified_orgs.append({
                "login":        meta.get("login", org).lower(),
                "name":         meta.get("name", ""),
                "description":  meta.get("description", ""),
                "homepage":     meta.get("blog", "") or meta.get("html_url", ""),
                "type":         meta.get("type", "Organization"),
                "public_repos": meta.get("public_repos", 0),
            })

            org_repos = self._fetch_repos(org)
            repos.extend(org_repos)

        graph: Dict[str, Any] = {
            "domain":     domain,
            "orgs":       verified_orgs,
            "org_logins": [o["login"] for o in verified_orgs],
            "repos":      repos,
        }
        self._graph[domain] = graph

        logger.info(
            "OrgGraph built: domain=%s → %d org(s), %d repo(s) indexed",
            domain, len(verified_orgs), len(repos),
        )
        return graph

    def is_repo_in_graph(self, repo_full_name: str, domain: str) -> bool:
        """
        Return True if *repo_full_name* is owned by a verified org for *domain*.
        Builds the graph on first call if not yet cached.
        """
        graph = self._graph.get(domain)
        if graph is None:
            graph = self.build_for_domain(domain)

        owner = (
            repo_full_name.split("/")[0].lower()
            if "/" in repo_full_name
            else repo_full_name.lower()
        )
        return owner in graph.get("org_logins", [])

    def summary(self) -> Dict[str, Any]:
        """Compact summary of the graph for embedding in scan reports."""
        return {
            domain: {
                "orgs":  [o["login"] for o in data.get("orgs", [])],
                "repos": len(data.get("repos", [])),
            }
            for domain, data in self._graph.items()
        }

    # ── GitHub API helpers ─────────────────────────────────────────────────────

    def _gh_get(self, path: str) -> Optional[Any]:
        """GET *path* from GitHub API. Returns parsed JSON or None."""
        url = f"{_GH_API}{path}"
        try:
            req = urllib.request.Request(url, headers=self._headers)
            with urllib.request.urlopen(req, timeout=_TIMEOUT) as resp:
                return json.loads(resp.read().decode())
        except urllib.error.HTTPError as exc:
            if exc.code not in (404, 403):
                logger.debug("OrgGraph: %s → HTTP %d", path, exc.code)
            return None
        except Exception as exc:
            logger.debug("OrgGraph: %s → %s", path, exc)
            return None

    def _fetch_org_or_user(self, login: str) -> Optional[Dict[str, Any]]:
        """Fetch org metadata; falls back to user endpoint if org 404s."""
        if login in self._cache:
            return self._cache[login]
        meta = self._gh_get(f"/orgs/{login}") or self._gh_get(f"/users/{login}")
        if meta:
            self._cache[login] = meta
        return meta

    def _fetch_repos(self, org: str) -> List[Dict[str, Any]]:
        """Fetch the first *_REPO_CAP* public repos for *org*."""
        data = (
            self._gh_get(f"/orgs/{org}/repos?per_page={_REPO_CAP}&sort=updated")
            or self._gh_get(f"/users/{org}/repos?per_page={_REPO_CAP}&sort=updated")
        )
        if not isinstance(data, list):
            return []
        return [
            {
                "full_name":   repo.get("full_name", ""),
                "description": repo.get("description", ""),
                "homepage":    repo.get("homepage", ""),
                "owner":       repo.get("owner", {}).get("login", "").lower(),
            }
            for repo in data
        ]
