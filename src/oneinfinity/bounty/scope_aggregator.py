"""
scope_aggregator.py — Live Bug Bounty Platform Scope Aggregation

Pulls in-scope assets from:
  - HackerOne GraphQL API
  - Bugcrowd REST API
  - Intigriti REST API
  - YesWeHack REST API
  - Public dataset: bounty-targets-data (JSON snapshots)

Also tracks scope diffs between runs to automatically surface newly added
attack surface — fresh assets that other hunters haven't reached yet.

Usage::
    aggregator = ScopeAggregator()
    assets = aggregator.aggregate(["hackerone:shopify", "bugcrowd:tesla"])
    aggregator.feed_scope_validator(scope_validator_instance)

    # Diff tracking
    new_assets = aggregator.diff_with_previous("hackerone:shopify", assets)
"""
from __future__ import annotations

import hashlib
import json
import logging
import os
import re
import time
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import dataclass, field, asdict
from pathlib import Path
from typing import Dict, List, Optional, Tuple

log = logging.getLogger("oneinfinity.scope_aggregator")

# ---------------------------------------------------------------------------
# Data models
# ---------------------------------------------------------------------------

@dataclass
class ScopeAsset:
    value: str                    # domain / IP / URL / wildcard
    asset_type: str               # url, domain, wildcard, cidr, android, ios
    max_severity: str = "critical"
    in_scope: bool = True
    platform: str = ""
    program: str = ""
    notes: str = ""
    fetched_at: float = field(default_factory=time.time)

    def to_dict(self) -> dict:
        return asdict(self)

    @property
    def fingerprint(self) -> str:
        return hashlib.md5(f"{self.value}:{self.platform}:{self.program}".encode()).hexdigest()


@dataclass
class ScopeDiff:
    program: str
    platform: str
    added: List[ScopeAsset] = field(default_factory=list)
    removed: List[ScopeAsset] = field(default_factory=list)
    unchanged_count: int = 0
    diff_at: float = field(default_factory=time.time)

    @property
    def has_changes(self) -> bool:
        return bool(self.added or self.removed)


# ---------------------------------------------------------------------------
# Platform clients
# ---------------------------------------------------------------------------

class HackerOneClient:
    """HackerOne GraphQL API client."""

    _GQL = "https://hackerone.com/graphql"

    def __init__(self, api_key: str = "", username: str = "") -> None:
        self.api_key = api_key or os.getenv("H1_API_KEY", os.getenv("HACKERONE_API_KEY", ""))
        self.username = username or os.getenv("H1_USERNAME", os.getenv("HACKERONE_USERNAME", ""))

    def _headers(self) -> Dict[str, str]:
        h = {"Content-Type": "application/json"}
        if self.api_key and self.username:
            import base64
            creds = base64.b64encode(f"{self.username}:{self.api_key}".encode()).decode()
            h["Authorization"] = f"Basic {creds}"
        return h

    def get_scope(self, handle: str) -> List[ScopeAsset]:
        """Fetch structured scope assets for a H1 program handle."""
        query = """
        query ProgramScope($handle: String!) {
          team(handle: $handle) {
            in_scope_assets: structured_scope_versions(current: true) {
              edges {
                node {
                  asset_identifier
                  asset_type
                  max_severity
                  instruction
                }
              }
            }
            out_of_scope: structured_scope_versions(current: true, out_of_scope: true) {
              edges {
                node {
                  asset_identifier
                  asset_type
                }
              }
            }
          }
        }
        """
        try:
            body = json.dumps({"query": query, "variables": {"handle": handle}}).encode()
            req = urllib.request.Request(self._GQL, data=body, headers=self._headers(), method="POST")
            with urllib.request.urlopen(req, timeout=15) as r:
                data = json.loads(r.read())
        except Exception as exc:
            log.warning("H1 scope fetch failed for %s: %s", handle, exc)
            return []

        assets: List[ScopeAsset] = []
        team = (data.get("data") or {}).get("team") or {}

        for edge in (team.get("in_scope_assets") or {}).get("edges", []):
            node = edge.get("node", {})
            assets.append(ScopeAsset(
                value=node.get("asset_identifier", ""),
                asset_type=(node.get("asset_type") or "url").lower(),
                max_severity=(node.get("max_severity") or "critical").lower(),
                in_scope=True,
                platform="hackerone",
                program=handle,
            ))

        for edge in (team.get("out_of_scope") or {}).get("edges", []):
            node = edge.get("node", {})
            assets.append(ScopeAsset(
                value=node.get("asset_identifier", ""),
                asset_type=(node.get("asset_type") or "url").lower(),
                in_scope=False,
                platform="hackerone",
                program=handle,
            ))

        log.info("H1 scope for %s: %d assets", handle, len(assets))
        return assets

    def get_hacktivity(self, handle: str, limit: int = 50) -> List[dict]:
        """Return recently disclosed vulnerability reports for a program."""
        query = """
        query Hacktivity($handle: String!, $limit: Int!) {
          team(handle: $handle) {
            disclosed_reports: hacktivity_items(
              first: $limit
              order_by: {field: latest_disclosable_activity_at, direction: DESC}
            ) {
              edges {
                node {
                  ... on HacktivityItemUnion {
                    report {
                      title
                      severity { rating }
                      weakness { name }
                      bounty_amount
                    }
                  }
                }
              }
            }
          }
        }
        """
        try:
            body = json.dumps({
                "query": query,
                "variables": {"handle": handle, "limit": limit},
            }).encode()
            req = urllib.request.Request(self._GQL, data=body, headers=self._headers(), method="POST")
            with urllib.request.urlopen(req, timeout=15) as r:
                data = json.loads(r.read())
        except Exception as exc:
            log.warning("H1 hacktivity fetch failed for %s: %s", handle, exc)
            return []

        items = []
        for edge in ((data.get("data") or {}).get("team") or {}).get("disclosed_reports", {}).get("edges", []):
            node = edge.get("node", {})
            report = node.get("report", {})
            if report:
                items.append({
                    "title": report.get("title", ""),
                    "severity": (report.get("severity") or {}).get("rating", ""),
                    "weakness": (report.get("weakness") or {}).get("name", ""),
                    "bounty": report.get("bounty_amount", 0),
                })
        return items


class BugcrowdClient:
    """Bugcrowd REST API client."""

    _BASE = "https://api.bugcrowd.com"

    def __init__(self, api_key: str = "") -> None:
        self.api_key = api_key or os.getenv("BUGCROWD_API_KEY", "")

    def _headers(self) -> Dict[str, str]:
        h = {
            "Accept": "application/vnd.bugcrowd.v4+json",
            "Content-Type": "application/json",
        }
        if self.api_key:
            h["Authorization"] = f"Token {self.api_key}"
        return h

    def get_scope(self, program_code: str) -> List[ScopeAsset]:
        """Fetch targets for a Bugcrowd program code."""
        try:
            url = f"{self._BASE}/programs/{program_code}/targets"
            req = urllib.request.Request(url, headers=self._headers(), method="GET")
            with urllib.request.urlopen(req, timeout=15) as r:
                data = json.loads(r.read())
        except Exception as exc:
            log.warning("Bugcrowd scope fetch failed for %s: %s", program_code, exc)
            return []

        assets: List[ScopeAsset] = []
        for item in data.get("data", []):
            attrs = item.get("attributes", {})
            category = attrs.get("category", "website").lower()
            name = attrs.get("name", "")
            if not name:
                continue
            assets.append(ScopeAsset(
                value=name,
                asset_type="url" if category in ("website", "api") else category,
                max_severity=(attrs.get("priority") or "p1").replace("p", "").replace("1", "critical")
                             .replace("2", "high").replace("3", "medium").replace("4", "low"),
                in_scope=not attrs.get("out_of_scope", False),
                platform="bugcrowd",
                program=program_code,
            ))

        log.info("Bugcrowd scope for %s: %d assets", program_code, len(assets))
        return assets


class IntigritiClient:
    """Intigriti REST API client."""

    _BASE = "https://api.intigriti.com/core/researcher/program"

    def __init__(self, api_key: str = "") -> None:
        self.api_key = api_key or os.getenv("INTIGRITI_API_KEY", "")

    def _headers(self) -> Dict[str, str]:
        h = {"Accept": "application/json"}
        if self.api_key:
            h["Authorization"] = f"Bearer {self.api_key}"
        return h

    def get_scope(self, program_id: str) -> List[ScopeAsset]:
        """Fetch scope for an Intigriti program ID."""
        try:
            url = f"{self._BASE}/{program_id}"
            req = urllib.request.Request(url, headers=self._headers(), method="GET")
            with urllib.request.urlopen(req, timeout=15) as r:
                data = json.loads(r.read())
        except Exception as exc:
            log.warning("Intigriti scope fetch failed for %s: %s", program_id, exc)
            return []

        assets: List[ScopeAsset] = []
        for domain in data.get("domains", {}).get("in_scope", []):
            endpoint = domain.get("endpoint", "")
            if endpoint:
                assets.append(ScopeAsset(
                    value=endpoint,
                    asset_type="url",
                    max_severity=(domain.get("tier") or "high").lower(),
                    in_scope=True,
                    platform="intigriti",
                    program=program_id,
                ))

        for domain in data.get("domains", {}).get("out_of_scope", []):
            endpoint = domain.get("endpoint", "")
            if endpoint:
                assets.append(ScopeAsset(
                    value=endpoint,
                    asset_type="url",
                    in_scope=False,
                    platform="intigriti",
                    program=program_id,
                ))

        log.info("Intigriti scope for %s: %d assets", program_id, len(assets))
        return assets


class YesWeHackClient:
    """YesWeHack REST API client."""

    _BASE = "https://api.yeswehack.com"

    def __init__(self, api_key: str = "") -> None:
        self.api_key = api_key or os.getenv("YESWEHACK_API_KEY", "")

    def _headers(self) -> Dict[str, str]:
        h = {"Accept": "application/json"}
        if self.api_key:
            h["Authorization"] = f"Bearer {self.api_key}"
        return h

    def get_scope(self, slug: str) -> List[ScopeAsset]:
        """Fetch scope for a YesWeHack program slug."""
        try:
            url = f"{self._BASE}/programs/{slug}"
            req = urllib.request.Request(url, headers=self._headers(), method="GET")
            with urllib.request.urlopen(req, timeout=15) as r:
                data = json.loads(r.read())
        except Exception as exc:
            log.warning("YWH scope fetch failed for %s: %s", slug, exc)
            return []

        assets: List[ScopeAsset] = []
        for scope_item in data.get("scopes", []):
            scope_type = scope_item.get("scope_type", "web-application").lower()
            scope_val = scope_item.get("scope", "")
            if scope_val:
                assets.append(ScopeAsset(
                    value=scope_val,
                    asset_type="url" if "web" in scope_type else scope_type,
                    in_scope=True,
                    platform="yeswehack",
                    program=slug,
                ))

        for scope_item in data.get("out_of_scope", []):
            scope_val = scope_item.get("scope", "")
            if scope_val:
                assets.append(ScopeAsset(
                    value=scope_val,
                    asset_type="url",
                    in_scope=False,
                    platform="yeswehack",
                    program=slug,
                ))

        log.info("YWH scope for %s: %d assets", slug, len(assets))
        return assets


class PublicDatasetClient:
    """
    Pulls scope data from the public bounty-targets-data JSON snapshots.
    No authentication required.
    """

    _H1_URL = "https://raw.githubusercontent.com/arkadiyt/bounty-targets-data/main/data/hackerone_data.json"
    _BC_URL = "https://raw.githubusercontent.com/arkadiyt/bounty-targets-data/main/data/bugcrowd_data.json"
    _INTIGRITI_URL = "https://raw.githubusercontent.com/arkadiyt/bounty-targets-data/main/data/intigriti_data.json"

    def __init__(self, cache_dir: Optional[Path] = None) -> None:
        self._cache_dir = cache_dir or (Path.home() / ".oneinfinity" / "scope_cache")
        self._cache_dir.mkdir(parents=True, exist_ok=True)

    def _fetch_or_cache(self, url: str, filename: str, max_age_hours: int = 6) -> dict:
        cache_path = self._cache_dir / filename
        if cache_path.exists():
            age_hours = (time.time() - cache_path.stat().st_mtime) / 3600
            if age_hours < max_age_hours:
                return json.loads(cache_path.read_text())

        try:
            req = urllib.request.Request(url, headers={"User-Agent": "OneInfinity/2.0"})
            with urllib.request.urlopen(req, timeout=30) as r:
                data = json.loads(r.read())
            cache_path.write_text(json.dumps(data))
            return data
        except Exception as exc:
            log.warning("Failed to fetch public dataset from %s: %s", url, exc)
            if cache_path.exists():
                return json.loads(cache_path.read_text())
            return []

    def get_all_programs(self) -> List[dict]:
        """Return all programs from public dataset."""
        programs = []
        for url, fname in [
            (self._H1_URL, "h1.json"),
            (self._BC_URL, "bc.json"),
            (self._INTIGRITI_URL, "intigriti.json"),
        ]:
            data = self._fetch_or_cache(url, fname)
            if isinstance(data, list):
                programs.extend(data)
        return programs

    def get_scope_for_handle(self, handle: str, platform: str = "") -> List[ScopeAsset]:
        """Find and return scope assets for a given program handle from public data."""
        all_programs = self.get_all_programs()
        assets: List[ScopeAsset] = []

        for prog in all_programs:
            name = (prog.get("name") or prog.get("handle") or "").lower()
            if handle.lower() not in name:
                continue

            for target in prog.get("targets", {}).get("in_scope", []):
                val = target.get("asset_identifier") or target.get("endpoint", "")
                if val:
                    assets.append(ScopeAsset(
                        value=val,
                        asset_type=(target.get("asset_type") or "url").lower(),
                        max_severity=(target.get("max_severity") or "critical").lower(),
                        in_scope=True,
                        platform=platform or prog.get("offers_bounties", ""),
                        program=handle,
                    ))

            for target in prog.get("targets", {}).get("out_of_scope", []):
                val = target.get("asset_identifier") or target.get("endpoint", "")
                if val:
                    assets.append(ScopeAsset(
                        value=val,
                        asset_type=(target.get("asset_type") or "url").lower(),
                        in_scope=False,
                        platform=platform or "",
                        program=handle,
                    ))

        return assets


# ---------------------------------------------------------------------------
# Main aggregator
# ---------------------------------------------------------------------------

_PLATFORM_RE = re.compile(r"^(hackerone|bugcrowd|intigriti|yeswehack|h1|bc|ywh):(.+)$", re.I)


class ScopeAggregator:
    """
    Orchestrates scope collection from multiple bug bounty platforms.

    program_specs format:
      "hackerone:shopify"       — H1 program handle
      "bugcrowd:tesla"          — Bugcrowd program code
      "intigriti:company_prog"  — Intigriti program ID
      "yeswehack:acme"          — YWH program slug
      "shopify"                 — search public dataset for this name
    """

    def __init__(
        self,
        h1_key: str = "",
        h1_username: str = "",
        bugcrowd_key: str = "",
        intigriti_key: str = "",
        ywh_key: str = "",
        scope_dir: Optional[Path] = None,
    ) -> None:
        self._h1 = HackerOneClient(h1_key, h1_username)
        self._bc = BugcrowdClient(bugcrowd_key)
        self._intigriti = IntigritiClient(intigriti_key)
        self._ywh = YesWeHackClient(ywh_key)
        self._public = PublicDatasetClient()
        self._scope_dir = scope_dir or (Path.home() / ".oneinfinity" / "scopes")
        self._scope_dir.mkdir(parents=True, exist_ok=True)
        self._last_fetched: List[ScopeAsset] = []  # populated by aggregate(); used by feed_scope_validator

    # ------------------------------------------------------------------ #
    #  Public API
    # ------------------------------------------------------------------ #

    def aggregate(self, program_specs: List[str]) -> List[ScopeAsset]:
        """Fetch and merge scope from all specified programs."""
        all_assets: List[ScopeAsset] = []
        for spec in program_specs:
            assets = self._fetch_spec(spec)
            all_assets.extend(assets)
            self._save_snapshot(spec, assets)

        # Deduplicate by (value, platform, program)
        seen: set = set()
        deduped = []
        for a in all_assets:
            key = f"{a.value}|{a.platform}|{a.program}"
            if key not in seen:
                seen.add(key)
                deduped.append(a)

        log.info("Aggregated %d unique scope assets from %d programs", len(deduped), len(program_specs))
        self._last_fetched = deduped
        return deduped

    def diff_with_previous(self, spec: str, current: List[ScopeAsset]) -> ScopeDiff:
        """Compare current scope against last saved snapshot for this program."""
        previous = self._load_snapshot(spec)
        prev_fps = {a.fingerprint for a in previous}
        curr_fps = {a.fingerprint for a in current}

        added = [a for a in current if a.fingerprint not in prev_fps]
        removed = [a for a in previous if a.fingerprint not in curr_fps]
        unchanged = len(curr_fps & prev_fps)

        platform, name = self._parse_spec(spec)
        diff = ScopeDiff(
            program=name,
            platform=platform,
            added=added,
            removed=removed,
            unchanged_count=unchanged,
        )

        if diff.has_changes:
            log.info("Scope diff for %s: +%d -%d assets", spec, len(added), len(removed))
        return diff

    def feed_scope_validator(self, validator) -> None:
        """Populate a ScopeValidator instance from loaded assets.

        Prefers the in-memory list from the most recent aggregate() call so that
        a first-run caller (no disk snapshots yet) still gets a populated validator.
        Falls back to reading all snapshot files on disk when no in-memory list exists.
        """
        from oneinfinity.core.scope_validator import ScopeValidator
        if not isinstance(validator, ScopeValidator):
            raise TypeError("Expected ScopeValidator instance")

        assets_to_load: List[ScopeAsset] = []
        if self._last_fetched:
            assets_to_load = self._last_fetched
        else:
            for snap_file in self._scope_dir.glob("*.json"):
                try:
                    assets_to_load.extend(
                        ScopeAsset(**a) for a in json.loads(snap_file.read_text())
                    )
                except Exception as exc:
                    log.debug("Failed loading scope snapshot %s: %s", snap_file, exc)

        for a in assets_to_load:
            if a.in_scope:
                validator.add_in_scope(a.value)
            else:
                validator.add_out_of_scope(a.value)

    def program_priority_score(self, handle: str) -> float:
        """
        Score a program by payout/complexity ratio using Hacktivity.
        Higher score = more bounty-efficient program to target first.
        """
        reports = self._h1.get_hacktivity(handle, limit=30)
        if not reports:
            return 0.0
        bounties = [r.get("bounty", 0) or 0 for r in reports]
        avg_bounty = sum(bounties) / len(bounties) if bounties else 0
        high_sev = sum(1 for r in reports if r.get("severity") in ("high", "critical"))
        ratio = high_sev / len(reports) if reports else 0
        return avg_bounty * ratio

    # ------------------------------------------------------------------ #
    #  Internal
    # ------------------------------------------------------------------ #

    def _fetch_spec(self, spec: str) -> List[ScopeAsset]:
        platform, name = self._parse_spec(spec)
        log.info("Fetching scope: %s / %s", platform, name)

        if platform == "hackerone":
            assets = self._h1.get_scope(name)
            if not assets:
                assets = self._public.get_scope_for_handle(name, "hackerone")
            return assets

        if platform == "bugcrowd":
            assets = self._bc.get_scope(name)
            if not assets:
                assets = self._public.get_scope_for_handle(name, "bugcrowd")
            return assets

        if platform == "intigriti":
            assets = self._intigriti.get_scope(name)
            return assets

        if platform in ("yeswehack", "ywh"):
            return self._ywh.get_scope(name)

        # No platform prefix — search public dataset
        return self._public.get_scope_for_handle(name)

    @staticmethod
    def _parse_spec(spec: str) -> Tuple[str, str]:
        m = _PLATFORM_RE.match(spec)
        if m:
            plat = m.group(1).lower().replace("h1", "hackerone").replace("bc", "bugcrowd").replace("ywh", "yeswehack")
            return plat, m.group(2)
        return "", spec  # No platform prefix

    def _snapshot_path(self, spec: str) -> Path:
        safe = re.sub(r"[^a-zA-Z0-9_-]", "_", spec)
        return self._scope_dir / f"{safe}.json"

    def _save_snapshot(self, spec: str, assets: List[ScopeAsset]) -> None:
        path = self._snapshot_path(spec)
        path.write_text(json.dumps([a.to_dict() for a in assets], indent=2))

    def _load_snapshot(self, spec: str) -> List[ScopeAsset]:
        path = self._snapshot_path(spec)
        if not path.exists():
            return []
        try:
            return [ScopeAsset(**a) for a in json.loads(path.read_text())]
        except Exception:
            return []
