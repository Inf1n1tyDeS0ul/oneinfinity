"""
Program Scope Analyzer — Fetches bug bounty program scopes and validates asset inclusion.
"""
import json
import re
import logging
import os
import ssl
import urllib.request
import urllib.parse
import urllib.error
from dataclasses import dataclass, field
from typing import Optional

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Data models
# ---------------------------------------------------------------------------

@dataclass
class ProgramScope:
    program_name: str
    handle: str
    platform: str             # hackerone / bugcrowd / intigriti
    in_scope: list[dict]      # [{asset_type, asset_identifier, max_severity}]
    out_of_scope: list[dict]
    max_bounty: int
    bounty_table: dict        # severity → reward
    response_time_days: int
    managed: bool
    url: str = ""


@dataclass
class ScopeCheckResult:
    asset: str
    in_scope: bool
    program: Optional[str]
    platform: Optional[str]
    max_severity: str
    notes: str


# ---------------------------------------------------------------------------
# Static fallback program list (15 well-known public programs)
# ---------------------------------------------------------------------------

_STATIC_PROGRAMS_RAW: list[dict] = [
    {
        "name": "HackerOne",
        "handle": "security",
        "platform": "hackerone",
        "url": "https://hackerone.com/security",
        "in_scope": [
            {"asset_type": "domain", "asset_identifier": "*.hackerone.com", "max_severity": "critical"},
            {"asset_type": "domain", "asset_identifier": "api.hackerone.com", "max_severity": "critical"},
        ],
        "out_of_scope": [
            {"asset_type": "domain", "asset_identifier": "docs.hackerone.com"},
        ],
        "max_bounty": 20000,
        "bounty_table": {"critical": 20000, "high": 5000, "medium": 1500, "low": 500},
        "response_time_days": 7,
        "managed": True,
    },
    {
        "name": "Shopify",
        "handle": "shopify",
        "platform": "hackerone",
        "url": "https://hackerone.com/shopify",
        "in_scope": [
            {"asset_type": "domain", "asset_identifier": "*.shopify.com", "max_severity": "critical"},
            {"asset_type": "domain", "asset_identifier": "*.myshopify.com", "max_severity": "high"},
            {"asset_type": "domain", "asset_identifier": "*.shopifycdn.com", "max_severity": "high"},
        ],
        "out_of_scope": [
            {"asset_type": "domain", "asset_identifier": "help.shopify.com"},
        ],
        "max_bounty": 50000,
        "bounty_table": {"critical": 50000, "high": 10000, "medium": 3000, "low": 500},
        "response_time_days": 5,
        "managed": True,
    },
    {
        "name": "GitHub",
        "handle": "githubsecurity",
        "platform": "hackerone",
        "url": "https://hackerone.com/github",
        "in_scope": [
            {"asset_type": "domain", "asset_identifier": "*.github.com", "max_severity": "critical"},
            {"asset_type": "domain", "asset_identifier": "*.github.io", "max_severity": "medium"},
            {"asset_type": "domain", "asset_identifier": "*.githubapp.com", "max_severity": "critical"},
        ],
        "out_of_scope": [],
        "max_bounty": 30000,
        "bounty_table": {"critical": 30000, "high": 10000, "medium": 3000, "low": 617},
        "response_time_days": 7,
        "managed": True,
    },
    {
        "name": "Tesla",
        "handle": "tesla",
        "platform": "bugcrowd",
        "url": "https://bugcrowd.com/tesla",
        "in_scope": [
            {"asset_type": "domain", "asset_identifier": "*.tesla.com", "max_severity": "critical"},
            {"asset_type": "domain", "asset_identifier": "*.teslamotors.com", "max_severity": "critical"},
        ],
        "out_of_scope": [],
        "max_bounty": 15000,
        "bounty_table": {"critical": 15000, "high": 5000, "medium": 1000, "low": 100},
        "response_time_days": 10,
        "managed": False,
    },
    {
        "name": "Yahoo",
        "handle": "yahoo",
        "platform": "hackerone",
        "url": "https://hackerone.com/yahoo",
        "in_scope": [
            {"asset_type": "domain", "asset_identifier": "*.yahoo.com", "max_severity": "critical"},
            {"asset_type": "domain", "asset_identifier": "*.yimg.com", "max_severity": "high"},
            {"asset_type": "domain", "asset_identifier": "*.yahooapis.com", "max_severity": "high"},
        ],
        "out_of_scope": [
            {"asset_type": "domain", "asset_identifier": "mail.yahoo.com"},
        ],
        "max_bounty": 15000,
        "bounty_table": {"critical": 15000, "high": 5000, "medium": 800, "low": 150},
        "response_time_days": 14,
        "managed": False,
    },
    {
        "name": "Twitter / X",
        "handle": "twitter",
        "platform": "hackerone",
        "url": "https://hackerone.com/twitter",
        "in_scope": [
            {"asset_type": "domain", "asset_identifier": "*.twitter.com", "max_severity": "critical"},
            {"asset_type": "domain", "asset_identifier": "*.x.com", "max_severity": "critical"},
            {"asset_type": "domain", "asset_identifier": "*.twimg.com", "max_severity": "medium"},
        ],
        "out_of_scope": [],
        "max_bounty": 15000,
        "bounty_table": {"critical": 15000, "high": 5040, "medium": 1260, "low": 140},
        "response_time_days": 7,
        "managed": False,
    },
    {
        "name": "PayPal",
        "handle": "paypal",
        "platform": "hackerone",
        "url": "https://hackerone.com/paypal",
        "in_scope": [
            {"asset_type": "domain", "asset_identifier": "*.paypal.com", "max_severity": "critical"},
            {"asset_type": "domain", "asset_identifier": "*.paypalobjects.com", "max_severity": "medium"},
            {"asset_type": "domain", "asset_identifier": "*.braintreegateway.com", "max_severity": "critical"},
        ],
        "out_of_scope": [],
        "max_bounty": 10000,
        "bounty_table": {"critical": 10000, "high": 3000, "medium": 750, "low": 50},
        "response_time_days": 10,
        "managed": True,
    },
    {
        "name": "Microsoft",
        "handle": "microsoft",
        "platform": "bugcrowd",
        "url": "https://www.microsoft.com/en-us/msrc/bounty",
        "in_scope": [
            {"asset_type": "domain", "asset_identifier": "*.microsoft.com", "max_severity": "critical"},
            {"asset_type": "domain", "asset_identifier": "*.azure.com", "max_severity": "critical"},
            {"asset_type": "domain", "asset_identifier": "*.live.com", "max_severity": "high"},
            {"asset_type": "domain", "asset_identifier": "*.office.com", "max_severity": "high"},
        ],
        "out_of_scope": [],
        "max_bounty": 250000,
        "bounty_table": {"critical": 250000, "high": 30000, "medium": 5000, "low": 500},
        "response_time_days": 14,
        "managed": True,
    },
    {
        "name": "Dropbox",
        "handle": "dropbox",
        "platform": "hackerone",
        "url": "https://hackerone.com/dropbox",
        "in_scope": [
            {"asset_type": "domain", "asset_identifier": "*.dropbox.com", "max_severity": "critical"},
            {"asset_type": "domain", "asset_identifier": "*.dropboxapi.com", "max_severity": "critical"},
            {"asset_type": "domain", "asset_identifier": "*.dropboxbusiness.com", "max_severity": "high"},
        ],
        "out_of_scope": [],
        "max_bounty": 32768,
        "bounty_table": {"critical": 32768, "high": 8192, "medium": 2048, "low": 216},
        "response_time_days": 10,
        "managed": True,
    },
    {
        "name": "Intigriti",
        "handle": "intigriti",
        "platform": "intigriti",
        "url": "https://app.intigriti.com/company/intigriti",
        "in_scope": [
            {"asset_type": "domain", "asset_identifier": "*.intigriti.com", "max_severity": "critical"},
        ],
        "out_of_scope": [],
        "max_bounty": 2500,
        "bounty_table": {"critical": 2500, "high": 1000, "medium": 500, "low": 50},
        "response_time_days": 5,
        "managed": True,
    },
    {
        "name": "Uber",
        "handle": "uber",
        "platform": "hackerone",
        "url": "https://hackerone.com/uber",
        "in_scope": [
            {"asset_type": "domain", "asset_identifier": "*.uber.com", "max_severity": "critical"},
            {"asset_type": "domain", "asset_identifier": "*.uberinternal.com", "max_severity": "critical"},
        ],
        "out_of_scope": [],
        "max_bounty": 10000,
        "bounty_table": {"critical": 10000, "high": 2000, "medium": 500, "low": 100},
        "response_time_days": 7,
        "managed": True,
    },
    {
        "name": "Coinbase",
        "handle": "coinbase",
        "platform": "hackerone",
        "url": "https://hackerone.com/coinbase",
        "in_scope": [
            {"asset_type": "domain", "asset_identifier": "*.coinbase.com", "max_severity": "critical"},
            {"asset_type": "domain", "asset_identifier": "*.coinbasepro.com", "max_severity": "critical"},
        ],
        "out_of_scope": [],
        "max_bounty": 50000,
        "bounty_table": {"critical": 50000, "high": 10000, "medium": 3000, "low": 200},
        "response_time_days": 5,
        "managed": True,
    },
    {
        "name": "Airbnb",
        "handle": "airbnb",
        "platform": "hackerone",
        "url": "https://hackerone.com/airbnb",
        "in_scope": [
            {"asset_type": "domain", "asset_identifier": "*.airbnb.com", "max_severity": "critical"},
            {"asset_type": "domain", "asset_identifier": "*.airbnbapi.com", "max_severity": "high"},
        ],
        "out_of_scope": [],
        "max_bounty": 15000,
        "bounty_table": {"critical": 15000, "high": 5000, "medium": 1500, "low": 250},
        "response_time_days": 7,
        "managed": True,
    },
    {
        "name": "GitLab",
        "handle": "gitlab",
        "platform": "hackerone",
        "url": "https://hackerone.com/gitlab",
        "in_scope": [
            {"asset_type": "domain", "asset_identifier": "*.gitlab.com", "max_severity": "critical"},
            {"asset_type": "domain", "asset_identifier": "gitlab.com", "max_severity": "critical"},
        ],
        "out_of_scope": [],
        "max_bounty": 33500,
        "bounty_table": {"critical": 33500, "high": 8000, "medium": 2000, "low": 250},
        "response_time_days": 7,
        "managed": True,
    },
    {
        "name": "Atlassian",
        "handle": "atlassian",
        "platform": "bugcrowd",
        "url": "https://bugcrowd.com/atlassian",
        "in_scope": [
            {"asset_type": "domain", "asset_identifier": "*.atlassian.com", "max_severity": "critical"},
            {"asset_type": "domain", "asset_identifier": "*.atlassian.net", "max_severity": "critical"},
            {"asset_type": "domain", "asset_identifier": "*.trello.com", "max_severity": "high"},
            {"asset_type": "domain", "asset_identifier": "*.jira.com", "max_severity": "high"},
        ],
        "out_of_scope": [],
        "max_bounty": 40000,
        "bounty_table": {"critical": 40000, "high": 7500, "medium": 2500, "low": 300},
        "response_time_days": 10,
        "managed": True,
    },
]


# ---------------------------------------------------------------------------
# Analyzer
# ---------------------------------------------------------------------------

class ProgramScopeAnalyzer:
    """Fetches and parses bug bounty program scopes; validates asset inclusion."""

    def __init__(self):
        self._cache: list[ProgramScope] = []

    # ------------------------------------------------------------------
    # Fetch all programs
    # ------------------------------------------------------------------

    def fetch_all_programs(self) -> list[ProgramScope]:
        """Combine results from all platforms; fall back to static list if APIs fail."""
        programs: list[ProgramScope] = []

        # Try live platforms
        try:
            programs.extend(self.fetch_hackerone_programs())
        except Exception as exc:
            logger.info(f"[scope] HackerOne API unavailable: {exc}")

        try:
            programs.extend(self.fetch_bugcrowd_programs())
        except Exception as exc:
            logger.info(f"[scope] Bugcrowd API unavailable: {exc}")

        try:
            programs.extend(self.fetch_intigriti_programs())
        except Exception as exc:
            logger.info(f"[scope] Intigriti API unavailable: {exc}")

        # Always merge static programs for known handles not yet present
        existing_handles = {p.handle for p in programs}
        for static in self._static_programs():
            if static.handle not in existing_handles:
                programs.append(static)

        self._cache = programs
        logger.info(f"[scope] Loaded {len(programs)} programs total")
        return programs

    # ------------------------------------------------------------------
    # HackerOne
    # ------------------------------------------------------------------

    def fetch_hackerone_programs(self) -> list[ProgramScope]:
        """Fetch public HackerOne programs. Requires H1_USERNAME + H1_API_KEY."""
        username = os.environ.get("H1_USERNAME", "")
        api_key = os.environ.get("H1_API_KEY", "")

        results: list[ProgramScope] = []

        if not username or not api_key:
            logger.info("[scope] H1_USERNAME / H1_API_KEY not set — using static HackerOne programs")
            return [p for p in self._static_programs() if p.platform == "hackerone"]

        import base64
        credentials = base64.b64encode(f"{username}:{api_key}".encode()).decode()
        url = "https://api.hackerone.com/v1/hackers/programs?page[size]=100"
        headers = {
            "Authorization": f"Basic {credentials}",
            "Accept": "application/json",
            "User-Agent": "OneInfinity/1.0",
        }

        try:
            ctx = ssl.create_default_context()
            req = urllib.request.Request(url, headers=headers)
            with urllib.request.urlopen(req, timeout=15, context=ctx) as resp:
                data = json.loads(resp.read().decode("utf-8", errors="replace"))
        except Exception as exc:
            logger.warning(f"[scope] HackerOne API error: {exc}")
            return [p for p in self._static_programs() if p.platform == "hackerone"]

        for item in data.get("data", []):
            attrs = item.get("attributes", {})
            handle = item.get("id", attrs.get("handle", ""))
            name = attrs.get("name", handle)

            # Parse scope from relationships if available
            in_scope: list[dict] = []
            out_of_scope: list[dict] = []
            relationships = item.get("relationships", {})
            structured_scopes = relationships.get("structured_scopes", {}).get("data", [])
            for scope_item in structured_scopes:
                scope_attrs = scope_item.get("attributes", {})
                entry = {
                    "asset_type": scope_attrs.get("asset_type", "domain").lower().replace("url", "domain"),
                    "asset_identifier": scope_attrs.get("asset_identifier", ""),
                    "max_severity": scope_attrs.get("max_severity", "critical"),
                }
                if scope_attrs.get("eligible_for_bounty", True):
                    in_scope.append(entry)
                else:
                    out_of_scope.append(entry)

            # Bounty table
            bounty_table = {}
            for severity, key in [("critical", "critical"), ("high", "high"), ("medium", "medium"), ("low", "low")]:
                val = attrs.get(f"most_recent_activity_{key}_bounty", 0) or 0
                bounty_table[severity] = int(val)

            max_bounty = max(bounty_table.values()) if bounty_table else 0

            results.append(
                ProgramScope(
                    program_name=name,
                    handle=handle,
                    platform="hackerone",
                    in_scope=in_scope,
                    out_of_scope=out_of_scope,
                    max_bounty=max_bounty,
                    bounty_table=bounty_table,
                    response_time_days=attrs.get("first_response_time", 0) or 0,
                    managed=attrs.get("team_managed_programs", False),
                    url=f"https://hackerone.com/{handle}",
                )
            )

        logger.info(f"[scope] HackerOne: fetched {len(results)} programs via API")
        return results

    # ------------------------------------------------------------------
    # Bugcrowd
    # ------------------------------------------------------------------

    def fetch_bugcrowd_programs(self) -> list[ProgramScope]:
        """Fetch public Bugcrowd programs from programs.json."""
        url = "https://bugcrowd.com/programs.json"
        results: list[ProgramScope] = []

        try:
            ctx = ssl.create_default_context()
            req = urllib.request.Request(
                url,
                headers={
                    "User-Agent": "OneInfinity/1.0",
                    "Accept": "application/json",
                },
            )
            with urllib.request.urlopen(req, timeout=15, context=ctx) as resp:
                data = json.loads(resp.read().decode("utf-8", errors="replace"))
        except Exception as exc:
            logger.warning(f"[scope] Bugcrowd programs.json error: {exc}")
            return [p for p in self._static_programs() if p.platform == "bugcrowd"]

        for item in data.get("programs", data if isinstance(data, list) else []):
            handle = item.get("code", item.get("handle", ""))
            name = item.get("name", handle)

            in_scope: list[dict] = []
            out_of_scope: list[dict] = []

            for tg in item.get("target_groups", []):
                in_scope_flag = tg.get("in_scope", True)
                for target in tg.get("targets", []):
                    entry = {
                        "asset_type": target.get("type", "website").lower(),
                        "asset_identifier": target.get("name", target.get("uri", "")),
                        "max_severity": "critical",
                    }
                    if in_scope_flag:
                        in_scope.append(entry)
                    else:
                        out_of_scope.append(entry)

            max_bounty_str = item.get("max_payout", "0")
            try:
                max_bounty = int(re.sub(r"[^\d]", "", str(max_bounty_str)))
            except ValueError:
                max_bounty = 0

            results.append(
                ProgramScope(
                    program_name=name,
                    handle=handle,
                    platform="bugcrowd",
                    in_scope=in_scope,
                    out_of_scope=out_of_scope,
                    max_bounty=max_bounty,
                    bounty_table={"critical": max_bounty},
                    response_time_days=0,
                    managed=item.get("managed_by_crowdcontrol", False),
                    url=f"https://bugcrowd.com/{handle}",
                )
            )

        logger.info(f"[scope] Bugcrowd: fetched {len(results)} programs")
        return results

    # ------------------------------------------------------------------
    # Intigriti
    # ------------------------------------------------------------------

    def fetch_intigriti_programs(self) -> list[ProgramScope]:
        """Fetch Intigriti programs. Requires INTIGRITI_TOKEN env var."""
        token = os.environ.get("INTIGRITI_TOKEN", "")
        results: list[ProgramScope] = []

        if not token:
            logger.info("[scope] INTIGRITI_TOKEN not set — using static Intigriti programs")
            return [p for p in self._static_programs() if p.platform == "intigriti"]

        url = "https://api.intigriti.com/core/researcher/programs"
        headers = {
            "Authorization": f"Bearer {token}",
            "Accept": "application/json",
            "User-Agent": "OneInfinity/1.0",
        }

        try:
            ctx = ssl.create_default_context()
            req = urllib.request.Request(url, headers=headers)
            with urllib.request.urlopen(req, timeout=15, context=ctx) as resp:
                data = json.loads(resp.read().decode("utf-8", errors="replace"))
        except Exception as exc:
            logger.warning(f"[scope] Intigriti API error: {exc}")
            return [p for p in self._static_programs() if p.platform == "intigriti"]

        records = data if isinstance(data, list) else data.get("records", data.get("items", []))

        for item in records:
            handle = item.get("handle", item.get("id", ""))
            name = item.get("name", handle)

            in_scope: list[dict] = []
            out_of_scope: list[dict] = []
            for domain in item.get("domains", []):
                endpoint = domain.get("endpoint", domain) if isinstance(domain, dict) else str(domain)
                in_scope.append({
                    "asset_type": "domain",
                    "asset_identifier": endpoint,
                    "max_severity": "critical",
                })

            max_bounty_val = item.get("maxBounty", item.get("max_bounty", 0)) or 0
            try:
                max_bounty = int(max_bounty_val)
            except (ValueError, TypeError):
                max_bounty = 0

            results.append(
                ProgramScope(
                    program_name=name,
                    handle=handle,
                    platform="intigriti",
                    in_scope=in_scope,
                    out_of_scope=out_of_scope,
                    max_bounty=max_bounty,
                    bounty_table={"critical": max_bounty},
                    response_time_days=0,
                    managed=item.get("managed", False),
                    url=f"https://app.intigriti.com/researcher/program/{handle}",
                )
            )

        logger.info(f"[scope] Intigriti: fetched {len(results)} programs")
        return results

    # ------------------------------------------------------------------
    # Scope validation
    # ------------------------------------------------------------------

    def check_asset_in_scope(
        self, asset: str, programs: list[ProgramScope]
    ) -> ScopeCheckResult:
        """
        Check if an asset falls within scope of any program.
        Returns the program with the highest bounty if multiple match.
        """
        matching: list[tuple[ProgramScope, dict]] = []

        for prog in programs:
            # First check out-of-scope
            oos = False
            for oos_entry in prog.out_of_scope:
                if self._wildcard_match(oos_entry.get("asset_identifier", ""), asset):
                    oos = True
                    break
            if oos:
                continue

            # Check in-scope
            for scope_entry in prog.in_scope:
                if self._wildcard_match(scope_entry.get("asset_identifier", ""), asset):
                    matching.append((prog, scope_entry))
                    break

        if not matching:
            return ScopeCheckResult(
                asset=asset,
                in_scope=False,
                program=None,
                platform=None,
                max_severity="none",
                notes="No matching program scope found.",
            )

        # Pick program with highest max_bounty
        matching.sort(key=lambda x: x[0].max_bounty, reverse=True)
        best_prog, best_scope = matching[0]

        return ScopeCheckResult(
            asset=asset,
            in_scope=True,
            program=best_prog.program_name,
            platform=best_prog.platform,
            max_severity=best_scope.get("max_severity", "critical"),
            notes=f"Matched by {best_scope.get('asset_identifier', '')} in {best_prog.handle}",
        )

    # ------------------------------------------------------------------
    # Domain extraction
    # ------------------------------------------------------------------

    def extract_domains_from_scope(self, program: ProgramScope) -> list[str]:
        """Extract all domain-like entries from a program's in-scope list."""
        domains: list[str] = []
        for entry in program.in_scope:
            asset_type = entry.get("asset_type", "")
            identifier = entry.get("asset_identifier", "")
            if not identifier:
                continue
            if asset_type in ("domain", "url", "wildcard", "website", "") or re.search(
                r"[a-zA-Z0-9\-]+\.[a-zA-Z]{2,}", identifier
            ):
                # Strip URL prefix
                identifier = re.sub(r"^https?://", "", identifier).split("/")[0]
                if identifier and identifier not in domains:
                    domains.append(identifier)
        return domains

    # ------------------------------------------------------------------
    # Wildcard matching
    # ------------------------------------------------------------------

    def _wildcard_match(self, pattern: str, asset: str) -> bool:
        """
        Match asset against a scope pattern.
        Supports: *.example.com, example.com, https://example.com/path/*, 192.168.1.0/24
        """
        if not pattern or not asset:
            return False

        # Normalise
        asset = asset.lower().rstrip("/")
        pattern = pattern.lower().rstrip("/")

        # Strip URL schemes for comparison
        asset_stripped = re.sub(r"^https?://", "", asset).split("/")[0]
        pattern_stripped = re.sub(r"^https?://", "", pattern).split("/")[0]

        # Direct match
        if asset_stripped == pattern_stripped:
            return True

        # Wildcard subdomain: *.example.com
        if pattern_stripped.startswith("*."):
            suffix = pattern_stripped[2:]
            if asset_stripped == suffix or asset_stripped.endswith("." + suffix):
                return True

        # URL path wildcard: example.com/api/*
        if "*" in pattern and not pattern.startswith("*."):
            regex_pat = re.escape(pattern).replace(r"\*", ".*")
            if re.match(regex_pat, asset):
                return True

        # CIDR matching for IPs
        if "/" in pattern_stripped and re.match(r"^\d+\.\d+\.\d+\.\d+", pattern_stripped):
            try:
                import ipaddress
                network = ipaddress.ip_network(pattern_stripped, strict=False)
                ip_str = re.sub(r"^https?://", "", asset).split("/")[0]
                if re.match(r"^\d+\.\d+\.\d+\.\d+$", ip_str):
                    return ipaddress.ip_address(ip_str) in network
            except Exception:
                pass

        return False

    # ------------------------------------------------------------------
    # Static program list (fallback)
    # ------------------------------------------------------------------

    def _static_programs(self) -> list[ProgramScope]:
        """Return the 15 hardcoded well-known programs as ProgramScope objects."""
        programs: list[ProgramScope] = []
        for raw in _STATIC_PROGRAMS_RAW:
            programs.append(
                ProgramScope(
                    program_name=raw["name"],
                    handle=raw["handle"],
                    platform=raw["platform"],
                    in_scope=raw.get("in_scope", []),
                    out_of_scope=raw.get("out_of_scope", []),
                    max_bounty=raw.get("max_bounty", 0),
                    bounty_table=raw.get("bounty_table", {}),
                    response_time_days=raw.get("response_time_days", 0),
                    managed=raw.get("managed", False),
                    url=raw.get("url", ""),
                )
            )
        return programs

    # ------------------------------------------------------------------
    # Convenience filter
    # ------------------------------------------------------------------

    def get_programs_by_bounty(self, min_bounty: int = 1000) -> list[ProgramScope]:
        """Return programs with max_bounty >= min_bounty, sorted descending."""
        programs = self._cache if self._cache else self._static_programs()
        filtered = [p for p in programs if p.max_bounty >= min_bounty]
        filtered.sort(key=lambda p: p.max_bounty, reverse=True)
        return filtered


# ---------------------------------------------------------------------------
# Module-level singleton
# ---------------------------------------------------------------------------

program_scope_analyzer = ProgramScopeAnalyzer()
