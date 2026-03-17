"""
Program Discovery Engine — Discover bug bounty programs from HackerOne, Bugcrowd, Intigriti.
Extract program scope (domains, subdomains, API endpoints).
"""

import re
import json
import time
import logging
import urllib.request
import urllib.error
import ssl
from dataclasses import dataclass, field
from typing import Optional

logger = logging.getLogger(__name__)

# Public program lists (no API key required — public directory endpoints)
HACKERONE_PUBLIC_URL = "https://hackerone.com/programs/search?query=type%3Ahackerone&sort=published_at%3Adescending&page=1"
BUGCROWD_PUBLIC_URL = "https://bugcrowd.com/programs.json"
INTIGRITI_PUBLIC_URL = "https://api.intigriti.com/core/researcher/programs?limit=20&offset=0"

# Curated well-known programs with public scope (static fallback when APIs unavailable)
STATIC_PROGRAMS = [
    {
        "platform": "hackerone",
        "handle": "security",
        "name": "HackerOne",
        "url": "https://hackerone.com/security",
        "scope": ["*.hackerone.com", "api.hackerone.com"],
        "out_of_scope": ["docs.hackerone.com"],
        "bounty_range": "$100 - $20000",
        "program_type": "public",
    },
    {
        "platform": "hackerone",
        "handle": "shopify",
        "name": "Shopify",
        "url": "https://hackerone.com/shopify",
        "scope": ["*.shopify.com", "*.myshopify.com", "*.shopifycdn.com"],
        "out_of_scope": ["help.shopify.com"],
        "bounty_range": "$500 - $50000",
        "program_type": "public",
    },
    {
        "platform": "hackerone",
        "handle": "githubsecurity",
        "name": "GitHub",
        "url": "https://hackerone.com/github",
        "scope": ["*.github.com", "*.github.io", "*.githubapp.com"],
        "out_of_scope": [],
        "bounty_range": "$617 - $30000",
        "program_type": "public",
    },
    {
        "platform": "bugcrowd",
        "handle": "tesla",
        "name": "Tesla",
        "url": "https://bugcrowd.com/tesla",
        "scope": ["*.tesla.com", "*.teslamotors.com"],
        "out_of_scope": [],
        "bounty_range": "$100 - $15000",
        "program_type": "public",
    },
    {
        "platform": "hackerone",
        "handle": "yahoo",
        "name": "Yahoo",
        "url": "https://hackerone.com/yahoo",
        "scope": ["*.yahoo.com", "*.yimg.com", "*.yahooapis.com"],
        "out_of_scope": ["mail.yahoo.com"],
        "bounty_range": "$150 - $15000",
        "program_type": "public",
    },
    {
        "platform": "hackerone",
        "handle": "twitter",
        "name": "Twitter / X",
        "url": "https://hackerone.com/twitter",
        "scope": ["*.twitter.com", "*.x.com", "*.twimg.com"],
        "out_of_scope": [],
        "bounty_range": "$140 - $15000",
        "program_type": "public",
    },
    {
        "platform": "hackerone",
        "handle": "paypal",
        "name": "PayPal",
        "url": "https://hackerone.com/paypal",
        "scope": ["*.paypal.com", "*.paypalobjects.com", "*.braintreegateway.com"],
        "out_of_scope": [],
        "bounty_range": "$50 - $10000",
        "program_type": "public",
    },
    {
        "platform": "bugcrowd",
        "handle": "microsoft",
        "name": "Microsoft",
        "url": "https://www.microsoft.com/en-us/msrc/bounty",
        "scope": ["*.microsoft.com", "*.azure.com", "*.live.com", "*.office.com"],
        "out_of_scope": [],
        "bounty_range": "$500 - $250000",
        "program_type": "public",
    },
    {
        "platform": "hackerone",
        "handle": "dropbox",
        "name": "Dropbox",
        "url": "https://hackerone.com/dropbox",
        "scope": ["*.dropbox.com", "*.dropboxapi.com", "*.dropboxbusiness.com"],
        "out_of_scope": [],
        "bounty_range": "$216 - $32768",
        "program_type": "public",
    },
    {
        "platform": "intigriti",
        "handle": "intigriti",
        "name": "Intigriti",
        "url": "https://app.intigriti.com/company/intigriti/intigriti/detail",
        "scope": ["*.intigriti.com"],
        "out_of_scope": [],
        "bounty_range": "$50 - $2500",
        "program_type": "public",
    },
]

SCOPE_DOMAIN_PATTERN = re.compile(
    r'\*?\.[a-zA-Z0-9](?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?(?:\.[a-zA-Z]{2,})+|'
    r'https?://[a-zA-Z0-9\-\.]+\.[a-zA-Z]{2,}(?:/[^\s]*)?'
)


@dataclass
class BugBountyProgram:
    platform: str
    handle: str
    name: str
    url: str = ""
    scope: list = field(default_factory=list)
    out_of_scope: list = field(default_factory=list)
    bounty_range: str = ""
    program_type: str = "public"  # public / private / vdp
    target_count: int = 0
    min_bounty: int = 0
    max_bounty: int = 0
    tags: list = field(default_factory=list)
    raw_domains: list = field(default_factory=list)
    api_endpoints: list = field(default_factory=list)

    def all_in_scope_domains(self) -> list:
        """Return all in-scope domains, expanding wildcards."""
        domains = []
        for s in self.scope:
            s = s.strip()
            if s.startswith("*."):
                domains.append(s[2:])    # bare domain
                domains.append(s)        # wildcard
            elif s.startswith("http"):
                try:
                    from urllib.parse import urlparse
                    host = urlparse(s).hostname
                    if host:
                        domains.append(host)
                except Exception:
                    pass
            else:
                domains.append(s)
        return list(dict.fromkeys(domains))

    def is_in_scope(self, domain: str) -> bool:
        for pattern in self.scope:
            if pattern.startswith("*."):
                suffix = pattern[1:]  # ".example.com"
                if domain.endswith(suffix) or domain == pattern[2:]:
                    return True
            elif domain == pattern or domain.endswith("." + pattern):
                return True
        return False

    def to_dict(self) -> dict:
        return self.__dict__.copy()


class ProgramDiscoveryEngine:
    """Discover and parse bug bounty programs from multiple platforms."""

    def __init__(self, timeout: int = 10):
        self.timeout = timeout
        self._ssl_ctx = ssl.create_default_context()
        self._ssl_ctx.check_hostname = False
        self._ssl_ctx.verify_mode = ssl.CERT_NONE

    def discover_all(self, use_api: bool = False) -> list:
        """Return programs from all platforms. Falls back to curated static list."""
        programs = list(STATIC_PROGRAMS)
        if use_api:
            programs = self._merge_programs(programs, self._fetch_hackerone())
            programs = self._merge_programs(programs, self._fetch_bugcrowd())
            programs = self._merge_programs(programs, self._fetch_intigriti())
        return [BugBountyProgram(**p) if isinstance(p, dict) else p for p in programs]

    def discover_from_hackerone(self) -> list:
        return self._fetch_hackerone() or [
            BugBountyProgram(**p) for p in STATIC_PROGRAMS if p["platform"] == "hackerone"
        ]

    def discover_from_bugcrowd(self) -> list:
        return self._fetch_bugcrowd() or [
            BugBountyProgram(**p) for p in STATIC_PROGRAMS if p["platform"] == "bugcrowd"
        ]

    def discover_from_intigriti(self) -> list:
        return self._fetch_intigriti() or [
            BugBountyProgram(**p) for p in STATIC_PROGRAMS if p["platform"] == "intigriti"
        ]

    def extract_scope(self, program: BugBountyProgram) -> list:
        """Return list of in-scope targets (domains/wildcards)."""
        targets = []
        for domain in program.scope:
            domain = domain.strip()
            if not domain:
                continue
            # Parse URL to domain if needed
            if domain.startswith("http"):
                try:
                    from urllib.parse import urlparse
                    domain = urlparse(domain).hostname or domain
                except Exception:
                    pass
            targets.append({
                "domain": domain,
                "is_wildcard": domain.startswith("*."),
                "program": program.handle,
                "platform": program.platform,
            })
        return targets

    def search(self, query: str) -> list:
        """Search static program list by name/handle."""
        q = query.lower()
        all_programs = self.discover_all()
        return [p for p in all_programs
                if q in p.name.lower() or q in p.handle.lower()]

    # ── Fetchers ──────────────────────────────────────────────────────────────

    def _fetch_hackerone(self) -> list:
        """Try to fetch from HackerOne public API."""
        programs = []
        try:
            url = "https://hackerone.com/programs/search?query=type%3Ahackerone&sort=published_at%3Adescending&page=1"
            req = urllib.request.Request(url)
            req.add_header("User-Agent", "Mozilla/5.0")
            req.add_header("Accept", "application/json")
            with urllib.request.urlopen(req, timeout=self.timeout, context=self._ssl_ctx) as resp:
                data = json.loads(resp.read(131072))
                for prog in data.get("results", [])[:20]:
                    attrs = prog.get("attributes", {})
                    scope = []
                    for target in attrs.get("structured_scope", {}).get("domains", []):
                        scope.append(target.get("asset_identifier", ""))
                    programs.append(BugBountyProgram(
                        platform="hackerone",
                        handle=attrs.get("handle", ""),
                        name=attrs.get("name", attrs.get("handle", "")),
                        url=f"https://hackerone.com/{attrs.get('handle','')}",
                        scope=scope or attrs.get("eligible_for_submission_domains", []),
                        bounty_range=f"${attrs.get('minimum_bounty_table',0)} - ${attrs.get('maximum_bounty_table',0)}",
                        program_type="public" if attrs.get("offers_bounties") else "vdp",
                    ))
        except Exception as e:
            logger.debug(f"HackerOne fetch error: {e}")
        return programs

    def _fetch_bugcrowd(self) -> list:
        programs = []
        try:
            req = urllib.request.Request("https://bugcrowd.com/programs.json")
            req.add_header("User-Agent", "Mozilla/5.0")
            with urllib.request.urlopen(req, timeout=self.timeout, context=self._ssl_ctx) as resp:
                data = json.loads(resp.read(262144))
                for prog in (data.get("programs", []) or data if isinstance(data, list) else [])[:20]:
                    programs.append(BugBountyProgram(
                        platform="bugcrowd",
                        handle=prog.get("code", prog.get("handle", "")),
                        name=prog.get("name", ""),
                        url=f"https://bugcrowd.com/{prog.get('code','')}",
                        scope=[t.get("target", "") for t in prog.get("targets", {}).get("in_scope", [])],
                        bounty_range=prog.get("min_payout", ""),
                        program_type="public" if prog.get("invited_status") == "open" else "private",
                    ))
        except Exception as e:
            logger.debug(f"Bugcrowd fetch error: {e}")
        return programs

    def _fetch_intigriti(self) -> list:
        programs = []
        try:
            req = urllib.request.Request(INTIGRITI_PUBLIC_URL)
            req.add_header("User-Agent", "Mozilla/5.0")
            with urllib.request.urlopen(req, timeout=self.timeout, context=self._ssl_ctx) as resp:
                data = json.loads(resp.read(131072))
                for prog in (data.get("records", data) if isinstance(data, dict) else data)[:20]:
                    programs.append(BugBountyProgram(
                        platform="intigriti",
                        handle=prog.get("handle", prog.get("id", "")),
                        name=prog.get("name", ""),
                        url=prog.get("url", ""),
                        scope=[t.get("endpoint", "") for t in prog.get("domains", [])],
                        bounty_range="varies",
                        program_type="public",
                    ))
        except Exception as e:
            logger.debug(f"Intigriti fetch error: {e}")
        return programs

    def _merge_programs(self, base: list, new: list) -> list:
        existing_handles = {p["handle"] if isinstance(p, dict) else p.handle for p in base}
        for p in new:
            handle = p["handle"] if isinstance(p, dict) else p.handle
            if handle not in existing_handles:
                base.append(p)
                existing_handles.add(handle)
        return base


program_discovery_engine = ProgramDiscoveryEngine()
