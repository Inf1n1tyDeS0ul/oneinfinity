"""
Target Discovery Engine — Autonomous OSINT-driven target discovery.
Integrates with attack_graph_core to populate graph with discovered assets.
"""
import re
import json
import time
import logging
import subprocess
import shutil
import socket
import ssl
import os
import urllib.request
import urllib.parse
from dataclasses import dataclass, field
from typing import Optional
from pathlib import Path

def _is_internal_domain(domain: str) -> bool:
    """Return True if domain is localhost, an IP address, or a .local/.internal hostname.
    These targets have wildcard DNS — subdomain enumeration produces only noise.
    """
    import ipaddress
    d = domain.split(':')[0].lower().strip()
    # Bare localhost or any *.localhost
    if d == 'localhost' or d.endswith('.localhost'):
        return True
    # .local / .internal / .test / .example TLDs (RFC 2606 / RFC 6761)
    if any(d.endswith(sfx) for sfx in ('.local', '.internal', '.test', '.example', '.invalid')):
        return True
    # IP address (v4 or v6)
    try:
        ipaddress.ip_address(d)
        return True
    except ValueError:
        pass
    return False


logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Data model
# ---------------------------------------------------------------------------

@dataclass
class DiscoveredTarget:
    domain: str
    source: str              # crtsh / asn / dns_brute / github / shodan / passive
    confidence: float        # 0.0-1.0
    program: str = ""        # which bug bounty program
    platform: str = ""       # hackerone / bugcrowd / intigriti
    in_scope: bool = True
    asset_type: str = "domain"  # domain / ip / url / wildcard
    metadata: dict = field(default_factory=dict)
    discovered_at: str = field(default_factory=lambda: str(time.time()))


# ---------------------------------------------------------------------------
# DNS brute-force wordlist
# ---------------------------------------------------------------------------

DNS_BRUTE_WORDLIST = [
    "www", "api", "mail", "app", "dev", "staging", "beta", "admin", "auth",
    "login", "secure", "test", "cdn", "static", "assets", "media", "s3",
    "bucket", "prod", "stage", "uat", "qa", "internal", "vpn", "remote",
    "git", "svn", "jira", "confluence", "jenkins", "docker", "k8s",
    "registry", "smtp", "ftp", "ssh", "mx", "ns1", "ns2", "pop", "imap",
    "webmail", "portal", "dashboard", "monitor", "status", "health",
    "metrics", "logs", "analytics", "data", "db", "database", "redis",
    "cache", "queue", "worker", "jobs", "scheduler", "cron", "backup",
    "archive", "old", "legacy", "v1", "v2", "v3", "mobile", "m", "wap",
    "shop", "store", "payment", "checkout", "billing", "invoice", "crm",
    "erp", "hr", "files", "upload", "download", "img", "images", "video",
    "stream", "live", "chat", "support", "help", "docs", "wiki", "forum",
    "community", "blog", "news", "press", "corp", "intranet", "extranet",
    "partner", "vendor", "client", "customer", "user", "account", "profile",
    "search", "es", "elastic", "kibana", "grafana", "prometheus",
]

# ---------------------------------------------------------------------------
# Engine
# ---------------------------------------------------------------------------

class TargetDiscoveryEngine:
    """Autonomous OSINT-driven target discovery engine."""

    def __init__(self, graph=None):
        self._graph = graph
        self._scope: list[str] = []

    # ------------------------------------------------------------------
    # Graph integration — lazy import to avoid circular imports
    # ------------------------------------------------------------------

    def _get_graph(self):
        """Return attack graph instance, importing lazily."""
        if self._graph is not None:
            return self._graph
        try:
            from oneinfinity.attack_graph_core import AttackGraphEngine
            from oneinfinity.attack_graph_core import get_graph  # noqa: F401  (may not exist)
            return get_graph()
        except Exception:
            try:
                from oneinfinity.attack_graph_core import AttackGraphEngine
                self._graph = AttackGraphEngine()
                return self._graph
            except Exception as exc:
                logger.debug(f"Could not obtain attack graph: {exc}")
                return None

    # ------------------------------------------------------------------
    # Primary entry point
    # ------------------------------------------------------------------

    def discover_all(
        self,
        seed_domains: list[str] = None,
        programs: list[str] = None,
    ) -> list[DiscoveredTarget]:
        """
        Run all discovery methods in sequence, deduplicate, add to graph,
        and return the full list of discovered targets.
        """
        seed_domains = seed_domains or []
        all_targets: list[DiscoveredTarget] = []

        for domain in seed_domains:
            if _is_internal_domain(domain):
                logger.info(f"[discovery] Skipping OSINT for internal/localhost target: {domain}")
                continue
            logger.info(f"[discovery] Starting all OSINT methods for {domain}")

            # crt.sh certificate transparency
            all_targets.extend(self.discover_via_crtsh(domain))

            # ASN / IP range
            all_targets.extend(self.discover_via_asn(domain))

            # DNS brute force
            all_targets.extend(self.discover_via_dns_brute(domain))

            # GitHub code search
            all_targets.extend(self.discover_via_github(domain))

            # Shodan InternetDB
            all_targets.extend(self.discover_via_shodan(domain))

            # Cloud asset discovery
            all_targets.extend(self.discover_cloud_assets(domain))

        deduped = self._deduplicate(all_targets)
        logger.info(f"[discovery] Total unique targets: {len(deduped)}")

        self.add_to_graph(deduped)
        return deduped

    # ------------------------------------------------------------------
    # crt.sh — certificate transparency
    # ------------------------------------------------------------------

    def discover_via_crtsh(self, domain: str) -> list[DiscoveredTarget]:
        """Query crt.sh for certificate transparency records."""
        results: list[DiscoveredTarget] = []
        url = f"https://crt.sh/?q=%25.{urllib.parse.quote(domain)}&output=json"
        try:
            ctx = ssl.create_default_context()
            req = urllib.request.Request(url, headers={"User-Agent": "OneInfinity/1.0"})
            with urllib.request.urlopen(req, timeout=20, context=ctx) as resp:
                data = json.loads(resp.read().decode("utf-8", errors="replace"))
        except Exception as exc:
            logger.warning(f"[crtsh] Failed for {domain}: {exc}")
            return results

        seen: set[str] = set()
        for entry in data if isinstance(data, list) else []:
            for field_name in ("common_name", "name_value"):
                raw = entry.get(field_name, "")
                for line in raw.split("\n"):
                    line = line.strip().lstrip("*.")
                    if not line or line in seen:
                        continue
                    if not re.match(r"^[a-zA-Z0-9._-]+\.[a-zA-Z]{2,}$", line):
                        continue
                    seen.add(line)
                    results.append(
                        DiscoveredTarget(
                            domain=line,
                            source="crtsh",
                            confidence=0.85,
                            asset_type="domain",
                            metadata={"issuer": entry.get("issuer_name", ""), "logged_at": entry.get("entry_timestamp", "")},
                        )
                    )

        logger.info(f"[crtsh] {domain} → {len(results)} subdomains")
        return results

    # ------------------------------------------------------------------
    # ASN / IP range discovery
    # ------------------------------------------------------------------

    def discover_via_asn(self, domain: str) -> list[DiscoveredTarget]:
        """Resolve domain to IP and gather ASN/BGP metadata."""
        results: list[DiscoveredTarget] = []
        try:
            hostname, aliases, ip_list = socket.gethostbyname_ex(domain)
        except socket.gaierror as exc:
            logger.warning(f"[asn] DNS resolution failed for {domain}: {exc}")
            return results

        for ip in ip_list:
            meta: dict = {"resolved_from": domain, "aliases": aliases}

            # Query BGP.he.net via their API (plain text whois-style)
            try:
                bgp_url = f"https://bgp.he.net/ip/{ip}"
                req = urllib.request.Request(bgp_url, headers={"User-Agent": "OneInfinity/1.0"})
                with urllib.request.urlopen(req, timeout=10) as resp:
                    body = resp.read().decode("utf-8", errors="replace")
                asn_match = re.search(r"AS(\d+)", body)
                if asn_match:
                    meta["asn"] = f"AS{asn_match.group(1)}"
                prefix_match = re.search(r"(\d+\.\d+\.\d+\.\d+/\d+)", body)
                if prefix_match:
                    meta["prefix"] = prefix_match.group(1)
            except Exception:
                pass  # BGP lookup optional

            results.append(
                DiscoveredTarget(
                    domain=ip,
                    source="asn",
                    confidence=0.90,
                    asset_type="ip",
                    metadata=meta,
                )
            )

        logger.info(f"[asn] {domain} → {len(results)} IPs")
        return results

    # ------------------------------------------------------------------
    # DNS brute force
    # ------------------------------------------------------------------

    def discover_via_dns_brute(
        self, domain: str, wordlist: list[str] = None
    ) -> list[DiscoveredTarget]:
        """Brute-force common subdomain prefixes via DNS resolution."""
        # Skip brute-force for internal/localhost domains (DNS wildcard = noise)
        if _is_internal_domain(domain):
            logger.info(f"[dns_brute] Skipping {domain} — internal/localhost target")
            return []
        wordlist = wordlist or DNS_BRUTE_WORDLIST
        results: list[DiscoveredTarget] = []

        for prefix in wordlist:
            fqdn = f"{prefix}.{domain}"
            try:
                socket.setdefaulttimeout(1)
                ip = socket.gethostbyname(fqdn)
                results.append(
                    DiscoveredTarget(
                        domain=fqdn,
                        source="dns_brute",
                        confidence=0.75,
                        asset_type="domain",
                        metadata={"resolved_ip": ip, "prefix": prefix},
                    )
                )
                logger.debug(f"[dns_brute] {fqdn} → {ip}")
            except (socket.gaierror, socket.timeout):
                pass
            finally:
                socket.setdefaulttimeout(None)

        logger.info(f"[dns_brute] {domain} → {len(results)} alive subdomains")
        return results

    # ------------------------------------------------------------------
    # GitHub code search
    # ------------------------------------------------------------------

    def discover_via_github(self, domain: str) -> list[DiscoveredTarget]:
        """Search GitHub for domain references in source code."""
        results: list[DiscoveredTarget] = []
        token = os.environ.get("GITHUB_TOKEN", "")
        if not token:
            logger.info("[github] GITHUB_TOKEN not set — skipping GitHub discovery")
            return results

        query = urllib.parse.quote(f"{domain} in:file")
        url = f"https://api.github.com/search/code?q={query}&per_page=50"
        headers = {
            "User-Agent": "OneInfinity/1.0",
            "Authorization": f"token {token}",
            "Accept": "application/vnd.github.v3+json",
        }
        try:
            req = urllib.request.Request(url, headers=headers)
            ctx = ssl.create_default_context()
            with urllib.request.urlopen(req, timeout=15, context=ctx) as resp:
                data = json.loads(resp.read().decode("utf-8", errors="replace"))
        except Exception as exc:
            logger.warning(f"[github] Search failed for {domain}: {exc}")
            return results

        items = data.get("items", [])
        seen: set[str] = set()

        for item in items:
            # Extract URLs and subdomains from text_matches or repo info
            text_fragments = []
            for tm in item.get("text_matches", []):
                text_fragments.append(tm.get("fragment", ""))
            combined = " ".join(text_fragments)

            for sub in self._extract_subdomains_from_text(combined, domain):
                if sub not in seen:
                    seen.add(sub)
                    results.append(
                        DiscoveredTarget(
                            domain=sub,
                            source="github",
                            confidence=0.60,
                            asset_type="domain",
                            metadata={
                                "repo": item.get("repository", {}).get("full_name", ""),
                                "file": item.get("path", ""),
                            },
                        )
                    )

        logger.info(f"[github] {domain} → {len(results)} assets from code search")
        return results

    # ------------------------------------------------------------------
    # Shodan InternetDB
    # ------------------------------------------------------------------

    def discover_via_shodan(self, domain: str) -> list[DiscoveredTarget]:
        """Query Shodan InternetDB (no API key needed) for IP intelligence."""
        results: list[DiscoveredTarget] = []

        # First resolve domain to IP(s)
        try:
            _, _, ip_list = socket.gethostbyname_ex(domain)
        except socket.gaierror:
            return results

        for ip in ip_list:
            url = f"https://internetdb.shodan.io/{ip}"
            try:
                req = urllib.request.Request(url, headers={"User-Agent": "OneInfinity/1.0"})
                ctx = ssl.create_default_context()
                with urllib.request.urlopen(req, timeout=10, context=ctx) as resp:
                    data = json.loads(resp.read().decode("utf-8", errors="replace"))
            except Exception as exc:
                logger.debug(f"[shodan] InternetDB query failed for {ip}: {exc}")
                continue

            meta = {
                "open_ports": data.get("ports", []),
                "cpes": data.get("cpes", []),
                "tags": data.get("tags", []),
                "vulns": data.get("vulns", []),
                "hostnames": data.get("hostnames", []),
            }

            results.append(
                DiscoveredTarget(
                    domain=ip,
                    source="shodan",
                    confidence=0.80,
                    asset_type="ip",
                    metadata=meta,
                )
            )

            # Also add any hostnames reported by Shodan
            for hostname in data.get("hostnames", []):
                hostname = hostname.strip()
                if hostname and re.match(r"^[a-zA-Z0-9._-]+\.[a-zA-Z]{2,}$", hostname):
                    results.append(
                        DiscoveredTarget(
                            domain=hostname,
                            source="shodan",
                            confidence=0.70,
                            asset_type="domain",
                            metadata={"resolved_ip": ip},
                        )
                    )

        logger.info(f"[shodan] {domain} → {len(results)} assets")
        return results

    # ------------------------------------------------------------------
    # Cloud asset discovery
    # ------------------------------------------------------------------

    def discover_cloud_assets(self, domain: str) -> list[DiscoveredTarget]:
        """Check common cloud storage patterns for the domain."""
        results: list[DiscoveredTarget] = []

        # Strip www. prefix for cleaner bucket names
        base = domain.lstrip("www.").replace(".", "-")
        base_dot = domain.lstrip("www.")

        candidates = [
            # S3 buckets
            (f"https://{base_dot}.s3.amazonaws.com/", "s3", "url"),
            (f"https://s3.amazonaws.com/{base_dot}/", "s3", "url"),
            (f"https://{base}.s3.amazonaws.com/", "s3", "url"),
            # GCP storage
            (f"https://storage.googleapis.com/{base_dot}/", "gcp_storage", "url"),
            (f"https://storage.googleapis.com/{base}/", "gcp_storage", "url"),
            # Azure Blob
            (f"https://{base_dot}.blob.core.windows.net/", "azure_blob", "url"),
            (f"https://{base}.blob.core.windows.net/", "azure_blob", "url"),
            # Cloudflare Pages
            (f"https://{base_dot}.pages.dev/", "cloudflare_pages", "url"),
            (f"https://{base}.pages.dev/", "cloudflare_pages", "url"),
        ]

        ctx = ssl.create_default_context()

        for asset_url, provider, asset_type in candidates:
            try:
                req = urllib.request.Request(
                    asset_url,
                    method="HEAD",
                    headers={"User-Agent": "OneInfinity/1.0"},
                )
                with urllib.request.urlopen(req, timeout=8, context=ctx) as resp:
                    status = resp.status
                    # 200, 403 = exists; 404 = likely not there
                    if status in (200, 403, 301, 302):
                        results.append(
                            DiscoveredTarget(
                                domain=asset_url,
                                source="passive",
                                confidence=0.70 if status == 200 else 0.55,
                                asset_type=asset_type,
                                metadata={"http_status": status, "provider": provider},
                            )
                        )
                        logger.info(f"[cloud] Found {provider} asset: {asset_url} (HTTP {status})")
            except urllib.error.HTTPError as exc:
                if exc.code in (403, 301, 302):
                    results.append(
                        DiscoveredTarget(
                            domain=asset_url,
                            source="passive",
                            confidence=0.55,
                            asset_type=asset_type,
                            metadata={"http_status": exc.code, "provider": provider},
                        )
                    )
            except Exception:
                pass  # Expected for non-existent assets

        logger.info(f"[cloud] {domain} → {len(results)} cloud assets")
        return results

    # ------------------------------------------------------------------
    # Subdomain monitoring
    # ------------------------------------------------------------------

    def monitor_subdomains(
        self, domain: str, known: set[str]
    ) -> list[DiscoveredTarget]:
        """
        Compare fresh crt.sh results against a known set and return only
        newly discovered subdomains.
        """
        fresh = self.discover_via_crtsh(domain)
        new_targets = [t for t in fresh if t.domain not in known]
        logger.info(f"[monitor] {domain} → {len(new_targets)} new subdomains (known={len(known)})")
        return new_targets

    # ------------------------------------------------------------------
    # Graph integration
    # ------------------------------------------------------------------

    def add_to_graph(self, targets: list[DiscoveredTarget]) -> int:
        """Add all discovered targets to the attack graph. Returns node count added."""
        graph = self._get_graph()
        if graph is None:
            logger.debug("[discovery] No attack graph available — skipping graph update")
            return 0

        try:
            from oneinfinity.attack_graph_core import NodeType, EdgeType
        except ImportError:
            logger.debug("[discovery] attack_graph_core not importable")
            return 0

        added = 0
        for t in targets:
            try:
                # Pick node type
                if t.asset_type == "ip":
                    ntype = NodeType.SERVICE
                elif t.asset_type in ("url",):
                    ntype = NodeType.URL
                else:
                    ntype = NodeType.SUBDOMAIN

                props = {
                    "source": t.source,
                    "confidence": t.confidence,
                    "program": t.program,
                    "platform": t.platform,
                    "in_scope": t.in_scope,
                    "asset_type": t.asset_type,
                    "discovered_at": t.discovered_at,
                    **t.metadata,
                }
                graph.add_node(
                    ntype,
                    t.domain,
                    properties=props,
                    source=f"target_discovery_{t.source}",
                )
                added += 1
            except Exception as exc:
                logger.debug(f"[discovery] Failed to add {t.domain} to graph: {exc}")

        logger.info(f"[discovery] Added {added} nodes to attack graph")
        return added

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------

    def _is_in_scope(self, domain: str, scope: list[str]) -> bool:
        """Check whether domain falls within the given scope list."""
        if not scope:
            return True
        domain = domain.lower()
        for pattern in scope:
            pattern = pattern.lower()
            if pattern.startswith("*."):
                suffix = pattern[2:]
                if domain == suffix or domain.endswith("." + suffix):
                    return True
            elif domain == pattern or domain.endswith("." + pattern):
                return True
        return False

    def _deduplicate(self, targets: list[DiscoveredTarget]) -> list[DiscoveredTarget]:
        """Deduplicate targets by normalized domain/asset string."""
        seen: set[str] = set()
        out: list[DiscoveredTarget] = []
        for t in targets:
            key = t.domain.lower().rstrip("/")
            if key not in seen:
                seen.add(key)
                out.append(t)
        return out

    def _extract_subdomains_from_text(self, text: str, root_domain: str) -> list[str]:
        """Extract subdomains of root_domain from arbitrary text."""
        pattern = re.compile(
            r"(?:https?://)?([a-zA-Z0-9](?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?(?:\.[a-zA-Z0-9](?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?)*\."
            + re.escape(root_domain) + r")"
        )
        return list({m.group(1).lower() for m in pattern.finditer(text)})


# ---------------------------------------------------------------------------
# Module-level singleton
# ---------------------------------------------------------------------------

target_discovery_engine = TargetDiscoveryEngine()
