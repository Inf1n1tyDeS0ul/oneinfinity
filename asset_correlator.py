"""
Asset Correlator — Links discovered assets and builds correlation map.
"""
import re
import socket
import json
import logging
from dataclasses import dataclass, field
from typing import Optional
from collections import defaultdict

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Data model
# ---------------------------------------------------------------------------

@dataclass
class AssetCorrelation:
    asset: str
    asset_type: str             # domain / ip / url / email / api_key
    related_assets: list[str]
    confidence: float
    source_programs: list[str]  # which bug bounty programs this appears in
    risk_indicators: list[str]  # exposed_api_key / admin_panel / dev_endpoint
    tags: list[str]


# ---------------------------------------------------------------------------
# Cloud provider detection patterns
# ---------------------------------------------------------------------------

_CLOUD_PATTERNS: list[tuple[str, str]] = [
    # AWS
    (r"\.amazonaws\.com$", "aws"),
    (r"\.elasticbeanstalk\.com$", "aws"),
    (r"\.cloudfront\.net$", "aws"),
    (r"\.awsdns-", "aws"),
    (r"ec2[-.]", "aws"),
    # GCP
    (r"\.googleapis\.com$", "gcp"),
    (r"\.googleusercontent\.com$", "gcp"),
    (r"\.appspot\.com$", "gcp"),
    (r"\.run\.app$", "gcp"),
    # Azure
    (r"\.azure\.com$", "azure"),
    (r"\.azurewebsites\.net$", "azure"),
    (r"\.blob\.core\.windows\.net$", "azure"),
    (r"\.azurecontainer\.io$", "azure"),
    (r"\.azureedge\.net$", "azure"),
    # Cloudflare
    (r"\.pages\.dev$", "cloudflare"),
    (r"\.workers\.dev$", "cloudflare"),
    (r"cloudflare", "cloudflare"),
    # Heroku
    (r"\.herokuapp\.com$", "heroku"),
    # Netlify
    (r"\.netlify\.app$", "netlify"),
    (r"\.netlify\.com$", "netlify"),
    # Vercel
    (r"\.vercel\.app$", "vercel"),
    # GitHub Pages
    (r"\.github\.io$", "github_pages"),
    # Fastly
    (r"\.fastly\.net$", "fastly"),
    (r"\.fastlylb\.net$", "fastly"),
    # DigitalOcean
    (r"\.digitaloceanspaces\.com$", "digitalocean"),
    (r"\.ondigitalocean\.app$", "digitalocean"),
]

# Risk indicator detection rules: (pattern, indicator_name)
_RISK_RULES: list[tuple[re.Pattern, str]] = [
    (re.compile(r"(?i)(^|[./])admin([./]|$)"), "admin_panel"),
    (re.compile(r"(?i)(^|[./])(dev|staging|test|uat|qa)([./\-]|$)"), "dev_endpoint"),
    (re.compile(r"(?i)\.env($|/)"), "exposed_env"),
    (re.compile(r"(?i)(^|[./])api($|[./])"), "api_exposed"),
    (re.compile(r"(?i)(^|[./])(internal|intranet|corp)([./\-]|$)"), "internal_asset"),
    (re.compile(r"(?i)(^|[./])(backup|bak|old|legacy|archive)([./\-_]|$)"), "legacy_asset"),
    (re.compile(r"(?i)(^|[./])(vpn|remote|ssh|bastion)([./\-]|$)"), "remote_access"),
    (re.compile(r"(?i)(^|[./])(git|svn|repo|source)([./\-]|$)"), "source_control"),
    (re.compile(r"(?i)(^|[./])(jenkins|ci|cd|deploy|pipeline)([./\-]|$)"), "cicd_exposed"),
    (re.compile(r"(?i)(^|[./])(jira|confluence|wiki|kb)([./\-]|$)"), "ticketing_system"),
    (re.compile(r"(?i)(^|[./])(kibana|grafana|prometheus|elastic)([./\-]|$)"), "monitoring_exposed"),
    (re.compile(r"(?i)(^|[./])(db|database|redis|mysql|mongo|postgres)([./\-]|$)"), "database_exposed"),
    (re.compile(r"(?i)(^|[./])debug([./\-]|$)"), "debug_endpoint"),
]


# ---------------------------------------------------------------------------
# Correlator
# ---------------------------------------------------------------------------

class AssetCorrelator:
    """Links discovered assets, identifies relationships, removes false positives."""

    # ------------------------------------------------------------------
    # Primary entry point
    # ------------------------------------------------------------------

    def correlate(self, assets: list[dict]) -> list[AssetCorrelation]:
        """
        Group assets by root domain, link IPs to domains, identify duplicates
        across sources, and return a deduplicated correlated list.

        Each asset dict is expected to have at least: {"asset": str, "asset_type": str, ...}
        """
        if not assets:
            return []

        # Step 1: Normalise and deduplicate
        deduped = self.deduplicate(assets)

        # Step 2: Group by root domain
        groups: dict[str, list[dict]] = defaultdict(list)
        for a in deduped:
            root = self.identify_root_domain(a.get("asset", ""))
            groups[root].append(a)

        # Step 3: Resolve IPs ↔ domains mapping
        all_ips = [a["asset"] for a in deduped if a.get("asset_type") == "ip"]
        all_domains = [a["asset"] for a in deduped if a.get("asset_type") in ("domain", "subdomain")]
        ip_domain_map = self.correlate_ips_to_domains(all_ips, all_domains)

        # Step 4: Build correlation objects
        correlations: list[AssetCorrelation] = []
        for asset_dict in deduped:
            asset = asset_dict.get("asset", "")
            asset_type = asset_dict.get("asset_type", "domain")

            # Related: everything in the same root domain group
            root = self.identify_root_domain(asset)
            related = [
                a["asset"]
                for a in groups.get(root, [])
                if a["asset"] != asset
            ]

            # Add IP↔domain relationships
            if asset_type == "ip":
                for domain in ip_domain_map.get(asset, {}).get("domains", []):
                    if domain not in related:
                        related.append(domain)
            elif asset_type in ("domain", "subdomain"):
                for ip, mapping in ip_domain_map.items():
                    if asset in mapping.get("domains", []) and ip not in related:
                        related.append(ip)

            # Cloud provider tag
            cloud = self.identify_cloud_provider(asset)
            tags: list[str] = []
            if cloud:
                tags.append(f"cloud:{cloud}")

            # Risk indicators
            risks = self.detect_risk_indicators(asset, asset_dict.get("metadata", {}))

            # Source programs
            source_programs: list[str] = []
            if asset_dict.get("program"):
                source_programs.append(asset_dict["program"])

            # Confidence: start from discovered confidence, boost if multi-source
            confidence = float(asset_dict.get("confidence", 0.7))

            correlations.append(
                AssetCorrelation(
                    asset=asset,
                    asset_type=asset_type,
                    related_assets=related[:50],  # cap to avoid memory bloat
                    confidence=min(confidence, 1.0),
                    source_programs=source_programs,
                    risk_indicators=risks,
                    tags=tags,
                )
            )

        return correlations

    # ------------------------------------------------------------------
    # Root domain identification
    # ------------------------------------------------------------------

    def identify_root_domain(self, subdomain: str) -> str:
        """
        Strip to the registrable root domain.
        api.example.com → example.com
        s3.eu-west-1.amazonaws.com → amazonaws.com (kept as-is for cloud assets)
        """
        if not subdomain:
            return ""

        # Remove protocol prefix
        subdomain = re.sub(r"^https?://", "", subdomain).split("/")[0]

        # If it looks like an IP, return as-is
        if re.match(r"^\d{1,3}(?:\.\d{1,3}){3}$", subdomain):
            return subdomain

        # Known two-part TLDs (simplified)
        TWO_PART_TLDS = {
            "co.uk", "co.in", "co.jp", "co.nz", "co.za", "com.au", "com.br",
            "com.cn", "com.mx", "com.sg", "com.tr", "net.au", "org.uk",
            "gov.uk", "ac.uk", "me.uk",
        }

        parts = subdomain.lower().split(".")
        if len(parts) >= 3:
            two_part = ".".join(parts[-2:])
            if two_part in TWO_PART_TLDS and len(parts) >= 3:
                return ".".join(parts[-3:])

        if len(parts) >= 2:
            return ".".join(parts[-2:])

        return subdomain

    # ------------------------------------------------------------------
    # IP ↔ domain correlation
    # ------------------------------------------------------------------

    def correlate_ips_to_domains(
        self, ips: list[str], domains: list[str]
    ) -> dict:
        """
        Perform reverse DNS for IPs and forward DNS for domains.
        Returns a mapping: {ip: {domains: [...], ptr: str}, ...}
        """
        mapping: dict[str, dict] = {}

        # Reverse DNS for each IP
        for ip in ips:
            entry = {"domains": [], "ptr": ""}
            try:
                socket.setdefaulttimeout(2)
                ptr = socket.gethostbyaddr(ip)[0]
                entry["ptr"] = ptr
                entry["domains"].append(ptr)
            except (socket.herror, socket.gaierror, socket.timeout):
                pass
            finally:
                socket.setdefaulttimeout(None)
            mapping[ip] = entry

        # Forward DNS for domains → check if resolves to a known IP
        for domain in domains:
            try:
                socket.setdefaulttimeout(2)
                _, _, ip_list = socket.gethostbyname_ex(domain)
                for ip in ip_list:
                    if ip in mapping:
                        if domain not in mapping[ip]["domains"]:
                            mapping[ip]["domains"].append(domain)
                    else:
                        mapping[ip] = {"domains": [domain], "ptr": ""}
            except (socket.gaierror, socket.timeout):
                pass
            finally:
                socket.setdefaulttimeout(None)

        return mapping

    # ------------------------------------------------------------------
    # Cloud provider detection
    # ------------------------------------------------------------------

    def identify_cloud_provider(self, asset: str) -> Optional[str]:
        """Detect AWS/GCP/Azure/Cloudflare/etc. from asset string."""
        asset_lower = asset.lower()
        for pattern, provider in _CLOUD_PATTERNS:
            if re.search(pattern, asset_lower):
                return provider
        return None

    # ------------------------------------------------------------------
    # Risk indicator detection
    # ------------------------------------------------------------------

    def detect_risk_indicators(self, asset: str, metadata: dict) -> list[str]:
        """
        Inspect the asset string and metadata for risk signals.
        Returns a list of indicator strings.
        """
        indicators: list[str] = []
        asset_lower = asset.lower()

        for pattern, indicator in _RISK_RULES:
            if pattern.search(asset_lower):
                indicators.append(indicator)

        # Metadata-driven indicators
        open_ports = metadata.get("open_ports", [])
        if isinstance(open_ports, list):
            dangerous_ports = {21: "ftp_open", 22: "ssh_open", 23: "telnet_open",
                               3306: "mysql_open", 5432: "postgres_open",
                               6379: "redis_open", 27017: "mongodb_open",
                               9200: "elasticsearch_open", 5601: "kibana_open",
                               8080: "dev_server_open", 8443: "dev_server_open"}
            for port in open_ports:
                if isinstance(port, int) and port in dangerous_ports:
                    ind = dangerous_ports[port]
                    if ind not in indicators:
                        indicators.append(ind)

        # Exposed .env or config files
        if any(kw in asset_lower for kw in (".env", ".git", "config.php", "wp-config", ".htpasswd")):
            if "sensitive_file_exposed" not in indicators:
                indicators.append("sensitive_file_exposed")

        # Vulnerability list from Shodan
        vulns = metadata.get("vulns", [])
        if vulns:
            indicators.append(f"known_vulns:{len(vulns)}")

        return indicators

    # ------------------------------------------------------------------
    # Scope filtering
    # ------------------------------------------------------------------

    def filter_out_of_scope(self, assets: list, scope_rules: list[str]) -> list:
        """
        Filter assets to only those matching at least one scope rule.
        Supports wildcard patterns: *.example.com, example.com/*, IP ranges (basic).
        """
        if not scope_rules:
            return assets

        in_scope: list = []
        for asset in assets:
            asset_str = asset.get("asset", asset) if isinstance(asset, dict) else str(asset)
            if self._matches_any_scope(asset_str, scope_rules):
                in_scope.append(asset)
        return in_scope

    def _matches_any_scope(self, asset: str, scope_rules: list[str]) -> bool:
        asset = asset.lower()
        for rule in scope_rules:
            rule = rule.lower().strip()
            if rule.startswith("*."):
                suffix = rule[2:]
                if asset == suffix or asset.endswith("." + suffix):
                    return True
                # URL case: strip https:// prefix
                for prefix in ("https://", "http://"):
                    if asset.startswith(prefix):
                        stripped = asset[len(prefix):]
                        if stripped == suffix or stripped.endswith("." + suffix):
                            return True
            elif rule.endswith("/*"):
                base = rule[:-2]
                if asset.startswith(base):
                    return True
            elif asset == rule or asset.startswith(rule + "/"):
                return True
        return False

    # ------------------------------------------------------------------
    # Deduplication
    # ------------------------------------------------------------------

    def deduplicate(self, assets: list) -> list:
        """Normalise and deduplicate asset dicts or strings."""
        seen: set[str] = set()
        out: list = []
        for asset in assets:
            if isinstance(asset, dict):
                key = asset.get("asset", "").lower().rstrip("/")
            else:
                key = str(asset).lower().rstrip("/")
            if key and key not in seen:
                seen.add(key)
                out.append(asset)
        return out

    # ------------------------------------------------------------------
    # Group by bug bounty program
    # ------------------------------------------------------------------

    def group_by_program(self, assets: list, programs: list[dict]) -> dict:
        """
        Assign each asset to the bug bounty program whose scope it matches.
        Returns {program_handle: [asset, ...], "_unmatched": [...]}.
        """
        result: dict[str, list] = defaultdict(list)

        for asset in assets:
            asset_str = asset.get("asset", asset) if isinstance(asset, dict) else str(asset)
            matched = False
            for prog in programs:
                scope_patterns = prog.get("scope", [])
                if self._matches_any_scope(asset_str, scope_patterns):
                    result[prog.get("handle", prog.get("name", "unknown"))].append(asset)
                    matched = True
                    break
            if not matched:
                result["_unmatched"].append(asset)

        return dict(result)


# ---------------------------------------------------------------------------
# Module-level singleton
# ---------------------------------------------------------------------------

asset_correlator = AssetCorrelator()
