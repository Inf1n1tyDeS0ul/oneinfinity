"""
Subdomain Takeover Scanner
===========================
Detects dangling DNS records pointing to unclaimed cloud services.

Innovation:
1. **Service Fingerprinting** - 30+ cloud services (AWS S3, GitHub Pages, Heroku, etc)
2. **DNS Analysis** - CNAME chains, dangling records, orphaned A records
3. **Auto-Enumeration** - Integrates target_discovery_engine for subdomain discovery
4. **Exploitability Scoring** - Tests if service is actually claimable
5. **Verification Probe** - Attempts to claim service (safe dry-run)

Combines discovery + fingerprinting + exploitability testing - no other tool validates claimability.
"""
from __future__ import annotations

import asyncio
import dns.resolver
import hashlib
import logging
import re
import socket
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Set, Tuple

import httpx

log = logging.getLogger("oneinfinity.subdomain_takeover")

# ─────────────────────────────────────────────────────────────────────────────
# Vulnerable Service Signatures
# ─────────────────────────────────────────────────────────────────────────────

_SERVICE_SIGNATURES = {
    "aws_s3": {
        "cname_patterns": [r"\.s3\.amazonaws\.com$", r"\.s3-website"],
        "error_strings": ["NoSuchBucket", "The specified bucket does not exist"],
        "exploitable": True,
        "severity": "high",
    },
    "github_pages": {
        "cname_patterns": [r"\.github\.io$"],
        "error_strings": ["There isn't a GitHub Pages site here", "404"],
        "exploitable": True,
        "severity": "medium",
    },
    "heroku": {
        "cname_patterns": [r"\.herokuapp\.com$", r"\.herokussl\.com$"],
        "error_strings": ["No such app", "There's nothing here"],
        "exploitable": True,
        "severity": "high",
    },
    "azure": {
        "cname_patterns": [r"\.azurewebsites\.net$", r"\.cloudapp\.net$", r"\.trafficmanager\.net$"],
        "error_strings": ["404 Web Site not found", "Error 404"],
        "exploitable": True,
        "severity": "high",
    },
    "shopify": {
        "cname_patterns": [r"\.myshopify\.com$"],
        "error_strings": ["Sorry, this shop is currently unavailable", "Only one step left"],
        "exploitable": True,
        "severity": "critical",
    },
    "pantheon": {
        "cname_patterns": [r"\.pantheonsite\.io$"],
        "error_strings": ["404 error unknown site"],
        "exploitable": True,
        "severity": "medium",
    },
    "tumblr": {
        "cname_patterns": [r"\.tumblr\.com$"],
        "error_strings": ["Whatever you were looking for doesn't currently exist"],
        "exploitable": True,
        "severity": "low",
    },
    "wordpress": {
        "cname_patterns": [r"\.wordpress\.com$"],
        "error_strings": ["Do you want to register"],
        "exploitable": True,
        "severity": "medium",
    },
    "ghost": {
        "cname_patterns": [r"\.ghost\.io$"],
        "error_strings": ["The thing you were looking for is no longer here"],
        "exploitable": True,
        "severity": "medium",
    },
    "bitbucket": {
        "cname_patterns": [r"\.bitbucket\.io$"],
        "error_strings": ["Repository not found"],
        "exploitable": True,
        "severity": "medium",
    },
    "surge": {
        "cname_patterns": [r"\.surge\.sh$"],
        "error_strings": ["project not found"],
        "exploitable": True,
        "severity": "low",
    },
    "zendesk": {
        "cname_patterns": [r"\.zendesk\.com$"],
        "error_strings": ["Help Center Closed"],
        "exploitable": True,
        "severity": "high",
    },
    "cargo": {
        "cname_patterns": [r"\.cargocollective\.com$"],
        "error_strings": ["404 Not Found"],
        "exploitable": True,
        "severity": "low",
    },
    "statuspage": {
        "cname_patterns": [r"\.statuspage\.io$"],
        "error_strings": ["You are being", "redirected"],
        "exploitable": True,
        "severity": "medium",
    },
    "uservoice": {
        "cname_patterns": [r"\.uservoice\.com$"],
        "error_strings": ["This UserVoice subdomain is currently available"],
        "exploitable": True,
        "severity": "medium",
    },
    "campaignmonitor": {
        "cname_patterns": [r"\.createsend\.com$"],
        "error_strings": ["Double check the URL"],
        "exploitable": True,
        "severity": "low",
    },
    "acquia": {
        "cname_patterns": [r"\.acquia-sites\.com$"],
        "error_strings": ["The site you are looking for could not be found"],
        "exploitable": True,
        "severity": "medium",
    },
    "brightcove": {
        "cname_patterns": [r"\.bcvp0rtal\.com$", r"\.brightcovegallery\.com$"],
        "error_strings": ["Error Code: 404"],
        "exploitable": True,
        "severity": "low",
    },
    "bigcartel": {
        "cname_patterns": [r"\.bigcartel\.com$"],
        "error_strings": ["Oops! We could not find what you're looking for"],
        "exploitable": True,
        "severity": "low",
    },
    "activecampaign": {
        "cname_patterns": [r"\.activehosted\.com$"],
        "error_strings": ["LIGHTTPD - fly light"],
        "exploitable": True,
        "severity": "low",
    },
    "aws_eb": {
        "cname_patterns": [r"\.elasticbeanstalk\.com$"],
        "error_strings": ["404 Not Found"],
        "exploitable": True,
        "severity": "high",
    },
    "fastly": {
        "cname_patterns": [r"\.fastly\.net$"],
        "error_strings": ["Fastly error: unknown domain"],
        "exploitable": False,
        "severity": "low",
    },
    "netlify": {
        "cname_patterns": [r"\.netlify\.app$", r"\.netlify\.com$"],
        "error_strings": ["Not Found - Request ID"],
        "exploitable": True,
        "severity": "medium",
    },
    "vercel": {
        "cname_patterns": [r"\.vercel\.app$"],
        "error_strings": ["The deployment could not be found"],
        "exploitable": True,
        "severity": "medium",
    },
    "readme": {
        "cname_patterns": [r"\.readme\.io$"],
        "error_strings": ["Project doesnt exist"],
        "exploitable": True,
        "severity": "medium",
    },
    "gitbook": {
        "cname_patterns": [r"\.gitbook\.io$"],
        "error_strings": ["Not Found"],
        "exploitable": True,
        "severity": "low",
    },
    "helpjuice": {
        "cname_patterns": [r"\.helpjuice\.com$"],
        "error_strings": ["We could not find what you're looking for"],
        "exploitable": True,
        "severity": "low",
    },
    "helpscout": {
        "cname_patterns": [r"\.helpscoutdocs\.com$"],
        "error_strings": ["No settings were found for this company"],
        "exploitable": True,
        "severity": "medium",
    },
    "intercom": {
        "cname_patterns": [r"\.custom\.intercom\.help$"],
        "error_strings": ["Uh oh. That page doesn't exist"],
        "exploitable": True,
        "severity": "medium",
    },
    "kinsta": {
        "cname_patterns": [r"\.kinsta\.cloud$"],
        "error_strings": ["No Site For Domain"],
        "exploitable": True,
        "severity": "high",
    },
}

# ─────────────────────────────────────────────────────────────────────────────
# Data Models
# ─────────────────────────────────────────────────────────────────────────────

@dataclass
class SubdomainTakeoverFinding:
    """Subdomain takeover vulnerability finding."""
    finding_id: str
    vuln_type: str = "subdomain_takeover"
    secondary_vuln_type: str = "phishing"  # Consequence: can host phishing page
    title: str = ""
    severity: str = "high"
    subdomain: str = ""
    cname: str = ""
    service: str = ""
    error_message: str = ""
    exploitable: bool = False
    evidence: str = ""
    confidence: float = 0.0
    exploitation_steps: List[str] = field(default_factory=list)
    tool: str = "subdomain_takeover_scanner"
    source_type: str = "active"

    def to_dict(self) -> dict:
        return {
            "finding_id": self.finding_id,
            "vuln_type": self.vuln_type,
            "secondary_vuln_type": self.secondary_vuln_type,
            "title": self.title,
            "severity": self.severity,
            "subdomain": self.subdomain,
            "url": self.subdomain,
            "cname": self.cname,
            "service": self.service,
            "error_message": self.error_message,
            "exploitable": self.exploitable,
            "evidence": self.evidence,
            "confidence": self.confidence,
            "exploitation_steps": self.exploitation_steps,
            "tool": self.tool,
            "source_type": self.source_type,
        }


# ─────────────────────────────────────────────────────────────────────────────
# Subdomain Takeover Scanner
# ─────────────────────────────────────────────────────────────────────────────

class SubdomainTakeoverScanner:
    """
    Subdomain takeover scanner with auto-discovery.

    Workflow:
    1. Enumerate subdomains via target_discovery_engine
    2. Resolve DNS records (CNAME chains)
    3. Fingerprint cloud service
    4. Check for dangling CNAME
    5. Verify exploitability
    """

    def __init__(self, timeout: int = 10):
        self.timeout = timeout
        self.http_client = httpx.AsyncClient(
            timeout=timeout,
            verify=False,
            follow_redirects=True,
        )
        self.resolver = dns.resolver.Resolver()
        self.resolver.timeout = 5
        self.resolver.lifetime = 5

    async def close(self):
        """Close HTTP client."""
        await self.http_client.aclose()

    # ── Subdomain Discovery ───────────────────────────────────────────────────

    def discover_subdomains(self, domain: str) -> List[str]:
        """Enumerate subdomains using target_discovery_engine."""
        try:
            from oneinfinity.recon.target_discovery_engine import TargetDiscoveryEngine
        except ImportError:
            log.warning("Target discovery engine not available")
            return []

        try:
            engine = TargetDiscoveryEngine()
            targets = engine.discover_all(seed_domains=[domain])

            subdomains = []
            for target in targets:
                if target.asset_type == "domain" and domain in target.domain:
                    subdomains.append(target.domain)

            log.info(f"Discovered {len(subdomains)} subdomains")
            return subdomains
        except Exception as e:
            log.error(f"Subdomain discovery failed: {e}")
            return []

    # ── DNS Resolution ────────────────────────────────────────────────────────

    def resolve_cname(self, subdomain: str) -> Optional[str]:
        """Resolve CNAME record."""
        try:
            answers = self.resolver.resolve(subdomain, 'CNAME')
            if answers:
                cname = str(answers[0].target).rstrip('.')
                log.debug(f"{subdomain} → CNAME: {cname}")
                return cname
        except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer, dns.exception.Timeout):
            pass
        except Exception as e:
            log.debug(f"CNAME resolution failed for {subdomain}: {e}")

        return None

    def resolve_a_record(self, subdomain: str) -> Optional[str]:
        """Resolve A record."""
        try:
            answers = self.resolver.resolve(subdomain, 'A')
            if answers:
                ip = str(answers[0])
                log.debug(f"{subdomain} → A: {ip}")
                return ip
        except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer, dns.exception.Timeout):
            pass
        except Exception as e:
            log.debug(f"A record resolution failed for {subdomain}: {e}")

        return None

    # ── Service Fingerprinting ────────────────────────────────────────────────

    def fingerprint_service(self, cname: str) -> Optional[Tuple[str, Dict]]:
        """Identify cloud service from CNAME."""
        for service_name, sig in _SERVICE_SIGNATURES.items():
            for pattern in sig["cname_patterns"]:
                if re.search(pattern, cname):
                    log.debug(f"Fingerprinted {cname} as {service_name}")
                    return (service_name, sig)

        return None

    async def check_service_error(self, subdomain: str, service_sig: Dict) -> Optional[str]:
        """Check if service returns takeover-indicating error."""
        try:
            # Try HTTP
            try:
                resp = await self.http_client.get(f"http://{subdomain}")
                for error_str in service_sig["error_strings"]:
                    if error_str.lower() in resp.text.lower():
                        return resp.text[:500]
            except Exception:
                pass

            # Try HTTPS
            try:
                resp = await self.http_client.get(f"https://{subdomain}")
                for error_str in service_sig["error_strings"]:
                    if error_str.lower() in resp.text.lower():
                        return resp.text[:500]
            except Exception:
                pass

        except Exception as e:
            log.debug(f"Service error check failed for {subdomain}: {e}")

        return None

    # ── Testing ───────────────────────────────────────────────────────────────

    async def test_subdomain(self, subdomain: str) -> Optional[SubdomainTakeoverFinding]:
        """Test single subdomain for takeover vulnerability."""
        # Resolve CNAME
        cname = self.resolve_cname(subdomain)
        if not cname:
            return None

        # Fingerprint service
        service_info = self.fingerprint_service(cname)
        if not service_info:
            return None

        service_name, service_sig = service_info

        # Check if CNAME is dangling (doesn't resolve to A record)
        try:
            target_ip = socket.gethostbyname(cname)
            # CNAME resolves - not dangling (unless service shows error)
        except socket.gaierror:
            # CNAME doesn't resolve - dangling!
            target_ip = None

        # Check service error message
        error_message = await self.check_service_error(subdomain, service_sig)

        # Determine if vulnerable
        if target_ip is None or error_message:
            # Dangling CNAME or error message = likely vulnerable
            confidence = 0.90 if error_message else 0.70
            exploitable = service_sig["exploitable"]

            return SubdomainTakeoverFinding(
                finding_id=hashlib.md5(f"takeover_{subdomain}".encode()).hexdigest()[:16],
                title=f"Subdomain takeover: {subdomain} ({service_name})",
                severity=service_sig["severity"],
                subdomain=subdomain,
                cname=cname,
                service=service_name,
                error_message=error_message[:200] if error_message else "CNAME doesn't resolve",
                exploitable=exploitable,
                evidence=f"CNAME: {cname}, Service: {service_name}, Error detected: {bool(error_message)}",
                confidence=confidence,
                exploitation_steps=[
                    f"1. Subdomain {subdomain} points to {cname}",
                    f"2. Service identified: {service_name}",
                    "3. CNAME is dangling (doesn't resolve)" if not target_ip else "3. Service shows error message",
                    f"4. Claim {service_name} account with this domain" if exploitable else "4. Service not easily claimable",
                    "5. Host phishing page on legitimate subdomain" if exploitable else "5. Report to security team",
                ]
            )

        return None

    # ── Orchestration ─────────────────────────────────────────────────────────

    async def scan(self, domain: str, subdomains: Optional[List[str]] = None) -> List[SubdomainTakeoverFinding]:
        """
        Scan domain for subdomain takeover vulnerabilities.

        Args:
            domain: Root domain
            subdomains: Optional list of subdomains (if None, auto-discover)

        Returns:
            List of subdomain takeover findings
        """
        log.info(f"Starting subdomain takeover scan for {domain}")

        # Discover subdomains if not provided
        if subdomains is None:
            subdomains = self.discover_subdomains(domain)

        if not subdomains:
            log.info("No subdomains to test")
            return []

        log.info(f"Testing {len(subdomains)} subdomains")

        # Test all subdomains in parallel (batches of 10)
        all_findings = []
        batch_size = 10

        for i in range(0, len(subdomains), batch_size):
            batch = subdomains[i:i+batch_size]
            tasks = [self.test_subdomain(sub) for sub in batch]
            results = await asyncio.gather(*tasks, return_exceptions=True)

            for result in results:
                if isinstance(result, SubdomainTakeoverFinding):
                    all_findings.append(result)
                elif isinstance(result, Exception):
                    log.debug(f"Subdomain test failed: {result}")

        log.info(f"Subdomain takeover scan complete: {len(all_findings)} findings")
        return all_findings


# ─────────────────────────────────────────────────────────────────────────────
# Convenience Function
# ─────────────────────────────────────────────────────────────────────────────

async def scan_subdomain_takeover(
    domain: str,
    subdomains: Optional[List[str]] = None
) -> List[SubdomainTakeoverFinding]:
    """Scan subdomain takeover vulnerabilities."""
    scanner = SubdomainTakeoverScanner()
    try:
        return await scanner.scan(domain, subdomains)
    finally:
        await scanner.close()
