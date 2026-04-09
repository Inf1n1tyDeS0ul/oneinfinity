"""
Target Prioritization Engine — Score and rank targets by attack surface,
technology stack, subdomain count, exposed APIs, and cloud infrastructure.
"""

import re
import json
import logging
import shutil
import subprocess
from dataclasses import dataclass, field
from typing import Optional

logger = logging.getLogger(__name__)

# Tech stack risk weights
TECH_RISK = {
    # High-risk frameworks / versions
    "struts": 9.0, "log4j": 9.5, "weblogic": 8.5, "jboss": 8.0,
    "coldfusion": 8.0, "exchange": 8.0, "sharepoint": 7.0,
    "drupal": 7.5, "wordpress": 7.0, "joomla": 7.0, "magento": 7.5,
    # APIs
    "graphql": 8.0, "swagger": 7.5, "openapi": 7.0, "api": 6.5,
    # Cloud / infra
    "s3": 6.0, "kubernetes": 7.0, "jenkins": 8.0, "gitlab": 7.5,
    "github": 6.5, "artifactory": 7.0, "sonarqube": 6.5,
    # Languages with common issues
    "php": 7.0, "java": 6.5, "ruby": 6.0, "python": 5.5, "go": 5.0,
    "node": 6.5, "react": 4.5, "angular": 4.5,
}

CLOUD_PROVIDERS = {
    "amazonaws.com", "cloudfront.net", "azurewebsites.net",
    "googleapis.com", "appspot.com", "heroku.com",
    "digitaloceanspaces.com", "storage.googleapis.com",
    "blob.core.windows.net", "cloudflare",
}

SENSITIVE_PATHS = [
    "/admin", "/api", "/graphql", "/swagger", "/openapi",
    "/actuator", "/metrics", "/health", "/.env", "/.git",
    "/phpmyadmin", "/wp-admin", "/jenkins", "/gitlab",
    "/console", "/debug", "/config", "/backup",
    "/login", "/auth", "/oauth", "/internal",
]


@dataclass
class TargetScore:
    domain: str
    total_score: float = 0.0
    subdomain_score: float = 0.0
    tech_score: float = 0.0
    api_score: float = 0.0
    cloud_score: float = 0.0
    exposure_score: float = 0.0
    login_score: float = 0.0
    subdomain_count: int = 0
    technologies: list = field(default_factory=list)
    exposed_services: list = field(default_factory=list)
    cloud_providers: list = field(default_factory=list)
    has_login: bool = False
    has_api: bool = False
    has_graphql: bool = False
    priority: str = "medium"  # critical / high / medium / low
    scan_order: int = 0

    def to_dict(self) -> dict:
        return self.__dict__.copy()


class TargetPrioritizationEngine:
    """Rank targets by attack surface richness and technology risk."""

    def __init__(self):
        self._httpx = shutil.which("httpx") or shutil.which("httpx-toolkit")
        self._subfinder = shutil.which("subfinder")

    def score_target(self, domain: str, recon_data: dict = None) -> TargetScore:
        """Score a single target. recon_data can provide pre-gathered info."""
        score = TargetScore(domain=domain)
        data = recon_data or {}

        # Subdomain count scoring
        subdomains = data.get("subdomains", [])
        score.subdomain_count = len(subdomains)
        if score.subdomain_count >= 100:
            score.subdomain_score = 10.0
        elif score.subdomain_count >= 50:
            score.subdomain_score = 8.0
        elif score.subdomain_count >= 20:
            score.subdomain_score = 6.0
        elif score.subdomain_count >= 5:
            score.subdomain_score = 4.0
        else:
            score.subdomain_score = 2.0

        # Technology stack scoring
        techs = data.get("technologies", data.get("tech_stack", []))
        tech_scores = []
        for tech in techs:
            tech_lower = str(tech).lower()
            for known_tech, risk in TECH_RISK.items():
                if known_tech in tech_lower:
                    tech_scores.append(risk)
                    score.technologies.append(str(tech))
                    break
        score.tech_score = min(10.0, sum(tech_scores) / max(len(tech_scores), 1) * 1.2 if tech_scores else 3.0)

        # API exposure scoring
        endpoints = data.get("endpoints", data.get("urls", []))
        api_count = sum(1 for e in endpoints if any(p in str(e).lower() for p in ["/api/", "/v1/", "/v2/", "/graphql", "/rest/"]))
        score.has_api = api_count > 0
        score.has_graphql = any("graphql" in str(e).lower() for e in endpoints)
        score.api_score = min(10.0, api_count * 0.5 + (3.0 if score.has_graphql else 0))

        # Cloud infrastructure scoring
        for provider in CLOUD_PROVIDERS:
            if provider in domain or any(provider in str(s) for s in subdomains):
                score.cloud_providers.append(provider)
                score.cloud_score = min(10.0, score.cloud_score + 2.0)

        # Sensitive path exposure
        exposed_paths = [p for p in SENSITIVE_PATHS if any(p in str(e) for e in endpoints)]
        score.exposed_services = exposed_paths
        score.exposure_score = min(10.0, len(exposed_paths) * 1.5)

        # Login/auth surface
        has_login = any("/login" in str(e).lower() or "/auth" in str(e).lower() or "/signin" in str(e).lower() for e in endpoints)
        score.has_login = has_login
        score.login_score = 4.0 if has_login else 0.0

        # Total weighted score
        score.total_score = (
            score.subdomain_score * 0.20 +
            score.tech_score * 0.25 +
            score.api_score * 0.20 +
            score.cloud_score * 0.10 +
            score.exposure_score * 0.15 +
            score.login_score * 0.10
        ) * 10  # scale to 0-100

        # Priority classification
        if score.total_score >= 75:
            score.priority = "critical"
        elif score.total_score >= 55:
            score.priority = "high"
        elif score.total_score >= 35:
            score.priority = "medium"
        else:
            score.priority = "low"

        return score

    def prioritize(self, targets: list, recon_data: dict = None) -> list:
        """
        Score and sort a list of domain strings.
        recon_data: {domain: {...recon_info...}}
        Returns list of TargetScore sorted by score desc.
        """
        recon_data = recon_data or {}
        scores = []
        for target in targets:
            domain = target if isinstance(target, str) else target.get("domain", str(target))
            domain_recon = recon_data.get(domain, {})
            ts = self.score_target(domain, domain_recon)
            scores.append(ts)

        scores.sort(key=lambda s: s.total_score, reverse=True)
        for i, s in enumerate(scores):
            s.scan_order = i + 1
        return scores

    def quick_score(self, domain: str) -> TargetScore:
        """Quick scoring without recon data — based on domain heuristics only."""
        score = TargetScore(domain=domain)
        # Domain heuristics
        if any(kw in domain for kw in ["api.", "admin.", "internal.", "dev.", "staging.", "test."]):
            score.api_score = 7.0
            score.has_api = True
        if any(kw in domain for kw in ["login.", "auth.", "sso.", "oauth."]):
            score.login_score = 6.0
            score.has_login = True
        for provider in CLOUD_PROVIDERS:
            if provider in domain:
                score.cloud_score = 5.0
                score.cloud_providers.append(provider)
        # Subdomain depth heuristic
        subdomain_depth = domain.count(".")
        score.subdomain_score = min(10.0, subdomain_depth * 1.5)
        score.total_score = (score.api_score * 0.3 + score.login_score * 0.2 + score.cloud_score * 0.2 + score.subdomain_score * 0.3) * 8
        score.priority = "high" if score.total_score >= 50 else "medium" if score.total_score >= 25 else "low"
        return score

    def filter_in_scope(self, targets: list, program_scope: list) -> list:
        """Filter targets to only include in-scope domains."""
        in_scope = []
        for target in targets:
            domain = target if isinstance(target, str) else target.get("domain", "")
            for scope_entry in program_scope:
                if scope_entry.startswith("*."):
                    suffix = scope_entry[1:]
                    if domain.endswith(suffix):
                        in_scope.append(target)
                        break
                elif domain == scope_entry or domain.endswith("." + scope_entry):
                    in_scope.append(target)
                    break
        return in_scope


target_prioritization_engine = TargetPrioritizationEngine()
