"""
Scan Profiles — predefined scanning configurations for different use cases.

Profiles:
  quick    — 15-20 min, passive recon + nuclei critical/high only
  deep     — 60-90 min, full recon + all vuln scanners + exploit chains
  research — iterative research mode, multi-iteration, AI-driven theory testing
  swarm    — distributed broad coverage, many targets, minimal depth per target
  stealth  — passive-only, no active probes, safe for production monitoring
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Dict, List, Optional


@dataclass
class ScanProfile:
    name: str
    description: str

    # Recon settings
    recon_subdomains: bool = True
    recon_urls: bool = True
    recon_ports: bool = False
    recon_dns: bool = True
    max_subdomains: int = 500
    max_urls: int = 2000
    crawl_depth: int = 2

    # Scan settings
    nuclei_enabled: bool = True
    nuclei_severity: str = "low,medium,high,critical"
    nuclei_tags: List[str] = field(default_factory=list)
    dalfox_enabled: bool = True
    sqlmap_enabled: bool = False
    nikto_enabled: bool = False
    custom_tests_enabled: bool = False

    # Parallelism
    max_workers: int = 8
    nuclei_rate_limit: int = 150
    nuclei_bulk_size: int = 25

    # Research mode
    research_mode: bool = False
    research_iterations: int = 3
    research_confidence_threshold: float = 0.60

    # Exploit chain detection
    chain_detection: bool = True

    # Timeout (seconds) per phase
    recon_timeout: int = 300
    scan_timeout: int = 600
    exploit_timeout: int = 120

    # Output
    report_formats: List[str] = field(default_factory=lambda: ["markdown"])
    platform: str = "hackerone"


# ------------------------------------------------------------------ #
#  Built-in profiles
# ------------------------------------------------------------------ #

PROFILES: Dict[str, ScanProfile] = {

    "quick": ScanProfile(
        name="quick",
        description="Fast 15-20 minute scan — passive recon + high/critical nuclei",
        recon_ports=False,
        max_subdomains=200,
        max_urls=500,
        crawl_depth=1,
        nuclei_severity="high,critical",
        nuclei_tags=["cve", "misconfig", "exposure"],
        dalfox_enabled=False,
        sqlmap_enabled=False,
        custom_tests_enabled=False,
        max_workers=12,
        nuclei_rate_limit=300,
        research_mode=False,
        research_iterations=0,
        chain_detection=False,
        recon_timeout=120,
        scan_timeout=300,
        report_formats=["markdown"],
    ),

    "deep": ScanProfile(
        name="deep",
        description="Full 60-90 minute scan — complete recon + all scanners + chains",
        recon_ports=True,
        max_subdomains=2000,
        max_urls=10000,
        crawl_depth=4,
        nuclei_severity="info,low,medium,high,critical",
        nuclei_tags=["cve", "misconfig", "exposure", "sqli", "xss", "ssrf", "lfi", "rce", "oast"],
        dalfox_enabled=True,
        sqlmap_enabled=True,
        nikto_enabled=True,
        custom_tests_enabled=True,
        max_workers=8,
        nuclei_rate_limit=100,
        nuclei_bulk_size=50,
        research_mode=False,
        research_iterations=0,
        chain_detection=True,
        recon_timeout=600,
        scan_timeout=1800,
        exploit_timeout=300,
        report_formats=["markdown", "json", "html"],
    ),

    "research": ScanProfile(
        name="research",
        description="AI-driven iterative research — theory generation + custom tests + zero-day detection",
        recon_ports=False,
        max_subdomains=500,
        max_urls=3000,
        crawl_depth=3,
        nuclei_severity="info,low,medium,high,critical",
        nuclei_tags=["cve", "misconfig", "exposure"],
        dalfox_enabled=True,
        sqlmap_enabled=True,
        custom_tests_enabled=True,
        max_workers=6,
        nuclei_rate_limit=100,
        research_mode=True,
        research_iterations=5,
        research_confidence_threshold=0.60,
        chain_detection=True,
        recon_timeout=300,
        scan_timeout=600,
        report_formats=["markdown", "json"],
        platform="hackerone",
    ),

    "swarm": ScanProfile(
        name="swarm",
        description="Broad coverage across many targets — minimal depth, max parallelism",
        recon_ports=False,
        max_subdomains=100,
        max_urls=200,
        crawl_depth=1,
        nuclei_severity="high,critical",
        nuclei_tags=["cve", "exposure"],
        dalfox_enabled=False,
        sqlmap_enabled=False,
        custom_tests_enabled=False,
        max_workers=16,
        nuclei_rate_limit=500,
        nuclei_bulk_size=100,
        research_mode=False,
        chain_detection=False,
        recon_timeout=60,
        scan_timeout=120,
        report_formats=["json"],
    ),

    "stealth": ScanProfile(
        name="stealth",
        description="Passive-only — no active probes, safe for monitoring production",
        recon_ports=False,
        max_subdomains=500,
        max_urls=5000,
        crawl_depth=2,
        nuclei_enabled=False,
        dalfox_enabled=False,
        sqlmap_enabled=False,
        nikto_enabled=False,
        custom_tests_enabled=False,
        max_workers=4,
        research_mode=False,
        chain_detection=False,
        recon_timeout=600,
        scan_timeout=0,
        report_formats=["json"],
    ),
}


def get_profile(name: str) -> ScanProfile:
    """Return a profile by name. Raises KeyError if unknown."""
    profile = PROFILES.get(name)
    if profile is None:
        available = ", ".join(PROFILES.keys())
        raise KeyError(f"Unknown scan profile '{name}'. Available: {available}")
    return profile


def list_profiles() -> str:
    lines = ["Available scan profiles:", ""]
    for name, profile in PROFILES.items():
        lines.append(f"  {name:<10} — {profile.description}")
    return "\n".join(lines)
