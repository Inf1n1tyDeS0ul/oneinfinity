"""
Live Attack Surface Expansion Engine
======================================
Discovers + tests targets in real-time during scan. No other tool does this.

Innovation:
1. **Dynamic Discovery** - Discovers new targets mid-scan, immediately tests them
2. **Recursive Expansion** - SSRF findings discover internal IPs, which discover services, which get tested
3. **Service Enumeration** - Probes discovered IPs for services, dispatches service-specific scanners
4. **Subdomain Chaining** - Each subdomain discovery triggers full scanner suite
5. **Real-time Dispatch** - Background tasks spawn scanners as targets discovered

Attack surface grows exponentially during scan.
"""
from __future__ import annotations

import asyncio
import logging
import re
from dataclasses import dataclass, field
from typing import List, Dict, Any, Optional, Set
from urllib.parse import urlparse

log = logging.getLogger("oneinfinity.live_attack_surface")


@dataclass
class DiscoveredAsset:
    """Asset discovered during scan."""
    asset_id: str
    asset_type: str  # domain, ip, service, endpoint
    value: str  # actual domain/IP/URL
    source: str  # ssrf, subdomain_enum, service_probe
    parent_asset: Optional[str] = None  # What discovered this
    tested: bool = False
    findings: List[Dict] = field(default_factory=list)
    discovered_children: List[str] = field(default_factory=list)


class LiveAttackSurfaceEngine:
    """
    Real-time attack surface expansion engine.

    Workflow:
    1. Start with seed targets
    2. Run initial scans in background
    3. Monitor findings for new targets (SSRF → IPs, subdomains)
    4. Immediately test new targets (recursive)
    5. Continue until no new targets found
    """

    def __init__(self, initial_targets: List[str]):
        self.initial_targets = initial_targets
        self.discovered_assets: Dict[str, DiscoveredAsset] = {}
        self.tested_assets: Set[str] = set()
        self.running_tasks: Dict[str, asyncio.Task] = {}
        self.findings: List[Dict] = []
        self.target_queue: asyncio.Queue = asyncio.Queue()

    # ── Asset Discovery ───────────────────────────────────────────────────────

    async def discover_subdomains(self, domain: str) -> List[DiscoveredAsset]:
        """Discover subdomains using TargetDiscoveryEngine."""
        assets = []

        try:
            from oneinfinity.recon.target_discovery_engine import TargetDiscoveryEngine

            engine = TargetDiscoveryEngine()
            discovered = engine.discover_all(seed_domains=[domain])

            for target in discovered:
                if target.asset_type == "domain" and target.domain != domain:
                    asset = DiscoveredAsset(
                        asset_id=f"subdomain_{target.domain}",
                        asset_type="domain",
                        value=target.domain,
                        source="subdomain_enum",
                        parent_asset=domain,
                    )
                    assets.append(asset)

            log.info(f"Discovered {len(assets)} subdomains from {domain}")

        except Exception as e:
            log.error(f"Subdomain discovery failed: {e}")

        return assets

    async def discover_internal_ips_from_ssrf(self, ssrf_findings: List[Dict]) -> List[DiscoveredAsset]:
        """Extract internal IPs from SSRF findings."""
        assets = []
        internal_ip_pattern = re.compile(r'\b(?:10\.|172\.(?:1[6-9]|2[0-9]|3[01])\.|192\.168\.)\d{1,3}\.\d{1,3}\b')

        for finding in ssrf_findings:
            evidence = finding.get('evidence', '')
            target_url = finding.get('target', '')

            # Extract IPs from evidence
            ips = internal_ip_pattern.findall(evidence + target_url)

            for ip in set(ips):
                asset = DiscoveredAsset(
                    asset_id=f"internal_ip_{ip}",
                    asset_type="ip",
                    value=ip,
                    source="ssrf_discovery",
                    parent_asset=finding.get('url', ''),
                )
                assets.append(asset)

        log.info(f"Discovered {len(assets)} internal IPs from SSRF")
        return assets

    async def probe_services(self, ip: str) -> List[DiscoveredAsset]:
        """Probe IP for common services."""
        assets = []
        common_ports = [80, 443, 8080, 8443, 3000, 5000, 8000, 9000]

        import socket

        for port in common_ports:
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(2)
                result = sock.connect_ex((ip, port))
                sock.close()

                if result == 0:
                    protocol = "https" if port in [443, 8443] else "http"
                    service_url = f"{protocol}://{ip}:{port}"

                    asset = DiscoveredAsset(
                        asset_id=f"service_{ip}_{port}",
                        asset_type="service",
                        value=service_url,
                        source="port_probe",
                        parent_asset=ip,
                    )
                    assets.append(asset)

            except Exception:
                continue

        log.info(f"Discovered {len(assets)} services on {ip}")
        return assets

    # ── Scanner Dispatch ──────────────────────────────────────────────────────

    async def dispatch_scanner_for_asset(self, asset: DiscoveredAsset) -> List[Dict]:
        """Dispatch appropriate scanner based on asset type."""
        findings = []

        try:
            if asset.asset_type == "domain":
                # Test subdomain for client-side attacks + subdomain takeover
                findings.extend(await self._scan_domain(asset.value))

            elif asset.asset_type == "ip":
                # Probe for services, then test each
                services = await self.probe_services(asset.value)
                for service_asset in services:
                    await self.target_queue.put(service_asset)

            elif asset.asset_type == "service":
                # Test service URL for all vulns
                findings.extend(await self._scan_service(asset.value))

        except Exception as e:
            log.error(f"Scanner dispatch failed for {asset.value}: {e}")

        return findings

    async def _scan_domain(self, domain: str) -> List[Dict]:
        """Scan domain for vulnerabilities."""
        findings = []

        try:
            # Client-side attacks
            from oneinfinity.scan.client_side_attack_scanner import scan_client_side_attacks
            client_findings = await scan_client_side_attacks(f"https://{domain}")
            findings.extend([f.to_dict() for f in client_findings])

            # Subdomain takeover
            from oneinfinity.scan.subdomain_takeover_scanner import scan_subdomain_takeover
            takeover_findings = await scan_subdomain_takeover(domain)
            findings.extend([f.to_dict() for f in takeover_findings])

            # DNS rebinding
            from oneinfinity.scan.dns_rebinding_scanner import scan_dns_rebinding
            dns_findings = await scan_dns_rebinding(f"https://{domain}")
            findings.extend([f.to_dict() for f in dns_findings])

        except Exception as e:
            log.error(f"Domain scan failed for {domain}: {e}")

        return findings

    async def _scan_service(self, service_url: str) -> List[Dict]:
        """Scan service URL for vulnerabilities."""
        findings = []

        try:
            # SSRF scanner
            from oneinfinity.scan.ssrf_scanner import scan_ssrf
            ssrf_findings = await scan_ssrf(service_url)
            findings.extend([f.to_dict() for f in ssrf_findings])

            # Path traversal
            from oneinfinity.scan.path_traversal_scanner import scan_path_traversal
            path_findings = await scan_path_traversal(service_url)
            findings.extend([f.to_dict() for f in path_findings])

        except Exception as e:
            log.error(f"Service scan failed for {service_url}: {e}")

        return findings

    # ── Recursive Expansion ───────────────────────────────────────────────────

    async def expand_attack_surface(self) -> Dict[str, Any]:
        """
        Main expansion loop: discovers + tests recursively.

        Returns:
            Summary with all discovered assets + findings
        """
        log.info(f"Starting live attack surface expansion with {len(self.initial_targets)} initial targets")

        # Seed queue with initial targets
        for target in self.initial_targets:
            parsed = urlparse(target if '://' in target else f"https://{target}")
            domain = parsed.hostname or target

            initial_asset = DiscoveredAsset(
                asset_id=f"initial_{domain}",
                asset_type="domain",
                value=domain,
                source="user_input",
            )
            await self.target_queue.put(initial_asset)

        # Process queue until empty
        while not self.target_queue.empty() or len(self.running_tasks) > 0:
            # Start new tasks from queue
            while not self.target_queue.empty() and len(self.running_tasks) < 10:  # Max 10 parallel
                asset = await self.target_queue.get()

                if asset.asset_id in self.tested_assets:
                    continue

                self.tested_assets.add(asset.asset_id)
                self.discovered_assets[asset.asset_id] = asset

                task = asyncio.create_task(self._test_and_expand(asset))
                self.running_tasks[asset.asset_id] = task

            # Wait for any task to complete
            if self.running_tasks:
                done, pending = await asyncio.wait(
                    self.running_tasks.values(),
                    return_when=asyncio.FIRST_COMPLETED,
                    timeout=1.0
                )

                for task in done:
                    # Find asset for this task
                    asset_id = next((aid for aid, t in self.running_tasks.items() if t == task), None)
                    if asset_id:
                        del self.running_tasks[asset_id]

        log.info(f"Attack surface expansion complete: {len(self.discovered_assets)} assets, {len(self.findings)} findings")

        return {
            "discovered_assets": [asset.__dict__ for asset in self.discovered_assets.values()],
            "total_assets": len(self.discovered_assets),
            "total_findings": len(self.findings),
            "findings": self.findings,
            "expansion_tree": self._build_expansion_tree(),
        }

    async def _test_and_expand(self, asset: DiscoveredAsset):
        """Test asset and discover new assets from results."""
        # Test asset
        findings = await self.dispatch_scanner_for_asset(asset)
        asset.findings = findings
        asset.tested = True
        self.findings.extend(findings)

        # Expand based on findings
        new_assets = []

        # If domain → discover subdomains
        if asset.asset_type == "domain":
            new_assets.extend(await self.discover_subdomains(asset.value))

        # If SSRF findings → extract internal IPs
        ssrf_findings = [f for f in findings if f.get('vuln_type') == 'ssrf']
        if ssrf_findings:
            new_assets.extend(await self.discover_internal_ips_from_ssrf(ssrf_findings))

        # Queue new assets for testing
        for new_asset in new_assets:
            if new_asset.asset_id not in self.tested_assets:
                await self.target_queue.put(new_asset)
                asset.discovered_children.append(new_asset.asset_id)

    def _build_expansion_tree(self) -> Dict[str, Any]:
        """Build tree showing how attack surface expanded."""
        tree = {}

        for asset_id, asset in self.discovered_assets.items():
            tree[asset_id] = {
                "type": asset.asset_type,
                "value": asset.value,
                "source": asset.source,
                "parent": asset.parent_asset,
                "children": asset.discovered_children,
                "findings_count": len(asset.findings),
            }

        return tree


# ── Convenience Function ──────────────────────────────────────────────────────

async def expand_attack_surface_live(targets: List[str]) -> Dict[str, Any]:
    """Run live attack surface expansion."""
    engine = LiveAttackSurfaceEngine(targets)
    return await engine.expand_attack_surface()
