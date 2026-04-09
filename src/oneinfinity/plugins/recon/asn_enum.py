"""
ASN / BGP Enumeration Plugin.

Resolves ASN information for a target and enumerates IP ranges
belonging to the same organization. Helps find forgotten assets
and shadow infrastructure.

Uses: bgp.he.net (passive), ipinfo.io (API)
"""

from __future__ import annotations

import ipaddress
import json
import logging
import re
import urllib.error
import urllib.request
from typing import Any, Dict, List, Optional, Set

log = logging.getLogger(__name__)

PLUGIN_META = {
    "name": "asn_enum",
    "type": "recon",
    "version": "1.0.0",
    "description": "ASN/BGP enumeration — discover IP ranges from ASN ownership",
    "author": "OneInfinity",
    "tags": ["recon", "asn", "bgp", "ips", "passive", "infrastructure"],
}

_IPINFO_URL = "https://ipinfo.io/{ip}/json"
_ASN_PREFIXES_URL = "https://ipinfo.io/AS{asn}/json"
_TIMEOUT = 15


class Plugin:
    """Enumerate IP ranges via ASN ownership data."""

    def run(self, target: str, context: Dict[str, Any]) -> Dict[str, Any]:
        """
        Args:
            target: domain or IP
            context:
                "api_token": ipinfo.io token (optional, increases rate limits)
                "max_prefixes": int (default 50)

        Returns:
            {
                "ip": str,
                "asn": str,
                "org": str,
                "country": str,
                "prefixes": [str],           # CIDR blocks
                "ip_count": int,             # total IPs across all prefixes
                "sample_ips": [str],         # first 10 IPs from each prefix
                "error": str | None
            }
        """
        api_token = context.get("api_token", "")
        max_prefixes = int(context.get("max_prefixes", 50))

        ip = self._resolve_ip(target)
        if not ip:
            return {"error": f"Could not resolve IP for {target}", "prefixes": [], "sample_ips": []}

        log.info("[asn_enum] Resolved %s → %s", target, ip)

        ip_info = self._fetch_ip_info(ip, api_token)
        if "error" in ip_info:
            return {**ip_info, "ip": ip, "prefixes": [], "sample_ips": []}

        asn = ip_info.get("org", "").split(" ")[0].lstrip("AS")
        org = " ".join(ip_info.get("org", "").split(" ")[1:])
        country = ip_info.get("country", "")

        log.info("[asn_enum] ASN=%s, Org=%s", asn, org)

        prefixes, sample_ips, total_ips = [], [], 0
        if asn and asn.isdigit():
            prefixes, sample_ips, total_ips = self._fetch_asn_prefixes(
                asn, api_token, max_prefixes
            )

        return {
            "ip": ip,
            "asn": f"AS{asn}" if asn else "",
            "org": org,
            "country": country,
            "prefixes": prefixes,
            "ip_count": total_ips,
            "sample_ips": sample_ips[:100],
            "error": None,
        }

    # ------------------------------------------------------------------ #
    #  Internal helpers
    # ------------------------------------------------------------------ #

    def _resolve_ip(self, target: str) -> Optional[str]:
        """Resolve domain to IP via socket."""
        import socket
        domain = self._clean_domain(target)
        try:
            return socket.gethostbyname(domain)
        except socket.gaierror as e:
            log.warning("[asn_enum] DNS resolution failed for %s: %s", domain, e)
            return None

    def _fetch_ip_info(self, ip: str, token: str = "") -> dict:
        url = _IPINFO_URL.format(ip=ip)
        if token:
            url += f"?token={token}"
        return self._get_json(url)

    def _fetch_asn_prefixes(
        self, asn: str, token: str, max_prefixes: int
    ):
        url = _ASN_PREFIXES_URL.format(asn=asn)
        if token:
            url += f"?token={token}"

        data = self._get_json(url)
        if "error" in data:
            return [], [], 0

        prefixes_data = data.get("prefixes", [])
        prefixes = []
        sample_ips = []
        total_ips = 0

        for pdata in prefixes_data[:max_prefixes]:
            cidr = pdata if isinstance(pdata, str) else pdata.get("netblock", "")
            if not cidr:
                continue
            prefixes.append(cidr)
            try:
                net = ipaddress.IPv4Network(cidr, strict=False)
                total_ips += net.num_addresses
                # sample first 10 usable IPs
                usable = list(net.hosts())[:10]
                sample_ips.extend(str(ip) for ip in usable)
            except ValueError:
                pass

        return prefixes, sample_ips, total_ips

    def _get_json(self, url: str) -> dict:
        req = urllib.request.Request(
            url, headers={"Accept": "application/json", "User-Agent": "OneInfinity/1.0"}
        )
        try:
            with urllib.request.urlopen(req, timeout=_TIMEOUT) as resp:
                return json.loads(resp.read().decode("utf-8"))
        except urllib.error.HTTPError as e:
            return {"error": f"HTTP {e.code}: {e.reason}"}
        except Exception as e:
            return {"error": str(e)}

    @staticmethod
    def _clean_domain(target: str) -> str:
        for scheme in ("https://", "http://"):
            if target.startswith(scheme):
                target = target[len(scheme):]
        return target.split("/")[0].lower().strip()
