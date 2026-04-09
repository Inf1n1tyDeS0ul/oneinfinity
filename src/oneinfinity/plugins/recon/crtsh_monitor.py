"""
Certificate Transparency Monitor Plugin.

Queries crt.sh to enumerate subdomains issued SSL certificates.
Supplements subfinder with historical certificate data.
"""

from __future__ import annotations

import json
import logging
import re
import urllib.error
import urllib.request
from typing import Any, Dict, List, Set

log = logging.getLogger(__name__)

PLUGIN_META = {
    "name": "crtsh_monitor",
    "type": "recon",
    "version": "1.0.0",
    "description": "Certificate Transparency subdomain enumeration via crt.sh",
    "author": "OneInfinity",
    "tags": ["recon", "subdomains", "passive", "ssl", "certificates"],
}

_CRTSH_URL = "https://crt.sh/?q=%.{domain}&output=json"
_TIMEOUT = 30  # seconds


class Plugin:
    """Enumerate subdomains via Certificate Transparency logs (crt.sh)."""

    def run(self, target: str, context: Dict[str, Any]) -> Dict[str, Any]:
        """
        Args:
            target: root domain (e.g. "acme.com")
            context: optional dict with "wildcard" (bool, default True)

        Returns:
            {
                "subdomains": [str],
                "count": int,
                "source": "crtsh",
                "error": str | None
            }
        """
        domain = self._clean_domain(target)
        log.info("[crtsh] Querying certificate transparency for %s", domain)

        try:
            subdomains = self._fetch(domain)
            log.info("[crtsh] Found %d subdomains for %s", len(subdomains), domain)
            return {
                "subdomains": sorted(subdomains),
                "count": len(subdomains),
                "source": "crtsh",
                "error": None,
            }
        except Exception as exc:
            log.error("[crtsh] Error: %s", exc)
            return {
                "subdomains": [],
                "count": 0,
                "source": "crtsh",
                "error": str(exc),
            }

    def _fetch(self, domain: str) -> Set[str]:
        url = _CRTSH_URL.format(domain=domain)
        req = urllib.request.Request(url, headers={"User-Agent": "OneInfinity/1.0"})
        try:
            with urllib.request.urlopen(req, timeout=_TIMEOUT) as resp:
                data = json.loads(resp.read().decode("utf-8"))
        except urllib.error.HTTPError as e:
            raise RuntimeError(f"crt.sh HTTP {e.code}: {e.reason}")
        except urllib.error.URLError as e:
            raise RuntimeError(f"crt.sh connection error: {e.reason}")

        subdomains: Set[str] = set()
        for entry in data:
            names = entry.get("name_value", "")
            for name in names.split("\n"):
                name = name.strip().lstrip("*. ").lower()
                if name.endswith(f".{domain}") or name == domain:
                    if self._is_valid_subdomain(name):
                        subdomains.add(name)

        return subdomains

    @staticmethod
    def _clean_domain(target: str) -> str:
        for scheme in ("https://", "http://"):
            if target.startswith(scheme):
                target = target[len(scheme):]
        return target.split("/")[0].lower().strip()

    @staticmethod
    def _is_valid_subdomain(name: str) -> bool:
        # Basic validation: only allow valid hostname characters
        return bool(re.match(r"^[a-z0-9]([a-z0-9\-\.]*[a-z0-9])?$", name))
