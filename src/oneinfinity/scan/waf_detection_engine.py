"""
waf_detection_engine.py — WAF detection and scan adaptation layer.

Detects:
  - Cloudflare, Akamai, AWS WAF, ModSecurity, F5 BIG-IP, Imperva

Adapts scan behavior:
  - Reduces request rate (rps)
  - Adds jitter between requests
  - Rotates User-Agent and IP headers
  - Switches aggressive tools to passive / nuclei-only mode
  - Returns WAFProfile for use by scanning modules
"""
from __future__ import annotations

import logging
import random
import time
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Tuple

import requests

log = logging.getLogger("oi.waf_detect")

# ---------------------------------------------------------------------------
# WAF fingerprints
# ---------------------------------------------------------------------------

_WAF_SIGNATURES: List[Tuple[str, str, str]] = [
    # (WAF name, header name, value pattern)
    ("Cloudflare",   "server",               "cloudflare"),
    ("Cloudflare",   "cf-ray",               ""),           # header present = CF
    ("AWS WAF",      "x-amzn-requestid",     ""),
    ("AWS WAF",      "x-amz-cf-id",          ""),
    ("Akamai",       "server",               "akamai"),
    ("Akamai",       "x-akamai-edgescape",   ""),
    ("Imperva",      "x-iinfo",              ""),
    ("Imperva",      "x-cdn",                "imperva"),
    ("F5 BIG-IP",    "server",               "bigip"),
    ("F5 BIG-IP",    "x-waf-status",         ""),
    ("ModSecurity",  "x-mod-security-message", ""),
    ("ModSecurity",  "server",               "mod_security"),
    ("Sucuri",       "server",               "sucuri"),
    ("Sucuri",       "x-sucuri-id",          ""),
]

# Status codes that indicate WAF blocking
_BLOCK_STATUS_CODES = {403, 406, 429, 503, 999}


@dataclass
class WAFProfile:
    detected: bool = False
    waf_name: str  = ""
    block_status_seen: bool = False
    recommended_rps: float  = 5.0    # Requests per second
    jitter_ms: int          = 0      # Extra jitter between requests (ms)
    rotate_headers: bool    = False  # Rotate User-Agent / X-Forwarded-For
    passive_only: bool      = False  # Skip active tools (dalfox, sqlmap)
    evidence: str           = ""
    raw_headers: Dict[str, str] = field(default_factory=dict)

    def as_scan_config(self) -> dict:
        """Return a scan configuration dict consumable by scan modules."""
        return {
            "waf_detected":      self.detected,
            "waf_name":          self.waf_name,
            "rate_limit_rps":    self.recommended_rps,
            "jitter_ms":         self.jitter_ms,
            "rotate_headers":    self.rotate_headers,
            "passive_only":      self.passive_only,
            "nuclei_rate_limit": int(self.recommended_rps * 60),  # requests/minute
        }


# ---------------------------------------------------------------------------
# User-Agent + header rotation pool
# ---------------------------------------------------------------------------

_UA_POOL = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.2 Safari/605.1.15",
    "Mozilla/5.0 (X11; Linux x86_64; rv:122.0) Gecko/20100101 Firefox/122.0",
    "Mozilla/5.0 (iPhone; CPU iPhone OS 17_0 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.0 Mobile/15E148 Safari/604.1",
    "Googlebot/2.1 (+http://www.google.com/bot.html)",
]

_XFF_POOL = [
    "1.1.1.1", "8.8.8.8", "127.0.0.1", "10.0.0.1", "192.168.1.1",
    "172.16.0.1", "203.0.113.1",
]


def random_headers() -> Dict[str, str]:
    return {
        "User-Agent":       random.choice(_UA_POOL),
        "X-Forwarded-For":  random.choice(_XFF_POOL),
        "X-Real-IP":        random.choice(_XFF_POOL),
        "Accept-Language":  random.choice(["en-US,en;q=0.9", "en-GB,en;q=0.8", "fr-FR,fr;q=0.7"]),
        "Accept-Encoding":  "gzip, deflate, br",
    }


# ---------------------------------------------------------------------------
# Detection engine
# ---------------------------------------------------------------------------

class WAFDetectionEngine:
    """
    Detect WAF from HTTP response headers + status codes.
    Returns a WAFProfile with adapted scan configuration.
    """

    def __init__(self, timeout: int = 8):
        self._timeout = timeout

    def detect(self, target_url: str) -> WAFProfile:
        """
        Send a probe request and analyse headers to detect WAF.
        Also sends a known-bad request (SQLi string) to see if it gets blocked.
        """
        profile = WAFProfile()

        try:
            # Normal probe
            r = requests.get(
                target_url, timeout=self._timeout,
                headers=random_headers(),
                allow_redirects=True,
                verify=False,
            )
            profile.raw_headers = dict(r.headers)
            profile = self._analyze_headers(r, profile)

            # Active probe: known-bad request (safe — just a string in a GET param)
            if not profile.detected:
                bad_url = target_url + ("&" if "?" in target_url else "?") + "q=1' OR '1'='1"
                r2 = requests.get(
                    bad_url, timeout=self._timeout,
                    headers=random_headers(),
                    allow_redirects=False,
                )
                if r2.status_code in _BLOCK_STATUS_CODES:
                    profile.detected       = True
                    profile.block_status_seen = True
                    profile.evidence      = f"Bad-request probe returned HTTP {r2.status_code}"
                    profile.waf_name      = profile.waf_name or "Unknown WAF"

        except requests.exceptions.RequestException as exc:
            log.warning("WAF probe failed for %s: %s", target_url, exc)

        self._apply_recommendations(profile)
        return profile

    def detect_from_headers(self, headers: Dict[str, str], status_code: int = 200) -> WAFProfile:
        """Analyse pre-collected headers (useful when running inside a pipeline)."""
        profile = WAFProfile(raw_headers=headers)

        h_lower = {k.lower(): v.lower() for k, v in headers.items()}
        for waf_name, header_name, value_pattern in _WAF_SIGNATURES:
            if header_name in h_lower:
                header_val = h_lower[header_name]
                if not value_pattern or value_pattern in header_val:
                    profile.detected  = True
                    profile.waf_name  = waf_name
                    profile.evidence  = f"Header '{header_name}': '{header_val}'"
                    break

        if status_code in _BLOCK_STATUS_CODES:
            profile.block_status_seen = True
            if not profile.detected:
                profile.detected  = True
                profile.waf_name  = "Unknown WAF"
                profile.evidence  = f"Block status code: {status_code}"

        self._apply_recommendations(profile)
        return profile

    def _analyze_headers(self, response: requests.Response, profile: WAFProfile) -> WAFProfile:
        h_lower = {k.lower(): v.lower() for k, v in response.headers.items()}
        for waf_name, header_name, value_pattern in _WAF_SIGNATURES:
            if header_name in h_lower:
                header_val = h_lower[header_name]
                if not value_pattern or value_pattern in header_val:
                    profile.detected  = True
                    profile.waf_name  = waf_name
                    profile.evidence  = f"Header '{header_name}': '{h_lower[header_name]}'"
                    break

        if response.status_code in _BLOCK_STATUS_CODES:
            profile.block_status_seen = True
            if not profile.detected:
                profile.detected  = True
                profile.waf_name  = "Unknown WAF"
                profile.evidence  = f"Block HTTP {response.status_code}"

        return profile

    def _apply_recommendations(self, profile: WAFProfile) -> None:
        """Set recommended scan parameters based on WAF profile."""
        if not profile.detected:
            profile.recommended_rps = 10.0
            profile.jitter_ms       = 0
            profile.rotate_headers  = False
            profile.passive_only    = False
            return

        waf = profile.waf_name.lower()

        if "cloudflare" in waf:
            # Cloudflare is aggressive — use low rate + heavy jitter
            profile.recommended_rps = 2.0
            profile.jitter_ms       = random.randint(800, 2000)
            profile.rotate_headers  = True
            profile.passive_only    = profile.block_status_seen

        elif "akamai" in waf:
            profile.recommended_rps = 3.0
            profile.jitter_ms       = random.randint(500, 1500)
            profile.rotate_headers  = True
            profile.passive_only    = False

        elif "aws" in waf:
            profile.recommended_rps = 4.0
            profile.jitter_ms       = random.randint(300, 800)
            profile.rotate_headers  = True
            profile.passive_only    = False

        elif "modsecurity" in waf or "mod_security" in waf:
            profile.recommended_rps = 5.0
            profile.jitter_ms       = random.randint(200, 600)
            profile.rotate_headers  = False
            profile.passive_only    = False

        else:  # Generic unknown WAF
            profile.recommended_rps = 3.0
            profile.jitter_ms       = random.randint(500, 1000)
            profile.rotate_headers  = True
            profile.passive_only    = profile.block_status_seen

        log.info(
            "WAF detected: %s | rps=%.1f | jitter=%dms | passive=%s",
            profile.waf_name, profile.recommended_rps,
            profile.jitter_ms, profile.passive_only,
        )


def detect_waf(target_url: str) -> WAFProfile:
    """Convenience function."""
    engine = WAFDetectionEngine()
    return engine.detect(target_url)
