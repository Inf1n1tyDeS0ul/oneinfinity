"""
target_classifier.py — Classify scan targets to select the right recon strategy.
"""
from __future__ import annotations
import ipaddress
import re

class TargetProfile:
    INTERNET_DOMAIN  = "internet_domain"   # public DNS, OSINT history exists
    INTERNAL_HOST    = "internal_host"     # RFC1918, .local, .internal
    LOCAL_PORT       = "local_port"        # localhost / 127.x.x.x with explicit port
    API_ENDPOINT     = "api_endpoint"      # URL with /api/ prefix or JSON content-type

def classify(target: str) -> str:
    """
    Classify a scan target string into a TargetProfile.
    target may be: 'example.com', 'localhost:8888', '192.168.1.1', 'http://localhost:3000/api/'
    Returns one of TargetProfile.* constants.
    """
    # Strip scheme
    raw = target.lower().strip()
    for scheme in ("https://", "http://"):
        if raw.startswith(scheme):
            raw = raw[len(scheme):]
    # Strip path
    raw_host = raw.split("/")[0]  # e.g. "localhost:8888"
    host = raw_host.split(":")[0]  # e.g. "localhost"

    # API endpoint detection (path-based)
    path = "/" + "/".join(raw.split("/")[1:]) if "/" in raw else "/"
    if any(p in path for p in ("/api/", "/graphql", "/rest/", "/v1/", "/v2/", "/v3/")):
        return TargetProfile.API_ENDPOINT

    # Localhost detection
    if host in ("localhost", "127.0.0.1", "::1") or host.endswith(".localhost"):
        return TargetProfile.LOCAL_PORT

    # IP address detection
    try:
        addr = ipaddress.ip_address(host)
        if addr.is_loopback:
            return TargetProfile.LOCAL_PORT
        if addr.is_private:
            return TargetProfile.INTERNAL_HOST
    except ValueError:
        pass

    # Internal TLD detection
    internal_tlds = (".local", ".internal", ".test", ".example", ".corp", ".home", ".lan", ".intranet")
    if any(host.endswith(t) for t in internal_tlds):
        return TargetProfile.INTERNAL_HOST

    # Private hostname patterns
    if re.match(r'^(dev|staging|test|uat|local|internal|vpn|corp)[-.]', host):
        return TargetProfile.INTERNAL_HOST

    return TargetProfile.INTERNET_DOMAIN


def is_local_target(profile: str) -> bool:
    """Return True if target is localhost or RFC1918 — needs HTTP-first probing."""
    return profile in (TargetProfile.LOCAL_PORT, TargetProfile.INTERNAL_HOST)
