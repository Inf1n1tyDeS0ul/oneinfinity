"""
Deduplicator — fingerprint-based finding deduplication.

Prevents duplicate vulnerability reports from flooding reports when the
same issue is found by multiple tools (e.g. dalfox + nuclei both find XSS
on the same endpoint/parameter).

Fingerprint strategy:
  1. Normalize URL (strip fragment, sort query params alphabetically)
  2. Canonicalize vuln type (aliases collapsed: "reflected xss" → "xss")
  3. SHA-256(vuln_type + normalized_url + parameter_name)

Usage:
    dedup = Deduplicator()
    for finding in raw_findings:
        if dedup.is_new(finding):
            dedup.add(finding)
            unique_findings.append(finding)
"""

from __future__ import annotations

import hashlib
import logging
import re
from typing import Any, Dict, List, Optional, Set
from urllib.parse import parse_qsl, urlencode, urlparse, urlunparse

log = logging.getLogger(__name__)

# Canonical vuln type aliases
_VULN_ALIASES: Dict[str, str] = {
    # XSS
    "reflected xss": "xss",
    "reflected cross-site scripting": "xss",
    "stored xss": "stored_xss",
    "stored cross-site scripting": "stored_xss",
    "dom xss": "dom_xss",
    "dom-based xss": "dom_xss",
    "cross-site scripting": "xss",
    "cross site scripting": "xss",
    # SQLi
    "sql injection": "sqli",
    "sql-injection": "sqli",
    "blind sql injection": "sqli_blind",
    "time-based blind sql injection": "sqli_time",
    "error-based sql injection": "sqli_error",
    # SSRF
    "server-side request forgery": "ssrf",
    "server side request forgery": "ssrf",
    # LFI/RFI
    "local file inclusion": "lfi",
    "local file read": "lfi",
    "remote file inclusion": "rfi",
    "path traversal": "lfi",
    "directory traversal": "lfi",
    # IDOR
    "insecure direct object reference": "idor",
    "insecure direct object references": "idor",
    # SSTI
    "server-side template injection": "ssti",
    "server side template injection": "ssti",
    # Open Redirect
    "open redirect": "open_redirect",
    "url redirection": "open_redirect",
    "open redirection": "open_redirect",
    # CRLF
    "crlf injection": "crlf",
    "http header injection": "crlf",
    # Auth
    "broken access control": "bac",
    "access control": "bac",
    "privilege escalation": "privesc",
    "authentication bypass": "auth_bypass",
    "authorization bypass": "auth_bypass",
    # Misc
    "rce": "rce",
    "remote code execution": "rce",
    "command injection": "cmdi",
    "os command injection": "cmdi",
    "xxe": "xxe",
    "xml external entity": "xxe",
    "csrf": "csrf",
    "cross-site request forgery": "csrf",
    "cors misconfiguration": "cors",
    "cors": "cors",
    "mass assignment": "mass_assignment",
    "idor": "idor",
    "ssrf": "ssrf",
    "lfi": "lfi",
    "xss": "xss",
    "sqli": "sqli",
    "sqli_blind": "sqli_blind",
}


def _canonical_vuln_type(vuln_type: str) -> str:
    return _VULN_ALIASES.get(vuln_type.lower().strip(), vuln_type.lower().strip())


def _normalize_url(url: str) -> str:
    """Sort query parameters to ensure consistent URL fingerprinting."""
    try:
        parsed = urlparse(url)
        params = sorted(parse_qsl(parsed.query, keep_blank_values=True))
        normalized = urlunparse((
            parsed.scheme.lower(),
            parsed.netloc.lower(),
            parsed.path,
            parsed.params,
            urlencode(params),
            "",  # strip fragment
        ))
        return normalized
    except Exception:
        return url.lower().strip()


def _make_fingerprint(
    vuln_type: str,
    url: str,
    parameter: str = "",
    extra: str = "",
) -> str:
    canonical_type = _canonical_vuln_type(vuln_type)
    canonical_url = _normalize_url(url)
    canonical_param = parameter.strip().lower()
    raw = f"{canonical_type}::{canonical_url}::{canonical_param}::{extra}"
    return hashlib.sha256(raw.encode()).hexdigest()[:16]


class Deduplicator:
    """
    Tracks fingerprints of seen findings and filters duplicates.

    Supports soft dedup (same fingerprint = duplicate) and
    near-dedup (same endpoint + vuln type, different parameter = related).
    """

    def __init__(self) -> None:
        self._seen: Set[str] = set()
        self._endpoint_vuln: Set[str] = set()  # endpoint+vuln without param
        self._findings: List[Dict[str, Any]] = []

    # ------------------------------------------------------------------ #
    #  Core API
    # ------------------------------------------------------------------ #

    def is_new(self, finding: Dict[str, Any]) -> bool:
        """Return True if this finding has not been seen before."""
        fp = self._fingerprint(finding)
        return fp not in self._seen

    def add(self, finding: Dict[str, Any]) -> str:
        """Record a finding. Returns the fingerprint."""
        fp = self._fingerprint(finding)
        self._seen.add(fp)
        ev = self._endpoint_vuln_key(finding)
        self._endpoint_vuln.add(ev)
        self._findings.append({**finding, "_fingerprint": fp})
        return fp

    def filter_new(self, findings: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Return only new (unseen) findings from the list, adding them as seen."""
        result = []
        for f in findings:
            if self.is_new(f):
                self.add(f)
                result.append(f)
            else:
                log.debug("Duplicate finding skipped: %s @ %s", f.get("vuln_type"), f.get("url", f.get("endpoint")))
        return result

    def is_related(self, finding: Dict[str, Any]) -> bool:
        """
        True if same endpoint + vuln_type already has at least one finding
        (possibly with a different parameter).
        """
        ev = self._endpoint_vuln_key(finding)
        return ev in self._endpoint_vuln

    def reset(self) -> None:
        self._seen.clear()
        self._endpoint_vuln.clear()
        self._findings.clear()

    # ------------------------------------------------------------------ #
    #  Stats
    # ------------------------------------------------------------------ #

    def stats(self) -> dict:
        return {
            "unique": len(self._findings),
            "fingerprints": len(self._seen),
        }

    def list_unique(self) -> List[Dict[str, Any]]:
        return list(self._findings)

    # ------------------------------------------------------------------ #
    #  Internals
    # ------------------------------------------------------------------ #

    def _fingerprint(self, finding: Dict[str, Any]) -> str:
        vuln_type = finding.get("vuln_type") or finding.get("type") or finding.get("name") or "unknown"
        url = finding.get("url") or finding.get("endpoint") or ""
        parameter = finding.get("parameter") or finding.get("param") or ""
        extra = finding.get("tool") or ""
        return _make_fingerprint(str(vuln_type), str(url), str(parameter), str(extra))

    def _endpoint_vuln_key(self, finding: Dict[str, Any]) -> str:
        vuln_type = finding.get("vuln_type") or finding.get("type") or finding.get("name") or "unknown"
        url = finding.get("url") or finding.get("endpoint") or ""
        canonical_type = _canonical_vuln_type(str(vuln_type))
        canonical_url = _normalize_url(str(url))
        raw = f"{canonical_type}::{canonical_url}"
        return hashlib.sha256(raw.encode()).hexdigest()[:16]
