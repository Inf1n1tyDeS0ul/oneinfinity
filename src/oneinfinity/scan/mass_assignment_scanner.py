"""
mass_assignment_scanner.py — Detects mass assignment, BOLA/IDOR, and API
version privilege-escalation vulnerabilities in REST APIs.

Three independent attack vectors:

1. Mass assignment — PUT/PATCH with injected privileged fields; compare
   GET before/after to detect server-side application of injected values.
2. API versioning — probe lower/dev versions of every discovered path and
   compare response size/field counts. Larger older responses often expose
   more data than the current version.
3. BOLA/IDOR — replace numeric IDs, UUIDs, and common username fields in
   URL paths with alternative values and detect cross-object data access.
"""
from __future__ import annotations

import asyncio
import hashlib
import json
import logging
import re
import ssl
import time
import urllib.error
import urllib.parse
import urllib.request
from typing import Any

log = logging.getLogger("oneinfinity.mass_assignment_scanner")

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

# Fields commonly omitted from API docs but accepted by frameworks that bind
# all JSON keys to ORM objects (Rails strong params bypass, Django rest
# framework writable fields, Laravel Eloquent fillable misconfig, etc.).
INJECTION_FIELDS: list[str] = [
    "admin",
    "is_admin",
    "role",
    "user_id",
    "owner_id",
    "price",
    "discount",
    "balance",
    "verified",
    "approved",
    "permissions",
    "scopes",
    "account_type",
    "internal_id",
    "is_staff",
    "is_superuser",
    "group",
    "credit",
    "loyalty_points",
    "enabled",
    "active",
    "subscription_tier",
    "plan",
    "access_level",
]

# Versioned path prefixes to try (oldest / dev first so downgrade is clear).
_VERSION_PREFIXES: list[str] = [
    "/api-internal",
    "/api-dev",
    "/api/internal",
    "/api/dev",
    "/v1",
    "/v2",
    "/v3",
    "/api/v1",
    "/api/v2",
    "/api/v3",
    "/api/v4",
    "/api/v5",
]

# Sentinel injection values that should never legitimately round-trip.
_INJECT_SENTINEL_BOOL = True
_INJECT_SENTINEL_INT = 9999999
_INJECT_SENTINEL_STR = "oi_mass_assign_probe"

# ID patterns for BOLA — numeric, UUID, and slug in path segments.
_RE_NUMERIC_ID = re.compile(r"(?<![a-zA-Z_])(\d{1,12})(?![a-zA-Z_])")
_RE_UUID = re.compile(
    r"[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}",
    re.IGNORECASE,
)

_DEFAULT_ALT_IDS: list[str] = ["1", "2", "100", "0", "9999"]


# ---------------------------------------------------------------------------
# Low-level HTTP helpers (sync, threadpool-friendly)
# ---------------------------------------------------------------------------

def _ssl_ctx() -> ssl.SSLContext:
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    return ctx


def _http(
    url: str,
    method: str = "GET",
    body: bytes | None = None,
    headers: dict | None = None,
    timeout: int = 10,
) -> tuple[int, bytes, dict]:
    """Return (status, body_bytes, response_headers).  Never raises."""
    try:
        req = urllib.request.Request(
            url,
            data=body,
            method=method.upper(),
            headers={
                "User-Agent": "Mozilla/5.0 (OneInfinity/2.0; MassAssignScanner)",
                "Accept": "application/json, */*",
                **(headers or {}),
            },
        )
        if body and "Content-Type" not in req.headers:
            req.add_header("Content-Type", "application/json")
        with urllib.request.urlopen(req, timeout=timeout, context=_ssl_ctx()) as resp:
            return resp.status, resp.read(512_000), dict(resp.headers)
    except urllib.error.HTTPError as exc:
        try:
            return exc.code, exc.read(512_000), dict(exc.headers)
        except Exception:
            return exc.code, b"", {}
    except Exception:
        return 0, b"", {}


def _json_body(data: dict) -> bytes:
    return json.dumps(data, separators=(",", ":")).encode()


def _try_parse(raw: bytes) -> Any:
    try:
        return json.loads(raw)
    except Exception:
        return None


def _fid(prefix: str, url: str) -> str:
    return hashlib.md5(f"{prefix}:{url}".encode()).hexdigest()[:16]


# ---------------------------------------------------------------------------
# MassAssignmentScanner
# ---------------------------------------------------------------------------

class MassAssignmentScanner:
    """
    Async scanner for mass assignment, API version privilege escalation,
    and BOLA/IDOR vulnerabilities.

    All public methods are coroutines that return a list of finding dicts
    compatible with the OneInfinity finding schema.
    """

    def __init__(
        self,
        timeout: int = 10,
        rate_limit: float = 0.3,
        max_bola_ids: int = 5,
    ) -> None:
        self._timeout = timeout
        self._rate_limit = rate_limit  # seconds between requests per endpoint
        self._max_bola_ids = max_bola_ids
        self._loop = None

    # ------------------------------------------------------------------
    # 1. Mass assignment
    # ------------------------------------------------------------------

    async def test_endpoint(
        self,
        url: str,
        method: str = "PUT",
        auth_headers: dict | None = None,
    ) -> list[dict]:
        """
        Test a single REST resource URL for mass assignment.

        Flow:
          1. GET the resource to capture its current field set and values.
          2. PUT/PATCH with legitimate body + injected privileged fields.
          3. GET again and compare — any newly-applied injected field is a
             confirmed mass assignment vulnerability.
        """
        findings: list[dict] = []
        loop = asyncio.get_event_loop()
        hdrs = dict(auth_headers or {})

        # Step 1 — baseline GET
        status_before, raw_before, _ = await loop.run_in_executor(
            None, _http, url, "GET", None, hdrs, self._timeout
        )
        if status_before not in range(200, 300):
            return findings
        obj_before = _try_parse(raw_before)
        if not isinstance(obj_before, dict):
            return findings

        await asyncio.sleep(self._rate_limit)

        # Step 2 — mutated PUT/PATCH: copy existing body + inject probe fields
        injected: dict[str, Any] = {}
        for field in INJECTION_FIELDS:
            # Infer sentinel type from existing field if present
            existing = obj_before.get(field)
            if isinstance(existing, bool):
                injected[field] = not existing       # flip booleans
            elif isinstance(existing, (int, float)):
                injected[field] = _INJECT_SENTINEL_INT
            else:
                injected[field] = _INJECT_SENTINEL_BOOL  # try bool on unknown

        probe_body: dict = {**obj_before, **injected}
        probe_hdrs = {**hdrs, "Content-Type": "application/json"}

        status_put, _, _ = await loop.run_in_executor(
            None, _http, url, method.upper(),
            _json_body(probe_body), probe_hdrs, self._timeout
        )

        await asyncio.sleep(self._rate_limit)

        # Step 3 — re-GET and compare
        status_after, raw_after, _ = await loop.run_in_executor(
            None, _http, url, "GET", None, hdrs, self._timeout
        )
        if status_after not in range(200, 300):
            return findings
        obj_after = _try_parse(raw_after)
        if not isinstance(obj_after, dict):
            return findings

        changed: list[str] = []
        for field, probe_val in injected.items():
            after_val = obj_after.get(field)
            before_val = obj_before.get(field)
            if after_val is not None and after_val != before_val:
                changed.append(
                    f"{field}: {before_val!r} → {after_val!r}"
                )

        for change in changed:
            field_name = change.split(":")[0].strip()
            findings.append({
                "id": _fid("mass_assign", f"{url}:{field_name}"),
                "vuln_type": "mass_assignment",
                "severity": "high",
                "title": f"Mass Assignment — {field_name} writable at {url}",
                "url": url,
                "method": method.upper(),
                "evidence": change,
                "tool": "mass_assignment_scanner",
                "description": (
                    f"Server accepted and persisted injected field '{field_name}' "
                    f"via {method.upper()} {url}. An attacker can elevate privileges "
                    f"or manipulate business-critical values by including this field "
                    f"in write requests."
                ),
                "remediation": (
                    "Explicitly allowlist writable fields in your serializer/model. "
                    "Never bind the entire request body to a database object."
                ),
                "timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
            })

        if changed:
            log.info(
                "[MassAssign] %s %s → %d changed field(s): %s",
                method.upper(), url, len(changed), changed,
            )

        return findings

    # ------------------------------------------------------------------
    # 2. API version privilege escalation
    # ------------------------------------------------------------------

    async def test_api_versioning(
        self,
        base_url: str,
        auth_headers: dict | None = None,
    ) -> list[dict]:
        """
        Probe lower/dev/internal API version prefixes and compare response
        richness against the current version.

        A finding is emitted when an older/internal version returns:
          - More JSON keys (additional data fields exposed)
          - Larger body (raw byte count significantly larger)
          - A 200 where the current canonical path returns 401/403/404
        """
        findings: list[dict] = []
        loop = asyncio.get_event_loop()
        hdrs = dict(auth_headers or {})
        base = base_url.rstrip("/")

        # Canonical baseline — try to get the current resource
        status_canon, raw_canon, _ = await loop.run_in_executor(
            None, _http, base, "GET", None, hdrs, self._timeout
        )
        canon_fields = len(_try_parse(raw_canon) or {}) if isinstance(_try_parse(raw_canon), dict) else 0
        canon_len = len(raw_canon)

        await asyncio.sleep(self._rate_limit)

        # Extract path suffix to re-graft under each version prefix
        parsed = urllib.parse.urlparse(base)
        path = parsed.path  # e.g. /api/v3/users/me

        # Strip any existing version segment so we can prepend alternatives
        _RE_VERSION_SEG = re.compile(
            r"^(/api)?/(v\d+|internal|dev)(/.*)?$", re.IGNORECASE
        )
        m = _RE_VERSION_SEG.match(path)
        resource_suffix = m.group(3) or "/" if m else path

        for ver_prefix in _VERSION_PREFIXES:
            alt_path = ver_prefix + resource_suffix
            alt_url = urllib.parse.urlunparse(parsed._replace(path=alt_path))

            if alt_url == base:
                continue

            await asyncio.sleep(self._rate_limit)
            status_alt, raw_alt, _ = await loop.run_in_executor(
                None, _http, alt_url, "GET", None, hdrs, self._timeout
            )

            if status_alt not in range(200, 300):
                continue

            alt_obj = _try_parse(raw_alt)
            alt_fields = len(alt_obj) if isinstance(alt_obj, dict) else 0
            alt_len = len(raw_alt)

            # Flag if alternative returns significantly more data
            field_diff = alt_fields - canon_fields
            byte_diff = alt_len - canon_len
            privileged_upgrade = (
                status_canon in (401, 403, 404) and status_alt == 200
            )

            if field_diff > 2 or byte_diff > 512 or privileged_upgrade:
                evidence_parts = []
                if field_diff > 0:
                    evidence_parts.append(f"+{field_diff} extra JSON fields")
                if byte_diff > 0:
                    evidence_parts.append(f"+{byte_diff} bytes")
                if privileged_upgrade:
                    evidence_parts.append(
                        f"canon returned {status_canon}, alt returned {status_alt}"
                    )

                findings.append({
                    "id": _fid("api_ver_priv", alt_url),
                    "vuln_type": "api_version_privilege_escalation",
                    "severity": "high" if privileged_upgrade else "medium",
                    "title": f"API Version Privilege Escalation — {ver_prefix} exposes more data",
                    "url": alt_url,
                    "canonical_url": base,
                    "method": "GET",
                    "evidence": "; ".join(evidence_parts),
                    "tool": "mass_assignment_scanner",
                    "description": (
                        f"API path {alt_url} returns richer data than the current "
                        f"version at {base}. Older/internal versions may bypass "
                        f"access controls or expose sensitive fields stripped from "
                        f"the current version."
                    ),
                    "remediation": (
                        "Retire legacy API versions or enforce identical access "
                        "controls across all version prefixes."
                    ),
                    "timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
                })
                log.info(
                    "[APIVersionPriv] %s → %s (%s)",
                    base, alt_url, "; ".join(evidence_parts),
                )

        return findings

    # ------------------------------------------------------------------
    # 3. BOLA / IDOR
    # ------------------------------------------------------------------

    async def test_bola(
        self,
        url: str,
        resource_id: str,
        alt_ids: list[str] | None = None,
        auth_headers: dict | None = None,
    ) -> list[dict]:
        """
        Test for Broken Object Level Authorization (BOLA/IDOR).

        Replaces every occurrence of *resource_id* in the URL path with
        alternative IDs and checks whether a different resource is returned
        with a 200 status (indicating missing owner check).
        """
        findings: list[dict] = []
        loop = asyncio.get_event_loop()
        hdrs = dict(auth_headers or {})
        probes = (alt_ids or _DEFAULT_ALT_IDS)[:self._max_bola_ids]

        # Baseline: fetch own resource so we know what "owner match" looks like
        status_own, raw_own, _ = await loop.run_in_executor(
            None, _http, url, "GET", None, hdrs, self._timeout
        )
        own_obj = _try_parse(raw_own)

        await asyncio.sleep(self._rate_limit)

        for alt_id in probes:
            if alt_id == resource_id:
                continue

            # Replace all occurrences of the original ID in the URL path
            alt_url = url.replace(resource_id, alt_id)
            if alt_url == url:
                continue

            await asyncio.sleep(self._rate_limit)
            status_alt, raw_alt, _ = await loop.run_in_executor(
                None, _http, alt_url, "GET", None, hdrs, self._timeout
            )

            if status_alt not in range(200, 300):
                continue

            alt_obj = _try_parse(raw_alt)

            # Confirm it's a different object (not redirected back to own resource)
            different = (raw_alt != raw_own)

            if not different:
                continue

            # Check if response contains the alt_id itself (confirms it's another object)
            body_str = raw_alt.decode("utf-8", errors="replace")
            id_present = alt_id in body_str

            severity = "critical" if id_present else "medium"
            evidence = (
                f"GET {alt_url} returned HTTP {status_alt} with different body "
                f"({'contains alt ID' if id_present else 'body differs from own resource'})"
            )

            findings.append({
                "id": _fid("bola_idor", alt_url),
                "vuln_type": "bola_idor",
                "severity": severity,
                "title": f"BOLA/IDOR — Unauthorised access to resource {alt_id}",
                "url": alt_url,
                "original_url": url,
                "method": "GET",
                "evidence": evidence,
                "original_id": resource_id,
                "tested_id": alt_id,
                "tool": "mass_assignment_scanner",
                "description": (
                    f"Accessing {alt_url} (resource ID {alt_id!r}) with the current "
                    f"session's credentials returned HTTP {status_alt} and a response "
                    f"body that differs from the authenticated user's own resource. "
                    f"The server does not enforce object-level ownership checks."
                ),
                "remediation": (
                    "Verify object ownership on every data-access operation using the "
                    "authenticated session's identity, not a client-supplied ID alone."
                ),
                "timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
            })
            log.info("[BOLA] %s → %s HTTP %d", url, alt_url, status_alt)

        return findings

    # ------------------------------------------------------------------
    # Auto-ID extraction helper
    # ------------------------------------------------------------------

    @staticmethod
    def _extract_ids_from_url(url: str) -> list[str]:
        """Return numeric IDs and UUIDs visible in the URL path."""
        parsed = urllib.parse.urlparse(url)
        ids: list[str] = []
        for seg in parsed.path.split("/"):
            if _RE_NUMERIC_ID.fullmatch(seg):
                ids.append(seg)
            elif _RE_UUID.fullmatch(seg):
                ids.append(seg)
        return ids

    # ------------------------------------------------------------------
    # 4. Coordinated scan entry-point
    # ------------------------------------------------------------------

    async def scan(
        self,
        target: str,
        urls: list[str] | None = None,
        auth_headers: dict | None = None,
    ) -> list[dict]:
        """
        Run all three attack vectors against the target.

        Args:
            target:       Base URL of the target application.
            urls:         Additional resource URLs discovered during recon.
            auth_headers: HTTP headers carrying a valid session token.

        Returns:
            Deduplicated list of finding dicts.
        """
        findings: list[dict] = []
        base = target.rstrip("/")
        all_urls = list(dict.fromkeys([base] + (urls or [])))

        # ── Vector 1: Mass assignment on PUT/PATCH-able endpoints ───────────
        put_patch_urls = [
            u for u in all_urls
            if any(
                seg in u.lower()
                for seg in ["/user", "/account", "/profile", "/me", "/settings",
                            "/order", "/product", "/payment", "/transfer"]
            )
        ]
        # Also probe top-level target with generic resource IDs
        if not put_patch_urls:
            put_patch_urls = [base]

        for u in put_patch_urls[:10]:
            for method in ("PUT", "PATCH"):
                try:
                    f = await self.test_endpoint(u, method=method, auth_headers=auth_headers)
                    findings.extend(f)
                except Exception as exc:
                    log.debug("mass_assign test_endpoint failed %s %s: %s", method, u, exc)

        # ── Vector 2: API version privilege escalation ──────────────────────
        versioned_urls = [
            u for u in all_urls
            if re.search(r"/v\d+/|/api/", u, re.IGNORECASE)
        ] or [base]

        for u in versioned_urls[:5]:
            try:
                f = await self.test_api_versioning(u, auth_headers=auth_headers)
                findings.extend(f)
            except Exception as exc:
                log.debug("api_versioning failed %s: %s", u, exc)

        # ── Vector 3: BOLA/IDOR on URLs containing IDs ──────────────────────
        for u in all_urls[:50]:
            ids = self._extract_ids_from_url(u)
            for rid in ids[:1]:  # one representative ID per URL
                try:
                    f = await self.test_bola(u, resource_id=rid, auth_headers=auth_headers)
                    findings.extend(f)
                except Exception as exc:
                    log.debug("bola test failed %s: %s", u, exc)

        # Deduplicate by finding ID
        seen: set[str] = set()
        deduped: list[dict] = []
        for fnd in findings:
            fid = fnd.get("id", "")
            if fid not in seen:
                seen.add(fid)
                deduped.append(fnd)

        log.info(
            "[MassAssignmentScanner] scan complete: %d findings for %s",
            len(deduped), target,
        )
        return deduped
