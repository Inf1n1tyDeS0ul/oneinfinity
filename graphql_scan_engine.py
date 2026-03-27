"""
graphql_scan_engine.py — GraphQL Security Scanner for OneInfinity

Probes GraphQL endpoints for common vulnerabilities including:
  - Introspection exposure
  - Deep query nesting attacks (DoS)
  - Batch query abuse
  - Null coercion / type confusion
  - Mutation fuzzing with malformed inputs
  - IDOR via sequential ID enumeration

Usage::

    engine = GraphQLScanEngine("https://example.com", output_dir="/tmp/out")
    findings = engine.run()
    for f in findings:
        print(f["vuln_type"], f["severity"], f["url"])
"""

from __future__ import annotations

import json
import logging
import uuid
from typing import Any, Dict, List, Optional
from urllib.parse import urljoin, urlparse

import requests
import urllib3

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

log = logging.getLogger("oi.graphql_scan_engine")

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

_COMMON_PATHS = [
    "/graphql",
    "/api/graphql",
    "/v1/graphql",
    "/graphql/v1",
    "/api",
    "/graphql/console",
    "/graphiql",
    "/playground",
    "/api/v1/graphql",
    "/query",
]

_INTROSPECTION_QUERY = """
query IntrospectionQuery {
  __schema {
    queryType { name }
    mutationType { name }
    subscriptionType { name }
    types {
      name
      kind
      fields {
        name
        args { name type { name kind ofType { name kind } } }
        type { name kind ofType { name kind } }
      }
    }
  }
}
"""

_DEFAULT_TIMEOUT = 10


# ---------------------------------------------------------------------------
# Helper
# ---------------------------------------------------------------------------

def _make_finding(
    vuln_type: str,
    severity: str,
    url: str,
    endpoint: str,
    payload: str,
    evidence: str,
    confidence: float,
    extra: Optional[dict] = None,
) -> dict:
    f = {
        "vuln_type": vuln_type,
        "severity": severity,
        "url": url,
        "endpoint": endpoint,
        "payload": payload,
        "evidence": evidence,
        "confidence": confidence,
        "tool": "graphql_scan_engine",
        "source_type": "tool",
        "finding_id": f"GQL-{uuid.uuid4().hex[:8].upper()}",
    }
    if extra:
        f.update(extra)
    return f


# ---------------------------------------------------------------------------
# Engine
# ---------------------------------------------------------------------------

class GraphQLScanEngine:
    """
    GraphQL-specific security scanner.

    Parameters
    ----------
    target : str
        Base URL of the target (e.g. "https://example.com").
    output_dir : str
        Directory where findings JSON will be written.
    """

    def __init__(self, target: str, output_dir: str = ".") -> None:
        self.target = target.rstrip("/")
        self.output_dir = output_dir
        self._session = requests.Session()
        self._session.verify = False
        self._session.headers.update({
            "Content-Type": "application/json",
            "Accept": "application/json",
            "User-Agent": "OneInfinity-GraphQL-Scanner/1.0",
        })
        # Named role sessions for auth-aware testing: role_name -> requests.Session
        self._auth_sessions: Dict[str, Any] = {}

    def set_auth_sessions(self, sessions: Dict[str, Any]) -> None:
        """
        Register named role sessions for auth-aware GraphQL testing.

        Parameters
        ----------
        sessions : dict
            Mapping of role_name -> requests.Session. Common keys:
            ``"unauthenticated"``, ``"user"``, ``"admin"``.
        """
        self._auth_sessions = dict(sessions)
        log.info("GraphQL auth sessions registered: %s", list(sessions.keys()))

    # ------------------------------------------------------------------ #
    # Endpoint discovery
    # ------------------------------------------------------------------ #

    def detect_endpoints(self) -> List[str]:
        """
        Probe common GraphQL path suffixes against the target.

        Returns a list of URLs that responded with HTTP 200 and a body
        that looks like GraphQL (contains 'data' or 'errors' or '__schema').
        """
        found: List[str] = []
        for path in _COMMON_PATHS:
            url = urljoin(self.target + "/", path.lstrip("/"))
            try:
                # Send a minimal introspection ping
                resp = self._session.post(
                    url,
                    json={"query": "{ __typename }"},
                    timeout=_DEFAULT_TIMEOUT,
                )
                body = resp.text.lower()
                if resp.status_code in (200, 400) and any(
                    kw in body for kw in ("__typename", "data", "errors", "graphql")
                ):
                    log.info("GraphQL endpoint found: %s (HTTP %d)", url, resp.status_code)
                    found.append(url)
            except requests.RequestException as exc:
                log.debug("Probe failed for %s: %s", url, exc)
        return found

    # ------------------------------------------------------------------ #
    # Introspection
    # ------------------------------------------------------------------ #

    def test_introspection(self, endpoint: str) -> dict:
        """
        Send a full introspection query to *endpoint*.

        Returns a dict with keys:
          - enabled (bool)
          - query_type (str)
          - mutation_type (str)
          - type_names (List[str])
          - raw_schema (dict)
          - finding (dict | None) — populated when introspection is exposed
        """
        result: dict = {
            "enabled": False,
            "query_type": None,
            "mutation_type": None,
            "type_names": [],
            "raw_schema": {},
            "finding": None,
        }
        try:
            resp = self._session.post(
                endpoint,
                json={"query": _INTROSPECTION_QUERY},
                timeout=_DEFAULT_TIMEOUT,
            )
            data = resp.json()
            schema = data.get("data", {}).get("__schema", {})
            if schema:
                result["enabled"] = True
                result["raw_schema"] = schema
                result["query_type"] = (schema.get("queryType") or {}).get("name")
                result["mutation_type"] = (schema.get("mutationType") or {}).get("name")
                result["type_names"] = [
                    t["name"] for t in schema.get("types", []) if t.get("name")
                ]
                result["finding"] = _make_finding(
                    vuln_type="graphql_introspection_enabled",
                    severity="medium",
                    url=endpoint,
                    endpoint=endpoint,
                    payload=_INTROSPECTION_QUERY.strip(),
                    evidence=(
                        f"Introspection returned {len(result['type_names'])} types. "
                        f"Query root: {result['query_type']}; "
                        f"Mutation root: {result['mutation_type']}"
                    ),
                    confidence=0.95,
                )
        except (requests.RequestException, ValueError, KeyError) as exc:
            log.debug("Introspection probe failed on %s: %s", endpoint, exc)
        return result

    # ------------------------------------------------------------------ #
    # Query fuzzing
    # ------------------------------------------------------------------ #

    def fuzz_queries(self, endpoint: str, schema: dict) -> List[dict]:
        """
        Send adversarial GraphQL queries:
          1. Deep nesting (10 levels)
          2. Batch queries (10 copies of the same operation)
          3. Null coercion (required field set to null)

        Returns a list of finding dicts.
        """
        findings: List[dict] = []

        # ---- 1. Deep nesting ----------------------------------------
        # Build a 10-level deep nested query; abusing types discovered via
        # introspection if available, otherwise use __schema nesting.
        query_type = (schema.get("queryType") or {}).get("name", "Query")
        type_names = [
            t["name"] for t in schema.get("types", [])
            if t.get("kind") == "OBJECT" and not t["name"].startswith("__")
        ]
        # Build synthetic deep-nesting using __schema (always available)
        nested = "{ __schema { types { fields { type { ofType { ofType { ofType { ofType { ofType { name kind } } } } } } } } } }"
        deep_payload = nested
        try:
            resp = self._session.post(
                endpoint,
                json={"query": deep_payload},
                timeout=_DEFAULT_TIMEOUT + 5,
            )
            body = resp.text
            if resp.elapsed.total_seconds() > 5 or "error" in body.lower():
                findings.append(_make_finding(
                    vuln_type="graphql_deep_nesting",
                    severity="medium",
                    url=endpoint,
                    endpoint=endpoint,
                    payload=deep_payload,
                    evidence=(
                        f"Deep nested query responded in "
                        f"{resp.elapsed.total_seconds():.2f}s "
                        f"(HTTP {resp.status_code})"
                    ),
                    confidence=0.65,
                ))
        except requests.RequestException as exc:
            log.debug("Deep nesting test failed on %s: %s", endpoint, exc)

        # ---- 2. Batch queries ----------------------------------------
        batch_payload = [{"query": "{ __typename }"}] * 10
        try:
            resp = self._session.post(
                endpoint,
                json=batch_payload,
                timeout=_DEFAULT_TIMEOUT,
            )
            if resp.status_code == 200:
                try:
                    body_json = resp.json()
                    if isinstance(body_json, list) and len(body_json) > 1:
                        findings.append(_make_finding(
                            vuln_type="graphql_batch_queries",
                            severity="medium",
                            url=endpoint,
                            endpoint=endpoint,
                            payload=json.dumps(batch_payload),
                            evidence=(
                                f"Server processed a batch of {len(body_json)} queries "
                                f"in a single request (HTTP 200)"
                            ),
                            confidence=0.85,
                        ))
                except ValueError:
                    pass
        except requests.RequestException as exc:
            log.debug("Batch query test failed on %s: %s", endpoint, exc)

        # ---- 3. Null coercion ----------------------------------------
        # Find a field that takes a non-nullable argument and send null
        null_payload = '{ __type(name: null) { name } }'
        try:
            resp = self._session.post(
                endpoint,
                json={"query": null_payload},
                timeout=_DEFAULT_TIMEOUT,
            )
            body = resp.text
            if resp.status_code == 200 and "errors" not in body.lower():
                # Server accepted null for a non-nullable argument
                findings.append(_make_finding(
                    vuln_type="graphql_null_coercion",
                    severity="low",
                    url=endpoint,
                    endpoint=endpoint,
                    payload=null_payload,
                    evidence=(
                        f"Server accepted null for non-nullable __type(name:) "
                        f"argument without error (HTTP {resp.status_code})"
                    ),
                    confidence=0.55,
                ))
        except requests.RequestException as exc:
            log.debug("Null coercion test failed on %s: %s", endpoint, exc)

        return findings

    # ------------------------------------------------------------------ #
    # Mutation testing
    # ------------------------------------------------------------------ #

    def test_mutations(self, endpoint: str, schema: dict) -> List[dict]:
        """
        Discover mutation fields via schema and fuzz them with empty /
        malformed inputs.

        Returns a list of finding dicts.
        """
        findings: List[dict] = []
        mutation_type_name = (schema.get("mutationType") or {}).get("name")
        if not mutation_type_name:
            log.debug("No mutation type found in schema for %s", endpoint)
            return findings

        # Extract mutation fields from the types list
        mutation_fields: List[dict] = []
        for t in schema.get("types", []):
            if t.get("name") == mutation_type_name:
                mutation_fields = t.get("fields") or []
                break

        if not mutation_fields:
            log.debug("No mutation fields resolved for type '%s'", mutation_type_name)
            return findings

        # Test up to 5 mutation fields to stay safe
        for field_def in mutation_fields[:5]:
            field_name = field_def.get("name", "")
            if not field_name:
                continue

            # 1. Empty input mutation
            empty_query = f"mutation {{ {field_name} }}"
            # 2. Malformed / injection input
            malformed_query = (
                f'mutation {{ {field_name}(input: {{id: "1 OR 1=1", '
                f'name: "<script>alert(1)</script>", email: "x@x.x"}}) }}'
            )

            for label, payload in [("empty", empty_query), ("malformed", malformed_query)]:
                try:
                    resp = self._session.post(
                        endpoint,
                        json={"query": payload},
                        timeout=_DEFAULT_TIMEOUT,
                    )
                    body = resp.text
                    # Flag if the mutation executed without authentication error
                    if resp.status_code == 200 and "data" in body.lower():
                        findings.append(_make_finding(
                            vuln_type="graphql_mutation_no_auth",
                            severity="high",
                            url=endpoint,
                            endpoint=endpoint,
                            payload=payload,
                            evidence=(
                                f"Mutation '{field_name}' with {label} input returned "
                                f"HTTP 200 with data response"
                            ),
                            confidence=0.70,
                        ))
                    # Flag SQL/NoSQL/XSS error leakage
                    error_patterns = ("syntax error", "sql", "exception", "traceback", "stacktrace")
                    if any(p in body.lower() for p in error_patterns):
                        findings.append(_make_finding(
                            vuln_type="graphql_mutation_error_leakage",
                            severity="medium",
                            url=endpoint,
                            endpoint=endpoint,
                            payload=payload,
                            evidence=f"Error details leaked in response to {label} mutation input",
                            confidence=0.75,
                        ))
                except requests.RequestException as exc:
                    log.debug("Mutation test failed for field '%s': %s", field_name, exc)

        return findings

    # ------------------------------------------------------------------ #
    # IDOR testing
    # ------------------------------------------------------------------ #

    def test_idor(self, endpoint: str, schema: dict) -> List[dict]:
        """
        Find ID-based query fields and probe them with sequential integer IDs
        to detect Insecure Direct Object Reference vulnerabilities.

        Returns a list of finding dicts.
        """
        findings: List[dict] = []

        # Look for query fields that accept an 'id' argument
        query_type_name = (schema.get("queryType") or {}).get("name")
        if not query_type_name:
            return findings

        id_fields: List[str] = []
        for t in schema.get("types", []):
            if t.get("name") == query_type_name:
                for f in t.get("fields") or []:
                    args = f.get("args") or []
                    for arg in args:
                        if arg.get("name", "").lower() == "id":
                            id_fields.append(f["name"])
                            break

        if not id_fields:
            log.debug("No ID-based query fields found at %s", endpoint)
            return findings

        for field_name in id_fields[:3]:
            # Try fetching IDs 1 and 2; if both return different data objects, flag IDOR
            responses: Dict[str, Any] = {}
            for test_id in ["1", "2", "999999"]:
                query = f'query {{ {field_name}(id: "{test_id}") }}'
                try:
                    resp = self._session.post(
                        endpoint,
                        json={"query": query},
                        timeout=_DEFAULT_TIMEOUT,
                    )
                    if resp.status_code == 200:
                        try:
                            responses[test_id] = resp.json()
                        except ValueError:
                            responses[test_id] = resp.text
                except requests.RequestException as exc:
                    log.debug("IDOR test failed for field '%s' id=%s: %s", field_name, test_id, exc)

            # If IDs 1 and 2 both returned data (not errors/null), flag potential IDOR
            data_1 = (responses.get("1") or {}).get("data", {})
            data_2 = (responses.get("2") or {}).get("data", {})
            errors_1 = (responses.get("1") or {}).get("errors")
            errors_2 = (responses.get("2") or {}).get("errors")

            if data_1 and data_2 and not errors_1 and not errors_2 and data_1 != data_2:
                findings.append(_make_finding(
                    vuln_type="graphql_idor",
                    severity="high",
                    url=endpoint,
                    endpoint=endpoint,
                    payload=f'query {{ {field_name}(id: "1") }} / (id: "2")',
                    evidence=(
                        f"Field '{field_name}' returned distinct data for IDs 1 and 2 "
                        f"without visible authorization enforcement"
                    ),
                    confidence=0.65,
                ))

        return findings

    # ------------------------------------------------------------------ #
    # Auth-aware comparison
    # ------------------------------------------------------------------ #

    def test_auth_comparison(self, endpoint: str, schema: dict) -> List[dict]:
        """
        Run the same introspection and top-level queries with each registered
        auth role and detect data that leaks to less-privileged roles.

        Requires roles to be set via :meth:`set_auth_sessions`.

        Returns a list of finding dicts.
        """
        findings: List[dict] = []
        if not self._auth_sessions:
            log.debug("No auth sessions registered; skipping auth comparison")
            return findings

        test_queries = [
            ("__schema check", "{ __schema { queryType { name } mutationType { name } } }"),
            ("__typename ping", "{ __typename }"),
        ]

        # Also pick up to 2 real query fields from schema
        query_type_name = (schema.get("queryType") or {}).get("name")
        if query_type_name:
            for t in schema.get("types", []):
                if t.get("name") == query_type_name:
                    for f in (t.get("fields") or [])[:2]:
                        fname = f.get("name", "")
                        if fname:
                            test_queries.append((fname, f"{{ {fname} }}"))
                    break

        for query_label, query in test_queries:
            role_results: Dict[str, dict] = {}

            # Default (unauthenticated) session
            try:
                resp = self._session.post(
                    endpoint,
                    json={"query": query},
                    timeout=_DEFAULT_TIMEOUT,
                )
                role_results["__default__"] = {
                    "status": resp.status_code,
                    "has_data": "data" in resp.text.lower(),
                    "has_error": "errors" in resp.text.lower(),
                    "body_len": len(resp.content),
                }
            except requests.RequestException:
                role_results["__default__"] = {"status": -1, "has_data": False, "has_error": True, "body_len": 0}

            # Named role sessions
            for role, sess in self._auth_sessions.items():
                try:
                    resp = sess.post(
                        endpoint,
                        json={"query": query},
                        timeout=_DEFAULT_TIMEOUT,
                    )
                    role_results[role] = {
                        "status": resp.status_code,
                        "has_data": "data" in resp.text.lower(),
                        "has_error": "errors" in resp.text.lower(),
                        "body_len": len(resp.content),
                    }
                except requests.RequestException:
                    role_results[role] = {"status": -1, "has_data": False, "has_error": True, "body_len": 0}

            # Detect privilege escalation: default/lower role sees data that only admins should
            default_data = role_results["__default__"]["has_data"]
            admin_data = role_results.get("admin", {}).get("has_data", False)

            if default_data and admin_data:
                # Both see data — flag if body lengths are similar (same data exposed)
                default_len = role_results["__default__"]["body_len"]
                admin_len = role_results.get("admin", {}).get("body_len", 0)
                if admin_len > 0 and abs(default_len - admin_len) < 50:
                    findings.append(_make_finding(
                        vuln_type="graphql_missing_auth",
                        severity="high",
                        url=endpoint,
                        endpoint=endpoint,
                        payload=query,
                        evidence=(
                            f"Query '{query_label}' returned similar data for "
                            f"unauthenticated and admin roles "
                            f"(len diff: {abs(default_len - admin_len)} bytes)"
                        ),
                        confidence=0.75,
                        extra={"role_results": role_results},
                    ))

            # Detect that an unprivileged user can access admin-only fields
            user_data = role_results.get("user", {}).get("has_data", False)
            if user_data and admin_data:
                user_len = role_results.get("user", {}).get("body_len", 0)
                admin_len = role_results.get("admin", {}).get("body_len", 0)
                if admin_len > 0 and abs(user_len - admin_len) < 50:
                    findings.append(_make_finding(
                        vuln_type="graphql_idor_auth_bypass",
                        severity="high",
                        url=endpoint,
                        endpoint=endpoint,
                        payload=query,
                        evidence=(
                            f"Query '{query_label}' returned similar data for "
                            f"user and admin roles (potential privilege escalation)"
                        ),
                        confidence=0.70,
                        extra={"role_results": role_results},
                    ))

        return findings

    # ------------------------------------------------------------------ #
    # Alias abuse
    # ------------------------------------------------------------------ #

    def test_alias_abuse(self, endpoint: str, schema: dict) -> List[dict]:
        """
        Test GraphQL alias abuse: send the same query with many aliases in a
        single request to bypass per-field rate limiting.

        Returns a list of finding dicts.
        """
        findings: List[dict] = []

        # Build a query with 20 aliased __typename fields
        alias_parts = "\n  ".join(f"q{i}: __typename" for i in range(20))
        alias_query = f"{{ {alias_parts} }}"

        try:
            resp = self._session.post(
                endpoint,
                json={"query": alias_query},
                timeout=_DEFAULT_TIMEOUT,
            )
            if resp.status_code == 200:
                try:
                    body = resp.json()
                    # Count how many aliased fields were returned
                    returned_aliases = [k for k in body.get("data", {}) if k.startswith("q")]
                    if len(returned_aliases) >= 10:
                        findings.append(_make_finding(
                            vuln_type="graphql_alias_abuse",
                            severity="medium",
                            url=endpoint,
                            endpoint=endpoint,
                            payload=alias_query,
                            evidence=(
                                f"Server processed {len(returned_aliases)} aliased queries "
                                f"in a single request — alias-based rate limiting bypass possible"
                            ),
                            confidence=0.80,
                        ))
                except ValueError:
                    pass
        except requests.RequestException as exc:
            log.debug("Alias abuse test failed on %s: %s", endpoint, exc)

        # Also try aliased mutations if mutation type exists
        mutation_type_name = (schema.get("mutationType") or {}).get("name")
        if mutation_type_name:
            for t in schema.get("types", []):
                if t.get("name") == mutation_type_name:
                    fields = t.get("fields") or []
                    if fields:
                        fname = fields[0].get("name", "")
                        if fname:
                            alias_mut = "\n  ".join(f"m{i}: {fname}" for i in range(5))
                            mut_query = f"mutation {{ {alias_mut} }}"
                            try:
                                resp = self._session.post(
                                    endpoint,
                                    json={"query": mut_query},
                                    timeout=_DEFAULT_TIMEOUT,
                                )
                                if resp.status_code == 200 and "data" in resp.text.lower():
                                    findings.append(_make_finding(
                                        vuln_type="graphql_alias_mutation_abuse",
                                        severity="high",
                                        url=endpoint,
                                        endpoint=endpoint,
                                        payload=mut_query,
                                        evidence=(
                                            f"Server processed 5 aliased mutations for '{fname}' "
                                            f"in one request (HTTP 200)"
                                        ),
                                        confidence=0.75,
                                    ))
                            except requests.RequestException as exc:
                                log.debug("Alias mutation test failed: %s", exc)
                    break

        return findings

    # ------------------------------------------------------------------ #
    # Fragment abuse
    # ------------------------------------------------------------------ #

    def test_fragment_abuse(self, endpoint: str, schema: dict) -> List[dict]:
        """
        Test fragment-based query complexity attacks:
          1. Deeply nested fragment chains
          2. Circular fragment references (should be rejected)
          3. Large field spread using fragments

        Returns a list of finding dicts.
        """
        findings: List[dict] = []

        # ---- 1. Fragment chain — nested spreads increasing complexity ----
        # Use __Schema and __Type which are always available
        fragment_chain = (
            "query FragChain { ...F1 }\n"
            "fragment F1 on Query { __typename ...F2 }\n"
            "fragment F2 on Query { __typename ...F3 }\n"
            "fragment F3 on Query { __typename ...F4 }\n"
            "fragment F4 on Query { __typename ...F5 }\n"
            "fragment F5 on Query { __typename }\n"
        )
        try:
            resp = self._session.post(
                endpoint,
                json={"query": fragment_chain},
                timeout=_DEFAULT_TIMEOUT,
            )
            elapsed = resp.elapsed.total_seconds() if hasattr(resp, "elapsed") else 0
            if resp.status_code == 200 and elapsed > 3:
                findings.append(_make_finding(
                    vuln_type="graphql_fragment_chain_dos",
                    severity="medium",
                    url=endpoint,
                    endpoint=endpoint,
                    payload=fragment_chain,
                    evidence=(
                        f"5-level fragment chain took {elapsed:.2f}s to process "
                        f"(HTTP {resp.status_code})"
                    ),
                    confidence=0.60,
                ))
        except requests.RequestException as exc:
            log.debug("Fragment chain test failed: %s", exc)

        # ---- 2. Circular fragment reference ----
        circular = (
            "query CircRef { ...CycleA }\n"
            "fragment CycleA on Query { __typename ...CycleB }\n"
            "fragment CycleB on Query { __typename ...CycleA }\n"
        )
        try:
            resp = self._session.post(
                endpoint,
                json={"query": circular},
                timeout=_DEFAULT_TIMEOUT,
            )
            body = resp.text.lower()
            # A properly hardened server should reject this with an error
            if resp.status_code == 200 and "errors" not in body:
                findings.append(_make_finding(
                    vuln_type="graphql_circular_fragment_no_error",
                    severity="medium",
                    url=endpoint,
                    endpoint=endpoint,
                    payload=circular,
                    evidence=(
                        "Server returned HTTP 200 for a circular fragment query "
                        "without reporting an error — missing cycle detection"
                    ),
                    confidence=0.70,
                ))
        except requests.RequestException as exc:
            log.debug("Circular fragment test failed: %s", exc)

        return findings

    # ------------------------------------------------------------------ #
    # Field-level argument fuzzing
    # ------------------------------------------------------------------ #

    def fuzz_field_args(self, endpoint: str, schema: dict) -> List[dict]:
        """
        Iterate over query fields that accept arguments and inject security
        payloads (SQLi, XSS, SSRF, path traversal) into each argument.

        Returns a list of finding dicts.
        """
        findings: List[dict] = []

        query_type_name = (schema.get("queryType") or {}).get("name")
        if not query_type_name:
            return findings

        # Find fields with arguments
        target_fields: List[dict] = []
        for t in schema.get("types", []):
            if t.get("name") == query_type_name:
                for f in t.get("fields") or []:
                    args = f.get("args") or []
                    if args:
                        target_fields.append({"name": f["name"], "args": args})
                break

        if not target_fields:
            return findings

        _PAYLOADS = [
            ("sqli", "1' OR '1'='1"),
            ("xss", "<script>alert(1)</script>"),
            ("ssrf", "http://169.254.169.254/latest/meta-data/"),
            ("path_traversal", "../../etc/passwd"),
            ("ssti", "{{7*7}}"),
        ]

        _ERROR_PATTERNS = (
            "sql", "syntax error", "exception", "traceback",
            "stack", "eval", "template", "injection",
        )

        # Test up to 3 fields, up to 2 args each
        for field in target_fields[:3]:
            fname = field["name"]
            for arg in field["args"][:2]:
                arg_name = arg.get("name", "")
                if not arg_name:
                    continue
                for payload_type, payload_val in _PAYLOADS:
                    query = f'query {{ {fname}({arg_name}: "{payload_val}") }}'
                    try:
                        resp = self._session.post(
                            endpoint,
                            json={"query": query},
                            timeout=_DEFAULT_TIMEOUT,
                        )
                        body = resp.text.lower()
                        if any(pat in body for pat in _ERROR_PATTERNS):
                            findings.append(_make_finding(
                                vuln_type=f"graphql_arg_injection_{payload_type}",
                                severity="high",
                                url=endpoint,
                                endpoint=endpoint,
                                payload=query,
                                evidence=(
                                    f"Field '{fname}' arg '{arg_name}' with {payload_type} payload "
                                    f"triggered error pattern in response (HTTP {resp.status_code})"
                                ),
                                confidence=0.72,
                            ))
                    except requests.RequestException as exc:
                        log.debug("fuzz_field_args failed for %s.%s: %s", fname, arg_name, exc)

        return findings

    # ------------------------------------------------------------------ #
    # Orchestration
    # ------------------------------------------------------------------ #

    def run(self) -> List[dict]:
        """
        Run all GraphQL security tests and return a normalized findings list.

        Steps:
          1. Detect endpoints
          2. For each endpoint: test introspection
          3. For each endpoint: fuzz queries
          4. For each endpoint with schema: test mutations, test IDOR
        """
        all_findings: List[dict] = []

        log.info("GraphQL scan starting for target: %s", self.target)
        endpoints = self.detect_endpoints()
        if not endpoints:
            log.info("No GraphQL endpoints detected at %s", self.target)
            return all_findings

        log.info("Detected %d GraphQL endpoint(s): %s", len(endpoints), endpoints)

        for endpoint in endpoints:
            log.info("Testing endpoint: %s", endpoint)

            # Introspection
            intro = self.test_introspection(endpoint)
            if intro["finding"]:
                all_findings.append(intro["finding"])
            schema = intro["raw_schema"]

            # Query fuzzing (works with or without introspection schema)
            try:
                fuzz_findings = self.fuzz_queries(endpoint, schema)
                all_findings.extend(fuzz_findings)
            except Exception as exc:
                log.warning("fuzz_queries failed on %s: %s", endpoint, exc)

            # Alias abuse (works without schema)
            try:
                alias_findings = self.test_alias_abuse(endpoint, schema)
                all_findings.extend(alias_findings)
            except Exception as exc:
                log.warning("test_alias_abuse failed on %s: %s", endpoint, exc)

            # Fragment abuse (works without schema)
            try:
                fragment_findings = self.test_fragment_abuse(endpoint, schema)
                all_findings.extend(fragment_findings)
            except Exception as exc:
                log.warning("test_fragment_abuse failed on %s: %s", endpoint, exc)

            # Auth-aware comparison (requires registered sessions)
            try:
                auth_findings = self.test_auth_comparison(endpoint, schema)
                all_findings.extend(auth_findings)
            except Exception as exc:
                log.warning("test_auth_comparison failed on %s: %s", endpoint, exc)

            if not intro["enabled"]:
                log.debug("Introspection disabled on %s; skipping mutation/IDOR/arg-fuzz tests", endpoint)
                continue

            # Mutation testing
            try:
                mutation_findings = self.test_mutations(endpoint, schema)
                all_findings.extend(mutation_findings)
            except Exception as exc:
                log.warning("test_mutations failed on %s: %s", endpoint, exc)

            # IDOR testing
            try:
                idor_findings = self.test_idor(endpoint, schema)
                all_findings.extend(idor_findings)
            except Exception as exc:
                log.warning("test_idor failed on %s: %s", endpoint, exc)

            # Field-level argument fuzzing
            try:
                arg_findings = self.fuzz_field_args(endpoint, schema)
                all_findings.extend(arg_findings)
            except Exception as exc:
                log.warning("fuzz_field_args failed on %s: %s", endpoint, exc)

        log.info(
            "GraphQL scan complete for %s — %d finding(s)",
            self.target,
            len(all_findings),
        )
        return all_findings


# ---------------------------------------------------------------------------
# CLI entry point
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    import sys
    import argparse

    logging.basicConfig(level=logging.INFO, format="%(levelname)s %(name)s %(message)s")

    parser = argparse.ArgumentParser(description="GraphQL Security Scanner")
    parser.add_argument("target", help="Base URL to scan (e.g. https://example.com)")
    parser.add_argument("--output-dir", default=".", help="Directory for output files")
    args = parser.parse_args()

    engine = GraphQLScanEngine(target=args.target, output_dir=args.output_dir)
    findings = engine.run()

    print(f"\n[+] GraphQL scan finished — {len(findings)} finding(s)\n")
    for f in findings:
        print(f"  [{f['severity'].upper()}] {f['vuln_type']} @ {f['url']}")
        print(f"         {f['evidence'][:120]}")

    if findings:
        import os
        out_path = os.path.join(args.output_dir, "graphql_findings.json")
        with open(out_path, "w") as fh:
            json.dump({"findings": findings}, fh, indent=2)
        print(f"\n[+] Findings written to {out_path}")
