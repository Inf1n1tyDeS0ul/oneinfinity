"""
token_execution_engine.py — Token-Aware HTTP Execution Engine

Loads TOKEN and SESSION nodes from the attack graph and uses them to:
  1. Inject tokens/sessions into requests to protected endpoints.
  2. Test privilege escalation (low-priv token → high-priv endpoint).
  3. Propagate tokens through multi-hop exploit chains (step N → step N+1).
  4. Report authentication bypass / privilege escalation findings.

Integration:
  - Called from unified_scan_engine._phase_exploit_chaining (after token extraction)
  - Uses attack_graph_brain graph nodes, not static config

Authorized use only — requires scope.yaml with authorized: true.
"""
from __future__ import annotations

import hashlib
import logging
import re
import time
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Tuple

log = logging.getLogger("oneinfinity.core.token_execution_engine")

# ---------------------------------------------------------------------------
# Result model
# ---------------------------------------------------------------------------

@dataclass
class TokenTestResult:
    """Outcome of a single token→endpoint test."""
    token_node_id:   str
    token_type:      str
    token_fp:        str          # fingerprint (not the raw secret)
    endpoint:        str
    status_code:     int
    success:         bool
    escalated:       bool = False  # True if lower-priv token accessed higher-priv data
    evidence:        str = ""
    chain_data:      dict = field(default_factory=dict)

    def to_finding(self, scan_id: str = "", target: str = "") -> dict:
        severity = "critical" if self.escalated else ("high" if self.success else "info")
        return {
            "tool":          "token_execution_engine",
            "vuln_type":     "privilege_escalation" if self.escalated else "authenticated_access",
            "title":         (
                f"Token Privilege Escalation: {self.token_type} → {self.endpoint}"
                if self.escalated else
                f"Authenticated Endpoint Access: {self.endpoint}"
            ),
            "severity":      severity,
            "confidence":    0.85 if self.escalated else 0.70,
            "url":           self.endpoint,
            "target":        target,
            "scan_id":       scan_id,
            "evidence":      self.evidence[:2000],
            "source_type":   "confirmed",
            "chain_data":    self.chain_data,
            "token_fp":      self.token_fp,
        }


# ---------------------------------------------------------------------------
# Engine
# ---------------------------------------------------------------------------

class TokenExecutionEngine:
    """
    Loads TOKEN/SESSION nodes from graph and executes authenticated HTTP
    requests against graph-connected endpoints.

    FIX 4: Token Propagation
    For multi-hop chains, propagates the token extracted from step N into
    step N+1 automatically via `execute_chain_with_tokens()`.
    """

    def __init__(self, timeout_s: float = 8.0, max_tests_per_token: int = 5):
        self._timeout_s = timeout_s
        self._max_per_token = max_tests_per_token
        self._session = None
        # FIX 9: Cache to avoid duplicate test execution
        self._tested_pairs: set = set()   # (token_fp, endpoint) already tested
        # Same-run token cache: fingerprint → raw_token value
        # Populated by store_raw_token(); never persisted to SQLite.
        self._token_cache: dict = {}

    def store_raw_token(self, fingerprint: str, raw_value: str) -> None:
        """
        Register a raw token value for the given fingerprint.
        Called by the scan pipeline after token extraction so that
        _build_auth_headers can inject it into subsequent requests
        within the same run — without persisting secrets to SQLite.
        """
        self._token_cache[fingerprint] = raw_value

    # ── HTTP helpers ─────────────────────────────────────────────────────

    def _get_session(self):
        if self._session is None:
            try:
                from oneinfinity.core.stealth_engine import new_stealth_session
                self._session = new_stealth_session(timeout_s=self._timeout_s)
            except ImportError:
                try:
                    import requests
                    import urllib3
                    urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
                    s = requests.Session()
                    s.headers.pop("User-Agent", None)
                    s.max_redirects = 3
                    self._session = s
                except ImportError:
                    return None
        return self._session

    def _request(self, method: str, url: str, headers: dict = None,
                 timeout: float = None) -> Optional[object]:
        s = self._get_session()
        if s is None:
            return None
        try:
            resp = s.request(
                method, url,
                headers=headers or {},
                timeout=timeout or self._timeout_s,
                verify=False,
                allow_redirects=True,
            )
            return resp
        except Exception as exc:
            log.debug("_request %s %s: %s", method, url[:80], exc)
            return None

    # ── Token injection ───────────────────────────────────────────────────

    def _build_auth_headers(self, token_node) -> dict:
        """Construct HTTP headers for a TOKEN or SESSION node."""
        token_type = token_node.properties.get("token_type", "")
        # We store only the fingerprint in the graph — reconstruct a usable
        # placeholder for testing.  Real value would come from chain_data.
        raw_token  = token_node.properties.get("raw_token", "")
        if not raw_token:
            fp = token_node.properties.get("fingerprint", "")
            raw_token = self._token_cache.get(fp, "")
        if not raw_token:
            return {}

        headers: dict = {}
        if token_type in ("jwt", "bearer", "oauth"):
            headers["Authorization"] = f"Bearer {raw_token}"
        elif token_type == "api_key":
            headers["X-Api-Key"] = raw_token
            headers["Authorization"] = f"ApiKey {raw_token}"
        elif token_type in ("session_cookie",):
            headers["Cookie"] = f"session={raw_token}"
        else:
            headers["Authorization"] = f"Token {raw_token}"
        return headers

    def _detect_priv_escalation(self, resp, endpoint: str) -> Tuple[bool, str]:
        """
        Heuristic detection of privilege escalation in the response.
        Returns (escalated: bool, evidence: str).
        """
        if resp is None:
            return False, ""
        body = ""
        try:
            body = resp.text[:4000]
        except Exception:
            return False, ""

        # Indicators of high-privilege data / admin access
        admin_patterns = [
            r"admin",
            r"superuser",
            r"is_admin[\"'\s]*:\s*true",
            r"role[\"'\s]*:\s*[\"']admin",
            r"\"users\":\s*\[",    # user list returned
            r"DELETE.*FROM",       # SQL in error response
            r"Access granted",
            r"Welcome,\s+admin",
        ]
        for pat in admin_patterns:
            if re.search(pat, body, re.IGNORECASE):
                snippet = re.search(pat, body, re.IGNORECASE)
                evidence = f"Pattern '{pat}' matched at response position {snippet.start()}: ...{body[max(0,snippet.start()-20):snippet.end()+40]}..."
                return True, evidence

        # 200 on an admin endpoint is suspicious
        if resp.status_code == 200 and any(p in endpoint for p in ["/admin", "/manage", "/root", "/superuser"]):
            return True, f"HTTP 200 on admin endpoint {endpoint}"

        return False, ""

    # ── Core test ─────────────────────────────────────────────────────────

    def _test_token_on_endpoint(self, token_node, endpoint: str,
                                 scan_id: str = "", target: str = "") -> Optional[TokenTestResult]:
        """Single token × endpoint test with FIX 9 dedup guard."""
        token_fp = token_node.properties.get("fingerprint", token_node.id[:8])
        dedup_key = (token_fp, endpoint)
        if dedup_key in self._tested_pairs:
            return None
        self._tested_pairs.add(dedup_key)

        headers = self._build_auth_headers(token_node)
        if not headers:
            return None

        resp = self._request("GET", endpoint, headers=headers)
        if resp is None:
            return None

        escalated, evidence = self._detect_priv_escalation(resp, endpoint)
        success = resp.status_code < 400

        if not success and not escalated:
            return None   # uninteresting

        log.info(
            "TokenExec: token=%s type=%s endpoint=%s status=%d escalated=%s",
            token_fp, token_node.properties.get("token_type", "?"),
            endpoint[:80], resp.status_code, escalated,
        )

        return TokenTestResult(
            token_node_id=token_node.id,
            token_type=token_node.properties.get("token_type", "unknown"),
            token_fp=token_fp,
            endpoint=endpoint,
            status_code=resp.status_code,
            success=success,
            escalated=escalated,
            evidence=evidence or f"HTTP {resp.status_code} from {endpoint}",
            chain_data={"response_snippet": resp.text[:500] if hasattr(resp, "text") else ""},
        )

    # ── Graph-driven execution ────────────────────────────────────────────

    def execute_from_graph(self, brain, scan_id: str = "",
                           target: str = "") -> List[TokenTestResult]:
        """
        FIX 3: Load all TOKEN/SESSION nodes from the graph and test them
        against their connected endpoints (AUTH_FOR edges).

        Returns list of TokenTestResult findings.
        """
        results: List[TokenTestResult] = []
        try:
            from oneinfinity.attack_graph_core.graph_engine import NodeType, EdgeType
            eng = brain._get_engine()

            token_nodes = eng.find_nodes(node_type=NodeType.TOKEN)
            session_nodes = eng.find_nodes(node_type=NodeType.SESSION)
            all_token_nodes = token_nodes + session_nodes

            if not all_token_nodes:
                log.info("TokenExecutionEngine: no token/session nodes in graph")
                return []

            for token_node in all_token_nodes:
                tested = 0
                # Follow AUTH_FOR edges to find protected endpoints
                for edge in eng.get_edges_from(token_node.id):
                    if edge.edge_type != EdgeType.AUTH_FOR:
                        continue
                    endpoint_node = eng.get_node(edge.target_id)
                    if endpoint_node is None:
                        continue
                    endpoint = endpoint_node.label
                    if not endpoint.startswith("http"):
                        continue
                    result = self._test_token_on_endpoint(token_node, endpoint, scan_id, target)
                    if result:
                        results.append(result)
                        # Update graph node to reflect confirmation
                        if result.escalated:
                            eng.update_node(endpoint_node.id, exploitable=True, severity="critical")
                    tested += 1
                    if tested >= self._max_per_token:
                        break

        except Exception as exc:
            log.error("TokenExecutionEngine.execute_from_graph: %s", exc)

        return results

    def execute_chain_with_tokens(
        self,
        chain_steps: List[dict],
        initial_token: Optional[str] = None,
        initial_token_type: str = "bearer",
        scan_id: str = "",
        target: str = "",
    ) -> Tuple[bool, List[TokenTestResult], str]:
        """
        FIX 4: Token Propagation through chain steps.

        Executes a multi-hop exploit chain where each step may produce a token
        that is injected into the next step.

        chain_steps: [{"url": str, "method": str, "params": dict}, ...]
        initial_token: optional seed token for the first step
        Returns: (chain_succeeded, results, final_evidence)
        """
        results: List[TokenTestResult] = []
        current_token = initial_token
        current_token_type = initial_token_type
        chain_succeeded = False
        final_evidence = ""

        for i, step in enumerate(chain_steps):
            url = step.get("url", "")
            method = step.get("method", "GET").upper()
            if not url.startswith("http"):
                continue

            headers: dict = {}
            if current_token:
                if current_token_type in ("jwt", "bearer", "oauth"):
                    headers["Authorization"] = f"Bearer {current_token}"
                elif current_token_type == "api_key":
                    headers["X-Api-Key"] = current_token
                elif current_token_type == "session_cookie":
                    headers["Cookie"] = f"session={current_token}"
                else:
                    headers["Authorization"] = f"Token {current_token}"

            resp = self._request(method, url, headers=headers)
            if resp is None:
                log.debug("chain step %d/%d: no response from %s", i + 1, len(chain_steps), url)
                break

            step_success = resp.status_code < 400
            escalated, evidence = self._detect_priv_escalation(resp, url)

            # Extract token from this response for next step
            try:
                body_text = resp.text if hasattr(resp, "text") else ""
                resp_headers = dict(resp.headers) if hasattr(resp, "headers") else {}
                next_token, next_type = self._extract_token_from_response(
                    resp_headers, body_text
                )
                if next_token:
                    current_token = next_token
                    current_token_type = next_type
                    log.debug("chain step %d: extracted %s token for next step", i + 1, next_type)
            except Exception as exc:
                log.debug("chain step %d: token extraction failed: %s", i + 1, exc)

            fp = hashlib.sha256((current_token or url).encode()).hexdigest()[:12]
            result = TokenTestResult(
                token_node_id=f"chain_step_{i}",
                token_type=current_token_type,
                token_fp=fp,
                endpoint=url,
                status_code=resp.status_code,
                success=step_success,
                escalated=escalated,
                evidence=evidence or f"HTTP {resp.status_code}",
                chain_data={"step": i + 1, "total_steps": len(chain_steps),
                            "token_propagated": current_token is not None},
            )
            results.append(result)
            final_evidence = evidence or final_evidence

            if not step_success:
                break

            if i == len(chain_steps) - 1 and step_success:
                chain_succeeded = True

        return chain_succeeded, results, final_evidence

    def _extract_token_from_response(self, headers: dict, body: str) -> Tuple[Optional[str], str]:
        """Extract the most prominent token from an HTTP response for propagation."""
        # JWT
        jwt_m = re.search(r'eyJ[A-Za-z0-9_-]{4,}\.eyJ[A-Za-z0-9_-]{4,}\.[A-Za-z0-9_-]+', body)
        if jwt_m:
            return jwt_m.group(), "jwt"
        # Bearer in response body
        bearer_m = re.search(r'"(?:access_token|token|id_token)"\s*:\s*"([A-Za-z0-9_\-\.]{20,})"', body)
        if bearer_m:
            return bearer_m.group(1), "bearer"
        # Set-Cookie session
        cookie = headers.get("Set-Cookie", "") or headers.get("set-cookie", "")
        sess_m = re.search(r'(?:session|PHPSESSID|JSESSIONID|connect\.sid)=([^;]{16,})', cookie)
        if sess_m:
            return sess_m.group(1), "session_cookie"
        return None, "unknown"


# ---------------------------------------------------------------------------
# Singleton
# ---------------------------------------------------------------------------

_engine: Optional[TokenExecutionEngine] = None


def get_token_execution_engine() -> TokenExecutionEngine:
    global _engine
    if _engine is None:
        _engine = TokenExecutionEngine()
    return _engine
