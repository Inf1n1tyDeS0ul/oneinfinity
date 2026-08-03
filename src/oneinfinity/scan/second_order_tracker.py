"""
src/oneinfinity/scan/second_order_tracker.py
Phase 1 — Core Coverage Gaps: Second-Order Vulnerability Tracker

Detects vulnerabilities where injection happens at point A but execution
happens at point B — often in a different user's browser, an admin panel,
an email template, a PDF export, or a background job.

Current tools (Burp, Nuclei, ZAP) are stateless: they test input and output
on the same HTTP round-trip. They CANNOT find second-order vulnerabilities.

Architecture:
  1. Inject distinct canary payloads at every stored-data input point.
  2. Build an observation grid: all paths that could render the stored data.
  3. Trigger each observation path (as different roles where possible).
  4. Check whether the canary payload executed or was reflected in executable context.

Integration: called from pipeline/executor._inline_second_order()
which is triggered by the canonical 'second_order' pipeline phase.
"""
from __future__ import annotations

import hashlib
import logging
import time
import uuid
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional
from urllib.parse import urljoin, urlparse

log = logging.getLogger("oneinfinity.second_order_tracker")

# ── Canary payload constants ──────────────────────────────────────────────────

# A unique run-specific prefix prevents false-positive matches across runs.
_CANARY_PREFIX = "oi_so_"

def _make_canary(run_id: str, payload_type: str, index: int) -> str:
    """Generate a unique, recognisable canary string for this injection point."""
    h = hashlib.sha1(f"{run_id}:{payload_type}:{index}".encode()).hexdigest()[:8]
    return f"{_CANARY_PREFIX}{h}"


# Payloads injected at each stored input point.
# Each is a (type, template) pair. {canary} is replaced with the unique canary string.
_INJECTION_PAYLOADS: List[tuple[str, str]] = [
    ("html_reflection",    "<script>/*{canary}*/</script>"),
    ("img_onerror",        "<img src=x onerror=/*{canary}*/>"),
    ("ssti_marker",        "{{{canary}}}"),        # Jinja / Twig / Handlebars
    ("sqli_comment",       "' OR 1=1--{canary}--"),
    ("crlf_header",        "\r\nX-Canary: {canary}"),
    ("path_marker",        "../{canary}"),
    ("json_injection",     '{"__canary__":"{canary}"}'),
]

# ── Dataclasses ───────────────────────────────────────────────────────────────

@dataclass
class InjectionPoint:
    """A stored-data input point where a canary was injected."""
    url: str
    method: str           # POST / PUT / PATCH
    param_name: str
    param_location: str   # body | query | header | cookie | json
    canary: str
    payload_type: str
    payload_sent: str
    injected_at: float = field(default_factory=time.time)
    status_code: int = 0
    response_snippet: str = ""


@dataclass
class ObservationPoint:
    """A path that could render stored data."""
    url: str
    method: str = "GET"
    role: str = "anonymous"   # anonymous | authenticated | admin
    trigger_action: str = ""  # description of what this path renders


@dataclass
class SecondOrderFinding:
    """A confirmed second-order vulnerability."""
    injection_point: InjectionPoint
    observation_url: str
    observation_role: str
    payload_type: str
    canary: str
    execution_context: str  # script | event_handler | css | reflected | header | ssti | sqli
    evidence_snippet: str
    severity: str           # high | medium | low
    vuln_type: str          # second_order_xss | second_order_ssti | etc.

    def to_finding_dict(self, scan_id: str, target: str) -> dict:
        return {
            "finding_id":  str(uuid.uuid4())[:12],
            "scan_id":     scan_id,
            "target":      target,
            "title":       f"Second-Order {self.vuln_type.upper()} — {self.injection_point.param_name}",
            "severity":    self.severity,
            "vuln_type":   self.vuln_type,
            "url":         self.injection_point.url,
            "evidence":    (
                f"Injected canary '{self.canary}' at {self.injection_point.url} "
                f"param={self.injection_point.param_name}. "
                f"Observed execution at {self.observation_url} "
                f"(role={self.observation_role}, context={self.execution_context}). "
                f"Snippet: {self.evidence_snippet[:200]}"
            ),
            "payload":     self.injection_point.payload_sent,
            "tool":        "second_order_tracker",
            "confidence":  0.85,
            "source_type": "tool",
            "raw": {
                "injection_url":    self.injection_point.url,
                "injection_param":  self.injection_point.param_name,
                "observation_url":  self.observation_url,
                "observation_role": self.observation_role,
                "canary":           self.canary,
                "payload_type":     self.payload_type,
                "execution_context": self.execution_context,
                "evidence_snippet": self.evidence_snippet,
            },
        }


# ── SecondOrderTracker ────────────────────────────────────────────────────────

class SecondOrderTracker:
    """
    Tracks second-order vulnerability patterns across a scan session.

    Workflow:
      1. build_observation_grid(urls)  — identify candidate observation paths
      2. inject_canaries(session, stored_endpoints) — inject and record
      3. observe_all(session)  — trigger observation paths, look for canaries
      4. get_findings()  — return confirmed second-order findings
    """

    def __init__(self, target: str, scan_id: str, session_headers: dict = None):
        self.target = target
        self.scan_id = scan_id
        self._session_headers = session_headers or {}
        self._run_id = str(uuid.uuid4())[:12]
        self._injection_points: List[InjectionPoint] = []
        self._observation_grid: List[ObservationPoint] = []
        self._findings: List[SecondOrderFinding] = []

    # ── Public API ────────────────────────────────────────────────────────────

    def run(
        self,
        urls: List[str],
        stored_input_endpoints: List[Dict[str, Any]],
        auth_sessions: Optional[List[Dict]] = None,
    ) -> List[dict]:
        """
        Full second-order tracking run.

        Args:
            urls: all discovered URLs for observation grid building
            stored_input_endpoints: list of {url, method, params:[{name, location}]}
                                    — endpoints that store user data
            auth_sessions: list of {headers, role} for multi-role observation

        Returns:
            List of finding dicts (same shape as NormalizedFinding.to_dict())
        """
        import requests

        log.info("[second_order] Starting — target=%s run_id=%s endpoints=%d",
                 self.target, self._run_id, len(stored_input_endpoints))

        # Step 1: build observation grid
        self._observation_grid = self.build_observation_grid(urls, auth_sessions)
        log.info("[second_order] Observation grid: %d paths", len(self._observation_grid))

        # Step 2: inject canaries
        session = requests.Session()
        session.headers.update(self._session_headers)
        session.timeout = 10
        self._injection_points = self._inject_canaries(session, stored_input_endpoints)
        log.info("[second_order] Injected %d canaries", len(self._injection_points))

        if not self._injection_points:
            log.info("[second_order] No injection points — skipping observation")
            return []

        # Brief wait for async processing (email queues, background jobs, etc.)
        time.sleep(2)

        # Step 3: observe all rendering paths
        self._observe_all(session, auth_sessions)

        findings = [f.to_finding_dict(self.scan_id, self.target) for f in self._findings]
        log.info("[second_order] Complete — %d second-order findings", len(findings))
        return findings

    def build_observation_grid(
        self,
        urls: List[str],
        auth_sessions: Optional[List[Dict]] = None,
    ) -> List[ObservationPoint]:
        """
        Build a list of observation paths from discovered URLs.

        Prioritises:
        - Admin panels (most likely to render stored user data unsafely)
        - Export / report endpoints
        - Email preview / template endpoints
        - Audit log endpoints
        - Search / list views (may render stored display names)
        """
        grid: List[ObservationPoint] = []
        seen: set = set()

        _priority_patterns = [
            ("admin",    ["admin", "dashboard", "management", "console", "panel", "staff"],   "admin",         "Admin panel — renders all user data"),
            ("export",   ["export", "report", "pdf", "download", "dump", "backup"],           "authenticated", "Export/report — renders stored content"),
            ("email",    ["email", "template", "notification", "message", "inbox", "mail"],   "authenticated", "Email/notification — renders stored display names"),
            ("audit",    ["audit", "log", "history", "activity", "event"],                    "admin",         "Audit log — renders all user actions"),
            ("list",     ["list", "search", "browse", "index", "feed", "users", "members"],   "authenticated", "List/search view — renders stored records"),
            ("profile",  ["profile", "account", "user", "bio", "about"],                      "anonymous",     "Profile view — renders stored bio/name"),
        ]

        for url in urls:
            if url in seen:
                continue
            parsed = urlparse(url)
            path_lower = parsed.path.lower()
            matched_role = "anonymous"
            matched_trigger = "Generic GET"

            for _cat, keywords, role, trigger in _priority_patterns:
                if any(kw in path_lower for kw in keywords):
                    matched_role = role
                    matched_trigger = trigger
                    break

            grid.append(ObservationPoint(
                url=url,
                method="GET",
                role=matched_role,
                trigger_action=matched_trigger,
            ))
            seen.add(url)

        # Cap at 100 observation points to bound scan time
        # Priority order: admin > export > email > audit > list > profile > other
        def _priority_score(op: ObservationPoint) -> int:
            p = op.url.lower()
            if any(k in p for k in ["admin", "staff", "console"]): return 0
            if any(k in p for k in ["export", "report", "pdf"]):   return 1
            if any(k in p for k in ["email", "mail", "template"]): return 2
            if any(k in p for k in ["audit", "log", "history"]):   return 3
            if any(k in p for k in ["list", "search", "users"]):   return 4
            return 5

        grid.sort(key=_priority_score)
        return grid[:100]

    def get_findings(self) -> List[SecondOrderFinding]:
        return list(self._findings)

    # ── Internal ─────────────────────────────────────────────────────────────

    def _inject_canaries(
        self,
        session: Any,
        stored_input_endpoints: List[Dict[str, Any]],
    ) -> List[InjectionPoint]:
        """Inject canary payloads at each stored-input endpoint."""
        points: List[InjectionPoint] = []
        for i, ep in enumerate(stored_input_endpoints[:30]):  # cap injections
            url    = ep.get("url", "")
            method = ep.get("method", "POST").upper()
            params = ep.get("params", [])
            if not url or not params:
                continue
            for param in params[:5]:  # cap params per endpoint
                param_name = param.get("name", "")
                param_loc  = param.get("location", "body")
                if not param_name:
                    continue
                for payload_type, payload_template in _INJECTION_PAYLOADS[:3]:
                    canary  = _make_canary(self._run_id, payload_type, i)
                    payload = payload_template.replace("{canary}", canary)
                    point   = InjectionPoint(
                        url=url, method=method,
                        param_name=param_name, param_location=param_loc,
                        canary=canary, payload_type=payload_type,
                        payload_sent=payload,
                    )
                    try:
                        resp = self._send_injection(session, point)
                        point.status_code = resp.status_code
                        point.response_snippet = resp.text[:200]
                        points.append(point)
                    except Exception as exc:
                        log.debug("[second_order] inject failed [%s %s]: %s", method, url, exc)
        return points

    def _send_injection(self, session: Any, point: InjectionPoint) -> Any:
        """Send the injection request."""
        data = {point.param_name: point.payload_sent}
        if point.method in ("POST", "PUT", "PATCH"):
            return session.request(point.method, point.url, data=data)
        # GET — append as query param
        sep = "&" if "?" in point.url else "?"
        return session.get(f"{point.url}{sep}{point.param_name}={point.payload_sent}")

    def _observe_all(
        self,
        session: Any,
        auth_sessions: Optional[List[Dict]] = None,
    ) -> None:
        """Trigger each observation path and check for canary execution."""
        all_canaries = {ip.canary: ip for ip in self._injection_points}
        if not all_canaries:
            return

        # Build role→headers map
        role_sessions: Dict[str, dict] = {"anonymous": {}}
        if auth_sessions:
            for s in auth_sessions:
                role = s.get("role", "authenticated")
                role_sessions[role] = s.get("headers", {})

        for obs in self._observation_grid:
            headers = role_sessions.get(obs.role, role_sessions.get("authenticated", {}))
            try:
                resp = session.get(obs.url, headers=headers, timeout=10)
                body = resp.text
            except Exception as exc:
                log.debug("[second_order] observe failed [%s]: %s", obs.url, exc)
                continue

            # Check for any canary in the response
            for canary, injection_point in all_canaries.items():
                if canary not in body:
                    continue
                # Canary found — determine execution context
                context = self._classify_execution_context(canary, body)
                severity = "high" if context in ("script", "event_handler", "ssti") else "medium"
                vuln_type = {
                    "script":        "second_order_xss",
                    "event_handler": "second_order_xss",
                    "ssti":          "second_order_ssti",
                    "sqli":          "second_order_sqli",
                    "crlf":          "second_order_crlf",
                    "reflected":     "second_order_reflected_injection",
                    "header":        "second_order_header_injection",
                    "css":           "second_order_css_injection",
                }.get(context, "second_order_stored_injection")

                # Collect evidence snippet
                idx = body.find(canary)
                snippet = body[max(0, idx - 60): idx + len(canary) + 60]

                finding = SecondOrderFinding(
                    injection_point=injection_point,
                    observation_url=obs.url,
                    observation_role=obs.role,
                    payload_type=injection_point.payload_type,
                    canary=canary,
                    execution_context=context,
                    evidence_snippet=snippet,
                    severity=severity,
                    vuln_type=vuln_type,
                )
                self._findings.append(finding)
                log.info(
                    "[second_order] FOUND %s — injected@%s observed@%s context=%s",
                    vuln_type, injection_point.url, obs.url, context,
                )

    @staticmethod
    def _classify_execution_context(canary: str, body: str) -> str:
        """Classify where the canary appears in the response body."""
        idx = body.find(canary)
        if idx < 0:
            return "reflected"

        # Check 200 chars of surrounding context
        window = body[max(0, idx - 200): idx + len(canary) + 200].lower()

        if "<script" in window[:200] or "</script>" in window[200:]:
            return "script"
        if "onerror=" in window or "onload=" in window or "onclick=" in window:
            return "event_handler"
        if "{{" in window or "{%" in window or "${" in window:
            return "ssti"
        if "' or " in window or "-- " in window or "1=1" in window:
            return "sqli"
        if "\r\n" in window or "%0d%0a" in window.lower():
            return "crlf"
        if "style=" in window or "@import" in window:
            return "css"
        # Check response headers indication
        if "x-canary" in window:
            return "header"
        return "reflected"


# ── Module-level singleton ────────────────────────────────────────────────────

def run_second_order_scan(
    target: str,
    scan_id: str,
    urls: List[str],
    stored_input_endpoints: List[Dict[str, Any]],
    auth_sessions: Optional[List[Dict]] = None,
    session_headers: Optional[Dict] = None,
) -> List[dict]:
    """
    Convenience function — run full second-order tracking and return finding dicts.

    Called from pipeline/executor._inline_second_order().
    """
    tracker = SecondOrderTracker(
        target=target,
        scan_id=scan_id,
        session_headers=session_headers or {},
    )
    return tracker.run(
        urls=urls,
        stored_input_endpoints=stored_input_endpoints,
        auth_sessions=auth_sessions,
    )
