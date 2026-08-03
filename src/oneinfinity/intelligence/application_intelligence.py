"""
Application Intelligence Engine
================================
Understands how a target application works by analyzing crawled endpoints,
HTTP responses, JavaScript files, authentication flows, and user roles.

Produces an AppModel that feeds the Vulnerability Theory Engine.
"""

from __future__ import annotations

import json
import re
import time
from dataclasses import dataclass, field
from pathlib import Path

from oneinfinity.infra.path_manager import resolve_output_dir
from typing import Any, Optional
from urllib.parse import urlparse, parse_qs


# ── Data models ───────────────────────────────────────────────────────────────

@dataclass
class AuthFlow:
    """Detected authentication mechanism."""
    auth_type: str              # jwt | oauth2 | session | api_key | basic | saml | none
    token_locations: list[str]  # header | cookie | query | body
    endpoints: list[str]        # login/logout/refresh endpoints
    token_header: str = ""      # e.g. "Authorization"
    cookie_names: list[str] = field(default_factory=list)
    has_refresh_token: bool = False
    has_mfa: bool = False
    notes: list[str] = field(default_factory=list)


@dataclass
class APIEndpoint:
    """A single mapped API endpoint."""
    path: str
    methods: list[str]          # GET, POST, PUT, DELETE, PATCH
    parameters: list[str]       # query/body params observed
    auth_required: bool = False
    roles_required: list[str] = field(default_factory=list)
    content_types: list[str] = field(default_factory=list)
    response_fields: list[str] = field(default_factory=list)  # keys seen in JSON resp
    id_params: list[str] = field(default_factory=list)        # params containing IDs
    sensitivity_score: float = 0.0  # 0.0–1.0
    tags: list[str] = field(default_factory=list)             # admin|payment|user|file|etc.


@dataclass
class SensitiveFeature:
    """A detected sensitive application feature."""
    name: str           # e.g. "Admin Panel", "Payment Processing", "File Upload"
    category: str       # admin | payment | auth | file | data | api | export
    endpoints: list[str]
    risk_level: str     # critical | high | medium | low
    notes: str = ""


@dataclass
class AppModel:
    """Complete model of the target application's structure and behavior."""
    target: str
    built_at: float = field(default_factory=time.time)

    # Authentication
    auth_system: str = "unknown"        # primary auth type
    auth_flows: list[AuthFlow] = field(default_factory=list)

    # Structure
    api_structure: list[str] = field(default_factory=list)   # all API paths
    api_endpoints: list[APIEndpoint] = field(default_factory=list)
    api_versions: list[str] = field(default_factory=list)    # v1, v2, etc.
    api_base_paths: list[str] = field(default_factory=list)  # /api, /v1, etc.

    # Roles
    user_roles: list[str] = field(default_factory=list)

    # Sensitive surfaces
    sensitive_endpoints: list[str] = field(default_factory=list)
    sensitive_features: list[SensitiveFeature] = field(default_factory=list)

    # Technology
    tech_stack: list[str] = field(default_factory=list)
    frameworks: list[str] = field(default_factory=list)
    server: str = ""

    # Observed behaviors
    error_patterns: list[str] = field(default_factory=list)   # error strings found
    redirect_endpoints: list[str] = field(default_factory=list)
    file_upload_endpoints: list[str] = field(default_factory=list)
    export_endpoints: list[str] = field(default_factory=list)

    # Parameters
    all_parameters: dict[str, list[str]] = field(default_factory=dict)  # path → params
    id_parameters: dict[str, list[str]] = field(default_factory=dict)   # path → id params

    # ── Phase 1: Semantic Intent Model (LLM-synthesised) ─────────────────
    # Populated by build_semantic_intent() after heuristic analysis.
    # Empty lists/dicts mean intent modeling has not run yet (not that the
    # application has no flows/invariants).
    primary_flows: list[dict] = field(default_factory=list)
    # Each flow: {name, steps:[str], invariants:[str], endpoints:[str]}
    invariants: list[dict] = field(default_factory=list)
    # Each invariant: {flow, rule, test_approach, severity}
    trust_boundaries: dict[str, list[str]] = field(default_factory=dict)
    # {public:[paths], authenticated:[paths], privileged:[paths]}
    sensitive_objects: list[dict] = field(default_factory=list)
    # Each object: {name, owner_field, endpoints:[str], contains:[str]}
    intent_built: bool = False   # True once build_semantic_intent() has run

    def to_dict(self) -> dict:
        return {
            "target": self.target,
            "built_at": self.built_at,
            "auth_system": self.auth_system,
            "auth_flows": [
                {
                    "auth_type": a.auth_type,
                    "token_locations": a.token_locations,
                    "endpoints": a.endpoints,
                    "has_mfa": a.has_mfa,
                    "notes": a.notes,
                }
                for a in self.auth_flows
            ],
            "api_structure": self.api_structure,
            "api_versions": self.api_versions,
            "api_base_paths": self.api_base_paths,
            "user_roles": self.user_roles,
            "sensitive_endpoints": self.sensitive_endpoints,
            "sensitive_features": [
                {
                    "name": f.name,
                    "category": f.category,
                    "endpoints": f.endpoints,
                    "risk_level": f.risk_level,
                    "notes": f.notes,
                }
                for f in self.sensitive_features
            ],
            "tech_stack": self.tech_stack,
            "frameworks": self.frameworks,
            "server": self.server,
            "error_patterns": self.error_patterns,
            "file_upload_endpoints": self.file_upload_endpoints,
            "export_endpoints": self.export_endpoints,
            "all_parameters": self.all_parameters,
            "id_parameters": self.id_parameters,
            # Semantic intent fields
            "primary_flows":    self.primary_flows,
            "invariants":       self.invariants,
            "trust_boundaries": self.trust_boundaries,
            "sensitive_objects": self.sensitive_objects,
            "intent_built":     self.intent_built,
        }

    def to_json(self, indent: int = 2) -> str:
        return json.dumps(self.to_dict(), indent=indent)

    @classmethod
    def from_dict(cls, d: dict) -> "AppModel":
        model = cls(target=d.get("target", ""))
        model.built_at = d.get("built_at", time.time())
        model.auth_system = d.get("auth_system", "unknown")
        model.api_structure = d.get("api_structure", [])
        model.api_versions = d.get("api_versions", [])
        model.api_base_paths = d.get("api_base_paths", [])
        model.user_roles = d.get("user_roles", [])
        model.sensitive_endpoints = d.get("sensitive_endpoints", [])
        model.tech_stack = d.get("tech_stack", [])
        model.frameworks = d.get("frameworks", [])
        model.server = d.get("server", "")
        model.error_patterns = d.get("error_patterns", [])
        model.file_upload_endpoints = d.get("file_upload_endpoints", [])
        model.export_endpoints = d.get("export_endpoints", [])
        model.all_parameters = d.get("all_parameters", {})
        model.id_parameters = d.get("id_parameters", {})
        # Semantic intent fields (present only in models built with Phase 1)
        model.primary_flows    = d.get("primary_flows", [])
        model.invariants       = d.get("invariants", [])
        model.trust_boundaries = d.get("trust_boundaries", {})
        model.sensitive_objects = d.get("sensitive_objects", [])
        model.intent_built     = d.get("intent_built", False)
        for sf in d.get("sensitive_features", []):
            model.sensitive_features.append(SensitiveFeature(
                name=sf.get("name", ""),
                category=sf.get("category", "misc"),
                endpoints=sf.get("endpoints", []),
                risk_level=sf.get("risk_level", "medium"),
                notes=sf.get("notes", ""),
            ))
        return model


# ── Signatures and patterns ───────────────────────────────────────────────────

# JWT patterns
_JWT_PATTERN = re.compile(
    r"eyJ[a-zA-Z0-9_-]{10,}\.[a-zA-Z0-9_-]{10,}\.[a-zA-Z0-9_-]{10,}"
)
_BEARER_PATTERN = re.compile(r"[Bb]earer\s+", re.I)
_API_KEY_HEADERS = {
    "x-api-key", "x-auth-token", "x-access-token", "api-key",
    "x-token", "auth-token", "authorization",
}

# OAuth patterns
_OAUTH_PARAMS = {"code", "state", "client_id", "redirect_uri", "grant_type", "access_token"}

# Sensitive endpoint patterns (path segment → category)
_SENSITIVE_PATH_PATTERNS: list[tuple[re.Pattern, str, str, str]] = [
    # (regex, feature_name, category, risk_level)
    (re.compile(r"/admin|/dashboard|/management|/console|/panel", re.I),
     "Admin Panel", "admin", "critical"),
    (re.compile(r"/pay|/checkout|/billing|/invoice|/subscription|/stripe|/payment", re.I),
     "Payment Processing", "payment", "critical"),
    (re.compile(r"/upload|/import|/file|/attach|/media/upload|/document", re.I),
     "File Upload", "file", "high"),
    (re.compile(r"/export|/download|/report|/dump|/backup", re.I),
     "Data Export", "export", "high"),
    (re.compile(r"/user|/account|/profile|/me|/settings", re.I),
     "User Management", "user", "high"),
    (re.compile(r"/login|/signin|/auth|/oauth|/sso|/saml|/oidc", re.I),
     "Authentication", "auth", "high"),
    (re.compile(r"/api/v\d|/rest/|/graphql|/gql", re.I),
     "API Endpoint", "api", "medium"),
    (re.compile(r"/search|/query|/find|/filter|/list", re.I),
     "Search / Data Query", "data", "medium"),
    (re.compile(r"/config|/settings|/env|/debug|/health|/metrics|/actuator", re.I),
     "Configuration / Debug", "config", "critical"),
    (re.compile(r"/webhook|/callback|/notify|/hook", re.I),
     "Webhook / Callback", "webhook", "high"),
    (re.compile(r"/token|/refresh|/logout|/revoke", re.I),
     "Token Management", "auth", "high"),
    (re.compile(r"/role|/permission|/privilege|/grant|/scope", re.I),
     "Access Control", "admin", "critical"),
    (re.compile(r"/delete|/remove|/destroy|/purge", re.I),
     "Destructive Action", "admin", "high"),
    (re.compile(r"/share|/invite|/transfer|/assign", re.I),
     "Object Sharing", "data", "high"),
    (re.compile(r"/reset|/forgot|/recover|/change.password|/password", re.I),
     "Password Management", "auth", "high"),
]

# ID parameter patterns
_ID_PARAM_PATTERNS = re.compile(
    r"\b(id|user_?id|account_?id|order_?id|item_?id|product_?id|file_?id|"
    r"doc_?id|record_?id|uuid|guid|ref|token|key|session_?id|customer_?id|"
    r"resource_?id|object_?id|entity_?id|pid|uid)\b",
    re.I
)

# Role keywords
_ROLE_KEYWORDS = [
    "admin", "administrator", "superuser", "root", "staff", "moderator",
    "manager", "owner", "user", "member", "guest", "anonymous", "viewer",
    "editor", "operator", "support", "developer", "auditor", "readonly",
]

# Error patterns (server-side disclosure)
_ERROR_PATTERNS = [
    "traceback", "stack trace", "exception", "syntaxerror", "typeerror",
    "referenceerror", "nameerror", "at line", "internal server error",
    "syntax error in sql", "mysql_fetch", "pg_query", "oci_execute",
    "warning: include(", "failed to open stream", "call stack",
    "laravel", "symfony exception", "django traceback",
]

_INTENT_SYSTEM_PROMPT = """\
You are a senior penetration tester analysing a web application's attack surface.
Your task is to model what the application INTENDS to do, so that a security
scanner can systematically try to violate those intentions.

You MUST respond with ONLY valid JSON — no prose, no markdown, no code fences.
Focus on business logic vulnerabilities: IDORs, state-machine bypasses, race
conditions, and authorization failures. Every invariant you list must be
phrased as something a scanner can actively try to break.
"""


# ── ApplicationIntelligenceEngine ─────────────────────────────────────────────

class ApplicationIntelligenceEngine:
    """
    Builds a structured AppModel from recon data (files on disk) and
    optionally live HTTP probing.
    """

    def __init__(self, target: str, output_dir: str = ""):
        self.target = target
        self.output_dir = resolve_output_dir(output_dir, target)
        self._model = AppModel(target=target)

    # ── Public API ────────────────────────────────────────────────────────────

    def analyze_application_structure(
        self,
        urls: list[str] | None = None,
        alive_hosts: list[dict] | None = None,
        tech_profile: dict | None = None,
    ) -> AppModel:
        """
        Main entry point. Loads existing recon data from disk (or uses
        provided data) and builds a complete AppModel.
        """
        # Load from disk if not provided
        urls = urls or self._load_urls()
        alive_hosts = alive_hosts or self._load_alive_hosts()
        tech_profile = tech_profile or self._load_tech_profile()

        # Populate tech info
        self._ingest_tech_profile(tech_profile, alive_hosts)

        # Parse URL structure
        self._parse_url_structure(urls)

        # Detect auth flows
        self._model.auth_flows = self.detect_authentication_flows(urls, alive_hosts)
        if self._model.auth_flows:
            self._model.auth_system = self._model.auth_flows[0].auth_type

        # Identify sensitive features
        self._model.sensitive_features = self.identify_sensitive_features(
            urls, alive_hosts
        )
        self._model.sensitive_endpoints = [
            ep
            for sf in self._model.sensitive_features
            for ep in sf.endpoints
        ]

        # Detect roles from URLs/responses
        self._detect_roles(urls, alive_hosts)

        # Phase 1: LLM semantic intent synthesis (non-blocking on failure)
        try:
            self.build_semantic_intent()
        except Exception as exc:
            log.warning("ApplicationIntelligenceEngine: semantic intent failed (non-fatal): %s", exc)

        # Save model to disk
        out_path = self.output_dir / "app_model.json"
        out_path.parent.mkdir(parents=True, exist_ok=True)
        out_path.write_text(self._model.to_json())

        return self._model

    def build_semantic_intent(self) -> AppModel:
        """
        Phase 1 — Application Intent Model: LLM synthesis pass.

        Takes the already-built heuristic AppModel and asks an LLM to reason
        about what the application is supposed to do, producing:
          - primary_flows: multi-step user journeys the application supports
          - invariants: per-flow business rules that must always hold
          - trust_boundaries: public / authenticated / privileged path classification
          - sensitive_objects: owned objects with their ownership fields

        This is the semantic layer that enables invariant-violation scanning
        (Pillar 2.1 of the enhancement masterplan): the scanner can then
        systematically try to violate each invariant.

        Returns the enriched AppModel (also modifies self._model in-place).
        Fails gracefully — on any LLM error the model is returned unchanged.
        """
        from oneinfinity.orchestration.offensive_router import get_model_for_task
        provider = get_model_for_task("business_logic_analysis")

        prompt = self._build_intent_prompt()
        try:
            resp = provider.chat(
                prompt=prompt,
                system=_INTENT_SYSTEM_PROMPT,
                max_tokens=2048,
                temperature=0.2,
            )
            self._parse_intent_response(resp.text)
            log.info(
                "ApplicationIntelligenceEngine: intent model built — "
                "flows=%d invariants=%d trust_zones=%d sensitive_objects=%d",
                len(self._model.primary_flows),
                len(self._model.invariants),
                len(self._model.trust_boundaries),
                len(self._model.sensitive_objects),
            )
        except Exception as exc:
            log.warning("build_semantic_intent: LLM call failed: %s", exc)
        return self._model

    def _build_intent_prompt(self) -> str:
        """Build the LLM prompt from the current heuristic AppModel."""
        m = self._model
        # Build compact endpoint summary (cap at 60 to stay within token budget)
        endpoints_sample = m.api_structure[:60]
        sensitive = [
            f"{sf.name} ({sf.category}, {sf.risk_level}): {sf.endpoints[:3]}"
            for sf in m.sensitive_features
        ]
        auth_summary = ", ".join(
            f"{a.auth_type}@{a.endpoints[:2]}" for a in m.auth_flows
        )
        id_params_sample = dict(list(m.id_parameters.items())[:20])
        roles = m.user_roles or ["unknown"]

        return f"""You are analysing the security attack surface of a web application.

TARGET: {m.target}
TECH STACK: {', '.join(m.tech_stack[:10]) or 'unknown'}
FRAMEWORKS: {', '.join(m.frameworks[:5]) or 'unknown'}
AUTH SYSTEM: {m.auth_system} ({auth_summary})
USER ROLES: {', '.join(roles)}

DISCOVERED ENDPOINTS ({len(m.api_structure)} total, showing up to 60):
{chr(10).join(endpoints_sample)}

SENSITIVE FEATURES:
{chr(10).join(sensitive) or 'none detected'}

ENDPOINTS WITH ID PARAMETERS:
{json.dumps(id_params_sample, indent=2)}

FILE UPLOAD ENDPOINTS: {m.file_upload_endpoints[:5]}
EXPORT ENDPOINTS: {m.export_endpoints[:5]}

Based on the above, produce a JSON object with this exact schema:
{{
  "application_type": "<e-commerce|api-platform|saas|cms|banking|social|other>",
  "primary_flows": [
    {{
      "name": "<flow name>",
      "steps": ["<step 1 endpoint>", "<step 2 endpoint>", ...],
      "invariants": [
        "<business rule that must always hold, e.g. 'payment must complete before order confirmed'>",
        ...
      ]
    }}
  ],
  "trust_boundaries": {{
    "public": ["<path prefix or endpoint>", ...],
    "authenticated": ["<path prefix or endpoint>", ...],
    "privileged": ["<path prefix or endpoint>", ...]
  }},
  "sensitive_objects": [
    {{
      "name": "<object type, e.g. Order, Cart, Profile>",
      "owner_field": "<field that identifies the owner, e.g. user_id>",
      "endpoints": ["<endpoint that exposes this object>", ...],
      "contains": ["<sensitive data this object holds>"]
    }}
  ]
}}

Rules:
- Respond with ONLY the JSON object. No prose, no markdown, no code fences.
- Infer flows from the endpoint set — only include flows supported by the endpoints.
- Each invariant must be testable: phrase it as something a scanner can try to violate.
- Limit to the 5 most important flows and 3 most critical invariants per flow.
- Limit sensitive_objects to the 6 most important owned object types.
"""

    def _parse_intent_response(self, raw_text: str) -> None:
        """Parse LLM JSON into AppModel semantic fields."""
        import re as _re
        text = raw_text.strip()
        # Strip markdown fences
        text = _re.sub(r"^```(?:json)?\s*", "", text, flags=_re.MULTILINE)
        text = _re.sub(r"\s*```$", "", text, flags=_re.MULTILINE).strip()
        try:
            data = json.loads(text)
        except json.JSONDecodeError as exc:
            log.warning("_parse_intent_response: JSON parse failed: %s | raw=%r", exc, raw_text[:200])
            return

        self._model.primary_flows    = data.get("primary_flows", [])
        self._model.invariants = [
            {"flow": f["name"], "rule": inv, "test_approach": "invariant_violation"}
            for f in self._model.primary_flows
            for inv in f.get("invariants", [])
        ]
        self._model.trust_boundaries = data.get("trust_boundaries", {})
        self._model.sensitive_objects = data.get("sensitive_objects", [])
        self._model.intent_built = True

    def detect_authentication_flows(
        self,
        urls: list[str] | None = None,
        alive_hosts: list[dict] | None = None,
    ) -> list[AuthFlow]:
        """
        Detect authentication mechanisms from URL patterns and HTTP headers.
        Returns one AuthFlow per detected mechanism (may detect multiple).
        """
        flows: list[AuthFlow] = []
        urls = urls or self._load_urls()
        alive_hosts = alive_hosts or self._load_alive_hosts()

        # Collect all headers from alive_hosts
        all_headers: dict[str, str] = {}
        for host in (alive_hosts or []):
            all_headers.update(
                {k.lower(): v for k, v in host.get("headers", {}).items()}
            )

        # ── JWT detection ──
        jwt_signals: list[str] = []
        if "authorization" in all_headers:
            v = all_headers["authorization"]
            if _BEARER_PATTERN.search(v) or _JWT_PATTERN.search(v):
                jwt_signals.append("Authorization: Bearer header")
        if any("/token" in u or "/refresh" in u or "jwt" in u.lower() for u in (urls or [])):
            jwt_signals.append("Token/refresh endpoint in URL set")
        if jwt_signals:
            auth_eps = [u for u in (urls or []) if any(
                k in u.lower() for k in ["/login", "/token", "/refresh", "/logout"]
            )]
            flows.append(AuthFlow(
                auth_type="jwt",
                token_locations=["header"],
                endpoints=auth_eps[:10],
                token_header="Authorization",
                notes=jwt_signals,
            ))

        # ── OAuth2 / OIDC detection ──
        oauth_signals: list[str] = []
        for url in (urls or []):
            parsed = urlparse(url)
            params = set(parse_qs(parsed.query).keys())
            if params & _OAUTH_PARAMS:
                oauth_signals.append(f"OAuth params in: {url[:80]}")
        if any("/oauth" in u or "/oidc" in u or "/authorize" in u for u in (urls or [])):
            oauth_signals.append("OAuth/OIDC endpoints detected")
        if oauth_signals:
            flows.append(AuthFlow(
                auth_type="oauth2",
                token_locations=["header", "query"],
                endpoints=[u for u in (urls or []) if "/oauth" in u or "/authorize" in u][:5],
                notes=oauth_signals[:3],
            ))

        # ── Session / Cookie detection ──
        session_cookies = []
        for host in (alive_hosts or []):
            for k in host.get("headers", {}).keys():
                if "set-cookie" in k.lower():
                    v = host["headers"][k]
                    cookies = [c.strip().split("=")[0] for c in v.split(";")]
                    session_cookies.extend(
                        c for c in cookies
                        if any(s in c.lower() for s in ["session", "sid", "auth", "token", "csrf"])
                    )
        if session_cookies or any(
            "/login" in u or "/signin" in u for u in (urls or [])
        ):
            flows.append(AuthFlow(
                auth_type="session",
                token_locations=["cookie"],
                endpoints=[u for u in (urls or []) if "/login" in u or "/signin" in u][:5],
                cookie_names=list(set(session_cookies)),
                notes=["Session cookies detected"],
            ))

        # ── API Key detection ──
        api_key_signals = [
            h for h in all_headers if h in _API_KEY_HEADERS and h != "authorization"
        ]
        if api_key_signals:
            flows.append(AuthFlow(
                auth_type="api_key",
                token_locations=["header", "query"],
                endpoints=[],
                token_header=api_key_signals[0] if api_key_signals else "",
                notes=[f"API key header: {', '.join(api_key_signals)}"],
            ))

        # ── SAML detection ──
        if any("/saml" in u or "/sso" in u for u in (urls or [])):
            flows.append(AuthFlow(
                auth_type="saml",
                token_locations=["body", "cookie"],
                endpoints=[u for u in (urls or []) if "/saml" in u or "/sso" in u][:5],
                notes=["SAML/SSO endpoints detected"],
            ))

        # Default: no auth detected
        if not flows:
            flows.append(AuthFlow(
                auth_type="none",
                token_locations=[],
                endpoints=[],
                notes=["No authentication mechanism detected"],
            ))

        return flows

    def identify_sensitive_features(
        self,
        urls: list[str] | None = None,
        alive_hosts: list[dict] | None = None,
    ) -> list[SensitiveFeature]:
        """
        Scan URL set and HTTP responses for sensitive application features.
        Returns one SensitiveFeature per detected category.
        """
        urls = urls or self._load_urls()
        features: dict[str, SensitiveFeature] = {}

        for url in (urls or []):
            parsed = urlparse(url)
            path = parsed.path

            for pattern, name, category, risk in _SENSITIVE_PATH_PATTERNS:
                if pattern.search(path):
                    if category not in features:
                        features[category] = SensitiveFeature(
                            name=name,
                            category=category,
                            endpoints=[],
                            risk_level=risk,
                        )
                    if url not in features[category].endpoints:
                        features[category].endpoints.append(url)

        # Detect file upload from response content types
        for host in (alive_hosts or []):
            ct = host.get("content_type", "")
            if "multipart" in ct:
                key = "file_upload"
                if key not in features:
                    features[key] = SensitiveFeature(
                        name="File Upload", category="file",
                        endpoints=[], risk_level="high",
                    )

        return list(features.values())

    # ── Private helpers ───────────────────────────────────────────────────────

    def _load_urls(self) -> list[str]:
        search_dirs = [self.output_dir, self.output_dir / "recon"]
        for fname in ["urls.json", "endpoints.json"]:
            for d in search_dirs:
                f = d / fname
                if f.exists():
                    try:
                        data = json.loads(f.read_text())
                        if isinstance(data, list):
                            return data
                        return data.get("urls", data.get("endpoints", []))
                    except Exception:
                        pass
        return []

    def _load_alive_hosts(self) -> list[dict]:
        search_dirs = [self.output_dir, self.output_dir / "recon"]
        for d in search_dirs:
            f = d / "alive_hosts.json"
            if f.exists():
                try:
                    data = json.loads(f.read_text())
                    if isinstance(data, dict):
                        return data.get("hosts", [])
                    return data if isinstance(data, list) else []
                except Exception:
                    pass
        return []

    def _load_tech_profile(self) -> dict:
        search_dirs = [self.output_dir, self.output_dir / "recon"]
        for fname in ["tech_profile.json", "adaptive_recon.json"]:
            for d in search_dirs:
                f = d / fname
                if f.exists():
                    try:
                        return json.loads(f.read_text())
                    except Exception:
                        pass
        return {}

    def _ingest_tech_profile(self, tech: dict, alive_hosts: list[dict]):
        if isinstance(tech, dict):
            tp = tech.get("tech_profile", tech)
            self._model.frameworks = _coerce_list(tp.get("frameworks", []))
            self._model.tech_stack = _coerce_list(
                tp.get("raw_tech", tp.get("technologies", []))
            )
            server = tp.get("server", "")
            if not server:
                for host in (alive_hosts or []):
                    server = host.get("webserver", "")
                    if server:
                        break
            self._model.server = server

    def _parse_url_structure(self, urls: list[str]):
        """Extract API paths, versions, parameters, and ID params."""
        api_paths: set[str] = set()
        api_versions: set[str] = set()
        api_base_paths: set[str] = set()
        file_upload_eps: list[str] = []
        export_eps: list[str] = []
        redirect_eps: list[str] = []
        all_params: dict[str, list[str]] = {}
        id_params: dict[str, list[str]] = {}

        _api_version_re = re.compile(r"/(v\d+)/", re.I)
        _api_base_re = re.compile(r"^(/api|/rest|/graphql|/gql|/v\d+)", re.I)

        for url in urls:
            parsed = urlparse(url)
            path = parsed.path

            # API structure
            api_paths.add(path)
            m = _api_version_re.search(path)
            if m:
                api_versions.add(m.group(1))
            bm = _api_base_re.match(path)
            if bm:
                api_base_paths.add(bm.group(1))

            # Parameters
            params = list(parse_qs(parsed.query).keys())
            if params:
                all_params.setdefault(path, [])
                for p in params:
                    if p not in all_params[path]:
                        all_params[path].append(p)

                # ID params
                id_ps = [p for p in params if _ID_PARAM_PATTERNS.search(p)]
                if id_ps:
                    id_params.setdefault(path, [])
                    id_params[path].extend(
                        p for p in id_ps if p not in id_params[path]
                    )

            # Special endpoint classification
            pl = path.lower()
            if any(k in pl for k in ["upload", "import", "attach"]):
                file_upload_eps.append(url)
            if any(k in pl for k in ["export", "download", "dump", "backup"]):
                export_eps.append(url)
            if any(k in pl for k in ["redirect", "callback", "return_url", "next="]):
                redirect_eps.append(url)

        self._model.api_structure = sorted(api_paths)
        self._model.api_versions = sorted(api_versions)
        self._model.api_base_paths = sorted(api_base_paths)
        self._model.all_parameters = all_params
        self._model.id_parameters = id_params
        self._model.file_upload_endpoints = list(set(file_upload_eps))
        self._model.export_endpoints = list(set(export_eps))
        self._model.redirect_endpoints = list(set(redirect_eps))

    def _detect_roles(self, urls: list[str], alive_hosts: list[dict]):
        """Infer user roles from URL paths and response bodies."""
        roles: set[str] = set()
        for url in (urls or []):
            for role in _ROLE_KEYWORDS:
                if re.search(rf"\b{role}\b", url, re.I):
                    roles.add(role)
        for host in (alive_hosts or []):
            body = host.get("body", "")
            for role in _ROLE_KEYWORDS:
                if re.search(rf"\b{role}\b", body, re.I):
                    roles.add(role)
        self._model.user_roles = sorted(roles)


# ── Utility ───────────────────────────────────────────────────────────────────

def _coerce_list(v: Any) -> list:
    if isinstance(v, list):
        return v
    if isinstance(v, str) and v:
        return [v]
    return []


def build_app_model(target: str, output_dir: str = "") -> AppModel:
    """Convenience wrapper — build model from disk recon data."""
    engine = ApplicationIntelligenceEngine(target, output_dir)
    return engine.analyze_application_structure()


def load_app_model(output_dir: str) -> Optional[AppModel]:
    """Load a previously saved AppModel from disk."""
    p = Path(output_dir) / "app_model.json"
    if p.exists():
        try:
            return AppModel.from_dict(json.loads(p.read_text()))
        except Exception:
            return None
    return None


# ── CLI entry point ───────────────────────────────────────────────────────────

def main_cli(args):
    from oneinfinity.modules.utils import banner, section, ok, info, warn
    target = args.domain
    output = resolve_output_dir(getattr(args, "output", None), target)
    banner(f"Application Intelligence — {target}")
    info(f"Output dir: {output}")

    engine = ApplicationIntelligenceEngine(target, output)
    model = engine.analyze_application_structure()

    section("Authentication")
    print(f"  Auth system : {model.auth_system}")
    for af in model.auth_flows:
        print(f"  └─ {af.auth_type} ({', '.join(af.token_locations)})")
        for n in af.notes[:2]:
            print(f"       {n}")

    section("API Structure")
    print(f"  {len(model.api_structure)} paths, versions: {', '.join(model.api_versions) or 'none'}")
    for path in model.api_structure[:20]:
        print(f"  {path}")
    if len(model.api_structure) > 20:
        print(f"  … and {len(model.api_structure) - 20} more")

    section("User Roles")
    print(f"  {', '.join(model.user_roles) or 'none detected'}")

    section("Sensitive Endpoints")
    for sf in model.sensitive_features:
        risk_color = {"critical": "\033[0;31m", "high": "\033[0;33m",
                      "medium": "\033[0;36m", "low": "\033[0;37m"}.get(sf.risk_level, "")
        reset = "\033[0m"
        print(f"  {risk_color}[{sf.risk_level.upper()}]{reset} {sf.name} ({len(sf.endpoints)} endpoints)")
        for ep in sf.endpoints[:3]:
            print(f"    {ep}")

    section("Parameters with ID fields")
    for path, params in list(model.id_parameters.items())[:10]:
        print(f"  {path} → {', '.join(params)}")

    ok(f"App model saved: {output}/app_model.json")
    print()
    return model
