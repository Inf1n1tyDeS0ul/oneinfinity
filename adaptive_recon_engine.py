"""
Adaptive Recon Intelligence Engine
====================================
Dynamically adapts reconnaissance strategy based on discovered technologies,
infrastructure, and attack surface characteristics — behaving like an
experienced bug bounty hunter who adjusts tactics based on findings.

Usage (standalone):
    engine = AdaptiveReconEngine("example.com")
    intel = engine.run()
    print(intel.to_json())

CLI:
    oneinfinity adaptive-recon example.com
    oneinfinity adaptive-recon example.com --output ~/.oneinfinity/raw/example.com --depth deep
"""

from __future__ import annotations

import json
import re
import ssl
import time
import urllib.error
import urllib.parse
import urllib.request
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import asdict, dataclass, field
from pathlib import Path

from path_manager import resolve_output_dir
from typing import Optional


# ── Colour helpers (no dependencies) ─────────────────────────────────────────

def _c(code: str, text: str) -> str:
    return f"\033[{code}m{text}\033[0m"

def _ok(msg: str):   print(f"  \033[0;32m[+]\033[0m {msg}", flush=True)
def _info(msg: str): print(f"  \033[0;36m[*]\033[0m {msg}", flush=True)
def _warn(msg: str): print(f"  \033[0;33m[!]\033[0m {msg}", flush=True)


# ══════════════════════════════════════════════════════════════════════════════
# DATA MODELS
# ══════════════════════════════════════════════════════════════════════════════

@dataclass
class TechProfile:
    """Detected technology stack."""
    frontend:   str = ""            # React, Next.js, Angular, Vue, Nuxt
    backend:    str = ""            # Node.js, Django, Laravel, Rails, Spring
    cloud:      str = ""            # AWS, GCP, Azure
    waf:        str = ""            # Cloudflare, AWS WAF, Akamai, F5
    cdn:        str = ""            # CloudFront, Fastly, Akamai
    database:   str = ""            # MySQL, PostgreSQL, MongoDB, Redis
    auth:       list[str] = field(default_factory=list)    # JWT, OAuth2, SAML
    frameworks: list[str] = field(default_factory=list)    # Express, Flask, etc.
    languages:  list[str] = field(default_factory=list)    # PHP, Python, Go, etc.
    cms:        str = ""            # WordPress, Drupal, Ghost
    raw_tech:   list[str] = field(default_factory=list)    # all detected labels


@dataclass
class APIEndpoint:
    path: str
    method: str = "GET"
    params: list[str] = field(default_factory=list)
    auth_required: bool = False
    source: str = ""                # "url_pattern" | "js" | "nuclei" | "crawl"


@dataclass
class APIMap:
    """Discovered API surface."""
    base_paths:   list[str] = field(default_factory=list)   # /api, /v1, /graphql
    endpoints:    list[APIEndpoint] = field(default_factory=list)
    has_graphql:  bool = False
    has_rest:     bool = False
    has_grpc:     bool = False
    api_versions: list[str] = field(default_factory=list)   # v1, v2, v3
    auth_schemes: list[str] = field(default_factory=list)   # Bearer, X-Api-Key
    mobile_api:   bool = False      # /mobile/, /m/, or user-agent hints


@dataclass
class CloudAssets:
    """Discovered cloud infrastructure."""
    provider:          str = ""
    s3_buckets:        list[str] = field(default_factory=list)
    cloudfront_ids:    list[str] = field(default_factory=list)
    gcs_buckets:       list[str] = field(default_factory=list)
    azure_resources:   list[str] = field(default_factory=list)
    cloud_functions:   list[str] = field(default_factory=list)
    exposed_metadata:  bool = False   # IMDSv1/GCP metadata accessible
    open_buckets:      list[str] = field(default_factory=list)   # publicly readable
    lambda_endpoints:  list[str] = field(default_factory=list)


@dataclass
class ReconTask:
    """A recommended recon/attack task with metadata."""
    task_id:     str
    title:       str
    description: str
    priority:    str           # critical | high | medium | low
    category:    str           # api | cloud | auth | injection | misc
    commands:    list[str] = field(default_factory=list)
    reason:      str = ""      # why this task was recommended


@dataclass
class ReconIntelligence:
    """Full adaptive recon result."""
    target:             str
    scan_duration_s:    float = 0.0
    technologies:       list[str] = field(default_factory=list)   # flat list for JSON compat
    tech_profile:       TechProfile = field(default_factory=TechProfile)
    alive_hosts:        list[dict] = field(default_factory=list)  # httpx results
    all_urls:           list[str] = field(default_factory=list)   # discovered URLs
    apis:               list[str] = field(default_factory=list)   # base API paths
    api_map:            APIMap = field(default_factory=APIMap)
    hidden_endpoints:   list[str] = field(default_factory=list)
    cloud_assets:       CloudAssets = field(default_factory=CloudAssets)
    recommended_tests:  list[str] = field(default_factory=list)   # task_ids
    recon_strategy:     dict = field(default_factory=dict)
    tasks:              list[ReconTask] = field(default_factory=list)
    attack_surface_score: int = 0    # 0-100 rough complexity score

    def to_dict(self) -> dict:
        d = asdict(self)
        # Flatten tech_profile for top-level "technologies" key
        d["technologies"] = self.tech_profile.raw_tech or list(filter(None, [
            self.tech_profile.frontend, self.tech_profile.backend,
            self.tech_profile.cloud, self.tech_profile.waf,
            self.tech_profile.cdn, self.tech_profile.cms,
        ]))
        d["apis"] = self.api_map.base_paths
        d["recommended_tests"] = [t.task_id for t in self.tasks]
        return d

    def to_json(self, indent: int = 2) -> str:
        return json.dumps(self.to_dict(), indent=indent, default=str)

    def summary_lines(self) -> list[str]:
        lines = [f"Target: {self.target}"]
        if self.tech_profile.frontend:
            lines.append(f"Frontend: {self.tech_profile.frontend}")
        if self.tech_profile.backend:
            lines.append(f"Backend: {self.tech_profile.backend}")
        if self.tech_profile.cloud:
            lines.append(f"Cloud: {self.tech_profile.cloud}")
        if self.tech_profile.waf:
            lines.append(f"WAF: {self.tech_profile.waf}")
        if self.api_map.has_graphql:
            lines.append("GraphQL API detected")
        if self.api_map.has_rest:
            lines.append(f"REST API — {len(self.api_map.base_paths)} base paths")
        if self.hidden_endpoints:
            lines.append(f"Hidden endpoints from JS: {len(self.hidden_endpoints)}")
        if self.cloud_assets.open_buckets:
            lines.append(f"⚠ OPEN BUCKETS: {', '.join(self.cloud_assets.open_buckets)}")
        return lines


# ══════════════════════════════════════════════════════════════════════════════
# TECHNOLOGY SIGNATURES — static knowledge base
# ══════════════════════════════════════════════════════════════════════════════

# Each entry: (field_name, tech_label, list_of_patterns_to_match)
# Patterns checked against: URL paths, headers (k:v), HTML body, JS content
_TECH_SIGS: list[tuple[str, str, list[str]]] = [
    # ── Frontend ──────────────────────────────────────────────────────────
    ("frontend", "Next.js",   ["__NEXT_DATA__", "/_next/", "_next/static",
                                "next/dist/client", "\"buildId\""]),
    ("frontend", "Nuxt.js",   ["__nuxt", "_nuxt/", "window.__NUXT__"]),
    ("frontend", "React",     ["data-reactroot", "data-reactid", "react.production.min.js",
                                "__webpack_require__", "ReactDOM.render"]),
    ("frontend", "Vue.js",    ["vue.runtime.min.js", "data-v-", "__vue__",
                                "Vue.component(", "<div id=\"app\""]),
    ("frontend", "Angular",   ["ng-app=", "ng-controller=", "angular.min.js",
                                "platformBrowserDynamic", "@angular/core"]),
    ("frontend", "Svelte",    ["svelte-", "__SAPPER__", "Svelte"]),
    ("frontend", "Ember.js",  ["ember.min.js", "Ember.Application"]),
    ("frontend", "jQuery",    ["jquery.min.js", "jQuery(", "$(document).ready"]),

    # ── Backend / Framework ────────────────────────────────────────────────
    ("backend", "Node.js",    ["x-powered-by:express", "x-powered-by:node",
                                "x-powered-by:feathers", "node_modules/"]),
    ("backend", "Express.js", ["x-powered-by:express"]),
    ("backend", "Django",     ["csrfmiddlewaretoken", "x-csrftoken",
                                "django.contrib", "__admin/", "wsgi.py"]),
    ("backend", "FastAPI",    ["/docs#/", "/redoc", "FastAPI", "pydantic"]),
    ("backend", "Flask",      ["Werkzeug/", "x-powered-by:flask",
                                "from flask import", "flask.pocoo.org"]),
    ("backend", "Laravel",    ["laravel_session", "X-XSRF-TOKEN", "XSRF-TOKEN",
                                "laravel.com", "x-powered-by:php", "artisan"]),
    ("backend", "Rails",      ["X-Powered-By:Phusion", "_rails_", "csrf-token",
                                "rails/ujs", "data-turbolinks"]),
    ("backend", "Spring",     ["X-Application-Context", "spring.io",
                                "WhitelabelError", "springSecurityCheck"]),
    ("backend", "ASP.NET",    ["X-AspNet-Version", "X-AspNetMvc-Version",
                                "__RequestVerificationToken", "asp.net"]),
    ("backend", "PHP",        ["x-powered-by:php", ".php?", "PHPSESSID"]),
    ("backend", "Go",         ["x-powered-by:go", "Go-http-client", "golang"]),
    ("backend", "Rust",       ["actix-web", "rocket.rs", "x-powered-by:actix"]),

    # ── CMS ───────────────────────────────────────────────────────────────
    ("cms", "WordPress",    ["/wp-content/", "/wp-includes/", "wp-login.php",
                              "wp-admin", "WordPress"]),
    ("cms", "Drupal",       ["/sites/default/files/", "Drupal.settings",
                              "drupal.org", "X-Generator:Drupal"]),
    ("cms", "Joomla",       ["/components/com_", "Joomla!", "/administrator/"]),
    ("cms", "Ghost",        ["ghost.org", "/ghost/api/", "x-ghost-cache"]),
    ("cms", "Strapi",       ["/strapi/", "strapi.io", "Strapi"]),

    # ── Cloud / Infra ──────────────────────────────────────────────────────
    ("cloud", "AWS",        ["x-amz-", "amazonaws.com", "cloudfront.net",
                              "x-amz-request-id", "aws-cdk", "AmazonS3"]),
    ("cloud", "GCP",        ["googleapis.com", "x-goog-", "storage.googleapis.com",
                              "appspot.com", "cloudfunctions.net"]),
    ("cloud", "Azure",      ["azure.com", "azurewebsites.net", "x-ms-",
                              "blob.core.windows.net", "azurecontainer.io"]),
    ("cloud", "Vercel",     ["x-vercel-", "vercel.app", "vercel.com"]),
    ("cloud", "Netlify",    ["x-nf-", "netlify.app", ".netlify.com"]),
    ("cloud", "Heroku",     ["heroku.com", "x-heroku-", ".herokuapp.com"]),

    # ── CDN ───────────────────────────────────────────────────────────────
    ("cdn", "Cloudflare",   ["x-powered-by:cloudflare", "cf-ray:", "__cfduid",
                              "cloudflare", "CF-Cache-Status"]),
    ("cdn", "Fastly",       ["x-served-by:cache-", "fastly.com", "Fastly-Debug"]),
    ("cdn", "CloudFront",   ["x-amz-cf-id:", "via:CloudFront", "cloudfront.net",
                              "X-Cache:Hit from cloudfront"]),
    ("cdn", "Akamai",       ["x-akamai-", "akamaihd.net", "x-check-cacheable"]),

    # ── WAF ───────────────────────────────────────────────────────────────
    ("waf", "Cloudflare WAF",  ["cloudflare", "cf-ray", "attention required"]),
    ("waf", "AWS WAF",         ["x-amzn-waf-", "x-amzn-requestid", "awselb"]),
    ("waf", "Imperva/Incapsula",["X-Iinfo:", "visid_incap_", "nlbi_", "incapsula"]),
    ("waf", "F5 BIG-IP",       ["TS01", "BigIP", "F5_ST", "x-via:trafficserver"]),
    ("waf", "ModSecurity",     ["mod_security", "NOYB", "406 Not Acceptable"]),

    # ── Auth / Identity ────────────────────────────────────────────────────
    ("auth", "JWT",         ["eyJ", "bearer eyJ", "authorization:bearer"]),
    ("auth", "OAuth2",      ["oauth", "access_token", "refresh_token",
                              "client_id=", "/oauth2/", "/authorize?"]),
    ("auth", "SAML",        ["SAMLRequest", "SAMLResponse", "sso.saml"]),
    ("auth", "LDAP",        ["ldap://", "ldaps://", "Active Directory"]),
    ("auth", "Okta",        ["okta.com", ".okta.", "dev-*.okta"]),
    ("auth", "Auth0",       ["auth0.com", ".auth0.com", "auth0.js"]),
    ("auth", "Keycloak",    ["keycloak", "/auth/realms/"]),

    # ── Database hints ─────────────────────────────────────────────────────
    ("database", "MongoDB",     ["mongodb://", "ObjectId(", "mongoose"]),
    ("database", "PostgreSQL",  ["pg_", "psycopg", "PostgreSQL"]),
    ("database", "MySQL",       ["mysql://", "mysqli", "MySQL"]),
    ("database", "Redis",       ["redis://", "RedisClient", ":6379"]),
    ("database", "Elasticsearch", ["_elasticsearch", "elastic.co", ":9200"]),
    ("database", "Firebase",    ["firebaseapp.com", "firestore", "googleapis.com/firebase"]),
]

# ── Vulnerability mapping: tech → priority attack types ──────────────────────
TECH_TO_ATTACKS: dict[str, list[tuple[str, str, str]]] = {
    # (task_id, title, priority)
    "Next.js":   [("nextjs_routes",    "Enumerate Next.js API routes (/api/*)",       "high"),
                  ("nextjs_ssr",       "Test SSR data leakage in getServerSideProps", "high"),
                  ("nextjs_sourcemap", "Check .map files for source code exposure",    "medium")],
    "React":     [("react_devtools",   "Check React DevTools exposure",               "medium"),
                  ("react_props",      "Inspect component props for sensitive data",   "medium")],
    "Angular":   [("angular_ssti",     "Test Angular template injection",              "high"),
                  ("angular_dom_xss",  "DOM-based XSS via AngularJS expressions",     "high")],
    "Vue.js":    [("vue_ssti",         "Test Vue.js template injection",              "high")],
    "GraphQL":   [("gql_introspect",   "GraphQL introspection query (schema leak)",   "critical"),
                  ("gql_injection",    "GraphQL argument injection/SQLi",             "critical"),
                  ("gql_batch",        "Batch query abuse / rate-limit bypass",       "high"),
                  ("gql_idor",         "IDOR via numeric/UUID node IDs",             "high"),
                  ("gql_subscription", "WebSocket/subscription endpoint testing",     "medium")],
    "Django":    [("django_admin",     "Probe /admin/ for exposed Django admin panel","critical"),
                  ("django_debug",     "Check DEBUG=True: /404, /__debug__",         "critical"),
                  ("django_ssti",      "Template injection in user-controlled fields","high"),
                  ("django_sqli",      "SQLi via ORM raw() queries",                 "high")],
    "Flask":     [("flask_debug",      "Werkzeug debugger pin brute-force (/console)","critical"),
                  ("flask_ssti",       "Jinja2 SSTI — {{7*7}} in all input fields",  "critical")],
    "Laravel":   [("laravel_debug",    "Laravel debug page — APP_DEBUG=true",        "critical"),
                  ("laravel_env",      "/.env exposure — DB creds, APP_KEY",         "critical"),
                  ("laravel_massassign","Mass assignment via guarded=[]/fillable=[]", "high")],
    "ASP.NET":   [("aspnet_viewstate","ViewState deserialization attack",             "high"),
                  ("aspnet_trace",     "Trace.axd / elmah.axd information leakage",  "high")],
    "WordPress": [("wp_xmlrpc",        "XML-RPC brute force / pingback SSRF",        "high"),
                  ("wp_userenum",      "Username enumeration via /?author=1",        "medium"),
                  ("wp_plugins",       "Vulnerable plugin detection (wpscan)",       "critical"),
                  ("wp_rest",          "WordPress REST API /wp-json/ data leak",     "high")],
    "Drupal":    [("drupal_sa",        "Drupalgeddon2 RCE check (SA-CORE-2018-002)", "critical"),
                  ("drupal_admin",     "Probe /admin, /user, /node paths",           "high")],
    "Spring":    [("spring_actuator",  "Spring Boot Actuator endpoints exposure",    "critical"),
                  ("spring_el",        "SpEL injection in expression fields",        "high")],
    "Node.js":   [("proto_pollution",  "Prototype pollution via JSON merge params",  "high"),
                  ("nosql_inject",     "NoSQL injection in MongoDB query objects",   "high"),
                  ("path_traversal",   "Path traversal in static file serving",      "medium")],
    "PHP":       [("php_objinject",    "PHP object injection via unserialize()",     "critical"),
                  ("php_lfi",          "Local file inclusion via include/require",   "high")],
    "AWS":       [("s3_buckets",       "Enumerate/test S3 bucket permissions",       "critical"),
                  ("imds_ssrf",        "SSRF to AWS IMDSv1 (169.254.169.254)",       "critical"),
                  ("iam_enum",         "IAM role / credential exposure via SSRF",   "critical"),
                  ("lambda_expose",    "Lambda function URL exposure",              "high"),
                  ("ecr_public",       "Public ECR registry image enumeration",     "medium")],
    "GCP":       [("gcp_metadata",     "SSRF to GCP metadata (metadata.google.internal)","critical"),
                  ("gcs_buckets",      "Enumerate GCS bucket permissions",           "critical")],
    "Azure":     [("azure_metadata",   "SSRF to Azure IMDS (169.254.169.254/metadata)","critical"),
                  ("blob_storage",     "Azure Blob Storage public access check",    "high")],
    "JWT":       [("jwt_none",         "JWT 'none' algorithm attack",               "critical"),
                  ("jwt_alg_confusion","RS256→HS256 algorithm confusion",            "critical"),
                  ("jwt_weak_secret",  "JWT weak HMAC secret brute force",         "high")],
    "OAuth2":    [("oauth_redirect",   "Open redirect in OAuth redirect_uri",       "critical"),
                  ("oauth_state",      "Missing/weak state parameter (CSRF)",       "high"),
                  ("oauth_token_leak", "Token leakage via Referer header",          "high")],
    "SAML":      [("saml_xml_sig",     "SAML XML signature wrapping attack",        "critical"),
                  ("saml_xxe",         "XXE via SAML assertion processing",         "high")],
    "MongoDB":   [("nosql_inject",     "NoSQL injection ($where, $gt, $ne)",        "critical")],
    "Firebase":  [("firebase_rules",   "Firebase misconfigured security rules",     "critical"),
                  ("firebase_rtdb",    "Firebase Realtime DB unauthenticated read", "critical")],
    "Elasticsearch": [("es_exposure",  "Unauthenticated Elasticsearch API (:9200)", "critical")],
    "Cloudflare":    [("cf_origin",    "Discover true origin IP behind Cloudflare", "medium"),
                      ("cf_bypass",    "WAF bypass via encoding/header tricks",     "medium")],
}


# ══════════════════════════════════════════════════════════════════════════════
# TECH DETECTOR
# ══════════════════════════════════════════════════════════════════════════════

class TechDetector:
    """
    Multi-signal technology detection.
    Signals: httpx results (headers + tech field), HTML body, URL patterns.
    """

    def detect(
        self,
        target: str,
        alive_hosts: list[dict] = None,
        html_content: str = "",
        extra_headers: dict = None,
    ) -> TechProfile:
        profile = TechProfile()
        all_signals: list[str] = []

        # 1. httpx "tech" field (already detected by httpx)
        for host in (alive_hosts or []):
            for t in host.get("tech", []):
                all_signals.append(t.lower())
            # Headers from httpx output
            for hk, hv in host.get("headers", {}).items():
                all_signals.append(f"{hk.lower()}:{hv.lower()}")

        # 2. Extra headers
        for hk, hv in (extra_headers or {}).items():
            all_signals.append(f"{hk.lower()}:{hv.lower()}")

        # 3. HTML body fragments
        if html_content:
            all_signals.append(html_content.lower())

        signals_blob = " ".join(all_signals)

        # Apply signature matching
        matched_by_field: dict[str, list[str]] = {}
        for field_name, label, patterns in _TECH_SIGS:
            for pat in patterns:
                if pat.lower() in signals_blob:
                    matched_by_field.setdefault(field_name, [])
                    if label not in matched_by_field[field_name]:
                        matched_by_field[field_name].append(label)
                    break

        # Fill profile — for multi-value fields keep list; for single take first
        for fname, labels in matched_by_field.items():
            if fname in ("auth",):
                getattr(profile, fname).extend(labels)
            elif fname == "frameworks":
                profile.frameworks.extend(labels)
            elif fname == "languages":
                profile.languages.extend(labels)
            else:
                if not getattr(profile, fname):
                    setattr(profile, fname, labels[0])
            for lbl in labels:
                if lbl not in profile.raw_tech:
                    profile.raw_tech.append(lbl)

        # Incorporate httpx tech labels directly
        for host in (alive_hosts or []):
            for t in host.get("tech", []):
                if t not in profile.raw_tech:
                    profile.raw_tech.append(t)

        return profile

    def fetch_and_detect(self, url: str, timeout: int = 10) -> tuple[TechProfile, str]:
        """Fetch URL and run detection. Returns (TechProfile, html_body)."""
        try:
            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
            req = urllib.request.Request(
                url,
                headers={"User-Agent": "Mozilla/5.0 (OneInfinity AdaptiveRecon/2.0)"},
            )
            with urllib.request.urlopen(req, timeout=timeout, context=ctx) as resp:
                headers = dict(resp.headers)
                body = resp.read(200_000).decode("utf-8", errors="replace")
            profile = self.detect("", html_content=body, extra_headers=headers)
            return profile, body
        except Exception:
            return TechProfile(), ""


# ══════════════════════════════════════════════════════════════════════════════
# API INTELLIGENCE
# ══════════════════════════════════════════════════════════════════════════════

# Regex to classify URL paths as API-related
_API_PATH_RE = re.compile(
    r"(/(?:api|graphql|gql|grpc|rpc|rest|services?|v\d+|internal|mobile|m|app|backend)"
    r"(?:/[a-zA-Z0-9_\-/]*)?)(?:[?#]|$)",
    re.IGNORECASE,
)
_VERSION_RE = re.compile(r"/v(\d+)/", re.IGNORECASE)
_AUTH_HEADER_RE = re.compile(
    r"authorization:\s*(bearer|basic|apikey|x-api-key|token)",
    re.IGNORECASE,
)


class APIIntelligence:
    """Identify and classify API endpoints from URL sets."""

    def detect_api_endpoints(self, urls: list[str]) -> list[str]:
        """Return unique API base paths found in URL list."""
        found: set[str] = set()
        for url in urls:
            try:
                parsed = urllib.parse.urlparse(url)
                m = _API_PATH_RE.match(parsed.path)
                if m:
                    # Normalise to base path (first 2 segments)
                    parts = [p for p in m.group(1).split("/") if p]
                    base = "/" + "/".join(parts[:2])
                    found.add(base)
            except Exception:
                pass
        return sorted(found)

    def map_api_structure(self, urls: list[str]) -> APIMap:
        api_map = APIMap()
        api_map.base_paths = self.detect_api_endpoints(urls)

        versions: set[str] = set()
        has_mobile_hints = False

        for url in urls:
            try:
                parsed = urllib.parse.urlparse(url)
                path_lower = parsed.path.lower()

                # GraphQL detection
                if any(k in path_lower for k in ["/graphql", "/gql", "/graph"]):
                    api_map.has_graphql = True

                # gRPC detection
                if "/grpc" in path_lower or "/rpc" in path_lower:
                    api_map.has_grpc = True

                # REST detection
                if _API_PATH_RE.search(path_lower):
                    api_map.has_rest = True

                # Version detection
                for m in _VERSION_RE.finditer(path_lower):
                    versions.add(f"v{m.group(1)}")

                # Mobile API hints
                if any(k in path_lower for k in ["/mobile", "/m/", "/app/", "/ios/",
                                                   "/android/", "/native/"]):
                    has_mobile_hints = True

                # Endpoint classification
                if _API_PATH_RE.search(parsed.path):
                    ep = APIEndpoint(
                        path=parsed.path,
                        params=list(urllib.parse.parse_qs(parsed.query).keys()),
                        source="url_pattern",
                    )
                    api_map.endpoints.append(ep)

            except Exception:
                pass

        api_map.api_versions = sorted(versions)
        api_map.mobile_api = has_mobile_hints

        # Detect versioned deprecation surface
        if len(api_map.api_versions) > 1:
            api_map.auth_schemes.append("deprecated-version-surface")

        return api_map


# ══════════════════════════════════════════════════════════════════════════════
# JAVASCRIPT INTELLIGENCE
# ══════════════════════════════════════════════════════════════════════════════

# Patterns to extract endpoint-like strings from JS
_JS_ENDPOINT_PATTERNS: list[re.Pattern] = [
    # fetch("path") / fetch('path')
    re.compile(r"""fetch\s*\(\s*["'`](/?[a-zA-Z0-9_\-/:%?&=.#]{4,200})["'`]"""),
    # axios.get/post/put/delete/patch("path")
    re.compile(r"""axios\s*\.\s*(?:get|post|put|delete|patch|request)\s*\(\s*["'`](/?[a-zA-Z0-9_\-/:%?&=.#]{4,200})["'`]"""),
    # $http.get/post(...)
    re.compile(r"""\$http\s*\.\s*(?:get|post|put|delete)\s*\(\s*["'`](/?[a-zA-Z0-9_\-/:%?&=.#]{4,200})["'`]"""),
    # url: "/path", path: "/path", endpoint: "/path", href: "/path"
    re.compile(r"""["'](?:url|path|endpoint|href|action|route|api)\s*["']\s*:\s*["'`](/?[a-zA-Z0-9_\-/%?&=.#]{4,200})["'`]"""),
    # method: 'GET', url: '/path' (combined)
    re.compile(r"""url\s*:\s*["'`](/?[a-zA-Z0-9_\-/%?&=.#]{4,200})["'`]"""),
    # XMLHttpRequest .open("GET", "/path")
    re.compile(r"""\.open\s*\(\s*["'][A-Z]+["']\s*,\s*["'`](/?[a-zA-Z0-9_\-/:%?&=.#]{4,200})["'`]"""),
    # apiUrl = "/path", baseUrl = "https://..."
    re.compile(r"""(?:apiUrl|baseUrl|apiBase|baseApi|rootUrl)\s*[=:]\s*["'`]([^"'`\s]{4,200})["'`]"""),
    # "/api/something" as a bare string with 2+ path segments
    re.compile(r"""["'`](/(?:api|v\d+|internal|graphql|admin|mobile|rpc|services?)/[a-zA-Z0-9_\-/%?&=.]{2,150})["'`]"""),
]

_SECRETS_IN_JS: list[tuple[str, re.Pattern]] = [
    ("API Key",       re.compile(r"""['"](?:api_?key|apikey|access_?key)['"\s]*[:=]\s*['"]([a-zA-Z0-9_\-]{16,64})['"]""", re.IGNORECASE)),
    ("AWS Key",       re.compile(r"""AKIA[0-9A-Z]{16}""")),
    ("Private Key",   re.compile(r"""-----BEGIN (?:RSA |EC )?PRIVATE KEY-----""")),
    ("Bearer Token",  re.compile(r"""bearer\s+([a-zA-Z0-9\-_=]{20,})""", re.IGNORECASE)),
]


class JSIntelligence:
    """Extract hidden endpoints and secrets from JavaScript files."""

    def __init__(self, max_js_files: int = 30, timeout: int = 15):
        self.max_js_files = max_js_files
        self.timeout = timeout

    def extract_js_endpoints(
        self,
        target: str,
        urls: list[str],
    ) -> tuple[list[str], list[str]]:
        """
        Returns (endpoints, potential_secrets_summary).
        Fetches JS files found in URL list and applies pattern extraction.
        """
        js_urls = [u for u in urls if u.endswith(".js") or ".js?" in u]
        if not js_urls:
            # Heuristic: probe common JS paths
            scheme = "https"
            js_urls = [
                f"{scheme}://{target}/static/js/main.chunk.js",
                f"{scheme}://{target}/app.js",
                f"{scheme}://{target}/bundle.js",
                f"{scheme}://{target}/assets/js/app.js",
            ]
        js_urls = list(dict.fromkeys(js_urls))[:self.max_js_files]

        all_endpoints: set[str] = set()
        all_secrets: list[str] = []

        with ThreadPoolExecutor(max_workers=8) as pool:
            futures = {pool.submit(self._fetch_js, url): url for url in js_urls}
            for future in as_completed(futures):
                content = future.result()
                if not content:
                    continue
                eps = self._extract_from_js_content(content)
                all_endpoints.update(eps)
                secs = self._check_secrets(content, futures[future])
                all_secrets.extend(secs)

        # Filter: keep only paths that look like real API/internal endpoints
        filtered = sorted({
            ep for ep in all_endpoints
            if ep.startswith("/")
            and len(ep) > 4
            and not any(ep.endswith(ext) for ext in
                        [".png", ".jpg", ".gif", ".svg", ".ico", ".woff", ".ttf", ".css"])
            and not ep.startswith("//")
        })
        return filtered, all_secrets

    def _fetch_js(self, url: str) -> str:
        try:
            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
            req = urllib.request.Request(
                url,
                headers={"User-Agent": "Mozilla/5.0 (OneInfinity/2.0)"},
            )
            with urllib.request.urlopen(req, timeout=self.timeout, context=ctx) as resp:
                ct = resp.headers.get("Content-Type", "")
                if "javascript" in ct or "text" in ct or url.endswith(".js"):
                    return resp.read(500_000).decode("utf-8", errors="replace")
        except Exception:
            pass
        return ""

    def _extract_from_js_content(self, content: str) -> list[str]:
        found: set[str] = set()
        for pattern in _JS_ENDPOINT_PATTERNS:
            for m in pattern.finditer(content):
                val = m.group(1).strip()
                if val and len(val) < 200:
                    found.add(val)
        return list(found)

    def _check_secrets(self, content: str, url: str) -> list[str]:
        found = []
        for label, pattern in _SECRETS_IN_JS:
            if pattern.search(content):
                found.append(f"{label} detected in {url}")
        return found


# ══════════════════════════════════════════════════════════════════════════════
# CLOUD ASSET INTELLIGENCE
# ══════════════════════════════════════════════════════════════════════════════

def _s3_name_variants(target: str) -> list[str]:
    """Generate S3 bucket name candidates from target domain."""
    base = target.split(".")[0]  # e.g. "example" from "example.com"
    variants = [
        base, f"{base}-assets", f"{base}-static", f"{base}-uploads",
        f"{base}-media", f"{base}-backup", f"{base}-backups",
        f"{base}-dev", f"{base}-prod", f"{base}-staging", f"{base}-test",
        f"{base}-data", f"{base}-logs", f"{base}-files", f"{base}-public",
        f"{base}-private", f"{base}-cdn", f"{base}-images",
        target.replace(".", "-"), target.replace(".", ""),
    ]
    return list(dict.fromkeys(variants))


class CloudAssetIntelligence:
    """Discover cloud assets: S3 buckets, GCS, Azure Blob, Lambda URLs."""

    def __init__(self, timeout: int = 10):
        self.timeout = timeout

    def detect_cloud_assets(
        self,
        target: str,
        subdomains: list[str] = None,
        tech_profile: TechProfile = None,
    ) -> CloudAssets:
        assets = CloudAssets()
        provider = (tech_profile.cloud if tech_profile else "") or ""
        assets.provider = provider

        with ThreadPoolExecutor(max_workers=6) as pool:
            futures = []
            if "AWS" in provider or not provider:
                futures.append(pool.submit(self._enumerate_s3, target))
                futures.append(pool.submit(self._check_imds_reachable))
            if "GCP" in provider or not provider:
                futures.append(pool.submit(self._enumerate_gcs, target))
            futures.append(pool.submit(self._scan_subdomains_for_cloud,
                                       subdomains or []))
            for f in as_completed(futures):
                result = f.result()
                if not result:
                    continue
                kind, data = result
                if kind == "s3":
                    assets.s3_buckets.extend(data.get("found", []))
                    assets.open_buckets.extend(data.get("open", []))
                elif kind == "gcs":
                    assets.gcs_buckets.extend(data.get("found", []))
                elif kind == "cloudfront":
                    assets.cloudfront_ids.extend(data)
                elif kind == "imds":
                    assets.exposed_metadata = data

        # Deduplicate
        assets.s3_buckets = list(dict.fromkeys(assets.s3_buckets))
        assets.open_buckets = list(dict.fromkeys(assets.open_buckets))
        assets.gcs_buckets = list(dict.fromkeys(assets.gcs_buckets))
        return assets

    def _enumerate_s3(self, target: str) -> tuple[str, dict]:
        found, open_buckets = [], []
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        for name in _s3_name_variants(target)[:12]:
            for url in [
                f"https://{name}.s3.amazonaws.com/",
                f"https://s3.amazonaws.com/{name}/",
            ]:
                try:
                    req = urllib.request.Request(
                        url, headers={"User-Agent": "OneInfinity/2.0"})
                    with urllib.request.urlopen(req, timeout=self.timeout, context=ctx) as resp:
                        body = resp.read(2000).decode("utf-8", errors="replace")
                        found.append(name)
                        # Public ListBucket response
                        if "<ListBucketResult" in body or "<Key>" in body:
                            open_buckets.append(name)
                        break
                except urllib.error.HTTPError as e:
                    if e.code == 403:
                        found.append(name)   # exists but private
                        break
                    elif e.code == 404:
                        pass  # does not exist
                except Exception:
                    pass
        return "s3", {"found": found, "open": open_buckets}

    def _enumerate_gcs(self, target: str) -> tuple[str, dict]:
        found = []
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        for name in _s3_name_variants(target)[:8]:
            url = f"https://storage.googleapis.com/{name}/"
            try:
                req = urllib.request.Request(
                    url, headers={"User-Agent": "OneInfinity/2.0"})
                with urllib.request.urlopen(req, timeout=self.timeout, context=ctx) as resp:
                    found.append(name)
            except urllib.error.HTTPError as e:
                if e.code == 403:
                    found.append(name)
            except Exception:
                pass
        return "gcs", {"found": found}

    def _check_imds_reachable(self) -> tuple[str, bool]:
        """Probe AWS IMDSv1 — only meaningful when running on EC2."""
        try:
            req = urllib.request.Request(
                "http://169.254.169.254/latest/meta-data/",
                headers={"User-Agent": "OneInfinity/2.0"},
            )
            with urllib.request.urlopen(req, timeout=2) as resp:
                return "imds", resp.status == 200
        except Exception:
            return "imds", False

    def _scan_subdomains_for_cloud(self, subdomains: list[str]) -> tuple[str, list]:
        cf_ids = []
        for sub in subdomains:
            if "cloudfront.net" in sub:
                cf_ids.append(sub)
            if ".s3." in sub or sub.endswith(".s3.amazonaws.com"):
                pass  # handled by S3 enum
        return "cloudfront", cf_ids


# ══════════════════════════════════════════════════════════════════════════════
# RECON STRATEGY ENGINE
# ══════════════════════════════════════════════════════════════════════════════

# Priority weights for sorting
_PRIORITY_WEIGHT = {"critical": 0, "high": 1, "medium": 2, "low": 3}

# Universal tasks always included
_UNIVERSAL_TASKS: list[ReconTask] = [
    ReconTask(
        task_id="idor_enum",
        title="IDOR via sequential ID enumeration",
        description="Enumerate numeric/UUID object references across all API endpoints",
        priority="high",
        category="api",
        commands=[],
        reason="Any authenticated API surface may expose IDOR",
    ),
    ReconTask(
        task_id="auth_bypass",
        title="Authentication bypass and privilege escalation",
        description="Test unauthenticated access to all discovered endpoints; try role-level parameter tampering",
        priority="high",
        category="auth",
        commands=[],
        reason="Auth checks often missing on internal/undocumented routes",
    ),
    ReconTask(
        task_id="cors_test",
        title="CORS misconfiguration",
        description="Test all API origins with arbitrary Origin: header; check Access-Control-Allow-Credentials",
        priority="medium",
        category="api",
        commands=["nuclei -u TARGET -tags cors -jsonl"],
        reason="APIs commonly misconfigure CORS to allow any origin",
    ),
    ReconTask(
        task_id="header_inject",
        title="Security header audit",
        description="Verify CSP, HSTS, X-Frame-Options, Permissions-Policy are present and configured correctly",
        priority="low",
        category="misc",
        commands=["nuclei -u TARGET -tags misconfig -jsonl"],
        reason="Missing security headers enable XSS/clickjacking chains",
    ),
]


class ReconStrategyEngine:
    """
    Decision engine: maps discovered tech + API surface → prioritised task list.
    Behaves like an experienced hunter deciding what to test next.
    """

    def generate_recon_strategy(
        self,
        tech_profile: TechProfile,
        api_map: APIMap,
        cloud_assets: CloudAssets,
        hidden_endpoints: list[str],
    ) -> tuple[list[ReconTask], dict]:
        """
        Returns (ordered_tasks, strategy_metadata).
        """
        scored: list[tuple[int, ReconTask]] = []

        # 1. Tech-specific tasks
        for label in tech_profile.raw_tech:
            if label in TECH_TO_ATTACKS:
                for task_id, title, priority in TECH_TO_ATTACKS[label]:
                    task = ReconTask(
                        task_id=task_id,
                        title=title,
                        description=f"Auto-generated for detected tech: {label}",
                        priority=priority,
                        category=self._category_for_task(task_id),
                        reason=f"{label} detected in target stack",
                    )
                    scored.append((_PRIORITY_WEIGHT[priority], task))

        # 2. API surface tasks
        if api_map.has_graphql:
            for task_id, title, priority in TECH_TO_ATTACKS["GraphQL"]:
                scored.append((_PRIORITY_WEIGHT[priority], ReconTask(
                    task_id=task_id, title=title,
                    description="GraphQL endpoint detected",
                    priority=priority, category="api",
                    commands=["python3 graphql_introspect.py TARGET/graphql"],
                    reason="GraphQL detected — introspection often enabled",
                )))

        if api_map.mobile_api:
            scored.append((1, ReconTask(
                task_id="mobile_idor",
                title="Mobile API IDOR and auth bypass",
                description="Mobile endpoints often skip authorization checks; test all with modified user IDs",
                priority="high", category="api",
                reason="Mobile API paths detected — common IDOR surface",
            )))

        if len(api_map.api_versions) > 1:
            scored.append((1, ReconTask(
                task_id="api_version_enum",
                title="Deprecated API version enumeration",
                description=f"Multiple API versions detected ({', '.join(api_map.api_versions)}). "
                            "Older versions often lack security controls of current version.",
                priority="high", category="api",
                commands=[f"ffuf -u TARGET/v{i}/FUZZ -w wordlist.txt" for i in range(1, 4)],
                reason=f"Versions {', '.join(api_map.api_versions)} suggest deprecated routes",
            )))

        # 3. Cloud tasks
        if cloud_assets.open_buckets:
            scored.insert(0, (0, ReconTask(
                task_id="s3_open_bucket",
                title=f"OPEN S3 BUCKETS: {', '.join(cloud_assets.open_buckets)}",
                description="Publicly listable S3 buckets found — immediate data exfiltration risk",
                priority="critical", category="cloud",
                commands=[f"aws s3 ls s3://{b} --no-sign-request"
                           for b in cloud_assets.open_buckets],
                reason="Bucket returned ListBucketResult — world-readable",
            )))

        if cloud_assets.s3_buckets and not cloud_assets.open_buckets:
            scored.append((0, ReconTask(
                task_id="s3_perms",
                title=f"S3 bucket permission testing ({len(cloud_assets.s3_buckets)} found)",
                description="Buckets exist — test write access, public file upload, and ACL misconfigurations",
                priority="critical", category="cloud",
                commands=[f"aws s3 cp /tmp/test.txt s3://{b}/test.txt --no-sign-request"
                           for b in cloud_assets.s3_buckets[:3]],
                reason="S3 buckets found — testing write/delete permissions",
            )))

        if cloud_assets.exposed_metadata:
            scored.insert(0, (-1, ReconTask(
                task_id="imds_v1",
                title="AWS IMDSv1 metadata service accessible — CRITICAL",
                description="Instance Metadata Service v1 is reachable. If SSRF exists, full IAM credential theft is possible.",
                priority="critical", category="cloud",
                commands=["curl http://169.254.169.254/latest/meta-data/iam/security-credentials/"],
                reason="IMDSv1 endpoint responded — SSRF→IMDS chain is live",
            )))

        # 4. Hidden endpoint tasks
        if hidden_endpoints:
            internal = [e for e in hidden_endpoints
                        if any(k in e.lower() for k in
                               ["admin", "internal", "debug", "delete", "reset",
                                "payment", "refund", "token", "secret", "config", "private"])]
            if internal:
                scored.insert(0, (0, ReconTask(
                    task_id="hidden_internal_endpoints",
                    title=f"High-value hidden endpoints from JS ({len(internal)} found)",
                    description=f"Internal endpoints extracted from JavaScript: {', '.join(internal[:5])}",
                    priority="critical", category="api",
                    commands=[f"curl -s https://TARGET{ep}" for ep in internal[:5]],
                    reason="JavaScript files contained admin/internal/payment endpoint paths",
                )))
            scored.append((1, ReconTask(
                task_id="js_endpoint_fuzz",
                title=f"Fuzz {len(hidden_endpoints)} JS-extracted endpoint(s)",
                description="Probe all hidden endpoints for auth bypass, IDOR, and injection",
                priority="high", category="api",
                reason=f"{len(hidden_endpoints)} non-public paths found in JS bundles",
            )))

        # 5. Always-include universal tasks
        for t in _UNIVERSAL_TASKS:
            scored.append((_PRIORITY_WEIGHT[t.priority], t))

        # Deduplicate by task_id, keep highest priority
        seen: dict[str, tuple[int, ReconTask]] = {}
        for weight, task in scored:
            if task.task_id not in seen or weight < seen[task.task_id][0]:
                seen[task.task_id] = (weight, task)

        ordered = [t for _, t in sorted(seen.values(), key=lambda x: (x[0], x[1].task_id))]

        strategy = {
            "next_tasks": [t.task_id for t in ordered],
            "priority_breakdown": {
                p: [t.task_id for t in ordered if t.priority == p]
                for p in ("critical", "high", "medium", "low")
            },
            "tech_driven": [t.task_id for t in ordered
                             if any(tech in t.reason for tech in tech_profile.raw_tech)],
            "cloud_driven": [t.task_id for t in ordered if t.category == "cloud"],
            "api_driven":   [t.task_id for t in ordered if t.category == "api"],
        }

        return ordered, strategy

    @staticmethod
    def _category_for_task(task_id: str) -> str:
        if any(k in task_id for k in ["s3", "imds", "gcp", "azure", "cloud", "bucket", "lambda"]):
            return "cloud"
        if any(k in task_id for k in ["jwt", "oauth", "saml", "ldap", "okta", "auth"]):
            return "auth"
        if any(k in task_id for k in ["gql", "graphql", "api", "rest", "grpc", "idor"]):
            return "api"
        if any(k in task_id for k in ["inject", "sqli", "ssti", "xss", "lfi", "rce", "proto"]):
            return "injection"
        return "misc"


# ══════════════════════════════════════════════════════════════════════════════
# TOOL-BACKED RECON FUNCTIONS (use ToolRegistry when available)
# ══════════════════════════════════════════════════════════════════════════════

def _run_cmd_simple(cmd: list[str], timeout: int = 60) -> str:
    """Lightweight subprocess runner (no ToolRegistry dependency)."""
    import subprocess
    import os
    env = dict(os.environ)
    home = Path.home()
    env["PATH"] = (
        env.get("PATH", "") +
        f":{home}/go/bin:{home}/.local/bin:/usr/local/go/bin"
    )
    try:
        result = subprocess.run(
            cmd, capture_output=True, text=True, timeout=timeout, env=env)
        return result.stdout
    except Exception:
        return ""


def _tool_available(name: str) -> bool:
    import shutil, os
    home = Path.home()
    extra = f"{home}/go/bin:{home}/.local/bin"
    path = os.environ.get("PATH", "") + ":" + extra
    return shutil.which(name, path=path) is not None


def _httpx_probe(targets: list[str], timeout: int = 60) -> list[dict]:
    """Run httpx and return parsed JSON lines."""
    if not _tool_available("httpx"):
        return []
    import tempfile
    with tempfile.NamedTemporaryFile(mode="w", suffix=".txt", delete=False) as f:
        f.write("\n".join(targets))
        inp = f.name
    out_data = _run_cmd_simple([
        "httpx", "-l", inp, "-json", "-title", "-tech-detect",
        "-status-code", "-follow-redirects", "-timeout", "8", "-silent",
    ], timeout=timeout)
    Path(inp).unlink(missing_ok=True)
    results = []
    for line in out_data.splitlines():
        try:
            results.append(json.loads(line))
        except Exception:
            pass
    return results


def _katana_crawl(url: str, depth: int = 2, timeout: int = 60) -> list[str]:
    """Run katana and return discovered URLs."""
    if not _tool_available("katana"):
        return []
    out = _run_cmd_simple([
        "katana", "-u", url, "-d", str(depth), "-silent",
        "-jc",    # crawl JavaScript
        "-ef", "png,jpg,gif,ico,woff,css,svg",
    ], timeout=timeout)
    return [l.strip() for l in out.splitlines() if l.strip().startswith("http")]


def _gau_fetch(domain: str, timeout: int = 45) -> list[str]:
    """Run gau/gauplus to get historical URLs."""
    tool = "gauplus" if _tool_available("gauplus") else ("gau" if _tool_available("gau") else None)
    if not tool:
        return []
    out = _run_cmd_simple([tool, domain], timeout=timeout)
    return [l.strip() for l in out.splitlines() if l.strip()]


def _subfinder_enum(domain: str, timeout: int = 60) -> list[str]:
    if not _tool_available("subfinder"):
        return []
    out = _run_cmd_simple(["subfinder", "-d", domain, "-silent"], timeout=timeout)
    return [l.strip() for l in out.splitlines() if l.strip()]


def _nuclei_tech_detect(url: str, timeout: int = 60) -> list[dict]:
    """Quick nuclei tech-detect pass."""
    if not _tool_available("nuclei"):
        return []
    out = _run_cmd_simple([
        "nuclei", "-u", url, "-tags", "tech-detect,waf-detect",
        "-severity", "info", "-jsonl", "-silent", "-nc",
    ], timeout=timeout)
    results = []
    for line in out.splitlines():
        try:
            results.append(json.loads(line))
        except Exception:
            pass
    return results


# ══════════════════════════════════════════════════════════════════════════════
# MAIN ORCHESTRATOR
# ══════════════════════════════════════════════════════════════════════════════

class AdaptiveReconEngine:
    """
    Orchestrates all recon intelligence components into a single adaptive run.

    Workflow:
    1. Subdomain enum (subfinder)
    2. HTTP probe all subdomains (httpx)
    3. Tech detection (httpx results + direct fetch + nuclei)
    4. URL discovery (gau + katana)
    5. API intelligence (URL pattern analysis)
    6. JS intelligence (endpoint extraction from bundles)
    7. Cloud asset enumeration (S3/GCS/Azure)
    8. Strategy generation (tech + API + cloud → prioritised task list)
    9. Attack graph integration
    10. Write output JSON
    """

    def __init__(
        self,
        target: str,
        output_dir: str = None,
        attack_graph=None,
        depth: str = "standard",    # quick | standard | deep
        tool_registry=None,
    ):
        # Strip scheme properly (lstrip strips individual chars, not substrings)
        _t = target
        for _scheme in ("https://", "http://"):
            if _t.startswith(_scheme):
                _t = _t[len(_scheme):]
                break
        self.target = _t.split("/")[0]
        self.output_dir = resolve_output_dir(output_dir, self.target)
        self.attack_graph = attack_graph
        self.depth = depth
        self.tool_registry = tool_registry

        self._tech_detector = TechDetector()
        self._api_intel = APIIntelligence()
        self._js_intel = JSIntelligence(
            max_js_files=50 if depth == "deep" else 20,
        )
        self._cloud_intel = CloudAssetIntelligence()
        self._strategy = ReconStrategyEngine()

        # State accumulated across phases
        self._subdomains: list[str] = []
        self._alive_hosts: list[dict] = []
        self._all_urls: list[str] = []
        self._tech_profile = TechProfile()
        self._api_map = APIMap()
        self._hidden_endpoints: list[str] = []
        self._js_secrets: list[str] = []
        self._cloud_assets = CloudAssets()

    # ── Public API ────────────────────────────────────────────────────────────

    def run(self) -> ReconIntelligence:
        """Execute full adaptive recon pipeline. Returns ReconIntelligence."""
        t0 = time.time()
        self.output_dir.mkdir(parents=True, exist_ok=True)

        _info(f"Adaptive Recon Intelligence — {self.target} [{self.depth}]")

        # 1. Load existing recon data if available
        self._load_existing_recon()

        # 2. Subdomain enumeration (if not already done)
        if not self._subdomains:
            self._phase_subdomain_enum()

        # 3. HTTP probe
        if not self._alive_hosts:
            self._phase_http_probe()

        # 4. URL discovery
        if not self._all_urls:
            self._phase_url_discovery()

        # 5. Technology detection
        self._phase_tech_detection()

        # 6. API intelligence
        self._phase_api_intelligence()

        # 7. JS intelligence
        if self.depth in ("standard", "deep"):
            self._phase_js_intelligence()

        # 8. Cloud asset intelligence
        self._phase_cloud_intelligence()

        # 9. Generate strategy
        tasks, strategy = self._strategy.generate_recon_strategy(
            self._tech_profile, self._api_map,
            self._cloud_assets, self._hidden_endpoints,
        )

        # 10. Compute attack surface score
        score = self._compute_attack_surface_score(tasks)

        # 11. Update attack graph
        if self.attack_graph:
            self._update_attack_graph(tasks)

        # Build result
        intel = ReconIntelligence(
            target=self.target,
            scan_duration_s=round(time.time() - t0, 1),
            tech_profile=self._tech_profile,
            alive_hosts=self._alive_hosts,
            all_urls=self._all_urls,
            api_map=self._api_map,
            hidden_endpoints=self._hidden_endpoints,
            cloud_assets=self._cloud_assets,
            tasks=tasks,
            recon_strategy=strategy,
            attack_surface_score=score,
        )
        # Populate flat alias fields for JSON compat
        intel.technologies = self._tech_profile.raw_tech
        intel.apis = self._api_map.base_paths
        intel.recommended_tests = [t.task_id for t in tasks]

        # Save output
        out_file = self.output_dir / "adaptive_recon.json"
        out_file.write_text(intel.to_json())
        _ok(f"Intelligence saved: {out_file}")

        return intel

    # ── Named public methods (as per spec) ───────────────────────────────────

    def detect_technologies(self, target: str = None) -> dict:
        """Detect technologies for target. Returns flat dict."""
        t = target or self.target
        profile, _ = self._tech_detector.fetch_and_detect(f"https://{t}")
        return {
            "frontend": profile.frontend,
            "backend": profile.backend,
            "cloud": profile.cloud,
            "waf": profile.waf,
            "cdn": profile.cdn,
            "cms": profile.cms,
            "auth": profile.auth,
            "raw": profile.raw_tech,
        }

    def detect_api_endpoints(self) -> list[str]:
        return self._api_intel.detect_api_endpoints(self._all_urls)

    def map_api_structure(self) -> APIMap:
        return self._api_intel.map_api_structure(self._all_urls)

    def extract_js_endpoints(self) -> list[str]:
        eps, secrets = self._js_intel.extract_js_endpoints(self.target, self._all_urls)
        return eps

    def detect_cloud_assets(self) -> CloudAssets:
        return self._cloud_intel.detect_cloud_assets(
            self.target, self._subdomains, self._tech_profile)

    def generate_recon_strategy(self) -> dict:
        tasks, strategy = self._strategy.generate_recon_strategy(
            self._tech_profile, self._api_map,
            self._cloud_assets, self._hidden_endpoints,
        )
        return strategy

    # ── Internal phases ───────────────────────────────────────────────────────

    def _load_existing_recon(self):
        """Load previously saved recon artifacts to avoid re-running."""
        subs_file = self.output_dir / "subdomains.json"
        if subs_file.exists():
            try:
                self._subdomains = json.loads(subs_file.read_text())
                _info(f"Loaded {len(self._subdomains)} subdomains from cache")
            except Exception:
                pass

        alive_file = self.output_dir / "alive_hosts.json"
        if alive_file.exists():
            try:
                data = json.loads(alive_file.read_text())
                self._alive_hosts = data.get("hosts", data) if isinstance(data, dict) else data
                _info(f"Loaded {len(self._alive_hosts)} alive hosts from cache")
            except Exception:
                pass

        urls_file = self.output_dir / "urls.json"
        if urls_file.exists():
            try:
                self._all_urls = json.loads(urls_file.read_text())
                _info(f"Loaded {len(self._all_urls)} URLs from cache")
            except Exception:
                pass

    def _phase_subdomain_enum(self):
        _info("Phase 1: Subdomain enumeration...")
        subs: set[str] = {self.target}

        # subfinder
        found = _subfinder_enum(self.target, timeout=90)
        subs.update(found)
        if found:
            _ok(f"subfinder: {len(found)} subdomains")

        # crt.sh
        try:
            crt = self._crtsh_lookup(self.target)
            subs.update(crt)
            if crt:
                _ok(f"crt.sh: {len(crt)} subdomains")
        except Exception as e:
            _warn(f"crt.sh failed: {e}")

        # HackerTarget Fallback
        try:
            ht = self._hackertarget_lookup(self.target)
            subs.update(ht)
            if ht:
                _ok(f"hackertarget: {len(ht)} subdomains")
        except Exception as e:
            _warn(f"hackertarget failed: {e}")

        self._subdomains = sorted(subs)
        (self.output_dir / "subdomains.json").write_text(
            json.dumps(self._subdomains, indent=2))
        _ok(f"Total subdomains: {len(self._subdomains)}")

    def _phase_http_probe(self):
        _info(f"Phase 2: HTTP probing {len(self._subdomains)} hosts...")
        self._alive_hosts = _httpx_probe(self._subdomains, timeout=120)
        (self.output_dir / "alive_hosts.json").write_text(
            json.dumps({"hosts": self._alive_hosts}, indent=2))
        _ok(f"Alive hosts: {len(self._alive_hosts)}")

    def _phase_url_discovery(self):
        _info("Phase 3: URL discovery (gau + katana)...")
        all_urls: set[str] = set()

        # Historical URLs
        gau_urls = _gau_fetch(self.target, timeout=60)
        all_urls.update(gau_urls)
        if gau_urls:
            _ok(f"gau: {len(gau_urls)} URLs")

        # Active crawl (first alive host)
        if self._alive_hosts:
            primary = self._alive_hosts[0].get("url", f"https://{self.target}")
            crawl_depth = 3 if self.depth == "deep" else 2
            katana_urls = _katana_crawl(primary, depth=crawl_depth, timeout=120)
            all_urls.update(katana_urls)
            if katana_urls:
                _ok(f"katana: {len(katana_urls)} URLs")

        self._all_urls = sorted(all_urls)
        (self.output_dir / "urls.json").write_text(
            json.dumps(self._all_urls, indent=2))
        _ok(f"Total URLs: {len(self._all_urls)}")

    def _phase_tech_detection(self):
        _info("Phase 4: Technology detection...")

        # From httpx results
        profile = self._tech_detector.detect(
            self.target, alive_hosts=self._alive_hosts)

        # Enhance with direct fetch if profile is sparse
        if not profile.frontend and not profile.backend:
            primary = (self._alive_hosts[0].get("url", f"https://{self.target}")
                       if self._alive_hosts else f"https://{self.target}")
            extra_profile, html = self._tech_detector.fetch_and_detect(primary)
            # Merge
            for attr in ("frontend", "backend", "cloud", "waf", "cdn", "cms"):
                if not getattr(profile, attr) and getattr(extra_profile, attr):
                    setattr(profile, attr, getattr(extra_profile, attr))
            for label in extra_profile.raw_tech:
                if label not in profile.raw_tech:
                    profile.raw_tech.append(label)

        # Nuclei tech-detect (quick pass)
        if _tool_available("nuclei") and self._alive_hosts:
            primary_url = self._alive_hosts[0].get("url", f"https://{self.target}")
            nuc_results = _nuclei_tech_detect(primary_url, timeout=45)
            for r in nuc_results:
                name = r.get("info", {}).get("name", "")
                if name and name not in profile.raw_tech:
                    profile.raw_tech.append(name)

        self._tech_profile = profile

        if profile.raw_tech:
            _ok(f"Technologies: {', '.join(profile.raw_tech[:8])}")
        else:
            _warn("No technologies detected")

        # Save
        (self.output_dir / "tech_profile.json").write_text(
            json.dumps(asdict(profile), indent=2))

    def _phase_api_intelligence(self):
        _info("Phase 5: API surface mapping...")
        self._api_map = self._api_intel.map_api_structure(self._all_urls)

        if self._api_map.has_graphql:
            _ok("GraphQL endpoint detected!")
        if self._api_map.has_rest:
            _ok(f"REST API: {len(self._api_map.base_paths)} base paths")
        if self._api_map.api_versions:
            _ok(f"API versions: {', '.join(self._api_map.api_versions)}")
        if self._api_map.mobile_api:
            _ok("Mobile API surface detected")

        (self.output_dir / "api_map.json").write_text(
            json.dumps(asdict(self._api_map), indent=2))

    def _phase_js_intelligence(self):
        _info("Phase 6: JavaScript endpoint extraction...")
        self._hidden_endpoints, self._js_secrets = self._js_intel.extract_js_endpoints(
            self.target, self._all_urls)

        if self._hidden_endpoints:
            _ok(f"Hidden endpoints from JS: {len(self._hidden_endpoints)}")
            for ep in self._hidden_endpoints[:5]:
                _info(f"  {ep}")
        if self._js_secrets:
            for s in self._js_secrets:
                _warn(f"POSSIBLE SECRET: {s}")

        (self.output_dir / "js_endpoints.json").write_text(
            json.dumps({
                "endpoints": self._hidden_endpoints,
                "potential_secrets": self._js_secrets,
            }, indent=2))

    def _phase_cloud_intelligence(self):
        _info("Phase 7: Cloud asset discovery...")
        self._cloud_assets = self._cloud_intel.detect_cloud_assets(
            self.target, self._subdomains, self._tech_profile)

        if self._cloud_assets.open_buckets:
            _warn(f"OPEN BUCKETS: {', '.join(self._cloud_assets.open_buckets)}")
        if self._cloud_assets.s3_buckets:
            _ok(f"S3 buckets found: {len(self._cloud_assets.s3_buckets)}")
        if self._cloud_assets.gcs_buckets:
            _ok(f"GCS buckets found: {len(self._cloud_assets.gcs_buckets)}")
        if self._cloud_assets.exposed_metadata:
            _warn("AWS IMDS metadata endpoint accessible!")

        (self.output_dir / "cloud_assets.json").write_text(
            json.dumps(asdict(self._cloud_assets), indent=2))

    def _compute_attack_surface_score(self, tasks: list[ReconTask]) -> int:
        """0-100 score based on surface complexity and critical findings."""
        score = 0
        score += min(len(self._subdomains) * 2, 20)
        score += min(len(self._alive_hosts) * 3, 15)
        score += min(len(self._api_map.base_paths) * 3, 15)
        score += 10 if self._api_map.has_graphql else 0
        score += 5 if self._api_map.has_rest else 0
        score += min(len(self._hidden_endpoints) * 2, 10)
        score += 10 if self._cloud_assets.s3_buckets else 0
        score += 5 if len(self._tech_profile.raw_tech) > 3 else 0
        critical_tasks = [t for t in tasks if t.priority == "critical"]
        score += min(len(critical_tasks) * 3, 15)
        return min(score, 100)

    def _update_attack_graph(self, tasks: list[ReconTask]):
        """Push intelligence into the attack graph."""
        try:
            from attack_graph.graph import Node, NodeType, Edge, EdgeType

            for host in self._alive_hosts:
                url = host.get("url", "")
                if url:
                    self.attack_graph.add_host(url, host.get("status_code", 200),
                                               host.get("tech", []))

            for ep in self._hidden_endpoints[:20]:
                full_url = f"https://{self.target}{ep}"
                self.attack_graph.add_endpoint(full_url, method="GET")

            if self._cloud_assets.open_buckets:
                for bucket in self._cloud_assets.open_buckets:
                    self.attack_graph.add_vulnerability(
                        vuln_id=f"open_s3_{bucket}",
                        vuln_type="S3 Bucket Public Access",
                        host=f"{bucket}.s3.amazonaws.com",
                        endpoint=f"https://{bucket}.s3.amazonaws.com/",
                        severity="critical",
                        evidence="Bucket ListBucketResult returned — world-readable",
                        confidence="high",
                    )

            for task in tasks:
                if task.priority == "critical":
                    self.attack_graph.add_vulnerability(
                        vuln_id=f"adaptive_{task.task_id}",
                        vuln_type=task.title[:60],
                        host=self.target,
                        endpoint=f"https://{self.target}",
                        severity="critical" if task.priority == "critical" else "high",
                        evidence=task.reason,
                        confidence="low",   # not yet validated
                    )
        except Exception as e:
            _warn(f"Attack graph update failed: {e}")

    def _crtsh_lookup(self, domain: str) -> list[str]:
        url = f"https://crt.sh/?q=%.{urllib.parse.quote(domain)}&output=json"
        req = urllib.request.Request(
            url, headers={"User-Agent": "Mozilla/5.0 (OneInfinity/2.0)"})
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        
        for attempt in range(3):
            try:
                with urllib.request.urlopen(req, timeout=30, context=ctx) as resp:
                    data = json.loads(resp.read())
                subs: set[str] = set()
                for entry in data:
                    for name in entry.get("name_value", "").splitlines():
                        name = name.strip().lstrip("*.")
                        if name.endswith(f".{domain}") or name == domain:
                            subs.add(name.lower())
                return list(subs)
            except Exception:
                time.sleep(1)
        return []

    def _hackertarget_lookup(self, domain: str) -> list[str]:
        url = f"https://api.hackertarget.com/hostsearch/?q={urllib.parse.quote(domain)}"
        req = urllib.request.Request(
            url, headers={"User-Agent": "Mozilla/5.0 (OneInfinity/2.0)"})
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        
        try:
            with urllib.request.urlopen(req, timeout=30, context=ctx) as resp:
                data = resp.read().decode("utf-8")
            subs: set[str] = set()
            for line in data.splitlines():
                parts = line.split(",")
                if len(parts) >= 1:
                    name = parts[0].strip()
                    if name.endswith(f".{domain}") or name == domain:
                        subs.add(name.lower())
            return list(subs)
        except Exception:
            return []


# ══════════════════════════════════════════════════════════════════════════════
# CLI DISPLAY HELPERS
# ══════════════════════════════════════════════════════════════════════════════

def print_intelligence_report(intel: ReconIntelligence, output_dir: str | Path | None = None):
    """Render a rich console report from ReconIntelligence."""

    W = 68
    print()
    print(_c("1;36", "═" * W))
    print(_c("1;36", f"  Adaptive Recon Intelligence — {intel.target}"))
    print(_c("1;36", "═" * W))
    print(f"  Scan duration : {intel.scan_duration_s}s")
    print(f"  Attack surface: {intel.attack_surface_score}/100")
    print()

    # Tech profile
    tp = intel.tech_profile
    if tp.raw_tech:
        print(_c("1;36", "  ── Technology Stack ─────────────────────────────────────────────"))
        if tp.frontend:  print(f"  Frontend  : {tp.frontend}")
        if tp.backend:   print(f"  Backend   : {tp.backend}")
        if tp.cloud:     print(f"  Cloud     : {tp.cloud}")
        if tp.waf:       print(f"  WAF/CDN   : {tp.waf or tp.cdn}")
        if tp.cms:       print(f"  CMS       : {tp.cms}")
        if tp.auth:      print(f"  Auth      : {', '.join(tp.auth)}")
        if tp.raw_tech:  print(f"  All       : {', '.join(tp.raw_tech)}")
        print()

    # API surface
    am = intel.api_map
    if am.base_paths or am.has_graphql:
        print(_c("1;36", "  ── API Surface ───────────────────────────────────────────────────"))
        if am.has_graphql:  print(f"  GraphQL   : ✓ detected")
        if am.has_rest:     print(f"  REST API  : {len(am.base_paths)} base paths")
        if am.api_versions: print(f"  Versions  : {', '.join(am.api_versions)}")
        if am.mobile_api:   print(f"  Mobile    : ✓ mobile API paths detected")
        for p in am.base_paths[:8]:
            print(f"    {p}")
        print()

    # Hidden endpoints
    if intel.hidden_endpoints:
        print(_c("1;36", "  ── JS-Extracted Hidden Endpoints ────────────────────────────────"))
        print(f"  Found {len(intel.hidden_endpoints)} endpoint(s) in JavaScript bundles:")
        for ep in intel.hidden_endpoints[:10]:
            marker = " ⚠" if any(k in ep.lower() for k in
                                   ["admin", "internal", "delete", "payment", "secret"]) else ""
            print(f"    {ep}{marker}")
        if len(intel.hidden_endpoints) > 10:
            print(f"    ... and {len(intel.hidden_endpoints) - 10} more (see js_endpoints.json)")
        print()

    # Cloud assets
    ca = intel.cloud_assets
    if ca.s3_buckets or ca.gcs_buckets or ca.open_buckets:
        print(_c("1;36", "  ── Cloud Assets ──────────────────────────────────────────────────"))
        if ca.provider:   print(f"  Provider  : {ca.provider}")
        if ca.open_buckets:
            for b in ca.open_buckets:
                print(_c("0;31", f"  ⚠ OPEN BUCKET : {b} (world-readable!)"))
        if ca.s3_buckets:  print(f"  S3 Buckets: {', '.join(ca.s3_buckets[:5])}")
        if ca.gcs_buckets: print(f"  GCS Buckets: {', '.join(ca.gcs_buckets[:5])}")
        print()

    # Recommended tasks
    if intel.tasks:
        print(_c("1;36", "  ── Recommended Tests (by priority) ──────────────────────────────"))
        for priority in ("critical", "high", "medium", "low"):
            tasks_at = [t for t in intel.tasks if t.priority == priority]
            if not tasks_at:
                continue
            colour = {"critical": "0;31", "high": "0;33",
                      "medium": "0;36", "low": "0;37"}[priority]
            print(f"  {_c(colour, priority.upper())}:")
            for task in tasks_at:
                print(f"    [{task.task_id}] {task.title}")
                if task.reason:
                    print(_c("0;37", f"      → {task.reason}"))
        print()

    # Output files
    print(_c("1;36", "  ── Output Files ──────────────────────────────────────────────────"))
    out_dir = resolve_output_dir(output_dir, intel.target)
    for fname in ["adaptive_recon.json", "tech_profile.json", "api_map.json",
                  "js_endpoints.json", "cloud_assets.json"]:
        p = out_dir / fname
        if p.exists():
            print(f"  {fname}")
    print()


# ══════════════════════════════════════════════════════════════════════════════
# ENTRY POINT (when called standalone)
# ══════════════════════════════════════════════════════════════════════════════

def main_cli(args):
    """Called by oneinfinity.py for 'oneinfinity adaptive-recon <domain>' command."""
    from modules.utils import banner
    target = args.domain
    depth = getattr(args, "depth", "standard")
    output = resolve_output_dir(getattr(args, "output", None), target)

    banner(f"Adaptive Recon Intelligence — {target}")

    # Optionally integrate attack graph
    attack_graph = None
    if not getattr(args, "no_graph", False):
        try:
            from attack_graph import AttackGraph, AttackGraphBuilder
            out_path = Path(output)
            if out_path.exists():
                builder = AttackGraphBuilder(target)
                attack_graph = builder.from_recon_dir(str(out_path))
            else:
                attack_graph = AttackGraph(target)
        except Exception:
            pass

    engine = AdaptiveReconEngine(
        target=target,
        output_dir=output,
        attack_graph=attack_graph,
        depth=depth,
    )

    intel = engine.run()
    print_intelligence_report(intel, output)

    # Print structured JSON summary for piping
    if getattr(args, "json", False):
        print(intel.to_json())

    return intel


if __name__ == "__main__":
    import argparse
    p = argparse.ArgumentParser(description="Adaptive Recon Intelligence Engine")
    p.add_argument("domain", help="Target domain")
    p.add_argument("--output", "-o", metavar="DIR",
                   help="Output directory (default: ~/.oneinfinity/raw/<domain>)")
    p.add_argument("--depth", choices=["quick", "standard", "deep"],
                   default="standard", help="Recon depth (default: standard)")
    p.add_argument("--json", action="store_true", help="Print JSON output")
    p.add_argument("--no-graph", dest="no_graph", action="store_true",
                   help="Skip attack graph integration")
    args = p.parse_args()
    main_cli(args)
