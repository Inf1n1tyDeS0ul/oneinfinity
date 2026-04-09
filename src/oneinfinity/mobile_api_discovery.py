"""
Mobile API Discovery Engine
============================
Discovers backend API endpoints, authentication schemes, and
network communication patterns from mobile application source code.
Builds a comprehensive mobile API attack surface map.
"""
from __future__ import annotations

import json
import logging
import os
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Dict, List, Optional, Tuple
from urllib.parse import urlparse

from oneinfinity.mobile_tool_registry import UnifiedFinding

logger = logging.getLogger("oneinfinity.mobile.api_discovery")

# ---------------------------------------------------------------------------
# URL / path patterns (as specified in the task)
# ---------------------------------------------------------------------------
_URL_PATTERNS = [
    r'https?://[a-zA-Z0-9\-._~:/?#\[\]@!$&\'()*+,;=%]+',
    r'["\']/(api|v\d+|rest|graphql|auth|user|admin|internal)/[^"\'<>\s]*["\']',
    r'@(GET|POST|PUT|DELETE|PATCH|HEAD)\s*\(\s*["\']([^"\']+)["\']',
    r'\.url\s*\(\s*["\']([^"\']+)["\']',
    r'baseUrl\s*\(?["\']([^"\']+)["\']',
    r'BASE_URL\s*[=:]\s*["\']([^"\']+)["\']',
    r'API_URL\s*[=:]\s*["\']([^"\']+)["\']',
]

_COMPILED_URL_PATTERNS = [re.compile(p) for p in _URL_PATTERNS]

# ---------------------------------------------------------------------------
# Retrofit / annotation patterns
# ---------------------------------------------------------------------------
_RETROFIT_ANNOTATION = re.compile(
    r'@(GET|POST|PUT|DELETE|PATCH|HEAD|OPTIONS)\s*\(\s*["\']([^"\']+)["\']'
)

# OkHttp patterns
_OKHTTP_URL = re.compile(r'(?:\.url|Request\.Builder\(\)\.url|HttpUrl\.parse)\s*\(\s*["\']([^"\']+)["\']')
_OKHTTP_BUILDER = re.compile(r'Request\.Builder\(\)')

# Volley
_VOLLEY_REQUEST = re.compile(
    r'new\s+(?:StringRequest|JsonObjectRequest|JsonArrayRequest)\s*\(\s*(?:Method\.(\w+)\s*,\s*)?["\']([^"\']+)["\']'
)

# HttpURLConnection / URL
_HTTPURL_CONN = re.compile(r'(?:openConnection|new URL)\s*\(\s*["\']([^"\']+)["\']')

# Apollo GraphQL
_APOLLO_QUERY = re.compile(r'\b(query|mutation|subscription)\s+(\w+)\s*\{')

# WebSocket (Java/Kotlin)
_WEBSOCKET_JAVA = re.compile(r'(?:new WebSocket|OkHttpClient\(\)\.newWebSocket)\s*\(\s*["\']([^"\']+)["\']')
_WEBSOCKET_GENERIC = re.compile(r'["\']wss?://[^\s"\']+["\']')

# Axios / fetch (JS in WebView)
_AXIOS_FETCH = re.compile(
    r'(?:axios\.(?:get|post|put|delete|patch|head)|fetch)\s*\(\s*["\`]([^"\`\s]+)["\`]'
)
_XHR_OPEN = re.compile(r'\.open\s*\(\s*["\'](\w+)["\'],\s*["\`]([^"\`\s]+)["\`]')

# URLSession (Swift)
_URLSESSION = re.compile(r'URLSession\.shared\.\w+\s*\(\s*with\s*URL\s*\(\s*string:\s*["\']([^"\']+)["\']')
_URLREQUEST_SWIFT = re.compile(r'URLRequest\s*\(\s*url:\s*URL\s*\(\s*string:\s*["\']([^"\']+)["\']')

# Alamofire (Swift)
_ALAMOFIRE = re.compile(r'AF\.request\s*\(\s*["\']([^"\']+)["\'](?:\s*,\s*method:\s*\.(\w+))?')
_ALAMOFIRE_OLD = re.compile(r'Alamofire\.request\s*\(\s*["\']([^"\']+)["\'](?:\s*,\s*method:\s*\.(\w+))?')

# ObjC NSURLRequest
_NSURLREQUEST = re.compile(
    r'requestWithURL:\s*\[NSURL URLWithString:\s*@["\']([^"\']+)["\']'
)
_AFNETWORKING = re.compile(r'AFHTTPSessionManager.*?(?:GET|POST|PUT|DELETE)\s*:\s*@?["\']([^"\']+)["\']')

# Base URL declarations
_BASE_URL_DECLS = re.compile(
    r'(?i)(?:BASE_URL|BASE_API|API_URL|API_BASE|SERVER_URL|HOST_URL|ENDPOINT_URL|baseUrl|apiUrl)\s*[=:]\s*["\']?(https?://[a-zA-Z0-9\-\.]+(?::\d+)?(?:/[^\s"\']*)?)["\']?'
)
_RETROFIT_BASEURL = re.compile(
    r'\.baseUrl\s*\(\s*["\']?(https?://[a-zA-Z0-9\-\.]+(?::\d+)?(?:/[^\s"\']*)?)["\']?\s*\)'
)

# Auth patterns
_AUTH_PATTERNS = [
    re.compile(r'(?i)(?:Authorization|Auth-Token|X-API-Key)\s*[=:,]\s*["\']?(?:Bearer|Basic|Token)\b'),
    re.compile(r'(?i)addHeader\s*\(\s*["\']Authorization["\']'),
    re.compile(r'(?i)\.setBearerToken|\.setAuthToken|\.setApiKey'),
    re.compile(r'(?i)(?:Bearer|Basic Auth|OAuth|JWT|API.?Key)'),
    re.compile(r'(?i)interceptor.*auth|auth.*interceptor'),
    re.compile(r'(?i)\.header\s*\(\s*["\']Authorization["\']'),
]

# WebSocket WS/WSS
_WS_URL = re.compile(r'["\']wss?://[^\s"\'<>]+["\']')

# GraphQL endpoint paths
_GRAPHQL_PATH = re.compile(r'["\'](?:https?://[^\s"\']+)?(/graphql|/gql|/query|/graphiql)["\']', re.IGNORECASE)

# Known third-party API hosts
_THIRD_PARTY_APIS: Dict[str, str] = {
    "api.stripe.com": "Stripe Payments",
    "api.braintreegateway.com": "Braintree Payments",
    "api.twilio.com": "Twilio SMS/Voice",
    "api.sendgrid.com": "SendGrid Email",
    "api.firebase.google.com": "Firebase",
    "firebaseio.com": "Firebase Realtime DB",
    "firebase.googleapis.com": "Firebase",
    "maps.googleapis.com": "Google Maps",
    "maps.google.com": "Google Maps",
    "graph.facebook.com": "Facebook Graph API",
    "api.twitter.com": "Twitter API",
    "api.instagram.com": "Instagram API",
    "api.github.com": "GitHub API",
    "api.segment.io": "Segment Analytics",
    "api.mixpanel.com": "Mixpanel Analytics",
    "api.amplitude.com": "Amplitude Analytics",
    "api.braze.com": "Braze (Appboy)",
    "api.intercom.io": "Intercom",
    "sentry.io": "Sentry Error Tracking",
    "bugsnag.com": "Bugsnag Error Tracking",
    "crashlytics.com": "Crashlytics",
    "amazonaws.com": "AWS",
    "s3.amazonaws.com": "AWS S3",
    "openai.com": "OpenAI",
    "api.anthropic.com": "Anthropic Claude",
    "api.paypal.com": "PayPal",
    "api.squareup.com": "Square Payments",
    "api.plaid.com": "Plaid Finance",
    "googleapis.com": "Google APIs",
    "graph.microsoft.com": "Microsoft Graph",
    "login.microsoftonline.com": "Microsoft Auth",
    "api.onesignal.com": "OneSignal Push",
    "fcm.googleapis.com": "Firebase Cloud Messaging",
    "apns2.push.apple.com": "Apple Push Notification",
    "sandbox.itunes.apple.com": "Apple App Store (sandbox)",
    "api.revenuecat.com": "RevenueCat",
    "api.appsflyer.com": "AppsFlyer",
    "api.adjust.com": "Adjust Analytics",
    "in.appcenter.ms": "App Center",
}

# Source extensions to scan
_SOURCE_EXTS = {
    ".java", ".kt", ".swift", ".m", ".h", ".js", ".ts", ".jsx", ".tsx",
    ".xml", ".json", ".yaml", ".yml", ".gradle", ".properties",
    ".smali", ".dart", ".cs",  # Unity
}

# Directories to skip
_SKIP_DIRS = {"__pycache__", "node_modules", ".git", "build", "dist", "test", "tests", ".gradle"}


# ---------------------------------------------------------------------------
# Dataclasses
# ---------------------------------------------------------------------------

@dataclass
class APIEndpoint:
    url: str
    method: str = "GET"
    params: List[str] = field(default_factory=list)
    headers: Dict[str, str] = field(default_factory=dict)
    auth_required: bool = False
    source_file: str = ""
    line_number: int = 0
    framework: str = ""
    risk_level: str = "low"
    notes: str = ""

    def to_dict(self) -> dict:
        return {
            "url": self.url,
            "method": self.method,
            "params": self.params,
            "headers": self.headers,
            "auth_required": self.auth_required,
            "source_file": self.source_file,
            "line_number": self.line_number,
            "framework": self.framework,
            "risk_level": self.risk_level,
            "notes": self.notes,
        }


@dataclass
class APIDiscoveryResult:
    app_id: str
    base_urls: List[str] = field(default_factory=list)
    endpoints: List[APIEndpoint] = field(default_factory=list)
    auth_schemes: List[str] = field(default_factory=list)
    websocket_urls: List[str] = field(default_factory=list)
    graphql_endpoints: List[str] = field(default_factory=list)
    third_party_apis: List[Dict] = field(default_factory=list)
    attack_surface: List[Dict] = field(default_factory=list)
    frameworks_detected: List[str] = field(default_factory=list)
    total_endpoints: int = 0

    def to_dict(self) -> dict:
        return {
            "app_id": self.app_id,
            "base_urls": self.base_urls,
            "endpoints": [e.to_dict() for e in self.endpoints],
            "auth_schemes": self.auth_schemes,
            "websocket_urls": self.websocket_urls,
            "graphql_endpoints": self.graphql_endpoints,
            "third_party_apis": self.third_party_apis,
            "attack_surface": self.attack_surface,
            "frameworks_detected": self.frameworks_detected,
            "total_endpoints": self.total_endpoints,
        }


# ---------------------------------------------------------------------------
# Main class
# ---------------------------------------------------------------------------

class MobileAPIDiscovery:
    """Discovers API endpoints from decompiled / source mobile application code."""

    # ------------------------------------------------------------------
    # Public entry point
    # ------------------------------------------------------------------

    def discover(self, app_id: str, extracted_dir: str) -> APIDiscoveryResult:
        """
        Orchestrate API discovery across Java/Kotlin, Swift/ObjC, JS, and config files.

        Returns an APIDiscoveryResult with all discovered endpoints, base URLs,
        auth schemes, WebSocket URLs, GraphQL endpoints, third-party APIs, and
        a pre-built attack surface map.
        """
        result = APIDiscoveryResult(app_id=app_id)
        root = Path(extracted_dir)

        if not root.exists():
            logger.warning("extracted_dir does not exist: %s", extracted_dir)
            return result

        # ── Phase 1: scan source files ────────────────────────────────
        java_eps = self._scan_java_kotlin(root)
        swift_eps = self._scan_swift_objc(root)
        config_eps = self._scan_config_files(root)
        js_eps = self._scan_js_files(root)

        all_eps: List[APIEndpoint] = java_eps + swift_eps + config_eps + js_eps

        # ── Phase 2: deduplicate endpoints ────────────────────────────
        seen: set = set()
        for ep in all_eps:
            key = (ep.method, ep.url)
            if key not in seen and ep.url:
                seen.add(key)
                result.endpoints.append(ep)

        # ── Phase 3: extract base URLs ────────────────────────────────
        result.base_urls = self._extract_base_urls(result.endpoints)

        # ── Phase 4: fill in full URLs for relative paths ─────────────
        if result.base_urls:
            primary_base = result.base_urls[0]
            for ep in result.endpoints:
                if ep.url.startswith("/") and not ep.url.startswith("//"):
                    ep.url = primary_base.rstrip("/") + ep.url

        # ── Phase 5: collect websocket & graphql ─────────────────────
        result.websocket_urls = self._collect_websocket_urls(root)
        result.graphql_endpoints = self._collect_graphql_endpoints(result.endpoints)

        # ── Phase 6: auth schemes ─────────────────────────────────────
        result.auth_schemes = self._detect_auth_scheme(result.endpoints)

        # ── Phase 7: third-party APIs ─────────────────────────────────
        result.third_party_apis = self._detect_third_party_apis(result.endpoints)

        # ── Phase 8: frameworks ───────────────────────────────────────
        result.frameworks_detected = self._detect_frameworks(result.endpoints)

        # ── Phase 9: risk assessment ──────────────────────────────────
        for ep in result.endpoints:
            ep.risk_level = self._assess_endpoint_risk(ep)

        # ── Phase 10: attack surface ──────────────────────────────────
        result.attack_surface = self._build_attack_surface(result)

        result.total_endpoints = len(result.endpoints)
        logger.info(
            "API discovery for %s: %d endpoints, %d base URLs, %d third-party",
            app_id, result.total_endpoints, len(result.base_urls), len(result.third_party_apis),
        )
        return result

    # ------------------------------------------------------------------
    # Java / Kotlin scanner
    # ------------------------------------------------------------------

    def _scan_java_kotlin(self, source_dir: Path) -> List[APIEndpoint]:
        """Scan Java and Kotlin files for API endpoint patterns."""
        endpoints: List[APIEndpoint] = []
        for fpath in self._iter_files(source_dir, {".java", ".kt", ".smali"}):
            try:
                text = fpath.read_text(errors="replace", encoding="utf-8")
            except Exception as exc:
                logger.debug("Cannot read %s: %s", fpath, exc)
                continue

            rel = str(fpath.relative_to(source_dir))

            # ── Retrofit annotations ─────────────────────────────
            for m in _RETROFIT_ANNOTATION.finditer(text):
                method = m.group(1).upper()
                path = m.group(2).strip()
                line = text[:m.start()].count("\n") + 1
                ep = APIEndpoint(
                    url=path, method=method,
                    source_file=rel, line_number=line,
                    framework="Retrofit",
                    auth_required=self._has_auth_context(text, m.start()),
                )
                endpoints.append(ep)

            # ── OkHttp URL ────────────────────────────────────────
            for m in _OKHTTP_URL.finditer(text):
                url = m.group(1).strip()
                line = text[:m.start()].count("\n") + 1
                method = self._guess_method_from_context(text, m.start())
                ep = APIEndpoint(
                    url=url, method=method,
                    source_file=rel, line_number=line,
                    framework="OkHttp",
                    auth_required=self._has_auth_context(text, m.start()),
                )
                endpoints.append(ep)

            # ── Volley ────────────────────────────────────────────
            for m in _VOLLEY_REQUEST.finditer(text):
                grp1 = m.group(1)  # may be None
                grp2 = m.group(2)
                method = grp1.upper() if grp1 else "GET"
                url = grp2.strip() if grp2 else ""
                if not url:
                    continue
                line = text[:m.start()].count("\n") + 1
                ep = APIEndpoint(
                    url=url, method=method,
                    source_file=rel, line_number=line,
                    framework="Volley",
                    auth_required=self._has_auth_context(text, m.start()),
                )
                endpoints.append(ep)

            # ── HttpURLConnection / new URL ───────────────────────
            for m in _HTTPURL_CONN.finditer(text):
                url = m.group(1).strip()
                line = text[:m.start()].count("\n") + 1
                method = self._guess_method_from_context(text, m.start())
                ep = APIEndpoint(
                    url=url, method=method,
                    source_file=rel, line_number=line,
                    framework="HttpURLConnection",
                    auth_required=self._has_auth_context(text, m.start()),
                )
                endpoints.append(ep)

            # ── Apollo GraphQL ────────────────────────────────────
            for m in _APOLLO_QUERY.finditer(text):
                op_type = m.group(1).lower()
                op_name = m.group(2)
                line = text[:m.start()].count("\n") + 1
                method = "POST" if op_type in ("mutation",) else "POST"
                ep = APIEndpoint(
                    url=f"/graphql ({op_type} {op_name})",
                    method=method,
                    source_file=rel, line_number=line,
                    framework="Apollo GraphQL",
                    auth_required=self._has_auth_context(text, m.start()),
                    notes=f"GraphQL {op_type}: {op_name}",
                )
                endpoints.append(ep)

            # ── WebSocket (Java) ──────────────────────────────────
            for m in _WEBSOCKET_JAVA.finditer(text):
                url = m.group(1).strip()
                line = text[:m.start()].count("\n") + 1
                ep = APIEndpoint(
                    url=url, method="WS",
                    source_file=rel, line_number=line,
                    framework="OkHttp WebSocket",
                    notes="WebSocket connection",
                )
                endpoints.append(ep)

            # ── Axis / fetch in Java WebView  ─────────────────────
            for m in _AXIOS_FETCH.finditer(text):
                url = m.group(1).strip()
                line = text[:m.start()].count("\n") + 1
                method = self._guess_method_from_context(text, m.start())
                ep = APIEndpoint(
                    url=url, method=method,
                    source_file=rel, line_number=line,
                    framework="JS-in-WebView",
                )
                endpoints.append(ep)

            # ── Base URL declarations ─────────────────────────────
            for m in _BASE_URL_DECLS.finditer(text):
                url = m.group(1).rstrip("/")
                ep = APIEndpoint(
                    url=url, method="BASE_URL",
                    source_file=rel,
                    line_number=text[:m.start()].count("\n") + 1,
                    framework="config",
                    notes="Base URL declaration",
                )
                endpoints.append(ep)

            for m in _RETROFIT_BASEURL.finditer(text):
                url = m.group(1).rstrip("/")
                ep = APIEndpoint(
                    url=url, method="BASE_URL",
                    source_file=rel,
                    line_number=text[:m.start()].count("\n") + 1,
                    framework="Retrofit",
                    notes="Retrofit base URL",
                )
                endpoints.append(ep)

        return endpoints

    # ------------------------------------------------------------------
    # Swift / ObjC scanner
    # ------------------------------------------------------------------

    def _scan_swift_objc(self, source_dir: Path) -> List[APIEndpoint]:
        """Scan Swift and Objective-C files for API endpoint patterns."""
        endpoints: List[APIEndpoint] = []
        for fpath in self._iter_files(source_dir, {".swift", ".m", ".h"}):
            try:
                text = fpath.read_text(errors="replace", encoding="utf-8")
            except Exception as exc:
                logger.debug("Cannot read %s: %s", fpath, exc)
                continue

            rel = str(fpath.relative_to(source_dir))

            # ── URLSession ───────────────────────────────────────
            for m in _URLSESSION.finditer(text):
                url = m.group(1).strip()
                line = text[:m.start()].count("\n") + 1
                method = self._guess_method_from_context(text, m.start())
                ep = APIEndpoint(
                    url=url, method=method,
                    source_file=rel, line_number=line,
                    framework="URLSession",
                    auth_required=self._has_auth_context(text, m.start()),
                )
                endpoints.append(ep)

            for m in _URLREQUEST_SWIFT.finditer(text):
                url = m.group(1).strip()
                line = text[:m.start()].count("\n") + 1
                method = self._guess_method_from_context(text, m.start())
                ep = APIEndpoint(
                    url=url, method=method,
                    source_file=rel, line_number=line,
                    framework="URLRequest",
                    auth_required=self._has_auth_context(text, m.start()),
                )
                endpoints.append(ep)

            # ── Alamofire ─────────────────────────────────────────
            for pat in (_ALAMOFIRE, _ALAMOFIRE_OLD):
                for m in pat.finditer(text):
                    url = m.group(1).strip()
                    method_raw = m.group(2) if m.lastindex >= 2 and m.group(2) else "GET"
                    method = method_raw.upper()
                    line = text[:m.start()].count("\n") + 1
                    ep = APIEndpoint(
                        url=url, method=method,
                        source_file=rel, line_number=line,
                        framework="Alamofire",
                        auth_required=self._has_auth_context(text, m.start()),
                    )
                    endpoints.append(ep)

            # ── NSURLRequest (ObjC) ───────────────────────────────
            for m in _NSURLREQUEST.finditer(text):
                url = m.group(1).strip()
                line = text[:m.start()].count("\n") + 1
                method = self._guess_method_from_context(text, m.start())
                ep = APIEndpoint(
                    url=url, method=method,
                    source_file=rel, line_number=line,
                    framework="NSURLRequest",
                    auth_required=self._has_auth_context(text, m.start()),
                )
                endpoints.append(ep)

            # ── AFNetworking ──────────────────────────────────────
            for m in _AFNETWORKING.finditer(text):
                url = m.group(1).strip()
                line = text[:m.start()].count("\n") + 1
                ep = APIEndpoint(
                    url=url, method="GET",
                    source_file=rel, line_number=line,
                    framework="AFNetworking",
                    auth_required=self._has_auth_context(text, m.start()),
                )
                endpoints.append(ep)

            # ── Moya (Swift wrapper over Alamofire) ───────────────
            _moya_case = re.compile(r'case\s+(\w+)\s*=\s*["\']([^"\']+)["\']')
            for m in _moya_case.finditer(text):
                path = m.group(2).strip()
                if "/" in path:
                    line = text[:m.start()].count("\n") + 1
                    ep = APIEndpoint(
                        url=path, method="GET",
                        source_file=rel, line_number=line,
                        framework="Moya",
                    )
                    endpoints.append(ep)

            # ── Base URL (Swift) ──────────────────────────────────
            for m in _BASE_URL_DECLS.finditer(text):
                url = m.group(1).rstrip("/")
                ep = APIEndpoint(
                    url=url, method="BASE_URL",
                    source_file=rel,
                    line_number=text[:m.start()].count("\n") + 1,
                    framework="config",
                    notes="Base URL declaration",
                )
                endpoints.append(ep)

        return endpoints

    # ------------------------------------------------------------------
    # Config file scanner
    # ------------------------------------------------------------------

    def _scan_config_files(self, extracted_dir: Path) -> List[APIEndpoint]:
        """Scan configuration files for API endpoints and base URLs."""
        endpoints: List[APIEndpoint] = []

        # ── google-services.json ──────────────────────────────────
        for cpath in extracted_dir.rglob("google-services.json"):
            try:
                data = json.loads(cpath.read_text(errors="replace"))
                # firebase URL
                firebase_url = (
                    data.get("project_info", {}).get("firebase_url")
                    or data.get("project_info", {}).get("storage_bucket")
                )
                if firebase_url:
                    if not firebase_url.startswith("http"):
                        firebase_url = "https://" + firebase_url
                    endpoints.append(APIEndpoint(
                        url=firebase_url, method="BASE_URL",
                        source_file=str(cpath.relative_to(extracted_dir)),
                        framework="Firebase",
                        notes="Firebase project URL",
                    ))
                # API key usage hints
                for client in data.get("client", []):
                    for api_key in client.get("api_key", []):
                        current_key = api_key.get("current_key", "")
                        if current_key:
                            endpoints.append(APIEndpoint(
                                url="https://googleapis.com",
                                method="BASE_URL",
                                source_file=str(cpath.relative_to(extracted_dir)),
                                framework="Firebase",
                                notes=f"Google API key detected (length={len(current_key)})",
                            ))
                            break
            except Exception as exc:
                logger.debug("Error parsing google-services.json: %s", exc)

        # ── firebase.json ─────────────────────────────────────────
        for cpath in extracted_dir.rglob("firebase.json"):
            try:
                data = json.loads(cpath.read_text(errors="replace"))
                hosting = data.get("hosting", {})
                if isinstance(hosting, dict):
                    site = hosting.get("site", "")
                    if site:
                        endpoints.append(APIEndpoint(
                            url=f"https://{site}.web.app",
                            method="BASE_URL",
                            source_file=str(cpath.relative_to(extracted_dir)),
                            framework="Firebase Hosting",
                            notes="Firebase hosting site",
                        ))
            except Exception as exc:
                logger.debug("Error parsing firebase.json: %s", exc)

        # ── config.xml (Cordova / Ionic) ──────────────────────────
        for cpath in extracted_dir.rglob("config.xml"):
            try:
                from xml.etree import ElementTree as ET
                tree = ET.parse(str(cpath))
                root_el = tree.getroot()
                # <content src="..."> for SPA entry point
                for content in root_el.iter("content"):
                    src = content.get("src", "")
                    if src.startswith("http"):
                        endpoints.append(APIEndpoint(
                            url=src, method="BASE_URL",
                            source_file=str(cpath.relative_to(extracted_dir)),
                            framework="Cordova",
                            notes="Cordova content src",
                        ))
                # <access origin="..."> for allowed URLs
                for access in root_el.iter("access"):
                    origin = access.get("origin", "")
                    if origin and origin != "*" and origin.startswith("http"):
                        endpoints.append(APIEndpoint(
                            url=origin, method="BASE_URL",
                            source_file=str(cpath.relative_to(extracted_dir)),
                            framework="Cordova",
                            notes="Cordova access origin",
                        ))
            except Exception as exc:
                logger.debug("Error parsing config.xml: %s", exc)

        # ── AndroidManifest.xml: deep links + intent-filters ──────
        for cpath in extracted_dir.rglob("AndroidManifest.xml"):
            try:
                from xml.etree import ElementTree as ET
                tree = ET.parse(str(cpath))
                root_el = tree.getroot()
                ns = "{http://schemas.android.com/apk/res/android}"

                for data_el in root_el.iter("data"):
                    scheme = data_el.get(f"{ns}scheme", "")
                    host = data_el.get(f"{ns}host", "")
                    path_prefix = data_el.get(f"{ns}pathPrefix", "")
                    if scheme and host:
                        url = f"{scheme}://{host}{path_prefix}"
                        endpoints.append(APIEndpoint(
                            url=url, method="DEEP_LINK",
                            source_file=str(cpath.relative_to(extracted_dir)),
                            framework="Android Deep Link",
                            notes="Deep link intent-filter",
                        ))
            except Exception as exc:
                logger.debug("Error parsing AndroidManifest.xml: %s", exc)

        # ── .env / .properties files ──────────────────────────────
        for cpath in self._iter_files(extracted_dir, {".properties", ".env", ".cfg"}):
            try:
                text = cpath.read_text(errors="replace", encoding="utf-8")
                for m in _BASE_URL_DECLS.finditer(text):
                    url = m.group(1).rstrip("/")
                    endpoints.append(APIEndpoint(
                        url=url, method="BASE_URL",
                        source_file=str(cpath.relative_to(extracted_dir)),
                        line_number=text[:m.start()].count("\n") + 1,
                        framework="config",
                        notes="Base URL from properties/env file",
                    ))
            except Exception:
                pass

        # ── AndroidManifest meta-data (server URL / API key hints) ─
        for cpath in extracted_dir.rglob("AndroidManifest.xml"):
            try:
                from xml.etree import ElementTree as ET
                tree = ET.parse(str(cpath))
                root_el = tree.getroot()
                ns_android = "http://schemas.android.com/apk/res/android"
                for meta in root_el.iter("meta-data"):
                    name = meta.get(f"{{{ns_android}}}name", "")
                    value = meta.get(f"{{{ns_android}}}value", "")
                    if value.startswith("http"):
                        endpoints.append(APIEndpoint(
                            url=value.rstrip("/"),
                            method="BASE_URL",
                            source_file=str(cpath.relative_to(extracted_dir)),
                            framework="AndroidManifest meta-data",
                            notes=f"meta-data key: {name}",
                        ))
            except Exception:
                pass

        return endpoints

    # ------------------------------------------------------------------
    # JavaScript scanner
    # ------------------------------------------------------------------

    def _scan_js_files(self, extracted_dir: Path) -> List[APIEndpoint]:
        """Scan JavaScript files (React Native bundles, WebView assets) for API patterns."""
        endpoints: List[APIEndpoint] = []

        for fpath in self._iter_files(extracted_dir, {".js", ".ts", ".jsx", ".tsx"}):
            try:
                text = fpath.read_text(errors="replace", encoding="utf-8")
            except Exception:
                continue

            # Skip very large minified bundles but still extract if manageable
            if len(text) > 5_000_000:
                logger.debug("Skipping oversized JS file: %s", fpath)
                continue

            rel = str(fpath.relative_to(extracted_dir))

            # ── axios / fetch ─────────────────────────────────────
            for m in _AXIOS_FETCH.finditer(text):
                url = m.group(1).strip()
                line = text[:m.start()].count("\n") + 1
                method = self._guess_js_method(text, m.start())
                ep = APIEndpoint(
                    url=url, method=method,
                    source_file=rel, line_number=line,
                    framework="axios/fetch",
                    auth_required=self._has_auth_context(text, m.start()),
                )
                endpoints.append(ep)

            # ── XMLHttpRequest ────────────────────────────────────
            for m in _XHR_OPEN.finditer(text):
                method = m.group(1).upper()
                url = m.group(2).strip()
                line = text[:m.start()].count("\n") + 1
                ep = APIEndpoint(
                    url=url, method=method,
                    source_file=rel, line_number=line,
                    framework="XMLHttpRequest",
                    auth_required=self._has_auth_context(text, m.start()),
                )
                endpoints.append(ep)

            # ── superagent ────────────────────────────────────────
            _superagent = re.compile(
                r'request\.(get|post|put|delete|patch)\s*\(\s*["\`]([^"\`\s]+)["\`]'
            )
            for m in _superagent.finditer(text):
                url = m.group(2).strip()
                method = m.group(1).upper()
                line = text[:m.start()].count("\n") + 1
                ep = APIEndpoint(
                    url=url, method=method,
                    source_file=rel, line_number=line,
                    framework="superagent",
                )
                endpoints.append(ep)

            # ── React Native: baseURL from axios.create ───────────
            _axios_create = re.compile(
                r'axios\.create\s*\(\s*\{[^}]*baseURL\s*:\s*["\`]([^"\`\s]+)["\`]'
            )
            for m in _axios_create.finditer(text):
                url = m.group(1).rstrip("/")
                ep = APIEndpoint(
                    url=url, method="BASE_URL",
                    source_file=rel,
                    line_number=text[:m.start()].count("\n") + 1,
                    framework="axios (React Native)",
                    notes="axios.create baseURL",
                )
                endpoints.append(ep)

            # ── Generic https:// URLs in JS ───────────────────────
            _https_url = re.compile(r'["\`](https?://[a-zA-Z0-9\-._~:/?#\[\]@!$&()*+,;=%]{10,})["\`]')
            for m in _https_url.finditer(text):
                url = m.group(1).strip()
                # Filter out obviously non-API URLs
                if any(skip in url for skip in ("schema.org", "w3.org", "xmlns", "example.com", "localhost")):
                    continue
                line = text[:m.start()].count("\n") + 1
                ep = APIEndpoint(
                    url=url, method="GET",
                    source_file=rel, line_number=line,
                    framework="JS literal",
                )
                endpoints.append(ep)

            # ── WebSocket ─────────────────────────────────────────
            for m in _WS_URL.finditer(text):
                ws = m.group(0).strip("\"'`")
                line = text[:m.start()].count("\n") + 1
                ep = APIEndpoint(
                    url=ws, method="WS",
                    source_file=rel, line_number=line,
                    framework="WebSocket (JS)",
                    notes="WebSocket URL",
                )
                endpoints.append(ep)

        return endpoints

    # ------------------------------------------------------------------
    # Helper: extract base URLs from endpoint list
    # ------------------------------------------------------------------

    def _extract_base_urls(self, endpoints: List[APIEndpoint]) -> List[str]:
        """Deduplicate and return unique base URLs from endpoint list."""
        bases: Dict[str, None] = {}  # ordered dict trick
        for ep in endpoints:
            url = ep.url
            if ep.method == "BASE_URL" and url.startswith("http"):
                bases[url.rstrip("/")] = None
                continue
            if url.startswith("http"):
                try:
                    parsed = urlparse(url)
                    base = f"{parsed.scheme}://{parsed.netloc}"
                    if parsed.netloc:
                        bases[base] = None
                except Exception:
                    pass
        return list(bases.keys())

    # ------------------------------------------------------------------
    # Helper: collect WebSocket URLs
    # ------------------------------------------------------------------

    def _collect_websocket_urls(self, extracted_dir: Path) -> List[str]:
        """Find all wss:// and ws:// URLs across source files."""
        ws_urls: List[str] = []
        seen: set = set()
        for fpath in self._iter_files(extracted_dir, _SOURCE_EXTS):
            try:
                text = fpath.read_text(errors="replace", encoding="utf-8")
            except Exception:
                continue
            for m in _WS_URL.finditer(text):
                ws = m.group(0).strip("\"'`")
                if ws not in seen:
                    seen.add(ws)
                    ws_urls.append(ws)
        return ws_urls

    # ------------------------------------------------------------------
    # Helper: collect GraphQL endpoints
    # ------------------------------------------------------------------

    def _collect_graphql_endpoints(self, endpoints: List[APIEndpoint]) -> List[str]:
        """Extract GraphQL endpoint URLs from discovered endpoint list."""
        gql: List[str] = []
        seen: set = set()
        for ep in endpoints:
            if "graphql" in ep.url.lower() or "graphql" in ep.framework.lower() or ep.notes.lower().startswith("graphql"):
                key = ep.url
                if key not in seen:
                    seen.add(key)
                    gql.append(ep.url)
            # Also check the path pattern
            if _GRAPHQL_PATH.search(ep.url) and ep.url not in seen:
                seen.add(ep.url)
                gql.append(ep.url)
        return gql

    # ------------------------------------------------------------------
    # Helper: detect auth schemes
    # ------------------------------------------------------------------

    def _detect_auth_scheme(self, endpoints: List[APIEndpoint]) -> List[str]:
        """
        Infer authentication schemes from endpoint metadata.
        Returns a list of unique scheme labels.
        """
        schemes: set = set()

        # Scan all source files for auth patterns
        for ep in endpoints:
            # From headers already populated
            for h_key in ep.headers:
                h_lower = h_key.lower()
                if "authorization" in h_lower:
                    if "bearer" in ep.headers[h_key].lower():
                        schemes.add("Bearer Token (JWT / OAuth2)")
                    elif "basic" in ep.headers[h_key].lower():
                        schemes.add("HTTP Basic Authentication")
                    else:
                        schemes.add("Authorization Header (unknown scheme)")
                if "x-api-key" in h_lower:
                    schemes.add("API Key (X-API-Key header)")

            # From notes / framework
            notes_lower = ep.notes.lower()
            if "oauth" in notes_lower:
                schemes.add("OAuth 2.0")
            if "jwt" in notes_lower:
                schemes.add("JWT")
            if "bearer" in notes_lower:
                schemes.add("Bearer Token")
            if "apikey" in notes_lower or "api key" in notes_lower:
                schemes.add("API Key")

        return sorted(schemes)

    # ------------------------------------------------------------------
    # Helper: detect third-party APIs
    # ------------------------------------------------------------------

    def _detect_third_party_apis(self, endpoints: List[APIEndpoint]) -> List[Dict]:
        """Identify known third-party API hosts from discovered endpoint URLs."""
        found: Dict[str, Dict] = {}
        for ep in endpoints:
            url = ep.url
            if not url.startswith("http"):
                continue
            try:
                parsed = urlparse(url)
                host = parsed.netloc.lstrip("www.")
            except Exception:
                host = ""
            for api_domain, service_name in _THIRD_PARTY_APIS.items():
                if api_domain in host:
                    if api_domain not in found:
                        found[api_domain] = {
                            "domain": api_domain,
                            "service": service_name,
                            "urls": [],
                            "risk": self._third_party_risk(service_name),
                        }
                    if url not in found[api_domain]["urls"]:
                        found[api_domain]["urls"].append(url)
        return list(found.values())

    def _third_party_risk(self, service_name: str) -> str:
        high_risk = {"Stripe Payments", "Braintree Payments", "PayPal", "Square Payments", "Plaid Finance"}
        medium_risk = {"Twilio SMS/Voice", "SendGrid Email", "Firebase", "Firebase Realtime DB", "OpenAI", "Anthropic Claude"}
        if service_name in high_risk:
            return "high"
        if service_name in medium_risk:
            return "medium"
        return "low"

    # ------------------------------------------------------------------
    # Helper: detect frameworks
    # ------------------------------------------------------------------

    def _detect_frameworks(self, endpoints: List[APIEndpoint]) -> List[str]:
        frameworks: set = set()
        for ep in endpoints:
            if ep.framework and ep.framework not in ("config", "JS literal"):
                frameworks.add(ep.framework)
        return sorted(frameworks)

    # ------------------------------------------------------------------
    # Helper: build attack surface
    # ------------------------------------------------------------------

    def _build_attack_surface(self, result: "APIDiscoveryResult") -> List[Dict]:
        """
        Build a structured attack surface map for all discovered endpoints.
        Each item includes attack vectors, severity, and test methodology.
        """
        surface: List[Dict] = []
        for ep in result.endpoints:
            if ep.method in ("BASE_URL", "DEEP_LINK", "WS"):
                continue

            vectors = self._suggest_attack_vectors(ep)
            if not vectors:
                continue

            surface.append({
                "url": ep.url,
                "method": ep.method,
                "framework": ep.framework,
                "auth_required": ep.auth_required,
                "risk_level": ep.risk_level,
                "source": ep.source_file,
                "attack_vectors": vectors,
            })

        # Also add websocket URLs
        for ws_url in result.websocket_urls:
            surface.append({
                "url": ws_url,
                "method": "WS",
                "framework": "WebSocket",
                "auth_required": False,
                "risk_level": "medium",
                "source": "",
                "attack_vectors": [
                    {"type": "websocket_hijacking", "severity": "medium",
                     "description": "WebSocket connections may lack authentication or CSRF protection.",
                     "test": "Connect without auth header; send crafted JSON payloads; test for SSRF."},
                ],
            })

        # GraphQL endpoints
        for gql_url in result.graphql_endpoints:
            surface.append({
                "url": gql_url,
                "method": "POST",
                "framework": "GraphQL",
                "auth_required": False,
                "risk_level": "high",
                "source": "",
                "attack_vectors": [
                    {"type": "graphql_introspection", "severity": "medium",
                     "description": "GraphQL introspection may expose full schema.",
                     "test": "POST {__schema{types{name}}} to endpoint."},
                    {"type": "graphql_injection", "severity": "high",
                     "description": "GraphQL queries may be vulnerable to injection via variables.",
                     "test": "Use graphw00f, CrackQL, or manual mutation fuzzing."},
                    {"type": "graphql_dos", "severity": "medium",
                     "description": "Deeply nested queries can cause server-side DoS.",
                     "test": "Send deeply nested query (10+ levels); check for query depth limits."},
                ],
            })

        return surface

    def _suggest_attack_vectors(self, ep: APIEndpoint) -> List[Dict]:
        vectors: List[Dict] = []
        path_lower = ep.url.lower()
        method = ep.method.upper()

        # IDOR / BOLA
        if re.search(r'/\d+|/\{[^}]+\}|/:[a-z_]+|/id/|/user_?id|/account', path_lower):
            vectors.append({
                "type": "idor_bola",
                "severity": "high",
                "description": "Endpoint accepts a user-controlled ID parameter — potential IDOR/BOLA.",
                "test": "Enumerate sequential IDs; swap auth tokens; access other users' objects.",
            })

        # Auth bypass
        if not ep.auth_required:
            vectors.append({
                "type": "missing_authentication",
                "severity": "high",
                "description": "No authentication context detected for this endpoint.",
                "test": "Call endpoint without any auth header; check response for data exposure.",
            })

        # Mass assignment (mutation endpoints)
        if method in ("POST", "PUT", "PATCH"):
            vectors.append({
                "type": "mass_assignment",
                "severity": "medium",
                "description": "Write endpoint may accept undocumented fields.",
                "test": "Add role=admin, is_admin=true, verified=true to request body; observe server behaviour.",
            })

        # Rate limiting
        vectors.append({
            "type": "rate_limit_bypass",
            "severity": "medium",
            "description": "Endpoint may lack rate limiting.",
            "test": "Send 20+ rapid requests; check for 429 responses; try IP rotation.",
        })

        # Injection
        if any(kw in path_lower for kw in ("search", "query", "filter", "find", "lookup", "q=")):
            vectors.append({
                "type": "injection",
                "severity": "high",
                "description": "Search/filter endpoint may be vulnerable to SQL/NoSQL injection.",
                "test": "Inject: ' OR 1=1--, {\"$ne\":null}, ../../etc/passwd in search params.",
            })

        # SSRF
        if any(kw in path_lower for kw in ("url", "redirect", "fetch", "proxy", "resource", "load", "webhook")):
            vectors.append({
                "type": "ssrf",
                "severity": "critical",
                "description": "URL/redirect parameter may be abused for SSRF.",
                "test": "Inject http://127.0.0.1/, http://169.254.169.254/latest/meta-data/.",
            })

        # File upload
        if any(kw in path_lower for kw in ("upload", "file", "image", "avatar", "attachment", "import")):
            vectors.append({
                "type": "unrestricted_upload",
                "severity": "critical",
                "description": "File upload endpoint may allow malicious file types.",
                "test": "Upload SVG with XSS, PHP shell, or XXE payload; bypass MIME check.",
            })

        # Admin / privileged
        if any(kw in path_lower for kw in ("admin", "internal", "debug", "management", "console", "dashboard")):
            vectors.append({
                "type": "privilege_escalation",
                "severity": "critical",
                "description": "Admin/internal endpoint accessible — potential privilege escalation.",
                "test": "Access without admin role; test horizontal/vertical privilege escalation.",
            })

        return vectors

    # ------------------------------------------------------------------
    # Helper: assess endpoint risk
    # ------------------------------------------------------------------

    def _assess_endpoint_risk(self, ep: APIEndpoint) -> str:
        """Return risk level: low / medium / high / critical."""
        url_lower = ep.url.lower()
        method = ep.method.upper()

        # Critical indicators
        if any(k in url_lower for k in ("admin", "internal", "debug", "management")):
            return "critical"
        if method in ("DELETE",) and not ep.auth_required:
            return "critical"
        if any(k in url_lower for k in ("payment", "billing", "checkout", "card", "transfer", "webhook")):
            return "critical"

        # High indicators
        if not ep.auth_required and method in ("POST", "PUT", "PATCH", "DELETE"):
            return "high"
        if any(k in url_lower for k in ("user", "account", "profile", "password", "token", "auth")):
            return "high"
        if re.search(r'/\d+|/\{[^}]+\}', url_lower):
            return "high"

        # Medium indicators
        if method in ("POST", "PUT", "PATCH"):
            return "medium"
        if any(k in url_lower for k in ("search", "query", "upload", "file")):
            return "medium"

        return "low"

    # ------------------------------------------------------------------
    # Convert to UnifiedFinding
    # ------------------------------------------------------------------

    def to_unified_findings(self, result: APIDiscoveryResult, target: str = "") -> List[UnifiedFinding]:
        """Convert discovery result into UnifiedFinding objects for the main pipeline."""
        findings: List[UnifiedFinding] = []

        # High-risk endpoints
        critical_eps = [ep for ep in result.endpoints if ep.risk_level in ("critical", "high")]
        if critical_eps:
            findings.append(UnifiedFinding(
                title=f"High-Risk API Endpoints Discovered ({len(critical_eps)} endpoints)",
                severity="high",
                finding_type="api_endpoint_exposure",
                tool="mobile_api_discovery",
                description=(
                    f"Discovered {len(critical_eps)} high/critical risk API endpoints. "
                    "These endpoints handle sensitive operations and require thorough security testing."
                ),
                evidence="\n".join(f"  {ep.method} {ep.url}" for ep in critical_eps[:10]),
                recommendation="Apply least-privilege access control, authenticate all sensitive endpoints, add rate limiting.",
                package=target,
                location=", ".join(set(ep.source_file for ep in critical_eps[:5])),
                raw={"endpoints": [ep.to_dict() for ep in critical_eps]},
            ))

        # Unauthenticated write endpoints
        unauth_write = [ep for ep in result.endpoints
                        if not ep.auth_required and ep.method in ("POST", "PUT", "PATCH", "DELETE")]
        if unauth_write:
            findings.append(UnifiedFinding(
                title=f"Unauthenticated Write Endpoints ({len(unauth_write)})",
                severity="high",
                finding_type="missing_authentication",
                tool="mobile_api_discovery",
                description="Write-method endpoints (POST/PUT/PATCH/DELETE) detected without authentication context.",
                evidence="\n".join(f"  {ep.method} {ep.url}" for ep in unauth_write[:10]),
                recommendation="Require authentication for all state-changing endpoints.",
                package=target,
                raw={"endpoints": [ep.to_dict() for ep in unauth_write]},
            ))

        # Third-party APIs
        high_risk_third_party = [tp for tp in result.third_party_apis if tp.get("risk") in ("high", "medium")]
        if high_risk_third_party:
            findings.append(UnifiedFinding(
                title=f"High-Risk Third-Party API Integrations ({len(high_risk_third_party)})",
                severity="medium",
                finding_type="third_party_api_exposure",
                tool="mobile_api_discovery",
                description=(
                    "The application integrates with high-risk third-party APIs (payment, communication, etc.). "
                    "Hardcoded API keys or insecure configuration may lead to credential theft."
                ),
                evidence="\n".join(f"  {tp['service']}: {tp['domain']}" for tp in high_risk_third_party),
                recommendation="Store third-party API keys server-side; use short-lived tokens; audit all third-party SDK permissions.",
                package=target,
                raw={"third_party_apis": high_risk_third_party},
            ))

        # GraphQL
        if result.graphql_endpoints:
            findings.append(UnifiedFinding(
                title=f"GraphQL Endpoints Detected ({len(result.graphql_endpoints)})",
                severity="medium",
                finding_type="graphql_exposure",
                tool="mobile_api_discovery",
                description="GraphQL endpoints may expose full schema via introspection and be vulnerable to injection/DoS.",
                evidence="\n".join(f"  {url}" for url in result.graphql_endpoints[:5]),
                recommendation="Disable introspection in production; implement query depth/complexity limits; authenticate all queries.",
                package=target,
                cwe="CWE-284",
                raw={"graphql_endpoints": result.graphql_endpoints},
            ))

        # WebSocket
        if result.websocket_urls:
            findings.append(UnifiedFinding(
                title=f"WebSocket Connections Detected ({len(result.websocket_urls)})",
                severity="medium",
                finding_type="websocket_exposure",
                tool="mobile_api_discovery",
                description="WebSocket connections detected. Ensure authentication and message validation are enforced.",
                evidence="\n".join(f"  {u}" for u in result.websocket_urls[:5]),
                recommendation="Authenticate WebSocket upgrade requests; validate all inbound message schemas; implement rate limiting.",
                package=target,
                raw={"websocket_urls": result.websocket_urls},
            ))

        return findings

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _iter_files(self, base: Path, extensions: set) -> List[Path]:
        results: List[Path] = []
        for fpath in base.rglob("*"):
            if fpath.is_file() and fpath.suffix.lower() in extensions:
                # Skip build/test directories
                parts = set(fpath.parts)
                if parts & _SKIP_DIRS:
                    continue
                results.append(fpath)
        return results

    def _has_auth_context(self, text: str, pos: int) -> bool:
        context = text[max(0, pos - 400): pos + 200]
        return any(pat.search(context) for pat in _AUTH_PATTERNS)

    def _guess_method_from_context(self, text: str, pos: int) -> str:
        context = text[max(0, pos - 300): pos + 100]
        for method in ("DELETE", "PATCH", "POST", "PUT", "GET", "HEAD"):
            if method.lower() in context.lower() or f'"{method}"' in context or f"'{method}'" in context:
                return method
        return "GET"

    def _guess_js_method(self, text: str, pos: int) -> str:
        context = text[max(0, pos - 50): pos + 30]
        for method in ("DELETE", "PATCH", "POST", "PUT", "GET"):
            if method.lower() in context.lower():
                return method
        # Check for axios.post, axios.delete, etc.
        m = re.search(r'axios\.(get|post|put|delete|patch|head)', context, re.I)
        if m:
            return m.group(1).upper()
        return "GET"


# Module-level singleton
mobile_api_discovery = MobileAPIDiscovery()
