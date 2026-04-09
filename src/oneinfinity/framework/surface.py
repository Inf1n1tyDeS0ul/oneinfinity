"""Phase 3: Attack surface mapping — ports, endpoints, parameters, APIs."""

import asyncio
import json
import re
import socket
import subprocess
import urllib.request
import urllib.parse
from dataclasses import dataclass, field
from pathlib import Path

from oneinfinity.infra.path_manager import resolve_output_dir

from oneinfinity.modules.utils import banner, section, ok, info, warn, write_json

# ── Embedded endpoint wordlist (500 common paths) ────────────────────────────
ENDPOINT_WORDLIST = [
    # Admin / management
    "admin", "admin/", "admin/login", "admin/dashboard", "administrator",
    "manage", "management", "dashboard", "panel", "control", "console",
    "backend", "wp-admin", "wp-login.php", "wp-json", "wp-json/wp/v2",
    "xmlrpc.php", "phpmyadmin", "pma", "webmin", "cpanel", "plesk",
    # Auth
    "login", "logout", "signin", "signup", "register", "auth", "oauth",
    "oauth2", "sso", "saml", "callback", "authorize", "token", "refresh",
    "verify", "activate", "reset", "password", "forgot", "change-password",
    # API
    "api", "api/v1", "api/v2", "api/v3", "api/v4", "v1", "v2", "v3",
    "api/users", "api/user", "api/accounts", "api/account", "api/me",
    "api/profile", "api/settings", "api/config", "api/admin", "api/health",
    "api/status", "api/ping", "api/info", "api/debug", "api/test",
    "api/internal", "api/private", "api/secret", "api/keys", "api/tokens",
    # GraphQL
    "graphql", "graphiql", "graph", "gql", "query",
    # Swagger / OpenAPI
    "swagger", "swagger-ui", "swagger-ui.html", "swagger.json", "swagger.yaml",
    "api-docs", "openapi.json", "openapi.yaml", "openapi", "spec.json",
    "api/swagger", "api/docs",
    # Health / debug
    "health", "healthcheck", "health-check", "ping", "status", "alive",
    "ready", "readiness", "liveness", "metrics", "actuator", "actuator/env",
    "actuator/health", "actuator/info", "actuator/beans", "actuator/mappings",
    "actuator/httptrace", "actuator/loggers", "debug", "info", "test",
    # Config / secrets exposure
    ".env", ".env.local", ".env.production", ".env.development",
    "config", "config.json", "config.yaml", "config.xml", "configuration",
    "settings", "settings.json", "settings.yaml", "application.properties",
    "application.yml", "web.config", "appsettings.json",
    # Git / VCS
    ".git", ".git/config", ".git/HEAD", ".git/index", ".git/COMMIT_EDITMSG",
    ".svn", ".svn/entries", ".hg", ".hg/hgrc", ".bzr",
    # Source maps / debug
    "main.js.map", "app.js.map", "bundle.js.map", "vendor.js.map",
    "robots.txt", "sitemap.xml", "security.txt", ".well-known/security.txt",
    "humans.txt", "crossdomain.xml", "clientaccesspolicy.xml",
    # Upload / files
    "upload", "uploads", "files", "file", "documents", "attachments",
    "media", "images", "img", "static", "assets", "public", "private",
    "download", "downloads", "export", "import", "backup", "backups",
    # User resources
    "user", "users", "account", "accounts", "profile", "profiles",
    "me", "self", "whoami", "session", "sessions", "token", "tokens",
    "key", "keys", "secret", "secrets", "password", "passwords", "cred",
    # SOAP / WSDL
    "wsdl", "service.wsdl", "api.wsdl", "webservice", "ws", "soap",
    # Common CMS
    "wp-content/uploads", "sites/default/files", "joomla", "drupal",
    "Magento", "prestashop", "opencart",
    # Server info
    "server-status", "server-info", "phpinfo.php", "info.php", "test.php",
    "php-info.php", "phpinfo", "_profiler", "_profiler/phpinfo",
    # Database admin
    "adminer", "adminer.php", "dbadmin", "myadmin", "mysql",
    # Monitoring
    "grafana", "kibana", "prometheus", "jaeger", "zipkin", "splunk",
    "datadog", "newrelic", "elastic", "logstash",
    # Internal tools
    "jenkins", "gitlab", "jira", "confluence", "sonar", "nexus",
    "artifactory", "harbor", "portainer", "rancher",
    # Misc
    "cgi-bin", "cgi-bin/test-cgi", "cgi-bin/printenv", ".DS_Store",
    "Thumbs.db", "htaccess", ".htaccess", "web.xml", "WEB-INF/web.xml",
    "WEB-INF", "META-INF", "crossdomain.xml",
]

TOP_PORTS = [
    21, 22, 23, 25, 53, 80, 110, 111, 135, 139, 143, 443, 445, 993, 995,
    1433, 1521, 2049, 2181, 3000, 3306, 3389, 4000, 4848, 5000, 5432, 5601,
    5672, 5900, 6379, 7001, 7080, 7443, 8000, 8008, 8009, 8080, 8088, 8443,
    8500, 8888, 9000, 9090, 9200, 9300, 9418, 9999, 10000, 11211, 15672,
    27017, 27018, 28017, 50000, 50030, 50070, 61616,
]


@dataclass
class PortInfo:
    host: str
    port: int
    open: bool = True
    banner: str = ""


@dataclass
class ParamInfo:
    url: str
    name: str
    source: str  # query|form|js|header
    method: str = "GET"


@dataclass
class ApiMap:
    host: str
    api_endpoints: list[str] = field(default_factory=list)
    graphql: list[str] = field(default_factory=list)
    swagger: list[str] = field(default_factory=list)
    soap_wsdl: list[str] = field(default_factory=list)


@dataclass
class SurfaceResult:
    alive_hosts: list = field(default_factory=list)   # HostInfo objects from recon
    ports: list[PortInfo] = field(default_factory=list)
    endpoints: list[str] = field(default_factory=list)
    parameters: list[ParamInfo] = field(default_factory=list)
    apis: list[ApiMap] = field(default_factory=list)


class SurfaceMapper:
    def __init__(self, program_dir: str, db, rate_limiter=None):
        self.program_dir = Path(program_dir)
        self.db = db
        self.rate_limiter = rate_limiter
        self.recon_dir = resolve_output_dir(self.program_dir / "recon")

    def run(self, alive_hosts, session_id: int) -> SurfaceResult:
        banner("Phase 3 — Attack Surface Mapping")
        result = SurfaceResult(alive_hosts=list(alive_hosts))

        # Extract hostnames from HostInfo objects or strings
        hosts = []
        for h in alive_hosts:
            if hasattr(h, "host"):
                hosts.append(h.host)
            else:
                hosts.append(str(h))

        hosts = list(set(hosts))
        info(f"Mapping surface for {len(hosts)} hosts")

        # 3a: Port scanning
        section("Port Scanning")
        for host in hosts[:20]:  # cap to avoid excessive scanning
            ports = self._scan_ports(host)
            result.ports.extend(ports)
            for p in ports:
                self.db.save_surface_item(
                    session_id, "port", host, str(p.port),
                    extra={"open": p.open, "banner": p.banner}
                )
        ok(f"Open ports found: {len(result.ports)}")

        # 3b: Endpoint discovery
        section("Endpoint Discovery")
        all_endpoints = []
        for host in hosts[:10]:  # cap
            eps = self._discover_endpoints(host)
            all_endpoints.extend(eps)
            for ep in eps:
                self.db.save_surface_item(session_id, "endpoint", host, ep, method="GET")
        result.endpoints = all_endpoints
        ok(f"Endpoints discovered: {len(all_endpoints)}")

        # 3c: Parameter extraction
        section("Parameter Extraction")
        for ep in all_endpoints[:100]:  # cap
            params = self._extract_parameters(ep)
            result.parameters.extend(params)
            for p in params:
                self.db.save_surface_item(
                    session_id, "parameter", p.url.split("/")[2] if "://" in p.url else "",
                    p.name, method=p.method,
                    extra={"source": p.source, "url": p.url}
                )
        ok(f"Parameters found: {len(result.parameters)}")

        # 3d: API mapping
        section("API Mapping")
        for host in hosts[:10]:
            api_map = self._map_apis(host, [ep for ep in all_endpoints if host in ep])
            result.apis.append(api_map)
            for ep in api_map.api_endpoints:
                self.db.save_surface_item(session_id, "api", host, ep)
            for ep in api_map.graphql:
                self.db.save_surface_item(session_id, "api", host, ep,
                                          extra={"type": "graphql"})
            for ep in api_map.swagger:
                self.db.save_surface_item(session_id, "api", host, ep,
                                          extra={"type": "swagger"})

        write_json(str(self.recon_dir / "surface.json"), {
            "ports": [{"host": p.host, "port": p.port} for p in result.ports],
            "endpoints": result.endpoints[:500],
            "parameter_count": len(result.parameters),
        })

        self.db.update_session(session_id, phase_reached=3)
        ok("Phase 3 complete")
        return result

    # ── Port scanning ─────────────────────────────────────────────────────────

    def _scan_ports(self, host: str) -> list[PortInfo]:
        # Try nmap first
        try:
            return self._nmap_scan(host)
        except FileNotFoundError:
            pass
        # Asyncio TCP fallback
        return asyncio.run(self._tcp_scan(host))

    def _nmap_scan(self, host: str) -> list[PortInfo]:
        out = subprocess.check_output(
            ["nmap", "-sV", "--open", "-T4", "--top-ports", "1000",
             "-oX", "-", host],
            stderr=subprocess.DEVNULL, timeout=120,
        )
        results = []
        # Parse XML output
        import xml.etree.ElementTree as ET
        root = ET.fromstring(out)
        for port_el in root.iter("port"):
            state_el = port_el.find("state")
            if state_el is None or state_el.get("state") != "open":
                continue
            port_num = int(port_el.get("portid", 0))
            svc_el = port_el.find("service")
            banner_str = ""
            if svc_el is not None:
                banner_str = f"{svc_el.get('name','')} {svc_el.get('version','')}".strip()
            results.append(PortInfo(host=host, port=port_num, banner=banner_str))
        return results

    async def _tcp_scan(self, host: str) -> list[PortInfo]:
        open_ports = []
        sem = asyncio.Semaphore(100)

        async def check_port(port: int):
            async with sem:
                try:
                    fut = asyncio.open_connection(host, port)
                    _, writer = await asyncio.wait_for(fut, timeout=2)
                    writer.close()
                    open_ports.append(PortInfo(host=host, port=port))
                except Exception:
                    pass

        await asyncio.gather(*[check_port(p) for p in TOP_PORTS])
        return open_ports

    # ── Endpoint discovery ────────────────────────────────────────────────────

    def _discover_endpoints(self, host: str) -> list[str]:
        # Try ffuf
        try:
            return self._ffuf_discover(host)
        except FileNotFoundError:
            pass
        # Pure Python fallback
        return asyncio.run(self._python_discover(host))

    def _ffuf_discover(self, host: str) -> list[str]:
        wl_path = str(self.recon_dir / "_wordlist.txt")
        Path(wl_path).write_text("\n".join(ENDPOINT_WORDLIST))
        base_url = f"https://{host}/FUZZ"
        out_file = str(self.recon_dir / f"_ffuf_{host.replace('.', '_')}.json")

        subprocess.run(
            ["ffuf", "-u", base_url, "-w", wl_path, "-of", "json",
             "-o", out_file, "-mc", "200,201,204,301,302,307,400,401,403,405,500",
             "-t", "50", "-timeout", "10", "-s"],
            stderr=subprocess.DEVNULL, timeout=180, check=False,
        )

        results = []
        if Path(out_file).exists():
            try:
                data = json.loads(Path(out_file).read_text())
                for r in data.get("results", []):
                    results.append(r.get("url", ""))
            except Exception:
                pass
        return [r for r in results if r]

    async def _python_discover(self, host: str) -> list[str]:
        found = []
        sem = asyncio.Semaphore(20)
        loop = asyncio.get_event_loop()

        def _check_sync(url: str) -> bool:
            import ssl
            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
            req = urllib.request.Request(
                url, headers={"User-Agent": "Mozilla/5.0 (OneInfinity/1.0)"}
            )
            try:
                with urllib.request.urlopen(req, timeout=8, context=ctx) as resp:
                    return resp.status not in (404,)
            except urllib.error.HTTPError as e:
                return e.code not in (404,)
            except Exception:
                return False

        async def check(path: str):
            async with sem:
                for scheme in ("https", "http"):
                    url = f"{scheme}://{host}/{path.lstrip('/')}"
                    try:
                        alive = await loop.run_in_executor(None, _check_sync, url)
                        if alive:
                            found.append(url)
                        break
                    except Exception:
                        break

        await asyncio.gather(*[check(p) for p in ENDPOINT_WORDLIST])
        return found

    # ── Parameter extraction ──────────────────────────────────────────────────

    def _extract_parameters(self, url: str) -> list[ParamInfo]:
        params = []

        # GET params from URL
        parsed = urllib.parse.urlparse(url)
        qs = urllib.parse.parse_qs(parsed.query)
        for name in qs:
            params.append(ParamInfo(url=url, name=name, source="query", method="GET"))

        # Fetch page and extract form fields + JS patterns
        try:
            req = urllib.request.Request(
                url, headers={"User-Agent": "Mozilla/5.0 (OneInfinity/1.0)"}
            )
            with urllib.request.urlopen(req, timeout=10) as resp:
                body = resp.read(50000).decode("utf-8", errors="replace")

            # HTML form fields
            form_names = re.findall(r'<input[^>]+name=["\']([^"\']+)["\']', body, re.IGNORECASE)
            for name in form_names:
                params.append(ParamInfo(url=url, name=name, source="form", method="POST"))

            # JS fetch/axios parameter patterns
            js_params = re.findall(r'[?&]([a-zA-Z_][a-zA-Z0-9_-]{0,30})=', body)
            for name in set(js_params):
                params.append(ParamInfo(url=url, name=name, source="js", method="GET"))

        except Exception:
            pass

        return params

    # ── API mapping ───────────────────────────────────────────────────────────

    def _map_apis(self, host: str, endpoints: list[str]) -> ApiMap:
        api_map = ApiMap(host=host)

        for ep in endpoints:
            path = urllib.parse.urlparse(ep).path.lower()
            if re.search(r"/api/|/v\d+/|/rest/|/rpc/", path):
                api_map.api_endpoints.append(ep)
            if re.search(r"/graphql|/gql|/graph\b", path):
                api_map.graphql.append(ep)
            if re.search(r"/swagger|/openapi|/api-docs|/spec\.json", path):
                api_map.swagger.append(ep)
            if re.search(r"\.wsdl|/soap|/ws\b", path):
                api_map.soap_wsdl.append(ep)

        # Also probe common API roots not in endpoints
        for scheme in ("https", "http"):
            for api_path in ("/graphql", "/api/graphql", "/swagger.json", "/openapi.json"):
                url = f"{scheme}://{host}{api_path}"
                try:
                    req = urllib.request.Request(
                        url, headers={"User-Agent": "Mozilla/5.0"}
                    )
                    with urllib.request.urlopen(req, timeout=5) as resp:
                        if resp.status == 200:
                            if "graphql" in api_path and url not in api_map.graphql:
                                api_map.graphql.append(url)
                            elif url not in api_map.swagger:
                                api_map.swagger.append(url)
                except Exception:
                    pass

        return api_map
