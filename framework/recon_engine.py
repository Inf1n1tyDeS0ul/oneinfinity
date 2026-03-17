"""Phase 2: Autonomous recon — subdomain enum, HTTP probing, cloud discovery."""

import asyncio
import json
import os
import re
import socket
import subprocess
import urllib.request
import urllib.parse
from dataclasses import dataclass, field
from pathlib import Path

from path_manager import resolve_output_dir
from typing import Optional

from modules.utils import banner, section, ok, info, warn, err, write_json, now_str

# ── Embedded subdomain brute wordlist (top 200 common prefixes) ───────────────
SUBDOMAIN_WORDLIST = [
    "www", "mail", "ftp", "localhost", "webmail", "smtp", "pop", "ns1", "ns2",
    "blog", "dev", "server", "api", "m", "mobile", "test", "shop", "admin",
    "support", "vpn", "proxy", "remote", "portal", "forum", "cdn", "static",
    "media", "img", "images", "video", "assets", "app", "apps", "git", "svn",
    "jenkins", "jira", "confluence", "grafana", "kibana", "prometheus", "beta",
    "staging", "stage", "uat", "preprod", "demo", "sandbox", "internal",
    "intranet", "corp", "corporate", "office", "help", "helpdesk", "status",
    "monitor", "metrics", "logs", "auth", "login", "sso", "oauth", "id",
    "identity", "account", "accounts", "user", "users", "api2", "api-v2",
    "v1", "v2", "v3", "graphql", "ws", "websocket", "rest", "services",
    "service", "backend", "frontend", "dashboard", "panel", "manage",
    "management", "console", "control", "cp", "db", "database", "mysql",
    "postgres", "redis", "memcache", "elasticsearch", "solr", "s3", "files",
    "upload", "uploads", "download", "downloads", "store", "storage", "backup",
    "wiki", "docs", "documentation", "kb", "knowledge", "events", "calendar",
    "newsletter", "careers", "jobs", "hr", "finance", "billing", "payment",
    "pay", "checkout", "cart", "crm", "erp", "reports", "reporting", "data",
    "analytics", "insights", "tracking", "click", "ads", "ad", "marketing",
    "survey", "feedback", "chat", "live", "broadcast", "stream", "media2",
    "cms", "content", "editor", "preview", "preview2", "uat2", "test2",
    "dev2", "staging2", "old", "legacy", "archive", "secure", "ssl",
    "waf", "firewall", "gateway", "relay", "bounce", "smtp2", "mx", "mx1",
    "mx2", "imap", "pop3", "webdav", "caldav", "carddav", "ldap", "ad",
    "radius", "ntp", "dns", "dns1", "dns2", "ns3", "ns4", "mail2", "email",
    "exchange", "autodiscover", "autoconfig", "cpanel", "whm", "plesk",
    "directadmin", "webmin", "phpmyadmin", "pma", "phpinfo", "info",
    "health", "ping", "alive", "ready", "actuator", "swagger", "openapi",
    "partners", "partner", "reseller", "affiliate", "affiliates", "refer",
    "integrations", "integration", "webhook", "webhooks", "hooks", "connect",
    "connector", "bridge", "adapter", "gateway2", "proxy2", "cache", "caching",
    "edge", "origin", "internal-api", "private", "secret", "hidden",
]

# ── Cloud asset prefixes ──────────────────────────────────────────────────────
CLOUD_S3_SUFFIXES = [
    "", "-dev", "-staging", "-prod", "-production", "-backup", "-assets",
    "-static", "-media", "-files", "-uploads", "-data", "-logs", "-archive",
    "-public", "-private", "-internal",
]


@dataclass
class HostInfo:
    host: str
    url: str
    status_code: int = 0
    title: str = ""
    tech_stack: list = field(default_factory=list)
    headers: dict = field(default_factory=dict)
    content_length: int = 0
    redirect_url: str = ""


@dataclass
class ReconResult:
    subdomains: list[str] = field(default_factory=list)
    alive_hosts: list[HostInfo] = field(default_factory=list)
    cloud_assets: list[str] = field(default_factory=list)
    total_assets: int = 0


class ReconEngine:
    def __init__(self, program_dir: str, db, rate_limiter=None):
        self.program_dir = Path(program_dir)
        self.db = db
        self.rate_limiter = rate_limiter
        self.recon_dir = resolve_output_dir(self.program_dir / "recon")

    def run(self, target: str, session_id: int) -> ReconResult:
        banner("Phase 2 — Reconnaissance")
        result = ReconResult()

        # 2a: Subdomain enumeration
        section("Subdomain Enumeration")
        subs = self._enumerate_subdomains(target)
        result.subdomains = subs
        info(f"Found {len(subs)} subdomains")
        # Save to file
        write_json(str(self.recon_dir / "subdomains.json"), subs)

        # Filter in scope
        all_hosts = subs + [target]
        try:
            from modules.scope import ScopeManager
            sm = ScopeManager(str(self.program_dir))
            if sm.exists():
                sm.load()
                in_scope, _ = sm.filter_in_scope(all_hosts)
                all_hosts = in_scope
        except Exception:
            pass

        # Save assets to DB
        for sub in subs:
            self.db.save_asset(session_id, "subdomain", sub, source="enum")

        # 2b: HTTP probing
        section("HTTP Probing")
        alive = self._probe_http(list(set(all_hosts)))
        result.alive_hosts = alive
        info(f"Alive hosts: {len(alive)}")

        for h in alive:
            tech = ", ".join(h.tech_stack) if h.tech_stack else None
            self.db.save_asset(
                session_id, "url", h.url,
                source="httpx", status_code=h.status_code, tech_stack=tech
            )

        # Write httpx-style JSON
        httpx_data = [
            {"url": h.url, "status-code": h.status_code, "title": h.title,
             "tech": h.tech_stack, "content-length": h.content_length}
            for h in alive
        ]
        write_json(str(self.recon_dir / "alive_hosts.json"), httpx_data)

        # 2c: Cloud discovery
        section("Cloud Asset Discovery")
        cloud = self._discover_cloud(target)
        result.cloud_assets = cloud
        if cloud:
            ok(f"Cloud assets found: {len(cloud)}")
            for c in cloud:
                self.db.save_asset(session_id, "cloud", c, source="cloud-enum")
        else:
            info("No exposed cloud assets found.")

        result.total_assets = len(subs) + len(alive) + len(cloud)
        ok(f"Phase 2 complete — {result.total_assets} total assets")

        self.db.update_session(session_id, phase_reached=2)
        return result

    # ── Subdomain enumeration ─────────────────────────────────────────────────

    def _enumerate_subdomains(self, target: str) -> list[str]:
        found: set[str] = set()

        # Try tool wrappers first (subfinder, assetfinder, amass, findomain)
        try:
            from modules.tool_wrappers import ToolRegistry, is_available
            reg = ToolRegistry()
            subdomain_tools = ["subfinder", "assetfinder", "findomain", "amass"]
            for tool_name in subdomain_tools:
                if not is_available(tool_name):
                    continue
                result = reg.run(tool_name, domain=target, timeout=120)
                if result.success and isinstance(result.data, dict):
                    subs = result.data.get("subdomains", [])
                    before = len(found)
                    found.update(subs)
                    ok(f"{tool_name}: +{len(found) - before} subdomains")
        except Exception as exc:
            warn(f"Tool wrapper subdomain enum failed: {exc} — using fallbacks")

        # crt.sh certificate transparency (always run)
        try:
            crt_subs = self._crtsh(target)
            before = len(found)
            found.update(crt_subs)
            ok(f"crt.sh: +{len(found) - before} subdomains")
        except Exception as e:
            warn(f"crt.sh lookup failed: {e}")

        # DNS brute force (embedded wordlist) — only if few results so far
        if len(found) < 20:
            try:
                brute_subs = self._dns_brute(target)
                before = len(found)
                found.update(brute_subs)
                ok(f"DNS brute: +{len(found) - before} subdomains")
            except Exception as e:
                warn(f"DNS brute failed: {e}")

        return sorted(found)

    def _crtsh(self, target: str) -> list[str]:
        url = f"https://crt.sh/?q=%.{urllib.parse.quote(target)}&output=json"
        req = urllib.request.Request(
            url, headers={"User-Agent": "Mozilla/5.0 (OneInfinity/1.0)"}
        )
        with urllib.request.urlopen(req, timeout=20) as resp:
            data = json.loads(resp.read())
        subs = set()
        for entry in data:
            for name in entry.get("name_value", "").splitlines():
                name = name.strip().lstrip("*.")
                if name.endswith(f".{target}") or name == target:
                    subs.add(name.lower())
        return list(subs)

    def _dns_brute(self, target: str) -> list[str]:
        found = []
        for prefix in SUBDOMAIN_WORDLIST:
            host = f"{prefix}.{target}"
            try:
                socket.getaddrinfo(host, None, socket.AF_INET)
                found.append(host)
            except socket.gaierror:
                pass
        return found

    # ── HTTP probing ──────────────────────────────────────────────────────────

    def _probe_http(self, hosts: list[str]) -> list[HostInfo]:
        # Try subprocess httpx first
        try:
            return self._probe_httpx_subprocess(hosts)
        except FileNotFoundError:
            pass
        # Pure Python fallback
        return asyncio.run(self._probe_python(hosts))

    def _probe_httpx_subprocess(self, hosts: list[str]) -> list[HostInfo]:
        # Write hosts to tmp file
        tmp = str(self.recon_dir / "_probe_input.txt")
        Path(tmp).write_text("\n".join(hosts))
        out_file = str(self.recon_dir / "_probe_raw.json")

        subprocess.run(
            ["httpx", "-l", tmp, "-json", "-o", out_file,
             "-title", "-tech-detect", "-status-code", "-follow-redirects",
             "-timeout", "10", "-rate-limit", "50"],
            stderr=subprocess.DEVNULL, timeout=300, check=False,
        )
        results = []
        if not Path(out_file).exists():
            return results
        with open(out_file) as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                try:
                    d = json.loads(line)
                except json.JSONDecodeError:
                    continue
                tech = d.get("tech", []) or []
                results.append(HostInfo(
                    host=d.get("host", ""),
                    url=d.get("url", d.get("input", "")),
                    status_code=d.get("status-code", 0),
                    title=d.get("title", ""),
                    tech_stack=tech if isinstance(tech, list) else list(tech),
                    content_length=d.get("content-length", 0),
                ))
        return results

    async def _probe_python(self, hosts: list[str]) -> list[HostInfo]:
        # Try httpx library first, fall back to urllib (stdlib)
        try:
            import httpx as _httpx
            use_httpx = True
        except ImportError:
            use_httpx = False

        results = []
        sem = asyncio.Semaphore(10)

        async def probe(host: str):
            async with sem:
                for scheme in ("https", "http"):
                    url = f"{scheme}://{host}" if not host.startswith("http") else host
                    try:
                        if use_httpx:
                            async with _httpx.AsyncClient(
                                follow_redirects=True,
                                timeout=10,
                                verify=False,
                            ) as client:
                                resp = await client.get(url)
                                body = resp.text
                                hdrs = dict(resp.headers)
                                status = resp.status_code
                                final_url = str(resp.url)
                        else:
                            # stdlib urllib fallback (synchronous via executor)
                            loop = asyncio.get_event_loop()
                            status, body, hdrs, final_url = await loop.run_in_executor(
                                None, self._urllib_get, url
                            )

                        title = ""
                        m = re.search(r"<title[^>]*>([^<]{0,200})</title>",
                                      body, re.IGNORECASE)
                        if m:
                            title = m.group(1).strip()
                        tech = self._fingerprint_tech(hdrs, body)
                        results.append(HostInfo(
                            host=host,
                            url=final_url,
                            status_code=status,
                            title=title,
                            tech_stack=tech,
                            headers=hdrs,
                            content_length=len(body),
                        ))
                        break
                    except Exception:
                        continue

        await asyncio.gather(*[probe(h) for h in hosts])
        return results

    def _urllib_get(self, url: str) -> tuple[int, str, dict, str]:
        """Synchronous urllib GET — used as asyncio executor fallback."""
        import ssl
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        req = urllib.request.Request(
            url, headers={"User-Agent": "Mozilla/5.0 (OneInfinity/1.0)"}
        )
        try:
            with urllib.request.urlopen(req, timeout=10, context=ctx) as resp:
                body = resp.read(200000).decode("utf-8", errors="replace")
                return resp.status, body, dict(resp.headers), resp.url
        except urllib.error.HTTPError as e:
            body = e.read(10000).decode("utf-8", errors="replace")
            return e.code, body, dict(e.headers), url
        except Exception:
            raise

    # ── Tech fingerprinting ───────────────────────────────────────────────────

    def _fingerprint_tech(self, headers, body: str = "") -> list[str]:
        if hasattr(headers, "items"):
            headers_dict = dict(headers)
        else:
            headers_dict = headers or {}
        tech = []
        server = headers_dict.get("server", headers_dict.get("Server", ""))
        if server:
            tech.append(server)
        powered = headers_dict.get("x-powered-by", headers_dict.get("X-Powered-By", ""))
        if powered:
            tech.append(powered)
        # Body-based detection
        patterns = [
            (r"wp-content|wordpress", "WordPress"),
            (r"Drupal\.settings|drupal\.js", "Drupal"),
            (r"Joomla|joomla", "Joomla"),
            (r"ng-version|angular\.js", "Angular"),
            (r"react\.development|__REACT", "React"),
            (r"__vue|vue\.js", "Vue.js"),
            (r"laravel_session|laravel", "Laravel"),
            (r"django|csrfmiddlewaretoken", "Django"),
            (r"spring|org\.springframework", "Spring"),
            (r"asp\.net|__VIEWSTATE", "ASP.NET"),
        ]
        for pattern, label in patterns:
            if re.search(pattern, body, re.IGNORECASE):
                tech.append(label)
        return list(set(tech))

    # ── Cloud discovery ───────────────────────────────────────────────────────

    def _discover_cloud(self, target: str) -> list[str]:
        found = []
        root = target.replace(".", "-")
        base_names = [root] + [f"{root}{s}" for s in CLOUD_S3_SUFFIXES if s]

        for name in base_names[:30]:  # limit checks
            # S3
            s3_url = f"https://{name}.s3.amazonaws.com"
            try:
                req = urllib.request.Request(s3_url, method="HEAD")
                with urllib.request.urlopen(req, timeout=5) as r:
                    if r.status in (200, 403):  # 403 = exists but private
                        found.append(s3_url)
                        ok(f"S3 bucket found: {s3_url} [{r.status}]")
            except Exception:
                pass

            # Azure blobs
            az_url = f"https://{name}.blob.core.windows.net"
            try:
                req = urllib.request.Request(az_url, method="HEAD")
                with urllib.request.urlopen(req, timeout=5) as r:
                    if r.status in (200, 400, 403):
                        found.append(az_url)
                        ok(f"Azure blob found: {az_url} [{r.status}]")
            except Exception:
                pass

            # GCP Storage
            gcp_url = f"https://storage.googleapis.com/{name}"
            try:
                req = urllib.request.Request(gcp_url, method="HEAD")
                with urllib.request.urlopen(req, timeout=5) as r:
                    if r.status in (200, 403):
                        found.append(gcp_url)
                        ok(f"GCP storage found: {gcp_url} [{r.status}]")
            except Exception:
                pass

        return found
