"""
Execution Pipeline — One&Infinity
==========================================
Modular pipeline that chains all tool wrappers into a structured
recon → discovery → vuln-scan → secrets flow.

Usage:
    from oneinfinity.modules.pipeline import Pipeline
    p = Pipeline(target="example.com", output_dir="/path/to/recon")
    results = p.run(phases=["recon", "ports", "crawl", "content", "vuln", "secrets"])
    print(p.summary())
"""

from __future__ import annotations

import json
import time
import re
from html.parser import HTMLParser
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Optional
from urllib.parse import urljoin, urlparse, urlencode, urlunparse, parse_qsl

from oneinfinity.modules.utils import banner, section, ok, info, warn, err
from oneinfinity.modules.tool_wrappers import ToolRegistry, ToolResult, is_available


# ── Phase result container ────────────────────────────────────────────────────

@dataclass
class PhaseOutput:
    phase: str
    tools_run: list[str] = field(default_factory=list)
    tools_failed: list[str] = field(default_factory=list)
    data: dict = field(default_factory=dict)
    duration: float = 0.0
    error: str = ""


@dataclass
class PipelineResult:
    target: str
    phases_run: list[PhaseOutput] = field(default_factory=list)
    subdomains: list[str] = field(default_factory=list)
    alive_hosts: list[dict] = field(default_factory=list)
    open_ports: list[dict] = field(default_factory=list)
    urls: list[str] = field(default_factory=list)
    endpoints: list[str] = field(default_factory=list)
    findings: list[dict] = field(default_factory=list)
    secrets: list[dict] = field(default_factory=list)
    total_duration: float = 0.0

    def summary(self) -> str:
        lines = [
            f"Target        : {self.target}",
            f"Subdomains    : {len(self.subdomains)}",
            f"Alive hosts   : {len(self.alive_hosts)}",
            f"Open ports    : {len(self.open_ports)}",
            f"URLs crawled  : {len(self.urls)}",
            f"Endpoints     : {len(self.endpoints)}",
            f"Findings      : {len(self.findings)}",
            f"Secrets       : {len(self.secrets)}",
            f"Total time    : {self.total_duration:.1f}s",
        ]
        return "\n".join(lines)

    def to_dict(self) -> dict:
        return {
            "target": self.target,
            "subdomains": self.subdomains,
            "alive_hosts": self.alive_hosts,
            "open_ports": self.open_ports,
            "urls": self.urls,
            "endpoints": self.endpoints,
            "findings": self.findings,
            "secrets": self.secrets,
            "total_duration": self.total_duration,
        }


# ── AI-driven tool selector ───────────────────────────────────────────────────

class ToolSelector:
    """Dynamically choose which tool to use based on target characteristics."""

    def __init__(self, registry: ToolRegistry):
        self.reg = registry
        self._avail = set(registry.available_tools())

    def _pick(self, candidates: list[str]) -> Optional[str]:
        for c in candidates:
            if c in self._avail:
                return c
        return None

    def subdomain_tool(self, domain: str, subdomain_count_hint: int = 0) -> str:
        """Pick subdomain tool: prefer amass for large attack surfaces."""
        if subdomain_count_hint > 100:
            return self._pick(["amass", "subfinder", "assetfinder", "findomain"]) or "subfinder"
        return self._pick(["subfinder", "assetfinder", "amass", "findomain"]) or "subfinder"

    def port_tool(self, target: str, fast: bool = True) -> str:
        """Pick port scanner: rustscan for fast initial scan, nmap for depth."""
        if fast:
            return self._pick(["naabu", "rustscan", "nmap"]) or "nmap"
        return self._pick(["nmap", "naabu", "masscan"]) or "nmap"

    def crawl_tool(self, url: str, has_js: bool = True) -> str:
        """Pick crawling tool: katana is best for JS-heavy apps."""
        if has_js:
            return self._pick(["katana", "hakrawler", "gauplus"]) or "gauplus"
        return self._pick(["hakrawler", "katana", "gauplus"]) or "gauplus"

    def content_tool(self, url: str, many_endpoints: bool = False) -> str:
        """Pick content discovery tool."""
        if many_endpoints:
            return self._pick(["ffuf", "dirsearch", "gobuster"]) or "ffuf"
        return self._pick(["ffuf", "gobuster", "dirsearch"]) or "ffuf"

    def xss_tool(self, url: str, has_forms: bool = True) -> str:
        """Pick XSS scanner: dalfox for forms, kxss for reflected."""
        if has_forms:
            return self._pick(["dalfox", "xssstrike", "kxss"]) or "dalfox"
        return self._pick(["kxss", "dalfox"]) or "kxss"

    def sqli_tool(self) -> str:
        return self._pick(["sqlmap", "commix"]) or "sqlmap"

    def vuln_scanner(self, endpoint_count: int = 0) -> str:
        """For large endpoint counts, nuclei is most scalable."""
        return self._pick(["nuclei", "nikto"]) or "nuclei"

    def secrets_tool(self, is_git_repo: bool = False) -> str:
        if is_git_repo:
            return self._pick(["gitleaks", "trufflehog"]) or "gitleaks"
        return self._pick(["trufflehog", "gitleaks"]) or "trufflehog"


# ── Pipeline ──────────────────────────────────────────────────────────────────

ALL_PHASES = ["recon", "ports", "crawl", "content", "vuln", "secrets"]


# ── Lightweight SPA/API heuristics (no external deps) ────────────────────────

_JS_ENDPOINT_PATTERNS: list[re.Pattern] = [
    re.compile(r"""['"]((?:https?://)[^'"]+/(?:api|v\d+|graphql|rest|ws|rpc|admin|internal)[^'"]*)['"]"""),
    re.compile(r"""['"](/(?:api|v\d+|graphql|rest|ws|rpc|admin|internal)[/\w\-\.\{\}?&=]*)['"]"""),
    re.compile(r"""fetch\s*\(\s*['"]((?:https?://|/)[^'"]+)['"]\s*\)"""),
    re.compile(r"""axios\.[a-z]+\s*\(\s*['"]((?:https?://|/)[^'"]+)['"]\s*\)"""),
    re.compile(r"""(?:url|endpoint|path|route)\s*[:=]\s*['"]((?:https?://|/)[^'"]{4,})['"]"""),
    re.compile(r"""(?:\.get|\.post|\.put|\.delete|\.patch)\s*\(\s*['"]((?:https?://|/)[^'"]+)['"]\s*[,\)]"""),
]
_PARAM_NAME_RE = re.compile(r"""[?&]([a-zA-Z0-9_\-]{1,32})=""")


def extract_js_endpoints_and_params(js_text: str) -> tuple[set[str], set[str]]:
    endpoints: set[str] = set()
    params: set[str] = set()
    if not js_text:
        return endpoints, params
    for pat in _JS_ENDPOINT_PATTERNS:
        for m in pat.finditer(js_text):
            ep = (m.group(1) or "").strip()
            if not ep:
                continue
            if ep.endswith((".png", ".jpg", ".jpeg", ".gif", ".css", ".ico", ".svg", ".woff", ".woff2")):
                continue
            endpoints.add(ep)
    for m in _PARAM_NAME_RE.finditer(js_text):
        params.add(m.group(1))
    return endpoints, params


class _FormParser(HTMLParser):
    def __init__(self) -> None:
        super().__init__()
        self._in_form = False
        self.forms: list[dict[str, Any]] = []
        self._cur: dict[str, Any] | None = None

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        attr = {k.lower(): (v or "") for k, v in attrs}
        if tag.lower() == "form":
            self._in_form = True
            self._cur = {
                "action": attr.get("action", ""),
                "method": (attr.get("method", "get") or "get").lower(),
                "inputs": [],
            }
        if self._in_form and tag.lower() in ("input", "select", "textarea"):
            if not self._cur:
                return
            name = (attr.get("name", "") or "").strip()
            if name:
                self._cur["inputs"].append(name)

    def handle_endtag(self, tag: str) -> None:
        if tag.lower() == "form" and self._in_form:
            self._in_form = False
            if self._cur:
                self.forms.append(self._cur)
            self._cur = None


def build_get_form_urls(base_url: str, html_text: str, max_forms: int = 25) -> list[str]:
    if not html_text:
        return []
    p = _FormParser()
    try:
        p.feed(html_text)
    except Exception:
        return []
    out: list[str] = []
    for f in p.forms[:max_forms]:
        if (f.get("method") or "get").lower() != "get":
            continue
        action = (f.get("action") or "").strip() or base_url
        inputs = [i for i in (f.get("inputs") or []) if isinstance(i, str) and i][:10]
        if not inputs:
            continue
        full = urljoin(base_url, action)
        q = urlencode({k: "1" for k in inputs}, doseq=True)
        u = urlparse(full)
        merged = dict(parse_qsl(u.query, keep_blank_values=True))
        merged.update({k: "1" for k in inputs})
        new_query = urlencode(merged, doseq=True)
        out.append(urlunparse(u._replace(query=new_query)))
    return out


class Pipeline:
    """
    Modular pipeline: recon → ports → crawl → content → vuln → secrets

    Each phase produces data that feeds the next. Errors in one phase
    do not abort subsequent phases.
    """

    def __init__(
        self,
        target: str,
        output_dir: str = ".",
        rate_limit: int = 30,
        timeout_multiplier: float = 1.0,
        subdomain_tools: list[str] = None,
        nuclei_severity: str = "medium,high,critical",
        nuclei_tags: Optional[list[str]] = None,
        oob_url: str = "",
    ):
        self.target = target
        self.output_dir = Path(output_dir)
        self.output_dir.mkdir(parents=True, exist_ok=True)
        self.rate_limit = rate_limit
        self.timeout_mult = timeout_multiplier
        self.nuclei_severity = nuclei_severity
        self.nuclei_tags = nuclei_tags
        self.oob_url = oob_url

        self.reg = ToolRegistry()
        self.sel = ToolSelector(self.reg)
        self.result = PipelineResult(target=target)

    def _t(self, base: int) -> int:
        """Apply timeout multiplier."""
        return int(base * self.timeout_mult)

    def _candidate_base_urls(self) -> list[str]:
        """
        Build a small set of candidate base URLs for the target.

        This is crucial for vuln-only runs where no recon has populated
        alive_hosts yet.
        """
        t = (self.target or "").strip()
        if not t:
            return []
        if "://" in t:
            return [t]

        hostport = t
        port = None
        m = re.search(r":(\d{2,5})$", hostport)
        if m:
            try:
                port = int(m.group(1))
            except Exception:
                port = None

        # Heuristic: non-TLS ports default to http; TLS ports default to https.
        if port in (443, 8443):
            schemes = ["https", "http"]
        elif port is not None:
            schemes = ["http", "https"]
        else:
            schemes = ["https", "http"]

        return [f"{s}://{hostport}" for s in schemes]

    def _seed_alive_urls(self, max_urls: int = 10) -> list[str]:
        alive_urls = [h.get("url", f"https://{h.get('host', '')}") for h in self.result.alive_hosts[:max_urls]]
        alive_urls = [u for u in alive_urls if isinstance(u, str) and "://" in u]
        if alive_urls:
            return alive_urls

        # No recon run yet — seed from target itself
        candidates = self._candidate_base_urls()
        if not candidates:
            return []

        # Prefer a reachable candidate, but always return at least one URL.
        try:
            import requests
            for u in candidates:
                try:
                    r = requests.get(u, timeout=3, allow_redirects=True, verify=False)
                    if getattr(r, "status_code", 0) > 0:
                        return [r.url] if getattr(r, "url", "") else [u]
                except Exception:
                    continue
        except Exception:
            pass

        return [candidates[0]]

    def _save(self, name: str, data: Any):
        """Write phase output to disk as JSON."""
        out_path = self.output_dir / f"{name}.json"
        with open(out_path, "w") as f:
            json.dump(data, f, indent=2, default=str)
        return str(out_path)

    def _http_probe_ok(self, status_code: int) -> bool:
        return status_code in (200, 201, 202, 204, 301, 302, 307, 308, 400, 401, 403, 405)

    def _probe_urls(self, urls: list[str], timeout: int = 4, max_ok: int = 50) -> list[str]:
        """Return URLs that respond (2xx/3xx/401/403/405/400). Best-effort."""
        ok_urls: list[str] = []
        try:
            import requests
        except Exception:
            return []
        for u in urls:
            if len(ok_urls) >= max_ok:
                break
            try:
                r = requests.get(u, timeout=timeout, allow_redirects=True, verify=False, headers={"User-Agent": "Mozilla/5.0"})
                if self._http_probe_ok(getattr(r, "status_code", 0)):
                    ok_urls.append(getattr(r, "url", "") or u)
            except Exception:
                continue
        return ok_urls

    def _discover_spa_api_urls(self, seed_pages: list[str], max_pages: int = 10, max_scripts: int = 20) -> tuple[set[str], set[str]]:
        """
        Fetch a handful of pages and their scripts to extract API endpoints and parameter names.
        Returns: (full_urls, param_names)
        """
        discovered: set[str] = set()
        params: set[str] = set()
        try:
            import requests
        except Exception:
            return discovered, params

        pages = [u for u in seed_pages if isinstance(u, str) and u.startswith(("http://", "https://"))][:max_pages]
        for page in pages:
            try:
                r = requests.get(page, timeout=6, allow_redirects=True, verify=False, headers={"User-Agent": "Mozilla/5.0"})
                ctype = (r.headers.get("content-type") or "").lower()
                if "html" not in ctype and not (r.text or "").lstrip().startswith("<"):
                    continue
                html = r.text or ""
            except Exception:
                continue

            # GET-form mining (helps SQLi/XSS tools trigger even when SPA hides params)
            for u in build_get_form_urls(page, html):
                discovered.add(u)
                if "?" in u:
                    for k, _ in parse_qsl(urlparse(u).query, keep_blank_values=True):
                        if k:
                            params.add(k)

            # Extract script src and inline JS
            script_srcs: list[str] = []
            for m in re.finditer(r"""<script[^>]+src=['"]([^'"]+)['"]""", html, flags=re.IGNORECASE):
                script_srcs.append(m.group(1))
            inline_js = "\n".join(re.findall(r"""<script[^>]*>(.*?)</script>""", html, flags=re.IGNORECASE | re.DOTALL))[:200_000]
            eps, ps = extract_js_endpoints_and_params(inline_js)
            params.update(ps)
            for ep in eps:
                discovered.add(urljoin(page, ep))

            for src in script_srcs[:max_scripts]:
                js_url = urljoin(page, src)
                try:
                    jr = requests.get(js_url, timeout=6, allow_redirects=True, verify=False, headers={"User-Agent": "Mozilla/5.0"})
                    js_text = jr.text or ""
                except Exception:
                    continue
                eps, ps = extract_js_endpoints_and_params(js_text[:400_000])
                params.update(ps)
                for ep in eps:
                    discovered.add(urljoin(page, ep))

        return discovered, params

    def _collect_subdomains(self, result: ToolResult) -> list[str]:
        if not result.success or not result.data:
            return []
        d = result.data
        if isinstance(d, dict):
            return d.get("subdomains", [])
        if isinstance(d, list):
            return d
        return []

    # ── Phase: Recon (subdomain enumeration + HTTP probing) ──────────────────

    def run_recon(self) -> PhaseOutput:
        section("Pipeline: Recon — Subdomain Enumeration & HTTP Probing")
        t0 = time.time()
        phase = PhaseOutput(phase="recon")
        found_subs: set[str] = set()

        # Run multiple subdomain tools in sequence for maximum coverage
        subdomain_tool_order = ["subfinder", "assetfinder", "amass", "findomain",
                                 "chaos", "sublist3r"]
        for tool_name in subdomain_tool_order:
            if not is_available(tool_name):
                continue
            info(f"Subdomain enum via {tool_name}...")
            result = self.reg.run(tool_name, domain=self.target,
                                  timeout=self._t(120))
            if result.success:
                subs = self._collect_subdomains(result)
                before = len(found_subs)
                found_subs.update(subs)
                ok(f"{tool_name}: +{len(found_subs) - before} subdomains")
                phase.tools_run.append(tool_name)
            else:
                warn(f"{tool_name}: {result.error[:80]}")
                phase.tools_failed.append(tool_name)

        # Always include root target
        found_subs.add(self.target)
        self.result.subdomains = sorted(found_subs)
        info(f"Total unique subdomains: {len(self.result.subdomains)}")
        self._save("subdomains", self.result.subdomains)

        # HTTP probing
        if is_available("httpx"):
            info(f"Probing {len(self.result.subdomains)} hosts with httpx...")
            probe_result = self.reg.run("httpx", targets=self.result.subdomains,
                                        timeout=self._t(180))
            if probe_result.success and isinstance(probe_result.data, dict):
                self.result.alive_hosts = probe_result.data.get("hosts", [])
                ok(f"Alive hosts: {len(self.result.alive_hosts)}")
                phase.tools_run.append("httpx")
            else:
                warn(f"httpx probe failed: {probe_result.error[:80]}")
                phase.tools_failed.append("httpx")
                # Fallback: assume all subs are alive
                self.result.alive_hosts = [
                    {"url": f"https://{s}", "host": s, "status-code": 0}
                    for s in self.result.subdomains
                ]
        else:
            warn("httpx not available — skipping HTTP probe")
            self.result.alive_hosts = [
                {"url": f"https://{s}", "host": s}
                for s in self.result.subdomains
            ]

        self._save("alive_hosts", self.result.alive_hosts)
        phase.data = {
            "subdomains": len(self.result.subdomains),
            "alive_hosts": len(self.result.alive_hosts),
        }
        phase.duration = time.time() - t0
        return phase

    # ── Phase: Ports ─────────────────────────────────────────────────────────

    def run_ports(self) -> PhaseOutput:
        section("Pipeline: Port Scanning")
        t0 = time.time()
        phase = PhaseOutput(phase="ports")

        # Only scan top-N alive hosts to avoid rate limits
        targets = [
            h.get("host", h.get("url", "").split("//")[-1].split("/")[0])
            for h in self.result.alive_hosts[:20]
        ]
        targets = [t for t in targets if t]

        if not targets:
            targets = [self.target]

        tool_order = ["naabu", "rustscan", "nmap"]
        for tool_name in tool_order:
            if not is_available(tool_name):
                continue
            info(f"Port scanning {len(targets)} hosts via {tool_name}...")
            ports_found = []
            for target in targets[:10]:
                result = self.reg.run(tool_name, target=target,
                                      timeout=self._t(120))
                if result.success and isinstance(result.data, dict):
                    open_ports = result.data.get("open_ports", [])
                    for p in open_ports:
                        p["host"] = target
                    ports_found.extend(open_ports)
                    if open_ports:
                        ok(f"{target}: {len(open_ports)} open ports")
                elif result.error and "not installed" not in result.error:
                    warn(f"{tool_name} on {target}: {result.error[:60]}")
            phase.tools_run.append(tool_name)
            self.result.open_ports.extend(ports_found)
            break  # use first available tool only

        self._save("ports", self.result.open_ports)
        phase.data = {"open_ports": len(self.result.open_ports)}
        phase.duration = time.time() - t0
        return phase

    # ── Phase: Crawl (URL & parameter discovery) ──────────────────────────────

    def run_crawl(self) -> PhaseOutput:
        section("Pipeline: Web Crawling & URL Discovery")
        t0 = time.time()
        phase = PhaseOutput(phase="crawl")
        all_urls: set[str] = set()

        alive_urls = [h.get("url", f"https://{h.get('host', '')}") for h in
                      self.result.alive_hosts[:15]]
        alive_urls = [u for u in alive_urls if u and "://" in u]
        if not alive_urls:
            alive_urls = self._seed_alive_urls(max_urls=10)

        # Seed common SPA/API entrypoints so deeper tools actually trigger
        api_seeds: list[str] = []
        common_paths = [
            "/", "/login", "/register",
            "/api", "/api/", "/api/v1", "/api/v1/",
            "/rest", "/rest/", "/graphql", "/graphql/",
            "/swagger", "/swagger/", "/swagger/index.html",
            "/swagger.json", "/openapi.json", "/api-docs",
        ]
        for base in alive_urls[:5]:
            for pth in common_paths:
                api_seeds.append(urljoin(base.rstrip("/") + "/", pth.lstrip("/")))
        api_seeds_ok = self._probe_urls(api_seeds, timeout=4, max_ok=60)
        all_urls.update(api_seeds_ok)
        if api_seeds_ok:
            self._save("api_seed_urls", sorted(set(api_seeds_ok)))
            phase.data["api_seed_urls"] = len(set(api_seeds_ok))

        # Historical URLs (Wayback / gauplus) — domain level
        for tool_name in ["gauplus", "waybackurls"]:
            if not is_available(tool_name):
                continue
            info(f"Historical URL discovery via {tool_name}...")
            result = self.reg.run(tool_name, domain=self.target,
                                  timeout=self._t(120))
            if result.success and isinstance(result.data, dict):
                urls = result.data.get("urls", [])
                all_urls.update(urls)
                ok(f"{tool_name}: +{len(urls)} historical URLs")
                phase.tools_run.append(tool_name)

        # Active crawling — per alive host
        for url in alive_urls[:5]:
            # katana / hakrawler for active crawl
            for tool_name in ["katana", "hakrawler"]:
                if not is_available(tool_name):
                    continue
                info(f"Crawling {url} with {tool_name}...")
                if tool_name == "katana":
                    result = self.reg.run(
                        "katana",
                        target=url,
                        depth=5,
                        js_crawl=True,
                        timeout=self._t(240),
                    )
                else:
                    result = self.reg.run("hakrawler", url=url, depth=3,
                                          timeout=self._t(180))
                if result.success and isinstance(result.data, dict):
                    urls = result.data.get("urls", [])
                    all_urls.update(urls)
                    ok(f"{tool_name}: +{len(urls)} URLs from {url}")
                    phase.tools_run.append(tool_name)
                    break

        # Parameter discovery
        if is_available("paramspider"):
            info("Parameter discovery via paramspider...")
            result = self.reg.run("paramspider", domain=self.target,
                                  timeout=self._t(120))
            if result.success and isinstance(result.data, dict):
                param_urls = result.data.get("urls", [])
                all_urls.update(param_urls)
                ok(f"paramspider: +{len(param_urls)} parameterized URLs")
                phase.tools_run.append("paramspider")

        # SPA/API mining: fetch a few pages + their JS and extract endpoint strings
        seed_pages = list(dict.fromkeys(alive_urls + sorted(all_urls)[:10]))
        js_urls, js_params = self._discover_spa_api_urls(seed_pages, max_pages=8, max_scripts=20)
        if js_urls:
            all_urls.update(js_urls)
            self._save("js_endpoints", sorted(js_urls))
        if js_params:
            self._save("js_param_names", sorted(js_params))
        phase.data["js_endpoints"] = len(js_urls)
        phase.data["js_param_names"] = len(js_params)

        self.result.urls = sorted(all_urls)
        self._save("urls", self.result.urls)

        # Classify as endpoints (URLs with parameters); synthesize a few when JS reveals param names
        endpoints: set[str] = set(u for u in self.result.urls if "?" in u)
        # Add a small set of synthetic parameterized URLs so dalfox/sqlmap can engage on SPAs/APIs
        param_names = [p for p in sorted(js_params) if p.lower() not in ("utm_source", "utm_campaign", "utm_medium", "gclid")][:8]
        synth_budget = 40
        if param_names:
            synth_bases = list(dict.fromkeys(api_seeds_ok + alive_urls))[:10]
            for b in synth_bases:
                if synth_budget <= 0:
                    break
                u = urlparse(b)
                merged = dict(parse_qsl(u.query, keep_blank_values=True))
                for p in param_names[: min(4, len(param_names))]:
                    merged.setdefault(p, "1")
                new_query = urlencode(merged, doseq=True)
                endpoints.add(urlunparse(u._replace(query=new_query)))
                synth_budget -= 1

        self.result.endpoints = sorted(endpoints)
        self._save("endpoints", self.result.endpoints)

        phase.data.update({
            "total_urls": len(self.result.urls),
            "endpoints_with_params": len(self.result.endpoints),
        })
        phase.duration = time.time() - t0
        return phase

    # ── Phase: Content Discovery ──────────────────────────────────────────────

    def run_content(self) -> PhaseOutput:
        section("Pipeline: Content & Directory Discovery")
        t0 = time.time()
        phase = PhaseOutput(phase="content")
        new_endpoints: set[str] = set()

        alive_urls = [h.get("url", f"https://{h.get('host', '')}") for h in
                      self.result.alive_hosts[:10]]
        alive_urls = [u for u in alive_urls if "://" in u]

        for url in alive_urls[:5]:
            tool_name = self.sel.content_tool(
                url, many_endpoints=len(self.result.endpoints) > 100
            )
            if not is_available(tool_name):
                # try fallbacks
                tool_name = next(
                    (t for t in ["ffuf", "gobuster", "dirsearch"] if is_available(t)),
                    None
                )
            if not tool_name:
                warn("No content discovery tool available")
                break

            info(f"Content discovery on {url} via {tool_name}...")
            if tool_name == "ffuf":
                result = self.reg.run("ffuf", url=url, timeout=self._t(300))
            elif tool_name == "gobuster":
                result = self.reg.run("gobuster", url=url, timeout=self._t(300))
            else:
                result = self.reg.run("dirsearch", url=url, timeout=self._t(300))

            if result.success and isinstance(result.data, dict):
                found = result.data.get("found", [])
                for item in found:
                    ep = item.get("url", "") or item.get("path", "")
                    if ep:
                        new_endpoints.add(ep)
                ok(f"{tool_name}: {len(found)} paths on {url}")
                phase.tools_run.append(tool_name)
            elif result.error and "wordlist" not in result.error.lower():
                warn(f"{tool_name} on {url}: {result.error[:60]}")
                phase.tools_failed.append(tool_name)

        self.result.endpoints = sorted(set(self.result.endpoints) | new_endpoints)
        # Keep `endpoints.json` as the canonical artifact; preserve legacy `all_endpoints.json`
        self._save("endpoints", self.result.endpoints)
        self._save("all_endpoints", self.result.endpoints)
        # Content discovery paths are also useful for kxss/etc
        self.result.urls = sorted(set(self.result.urls) | new_endpoints)
        self._save("urls", self.result.urls)
        phase.data = {"new_paths_found": len(new_endpoints)}
        phase.duration = time.time() - t0
        return phase

    # ── Phase: Vulnerability Scanning ────────────────────────────────────────

    def run_vuln(self) -> PhaseOutput:
        section("Pipeline: Vulnerability Scanning")
        t0 = time.time()
        phase = PhaseOutput(phase="vuln")
        all_findings: list[dict] = []

        alive_urls = self._seed_alive_urls(max_urls=50)

        # 1. Nuclei — broad scan across all alive hosts
        if is_available("nuclei") and alive_urls:
            info(f"Nuclei scan on {len(alive_urls)} hosts...")
            try:
                if len(alive_urls) > 1:
                    import os
                    import tempfile
                    from oneinfinity.modules.tool_wrappers import run_nuclei_on_list

                    with tempfile.NamedTemporaryFile(mode="w", suffix=".txt", delete=False) as tf:
                        tf.write("\n".join(alive_urls))
                        tf_name = tf.name
                    result = run_nuclei_on_list(
                        tf_name,
                        severity=self.nuclei_severity,
                        timeout=self._t(1800),
                    )
                    os.unlink(tf_name)
                else:
                    result = self.reg.run(
                        "nuclei",
                        target=alive_urls[0],
                        severity=self.nuclei_severity,
                        tags=self.nuclei_tags,
                        timeout=self._t(600),
                    )

                if result.success and isinstance(result.data, dict):
                    findings = result.data.get("findings", [])
                    for f in findings:
                        f["source_tool"] = "nuclei"
                    all_findings.extend(findings)
                    ok(f"nuclei: {len(findings)} findings")
                    phase.tools_run.append("nuclei")
                else:
                    warn(f"nuclei failed: {result.error[:120]}")
                    phase.tools_failed.append("nuclei")
            except Exception as exc:
                warn(f"nuclei crashed: {exc}")
                phase.tools_failed.append("nuclei")

        # 2. Dalfox — XSS scan; use pipe-mode when params are scarce (SPA/APIs)
        param_endpoints = [u for u in self.result.endpoints if isinstance(u, str) and "?" in u][:30]
        if is_available("dalfox"):
            dalfox_targets: list[str] = []
            if param_endpoints:
                dalfox_targets = param_endpoints[:10]
                info(f"Dalfox XSS scan on {len(dalfox_targets)} parameterized endpoints...")
                for url in dalfox_targets:
                    result = self.reg.run("dalfox", url=url, timeout=self._t(180))
                    if result.success and isinstance(result.data, dict):
                        for f in result.data.get("findings", []):
                            if isinstance(f, dict):
                                f["source_tool"] = "dalfox"
                            all_findings.append(f)
            elif self.result.urls:
                dalfox_targets = [u for u in self.result.urls if isinstance(u, str) and u.startswith(("http://", "https://"))][:20]
                info(f"Dalfox XSS scan (pipe mode) on {len(dalfox_targets)} URLs...")
                result = self.reg.run("dalfox", url=dalfox_targets, timeout=self._t(300))
                if result.success and isinstance(result.data, dict):
                    for f in result.data.get("findings", []):
                        if isinstance(f, dict):
                            f["source_tool"] = "dalfox"
                        all_findings.append(f)
            if dalfox_targets:
                phase.tools_run.append("dalfox")

        # 3. CRLF injection
        if is_available("crlfuzz") and alive_urls:
            info("CRLF injection checks...")
            for url in alive_urls[:5]:
                result = self.reg.run("crlfuzz", target=url, timeout=self._t(60))
                if result.success and isinstance(result.data, dict):
                    if result.data.get("vulnerable"):
                        for finding in result.data.get("findings", []):
                            all_findings.append({
                                "source_tool": "crlfuzz",
                                "type": "crlf-injection",
                                "url": url,
                                "evidence": finding,
                                "severity": "medium",
                            })
            phase.tools_run.append("crlfuzz")

        # 4. kxss — reflected XSS on all URLs
        if is_available("kxss") and self.result.urls:
            info(f"kxss reflected XSS check on {min(len(self.result.urls), 200)} URLs...")
            result = self.reg.run("kxss",
                                  urls=self.result.urls[:200],
                                  timeout=self._t(120))
            if result.success and isinstance(result.data, dict):
                reflected = result.data.get("reflected", [])
                for r in reflected:
                    all_findings.append({
                        "source_tool": "kxss",
                        "type": "reflected-xss",
                        "evidence": r,
                        "severity": "medium",
                    })
                if reflected:
                    ok(f"kxss: {len(reflected)} reflected XSS candidates")
            phase.tools_run.append("kxss")

        # 5. Nikto — web server misconfiguration
        if is_available("nikto") and alive_urls:
            info("Nikto web server scan...")
            result = self.reg.run("nikto", target=alive_urls[0],
                                  timeout=self._t(300))
            if result.success:
                phase.tools_run.append("nikto")

        # 6. SQLMap — on form/param endpoints (only high-confidence candidates)
        sqli_candidates = [u for u in param_endpoints
                           if any(p in u.lower() for p in
                                  ["id=", "uid=", "pid=", "user=", "query=", "q=", "search=", "name=", "page=", "item="])][:3]
        if is_available("sqlmap") and sqli_candidates:
            info(f"SQLMap on {len(sqli_candidates)} likely SQLi candidates...")
            for url in sqli_candidates:
                result = self.reg.run("sqlmap", url=url, timeout=self._t(300))
                if result.success and isinstance(result.data, dict):
                    if result.data.get("is_vulnerable"):
                        all_findings.append({
                            "source_tool": "sqlmap",
                            "type": "sql-injection",
                            "url": url,
                            "parameters": result.data.get("vulnerable_parameters", []),
                            "severity": "high",
                        })
            phase.tools_run.append("sqlmap")

        self.result.findings.extend(all_findings)
        self._save("findings", self.result.findings)
        phase.data = {"total_findings": len(all_findings)}
        phase.duration = time.time() - t0
        return phase

    # ── Phase: Secrets Discovery ──────────────────────────────────────────────

    def run_secrets(self) -> PhaseOutput:
        section("Pipeline: Secrets Discovery")
        t0 = time.time()
        phase = PhaseOutput(phase="secrets")

        # TruffleHog on output directory (JS files, responses cached)
        if is_available("trufflehog"):
            info("TruffleHog scan on recon output directory...")
            result = self.reg.run("trufflehog",
                                  target=str(self.output_dir),
                                  target_type="filesystem",
                                  timeout=self._t(180))
            if result.success and isinstance(result.data, dict):
                secrets = result.data.get("secrets", [])
                self.result.secrets.extend(secrets)
                if secrets:
                    ok(f"trufflehog: {len(secrets)} secrets found")
                phase.tools_run.append("trufflehog")

        # Gitleaks — if target output dir looks like a git repo
        git_dir = self.output_dir / ".git"
        if is_available("gitleaks") and git_dir.exists():
            info("Gitleaks scan on local git history...")
            result = self.reg.run("gitleaks", target=str(self.output_dir),
                                  timeout=self._t(120))
            if result.success and isinstance(result.data, dict):
                secrets = result.data.get("secrets", [])
                self.result.secrets.extend(secrets)
                if secrets:
                    ok(f"gitleaks: {len(secrets)} secrets found in git history")
                phase.tools_run.append("gitleaks")

        self._save("secrets", self.result.secrets)
        phase.data = {"secrets_found": len(self.result.secrets)}
        phase.duration = time.time() - t0
        return phase

    # ── Step-level checkpoints ────────────────────────────────────────────────

    def _check_phase_precondition(self, phase_name: str) -> str:
        """Return a non-empty string if precondition is NOT met (caller should skip phase)."""
        # crawl and vuln phases need at least one alive host or URL
        if phase_name in ("crawl", "content", "vuln"):
            if not self.result.alive_hosts and not self.result.urls and not self.result.subdomains:
                return "no alive hosts or URLs discovered yet — recon may have found nothing"
        # secrets phase needs URLs or endpoints
        if phase_name == "secrets":
            if not self.result.urls and not self.result.endpoints:
                return "no URLs or endpoints to scan for secrets"
        return ""

    def _validate_phase_output(self, phase_name: str, phase_output: PhaseOutput) -> None:
        """Log a checkpoint warning if a phase produced no output."""
        data_counts = {
            "recon":   len(self.result.subdomains) + len(self.result.alive_hosts),
            "ports":   len(self.result.open_ports),
            "crawl":   len(self.result.urls),
            "content": len(self.result.endpoints),
            "vuln":    len(self.result.findings),
            "secrets": len(self.result.secrets),
        }
        count = data_counts.get(phase_name, -1)
        if count == 0:
            warn(f"[CHECKPOINT] Phase '{phase_name}' produced 0 results. "
                 f"Tools run: {phase_output.tools_run or 'none'}. "
                 f"Tools failed: {phase_output.tools_failed or 'none'}.")
        elif count > 0:
            ok(f"[CHECKPOINT] Phase '{phase_name}' validated — {count} item(s) accumulated.")

    # ── Master run ────────────────────────────────────────────────────────────

    def run(self, phases: list[str] = None) -> PipelineResult:
        if phases is None:
            phases = ALL_PHASES

        banner(f"Bug Bounty Pipeline — {self.target}")
        info(f"Phases     : {', '.join(phases)}")
        info(f"Output dir : {self.output_dir}")
        info(f"Available  : {', '.join(self.reg.available_tools())}")
        print()

        t_start = time.time()
        phase_map = {
            "recon":   self.run_recon,
            "ports":   self.run_ports,
            "crawl":   self.run_crawl,
            "content": self.run_content,
            "vuln":    self.run_vuln,
            "secrets": self.run_secrets,
        }

        for phase_name in phases:
            if phase_name not in phase_map:
                warn(f"Unknown phase: {phase_name} — skipping")
                continue

            # ── Step-level checkpoint: validate preconditions ─────────────────
            checkpoint_fail = self._check_phase_precondition(phase_name)
            if checkpoint_fail:
                warn(f"[CHECKPOINT] Phase '{phase_name}' skipped — precondition not met: {checkpoint_fail}")
                self.result.phases_run.append(
                    PhaseOutput(phase=phase_name, error=f"precondition-skip: {checkpoint_fail}")
                )
                continue

            try:
                phase_output = phase_map[phase_name]()
                self.result.phases_run.append(phase_output)
                status = "✓" if not phase_output.error else "✗"
                ok(f"Phase '{phase_name}' {status} in {phase_output.duration:.1f}s "
                   f"(tools: {', '.join(phase_output.tools_run) or 'none'})")

                # ── Step-level checkpoint: validate phase output ───────────────
                self._validate_phase_output(phase_name, phase_output)

            except Exception as exc:
                err(f"Phase '{phase_name}' crashed: {exc}")
                self.result.phases_run.append(
                    PhaseOutput(phase=phase_name, error=str(exc))
                )

        self.result.total_duration = time.time() - t_start
        self._save("pipeline_result", self.result.to_dict())

        banner("Pipeline Complete")
        print(self.result.summary())
        print()
        return self.result
