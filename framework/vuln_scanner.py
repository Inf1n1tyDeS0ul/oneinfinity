"""Phase 4: Vulnerability discovery — XSS, SSRF, IDOR, CORS, secrets, misconfigs."""

import json
import re
import time
import urllib.parse
import urllib.request
from dataclasses import dataclass, field
from typing import Optional

from modules.utils import banner, section, ok, info, warn, err

# ── Reuse secret patterns from analyzer ───────────────────────────────────────
try:
    from modules.analyzer import SECRET_PATTERNS
except ImportError:
    SECRET_PATTERNS = [
        (r"(?i)(api[_-]?key|apikey)\s*[:=]\s*['\"]([A-Za-z0-9_\-]{16,})['\"]", "API Key"),
        (r"(?i)(secret[_-]?key|secret)\s*[:=]\s*['\"]([A-Za-z0-9_\-]{16,})['\"]", "Secret Key"),
        (r"(?i)(access[_-]?token|auth[_-]?token)\s*[:=]\s*['\"]([A-Za-z0-9._\-]{20,})['\"]", "Token"),
        (r"AKIA[0-9A-Z]{16}", "AWS Access Key"),
        (r"(?i)(password|passwd|pwd)\s*[:=]\s*['\"]([^'\"]{6,})['\"]", "Password"),
    ]

# ── XSS probe payloads ────────────────────────────────────────────────────────
XSS_PROBES = [
    'xsstest<"\'>', "xsstest<script>", "xsstest<img src=x>",
    "<svg onload=1>", "\"'><svg/onload=1>",
]

# ── SSRF targets ──────────────────────────────────────────────────────────────
SSRF_INTERNAL_TARGETS = [
    "http://127.0.0.1/",
    "http://localhost/",
    "http://169.254.169.254/latest/meta-data/",
    "http://metadata.google.internal/computeMetadata/v1/",
    "http://169.254.169.254/metadata/v1/",
]

# ── Misconfiguration paths ────────────────────────────────────────────────────
MISCONFIG_PATHS = [
    ".git/config", ".git/HEAD", ".env", ".env.local", ".env.production",
    "swagger.json", "swagger.yaml", "openapi.json", "openapi.yaml",
    "api-docs.json", "actuator/env", "actuator/health", "actuator/beans",
    "phpinfo.php", "info.php", "server-status", "server-info",
    "wp-config.php.bak", "config.php.bak", "backup.sql", "dump.sql",
    "database.sql", "db.sql", "web.config.bak", ".htaccess",
]

# ── Common URL parameters that often carry URLs ───────────────────────────────
URL_PARAMS = [
    "url", "uri", "link", "src", "source", "redirect", "return", "next",
    "target", "dest", "destination", "redir", "goto", "path", "file",
    "page", "load", "fetch", "webhook", "callback", "service", "host",
    "proxy", "api", "endpoint", "remote", "resource", "image", "img",
]


@dataclass
class VulnCandidate:
    vuln_type: str
    host: str
    endpoint: str
    parameter: str = ""
    method: str = "GET"
    payload: str = ""
    evidence: str = ""
    confidence: str = "medium"  # low|medium|high


class VulnScanner:
    def __init__(self, program_dir, db, session_id: int, rate_limiter=None, oob_url: str = ""):
        self.program_dir = program_dir
        self.db = db
        self.session_id = session_id
        self.rate_limiter = rate_limiter
        self.oob_url = oob_url
        self._response_cache: dict[str, tuple] = {}  # url → (status, body, headers)

    def run(self, surface, session_id: int) -> list[VulnCandidate]:
        banner("Phase 4 — Vulnerability Discovery")
        all_candidates: list[VulnCandidate] = []

        # Collect hosts and endpoints from surface result (SurfaceResult) or recon fallback
        alive_hosts: list[str] = []
        endpoints: list[str] = []
        params_by_url: dict[str, list] = {}

        if surface:
            # SurfaceResult has .endpoints, .parameters, .ports
            # ReconResult has .alive_hosts
            if hasattr(surface, "alive_hosts"):
                for h in surface.alive_hosts:
                    url = h.url if hasattr(h, "url") else str(h)
                    host = h.host if hasattr(h, "host") else (url.split("/")[2] if "://" in url else url)
                    alive_hosts.append(host)
                    endpoints.append(url)
            if hasattr(surface, "endpoints"):
                for ep in surface.endpoints:
                    if ep not in endpoints:
                        endpoints.append(ep)
                    host = ep.split("/")[2] if "://" in ep else ep
                    if host not in alive_hosts:
                        alive_hosts.append(host)
            if hasattr(surface, "parameters"):
                for p in surface.parameters:
                    params_by_url.setdefault(p.url, []).append(p)

        alive_hosts = list(set(alive_hosts))
        endpoints = list(set(endpoints))

        info(f"Scanning {len(alive_hosts)} hosts, {len(endpoints)} endpoints")

        # ── Per-host checks ────────────────────────────────────────────────────
        section("CORS Checks")
        for host in alive_hosts[:20]:
            c = self.check_cors(host)
            if c:
                all_candidates.append(c)
                self._save(c)

        section("Security Header Checks")
        for host in alive_hosts[:20]:
            for c in self.check_headers(host):
                all_candidates.append(c)
                self._save(c)

        section("Misconfiguration Checks")
        for host in alive_hosts[:10]:
            for ep in endpoints[:5]:
                for c in self.check_misconfigs(host, ep):
                    all_candidates.append(c)
                    self._save(c)

        # ── Per-endpoint/param checks ─────────────────────────────────────────
        section("XSS Checks")
        for url, plist in list(params_by_url.items())[:30]:
            host = url.split("/")[2] if "://" in url else ""
            pnames = [p.name for p in plist]
            for c in self.check_xss(host, url, pnames):
                all_candidates.append(c)
                self._save(c)

        section("SSRF Checks")
        for url, plist in list(params_by_url.items())[:30]:
            host = url.split("/")[2] if "://" in url else ""
            pnames = [p.name for p in plist]
            for c in self.check_ssrf(host, url, pnames):
                all_candidates.append(c)
                self._save(c)

        section("IDOR Checks")
        for url, plist in list(params_by_url.items())[:30]:
            host = url.split("/")[2] if "://" in url else ""
            pnames = [p.name for p in plist]
            for c in self.check_idor(host, url, pnames):
                all_candidates.append(c)
                self._save(c)

        section("Open Redirect Checks")
        for url, plist in list(params_by_url.items())[:30]:
            host = url.split("/")[2] if "://" in url else ""
            c = self.check_open_redirect(host, url)
            if c:
                all_candidates.append(c)
                self._save(c)

        section("Secret Scanning")
        # Collect response bodies
        responses = []
        for ep in endpoints[:50]:
            status, body, headers = self._fetch(ep)
            if body:
                responses.append({"url": ep, "body": body, "headers": headers})
        for c in self.check_secrets(responses):
            all_candidates.append(c)
            self._save(c)

        section("Auth Bypass Checks")
        for ep in endpoints[:20]:
            host = ep.split("/")[2] if "://" in ep else ""
            for c in self.check_auth_bypass(host, ep):
                all_candidates.append(c)
                self._save(c)

        # ── Tool wrapper integrations ─────────────────────────────────────────
        section("Nuclei Scan (tool wrapper)")
        nuclei_candidates = self._run_nuclei_wrapper(endpoints[:10])
        all_candidates.extend(nuclei_candidates)

        section("Dalfox XSS Scan (tool wrapper)")
        dalfox_candidates = self._run_dalfox_wrapper(
            [ep for ep in endpoints if "?" in ep][:10]
        )
        all_candidates.extend(dalfox_candidates)

        section("CRLF Injection (tool wrapper)")
        crlf_candidates = self._run_crlfuzz_wrapper(endpoints[:5])
        all_candidates.extend(crlf_candidates)

        self.db.update_session(session_id, phase_reached=4)
        ok(f"Phase 4 complete — {len(all_candidates)} candidates found")
        return all_candidates

    # ── Tool wrapper integrations ─────────────────────────────────────────────

    def _run_nuclei_wrapper(self, endpoints: list[str]) -> list[VulnCandidate]:
        candidates = []
        try:
            from modules.tool_wrappers import is_available, run_nuclei
            if not is_available("nuclei") or not endpoints:
                return candidates
            for ep in endpoints:
                result = run_nuclei(ep, severity="medium,high,critical", timeout=120)
                if result.success and isinstance(result.data, dict):
                    for f in result.data.get("findings", []):
                        host = ep.split("/")[2] if "://" in ep else ep
                        candidates.append(VulnCandidate(
                            vuln_type=f"Nuclei:{f.get('name', f.get('template_id', 'unknown'))}",
                            host=host,
                            endpoint=f.get("matched_at", ep),
                            evidence=(f"[{f.get('severity', 'info').upper()}] "
                                      f"{f.get('description', '')[:200]}"),
                            confidence={"critical": "high", "high": "high",
                                        "medium": "medium"}.get(
                                f.get("severity", "low"), "low"),
                        ))
        except Exception as exc:
            warn(f"nuclei wrapper failed: {exc}")
        return candidates

    def _run_dalfox_wrapper(self, endpoints: list[str]) -> list[VulnCandidate]:
        candidates = []
        try:
            from modules.tool_wrappers import is_available, run_dalfox
            if not is_available("dalfox") or not endpoints:
                return candidates
            for ep in endpoints:
                result = run_dalfox(ep, timeout=60)
                if result.success and isinstance(result.data, dict):
                    for f in result.data.get("findings", []):
                        host = ep.split("/")[2] if "://" in ep else ep
                        evidence = f.get("raw", str(f))[:200]
                        candidates.append(VulnCandidate(
                            vuln_type="XSS",
                            host=host,
                            endpoint=ep,
                            evidence=f"dalfox: {evidence}",
                            confidence="high",
                        ))
        except Exception as exc:
            warn(f"dalfox wrapper failed: {exc}")
        return candidates

    def _run_crlfuzz_wrapper(self, endpoints: list[str]) -> list[VulnCandidate]:
        candidates = []
        try:
            from modules.tool_wrappers import is_available, run_crlfuzz
            if not is_available("crlfuzz") or not endpoints:
                return candidates
            for ep in endpoints:
                result = run_crlfuzz(ep, timeout=30)
                if result.success and isinstance(result.data, dict):
                    if result.data.get("vulnerable"):
                        host = ep.split("/")[2] if "://" in ep else ep
                        candidates.append(VulnCandidate(
                            vuln_type="CRLF Injection",
                            host=host,
                            endpoint=ep,
                            evidence="crlfuzz confirmed CRLF injection",
                            confidence="high",
                        ))
        except Exception as exc:
            warn(f"crlfuzz wrapper failed: {exc}")
        return candidates

    # ── Internal helpers ──────────────────────────────────────────────────────

    def _fetch(self, url: str, method: str = "GET", headers: dict = None,
               body: bytes = None, timeout: int = 10) -> tuple[int, str, dict]:
        cache_key = f"{method}:{url}:{body}"
        if cache_key in self._response_cache:
            return self._response_cache[cache_key]

        if self.rate_limiter:
            self.rate_limiter.wait()

        h = {"User-Agent": "Mozilla/5.0 (OneInfinity/1.0)"}
        if headers:
            h.update(headers)
        try:
            req = urllib.request.Request(url, headers=h, method=method, data=body)
            with urllib.request.urlopen(req, timeout=timeout) as resp:
                resp_body = resp.read(100000).decode("utf-8", errors="replace")
                resp_headers = dict(resp.headers)
                result = (resp.status, resp_body, resp_headers)
        except urllib.error.HTTPError as e:
            result = (e.code, e.read(10000).decode("utf-8", errors="replace"),
                      dict(e.headers))
        except Exception:
            result = (0, "", {})

        self._response_cache[cache_key] = result
        return result

    def _save(self, c: VulnCandidate):
        self.db.save_candidate(
            self.session_id, c.vuln_type, c.host, c.endpoint,
            parameter=c.parameter, method=c.method,
            payload=c.payload, evidence=c.evidence[:500],
            confidence=c.confidence,
        )
        level = {"high": ok, "medium": warn, "low": info}.get(c.confidence, info)
        level(f"[{c.confidence.upper()}] {c.vuln_type} @ {c.endpoint}"
              + (f" [{c.parameter}]" if c.parameter else ""))

    # ── XSS ──────────────────────────────────────────────────────────────────

    def check_xss(self, host: str, endpoint: str, params: list[str]) -> list[VulnCandidate]:
        candidates = []
        parsed = urllib.parse.urlparse(endpoint)
        qs = dict(urllib.parse.parse_qsl(parsed.query))

        for param in params:
            for probe in XSS_PROBES[:2]:  # limit probes to keep scanning fast
                test_qs = {**qs, param: probe}
                test_url = urllib.parse.urlunparse(parsed._replace(
                    query=urllib.parse.urlencode(test_qs)
                ))
                status, body, hdrs = self._fetch(test_url)
                if probe in body and probe != urllib.parse.unquote(probe):
                    # Probe reflected verbatim — potential XSS
                    candidates.append(VulnCandidate(
                        vuln_type="XSS",
                        host=host,
                        endpoint=endpoint,
                        parameter=param,
                        payload=probe,
                        evidence=f"Probe '{probe}' reflected unescaped in response",
                        confidence="medium",
                    ))
                    break
                elif probe in body:
                    candidates.append(VulnCandidate(
                        vuln_type="XSS",
                        host=host,
                        endpoint=endpoint,
                        parameter=param,
                        payload=probe,
                        evidence=f"Probe '{probe}' reflected in response (check encoding)",
                        confidence="low",
                    ))
                    break
        return candidates

    # ── SSRF ─────────────────────────────────────────────────────────────────

    def check_ssrf(self, host: str, endpoint: str, params: list[str]) -> list[VulnCandidate]:
        candidates = []
        parsed = urllib.parse.urlparse(endpoint)
        qs = dict(urllib.parse.parse_qsl(parsed.query))

        url_params_in_ep = [p for p in params if p.lower() in URL_PARAMS]
        for param in url_params_in_ep:
            # Try localhost
            test_qs = {**qs, param: "http://127.0.0.1/"}
            test_url = urllib.parse.urlunparse(parsed._replace(
                query=urllib.parse.urlencode(test_qs)
            ))
            status_base, body_base, _ = self._fetch(test_url)
            test_qs2 = {**qs, param: "http://127.0.0.1:22/"}
            test_url2 = urllib.parse.urlunparse(parsed._replace(
                query=urllib.parse.urlencode(test_qs2)
            ))
            status_22, body_22, _ = self._fetch(test_url2)

            # Response difference suggests SSRF
            if abs(len(body_base) - len(body_22)) > 50 or status_base != status_22:
                candidates.append(VulnCandidate(
                    vuln_type="SSRF",
                    host=host,
                    endpoint=endpoint,
                    parameter=param,
                    payload="http://127.0.0.1/",
                    evidence=f"Response differs with different internal targets "
                             f"({len(body_base)} vs {len(body_22)} bytes)",
                    confidence="medium",
                ))

            # OOB check
            if self.oob_url:
                oob_target = self.oob_url.rstrip("/") + f"/ssrf-{param}"
                test_qs3 = {**qs, param: oob_target}
                test_url3 = urllib.parse.urlunparse(parsed._replace(
                    query=urllib.parse.urlencode(test_qs3)
                ))
                self._fetch(test_url3)  # fire-and-forget; OOB server logs it
                candidates.append(VulnCandidate(
                    vuln_type="SSRF",
                    host=host,
                    endpoint=endpoint,
                    parameter=param,
                    payload=oob_target,
                    evidence=f"OOB payload sent to {oob_target} — check OOB server",
                    confidence="low",
                ))

        return candidates

    # ── IDOR ─────────────────────────────────────────────────────────────────

    def check_idor(self, host: str, endpoint: str, params: list[str]) -> list[VulnCandidate]:
        candidates = []
        parsed = urllib.parse.urlparse(endpoint)
        qs = dict(urllib.parse.parse_qsl(parsed.query))

        for param in params:
            val = qs.get(param, "")
            if not val.isdigit():
                continue
            base_id = int(val)

            # Fetch baseline
            _, body_base, _ = self._fetch(endpoint)

            for delta in (1, -1):
                test_id = str(base_id + delta)
                test_qs = {**qs, param: test_id}
                test_url = urllib.parse.urlunparse(parsed._replace(
                    query=urllib.parse.urlencode(test_qs)
                ))
                _, body_alt, _ = self._fetch(test_url)

                # If response has similar structure but different content → IDOR candidate
                if (body_alt and body_base and
                        abs(len(body_base) - len(body_alt)) < len(body_base) * 0.5 and
                        body_base != body_alt):
                    candidates.append(VulnCandidate(
                        vuln_type="IDOR",
                        host=host,
                        endpoint=endpoint,
                        parameter=param,
                        payload=f"{param}={test_id} (orig={val})",
                        evidence=f"Different response for ID {test_id} vs {val} "
                                 f"({len(body_alt)} vs {len(body_base)} bytes)",
                        confidence="low",
                    ))
                    break
        return candidates

    # ── CORS ─────────────────────────────────────────────────────────────────

    def check_cors(self, host: str) -> Optional[VulnCandidate]:
        for scheme in ("https", "http"):
            url = f"{scheme}://{host}/"
            status, body, hdrs = self._fetch(
                url, headers={"Origin": "https://evil.com"}
            )
            if status == 0:
                continue
            acao = (hdrs.get("access-control-allow-origin") or
                    hdrs.get("Access-Control-Allow-Origin", ""))
            acac = (hdrs.get("access-control-allow-credentials") or
                    hdrs.get("Access-Control-Allow-Credentials", ""))

            if "evil.com" in acao:
                confidence = "high" if acac.lower() == "true" else "medium"
                return VulnCandidate(
                    vuln_type="CORS",
                    host=host,
                    endpoint=url,
                    payload="Origin: https://evil.com",
                    evidence=f"ACAO: {acao} | ACAC: {acac}",
                    confidence=confidence,
                )
            if acao == "*" and acac.lower() == "true":
                return VulnCandidate(
                    vuln_type="CORS",
                    host=host,
                    endpoint=url,
                    payload="Origin: *",
                    evidence="ACAO: * with ACAC: true (invalid but worth noting)",
                    confidence="low",
                )
        return None

    # ── Security headers ──────────────────────────────────────────────────────

    def check_headers(self, host: str) -> list[VulnCandidate]:
        candidates = []
        for scheme in ("https", "http"):
            url = f"{scheme}://{host}/"
            status, _, hdrs = self._fetch(url)
            if status == 0:
                continue

            missing = []
            REQUIRED = [
                "Strict-Transport-Security", "Content-Security-Policy",
                "X-Frame-Options", "X-Content-Type-Options",
                "Referrer-Policy",
            ]
            for h in REQUIRED:
                if not hdrs.get(h) and not hdrs.get(h.lower()):
                    missing.append(h)

            if missing:
                candidates.append(VulnCandidate(
                    vuln_type="Missing Security Headers",
                    host=host,
                    endpoint=url,
                    evidence=f"Missing: {', '.join(missing)}",
                    confidence="low",
                ))

            # Info leaking headers
            leaky = []
            for h in ("Server", "X-Powered-By", "X-AspNet-Version", "X-Generator"):
                val = hdrs.get(h) or hdrs.get(h.lower(), "")
                if val:
                    leaky.append(f"{h}: {val}")
            if leaky:
                candidates.append(VulnCandidate(
                    vuln_type="Information Disclosure",
                    host=host,
                    endpoint=url,
                    evidence=f"Leaky headers: {'; '.join(leaky)}",
                    confidence="low",
                ))
            break  # only check first working scheme
        return candidates

    # ── Open redirect ─────────────────────────────────────────────────────────

    def check_open_redirect(self, host: str, endpoint: str) -> Optional[VulnCandidate]:
        parsed = urllib.parse.urlparse(endpoint)
        qs = dict(urllib.parse.parse_qsl(parsed.query))
        redirect_params = [p for p in qs if p.lower() in
                           ("redirect", "next", "return", "url", "goto", "dest",
                            "destination", "redir", "target", "link")]

        for param in redirect_params:
            payload = "https://evil.com"
            test_qs = {**qs, param: payload}
            test_url = urllib.parse.urlunparse(parsed._replace(
                query=urllib.parse.urlencode(test_qs)
            ))
            status, body, hdrs = self._fetch(test_url)
            location = hdrs.get("location") or hdrs.get("Location", "")
            if "evil.com" in location:
                return VulnCandidate(
                    vuln_type="Open Redirect",
                    host=host,
                    endpoint=endpoint,
                    parameter=param,
                    payload=payload,
                    evidence=f"Location header: {location}",
                    confidence="high",
                )
        return None

    # ── Secret scanning ───────────────────────────────────────────────────────

    def check_secrets(self, responses: list[dict]) -> list[VulnCandidate]:
        candidates = []
        import re as _re
        for resp in responses:
            url = resp.get("url", "")
            body = resp.get("body", "")
            host = url.split("/")[2] if "://" in url else ""

            for pattern, label in SECRET_PATTERNS:
                for match in _re.finditer(pattern, body):
                    snippet = match.group(0)[:80]
                    candidates.append(VulnCandidate(
                        vuln_type="Secret Exposure",
                        host=host,
                        endpoint=url,
                        evidence=f"{label} found: {snippet}",
                        confidence="high",
                    ))
        return candidates

    # ── Misconfigurations ─────────────────────────────────────────────────────

    def check_misconfigs(self, host: str, endpoint: str) -> list[VulnCandidate]:
        candidates = []
        for scheme in ("https", "http"):
            base = f"{scheme}://{host}"
            for path in MISCONFIG_PATHS:
                url = f"{base}/{path}"
                status, body, hdrs = self._fetch(url)
                if status in (200, 206):
                    content_type = hdrs.get("content-type", hdrs.get("Content-Type", ""))
                    # Skip HTML responses that are just 200 OK generic pages
                    if "text/html" in content_type and len(body) > 5000:
                        continue
                    candidates.append(VulnCandidate(
                        vuln_type="Misconfiguration",
                        host=host,
                        endpoint=url,
                        evidence=f"Accessible path '{path}' (HTTP {status}, "
                                 f"{len(body)} bytes)",
                        confidence="high" if path in (".env", ".git/config", "actuator/env")
                                   else "medium",
                    ))
            break  # try https first; if any found, stop
        return candidates

    # ── Auth bypass ───────────────────────────────────────────────────────────

    def check_auth_bypass(self, host: str, endpoint: str) -> list[VulnCandidate]:
        candidates = []

        # Try authenticated endpoint without token
        _, body_no_auth, hdrs_no_auth = self._fetch(endpoint)
        status_no_auth = 0
        try:
            req = urllib.request.Request(
                endpoint, headers={"User-Agent": "Mozilla/5.0"}
            )
            with urllib.request.urlopen(req, timeout=10) as r:
                status_no_auth = r.status
        except urllib.error.HTTPError as e:
            status_no_auth = e.code
        except Exception:
            pass

        # Try with empty Authorization header
        _, body_empty_auth, _ = self._fetch(
            endpoint, headers={"Authorization": ""}
        )
        # Try with null Bearer
        _, body_null_auth, _ = self._fetch(
            endpoint, headers={"Authorization": "Bearer null"}
        )

        # If no-auth and empty-auth return similar content to authenticated response
        # (i.e., status 200 when we'd expect 401/403), flag it
        if status_no_auth == 200 and "/api/" in endpoint.lower():
            candidates.append(VulnCandidate(
                vuln_type="Auth Bypass",
                host=host,
                endpoint=endpoint,
                evidence=f"API endpoint returns HTTP 200 without any auth token",
                confidence="low",
            ))

        return candidates
