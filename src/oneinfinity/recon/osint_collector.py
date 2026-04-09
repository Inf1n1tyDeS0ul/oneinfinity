"""
OSINT Collector — Gathers intelligence from public sources.
"""
import json
import time
import logging
import socket
import urllib.request
import urllib.parse
import urllib.error
import os
import re
import ssl
from dataclasses import dataclass, field
from typing import Optional

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Data model
# ---------------------------------------------------------------------------

@dataclass
class OSINTResult:
    source: str
    domain: str
    findings: list[dict]       # raw findings
    subdomains: list[str]
    emails: list[str]
    ips: list[str]
    technologies: list[str]
    urls: list[str]
    api_keys_found: list[str]  # redacted previews
    error: str = ""
    collected_at: str = field(default_factory=lambda: str(time.time()))


# ---------------------------------------------------------------------------
# Regex patterns
# ---------------------------------------------------------------------------

# Matches email addresses
_EMAIL_RE = re.compile(r"[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}")

# Common API key / secret patterns — we redact after detection
_API_KEY_PATTERNS = [
    # AWS
    re.compile(r"AKIA[0-9A-Z]{16}"),
    # Generic "token"
    re.compile(r'(?i)(?:api[_\-]?key|secret[_\-]?key|access[_\-]?token|auth[_\-]?token)\s*[:=]\s*["\']?([A-Za-z0-9_\-]{20,60})["\']?'),
    # GitHub personal access token
    re.compile(r"ghp_[A-Za-z0-9]{36}"),
    # Slack token
    re.compile(r"xox[baprs]-[0-9]{10,13}-[0-9]{10,13}-[A-Za-z0-9]{24,32}"),
    # Google API key
    re.compile(r"AIza[0-9A-Za-z\-_]{35}"),
    # Stripe key
    re.compile(r"sk_live_[0-9a-zA-Z]{24,99}"),
    # Twilio SID
    re.compile(r"AC[a-z0-9]{32}"),
    # SendGrid
    re.compile(r"SG\.[A-Za-z0-9\-_]{22}\.[A-Za-z0-9\-_]{43}"),
    # JWT
    re.compile(r"ey[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}"),
]


# ---------------------------------------------------------------------------
# Collector
# ---------------------------------------------------------------------------

class OSINTCollector:
    """Multi-source OSINT data collection for a given domain."""

    # ------------------------------------------------------------------
    # Primary entry point
    # ------------------------------------------------------------------

    def collect_all(self, domain: str) -> list[OSINTResult]:
        """Run all OSINT sources and return a list of OSINTResult objects."""
        results: list[OSINTResult] = []

        collectors = [
            self.collect_crtsh,
            self.collect_hackertarget,
            self.collect_dnsdumpster,
            self.collect_urlscan,
            self.collect_wayback,
            self.collect_github_dorks,
        ]

        for fn in collectors:
            try:
                result = fn(domain)
                if result:
                    results.append(result)
            except Exception as exc:
                logger.warning(f"[osint] {fn.__name__} raised: {exc}")

        # Shodan for each resolved IP
        try:
            _, _, ip_list = socket.gethostbyname_ex(domain)
            for ip in ip_list:
                try:
                    r = self.collect_shodan_ip(ip)
                    if r:
                        results.append(r)
                except Exception as exc:
                    logger.debug(f"[osint] Shodan failed for {ip}: {exc}")
        except socket.gaierror:
            pass

        return results

    # ------------------------------------------------------------------
    # crt.sh — certificate transparency
    # ------------------------------------------------------------------

    def collect_crtsh(self, domain: str) -> OSINTResult:
        """Extract subdomains from certificate transparency via crt.sh."""
        url = f"https://crt.sh/?q=%25.{urllib.parse.quote(domain)}&output=json"
        data = self._safe_request(url, timeout=20)

        subdomains: list[str] = []
        findings: list[dict] = []

        if data and isinstance(data, list):
            seen: set[str] = set()
            for entry in data:
                for fname in ("common_name", "name_value"):
                    for raw in entry.get(fname, "").split("\n"):
                        raw = raw.strip().lstrip("*.")
                        if raw and raw not in seen and re.match(r"^[a-zA-Z0-9._-]+\.[a-zA-Z]{2,}$", raw):
                            seen.add(raw)
                            subdomains.append(raw)
                            findings.append({
                                "name_value": raw,
                                "issuer": entry.get("issuer_name", ""),
                                "not_before": entry.get("not_before", ""),
                                "not_after": entry.get("not_after", ""),
                            })

        return OSINTResult(
            source="crtsh",
            domain=domain,
            findings=findings,
            subdomains=subdomains,
            emails=[],
            ips=[],
            technologies=[],
            urls=[],
            api_keys_found=[],
            error="" if data else "request_failed",
        )

    # ------------------------------------------------------------------
    # HackerTarget hostsearch
    # ------------------------------------------------------------------

    def collect_hackertarget(self, domain: str) -> OSINTResult:
        """Query hackertarget.com for hostname/IP pairs."""
        url = f"https://api.hackertarget.com/hostsearch/?q={urllib.parse.quote(domain)}"
        subdomains: list[str] = []
        ips: list[str] = []
        findings: list[dict] = []
        error = ""

        try:
            req = urllib.request.Request(url, headers={"User-Agent": "OneInfinity/1.0"})
            with urllib.request.urlopen(req, timeout=10) as resp:
                body = resp.read().decode("utf-8", errors="replace")
        except Exception as exc:
            error = str(exc)
            body = ""

        for line in body.splitlines():
            line = line.strip()
            if not line or "error" in line.lower()[:30]:
                continue
            parts = line.split(",")
            if len(parts) >= 2:
                hostname = parts[0].strip()
                ip = parts[1].strip()
                if re.match(r"^[a-zA-Z0-9._-]+\.[a-zA-Z]{2,}$", hostname):
                    subdomains.append(hostname)
                if re.match(r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$", ip):
                    ips.append(ip)
                findings.append({"hostname": hostname, "ip": ip})

        return OSINTResult(
            source="hackertarget",
            domain=domain,
            findings=findings,
            subdomains=subdomains,
            emails=[],
            ips=ips,
            technologies=[],
            urls=[],
            api_keys_found=[],
            error=error,
        )

    # ------------------------------------------------------------------
    # HackerTarget DNS lookup
    # ------------------------------------------------------------------

    def collect_dnsdumpster(self, domain: str) -> OSINTResult:
        """Query hackertarget.com DNS lookup endpoint for DNS records."""
        url = f"https://api.hackertarget.com/dnslookup/?q={urllib.parse.quote(domain)}"
        findings: list[dict] = []
        ips: list[str] = []
        error = ""

        try:
            req = urllib.request.Request(url, headers={"User-Agent": "OneInfinity/1.0"})
            with urllib.request.urlopen(req, timeout=10) as resp:
                body = resp.read().decode("utf-8", errors="replace")
        except Exception as exc:
            error = str(exc)
            body = ""

        # Parse "TYPE RECORD" lines
        for line in body.splitlines():
            line = line.strip()
            if not line or "error" in line.lower()[:30]:
                continue
            findings.append({"record": line})
            # Extract IPs
            for ip_match in re.finditer(r"\b(\d{1,3}(?:\.\d{1,3}){3})\b", line):
                ip = ip_match.group(1)
                if ip not in ips:
                    ips.append(ip)

        return OSINTResult(
            source="dnsdumpster",
            domain=domain,
            findings=findings,
            subdomains=[],
            emails=[],
            ips=ips,
            technologies=[],
            urls=[],
            api_keys_found=[],
            error=error,
        )

    # ------------------------------------------------------------------
    # urlscan.io
    # ------------------------------------------------------------------

    def collect_urlscan(self, domain: str) -> OSINTResult:
        """Query urlscan.io for scan results referencing the domain."""
        query = urllib.parse.quote(f"domain:{domain}")
        url = f"https://urlscan.io/api/v1/search/?q={query}&size=100"
        data = self._safe_request(url, timeout=15)

        subdomains: list[str] = []
        urls: list[str] = []
        ips: list[str] = []
        technologies: list[str] = []
        findings: list[dict] = []
        error = ""

        if data is None:
            error = "request_failed"
        else:
            for result in data.get("results", []):
                page = result.get("page", {})
                url_val = page.get("url", "")
                ip_val = page.get("ip", "")
                domain_val = page.get("domain", "")

                if url_val:
                    urls.append(url_val)
                if ip_val and re.match(r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$", ip_val):
                    ips.append(ip_val)
                if domain_val and domain_val not in subdomains:
                    subdomains.append(domain_val)

                # Technologies from lists
                for tech in result.get("lists", {}).get("technologies", []):
                    name = tech.get("name") or tech if isinstance(tech, str) else ""
                    if name and name not in technologies:
                        technologies.append(name)

                findings.append({
                    "url": url_val,
                    "ip": ip_val,
                    "domain": domain_val,
                    "scan_id": result.get("_id", ""),
                })

        return OSINTResult(
            source="urlscan",
            domain=domain,
            findings=findings,
            subdomains=list(set(subdomains)),
            emails=[],
            ips=list(set(ips)),
            technologies=list(set(technologies)),
            urls=list(set(urls)),
            api_keys_found=[],
            error=error,
        )

    # ------------------------------------------------------------------
    # Wayback Machine CDX
    # ------------------------------------------------------------------

    def collect_wayback(self, domain: str) -> OSINTResult:
        """Query Wayback CDX API for historical URLs of the domain."""
        url = (
            f"http://web.archive.org/cdx/search/cdx"
            f"?url=*.{urllib.parse.quote(domain)}/*"
            f"&output=json&fl=original&collapse=urlkey&limit=500"
        )
        urls: list[str] = []
        subdomains: list[str] = []
        findings: list[dict] = []
        error = ""

        try:
            req = urllib.request.Request(url, headers={"User-Agent": "OneInfinity/1.0"})
            with urllib.request.urlopen(req, timeout=20) as resp:
                body = resp.read().decode("utf-8", errors="replace")
            data = json.loads(body)
        except Exception as exc:
            error = str(exc)
            data = []

        # CDX returns [[header], [url], [url], ...]
        seen_urls: set[str] = set()
        seen_subs: set[str] = set()
        for row in data[1:] if len(data) > 1 else []:  # skip header row
            if isinstance(row, list) and row:
                raw_url = row[0]
            elif isinstance(row, str):
                raw_url = row
            else:
                continue

            if raw_url not in seen_urls:
                seen_urls.add(raw_url)
                urls.append(raw_url)
                findings.append({"url": raw_url})

            # Extract subdomain
            subdomain = self._extract_subdomains(raw_url, domain)
            for sub in subdomain:
                if sub not in seen_subs:
                    seen_subs.add(sub)
                    subdomains.append(sub)

        return OSINTResult(
            source="wayback",
            domain=domain,
            findings=findings,
            subdomains=subdomains,
            emails=[],
            ips=[],
            technologies=[],
            urls=urls,
            api_keys_found=[],
            error=error,
        )

    # ------------------------------------------------------------------
    # GitHub dorks
    # ------------------------------------------------------------------

    def collect_github_dorks(self, domain: str) -> OSINTResult:
        """Search GitHub for domain references, API keys, and credentials."""
        token = os.environ.get("GITHUB_TOKEN", "")
        if not token:
            return OSINTResult(
                source="github_dorks",
                domain=domain,
                findings=[],
                subdomains=[],
                emails=[],
                ips=[],
                technologies=[],
                urls=[],
                api_keys_found=[],
                error="GITHUB_TOKEN not set",
            )

        dork_queries = [
            f"{domain} in:file",
            f"{domain} password in:file",
            f"{domain} api_key in:file",
            f'"{domain}" .env in:path',
        ]

        headers = {
            "User-Agent": "OneInfinity/1.0",
            "Authorization": f"token {token}",
            "Accept": "application/vnd.github.v3.text-match+json",
        }

        all_findings: list[dict] = []
        all_subdomains: set[str] = set()
        all_urls: set[str] = set()
        all_emails: set[str] = set()
        all_keys: list[str] = []
        error = ""

        for dork in dork_queries:
            query = urllib.parse.quote(dork)
            url = f"https://api.github.com/search/code?q={query}&per_page=30"
            ctx = ssl.create_default_context()
            try:
                req = urllib.request.Request(url, headers=headers)
                with urllib.request.urlopen(req, timeout=15, context=ctx) as resp:
                    data = json.loads(resp.read().decode("utf-8", errors="replace"))
            except Exception as exc:
                logger.debug(f"[github_dorks] Query '{dork}' failed: {exc}")
                error = str(exc)
                continue

            for item in data.get("items", []):
                repo = item.get("repository", {}).get("full_name", "")
                path = item.get("path", "")
                fragment_texts: list[str] = []
                for tm in item.get("text_matches", []):
                    fragment_texts.append(tm.get("fragment", ""))
                combined = "\n".join(fragment_texts)

                all_findings.append({
                    "repo": repo,
                    "path": path,
                    "url": item.get("html_url", ""),
                    "dork": dork,
                })

                for sub in self._extract_subdomains(combined, domain):
                    all_subdomains.add(sub)
                for email in self._extract_emails(combined):
                    all_emails.add(email)
                for key in self._extract_api_keys(combined):
                    all_keys.append(key)

                # Extract raw URLs
                for url_match in re.finditer(r"https?://[^\s\"'>]{10,}", combined):
                    all_urls.add(url_match.group(0))

            # Respect GitHub rate limiting
            time.sleep(1)

        return OSINTResult(
            source="github_dorks",
            domain=domain,
            findings=all_findings,
            subdomains=list(all_subdomains),
            emails=list(all_emails),
            ips=[],
            technologies=[],
            urls=list(all_urls),
            api_keys_found=all_keys,
            error=error,
        )

    # ------------------------------------------------------------------
    # Shodan InternetDB (no API key required)
    # ------------------------------------------------------------------

    def collect_shodan_ip(self, ip: str) -> OSINTResult:
        """Query Shodan InternetDB for IP intelligence."""
        url = f"https://internetdb.shodan.io/{ip}"
        data = self._safe_request(url, timeout=10)

        technologies: list[str] = []
        findings: list[dict] = []
        error = ""

        if data is None:
            error = "request_failed"
        else:
            # CPEs → technology names
            for cpe in data.get("cpes", []):
                # e.g. cpe:/a:apache:http_server:2.4.41
                parts = cpe.split(":")
                if len(parts) >= 4:
                    technologies.append(f"{parts[3]}/{parts[4]}" if len(parts) > 4 else parts[3])

            findings.append({
                "ip": ip,
                "ports": data.get("ports", []),
                "vulns": data.get("vulns", []),
                "tags": data.get("tags", []),
                "hostnames": data.get("hostnames", []),
                "cpes": data.get("cpes", []),
            })

        return OSINTResult(
            source="shodan_internetdb",
            domain=ip,
            findings=findings,
            subdomains=data.get("hostnames", []) if data else [],
            emails=[],
            ips=[ip],
            technologies=technologies,
            urls=[],
            api_keys_found=[],
            error=error,
        )

    # ------------------------------------------------------------------
    # Shared helpers
    # ------------------------------------------------------------------

    def _safe_request(self, url: str, timeout: int = 10) -> Optional[dict]:
        """Send a GET request and return parsed JSON, or None on failure."""
        try:
            ctx = ssl.create_default_context()
            req = urllib.request.Request(
                url, headers={"User-Agent": "OneInfinity/1.0"}
            )
            with urllib.request.urlopen(req, timeout=timeout, context=ctx) as resp:
                body = resp.read().decode("utf-8", errors="replace")
                return json.loads(body)
        except json.JSONDecodeError:
            return None
        except Exception as exc:
            logger.debug(f"[osint] _safe_request {url}: {exc}")
            return None

    def _extract_subdomains(self, text: str, domain: str) -> list[str]:
        """Extract subdomains of the given root domain from arbitrary text."""
        pattern = re.compile(
            r"(?<![a-zA-Z0-9\-.])"
            r"([a-zA-Z0-9](?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?"
            r"(?:\.[a-zA-Z0-9](?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?)*\."
            + re.escape(domain) + r")"
            r"(?![a-zA-Z0-9\-.])"
        )
        results = []
        for m in pattern.finditer(text):
            sub = m.group(1).lower()
            if sub and sub not in results:
                results.append(sub)
        return results

    def _extract_emails(self, text: str) -> list[str]:
        """Extract email addresses from text."""
        return list({m.group(0).lower() for m in _EMAIL_RE.finditer(text)})

    def _extract_api_keys(self, text: str) -> list[str]:
        """Detect and return redacted previews of API keys / secrets."""
        found: list[str] = []
        for pattern in _API_KEY_PATTERNS:
            for m in pattern.finditer(text):
                raw = m.group(0)
                # Redact: show first 6 chars + asterisks
                if len(raw) > 10:
                    redacted = raw[:6] + "*" * min(len(raw) - 6, 20) + "...[REDACTED]"
                else:
                    redacted = "*" * len(raw) + "[REDACTED]"
                found.append(redacted)
        return found


# ---------------------------------------------------------------------------
# Module-level singleton
# ---------------------------------------------------------------------------

osint_collector = OSINTCollector()
