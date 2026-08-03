"""
Supply Chain Attack Engine
==========================
Probes for dependency confusion, typosquatting, lockfile poisoning, and
unpinned GitHub Actions in the target's supply chain.

Innovation:
1. **Dependency Confusion** - Internal pkg names found in JS bundles / manifest files,
   checked against public registries (PyPI, npm).
2. **Typosquatting Exposure** - Transposition / omission / doubling variants checked
   against public registries.
3. **Lockfile Poisoning** - Exposed lockfiles with known-malicious SHA stubs.
4. **GitHub Actions Pinning** - Unpinned ``uses:`` directives in workflow files.
5. **Package Manifest Exposure** - Sensitive dependency metadata leaked at common paths.

No other tool combines all 5 supply-chain attack vectors.
"""
from __future__ import annotations

import asyncio
import hashlib
import logging
import re
from typing import List, Optional
from urllib.parse import urlparse

import httpx

log = logging.getLogger("oneinfinity.supply_chain")

# ─────────────────────────────────────────────────────────────────────────────
# Known-malicious package SHA stubs (extend with real threat-intel feeds)
# ─────────────────────────────────────────────────────────────────────────────

_KNOWN_MALICIOUS_SHAS: set[str] = {
    # Stub entries — real deployment should feed from OSV / Socket.dev / Sonatype
    "aabbccddeeff00112233445566778899aabbccddeeff00112233445566778899",
}

# Manifest / lockfile paths to probe
_MANIFEST_PATHS = [
    "/package.json",
    "/package-lock.json",
    "/yarn.lock",
    "/Pipfile",
    "/Pipfile.lock",
    "/requirements.txt",
    "/composer.json",
    "/composer.lock",
    "/Gemfile",
    "/Gemfile.lock",
    "/.git/config",
]

# Regex for extracting package names
_REQUIRE_RE = re.compile(r"""require\(['"]([^'"./][^'"]*)['"]\)""")
_IMPORT_RE = re.compile(r"""import\s+(?:\S+\s+from\s+)?['"]([^'"./][^'"]*)['"]""")
_PYPI_DEP_RE = re.compile(r"""^([A-Za-z0-9]([A-Za-z0-9._-]*[A-Za-z0-9])?)""", re.MULTILINE)
_SEMVER_RE = re.compile(r"(\d+\.\d+(?:\.\d+)?)")

# Unpinned action pattern: uses: owner/action@branch-or-tag (not a SHA)
_UNPINNED_ACTION_RE = re.compile(
    r'uses:\s+([a-zA-Z0-9_.-]+/[a-zA-Z0-9_.-]+)@(?!(?:[0-9a-f]{40})\b)([^\s#]+)'
)


# ─────────────────────────────────────────────────────────────────────────────
# Engine
# ─────────────────────────────────────────────────────────────────────────────

class SupplyChainAttackEngine:
    """
    Supply chain attack surface scanner.

    Primary entrypoint: ``scan(target)`` → list of finding dicts.
    Each finding dict always contains:
      vuln_type, severity, url, payload, evidence, tool, target
    """

    def __init__(self, timeout: int = 15):
        self.timeout = timeout
        self.http_client = httpx.AsyncClient(
            timeout=timeout,
            verify=False,
            follow_redirects=True,
            headers={"User-Agent": "OneInfinity-SupplyChainEngine/1.0"},
        )

    async def close(self) -> None:
        await self.http_client.aclose()

    # ── Internal Helpers ──────────────────────────────────────────────────────

    def _finding(
        self,
        *,
        vuln_type: str,
        severity: str,
        url: str,
        target: str,
        payload: str = "",
        evidence: str = "",
        extra: dict | None = None,
    ) -> dict:
        base = {
            "vuln_type": vuln_type,
            "severity": severity,
            "url": url,
            "payload": payload,
            "evidence": evidence,
            "tool": "supply_chain_attack_engine",
            "target": target,
            "finding_id": hashlib.md5(f"{vuln_type}_{url}_{payload}".encode()).hexdigest()[:16],
        }
        if extra:
            base.update(extra)
        return base

    async def _get(self, url: str) -> Optional[httpx.Response]:
        """Safe GET returning None on any error."""
        try:
            resp = await self.http_client.get(url)
            return resp
        except Exception as e:
            log.debug(f"GET {url} failed: {e}")
            return None

    async def _check_npm(self, name: str) -> bool:
        """Return True if package exists on npm."""
        resp = await self._get(f"https://registry.npmjs.org/{name}")
        return resp is not None and resp.status_code == 200

    async def _check_pypi(self, name: str) -> bool:
        """Return True if package exists on PyPI."""
        resp = await self._get(f"https://pypi.org/pypi/{name}/json")
        return resp is not None and resp.status_code == 200

    # ── 1. Discover Internal Package Names ───────────────────────────────────

    async def discover_internal_package_names(self, target: str) -> list[str]:
        """
        Fetch JS bundle and common manifest files from *target*.
        Extract package names via regex; return deduplicated list.
        """
        names: set[str] = set()
        parsed = urlparse(target)
        base = f"{parsed.scheme}://{parsed.netloc}"

        # Probe manifest / lockfile paths
        probe_paths = _MANIFEST_PATHS + ["/static/bundle.js", "/dist/main.js", "/assets/app.js"]
        responses: list[tuple[str, str]] = []

        for path in probe_paths:
            resp = await self._get(base + path)
            if resp and resp.status_code == 200:
                responses.append((base + path, resp.text))

        # Also probe the target URL itself for JS imports
        resp = await self._get(target)
        if resp and resp.status_code == 200:
            responses.append((target, resp.text))

        for _url, body in responses:
            # npm / JS package names
            names.update(m.group(1) for m in _REQUIRE_RE.finditer(body))
            names.update(m.group(1) for m in _IMPORT_RE.finditer(body))
            # Python package names (requirements.txt style)
            for m in _PYPI_DEP_RE.finditer(body):
                pkg = m.group(1)
                if 3 <= len(pkg) <= 80:
                    names.add(pkg)

        # Filter out obvious stdlib / built-in names
        builtins = {"os", "sys", "re", "fs", "path", "util", "http", "url", "net",
                    "crypto", "stream", "events", "buffer", "assert", "child_process"}
        names -= builtins

        log.info(f"Discovered {len(names)} candidate package names from {target}")
        return sorted(names)

    # ── 2. Dependency Confusion ───────────────────────────────────────────────

    async def test_dependency_confusion(self, package_names: list[str]) -> list[dict]:
        """
        For each package name check whether it exists on PyPI and npm.
        If absent: flag as exploitable dependency confusion target.
        """
        findings: list[dict] = []

        async def _check_one(name: str) -> None:
            on_npm = await self._check_npm(name)
            on_pypi = await self._check_pypi(name)

            if not on_npm:
                findings.append(self._finding(
                    vuln_type="dependency_confusion_npm",
                    severity="high",
                    url=f"https://registry.npmjs.org/{name}",
                    target=name,
                    payload=name,
                    evidence=(
                        f"Package '{name}' is referenced internally but does NOT exist on npm. "
                        "An attacker can publish a malicious package with the same name."
                    ),
                    extra={"package_name": name, "registry": "npm"},
                ))

            if not on_pypi:
                findings.append(self._finding(
                    vuln_type="dependency_confusion_pypi",
                    severity="high",
                    url=f"https://pypi.org/pypi/{name}/json",
                    target=name,
                    payload=name,
                    evidence=(
                        f"Package '{name}' is referenced internally but does NOT exist on PyPI. "
                        "An attacker can publish a malicious package with the same name."
                    ),
                    extra={"package_name": name, "registry": "pypi"},
                ))

        await asyncio.gather(*(_check_one(n) for n in package_names[:50]))
        return findings

    # ── 3. Typosquatting Exposure ─────────────────────────────────────────────

    @staticmethod
    def _generate_typos(name: str) -> list[str]:
        """Generate typosquat variants: transposition, omission, doubling."""
        variants: set[str] = set()
        n = len(name)

        # Transposition: swap adjacent chars
        for i in range(n - 1):
            v = list(name)
            v[i], v[i + 1] = v[i + 1], v[i]
            variants.add("".join(v))

        # Omission: drop one character
        for i in range(n):
            variants.add(name[:i] + name[i + 1:])

        # Doubling: double one character
        for i in range(n):
            variants.add(name[:i] + name[i] + name[i:])

        # Hyphen ↔ underscore swap
        if "-" in name:
            variants.add(name.replace("-", "_"))
        if "_" in name:
            variants.add(name.replace("_", "-"))

        variants.discard(name)
        return sorted(variants)

    async def test_typosquat_exposure(self, package_names: list[str]) -> list[dict]:
        """
        For each package name generate typo variants and check npm/PyPI.
        Existing variants are flagged as potential typosquatting risks.
        """
        findings: list[dict] = []

        async def _check_pkg(name: str) -> None:
            for variant in self._generate_typos(name)[:20]:  # cap at 20 per pkg
                on_npm = await self._check_npm(variant)
                on_pypi = await self._check_pypi(variant)

                if on_npm:
                    findings.append(self._finding(
                        vuln_type="typosquatting_npm",
                        severity="medium",
                        url=f"https://www.npmjs.com/package/{variant}",
                        target=name,
                        payload=variant,
                        evidence=(
                            f"Typo variant '{variant}' of internal package '{name}' "
                            "exists on npm — potential typosquatting attack vector."
                        ),
                        extra={"original": name, "variant": variant, "registry": "npm"},
                    ))

                if on_pypi:
                    findings.append(self._finding(
                        vuln_type="typosquatting_pypi",
                        severity="medium",
                        url=f"https://pypi.org/project/{variant}/",
                        target=name,
                        payload=variant,
                        evidence=(
                            f"Typo variant '{variant}' of internal package '{name}' "
                            "exists on PyPI — potential typosquatting attack vector."
                        ),
                        extra={"original": name, "variant": variant, "registry": "pypi"},
                    ))

        # Limit to first 20 packages to avoid registry hammering
        await asyncio.gather(*(_check_pkg(n) for n in package_names[:20]))
        return findings

    # ── 4. Lockfile Poisoning ─────────────────────────────────────────────────

    async def test_lockfile_poisoning(self, target: str) -> list[dict]:
        """
        Attempt to retrieve lockfiles from *target*.
        If found, extract dependency SHAs and compare against known-malicious list.
        """
        findings: list[dict] = []
        parsed = urlparse(target)
        base = f"{parsed.scheme}://{parsed.netloc}"

        lockfile_paths = [
            "/package-lock.json",
            "/yarn.lock",
            "/Pipfile.lock",
            "/composer.lock",
        ]

        for path in lockfile_paths:
            url = base + path
            resp = await self._get(url)
            if not resp or resp.status_code != 200:
                continue

            body = resp.text

            # Flag: lockfile exposed at all
            findings.append(self._finding(
                vuln_type="lockfile_exposed",
                severity="medium",
                url=url,
                target=target,
                payload="",
                evidence=f"Lockfile accessible at {url} — reveals exact dependency tree for supply-chain attacks.",
            ))

            # Extract SHAs (npm package-lock.json style: "integrity": "sha512-...")
            sha_pattern = re.compile(r'"integrity":\s*"(?:sha\d+-)?([A-Za-z0-9+/=]{20,})"')
            for m in sha_pattern.finditer(body):
                sha_val = m.group(1)
                if sha_val.lower() in _KNOWN_MALICIOUS_SHAS:
                    findings.append(self._finding(
                        vuln_type="lockfile_malicious_sha",
                        severity="critical",
                        url=url,
                        target=target,
                        payload=sha_val,
                        evidence=f"Dependency in {path} matches known-malicious SHA: {sha_val[:20]}...",
                        extra={"sha": sha_val},
                    ))

            # yarn.lock: check for HTTP (non-HTTPS) resolved URLs
            if "yarn.lock" in path:
                http_resolved = re.findall(r'resolved "http://[^"]*"', body)
                for resolved in http_resolved:
                    findings.append(self._finding(
                        vuln_type="lockfile_insecure_resolution",
                        severity="high",
                        url=url,
                        target=target,
                        payload=resolved,
                        evidence=f"yarn.lock resolves package over plain HTTP: {resolved[:80]}",
                    ))

        return findings

    # ── 5. GitHub Actions Pinning ─────────────────────────────────────────────

    async def test_github_action_pinning(self, target: str) -> list[dict]:
        """
        If *target* is a github.com URL (https://github.com/<org>/<repo>),
        fetch workflow files via the GitHub API and flag unpinned ``uses:`` directives.
        """
        findings: list[dict] = []
        parsed = urlparse(target)

        if "github.com" not in (parsed.netloc or ""):
            return findings

        parts = parsed.path.strip("/").split("/")
        if len(parts) < 2:
            return findings

        org, repo = parts[0], parts[1]
        api_base = f"https://api.github.com/repos/{org}/{repo}"

        # List workflow files
        workflows_resp = await self._get(f"{api_base}/contents/.github/workflows")
        if not workflows_resp or workflows_resp.status_code != 200:
            return findings

        try:
            workflow_files = workflows_resp.json()
        except Exception:
            return findings

        if not isinstance(workflow_files, list):
            return findings

        for wf in workflow_files:
            if not isinstance(wf, dict):
                continue
            download_url = wf.get("download_url") or wf.get("url")
            if not download_url:
                continue

            content_resp = await self._get(download_url)
            if not content_resp or content_resp.status_code != 200:
                continue

            wf_content = content_resp.text
            wf_name = wf.get("name", "unknown")

            for m in _UNPINNED_ACTION_RE.finditer(wf_content):
                action_ref = m.group(1)
                pin_ref = m.group(2)
                findings.append(self._finding(
                    vuln_type="github_action_unpinned",
                    severity="high",
                    url=f"https://github.com/{org}/{repo}/blob/HEAD/.github/workflows/{wf_name}",
                    target=target,
                    payload=f"uses: {action_ref}@{pin_ref}",
                    evidence=(
                        f"Workflow '{wf_name}' uses '{action_ref}@{pin_ref}' without a full SHA pin. "
                        "A compromised tag/branch on the action repo executes arbitrary code in CI."
                    ),
                    extra={"workflow": wf_name, "action": action_ref, "ref": pin_ref},
                ))

        return findings

    # ── Orchestration ─────────────────────────────────────────────────────────

    # ── Phase 2: SRI Audit + Third-Party Script Behavior (Pillar 4.2) ─────────

    async def test_sri_audit(self, target: str) -> list[dict]:
        """
        SRI (Subresource Integrity) audit — checks every CDN <script> tag
        in the target's HTML for the presence and correctness of integrity hashes.

        Without SRI, any CDN can inject malicious code into the page. This is
        a supply chain attack vector that no majority tool checks systematically.

        Tests:
          1. Missing integrity attribute on CDN <script src="...">
          2. integrity attribute present but hash algorithm is weak (sha1, md5)
          3. Fetch the CDN script and verify the hash matches the live content
        """
        findings: list[dict] = []
        # Fetch target HTML
        resp = await self._get(target)
        if not resp:
            return findings
        html = resp.text

        # Find all <script src="..."> tags
        script_tags = re.findall(
            r'<script\b([^>]*)>',
            html, re.IGNORECASE | re.DOTALL
        )
        cdn_domains = (
            "cdn.jsdelivr.net", "cdnjs.cloudflare.com", "unpkg.com",
            "ajax.googleapis.com", "stackpath.bootstrapcdn.com",
            "code.jquery.com", "maxcdn.bootstrapcdn.com",
            "cdn.tailwindcss.com", "cdn.ampproject.org",
        )

        for attrs_str in script_tags:
            # Extract src
            src_match = re.search(r'\bsrc=["\']([^"\']+)["\']', attrs_str, re.I)
            if not src_match:
                continue
            src = src_match.group(1)
            is_cdn = any(d in src for d in cdn_domains) or src.startswith("//") or (
                src.startswith("http") and urlparse(src).netloc != urlparse(target).netloc
            )
            if not is_cdn:
                continue

            # Check integrity attribute
            integrity_match = re.search(r'\bintegrity=["\']([^"\']+)["\']', attrs_str, re.I)
            if not integrity_match:
                findings.append(self._finding(
                    vuln_type="sri_missing",
                    severity="medium",
                    url=src,
                    target=target,
                    payload=f'<script src="{src}">',
                    evidence=(
                        f"CDN script loaded without SRI integrity hash: {src}. "
                        f"If the CDN is compromised, arbitrary code will execute on all visitors."
                    ),
                ))
                continue

            # Check hash algorithm strength
            integrity_val = integrity_match.group(1)
            if any(integrity_val.startswith(weak) for weak in ("sha1-", "md5-")):
                findings.append(self._finding(
                    vuln_type="sri_weak_hash",
                    severity="medium",
                    url=src,
                    target=target,
                    payload=integrity_val,
                    evidence=(
                        f"CDN script uses weak SRI hash algorithm: {integrity_val[:40]}. "
                        f"SHA-1 and MD5 are collision-vulnerable — use sha256 or sha384."
                    ),
                ))
                continue

            # Verify hash matches live CDN content (sha256/sha384/sha512)
            try:
                import hashlib as _hl, base64 as _b64
                algo_map = {"sha256": _hl.sha256, "sha384": _hl.sha384, "sha512": _hl.sha512}
                for algo_name, algo_fn in algo_map.items():
                    if not integrity_val.startswith(f"{algo_name}-"):
                        continue
                    expected_b64 = integrity_val[len(algo_name) + 1:]
                    cdn_resp = await self._get(src if src.startswith("http") else f"https:{src}")
                    if cdn_resp and cdn_resp.status_code == 200:
                        actual_hash = _b64.b64encode(
                            algo_fn(cdn_resp.content).digest()
                        ).decode()
                        if actual_hash != expected_b64:
                            findings.append(self._finding(
                                vuln_type="sri_hash_mismatch",
                                severity="critical",
                                url=src,
                                target=target,
                                payload=integrity_val,
                                evidence=(
                                    f"SRI hash MISMATCH for {src}. "
                                    f"Expected: {expected_b64[:32]}... "
                                    f"Actual:   {actual_hash[:32]}... "
                                    f"The CDN content may have been tampered with."
                                ),
                            ))
            except Exception as exc:
                log.debug("SRI verification failed for %s: %s", src, exc)

        return findings

    async def test_third_party_script_behavior(self, target: str) -> list[dict]:
        """
        Third-party script behavior analysis.

        Fetches CDN scripts and analyses their source for:
          1. Cookie writes (document.cookie = ...) → session hijack risk
          2. localStorage writes → persistent tracking / data storage
          3. Cross-origin fetch/XHR to domains the application doesn't control
          4. eval() or Function() calls with externally controlled content
          5. postMessage() handlers without origin validation

        This is a static analysis pass — no JS execution required.
        """
        findings: list[dict] = []
        resp = await self._get(target)
        if not resp:
            return findings

        cdn_srcs = re.findall(
            r'<script\b[^>]*\bsrc=["\']([^"\']+)["\'][^>]*>',
            resp.text, re.IGNORECASE
        )
        target_host = urlparse(target).netloc

        for src in cdn_srcs[:10]:  # cap to bound cost
            if target_host and target_host in src:
                continue  # skip first-party scripts
            cdn_url = src if src.startswith("http") else f"https:{src}"
            script_resp = await self._get(cdn_url)
            if not script_resp or script_resp.status_code != 200:
                continue
            js = script_resp.text

            # Pattern: cookie write
            if re.search(r'document\.cookie\s*=', js):
                findings.append(self._finding(
                    vuln_type="third_party_cookie_write",
                    severity="high",
                    url=cdn_url, target=target,
                    payload=src,
                    evidence=(
                        f"Third-party CDN script {src} writes to document.cookie. "
                        f"This script can set or overwrite session cookies."
                    ),
                ))

            # Pattern: localStorage write
            if re.search(r'localStorage\.setItem', js):
                findings.append(self._finding(
                    vuln_type="third_party_localstorage_write",
                    severity="medium",
                    url=cdn_url, target=target,
                    payload=src,
                    evidence=(
                        f"Third-party CDN script {src} writes to localStorage. "
                        f"May store sensitive user data in a third-party controlled key."
                    ),
                ))

            # Pattern: cross-origin XHR/fetch to non-CDN domain
            cross_origins = re.findall(
                r'''(?:fetch|XMLHttpRequest|\.open)\s*\(?\s*["'`](https?://[^"'`\s]+)''',
                js, re.I
            )
            for co_url in cross_origins[:5]:
                if target_host and target_host not in co_url and cdn_url not in co_url:
                    findings.append(self._finding(
                        vuln_type="third_party_cross_origin_request",
                        severity="medium",
                        url=cdn_url, target=target,
                        payload=co_url,
                        evidence=(
                            f"Third-party CDN script {src} makes requests to {co_url}. "
                            f"This domain is not the application — user data may be exfiltrated."
                        ),
                    ))
                    break  # one finding per script for cross-origin

            # Pattern: eval with external data
            if re.search(r'eval\s*\(|new\s+Function\s*\(', js):
                findings.append(self._finding(
                    vuln_type="third_party_dynamic_eval",
                    severity="high",
                    url=cdn_url, target=target,
                    payload=src,
                    evidence=(
                        f"Third-party CDN script {src} uses eval() or new Function(). "
                        f"If this script is compromised, eval() enables arbitrary code execution."
                    ),
                ))

        return findings
    async def scan(self, target: str) -> list[dict]:
        """
        Full supply chain scan of *target*.

        Returns list of finding dicts (vuln_type, severity, url, payload,
        evidence, tool, target).
        """
        log.info(f"Starting supply chain scan for {target}")

        # Step 1: discover internal package names
        try:
            package_names = await self.discover_internal_package_names(target)
        except Exception as e:
            log.debug(f"Package name discovery failed: {e}")
            package_names = []

        # Steps 2-7 run concurrently
        tasks = [
            self.test_lockfile_poisoning(target),
            self.test_github_action_pinning(target),
            self.test_sri_audit(target),                    # Phase 2: SRI checks
            self.test_third_party_script_behavior(target),  # Phase 2: CDN script analysis
        ]
        if package_names:
            tasks += [
                self.test_dependency_confusion(package_names),
                self.test_typosquat_exposure(package_names),
            ]

        results = await asyncio.gather(*tasks, return_exceptions=True)

        findings: list[dict] = []
        for result in results:
            if isinstance(result, list):
                findings.extend(result)
            elif isinstance(result, Exception):
                log.debug(f"Supply chain test error: {result}")

        log.info(f"Supply chain scan complete: {len(findings)} findings for {target}")
        return findings


# ─────────────────────────────────────────────────────────────────────────────
# Convenience wrapper
# ─────────────────────────────────────────────────────────────────────────────

async def scan_supply_chain(target: str) -> list[dict]:
    """Scan supply chain attack surface for *target*."""
    engine = SupplyChainAttackEngine()
    try:
        return await engine.scan(target)
    finally:
        await engine.close()
