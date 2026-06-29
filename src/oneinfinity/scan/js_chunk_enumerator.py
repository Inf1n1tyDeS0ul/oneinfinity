"""
JS Chunk Enumerator
====================
Discovers JavaScript chunk URLs beyond what asset manifests expose:
  1. Parse asset-manifest.json / webpack-stats.json (same as JSIntelligence baseline)
  2. Brute-force numbered chunks: /static/js/0.chunk.js … N.chunk.js
  3. Probe common hashed-chunk patterns derived from known chunk URLs
  4. Probe framework-specific chunk routes (Next.js pages, Nuxt, etc.)

Feeds discovered URLs into _phase_js_intelligence for secret scanning.
All HTTP is async via ThreadPoolExecutor so we don't block the pipeline.
"""
from __future__ import annotations

import json
import logging
import re
import ssl
import urllib.request
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import List, Optional

log = logging.getLogger("oneinfinity.scan.js_chunk_enumerator")

_SSL_CTX = ssl.create_default_context()
_SSL_CTX.check_hostname = False
_SSL_CTX.verify_mode = ssl.CERT_NONE

# ── Asset manifest / stats paths ─────────────────────────────────────────────
_MANIFEST_PATHS = [
    "/asset-manifest.json",
    "/webpack-stats.json",
    "/chunk-manifest.json",
    "/.vite/manifest.json",
    "/build-manifest.json",
    "/manifest.json",
    "/_next/static/development/_buildManifest.js",
    "/_nuxt/manifest.js",
    "/static/js/chunk-manifest.json",
]

# ── Numbered chunk templates ─────────────────────────────────────────────────
_NUMBERED_CHUNK_TEMPLATES = [
    "/static/js/{n}.chunk.js",
    "/static/js/{n}.{n}.chunk.js",
    "/js/{n}.chunk.js",
    "/assets/js/{n}.js",
    "/assets/{n}.js",
    "/dist/js/{n}.chunk.js",
    "/build/static/js/{n}.chunk.js",
]

# Probe up to this many numbered chunks before stopping
_MAX_NUMBERED_PROBES = 20

# ── Next.js page chunk patterns ───────────────────────────────────────────────
_NEXTJS_PAGE_CHUNKS = [
    "/_next/static/chunks/pages/_app.js",
    "/_next/static/chunks/pages/_error.js",
    "/_next/static/chunks/pages/index.js",
    "/_next/static/chunks/pages/login.js",
    "/_next/static/chunks/pages/dashboard.js",
    "/_next/static/chunks/pages/admin.js",
    "/_next/static/chunks/pages/api.js",
    "/_next/static/chunks/pages/settings.js",
    "/_next/static/chunks/pages/profile.js",
    "/_next/static/chunks/pages/checkout.js",
]


class JSChunkEnumerator:
    """
    Discovers JS chunk URLs via manifest parsing and brute-force probing.
    """

    def __init__(self, timeout: int = 8, headers: dict = None, workers: int = 10):
        self.timeout = timeout
        self.headers = headers or {}
        self.workers = workers

    # ── Public API ────────────────────────────────────────────────────────────

    def enumerate(
        self,
        target: str,
        scheme: str = "https",
        tech_profile=None,
        known_urls: List[str] = None,
    ) -> List[str]:
        """
        Returns list of discovered JS chunk URLs (full https://... form).
        Deduplicates against known_urls.
        """
        base = f"{scheme}://{target}"
        known = set(known_urls or [])
        found: set[str] = set()

        # Phase 1: Parse asset manifests
        manifest_urls = self._parse_manifests(base)
        found.update(manifest_urls)

        # Phase 2: Numbered chunk brute-force
        numbered_urls = self._probe_numbered_chunks(base)
        found.update(numbered_urls)

        # Phase 3: Framework-specific chunks based on tech profile
        if tech_profile:
            fw_urls = self._probe_framework_chunks(base, tech_profile)
            found.update(fw_urls)

        # Phase 4: Derive hashed variants from known chunk patterns
        if known:
            hashed_urls = self._derive_hashed_chunks(base, known)
            found.update(hashed_urls)

        new_urls = sorted(found - known)
        log.info(
            "JSChunkEnumerator: discovered %d new chunk URLs for %s",
            len(new_urls), target,
        )
        return new_urls

    # ── Phase 1: Asset manifest parsing ──────────────────────────────────────

    def _parse_manifests(self, base: str) -> List[str]:
        chunks: List[str] = []
        h = {"User-Agent": "Mozilla/5.0 (OneInfinity ChunkEnumerator/1.0)"}
        h.update(self.headers)

        for path in _MANIFEST_PATHS:
            url = base + path
            try:
                req = urllib.request.Request(url, headers=h)
                with urllib.request.urlopen(req, timeout=self.timeout, context=_SSL_CTX) as resp:
                    if resp.status not in (200, 304):
                        continue
                    raw = resp.read(500_000).decode("utf-8", errors="replace")
                    if not raw.strip():
                        continue
                    extracted = self._parse_manifest_json(raw, base)
                    chunks.extend(extracted)
                    if extracted:
                        log.info("JSChunkEnumerator: manifest at %s → %d chunks", path, len(extracted))
            except Exception:
                continue
        return chunks

    def _parse_manifest_json(self, raw: str, base: str) -> List[str]:
        chunks: List[str] = []
        if not raw.strip().startswith("{"):
            # Try to extract from JS (e.g. /_next/static/development/_buildManifest.js)
            for m in re.finditer(r"""["'`]([^"'`\s]+\.js)["'`]""", raw):
                path = m.group(1)
                if path.endswith(".js") and "/" in path:
                    chunks.append(f"{base}/{path.lstrip('/')}")
            return chunks
        try:
            data = json.loads(raw)
        except Exception:
            return chunks

        # CRA asset-manifest.json: {"files": {"/static/js/main.chunk.js": "/static/js/main.chunk.js"}}
        files = data.get("files") or data.get("entrypoints") or {}
        if isinstance(files, dict):
            for path in files.values():
                if isinstance(path, str) and path.endswith(".js"):
                    chunks.append(f"{base}/{path.lstrip('/')}")
        elif isinstance(files, list):
            for path in files:
                if isinstance(path, str) and path.endswith(".js"):
                    chunks.append(f"{base}/{path.lstrip('/')}")

        # webpack-stats.json: {"chunks": [{"files": [...]}]}
        for chunk in data.get("chunks", []):
            for f in chunk.get("files", []):
                if f.endswith(".js"):
                    chunks.append(f"{base}/{f.lstrip('/')}")

        # Vite manifest: {"index.html": {"file": "assets/index-abc123.js", "imports": [...]}}
        for entry in data.values():
            if isinstance(entry, dict):
                file_path = entry.get("file", "")
                if file_path.endswith(".js"):
                    chunks.append(f"{base}/{file_path.lstrip('/')}")
                for imp in entry.get("imports", []):
                    if isinstance(imp, str) and imp.endswith(".js"):
                        chunks.append(f"{base}/{imp.lstrip('/')}")

        return list(dict.fromkeys(chunks))

    # ── Phase 2: Numbered chunk brute-force ───────────────────────────────────

    def _probe_numbered_chunks(self, base: str) -> List[str]:
        """Probe /static/js/0.chunk.js … N.chunk.js using exponential backoff."""
        to_probe: List[str] = []
        for n in range(0, _MAX_NUMBERED_PROBES):
            for template in _NUMBERED_CHUNK_TEMPLATES:
                to_probe.append(base + template.format(n=n))

        return self._probe_urls_parallel(to_probe)

    # ── Phase 3: Framework-specific probing ───────────────────────────────────

    def _probe_framework_chunks(self, base: str, tech_profile) -> List[str]:
        frontend = (getattr(tech_profile, "frontend", "") or "").lower()
        raw_tech = [t.lower() for t in (getattr(tech_profile, "raw_tech", []) or [])]

        to_probe: List[str] = []
        if "next.js" in frontend or any("next" in t for t in raw_tech):
            to_probe.extend(base + p for p in _NEXTJS_PAGE_CHUNKS)

        return self._probe_urls_parallel(to_probe)

    # ── Phase 4: Hashed chunk derivation ──────────────────────────────────────

    def _derive_hashed_chunks(self, base: str, known_urls: set) -> List[str]:
        """
        Given known chunk URLs like /static/js/2.abc123de.chunk.js,
        try to find more by incrementing the numeric prefix.
        """
        # Extract numeric-prefix patterns: /path/N.HASH.chunk.js
        hash_chunk_re = re.compile(
            r"(/[a-zA-Z0-9/_\-]*/)(\d+)\.([a-f0-9]{6,16})\.chunk\.js$", re.I
        )
        to_probe: List[str] = []
        base_without_scheme = base.split("://", 1)[-1]

        for url in known_urls:
            if base_without_scheme not in url:
                continue
            path = "/" + url.split("://", 1)[-1].split("/", 1)[-1] if "://" in url else url
            m = hash_chunk_re.search(path)
            if not m:
                continue
            prefix, num, hash_part = m.group(1), int(m.group(2)), m.group(3)
            # Probe adjacent numbered chunks with the same hash
            for delta in range(-3, 10):
                candidate_n = num + delta
                if candidate_n < 0:
                    continue
                candidate = f"{base}{prefix}{candidate_n}.{hash_part}.chunk.js"
                to_probe.append(candidate)

        return self._probe_urls_parallel(to_probe) if to_probe else []

    # ── HTTP probe helper ─────────────────────────────────────────────────────

    def _probe_single(self, url: str) -> Optional[str]:
        h = {"User-Agent": "Mozilla/5.0 (OneInfinity ChunkEnumerator/1.0)"}
        h.update(self.headers)
        try:
            req = urllib.request.Request(url, headers=h)
            req.get_method = lambda: "HEAD"
            with urllib.request.urlopen(req, timeout=self.timeout, context=_SSL_CTX) as resp:
                if resp.status in (200, 304):
                    ct = resp.headers.get("Content-Type", "")
                    if "javascript" in ct or "text" in ct or url.endswith(".js"):
                        return url
        except Exception:
            pass
        return None

    def _probe_urls_parallel(self, urls: List[str]) -> List[str]:
        if not urls:
            return []
        found: List[str] = []
        with ThreadPoolExecutor(max_workers=self.workers) as pool:
            futures = {pool.submit(self._probe_single, u): u for u in urls}
            for future in as_completed(futures):
                result = future.result()
                if result:
                    found.append(result)
        return found
