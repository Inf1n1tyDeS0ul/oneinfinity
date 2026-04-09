"""
JADX Wrapper
============
Decompile APK/DEX files to Java source code using JADX.
Enables source-level analysis, pattern searching, endpoint extraction,
and AI-assisted reverse engineering.

JADX output structure::

    <output_dir>/
    ├── sources/
    │   └── com/example/app/
    │       ├── MainActivity.java
    │       └── ...
    └── resources/
        ├── AndroidManifest.xml
        └── ...

Usage::

    from oneinfinity.jadx_wrapper import jadx_wrapper

    result = jadx_wrapper.decompile("/path/to/app.apk")
    if result.success:
        endpoints = jadx_wrapper.extract_api_endpoints(result)
        findings  = jadx_wrapper.analyze_for_vulns(result)
        secrets   = jadx_wrapper.extract_hardcoded_strings(result)
"""

from __future__ import annotations

import logging
import os
import re
import shutil
import subprocess
import tempfile
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Dict, List, Optional, Tuple

from oneinfinity.mobile_tool_registry import UnifiedFinding, tool_registry

log = logging.getLogger("oneinfinity.mobile.jadx")

# ──────────────────────────────────────────────────────────────────────────────
#  Result type
# ──────────────────────────────────────────────────────────────────────────────

@dataclass
class JadxResult:
    """Output of a JADX decompilation run."""

    apk_path: str
    """Absolute path of the source APK/DEX/IPA."""

    output_dir: str
    """Directory where JADX wrote decompiled output."""

    source_dir: str = ""
    """Absolute path to the sources/ subdirectory."""

    resource_dir: str = ""
    """Absolute path to the resources/ subdirectory."""

    success: bool = False
    """True when decompilation completed without fatal errors."""

    java_files: int = 0
    """Number of .java files produced."""

    error: str = ""
    """Error or warning message on failure."""

    decompile_time: float = 0.0
    """Wall-clock time in seconds for decompilation."""

    def __repr__(self) -> str:
        return (
            f"<JadxResult apk={os.path.basename(self.apk_path)!r} "
            f"success={self.success} java_files={self.java_files}>"
        )


# ──────────────────────────────────────────────────────────────────────────────
#  Vulnerability patterns (Java source level)
# ──────────────────────────────────────────────────────────────────────────────

# Each entry: (compiled_regex, vuln_name, attack_type, severity, confidence, cvss, remediation)
def _build_java_vuln_patterns() -> List[Tuple]:
    _raw = [
        # ── Weak / broken crypto ──────────────────────────────────────────────
        (
            r'Cipher\.getInstance\s*\(\s*"(?:DES|DESede|3DES|RC4|RC2|ARCFOUR)(?:/[A-Z]+/[A-Z]+)?"',
            "Insecure Cipher Algorithm",
            "weak_crypto", "high", 0.90, 7.0,
            "Replace DES/3DES/RC4 with AES-256-GCM. Use Cipher.getInstance(\"AES/GCM/NoPadding\").",
        ),
        (
            r'Cipher\.getInstance\s*\(\s*"[A-Z]+/ECB/',
            "AES-ECB Mode (Pattern-Revealing)",
            "weak_crypto", "high", 0.92, 7.3,
            "ECB mode is deterministic and leaks patterns. Use AES/GCM/NoPadding with a random IV.",
        ),
        (
            r'MessageDigest\.getInstance\s*\(\s*"MD5"',
            "MD5 MessageDigest Usage",
            "weak_crypto", "medium", 0.80, 5.9,
            "MD5 is collision-vulnerable. Use SHA-256 or SHA-3 for cryptographic purposes.",
        ),
        (
            r'MessageDigest\.getInstance\s*\(\s*"SHA-?1"',
            "SHA-1 MessageDigest Usage",
            "weak_crypto", "medium", 0.75, 5.3,
            "SHA-1 is deprecated for security. Migrate to SHA-256 or BLAKE2b.",
        ),
        # ── Insecure randomness ───────────────────────────────────────────────
        (
            r'(?<![Ss]ecure)(?<![Ss]trong)new\s+Random\s*\(\)',
            "Insecure java.util.Random Instantiation",
            "weak_random", "medium", 0.75, 5.3,
            "Use java.security.SecureRandom for all security-sensitive random number generation.",
        ),
        (
            r'Math\.random\s*\(\)',
            "Math.random() Used",
            "weak_random", "medium", 0.70, 5.3,
            "Math.random() is not cryptographically secure. Use SecureRandom.nextDouble() instead.",
        ),
        # ── SQL injection ──────────────────────────────────────────────────────
        (
            r'(?:rawQuery|execSQL|query)\s*\([^)]*\+[^)]*\)',
            "Potential SQL Injection (String Concatenation in DB Query)",
            "sql_injection", "high", 0.70, 8.1,
            (
                "Use parameterised queries: db.rawQuery(\"SELECT * FROM t WHERE id=?\", "
                "new String[]{userInput}). Never concatenate user input into SQL."
            ),
        ),
        # ── WebView misconfigurations ─────────────────────────────────────────
        (
            r'setJavaScriptEnabled\s*\(\s*true\s*\)',
            "WebView JavaScript Enabled",
            "webview_misconfiguration", "medium", 0.85, 5.3,
            (
                "Only enable JavaScript in WebViews that load trusted content. "
                "Restrict the origin with allowContentAccess/allowFileAccess=false."
            ),
        ),
        (
            r'addJavascriptInterface\s*\(',
            "WebView addJavascriptInterface Used",
            "webview_misconfiguration", "high", 0.90, 8.8,
            (
                "addJavascriptInterface is a known attack surface. "
                "Annotate each exposed method with @JavascriptInterface and "
                "restrict WebView origins."
            ),
        ),
        (
            r'setAllowFileAccessFromFileURLs\s*\(\s*true\s*\)',
            "WebView File Access from URLs Enabled",
            "webview_misconfiguration", "high", 0.85, 7.5,
            "Disable setAllowFileAccessFromFileURLs to prevent cross-origin file reads.",
        ),
        (
            r'setAllowUniversalAccessFromFileURLs\s*\(\s*true\s*\)',
            "WebView Universal File Access Enabled",
            "webview_misconfiguration", "high", 0.88, 8.0,
            (
                "setAllowUniversalAccessFromFileURLs=true allows file:// URLs to reach "
                "any origin. Disable this setting."
            ),
        ),
        # ── Insecure storage ──────────────────────────────────────────────────
        (
            r'MODE_WORLD_READABLE|MODE_WORLD_WRITEABLE',
            "World-Readable / World-Writable File Mode",
            "insecure_storage", "high", 0.92, 6.5,
            "Never create world-readable files. Use EncryptedFile or app-private storage.",
        ),
        (
            r'getSharedPreferences\s*\([^)]*\)',
            "SharedPreferences Usage (Possible Sensitive Data)",
            "insecure_storage", "low", 0.50, 3.1,
            (
                "Audit SharedPreferences keys for sensitive data. "
                "Use EncryptedSharedPreferences for secrets."
            ),
        ),
        (
            r'openFileOutput\s*\([^,]+,\s*(?:Context\.)?MODE_(?:WORLD|APPEND)',
            "Insecure File Output Mode",
            "insecure_storage", "medium", 0.80, 5.5,
            "Use MODE_PRIVATE for file output. Never use world-readable or world-writable modes.",
        ),
        # ── Logging / PII leakage ─────────────────────────────────────────────
        (
            r'Log\.[devwiDEVWI]\s*\(\s*(?:TAG\s*,\s*)?["\']?(?:password|passwd|token|secret|key|credential)',
            "Sensitive Data Logged via android.util.Log",
            "insecure_logging", "medium", 0.80, 5.0,
            (
                "Remove Log statements that print sensitive data. "
                "Use ProGuard/R8 to strip all log calls in release builds."
            ),
        ),
        (
            r'System\.out\.print(?:ln)?\s*\([^)]*(?:password|token|secret)',
            "Sensitive Data Printed to stdout",
            "insecure_logging", "medium", 0.75, 4.5,
            "Remove System.out.println calls containing sensitive data.",
        ),
        # ── Hardcoded secrets ──────────────────────────────────────────────────
        (
            r'(?:AKIA|ASIA|AROA)[A-Z0-9]{16}',
            "Hardcoded AWS Access Key",
            "hardcoded_secret", "critical", 0.95, 9.0,
            "Revoke the exposed key immediately. Use IAM roles and instance metadata instead.",
        ),
        (
            r'sk-[A-Za-z0-9]{32,}',
            "Hardcoded OpenAI API Key",
            "hardcoded_secret", "critical", 0.92, 9.0,
            "Revoke and regenerate the key. Fetch API credentials from a secure server endpoint.",
        ),
        (
            r'AIza[0-9A-Za-z_\-]{35}',
            "Hardcoded Google API Key",
            "hardcoded_secret", "high", 0.90, 7.5,
            "Restrict the key in the Google Cloud Console and rotate it.",
        ),
        (
            r'ghp_[A-Za-z0-9]{36,}',
            "Hardcoded GitHub Personal Access Token",
            "hardcoded_secret", "critical", 0.95, 9.0,
            "Revoke the PAT on GitHub immediately. Never embed tokens in source code.",
        ),
        (
            r'-----BEGIN (?:RSA |EC |DSA )?PRIVATE KEY-----',
            "Private Key Embedded in Source",
            "hardcoded_secret", "critical", 0.99, 10.0,
            "Remove the private key immediately. Use Android Keystore for key storage.",
        ),
        (
            r'(?i)(?:password|passwd|pwd)\s*=\s*["\'](?!.*BuildConfig)[^"\']{6,}["\']',
            "Hardcoded Password",
            "hardcoded_secret", "critical", 0.75, 9.0,
            "Remove hardcoded passwords. Fetch credentials from a secure vault at runtime.",
        ),
        # ── Network / TLS ──────────────────────────────────────────────────────
        (
            r'(?i)AllowAllHostnameVerifier|ALLOW_ALL_HOSTNAME_VERIFIER',
            "Hostname Verifier Bypassed",
            "insecure_tls", "critical", 0.95, 9.8,
            "Never bypass hostname verification. Use the default HostnameVerifier.",
        ),
        (
            r'(?i)TrustAllCert|trustAll|X509TrustManager[^{]*\{\s*public\s+void\s+checkServer',
            "Custom TrustManager Bypassing Certificate Validation",
            "insecure_tls", "critical", 0.90, 9.8,
            "Remove custom TrustManagers that accept all certificates. Use system CA store.",
        ),
        (
            r'"http://(?!localhost|127\.0\.0\.1)',
            "Cleartext HTTP URL",
            "insecure_transport", "medium", 0.80, 5.9,
            "Replace http:// with https://. Enforce HTTPS via network_security_config.xml.",
        ),
        # ── Dynamic code loading ───────────────────────────────────────────────
        (
            r'DexClassLoader\s*\(',
            "Dynamic DEX Class Loading",
            "code_injection", "high", 0.85, 8.1,
            "Verify the integrity of dynamically loaded DEX files before execution.",
        ),
        (
            r'Runtime\.exec\s*\(',
            "Runtime.exec() Used (Command Execution)",
            "command_injection", "high", 0.80, 8.5,
            "Avoid Runtime.exec() with user-controlled input. Use ProcessBuilder with an argument array.",
        ),
        # ── Intents ────────────────────────────────────────────────────────────
        (
            r'getIntent\(\)\.getStringExtra\s*\(',
            "Intent Extra Received Without Validation",
            "insecure_ipc", "low", 0.55, 3.1,
            "Validate and sanitise all Intent extras before use to prevent intent injection.",
        ),
    ]
    return [
        (re.compile(pattern), vuln, attack, sev, conf, cvss, fix)
        for pattern, vuln, attack, sev, conf, cvss, fix in _raw
    ]


_JAVA_VULN_PATTERNS = _build_java_vuln_patterns()


# ──────────────────────────────────────────────────────────────────────────────
#  Endpoint / string extraction patterns
# ──────────────────────────────────────────────────────────────────────────────

# Retrofit annotation patterns
_RETROFIT_PATTERN = re.compile(
    r'@(?:GET|POST|PUT|DELETE|PATCH|HEAD|OPTIONS|HTTP)\s*\(\s*["\']([^"\']+)["\']',
    re.IGNORECASE,
)
# OkHttp / generic URL builder
_URL_BUILD_PATTERN = re.compile(
    r'\.url\s*\(\s*["\']([^"\']+)["\']',
    re.IGNORECASE,
)
# String literals that look like API paths
_API_PATH_PATTERN = re.compile(
    r'["\'](?:/[a-zA-Z0-9_\-/{}]+(?:\?[a-zA-Z0-9_=&]+)?)["\']',
)
# Full URLs
_FULL_URL_PATTERN = re.compile(
    r'["\']https?://[a-zA-Z0-9\-._~:/?#\[\]@!$&\'()*+,;=%]{10,}["\']',
)
# Retrofit BaseUrl
_BASE_URL_PATTERN = re.compile(
    r'baseUrl\s*\(\s*["\']([^"\']+)["\']',
    re.IGNORECASE,
)

# String literals that look like secrets
_INTERESTING_STRING_PATTERN = re.compile(
    r'"([A-Za-z0-9_\-./+]{16,})"',
)
_SECRET_STRING_PATTERNS: List[Tuple[re.Pattern, str]] = [
    (re.compile(r'(?:AKIA|ASIA|AROA)[A-Z0-9]{16}'),  "aws_access_key"),
    (re.compile(r'AIza[0-9A-Za-z_\-]{35}'),            "google_api_key"),
    (re.compile(r'sk-[A-Za-z0-9]{32,}'),               "openai_key"),
    (re.compile(r'ghp_[A-Za-z0-9]{36,}'),              "github_pat"),
    (re.compile(r'-----BEGIN (?:RSA |EC )?PRIVATE KEY'),  "private_key"),
    (re.compile(r'eyJ[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]+\.[A-Za-z0-9_\-]+'), "jwt"),
    (re.compile(r'(?i)(?:password|passwd|pwd)\s*=\s*["\'][^"\']{6,}["\']'), "hardcoded_password"),
    (re.compile(r'(?i)(?:apikey|api_key|secret)\s*=\s*["\'][A-Za-z0-9_\-]{10,}["\']'), "api_key"),
]


# ──────────────────────────────────────────────────────────────────────────────
#  Wrapper
# ──────────────────────────────────────────────────────────────────────────────

class JadxWrapper:
    """
    Subprocess-based wrapper around the JADX command-line decompiler.

    All methods degrade gracefully when JADX is not installed — they log
    warnings and return empty/failed results rather than raising.
    """

    def __init__(self) -> None:
        self._jadx_bin: Optional[str] = self._find_jadx()
        if not self._jadx_bin:
            log.warning(
                "JADX binary not found. Java source decompilation will be unavailable. "
                "Install from: https://github.com/skylot/jadx/releases"
            )

    # ── Binary discovery ──────────────────────────────────────────────────────

    def _find_jadx(self) -> Optional[str]:
        """
        Locate the JADX binary.

        Search order:
        1. Tool registry
        2. PATH (jadx, jadx.bat)
        3. Common install directories
        """
        # Tool registry
        t = tool_registry.get_tool("jadx")
        if t and t.is_available() and t.binary_path:
            return t.binary_path

        # PATH
        for name in ("jadx", "jadx.bat"):
            found = shutil.which(name)
            if found:
                return found

        # Extra directories
        extra_dirs = [
            str(Path.home() / ".local" / "bin"),
            str(Path.home() / "tools" / "bin"),
            str(Path.home() / "tools" / "jadx" / "bin"),
            "/usr/local/bin",
            "/opt/jadx/bin",
        ]
        for d in extra_dirs:
            for name in ("jadx", "jadx.bat"):
                candidate = os.path.join(d, name)
                if os.path.isfile(candidate) and os.access(candidate, os.X_OK):
                    return candidate

        return None

    # ── Decompilation ─────────────────────────────────────────────────────────

    def decompile(
        self,
        apk_path: str,
        output_dir: Optional[str] = None,
        jobs: int = 4,
    ) -> JadxResult:
        """
        Decompile an APK or DEX file to Java source code using JADX.

        Parameters
        ----------
        apk_path:
            Absolute path to the APK, DEX, or AAB file.
        output_dir:
            Destination directory.  A unique temp directory is created if None.
        jobs:
            Number of parallel decompilation threads (default 4).

        Returns
        -------
        ``JadxResult`` with ``success=True`` and populated paths on success.

        Command run::

            jadx -d <output_dir> --jobs <jobs> <apk_path>
        """
        apk_path = os.path.abspath(apk_path)
        result = JadxResult(apk_path=apk_path, output_dir="")

        if not os.path.isfile(apk_path):
            result.error = f"Input file not found: {apk_path}"
            log.error(result.error)
            return result

        if not self._jadx_bin:
            result.error = (
                "JADX is not installed. "
                "Download from https://github.com/skylot/jadx/releases"
            )
            log.warning(result.error)
            return result

        # Determine output directory
        if output_dir is None:
            base = tempfile.mkdtemp(prefix="oneinfinity_jadx_")
            app_name = Path(apk_path).stem
            output_dir = os.path.join(base, app_name)
        result.output_dir = os.path.abspath(output_dir)

        cmd = [
            self._jadx_bin,
            "-d", result.output_dir,
            "--jobs", str(jobs),
            apk_path,
        ]

        log.info("Decompiling %s → %s (jobs=%d)", os.path.basename(apk_path), result.output_dir, jobs)
        log.debug("JADX cmd: %s", " ".join(cmd))

        start = time.monotonic()
        try:
            proc = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=600,   # large apps may take several minutes
            )
            result.decompile_time = time.monotonic() - start

            # JADX exits 0 even on partial failure; check stderr for fatal errors
            stderr_lower = (proc.stderr or "").lower()
            if proc.returncode != 0 and "error" in stderr_lower:
                result.error = (
                    f"JADX exited with code {proc.returncode}. "
                    f"stderr: {(proc.stderr or '')[:500]}"
                )
                log.error(result.error)
                # Fall through — JADX often produces partial output even on non-zero exit

        except subprocess.TimeoutExpired:
            result.decompile_time = time.monotonic() - start
            result.error = "JADX decompilation timed out after 600s."
            log.error(result.error)
            return result

        except FileNotFoundError as exc:
            result.error = f"JADX binary not found at runtime: {exc}"
            log.error(result.error)
            return result

        except Exception as exc:  # noqa: BLE001
            result.error = f"JADX unexpected error: {exc}"
            log.exception(result.error)
            return result

        # ── Populate result paths ──────────────────────────────────────────────
        self._populate_paths(result)

        if result.java_files > 0:
            result.success = True
        elif not result.error:
            result.error = f"JADX produced no Java files in {result.output_dir}"
            log.warning(result.error)

        log.info(
            "Decompilation complete in %.1fs: java_files=%d success=%s",
            result.decompile_time, result.java_files, result.success,
        )
        return result

    def _populate_paths(self, result: JadxResult) -> None:
        """Discover sources/ and resources/ directories, count Java files."""
        out = Path(result.output_dir)

        # JADX ≥ 1.4 uses sources/, older versions use src/
        for src_name in ("sources", "src"):
            src = out / src_name
            if src.is_dir():
                result.source_dir = str(src)
                break

        # resources/
        for res_name in ("resources", "res"):
            res = out / res_name
            if res.is_dir():
                result.resource_dir = str(res)
                break

        # Count java files
        if result.source_dir:
            result.java_files = sum(1 for _ in Path(result.source_dir).rglob("*.java"))

    # ── File accessors ────────────────────────────────────────────────────────

    def get_java_files(self, result: JadxResult) -> List[Path]:
        """
        Enumerate all ``.java`` files in the decompiled output.

        Parameters
        ----------
        result:
            A ``JadxResult`` from a successful ``decompile()`` call.

        Returns
        -------
        Sorted list of ``Path`` objects.
        """
        if not result.source_dir:
            return []
        return sorted(Path(result.source_dir).rglob("*.java"))

    def read_class(
        self,
        class_name: str,
        result: JadxResult,
    ) -> Optional[str]:
        """
        Find and return the source of a Java class by fully-qualified name.

        Parameters
        ----------
        class_name:
            Fully qualified class name (dot or slash notation), e.g.
            ``com.example.MainActivity``.
        result:
            A ``JadxResult`` from a successful ``decompile()`` call.

        Returns
        -------
        Source code string, or None if the class was not found.
        """
        if not result.source_dir:
            return None

        # Normalise: dots → path separators
        relative = class_name.replace(".", "/").removesuffix(".class").removesuffix(".java") + ".java"
        candidate = Path(result.source_dir) / relative
        if candidate.is_file():
            try:
                return candidate.read_text(encoding="utf-8", errors="replace")
            except OSError as exc:
                log.debug("read_class: error reading %s: %s", candidate, exc)
                return None

        # Fallback: search by file name only (handles obfuscated package paths)
        file_name = Path(relative).name
        for p in Path(result.source_dir).rglob(file_name):
            try:
                return p.read_text(encoding="utf-8", errors="replace")
            except OSError:
                pass

        log.debug("read_class: class '%s' not found in %s", class_name, result.source_dir)
        return None

    # ── Pattern search ────────────────────────────────────────────────────────

    def search_pattern(
        self,
        pattern: str,
        result: JadxResult,
        case_insensitive: bool = False,
    ) -> List[Tuple[Path, int, str]]:
        """
        Search for a regex pattern across all decompiled Java source files.

        Parameters
        ----------
        pattern:
            Regular expression to search for.
        result:
            A ``JadxResult`` from a successful ``decompile()`` call.
        case_insensitive:
            If True, compile with re.IGNORECASE.

        Returns
        -------
        List of ``(file_path, line_number, line_content)`` tuples for every match.
        Results are capped at 200 to avoid flooding.
        """
        flags = re.IGNORECASE if case_insensitive else 0
        try:
            regex = re.compile(pattern, flags)
        except re.error as exc:
            log.error("search_pattern: invalid regex %r: %s", pattern, exc)
            return []

        matches: List[Tuple[Path, int, str]] = []
        _MAX_RESULTS = 200

        for java_file in self.get_java_files(result):
            try:
                for line_no, line in enumerate(
                    java_file.read_text(encoding="utf-8", errors="replace").splitlines(),
                    start=1,
                ):
                    if regex.search(line):
                        matches.append((java_file, line_no, line.strip()))
                        if len(matches) >= _MAX_RESULTS:
                            log.debug("search_pattern: hit cap of %d results.", _MAX_RESULTS)
                            return matches
            except OSError:
                continue

        return matches

    # ── Endpoint extraction ───────────────────────────────────────────────────

    def extract_api_endpoints(self, result: JadxResult) -> List[str]:
        """
        Extract API endpoint URLs and path fragments from the Java source.

        Detection strategies:
        - Retrofit ``@GET``/``@POST``/… annotations
        - OkHttp ``.url(...)`` builder calls
        - ``baseUrl(...)`` calls
        - Generic string literals that look like URL paths (``/api/v1/...``)
        - Full https:// URLs

        Parameters
        ----------
        result:
            A ``JadxResult`` from a successful ``decompile()`` call.

        Returns
        -------
        Deduplicated, sorted list of endpoint strings.
        """
        endpoints: set = set()

        for java_file in self.get_java_files(result):
            try:
                content = java_file.read_text(encoding="utf-8", errors="replace")
            except OSError:
                continue

            for regex in (_RETROFIT_PATTERN, _URL_BUILD_PATTERN, _BASE_URL_PATTERN):
                for m in regex.finditer(content):
                    ep = m.group(1).strip()
                    if ep:
                        endpoints.add(ep)

            for m in _FULL_URL_PATTERN.finditer(content):
                url = m.group(0).strip('"\'')
                if len(url) >= 10:
                    endpoints.add(url)

            for m in _API_PATH_PATTERN.finditer(content):
                path = m.group(0).strip('"\'')
                # Only include paths with at least two segments to reduce noise
                if path.count("/") >= 2:
                    endpoints.add(path)

        # Filter out obvious non-endpoints
        filtered = {
            ep for ep in endpoints
            if not ep.endswith((".xml", ".html", ".css", ".png", ".jpg", ".svg"))
            and not ep.startswith("//")
        }

        log.debug("extract_api_endpoints: found %d endpoints", len(filtered))
        return sorted(filtered)

    # ── Hardcoded string extraction ────────────────────────────────────────────

    def extract_hardcoded_strings(
        self,
        result: JadxResult,
    ) -> List[Tuple[str, Path, int]]:
        """
        Extract interesting hardcoded string literals from Java source.

        Focuses on strings that match known secret patterns (AWS keys, API tokens,
        JWTs, private keys, hardcoded passwords, etc.).

        Parameters
        ----------
        result:
            A ``JadxResult`` from a successful ``decompile()`` call.

        Returns
        -------
        List of ``(secret_value, file_path, line_number)`` tuples.
        Capped at 100 results total.
        """
        results_list: List[Tuple[str, Path, int]] = []
        seen_values: set = set()
        _MAX = 100

        for java_file in self.get_java_files(result):
            try:
                lines = java_file.read_text(encoding="utf-8", errors="replace").splitlines()
            except OSError:
                continue

            for line_no, line in enumerate(lines, start=1):
                for regex, _label in _SECRET_STRING_PATTERNS:
                    m = regex.search(line)
                    if m:
                        val = m.group(0)[:200]
                        if val in seen_values:
                            continue
                        seen_values.add(val)
                        results_list.append((val, java_file, line_no))
                        if len(results_list) >= _MAX:
                            return results_list

        log.debug("extract_hardcoded_strings: found %d strings", len(results_list))
        return results_list

    # ── Package structure ─────────────────────────────────────────────────────

    def get_package_structure(self, result: JadxResult) -> Dict[str, List[str]]:
        """
        Build a map of package name → class names from the decompiled source.

        Parameters
        ----------
        result:
            A ``JadxResult`` from a successful ``decompile()`` call.

        Returns
        -------
        ``{package_name: [ClassName, ...]}`` dict, sorted alphabetically.
        """
        packages: Dict[str, List[str]] = {}

        if not result.source_dir:
            return packages

        src = Path(result.source_dir)
        for java_file in self.get_java_files(result):
            # Derive package from directory structure relative to sources/
            try:
                rel = java_file.relative_to(src)
            except ValueError:
                rel = java_file

            parts = list(rel.parts)
            class_name = java_file.stem
            pkg_name = ".".join(parts[:-1]) if len(parts) > 1 else "(default)"

            packages.setdefault(pkg_name, []).append(class_name)

        return dict(sorted(packages.items()))

    # ── Vulnerability analysis ─────────────────────────────────────────────────

    def analyze_for_vulns(self, result: JadxResult) -> List[UnifiedFinding]:
        """
        Perform static vulnerability analysis on decompiled Java source.

        Checks performed:

        **Weak cryptography:**
        DES, 3DES, RC4, AES-ECB, MD5, SHA-1

        **Insecure randomness:**
        java.util.Random, Math.random()

        **Injection vulnerabilities:**
        SQL injection (string concatenation in DB queries)
        Runtime.exec() with string concatenation

        **WebView misconfigurations:**
        setJavaScriptEnabled(true), addJavascriptInterface,
        setAllowFileAccessFromFileURLs(true), setAllowUniversalAccessFromFileURLs(true)

        **Insecure storage:**
        MODE_WORLD_READABLE / MODE_WORLD_WRITABLE, plain SharedPreferences for secrets

        **Sensitive data logging:**
        Log.d/e/v with password/token/secret keywords, System.out.println

        **Hardcoded secrets:**
        AWS keys, OpenAI keys, Google API keys, GitHub PATs, private keys, passwords

        **Insecure TLS:**
        Custom TrustManagers that accept all certs, AllowAllHostnameVerifier

        **Network:**
        Cleartext http:// URLs

        **Dynamic code loading:**
        DexClassLoader, Runtime.exec()

        Parameters
        ----------
        result:
            A ``JadxResult`` from a successful ``decompile()`` call.

        Returns
        -------
        List of ``UnifiedFinding`` objects sorted by severity (most severe first).
        """
        if not result.success:
            log.warning("analyze_for_vulns: decompilation was unsuccessful, skipping.")
            return []

        java_files = self.get_java_files(result)
        log.info(
            "Scanning %d Java files for vulnerabilities (output=%s) …",
            len(java_files), result.output_dir,
        )

        package = _infer_package_from_source(result)
        findings: List[UnifiedFinding] = []

        # Per-vulnerability type cap to avoid noise
        _MAX_PER_VULN = 5
        vuln_counts: Dict[str, int] = {}

        for java_file in java_files:
            try:
                content = java_file.read_text(encoding="utf-8", errors="replace")
            except OSError:
                continue

            lines = content.splitlines()

            for regex, vuln, attack, sev, conf, cvss, fix in _JAVA_VULN_PATTERNS:
                if vuln_counts.get(vuln, 0) >= _MAX_PER_VULN:
                    continue

                for line_no, line in enumerate(lines, start=1):
                    if regex.search(line):
                        vuln_counts[vuln] = vuln_counts.get(vuln, 0) + 1
                        findings.append(UnifiedFinding(
                            target=package,
                            vulnerability=vuln,
                            attack_type=attack,
                            tool="jadx",
                            severity=sev,
                            file_path=str(java_file),
                            line_number=line_no,
                            evidence=line.strip()[:400],
                            confidence=conf,
                            cvss=cvss,
                            remediation=fix,
                            tags=["jadx", "static", "java", attack],
                        ))
                        break   # one finding per pattern per file

        # Also include explicit hardcoded secrets as HIGH+ findings
        for secret_val, secret_file, secret_line in self.extract_hardcoded_strings(result):
            # Determine type
            label = "Hardcoded Secret"
            sev = "high"
            for regex, lbl in _SECRET_STRING_PATTERNS:
                if regex.search(secret_val):
                    label = f"Hardcoded {lbl.replace('_', ' ').title()}"
                    if "aws" in lbl or "openai" in lbl or "private" in lbl or "password" in lbl:
                        sev = "critical"
                    break

            # Avoid duplicating findings already caught by pattern scan
            key = (label, str(secret_file))
            if key not in {(f.vulnerability, f.file_path) for f in findings}:
                findings.append(UnifiedFinding(
                    target=package,
                    vulnerability=label,
                    attack_type="hardcoded_secret",
                    tool="jadx",
                    severity=sev,
                    file_path=str(secret_file),
                    line_number=secret_line,
                    evidence=secret_val[:200],
                    confidence=0.85,
                    cvss=9.0 if sev == "critical" else 7.5,
                    remediation=(
                        "Remove all hardcoded credentials from the app. "
                        "Fetch secrets at runtime from a secure server endpoint."
                    ),
                    tags=["jadx", "static", "hardcoded_secret"],
                ))

        sorted_findings = sorted(
            findings,
            key=lambda f: {"critical": 4, "high": 3, "medium": 2, "low": 1, "info": 0}.get(
                f.severity, 0
            ),
            reverse=True,
        )

        log.info(
            "analyze_for_vulns: %d total findings for %s",
            len(sorted_findings),
            os.path.basename(result.apk_path),
        )
        return sorted_findings

    def __repr__(self) -> str:   # pragma: no cover
        status = "available" if self._jadx_bin else "unavailable"
        return f"<JadxWrapper jadx={status}>"


# ──────────────────────────────────────────────────────────────────────────────
#  Helpers
# ──────────────────────────────────────────────────────────────────────────────

def _infer_package_from_source(result: JadxResult) -> str:
    """Infer the app package name from the source directory structure."""
    if not result.source_dir:
        return os.path.basename(result.apk_path)

    src = Path(result.source_dir)
    # Look for the deepest directory that contains at least one .java file
    # and whose path looks like com/example/app
    for java_file in sorted(src.rglob("*.java"))[:5]:
        try:
            rel = java_file.relative_to(src)
            parts = list(rel.parts[:-1])   # drop filename
            # Filter to parts that look like Java package components (all lowercase, no hyphens)
            pkg_parts = [p for p in parts if re.match(r'^[a-z][a-z0-9_]*$', p)]
            if len(pkg_parts) >= 2:
                return ".".join(pkg_parts)
        except ValueError:
            continue

    return os.path.basename(result.apk_path)


# ──────────────────────────────────────────────────────────────────────────────
#  Module-level singleton
# ──────────────────────────────────────────────────────────────────────────────

#: Global singleton.  Import as:
#:     ``from jadx_wrapper import jadx_wrapper``
jadx_wrapper: JadxWrapper = JadxWrapper()
