"""
APKTool Wrapper
===============
Decompile APK files using APKTool to recover smali bytecode,
resources, and AndroidManifest.xml.

APKTool produces a directory structure::

    <output_dir>/
    ├── AndroidManifest.xml
    ├── apktool.yml
    ├── res/                  (decoded resources)
    ├── smali/                (primary dex → smali)
    ├── smali_classes2/       (multi-dex classes)
    └── ...

Usage::

    from oneinfinity.apktool_wrapper import apktool_wrapper

    result = apktool_wrapper.decompile("/path/to/app.apk")
    if result.success:
        manifest_text = apktool_wrapper.get_manifest(result)
        smali_files   = apktool_wrapper.get_smali_files(result)
        findings      = apktool_wrapper.analyze_for_vulns(result)
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

log = logging.getLogger("oneinfinity.mobile.apktool")

# ──────────────────────────────────────────────────────────────────────────────
#  Result type
# ──────────────────────────────────────────────────────────────────────────────

@dataclass
class ApktoolResult:
    """Output of a successful (or failed) APKTool decompilation."""

    apk_path: str
    """Absolute path of the original APK."""

    output_dir: str
    """Directory where APKTool wrote decompiled files."""

    manifest_path: str = ""
    """Absolute path to AndroidManifest.xml, or '' if not found."""

    smali_dirs: List[str] = field(default_factory=list)
    """List of smali_* directories (primary + multi-dex)."""

    resource_dir: str = ""
    """Absolute path to the res/ directory, or '' if absent."""

    success: bool = False
    """True when decompilation completed without fatal errors."""

    error: str = ""
    """Error message if decompilation failed."""

    decompile_time: float = 0.0
    """Wall-clock time in seconds taken for decompilation."""

    def __repr__(self) -> str:
        return (
            f"<ApktoolResult apk={os.path.basename(self.apk_path)!r} "
            f"success={self.success} smali_dirs={len(self.smali_dirs)}>"
        )


# ──────────────────────────────────────────────────────────────────────────────
#  Vulnerability patterns for smali analysis
# ──────────────────────────────────────────────────────────────────────────────

# Each entry: (compiled_regex, vuln_name, attack_type, severity, confidence, cvss, remediation)
_SMALI_VULN_PATTERNS: List[Tuple] = []

def _build_smali_patterns() -> List[Tuple]:
    """Build compiled smali vulnerability pattern list."""
    _raw = [
        # ── Weak crypto ───────────────────────────────────────────────────────
        (
            r'const-string[^"]*"DES(?:/[A-Z]+/[A-Z]+)?"',
            "Insecure DES/3DES Cipher",
            "weak_crypto", "high", 0.85, 7.0,
            "Replace DES/3DES with AES-256-GCM. DES has a 56-bit key space broken trivially.",
        ),
        (
            r'const-string[^"]*"RC4"',
            "Insecure RC4 Stream Cipher",
            "weak_crypto", "high", 0.85, 7.0,
            "RC4 is cryptographically broken. Use AES-256-GCM or ChaCha20-Poly1305.",
        ),
        (
            r'const-string[^"]*"MD5"',
            "MD5 Used (Potentially for Security)",
            "weak_crypto", "medium", 0.70, 5.9,
            "MD5 is collision-vulnerable. Use SHA-256 or SHA-3 for security purposes.",
        ),
        (
            r'const-string[^"]*"SHA-?1"',
            "SHA-1 Used (Deprecated for Security)",
            "weak_crypto", "medium", 0.70, 5.3,
            "SHA-1 is deprecated for security use. Migrate to SHA-256 or SHA-3.",
        ),
        (
            r'const-string[^"]*"AES/ECB',
            "AES-ECB Mode Detected",
            "weak_crypto", "high", 0.90, 7.3,
            "ECB mode does not hide plaintext patterns. Use AES-GCM or AES-CBC with a random IV.",
        ),
        # ── Hardcoded secrets (smali const-string) ────────────────────────────
        (
            r'const-string[^"]*"(?:AKIA|ASIA|AROA)[A-Z0-9]{16}"',
            "Hardcoded AWS Access Key",
            "hardcoded_secret", "critical", 0.95, 9.0,
            "Never embed AWS keys in app binaries. Use IAM roles and fetch credentials at runtime.",
        ),
        (
            r'const-string[^"]*"(?:sk-[A-Za-z0-9]{32,})"',
            "Hardcoded OpenAI API Key",
            "hardcoded_secret", "critical", 0.92, 9.0,
            "Revoke the exposed key and retrieve API keys from a secure server endpoint.",
        ),
        (
            r'const-string[^"]*"AIza[0-9A-Za-z_\-]{35}"',
            "Hardcoded Google API Key",
            "hardcoded_secret", "high", 0.90, 7.5,
            "Restrict the API key in Google Cloud Console and rotate it immediately.",
        ),
        # ── Logging ───────────────────────────────────────────────────────────
        (
            r'invoke-[a-z]+[^"]*Landroid/util/Log;->[deviwDEVIW]\b',
            "Android Logging APIs Used",
            "insecure_logging", "low", 0.60, 3.0,
            (
                "Audit all Log.d/Log.v/Log.e calls for sensitive data. "
                "Strip debug logs in release builds using ProGuard rules."
            ),
        ),
        # ── Reflection ────────────────────────────────────────────────────────
        (
            r'invoke-[a-z]+[^"]*Ljava/lang/reflect/Method;->invoke\b',
            "Java Reflection Used",
            "reflection", "low", 0.55, 3.1,
            (
                "Reflection can be used to bypass access controls. "
                "Validate class/method names before reflective invocation."
            ),
        ),
        # ── Dynamic code loading ───────────────────────────────────────────────
        (
            r'invoke-[a-z]+[^"]*Ldalvik/system/DexClassLoader;-><init>',
            "Dynamic DEX Loading (DexClassLoader)",
            "code_injection", "high", 0.85, 8.1,
            (
                "Dynamic code loading can introduce unverified code. "
                "Verify loaded DEX files with code signing before execution."
            ),
        ),
        (
            r'invoke-[a-z]+[^"]*Ldalvik/system/PathClassLoader;-><init>',
            "Dynamic DEX Loading (PathClassLoader)",
            "code_injection", "medium", 0.75, 6.5,
            "Ensure all dynamically loaded code is signature-verified.",
        ),
        # ── Insecure IPC ─────────────────────────────────────────────────────
        (
            r'invoke-[a-z]+[^"]*Landroid/content/Intent;->setAction\([^)]*\)',
            "Implicit Intent Used",
            "insecure_ipc", "low", 0.50, 3.1,
            "Use explicit intents or broadcast with permissions to avoid intent hijacking.",
        ),
        # ── Network (cleartext) ───────────────────────────────────────────────
        (
            r'const-string[^"]*"http://(?!localhost|127\.0\.0\.1)[a-zA-Z0-9]',
            "Cleartext HTTP URL Hardcoded",
            "insecure_transport", "medium", 0.80, 5.9,
            "Replace http:// URLs with https:// and enforce network_security_config.xml.",
        ),
        # ── Insecure random ───────────────────────────────────────────────────
        (
            r'invoke-[a-z]+[^"]*Ljava/util/Random;-><init>',
            "Insecure java.util.Random Used",
            "weak_random", "medium", 0.70, 5.3,
            "Use java.security.SecureRandom for all security-sensitive random values.",
        ),
        (
            r'invoke-[a-z]+[^"]*Ljava/lang/Math;->random\(',
            "Math.random() Used",
            "weak_random", "medium", 0.70, 5.3,
            "Math.random() is not cryptographically secure. Use SecureRandom instead.",
        ),
    ]
    return [
        (re.compile(pattern), vuln, attack, sev, conf, cvss, fix)
        for pattern, vuln, attack, sev, conf, cvss, fix in _raw
    ]


# Built lazily to avoid module-load cost
_SMALI_VULN_PATTERNS = _build_smali_patterns()


# ──────────────────────────────────────────────────────────────────────────────
#  Manifest vulnerability checks
# ──────────────────────────────────────────────────────────────────────────────

@dataclass
class _ManifestCheck:
    """A single manifest security rule."""
    pattern: re.Pattern
    vuln: str
    attack_type: str
    severity: str
    confidence: float
    cvss: float
    remediation: str


_MANIFEST_CHECKS = [
    _ManifestCheck(
        re.compile(r'android:debuggable\s*=\s*["\']true["\']', re.IGNORECASE),
        "Application Debuggable in Release Build",
        "misconfiguration",
        "high", 0.95, 7.4,
        (
            "Remove android:debuggable=\"true\" from the production manifest. "
            "Enable only in debug build variants. Debuggable apps expose "
            "the full Dalvik VM and allow arbitrary code injection."
        ),
    ),
    _ManifestCheck(
        re.compile(r'android:allowBackup\s*=\s*["\']true["\']', re.IGNORECASE),
        "Application Backup Enabled (allowBackup=true)",
        "insecure_backup",
        "medium", 0.90, 5.5,
        (
            "Set android:allowBackup=\"false\" or restrict backup with "
            "android:fullBackupContent / android:dataExtractionRules "
            "to prevent sensitive data leakage via ADB or cloud backup."
        ),
    ),
    _ManifestCheck(
        re.compile(r'android:usesCleartextTraffic\s*=\s*["\']true["\']', re.IGNORECASE),
        "Cleartext Traffic Explicitly Permitted",
        "insecure_transport",
        "high", 0.95, 7.5,
        (
            "Set android:usesCleartextTraffic=\"false\" and define a "
            "network_security_config.xml that prohibits cleartext HTTP."
        ),
    ),
    _ManifestCheck(
        re.compile(r'android:networkSecurityConfig\s*=\s*["\']', re.IGNORECASE),
        "Custom Network Security Config Present",
        "network_security",
        "info", 0.70, 0.0,
        "Review the network_security_config.xml to ensure no cleartext exceptions are granted.",
    ),
    _ManifestCheck(
        re.compile(
            r'<(?:activity|service|receiver|provider)[^>]+android:exported\s*=\s*["\']true["\'][^>]*>',
            re.IGNORECASE | re.DOTALL,
        ),
        "Exported Component Without Explicit Permission",
        "exported_component",
        "medium", 0.80, 6.5,
        (
            "Add android:permission to exported components or set "
            "android:exported=\"false\" if the component is only used internally."
        ),
    ),
    _ManifestCheck(
        re.compile(r'android:protectionLevel\s*=\s*["\'](?:normal|dangerous)["\']', re.IGNORECASE),
        "Custom Permission with Weak Protection Level",
        "permission_misconfiguration",
        "low", 0.70, 3.5,
        "Use protectionLevel=\"signature\" for custom permissions protecting sensitive components.",
    ),
    _ManifestCheck(
        re.compile(r'<intent-filter[^>]*>\s*<action[^/]*/>\s*</intent-filter>', re.DOTALL | re.IGNORECASE),
        "Activity with Open Intent Filter",
        "insecure_ipc",
        "low", 0.60, 3.1,
        (
            "Restrict intent filters to specific actions. "
            "Protect exported components that handle intents with permissions."
        ),
    ),
]


# ──────────────────────────────────────────────────────────────────────────────
#  Wrapper
# ──────────────────────────────────────────────────────────────────────────────

class ApktoolWrapper:
    """
    Thin wrapper around the APKTool command-line tool.

    All public methods degrade gracefully when APKTool is not installed —
    they log warnings and return empty/failed results rather than raising.
    """

    # Potential Java-based APKTool jar locations
    _JAR_CANDIDATES: List[str] = [
        str(Path.home() / ".local" / "lib" / "apktool.jar"),
        str(Path.home() / ".local" / "share" / "apktool" / "apktool.jar"),
        "/usr/local/lib/apktool.jar",
        "/opt/apktool/apktool.jar",
        "/usr/share/apktool/apktool.jar",
    ]

    def __init__(self) -> None:
        self._apktool_cmd: Optional[List[str]] = self._find_apktool()
        if not self._apktool_cmd:
            log.warning(
                "APKTool not found. Static smali analysis will be unavailable. "
                "Install with: sudo apt install apktool  OR  "
                "https://apktool.org/docs/install"
            )

    # ── Binary discovery ──────────────────────────────────────────────────────

    def _find_apktool(self) -> Optional[List[str]]:
        """
        Locate an APKTool executable.

        Returns a list suitable for use as ``subprocess.run``'s *cmd* argument
        (e.g. ``["apktool"]`` or ``["java", "-jar", "/path/to/apktool.jar"]``),
        or ``None`` if APKTool cannot be found.
        """
        # 1. Check tool registry
        t = tool_registry.get_tool("apktool")
        if t and t.is_available() and t.binary_path:
            return [t.binary_path]

        # 2. Check PATH directly
        for name in ("apktool", "apktool.sh"):
            found = shutil.which(name)
            if found:
                return [found]

        # 3. Extra search dirs
        extra_dirs = [
            str(Path.home() / ".local" / "bin"),
            str(Path.home() / "tools" / "bin"),
            "/usr/local/bin",
        ]
        for d in extra_dirs:
            for name in ("apktool", "apktool.sh"):
                candidate = os.path.join(d, name)
                if os.path.isfile(candidate) and os.access(candidate, os.X_OK):
                    return [candidate]

        # 4. Java JAR fallback
        java = shutil.which("java")
        if java:
            for jar in self._JAR_CANDIDATES:
                if os.path.isfile(jar):
                    log.info("Using APKTool JAR: %s", jar)
                    return [java, "-jar", jar]

        return None

    # ── Decompilation ─────────────────────────────────────────────────────────

    def decompile(
        self,
        apk_path: str,
        output_dir: Optional[str] = None,
    ) -> ApktoolResult:
        """
        Decompile an APK using APKTool.

        Parameters
        ----------
        apk_path:
            Absolute path to the APK file.
        output_dir:
            Destination directory.  If None, a temporary directory is created
            inside the system temp tree.

        Returns
        -------
        ``ApktoolResult`` with ``success=True`` and populated paths on success,
        or ``success=False`` with an error message on failure.

        The command run is::

            apktool d -f -r <apk_path> -o <output_dir>

        Flags:
        * ``d``  — decode (decompile) mode
        * ``-f`` — force overwrite of output_dir
        * ``-r`` — do not decode resources (faster; preserves resources.arsc)
        """
        apk_path = os.path.abspath(apk_path)
        result = ApktoolResult(apk_path=apk_path, output_dir="")

        if not os.path.isfile(apk_path):
            result.error = f"APK file not found: {apk_path}"
            log.error(result.error)
            return result

        if not self._apktool_cmd:
            result.error = (
                "APKTool is not installed or not found. "
                "Install with: sudo apt install apktool"
            )
            log.warning(result.error)
            return result

        # Determine output directory
        if output_dir is None:
            base = tempfile.mkdtemp(prefix="oneinfinity_apktool_")
            app_name = Path(apk_path).stem
            output_dir = os.path.join(base, app_name)
        result.output_dir = os.path.abspath(output_dir)

        cmd = self._apktool_cmd + ["d", "-f", apk_path, "-o", result.output_dir]
        log.info("Decompiling %s → %s", os.path.basename(apk_path), result.output_dir)
        log.debug("APKTool cmd: %s", " ".join(cmd))

        start = time.monotonic()
        try:
            proc = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=300,    # large APKs can take a while
            )
            result.decompile_time = time.monotonic() - start

            if proc.returncode != 0:
                result.error = (
                    f"APKTool exited with code {proc.returncode}. "
                    f"stderr: {(proc.stderr or '')[:500]}"
                )
                log.error(result.error)
                return result

        except subprocess.TimeoutExpired:
            result.decompile_time = time.monotonic() - start
            result.error = "APKTool decompilation timed out after 300s."
            log.error(result.error)
            return result

        except FileNotFoundError as exc:
            result.error = f"APKTool binary not found at runtime: {exc}"
            log.error(result.error)
            return result

        except Exception as exc:  # noqa: BLE001
            result.error = f"APKTool unexpected error: {exc}"
            log.exception(result.error)
            return result

        # ── Populate result paths ──────────────────────────────────────────────
        result.success = True
        self._populate_paths(result)

        log.info(
            "Decompilation complete in %.1fs: manifest=%s, smali_dirs=%d",
            result.decompile_time,
            bool(result.manifest_path),
            len(result.smali_dirs),
        )
        return result

    def _populate_paths(self, result: ApktoolResult) -> None:
        """Fill in manifest_path, smali_dirs, and resource_dir after decompilation."""
        out = Path(result.output_dir)

        # AndroidManifest.xml
        manifest = out / "AndroidManifest.xml"
        if manifest.is_file():
            result.manifest_path = str(manifest)

        # smali directories (primary + multi-dex)
        smali_dirs = sorted(out.glob("smali*"))
        result.smali_dirs = [str(d) for d in smali_dirs if d.is_dir()]

        # res/
        res = out / "res"
        if res.is_dir():
            result.resource_dir = str(res)

    # ── Recompilation ─────────────────────────────────────────────────────────

    def recompile(
        self,
        source_dir: str,
        output_apk: Optional[str] = None,
    ) -> bool:
        """
        Recompile a decompiled APKTool directory back to an APK.

        Parameters
        ----------
        source_dir:
            Directory produced by ``decompile()``.
        output_apk:
            Destination APK path.  Defaults to ``<source_dir>/dist/<name>.apk``.

        Returns
        -------
        True on success, False on failure.
        """
        if not self._apktool_cmd:
            log.warning("recompile: APKTool not available.")
            return False

        cmd = self._apktool_cmd + ["b", source_dir]
        if output_apk:
            cmd += ["-o", output_apk]

        log.info("Recompiling %s …", source_dir)
        try:
            proc = subprocess.run(cmd, capture_output=True, text=True, timeout=300)
            if proc.returncode != 0:
                log.error("Recompile failed (rc=%d): %s", proc.returncode, proc.stderr[:300])
                return False
            log.info("Recompile successful.")
            return True
        except subprocess.TimeoutExpired:
            log.error("Recompile timed out.")
            return False
        except Exception as exc:  # noqa: BLE001
            log.exception("Recompile error: %s", exc)
            return False

    # ── File accessors ────────────────────────────────────────────────────────

    def get_manifest(self, result: ApktoolResult) -> Optional[str]:
        """
        Read and return the AndroidManifest.xml content as a string.

        Parameters
        ----------
        result:
            An ``ApktoolResult`` from a successful ``decompile()`` call.

        Returns
        -------
        Manifest content string, or None if the manifest file is absent.
        """
        if not result.manifest_path or not os.path.isfile(result.manifest_path):
            log.debug("get_manifest: manifest not found in result %r", result.output_dir)
            return None
        try:
            return Path(result.manifest_path).read_text(encoding="utf-8", errors="replace")
        except OSError as exc:
            log.error("get_manifest: could not read %s: %s", result.manifest_path, exc)
            return None

    def get_smali_files(self, result: ApktoolResult) -> List[Path]:
        """
        Enumerate all .smali files in the decompiled output.

        Parameters
        ----------
        result:
            An ``ApktoolResult`` from a successful ``decompile()`` call.

        Returns
        -------
        Sorted list of ``Path`` objects for every ``.smali`` file found.
        """
        smali_files: List[Path] = []
        for smali_dir in result.smali_dirs:
            smali_files.extend(sorted(Path(smali_dir).rglob("*.smali")))
        return smali_files

    def get_resource_files(self, result: ApktoolResult) -> List[Path]:
        """
        Enumerate all files in the res/ directory.

        Parameters
        ----------
        result:
            An ``ApktoolResult`` from a successful ``decompile()`` call.

        Returns
        -------
        Sorted list of ``Path`` objects for every file under res/.
        """
        if not result.resource_dir:
            return []
        return sorted(Path(result.resource_dir).rglob("*"))

    # ── Smali utilities ───────────────────────────────────────────────────────

    def extract_strings_from_smali(self, smali_file: Path) -> List[str]:
        """
        Extract all ``const-string`` literal values from a smali file.

        Parameters
        ----------
        smali_file:
            Path to a ``.smali`` file.

        Returns
        -------
        List of string literals (may include duplicates).
        """
        pattern = re.compile(r'const-string(?:/jumbo)?\s+\w+,\s*"([^"]*)"')
        try:
            text = smali_file.read_text(encoding="utf-8", errors="replace")
            return pattern.findall(text)
        except OSError as exc:
            log.debug("extract_strings_from_smali: error reading %s: %s", smali_file, exc)
            return []

    def find_class_in_smali(
        self,
        class_name: str,
        result: ApktoolResult,
    ) -> Optional[Path]:
        """
        Find the smali file for a given Java class name.

        Parameters
        ----------
        class_name:
            Fully qualified class name using either dot or slash notation,
            e.g. ``com.example.App`` or ``com/example/App``.
        result:
            An ``ApktoolResult`` with populated smali_dirs.

        Returns
        -------
        The ``Path`` of the matching ``.smali`` file, or None.
        """
        # Normalise: dots → slashes, strip trailing .class suffix
        normalised = class_name.replace(".", "/").removesuffix(".class")
        target_file = normalised + ".smali"

        for smali_dir in result.smali_dirs:
            candidate = Path(smali_dir) / target_file
            if candidate.is_file():
                return candidate

        # Case-insensitive fallback (for obfuscated class names)
        target_lower = target_file.lower()
        for smali_dir in result.smali_dirs:
            for p in Path(smali_dir).rglob("*.smali"):
                if p.name.lower() == Path(target_lower).name:
                    return p

        log.debug("find_class_in_smali: class '%s' not found.", class_name)
        return None

    # ── Vulnerability analysis ────────────────────────────────────────────────

    def analyze_for_vulns(self, result: ApktoolResult) -> List[UnifiedFinding]:
        """
        Perform static vulnerability analysis on a decompiled APK.

        Checks performed:

        **Manifest:**
        - ``android:debuggable="true"``         → HIGH
        - ``android:allowBackup="true"``         → MEDIUM
        - ``usesCleartextTraffic="true"``        → HIGH
        - Exported components without permissions → MEDIUM
        - Custom permissions with weak protection → LOW
        - Open intent filters                   → LOW

        **Smali bytecode:**
        - DES, 3DES, RC4, AES/ECB              → HIGH
        - MD5, SHA-1 in security context        → MEDIUM
        - Hardcoded AWS / OpenAI / Google keys  → CRITICAL/HIGH
        - Dynamic DEX loading                   → HIGH
        - java.util.Random / Math.random()      → MEDIUM
        - Reflection                            → LOW

        Parameters
        ----------
        result:
            An ``ApktoolResult`` from a successful ``decompile()`` call.

        Returns
        -------
        List of UnifiedFinding objects sorted by severity (most severe first).
        """
        if not result.success:
            log.warning("analyze_for_vulns: decompilation was unsuccessful, skipping.")
            return []

        findings: List[UnifiedFinding] = []
        package = _infer_package(result)

        # ── Manifest analysis ──────────────────────────────────────────────────
        manifest_text = self.get_manifest(result)
        if manifest_text:
            findings.extend(
                self._analyze_manifest(manifest_text, package=package, result=result)
            )
        else:
            log.warning("analyze_for_vulns: manifest not found in %s", result.output_dir)

        # ── Smali analysis ─────────────────────────────────────────────────────
        smali_files = self.get_smali_files(result)
        log.info(
            "Scanning %d smali files for vulnerabilities (pkg=%s) …",
            len(smali_files), package,
        )
        findings.extend(
            self._analyze_smali_files(smali_files, package=package)
        )

        log.info(
            "analyze_for_vulns: %d total findings for %s",
            len(findings), os.path.basename(result.apk_path),
        )
        return sorted(findings, key=lambda f: _sev_order(f.severity), reverse=True)

    def _analyze_manifest(
        self,
        manifest_text: str,
        package: str,
        result: ApktoolResult,
    ) -> List[UnifiedFinding]:
        """Apply manifest security checks and return findings."""
        findings: List[UnifiedFinding] = []

        for check in _MANIFEST_CHECKS:
            match = check.pattern.search(manifest_text)
            if not match:
                continue

            evidence = match.group(0)[:300]

            # Tighten exported-component findings: only flag if no permission attr
            if check.attack_type == "exported_component":
                # Check whether android:permission is present in the same tag
                tag_start = manifest_text.rfind("<", 0, match.start())
                tag_end   = manifest_text.find(">", match.end())
                tag_body  = manifest_text[tag_start:tag_end + 1] if tag_end != -1 else ""
                if "android:permission" in tag_body:
                    continue   # protected — skip

            findings.append(UnifiedFinding(
                target=package,
                vulnerability=check.vuln,
                attack_type=check.attack_type,
                tool="apktool",
                severity=check.severity,
                file_path=result.manifest_path,
                evidence=evidence,
                confidence=check.confidence,
                cvss=check.cvss,
                remediation=check.remediation,
                tags=["apktool", "manifest", "android", "static"],
            ))

        return findings

    def _analyze_smali_files(
        self,
        smali_files: List[Path],
        package: str,
    ) -> List[UnifiedFinding]:
        """Scan smali files for vulnerability patterns; return deduplicated findings."""
        # Track (vuln, file) pairs to avoid massive duplicates across files
        finding_vuln_counts: Dict[str, int] = {}
        _MAX_PER_VULN = 5   # cap findings per vulnerability type

        findings: List[UnifiedFinding] = []

        for smali_path in smali_files:
            try:
                content = smali_path.read_text(encoding="utf-8", errors="replace")
            except OSError:
                continue

            lines = content.splitlines()

            for regex, vuln, attack, sev, conf, cvss, fix in _SMALI_VULN_PATTERNS:
                count = finding_vuln_counts.get(vuln, 0)
                if count >= _MAX_PER_VULN:
                    continue   # already reported enough instances

                for line_no, line in enumerate(lines, start=1):
                    if regex.search(line):
                        finding_vuln_counts[vuln] = count + 1
                        findings.append(UnifiedFinding(
                            target=package,
                            vulnerability=vuln,
                            attack_type=attack,
                            tool="apktool",
                            severity=sev,
                            file_path=str(smali_path),
                            line_number=line_no,
                            evidence=line.strip()[:300],
                            confidence=conf,
                            cvss=cvss,
                            remediation=fix,
                            tags=["apktool", "smali", "static", attack],
                        ))
                        break  # one finding per pattern per file

        return findings


# ──────────────────────────────────────────────────────────────────────────────
#  Helpers
# ──────────────────────────────────────────────────────────────────────────────

def _infer_package(result: ApktoolResult) -> str:
    """Extract the package name from apktool.yml or the manifest."""
    yml = Path(result.output_dir) / "apktool.yml"
    if yml.is_file():
        try:
            text = yml.read_text(encoding="utf-8", errors="replace")
            m = re.search(r"packageInfo\s*:\s*\n\s*name\s*:\s*([^\s]+)", text)
            if m:
                return m.group(1)
        except OSError:
            pass

    if result.manifest_path and os.path.isfile(result.manifest_path):
        try:
            text = Path(result.manifest_path).read_text(encoding="utf-8", errors="replace")
            m = re.search(r'package\s*=\s*["\']([^"\']+)["\']', text)
            if m:
                return m.group(1)
        except OSError:
            pass

    return os.path.basename(result.apk_path)


def _sev_order(severity: str) -> int:
    return {"critical": 4, "high": 3, "medium": 2, "low": 1, "info": 0}.get(severity, 0)


# ──────────────────────────────────────────────────────────────────────────────
#  Module-level singleton
# ──────────────────────────────────────────────────────────────────────────────

#: Global singleton.  Import as:
#:     ``from apktool_wrapper import apktool_wrapper``
apktool_wrapper: ApktoolWrapper = ApktoolWrapper()
