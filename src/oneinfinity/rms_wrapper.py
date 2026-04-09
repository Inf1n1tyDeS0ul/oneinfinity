"""
RMS (Runtime Mobile Security) Wrapper
======================================
Runtime analysis using RMS - Runtime Mobile Security.
RMS provides a Frida-based runtime analysis framework.
"""

from __future__ import annotations

import json
import logging
import os
import re
import shutil
import subprocess
import tempfile
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional

from oneinfinity.mobile.tool_registry import UnifiedFinding

logger = logging.getLogger("oneinfinity.mobile.rms")

_TOOL = "rms"

# Known RMS module names
_RMS_MODULES = [
    "crypto",
    "network",
    "storage",
    "intents",
    "ssl",
    "root",
    "biometric",
    "clipboard",
    "webview",
    "debugger",
]

# Search directories for RMS installation
_RMS_SEARCH_DIRS = [
    Path.home() / ".local" / "share" / "rms",
    Path.home() / ".local" / "lib" / "rms",
    Path("/opt/rms"),
    Path("/usr/local/lib/rms"),
    Path("/usr/share/rms"),
]


@dataclass
class RMSConfig:
    rms_path: str = ""
    device_id: str = ""
    output_dir: str = ""


class RMSWrapper:
    """Wraps Runtime Mobile Security (RMS) for Frida-based runtime analysis."""

    def __init__(self, config: RMSConfig = None) -> None:
        self.config = config or RMSConfig()
        self._rms_path: Optional[str] = self._find_rms()
        self._scripts_dir: Optional[Path] = self._find_rms_scripts()
        self._frida: Optional[str] = shutil.which("frida")

    # ------------------------------------------------------------------ discovery

    def _find_rms(self) -> Optional[str]:
        """
        Locate the RMS CLI.

        Search order:
        1. config.rms_path (if set and executable)
        2. 'rms' on $PATH
        3. npm global packages (rms, runtime-mobile-security)
        4. Python entry-point 'rms'
        """
        # Explicit config override
        if self.config.rms_path and os.access(self.config.rms_path, os.X_OK):
            return self.config.rms_path

        # $PATH lookup
        for name in ("rms", "runtime-mobile-security"):
            path = shutil.which(name)
            if path:
                logger.debug("Found RMS at %s", path)
                return path

        # npm global: ~/.npm-global/bin, /usr/local/lib/node_modules/.bin
        npm_dirs = [
            Path.home() / ".npm-global" / "bin",
            Path("/usr/local/bin"),
            Path("/usr/local/lib") / "node_modules" / ".bin",
            Path.home() / "node_modules" / ".bin",
        ]
        for d in npm_dirs:
            for name in ("rms", "runtime-mobile-security"):
                candidate = d / name
                if candidate.is_file() and os.access(candidate, os.X_OK):
                    logger.debug("Found RMS (npm) at %s", candidate)
                    return str(candidate)

        # Python package entry-point
        pipx = shutil.which("pipx")
        if pipx:
            pipx_home = Path.home() / ".local" / "pipx" / "venvs" / "rms" / "bin" / "rms"
            if pipx_home.is_file() and os.access(pipx_home, os.X_OK):
                return str(pipx_home)

        logger.info("RMS CLI not found — will use Frida scripts directly if available")
        return None

    def _find_rms_scripts(self) -> Optional[Path]:
        """
        Locate the RMS Frida scripts directory.

        Checks:
        1. Known installation directories
        2. npm package path (node_modules/rms/scripts)
        3. Cloned git repositories in ~/tools or ~/src
        """
        for base in _RMS_SEARCH_DIRS:
            if base.is_dir():
                # Check for a scripts/ subdirectory with .js files
                scripts = base / "scripts"
                if scripts.is_dir() and list(scripts.glob("*.js")):
                    logger.debug("Found RMS scripts at %s", scripts)
                    return scripts
                # Some installs keep scripts at the root
                if list(base.glob("*.js")):
                    return base

        # Check npm node_modules
        npm_roots = [
            Path.home() / "node_modules" / "rms" / "agent" / "src",
            Path.home() / "node_modules" / "runtime-mobile-security" / "scripts",
            Path("/usr/local/lib") / "node_modules" / "rms" / "scripts",
        ]
        for p in npm_roots:
            if p.is_dir():
                return p

        # Common git-clone locations
        git_locations = [
            Path.home() / "tools" / "rms",
            Path.home() / "src" / "rms",
            Path.home() / "rms",
            Path("/opt") / "rms",
        ]
        for loc in git_locations:
            for subdir in ("scripts", "agent/src", "."):
                candidate = loc / subdir
                if candidate.is_dir() and list(candidate.glob("*.js")):
                    return candidate

        return None

    # ------------------------------------------------------------------ module list

    def get_available_modules(self) -> List[str]:
        """
        Return the list of available RMS analysis modules.

        If the scripts directory was found, enumerates .js files.
        Otherwise returns the built-in default module list.
        """
        if self._scripts_dir and self._scripts_dir.is_dir():
            modules = [
                f.stem for f in sorted(self._scripts_dir.glob("*.js"))
                if not f.name.startswith("_")
            ]
            if modules:
                return modules

        return list(_RMS_MODULES)

    # ------------------------------------------------------------------ module execution

    def run_module(
        self,
        package: str,
        module: str,
        device_id: str = "",
        timeout: int = 60,
    ) -> dict:
        """
        Run an RMS module against *package*.

        If the RMS CLI is available:
            rms run --package {package} --module {module} [--device {device_id}]

        If only a scripts directory is found and frida is available:
            frida -U -f {package} -l {scripts_dir}/{module}.js --no-pause

        Returns parsed JSON output or a dict with an 'error' key on failure.
        """
        effective_device = device_id or self.config.device_id

        # ── RMS CLI path ──────────────────────────────────────────────────────
        if self._rms_path:
            cmd = [self._rms_path, "run", "--package", package, "--module", module]
            if effective_device:
                cmd += ["--device", effective_device]
            return self._run_cmd_json(cmd, timeout=timeout)

        # ── Frida + script fallback ───────────────────────────────────────────
        if self._frida and self._scripts_dir:
            script_path = self._scripts_dir / f"{module}.js"
            if not script_path.exists():
                return {"error": f"Script {script_path} not found"}

            cmd = [
                self._frida, "-U", "-f", package,
                "-l", str(script_path),
                "--no-pause", "--runtime=v8",
            ]
            if effective_device:
                cmd = [self._frida, "-D", effective_device, "-f", package,
                       "-l", str(script_path), "--no-pause", "--runtime=v8"]
            return self._run_cmd_json(cmd, timeout=timeout)

        return {"error": "RMS and frida are both unavailable"}

    def _run_cmd_json(self, cmd: List[str], timeout: int = 60) -> dict:
        """Run *cmd* and parse stdout as JSON. Falls back to raw text dict."""
        logger.debug("RMS command: %s", " ".join(str(c) for c in cmd))
        try:
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=timeout,
            )
            stdout = result.stdout.strip()
            if not stdout:
                return {"raw": result.stderr.strip(), "returncode": result.returncode}

            # Try to extract JSON from stdout
            for line in stdout.splitlines():
                line = line.strip()
                if line.startswith("{") or line.startswith("["):
                    try:
                        return json.loads(line)
                    except json.JSONDecodeError:
                        continue

            # Try the whole output as JSON
            try:
                return json.loads(stdout)
            except json.JSONDecodeError:
                return {"raw": stdout, "stderr": result.stderr.strip()}

        except subprocess.TimeoutExpired:
            return {"error": f"RMS module timed out after {timeout}s"}
        except FileNotFoundError:
            return {"error": "RMS binary not found at runtime"}
        except Exception as exc:
            return {"error": str(exc)}

    # ------------------------------------------------------------------ crypto

    def intercept_crypto(self, package: str, device_id: str = "") -> List[UnifiedFinding]:
        """
        Monitor cryptographic operations:
          - Detect weak algorithms (DES, RC4, MD5, SHA1, ECB mode)
          - Flag short key sizes
          - Detect IV reuse across calls
        """
        findings: List[UnifiedFinding] = []

        raw = self.run_module(package, "crypto", device_id=device_id)
        if "error" in raw:
            logger.info("crypto module: %s", raw["error"])
            return findings

        operations = raw if isinstance(raw, list) else raw.get("operations", raw.get("events", []))
        if isinstance(operations, dict):
            operations = [operations]

        _WEAK_ALGOS = {
            "DES", "RC4", "RC2", "3DES", "MD5", "SHA1", "ECB", "ARCFOUR", "BLOWFISH"
        }
        seen_ivs: Dict[str, int] = {}

        for op in operations:
            if not isinstance(op, dict):
                continue

            algo = (
                op.get("algorithm") or op.get("algo") or op.get("cipher") or ""
            ).upper()
            key_size = int(op.get("keySize") or op.get("key_size") or 0)
            iv = op.get("iv") or op.get("IV") or ""

            # Weak algorithm check
            for weak in _WEAK_ALGOS:
                if weak in algo:
                    findings.append(UnifiedFinding(
                        target=package,
                        vulnerability=f"Weak Cryptographic Algorithm: {algo}",
                        attack_type="weak_crypto",
                        tool=_TOOL,
                        severity="medium",
                        evidence=f"Algorithm: {algo} | Op: {op.get('operation', '?')}",
                        remediation=(
                            f"Replace {algo} with AES-256-GCM or ChaCha20-Poly1305. "
                            "Use secure random IVs for each operation."
                        ),
                        cvss=5.9,
                    ))
                    break

            # Short key size
            if key_size and key_size < 128 and "RSA" not in algo:
                findings.append(UnifiedFinding(
                    target=package,
                    vulnerability=f"Insufficient Key Size: {key_size} bits for {algo}",
                    attack_type="weak_key_size",
                    tool=_TOOL,
                    severity="medium",
                    evidence=f"Algorithm: {algo} | KeySize: {key_size}",
                    remediation="Use at least 256-bit symmetric keys and 2048-bit RSA keys.",
                    cvss=5.3,
                ))

            # IV reuse detection
            if iv:
                if iv in seen_ivs:
                    findings.append(UnifiedFinding(
                        target=package,
                        vulnerability=f"Cryptographic IV Reuse Detected for {algo}",
                        attack_type="iv_reuse",
                        tool=_TOOL,
                        severity="high",
                        evidence=f"IV reused at least {seen_ivs[iv] + 1} times | algo: {algo}",
                        remediation=(
                            "Generate a fresh random IV for every encryption operation. "
                            "Use AEAD modes (GCM, CCM) which handle IVs safely."
                        ),
                        cvss=7.4,
                    ))
                seen_ivs[iv] = seen_ivs.get(iv, 0) + 1

        return self._deduplicate(findings)

    # ------------------------------------------------------------------ network

    def intercept_network(self, package: str, device_id: str = "") -> List[UnifiedFinding]:
        """
        Monitor network calls:
          - HTTP (cleartext) endpoints
          - Auth headers sent over HTTP
          - Sensitive query parameters
        """
        findings: List[UnifiedFinding] = []

        raw = self.run_module(package, "network", device_id=device_id)
        if "error" in raw:
            logger.info("network module: %s", raw["error"])
            return findings

        requests = raw if isinstance(raw, list) else raw.get("requests", raw.get("events", []))
        if isinstance(requests, dict):
            requests = [requests]

        _AUTH_HEADER_RE = re.compile(r"^(Authorization|X-Auth-Token|X-API-Key)$", re.IGNORECASE)
        _SENSITIVE_PARAM_RE = re.compile(
            r"(password|secret|token|api[_-]?key|auth)", re.IGNORECASE
        )

        seen: set = set()

        for req in requests:
            if not isinstance(req, dict):
                continue

            url = req.get("url") or req.get("uri") or ""
            method = req.get("method") or req.get("type") or "?"
            headers = req.get("headers") or {}
            if isinstance(headers, list):
                headers = {h.split(":")[0]: h.split(":", 1)[-1] for h in headers if ":" in h}

            is_http = url.startswith("http://")

            # Cleartext HTTP
            if is_http and url not in seen:
                seen.add(url)
                findings.append(UnifiedFinding(
                    target=package,
                    vulnerability=f"Cleartext HTTP Network Request: {url[:80]}",
                    attack_type="cleartext_network",
                    tool=_TOOL,
                    severity="medium",
                    evidence=f"{method} {url[:100]}",
                    remediation=(
                        "Migrate all endpoints to HTTPS. "
                        "Enable android:cleartextTrafficPermitted=\"false\"."
                    ),
                    cvss=4.8,
                ))

            # Auth header over HTTP
            if is_http:
                for header_name, header_val in headers.items():
                    if _AUTH_HEADER_RE.match(str(header_name)):
                        key = (url[:80], str(header_name))
                        if key not in seen:
                            seen.add(key)
                            findings.append(UnifiedFinding(
                                target=package,
                                vulnerability=(
                                    f"Authentication Header '{header_name}' Sent Over HTTP"
                                ),
                                attack_type="auth_header_over_http",
                                tool=_TOOL,
                                severity="high",
                                evidence=f"URL: {url[:80]} | Header: {header_name}",
                                remediation="Never send authentication headers over HTTP.",
                                cvss=7.4,
                            ))

            # Sensitive parameters in URL
            from urllib.parse import urlparse, parse_qs
            try:
                parsed = urlparse(url)
                params = parse_qs(parsed.query)
                for param_name in params:
                    if _SENSITIVE_PARAM_RE.search(param_name):
                        key = (param_name, url[:80])
                        if key not in seen:
                            seen.add(key)
                            findings.append(UnifiedFinding(
                                target=package,
                                vulnerability=(
                                    f"Sensitive Parameter '{param_name}' in URL Query String"
                                ),
                                attack_type="sensitive_param_in_url",
                                tool=_TOOL,
                                severity="medium" if not is_http else "high",
                                evidence=f"Param: {param_name} in {url[:80]}",
                                remediation=(
                                    "Move sensitive parameters to the POST body or "
                                    "Authorization header."
                                ),
                                cvss=5.3,
                            ))
            except Exception:
                pass

        return self._deduplicate(findings)

    # ------------------------------------------------------------------ storage

    def intercept_storage(self, package: str, device_id: str = "") -> List[UnifiedFinding]:
        """
        Monitor file I/O operations:
          - Sensitive data written to world-readable locations
          - Cleartext writes to external storage
          - Secrets written to SharedPreferences without encryption
        """
        findings: List[UnifiedFinding] = []

        raw = self.run_module(package, "storage", device_id=device_id)
        if "error" in raw:
            logger.info("storage module: %s", raw["error"])
            return findings

        operations = raw if isinstance(raw, list) else raw.get("operations", raw.get("events", []))
        if isinstance(operations, dict):
            operations = [operations]

        _INSECURE_PATHS = (
            "/sdcard/",
            "/storage/emulated/0/",
            "/mnt/sdcard/",
            "/external_storage/",
            "/storage/",
        )
        _SENSITIVE_DATA_RE = re.compile(
            r"(password|passwd|token|secret|key|credential|ssn|credit)", re.IGNORECASE
        )
        seen: set = set()

        for op in operations:
            if not isinstance(op, dict):
                continue

            file_path = op.get("path") or op.get("file") or op.get("filename") or ""
            data = str(op.get("data") or op.get("content") or op.get("value") or "")
            operation_type = op.get("operation") or op.get("type") or "write"

            # External/world-readable path
            for insecure_prefix in _INSECURE_PATHS:
                if file_path.startswith(insecure_prefix):
                    key = ("insecure_storage_path", file_path)
                    if key not in seen:
                        seen.add(key)
                        findings.append(UnifiedFinding(
                            target=package,
                            vulnerability=f"Data Written to Insecure External Storage: {file_path}",
                            attack_type="insecure_external_storage",
                            tool=_TOOL,
                            severity="high",
                            evidence=f"Path: {file_path} | Op: {operation_type}",
                            remediation=(
                                "Store sensitive files in the app's internal storage "
                                "(getFilesDir() or getDataDir()). "
                                "Use EncryptedFile for sensitive data."
                            ),
                            cvss=7.1,
                        ))
                    break

            # Sensitive data in write content
            if "write" in str(operation_type).lower() and _SENSITIVE_DATA_RE.search(data):
                key = ("sensitive_cleartext_write", file_path, data[:30])
                if key not in seen:
                    seen.add(key)
                    findings.append(UnifiedFinding(
                        target=package,
                        vulnerability=f"Sensitive Data Written in Cleartext to {file_path or 'file'}",
                        attack_type="cleartext_sensitive_write",
                        tool=_TOOL,
                        severity="medium",
                        evidence=f"Path: {file_path} | Data snippet: {data[:80]}",
                        remediation=(
                            "Encrypt sensitive data before writing to disk. "
                            "Use Android Keystore + AES-GCM for file encryption."
                        ),
                        cvss=5.5,
                    ))

        return self._deduplicate(findings)

    # ------------------------------------------------------------------ intents

    def intercept_intents(self, package: str, device_id: str = "") -> List[UnifiedFinding]:
        """
        Monitor Android intents:
          - Implicit intents that may be intercepted by malicious apps
          - Intents carrying sensitive extras
          - Pending intents without immutability flag
        """
        findings: List[UnifiedFinding] = []

        raw = self.run_module(package, "intents", device_id=device_id)
        if "error" in raw:
            logger.info("intents module: %s", raw["error"])
            return findings

        intents = raw if isinstance(raw, list) else raw.get("intents", raw.get("events", []))
        if isinstance(intents, dict):
            intents = [intents]

        _SENSITIVE_EXTRA_RE = re.compile(
            r"(password|token|secret|key|auth|credential|ssn)", re.IGNORECASE
        )
        seen: set = set()

        for intent in intents:
            if not isinstance(intent, dict):
                continue

            action = intent.get("action") or ""
            component = intent.get("component") or intent.get("class") or ""
            extras = intent.get("extras") or intent.get("data") or {}
            intent_type = intent.get("type") or intent.get("kind") or ""
            is_implicit = not component and bool(action)
            is_pending = "pending" in str(intent_type).lower()

            # Implicit intent that can be intercepted
            if is_implicit and action:
                key = ("implicit_intent", action)
                if key not in seen:
                    seen.add(key)
                    findings.append(UnifiedFinding(
                        target=package,
                        vulnerability=f"Implicit Intent May Be Intercepted: {action}",
                        attack_type="implicit_intent_interception",
                        tool=_TOOL,
                        severity="medium",
                        evidence=f"Action: {action} | Extras keys: {list(extras.keys())[:5]}",
                        remediation=(
                            "Use explicit intents (set component explicitly) to prevent "
                            "intent hijacking. If implicit intents are required, "
                            "validate the receiving app's signature."
                        ),
                        cvss=5.4,
                    ))

            # Sensitive data in intent extras
            if isinstance(extras, dict):
                for extra_key in extras:
                    if _SENSITIVE_EXTRA_RE.search(str(extra_key)):
                        key = ("sensitive_intent_extra", action, str(extra_key))
                        if key not in seen:
                            seen.add(key)
                            findings.append(UnifiedFinding(
                                target=package,
                                vulnerability=(
                                    f"Sensitive Data in Intent Extra: '{extra_key}'"
                                ),
                                attack_type="sensitive_intent_extra",
                                tool=_TOOL,
                                severity="medium",
                                evidence=f"Action: {action} | Key: {extra_key}",
                                remediation=(
                                    "Avoid passing sensitive data via intent extras. "
                                    "Use local IPC mechanisms (Binder, ContentProvider) "
                                    "with proper access controls."
                                ),
                                cvss=4.3,
                            ))

            # Mutable pending intent
            if is_pending:
                key = ("mutable_pending_intent", action, component)
                if key not in seen:
                    seen.add(key)
                    flags = intent.get("flags") or 0
                    immutable = bool(int(flags) & 0x04000000)  # FLAG_IMMUTABLE
                    if not immutable:
                        findings.append(UnifiedFinding(
                            target=package,
                            vulnerability=(
                                "Mutable PendingIntent Without FLAG_IMMUTABLE"
                            ),
                            attack_type="mutable_pending_intent",
                            tool=_TOOL,
                            severity="medium",
                            evidence=f"Action: {action} | Flags: {flags}",
                            remediation=(
                                "Set FLAG_IMMUTABLE on all PendingIntents "
                                "(required on Android 12+). "
                                "Only use FLAG_MUTABLE when the system must fill in extras."
                            ),
                            cvss=5.4,
                        ))

        return self._deduplicate(findings)

    # ------------------------------------------------------------------ full analysis

    def run_full_analysis(self, package: str, device_id: str = "") -> List[UnifiedFinding]:
        """
        Run all intercept modules and aggregate findings.

        Executes: crypto → network → storage → intents
        Deduplicates across all modules before returning.
        """
        if not self._rms_path and not self._frida:
            return [
                UnifiedFinding(
                    target=package,
                    vulnerability="RMS and Frida unavailable — runtime analysis skipped",
                    attack_type="tool_missing",
                    tool=_TOOL,
                    severity="info",
                    remediation=(
                        "Install RMS (npm install -g runtime-mobile-security) and/or "
                        "frida-tools (pip install frida-tools) for runtime analysis."
                    ),
                )
            ]

        all_findings: List[UnifiedFinding] = []

        intercept_fns = [
            ("crypto",   self.intercept_crypto),
            ("network",  self.intercept_network),
            ("storage",  self.intercept_storage),
            ("intents",  self.intercept_intents),
        ]

        for module_name, fn in intercept_fns:
            try:
                logger.info("RMS: running '%s' module on %s", module_name, package)
                results = fn(package, device_id=device_id)
                all_findings.extend(results)
            except Exception as exc:
                logger.warning("RMS module '%s' failed: %s", module_name, exc)

        deduped = self._deduplicate(all_findings)
        logger.info("run_full_analysis(%s): %d unique findings", package, len(deduped))
        return deduped

    # ------------------------------------------------------------------ output parsing

    def _parse_rms_output(self, raw: str, module: str) -> List[UnifiedFinding]:
        """
        Normalise raw RMS JSON output into UnifiedFinding objects.

        Handles both array and dict-with-events shapes.
        Unknown fields are surfaced via evidence.
        """
        findings: List[UnifiedFinding] = []

        if not raw or not raw.strip():
            return findings

        try:
            data = json.loads(raw)
        except json.JSONDecodeError:
            # Try to extract JSON lines
            for line in raw.splitlines():
                line = line.strip()
                if line.startswith(("{", "[")):
                    try:
                        data = json.loads(line)
                        break
                    except json.JSONDecodeError:
                        continue
            else:
                logger.debug("_parse_rms_output: could not parse JSON from %s output", module)
                return findings

        events: List[Any] = data if isinstance(data, list) else data.get("events", [data])

        _SEVERITY_MAP = {
            "critical": "critical",
            "high": "high",
            "warning": "medium",
            "warn": "medium",
            "medium": "medium",
            "low": "low",
            "info": "info",
        }

        for event in events:
            if not isinstance(event, dict):
                continue

            sev_raw = str(
                event.get("severity") or event.get("level") or event.get("risk") or "info"
            ).lower()
            severity = _SEVERITY_MAP.get(sev_raw, "info")

            vuln = (
                event.get("vulnerability")
                or event.get("title")
                or event.get("name")
                or event.get("type")
                or f"RMS {module} finding"
            )
            attack_type = (
                event.get("attack_type")
                or event.get("category")
                or module
            )
            target = event.get("target") or event.get("package") or event.get("app") or ""
            evidence = str(
                event.get("evidence") or event.get("detail") or event.get("value") or event
            )[:300]
            remediation = (
                event.get("remediation")
                or event.get("recommendation")
                or event.get("fix")
                or ""
            )

            findings.append(UnifiedFinding(
                target=str(target),
                vulnerability=str(vuln),
                attack_type=str(attack_type),
                tool=_TOOL,
                severity=severity,
                evidence=evidence,
                remediation=str(remediation),
            ))

        return self._deduplicate(findings)

    # ------------------------------------------------------------------ helpers

    @staticmethod
    def _deduplicate(findings: List[UnifiedFinding]) -> List[UnifiedFinding]:
        """Remove duplicate findings by (attack_type, vulnerability, target)."""
        seen: set = set()
        result: List[UnifiedFinding] = []
        for f in findings:
            key = (f.attack_type, f.vulnerability[:80], f.target)
            if key not in seen:
                seen.add(key)
                result.append(f)
        return result


# Module-level singleton
rms_wrapper = RMSWrapper()
