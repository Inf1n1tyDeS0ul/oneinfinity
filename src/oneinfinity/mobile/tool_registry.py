"""
Mobile Tool Registry
====================
Central registry for all mobile security testing tools.
Handles tool discovery, version detection, capability registration,
execution, and output normalization.

Usage::

    from oneinfinity.mobile_tool_registry import tool_registry, UnifiedFinding, ToolStatus

    # Check what's available
    print(tool_registry.tool_summary())

    # Execute a registered tool
    rc, stdout, stderr = tool_registry.execute("frida", ["--version"])

    # Normalise raw findings from any tool into UnifiedFinding objects
    findings = tool_registry.normalize_findings(raw_list, "trufflehog")
"""

from __future__ import annotations

import logging
import os
import re
import shutil
import subprocess
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from pathlib import Path
from typing import Any, ClassVar, Dict, List, Optional, Tuple

log = logging.getLogger("oneinfinity.mobile.registry")

# ──────────────────────────────────────────────────────────────────────────────
#  Enumerations
# ──────────────────────────────────────────────────────────────────────────────

class ToolStatus(Enum):
    """Lifecycle status of a registered tool binary."""
    AVAILABLE = "available"    # Binary found and responsive
    MISSING   = "missing"      # Binary not found on PATH or known locations
    ERROR     = "error"        # Binary found but crashed / non-functional
    TIMEOUT   = "timeout"      # Version check timed out


class ToolCapability(Enum):
    """Functional category that a tool satisfies."""
    STATIC    = "static"       # Static analysis (decompile, code scan)
    DYNAMIC   = "dynamic"      # Dynamic analysis (runtime hooking, tracing)
    SECRET    = "secret"       # Secret / credential detection
    NETWORK   = "network"      # Network traffic analysis / interception
    COMPONENT = "component"    # Android component analysis (IPC, activities)
    FUZZING   = "fuzzing"      # Fuzzing / active probing


# ──────────────────────────────────────────────────────────────────────────────
#  Core data classes
# ──────────────────────────────────────────────────────────────────────────────

@dataclass
class MobileTool:
    """Metadata and runtime state for a single registered mobile security tool."""

    name: str
    binary_names: List[str]
    capabilities: List[ToolCapability]
    description: str
    config: Dict[str, Any] = field(default_factory=dict)

    # Populated automatically by MobileToolRegistry.check_all()
    binary_path: Optional[str] = None
    version: str = "unknown"
    status: ToolStatus = ToolStatus.MISSING

    def is_available(self) -> bool:
        """True when the tool was found and is ready to execute."""
        return self.status == ToolStatus.AVAILABLE

    def capability_names(self) -> List[str]:
        return [c.value for c in self.capabilities]

    def __repr__(self) -> str:
        return (
            f"<MobileTool name={self.name!r} status={self.status.value} "
            f"version={self.version!r}>"
        )


@dataclass
class UnifiedFinding:
    """
    Normalised vulnerability finding produced by any mobile security tool.

    All wrapper modules convert their raw output into ``UnifiedFinding`` objects
    so that downstream consumers (report generator, deduplicator, attack graph)
    work with a single schema regardless of which tool produced the data.

    Field conventions
    -----------------
    id          : Short UUID prefix (8 hex chars) auto-generated on creation.
    target      : Package name, file path, or domain under test.
    vulnerability: Short human-readable name of the finding.
    attack_type : Category / CWE-aligned label (e.g. "insecure_storage").
    tool        : Canonical name of the tool that generated this finding.
    severity    : One of: critical | high | medium | low | info
    evidence    : Raw match/snippet supporting the finding.
    file_path   : Source file where the issue was found (if applicable).
    line_number : Line number within file_path (0 = unknown).
    payload     : Attack payload or matched secret value.
    confidence  : Float 0.0–1.0; how confident the tool is in this result.
    cvss        : CVSS base score 0.0–10.0.
    remediation : Actionable fix recommendation.
    tags        : List of labels; the emitting tool name is always appended.
    timestamp   : ISO-8601 UTC timestamp of creation.
    """

    target: str
    vulnerability: str
    attack_type: str
    tool: str
    severity: str                      # canonical after __post_init__
    evidence: str = ""
    file_path: str = ""
    line_number: int = 0
    payload: str = ""
    confidence: float = 0.5
    cvss: float = 0.0
    remediation: str = ""
    tags: List[str] = field(default_factory=list)
    timestamp: str = field(
        default_factory=lambda: datetime.now(timezone.utc).isoformat()
    )
    id: str = field(default_factory=lambda: str(uuid.uuid4())[:8])

    # ── Severity helpers ──────────────────────────────────────────────────────

    # ClassVar annotations are not treated as dataclass fields.
    # Map common raw severity strings → canonical five-level set.
    _SEV_MAP: ClassVar[Dict[str, str]] = {
        "critical": "critical", "crit": "critical",
        "high":     "high",     "error": "high",
        "medium":   "medium",   "med": "medium",
        "moderate": "medium",   "warning": "medium",
        "warn":     "medium",
        "low":      "low",
        "info":     "info",     "informational": "info",
        "note":     "info",     "notice": "info",
    }

    @staticmethod
    def normalise_severity(sev: str) -> str:
        """Map arbitrary severity strings to the canonical five-level set."""
        s = sev.strip().lower()
        return UnifiedFinding._SEV_MAP.get(s, "info")

    def __post_init__(self) -> None:
        self.severity = self.normalise_severity(self.severity)
        self.confidence = max(0.0, min(1.0, float(self.confidence)))
        self.cvss = max(0.0, min(10.0, float(self.cvss)))

    def to_dict(self) -> dict:
        return {
            "id":            self.id,
            "target":        self.target,
            "vulnerability": self.vulnerability,
            "attack_type":   self.attack_type,
            "tool":          self.tool,
            "severity":      self.severity,
            "evidence":      self.evidence,
            "file_path":     self.file_path,
            "line_number":   self.line_number,
            "payload":       self.payload,
            "confidence":    self.confidence,
            "cvss":          self.cvss,
            "remediation":   self.remediation,
            "tags":          self.tags,
            "timestamp":     self.timestamp,
        }

    @classmethod
    def from_dict(cls, d: dict) -> UnifiedFinding:
        obj = cls(
            target=d.get("target", ""),
            vulnerability=d.get("vulnerability", d.get("title", "Unknown")),
            attack_type=d.get("attack_type", d.get("category", "unknown")),
            tool=d.get("tool", ""),
            severity=d.get("severity", "info"),
            evidence=d.get("evidence", ""),
            file_path=d.get("file_path", d.get("file", "")),
            line_number=int(d.get("line_number", d.get("line", 0))),
            payload=d.get("payload", ""),
            confidence=float(d.get("confidence", 0.5)),
            cvss=float(d.get("cvss", 0.0)),
            remediation=d.get("remediation", d.get("recommendation", "")),
            tags=d.get("tags", []),
        )
        if "id" in d:
            obj.id = d["id"]
        if "timestamp" in d:
            obj.timestamp = d["timestamp"]
        return obj


# Backwards-compatible helpers for older code that used the stub schema.

def severity_rank(severity: str) -> int:
    """Return a numeric rank for sorting (higher = more severe)."""
    return {"critical": 4, "high": 3, "medium": 2, "low": 1, "info": 0}.get(
        severity.lower(), 0
    )


def sort_findings(findings: List[UnifiedFinding]) -> List[UnifiedFinding]:
    """Sort findings from most to least severe."""
    return sorted(findings, key=lambda f: severity_rank(f.severity), reverse=True)


def deduplicate_findings(findings: List[UnifiedFinding]) -> List[UnifiedFinding]:
    """Remove duplicate findings by (attack_type, vulnerability, target, file_path)."""
    seen: set = set()
    result: List[UnifiedFinding] = []
    for f in findings:
        key = (f.attack_type, f.vulnerability, f.target, f.file_path)
        if key not in seen:
            seen.add(key)
            result.append(f)
    return result


# ──────────────────────────────────────────────────────────────────────────────
#  Extra binary search directories
# ──────────────────────────────────────────────────────────────────────────────

_EXTRA_SEARCH_DIRS: List[str] = [
    str(Path.home() / ".local" / "bin"),
    str(Path.home() / "go" / "bin"),
    str(Path.home() / "tools" / "bin"),
    str(Path.home() / "bin"),
    "/usr/local/bin",
    "/opt/homebrew/bin",
    "/opt/android-studio/bin",
]


# ──────────────────────────────────────────────────────────────────────────────
#  Registry
# ──────────────────────────────────────────────────────────────────────────────

class MobileToolRegistry:
    """
    Centralised registry for mobile security testing tools.

    Lifecycle
    ---------
    1. ``__init__`` calls ``_register_defaults()`` then ``check_all()``.
    2. ``check_all()`` probes every registered tool on disk and populates
       ``binary_path``, ``version``, and ``status``.
    3. Wrappers call ``execute(name, args)`` to run tools.
    4. Raw output dicts are normalised via ``normalize_findings()``.

    Thread safety
    -------------
    ``execute()`` spawns isolated subprocesses and does not mutate registry
    state, so concurrent calls are safe after initialisation completes.
    """

    def __init__(self) -> None:
        self._tools: Dict[str, MobileTool] = {}
        self._register_defaults()
        self.check_all()

    # ── Registration ──────────────────────────────────────────────────────────

    def register_tool(
        self,
        name: str,
        binary_names: List[str],
        capabilities: List[ToolCapability],
        description: str,
        config: Optional[Dict[str, Any]] = None,
    ) -> None:
        """
        Register a tool definition.

        Parameters
        ----------
        name:
            Canonical short identifier used for lookup (e.g. ``"frida"``).
        binary_names:
            Ordered list of executable names / paths to probe.
        capabilities:
            Which ToolCapability values this tool satisfies.
        description:
            One-line human-readable description.
        config:
            Optional tool-specific configuration (API URLs, flags, etc.).
        """
        self._tools[name] = MobileTool(
            name=name,
            binary_names=binary_names,
            capabilities=capabilities,
            description=description,
            config=config or {},
        )
        log.debug("Registered tool: %s  binaries=%s", name, binary_names)

    def _register_defaults(self) -> None:
        """Register all built-in mobile security tools."""
        C = ToolCapability

        self.register_tool(
            "mobsf",
            binary_names=["mobsf"],
            capabilities=[C.STATIC, C.DYNAMIC],
            description=(
                "Mobile Security Framework — comprehensive static + dynamic "
                "analysis server with REST API"
            ),
            config={"api_url": f"http://localhost:{os.environ.get('MOBSF_PORT', '47297')}"},
        )
        self.register_tool(
            "frida",
            binary_names=["frida"],
            capabilities=[C.DYNAMIC],
            description=(
                "Frida — dynamic instrumentation toolkit; hooks Java, native, "
                "and ObjC methods at runtime"
            ),
        )
        self.register_tool(
            "frida-ps",
            binary_names=["frida-ps"],
            capabilities=[C.DYNAMIC],
            description="Frida process listing utility — enumerates running apps on device",
        )
        self.register_tool(
            "apktool",
            binary_names=["apktool", "apktool.sh"],
            capabilities=[C.STATIC],
            description=(
                "APKTool — reverse-engineer APKs to smali bytecode + resources; "
                "also supports recompilation"
            ),
        )
        self.register_tool(
            "jadx",
            binary_names=["jadx", "jadx.bat"],
            capabilities=[C.STATIC],
            description=(
                "JADX — decompile DEX/APK to readable Java source; "
                "supports Kotlin decompilation and resource decoding"
            ),
        )
        self.register_tool(
            "objection",
            binary_names=["objection"],
            capabilities=[C.DYNAMIC],
            description=(
                "Objection — runtime mobile exploration toolkit built on Frida; "
                "SSL pinning bypass, root bypass, data dumps"
            ),
        )
        self.register_tool(
            "drozer",
            binary_names=["drozer"],
            capabilities=[C.COMPONENT],
            description=(
                "Drozer — Android attack surface assessment; "
                "IPC fuzzing, exported component enumeration, content provider attacks"
            ),
        )
        self.register_tool(
            "adb",
            binary_names=["adb"],
            capabilities=[C.DYNAMIC],
            description=(
                "Android Debug Bridge — device communication, shell access, "
                "logcat, file push/pull"
            ),
        )
        self.register_tool(
            "strings",
            binary_names=["strings"],
            capabilities=[C.STATIC],
            description="GNU strings — extract printable strings from compiled binaries",
        )
        self.register_tool(
            "trufflehog",
            binary_names=[
                "trufflehog",
                str(Path.home() / ".local" / "bin" / "trufflehog"),
            ],
            capabilities=[C.SECRET],
            description=(
                "TruffleHog — entropy + pattern-based secret scanner; "
                "detects 700+ credential types"
            ),
        )
        self.register_tool(
            "gitleaks",
            binary_names=["gitleaks"],
            capabilities=[C.SECRET],
            description=(
                "Gitleaks — SAST secret scanner; rule-based detection of "
                "hardcoded credentials in source trees"
            ),
        )
        self.register_tool(
            "burp",
            binary_names=["burp", "burpsuite", "BurpSuiteCommunity", "BurpSuitePro"],
            capabilities=[C.NETWORK],
            description=(
                "Burp Suite — HTTP(S) intercepting proxy for capturing and "
                "analysing mobile app network traffic"
            ),
        )

    # ── Discovery ─────────────────────────────────────────────────────────────

    def _find_binary(self, names: List[str]) -> Optional[str]:
        """
        Locate an executable by trying each name in *names*.

        Search order:
        1. Absolute path provided directly in *names* (checked for execute bit).
        2. ``shutil.which`` — honours $PATH.
        3. Directories in ``_EXTRA_SEARCH_DIRS`` (``~/.local/bin``, ``~/go/bin``, …).
        """
        for name in names:
            if not name:
                continue

            # Absolute path — check it directly
            if os.path.isabs(name):
                if os.path.isfile(name) and os.access(name, os.X_OK):
                    log.debug("Found binary at explicit path: %s", name)
                    return name
                continue

            # $PATH lookup
            found = shutil.which(name)
            if found:
                log.debug("Found '%s' via PATH: %s", name, found)
                return found

            # Extra directories
            for directory in _EXTRA_SEARCH_DIRS:
                candidate = os.path.join(directory, name)
                if os.path.isfile(candidate) and os.access(candidate, os.X_OK):
                    log.debug("Found '%s' in extra dir: %s", name, candidate)
                    return candidate

        return None

    def _detect_version(self, binary: str) -> str:
        """
        Query the tool for its version string.

        Tries ``--version``, then ``version`` (Go/Cobra CLIs), then ``-version``.
        Returns the first non-empty output line (≤ 80 chars) or a sentinel string.

        Sentinels
        ---------
        ``"timeout"``  — subprocess timed out.
        ``"unknown"``  — binary ran but produced no recognisable version output.
        """
        for flag in ("--version", "version", "-version", "-v"):
            try:
                result = subprocess.run(
                    [binary, flag],
                    capture_output=True,
                    text=True,
                    timeout=10,
                )
                output = (result.stdout or result.stderr or "").strip()
                if output:
                    for line in output.splitlines():
                        line = line.strip()
                        if line:
                            return line[:80]
            except subprocess.TimeoutExpired:
                log.debug("Version check timed out: %s %s", binary, flag)
                return "timeout"
            except FileNotFoundError:
                break   # Binary vanished between find and exec
            except OSError as exc:
                log.debug("Version check OS error for %s: %s", binary, exc)
                break
            except Exception as exc:   # noqa: BLE001
                log.debug("Version check error for %s: %s", binary, exc)

        return "unknown"

    def check_all(self) -> None:
        """
        Probe every registered tool on disk.

        Sets ``binary_path``, ``version``, and ``status`` for each entry.
        Call this again after installing new tools to refresh the registry.
        """
        available = 0
        missing = 0
        for tool in self._tools.values():
            path = self._find_binary(tool.binary_names)
            if path is None:
                tool.status = ToolStatus.MISSING
                tool.binary_path = None
                tool.version = "unknown"
                missing += 1
                log.debug("Tool not found: %s", tool.name)
                continue

            tool.binary_path = path
            version = self._detect_version(path)

            if version == "timeout":
                tool.status = ToolStatus.TIMEOUT
                tool.version = "timeout"
                log.warning(
                    "Tool '%s' binary found but version check timed out: %s",
                    tool.name, path,
                )
            else:
                # "unknown" means binary responded (exit code irrelevant), mark AVAILABLE
                tool.status = ToolStatus.AVAILABLE
                tool.version = version
                available += 1
                log.info(
                    "Tool '%s' available  version=%r  path=%s",
                    tool.name, version, path,
                )

        log.info(
            "Tool check complete: %d/%d available, %d missing",
            available, len(self._tools), missing,
        )

    # ── Accessors ─────────────────────────────────────────────────────────────

    def get_available_tools(self) -> List[MobileTool]:
        """Return all tools whose status is AVAILABLE."""
        return [t for t in self._tools.values() if t.status == ToolStatus.AVAILABLE]

    def get_tool(self, name: str) -> Optional[MobileTool]:
        """Return the ``MobileTool`` entry for *name*, or ``None`` if not registered."""
        return self._tools.get(name)

    def get_tools_by_capability(self, capability: ToolCapability) -> List[MobileTool]:
        """Return available tools that support *capability*."""
        return [
            t for t in self._tools.values()
            if t.status == ToolStatus.AVAILABLE and capability in t.capabilities
        ]

    # ── Execution ─────────────────────────────────────────────────────────────

    def execute(
        self,
        name: str,
        args: List[str],
        timeout: int = 120,
        cwd: Optional[str] = None,
        env: Optional[Dict[str, str]] = None,
    ) -> Tuple[int, str, str]:
        """
        Execute a registered tool with the given arguments.

        Parameters
        ----------
        name:
            Canonical tool name as passed to ``register_tool``.
        args:
            CLI arguments (not including the binary itself).
        timeout:
            Maximum execution time in seconds (default 120).
        cwd:
            Working directory for the subprocess.
        env:
            Optional environment variable overrides merged into the current env.

        Returns
        -------
        ``(returncode, stdout, stderr)``

        Special return codes:
        * ``-1`` — tool not registered, not available, or unexpected exception.
        * ``-2`` — subprocess timed out.

        Never raises; all exceptions are caught and surfaced via the return value.
        """
        tool = self._tools.get(name)
        if tool is None:
            msg = f"Tool '{name}' is not registered in the mobile tool registry."
            log.error(msg)
            return -1, "", msg

        if not tool.is_available() or not tool.binary_path:
            msg = (
                f"Tool '{name}' is not available "
                f"(status={tool.status.value}, path={tool.binary_path!r})."
            )
            log.warning(msg)
            return -1, "", msg

        cmd = [tool.binary_path] + [str(a) for a in args]
        log.debug("Executing: %s", " ".join(cmd))

        try:
            proc_env = os.environ.copy()
            if env:
                proc_env.update(env)

            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=timeout,
                cwd=cwd,
                env=proc_env,
            )
            return result.returncode, result.stdout, result.stderr

        except subprocess.TimeoutExpired:
            msg = f"Tool '{name}' timed out after {timeout}s."
            log.warning(msg)
            return -2, "", msg

        except FileNotFoundError:
            tool.status = ToolStatus.MISSING   # binary disappeared
            msg = f"Tool '{name}' binary not found at runtime: {tool.binary_path}"
            log.error(msg)
            return -1, "", msg

        except OSError as exc:
            tool.status = ToolStatus.ERROR
            msg = f"Tool '{name}' OS error: {exc}"
            log.error(msg)
            return -1, "", msg

        except Exception as exc:  # noqa: BLE001
            tool.status = ToolStatus.ERROR
            msg = f"Tool '{name}' unexpected execution error: {exc}"
            log.exception(msg)
            return -1, "", msg

    # ── Output normalisation ──────────────────────────────────────────────────

    # Default CVSS base scores when the tool doesn't emit one.
    _DEFAULT_CVSS: Dict[str, float] = {
        "critical": 9.5,
        "high":     7.5,
        "medium":   5.0,
        "low":      3.0,
        "info":     0.0,
    }

    # Default confidence by severity (used when tool doesn't emit confidence).
    _DEFAULT_CONFIDENCE: Dict[str, float] = {
        "critical": 0.95,
        "high":     0.80,
        "medium":   0.65,
        "low":      0.50,
        "info":     0.30,
    }

    def normalize_findings(
        self,
        findings: List[dict],
        tool_name: str,
    ) -> List[UnifiedFinding]:
        """
        Convert raw tool-output dicts into ``UnifiedFinding`` objects.

        Handles the diverse field-name conventions used by MobSF, TruffleHog,
        Gitleaks, Nuclei, custom Frida scripts, and other mobile security tools.
        Unknown or missing fields fall back to safe defaults.

        Parameters
        ----------
        findings:
            List of raw output dicts.  Non-dict items are silently skipped.
        tool_name:
            Canonical name of the emitting tool; appended to ``tags``.

        Returns
        -------
        List of normalised ``UnifiedFinding`` instances (one per input dict).
        """
        results: List[UnifiedFinding] = []

        for raw in findings:
            if not isinstance(raw, dict):
                log.debug("normalize_findings: skipping non-dict: %r", type(raw))
                continue

            # ── severity ──────────────────────────────────────────────────────
            sev_raw = (
                raw.get("severity")
                or raw.get("Severity")
                or raw.get("level")
                or raw.get("risk")
                or raw.get("Risk")
                or "info"
            )
            severity = UnifiedFinding.normalise_severity(str(sev_raw))

            # ── vulnerability name ─────────────────────────────────────────────
            vuln = (
                raw.get("vulnerability")
                or raw.get("vuln_type")
                or raw.get("title")
                or raw.get("Title")
                or raw.get("name")
                or raw.get("Name")
                or raw.get("description")
                or raw.get("Description")
                or raw.get("type")
                or "Unknown Vulnerability"
            )

            # ── attack type / category ─────────────────────────────────────────
            attack_type = (
                raw.get("attack_type")
                or raw.get("category")
                or raw.get("Category")
                or raw.get("finding_type")
                or raw.get("vuln_type")
                or str(vuln)
            )

            # ── target ────────────────────────────────────────────────────────
            target = (
                raw.get("target")
                or raw.get("package")
                or raw.get("Package")
                or raw.get("app")
                or raw.get("apk")
                or raw.get("file")
                or ""
            )

            # ── evidence ──────────────────────────────────────────────────────
            evidence = (
                raw.get("evidence")
                or raw.get("match")
                or raw.get("Match")
                or raw.get("snippet")
                or raw.get("value")
                or raw.get("raw")
                or raw.get("detail")
                or ""
            )

            # ── location ──────────────────────────────────────────────────────
            file_path = (
                raw.get("file_path")
                or raw.get("file")
                or raw.get("File")
                or raw.get("filename")
                or raw.get("path")
                or raw.get("location")
                or ""
            )
            try:
                line_number = int(
                    raw.get("line_number")
                    or raw.get("line")
                    or raw.get("Line")
                    or raw.get("lineNumber")
                    or 0
                )
            except (ValueError, TypeError):
                line_number = 0

            # ── payload / secret value ─────────────────────────────────────────
            payload = (
                raw.get("payload")
                or raw.get("Payload")
                or raw.get("secret")
                or raw.get("value")
                or ""
            )

            # ── confidence ────────────────────────────────────────────────────
            raw_conf = raw.get("confidence") or raw.get("Confidence")
            if raw_conf is not None:
                try:
                    confidence = float(raw_conf)
                    if confidence > 1.0:
                        confidence /= 100.0   # percentage → fraction
                except (ValueError, TypeError):
                    confidence = self._DEFAULT_CONFIDENCE.get(severity, 0.5)
            else:
                confidence = self._DEFAULT_CONFIDENCE.get(severity, 0.5)

            # ── CVSS ──────────────────────────────────────────────────────────
            raw_cvss = raw.get("cvss") or raw.get("CVSS") or raw.get("cvss_score")
            try:
                cvss = float(raw_cvss) if raw_cvss is not None else self._DEFAULT_CVSS.get(severity, 0.0)
            except (ValueError, TypeError):
                cvss = self._DEFAULT_CVSS.get(severity, 0.0)

            # ── remediation ───────────────────────────────────────────────────
            remediation = (
                raw.get("remediation")
                or raw.get("Remediation")
                or raw.get("recommendation")
                or raw.get("fix")
                or raw.get("Fix")
                or ""
            )

            # ── tags ──────────────────────────────────────────────────────────
            tags_raw = raw.get("tags") or raw.get("Tags") or []
            if isinstance(tags_raw, str):
                tags = [t.strip() for t in re.split(r"[,;]", tags_raw) if t.strip()]
            elif isinstance(tags_raw, list):
                tags = [str(t) for t in tags_raw]
            else:
                tags = []
            if tool_name not in tags:
                tags.append(tool_name)

            finding = UnifiedFinding(
                target=str(target),
                vulnerability=str(vuln),
                attack_type=str(attack_type),
                tool=tool_name,
                severity=severity,
                evidence=str(evidence)[:2000],   # guard against huge blobs
                file_path=str(file_path),
                line_number=line_number,
                payload=str(payload)[:500],
                confidence=confidence,
                cvss=cvss,
                remediation=str(remediation),
                tags=tags,
            )
            results.append(finding)

        log.debug(
            "normalize_findings: %d raw dicts → %d UnifiedFindings  tool=%r",
            len(findings), len(results), tool_name,
        )
        return results

    # ── Summary / reporting ───────────────────────────────────────────────────

    def tool_summary(self) -> Dict[str, dict]:
        """
        Return a serialisable summary of all registered tools.

        Shape::

            {
                "frida": {
                    "status": "available",
                    "version": "16.3.3",
                    "capabilities": ["dynamic"],
                    "binary_path": "/usr/local/bin/frida",
                    "description": "..."
                },
                ...
            }
        """
        return {
            name: {
                "status":       tool.status.value,
                "version":      tool.version,
                "capabilities": tool.capability_names(),
                "binary_path":  tool.binary_path or "",
                "description":  tool.description,
            }
            for name, tool in self._tools.items()
        }

    def available_count(self) -> int:
        """Return the number of AVAILABLE tools."""
        return sum(1 for t in self._tools.values() if t.status == ToolStatus.AVAILABLE)

    def missing_tools(self) -> List[str]:
        """Return names of all MISSING tools."""
        return [n for n, t in self._tools.items() if t.status == ToolStatus.MISSING]

    def __repr__(self) -> str:   # pragma: no cover
        return (
            f"<MobileToolRegistry tools={len(self._tools)} "
            f"available={self.available_count()}>"
        )


# ──────────────────────────────────────────────────────────────────────────────
#  Module-level singleton
# ──────────────────────────────────────────────────────────────────────────────

#: Global singleton.  Import as:
#:     ``from mobile_tool_registry import tool_registry, UnifiedFinding``
tool_registry: MobileToolRegistry = MobileToolRegistry()
