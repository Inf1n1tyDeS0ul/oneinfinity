"""
Mobile Secret Scanner
=====================
Scan extracted APK/IPA source code for hardcoded secrets, credentials,
API keys, tokens, and other sensitive information.

Integrates with:
  - TruffleHog (if installed)
  - Gitleaks (if installed)
  - Custom regex patterns (always available)

Returns structured findings compatible with AIVulnFinding format.
"""

from __future__ import annotations

import json
import logging
import os
import re
import subprocess
import tempfile
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Optional, Tuple

log = logging.getLogger("oneinfinity.mobile.secrets")


# ─────────────────────────────────────────────────────────────────────────────
#  Secret pattern library
# ─────────────────────────────────────────────────────────────────────────────

_SECRET_PATTERNS: List[Tuple[str, str, str, float]] = [
    # (pattern, secret_type, severity, confidence)
    (r'AIza[0-9A-Za-z_\-]{35}', "google_api_key", "high", 0.95),
    (r'AAAA[A-Za-z0-9_\-]{100,}', "firebase_cloud_messaging", "high", 0.90),
    (r'(?i)firebase.*["\']([A-Za-z0-9_\-]{40})["\']', "firebase_key", "high", 0.85),
    (r'(?:AKIA|ASIA|AROA|AIDA|ANPA|AIPA|ASPA|AGPA)[A-Z0-9]{16}', "aws_access_key", "critical", 0.98),
    (r'(?i)aws[_\-]?secret[_\-]?access[_\-]?key[\s"\'=:]+([A-Za-z0-9/+]{40})', "aws_secret", "critical", 0.95),
    (r'sk-[A-Za-z0-9]{32,}', "openai_api_key", "critical", 0.92),
    (r'sk-ant-[A-Za-z0-9_\-]{80,}', "anthropic_api_key", "critical", 0.99),
    (r'github_pat_[A-Za-z0-9_]{36,}', "github_pat", "high", 0.99),
    (r'ghp_[A-Za-z0-9]{36,}', "github_token", "high", 0.99),
    (r'ghs_[A-Za-z0-9]{36,}', "github_secret", "high", 0.99),
    (r'eyJ[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]+\.[A-Za-z0-9_\-]+', "jwt_token", "high", 0.90),
    (r'ya29\.[A-Za-z0-9_\-]{60,}', "google_oauth_token", "critical", 0.95),
    (r'(?i)(?:password|passwd|pwd)\s*[=:]\s*["\']([^"\']{6,})["\']', "hardcoded_password", "critical", 0.80),
    (r'(?i)(?:api[_\-]?key|apikey|api[_\-]?secret)\s*[=:"\s]+([A-Za-z0-9_\-]{16,})', "api_key", "high", 0.75),
    (r'-----BEGIN (?:RSA |EC |DSA )?PRIVATE KEY-----', "private_key", "critical", 0.99),
    (r'(?i)(?:secret|token)\s*=\s*["\']([A-Za-z0-9_\-]{16,})["\']', "generic_secret", "medium", 0.70),
    (r'[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}', "uuid_token", "low", 0.40),
    (r'(?i)basic\s+[A-Za-z0-9+/]{20,}={0,2}', "basic_auth", "high", 0.85),
    (r'(?i)bearer\s+[A-Za-z0-9_\-\.]{20,}', "bearer_token", "high", 0.85),
    (r'(?i)stripe[_\-]?(?:test|live|secret)[_\-]?key\s*[=:]\s*["\']?(sk_(?:test|live)_[A-Za-z0-9]{24,})', "stripe_key", "critical", 0.99),
    (r'(?i)twilio.*[Ss][Ii][Dd].*["\']([A-Za-z0-9]{34})["\']', "twilio_sid", "high", 0.85),
    (r'(?i)slack[_\-]?(?:token|webhook)[_\-]?(?:url)?\s*[=:"\s]+([A-Za-z0-9_\-\/\.]{30,})', "slack_token", "high", 0.80),
    (r'sq0csp-[A-Za-z0-9_\-]{43}', "square_oauth", "critical", 0.99),
    (r'mongodb(?:\+srv)?://[^\s"\'<>]+', "mongodb_connection_string", "critical", 0.95),
    (r'postgres(?:ql)?://[^\s"\'<>]+', "postgres_connection_string", "critical", 0.95),
    (r'mysql://[^\s"\'<>]+', "mysql_connection_string", "critical", 0.90),
    (r'redis://[^\s"\'<>]+', "redis_connection_string", "high", 0.90),
    # DEX/binary-extracted patterns
    (r'(?i)(?:api[_\-\s]?key|apikey)\s*[:=]\s*([A-Za-z0-9_\-]{8,})', "api_key_assignment", "high", 0.80),
    (r'INSERT\s+INTO\s+\w+\s+VALUES\s*\([^)]*["\']([^"\']{6,})["\']', "sql_hardcoded_data", "critical", 0.85),
    (r'SELECT\s+.*\s+FROM\s+\w+\s+WHERE\s+.*[=<>]', "sql_injection_template", "high", 0.75),
    (r'(?i)(?:password|passwd|pwd)\s*=\s*["\']([^\s"\']{4,})["\']', "hardcoded_password_sql", "critical", 0.85),
    (r'\b[0-9]{13,19}\b', "potential_card_number", "high", 0.60),
]

_COMPILED_PATTERNS = [
    (re.compile(p, re.MULTILINE), stype, sev, conf)
    for p, stype, sev, conf in _SECRET_PATTERNS
]

# File extensions to scan
_SCAN_EXTENSIONS = {
    ".java", ".kt", ".smali", ".xml", ".json", ".js", ".ts",
    ".yaml", ".yml", ".properties", ".gradle", ".plist",
    ".strings", ".swift", ".m", ".h", ".conf", ".config",
    ".env", ".txt", ".html", ".php", ".py", ".rb", ".dex",
}

# Binary extensions — extract printable strings before regex scan
_BINARY_EXTENSIONS = {".dex", ".so", ".dylib"}


def _extract_strings(data: bytes, min_len: int = 6) -> str:
    """Extract printable ASCII strings from binary data (like `strings` command)."""
    result = []
    current: List[int] = []
    for byte in data:
        if 0x20 <= byte <= 0x7E:  # printable ASCII
            current.append(byte)
        else:
            if len(current) >= min_len:
                result.append(bytes(current).decode("ascii"))
            current = []
    if len(current) >= min_len:
        result.append(bytes(current).decode("ascii"))
    return "\n".join(result)

# Files to skip
_SKIP_PATTERNS = {"node_modules", ".git", "test", "__pycache__"}


@dataclass
class SecretFinding:
    id: str                     = ""
    secret_type: str            = ""
    severity: str               = "medium"
    confidence: float           = 0.8
    file_path: str              = ""
    line_number: int            = 0
    matched_text: str           = ""
    context: str                = ""
    tool: str                   = "regex"
    timestamp: str              = field(default_factory=lambda: datetime.utcnow().isoformat())

    def to_dict(self) -> Dict:
        return {
            "id": self.id,
            "secret_type": self.secret_type,
            "severity": self.severity,
            "confidence": self.confidence,
            "file_path": self.file_path,
            "line_number": self.line_number,
            "matched_text": f"{self.matched_text[:8]}...{self.matched_text[-4:]}" if len(self.matched_text) > 12 else self.matched_text,
            "context": self.context[:200],
            "tool": self.tool,
        }

    def to_vuln_finding(self, target: str = "", app_id: str = "") -> Dict:
        """Convert to AIVulnFinding-compatible format."""
        return {
            "target": target,
            "vulnerability": f"Hardcoded Secret: {self.secret_type}",
            "attack_type": "secret_disclosure",
            "tool": f"Mobile Secret Scanner ({self.tool})",
            "severity": self.severity,
            "payload": self.matched_text[:20] + "...",
            "response": "",
            "evidence": f"Secret found in {self.file_path}:{self.line_number}\nType: {self.secret_type}\nContext: {self.context[:200]}",
            "confidence": self.confidence,
            "remediation": (
                f"Remove hardcoded {self.secret_type} from source code. "
                "Use environment variables or secure vault (Android Keystore / iOS Keychain). "
                "Rotate the exposed credential immediately."
            ),
            "cvss": 8.0 if self.severity == "critical" else 6.5 if self.severity == "high" else 4.5,
            "tags": ["mobile", "secret", "hardcoded", self.secret_type, app_id],
        }


class MobileSecretScanner:
    """
    Scan extracted mobile app source code for hardcoded secrets.
    Uses TruffleHog + Gitleaks + custom regex patterns.
    """

    def __init__(self) -> None:
        self._trufflehog = self._find_tool("trufflehog")
        self._gitleaks = self._find_tool("gitleaks")
        log.info("Secret scanner tools: trufflehog=%s gitleaks=%s",
                 self._trufflehog or "N/A", self._gitleaks or "N/A")

    def scan(self, extract_path: str, app_id: str = "") -> List[SecretFinding]:
        """
        Scan an extracted app directory for secrets.
        Returns deduplicated list of SecretFinding.
        """
        root = Path(extract_path)
        if not root.exists():
            raise FileNotFoundError(f"Extract path not found: {extract_path}")

        findings: List[SecretFinding] = []
        seen: set = set()

        # 1. Custom regex scan (always runs)
        log.info("Running regex secret scan on %s", extract_path)
        regex_findings = self._regex_scan(root)
        for f in regex_findings:
            key = f"{f.file_path}:{f.line_number}:{f.secret_type}"
            if key not in seen:
                seen.add(key)
                findings.append(f)

        # 2. TruffleHog
        if self._trufflehog:
            log.info("Running TruffleHog on %s", extract_path)
            th_findings = self._run_trufflehog(extract_path)
            for f in th_findings:
                key = f"{f.file_path}:{f.line_number}:{f.secret_type}"
                if key not in seen:
                    seen.add(key)
                    findings.append(f)

        # 3. Gitleaks
        if self._gitleaks:
            log.info("Running Gitleaks on %s", extract_path)
            gl_findings = self._run_gitleaks(extract_path)
            for f in gl_findings:
                key = f"{f.file_path}:{f.secret_type}"
                if key not in seen:
                    seen.add(key)
                    findings.append(f)

        log.info("Secret scan complete: %d findings", len(findings))
        return findings

    # ── Regex scanner ─────────────────────────────────────────────────────────

    def _regex_scan(self, root: Path) -> List[SecretFinding]:
        findings = []
        import uuid as _uuid
        file_count = 0
        for path in root.rglob("*"):
            if not path.is_file():
                continue
            if any(skip in str(path) for skip in _SKIP_PATTERNS):
                continue
            if path.suffix.lower() not in _SCAN_EXTENSIONS and path.suffix != "":
                continue
            if path.stat().st_size > 5 * 1024 * 1024:  # skip files > 5MB
                continue
            try:
                if path.suffix.lower() in _BINARY_EXTENSIONS:
                    raw = path.read_bytes()
                    content = _extract_strings(raw)
                else:
                    content = path.read_text(encoding="utf-8", errors="ignore")
            except Exception:
                continue
            file_count += 1
            lines = content.splitlines()
            for pat, stype, sev, conf in _COMPILED_PATTERNS:
                for match in pat.finditer(content):
                    # Get line number
                    line_num = content[:match.start()].count("\n") + 1
                    context_start = max(0, line_num - 2)
                    context_end = min(len(lines), line_num + 2)
                    context = "\n".join(lines[context_start:context_end])
                    findings.append(SecretFinding(
                        id=str(_uuid.uuid4())[:8],
                        secret_type=stype,
                        severity=sev,
                        confidence=conf,
                        file_path=str(path.relative_to(root)),
                        line_number=line_num,
                        matched_text=match.group()[:100],
                        context=context,
                        tool="regex",
                    ))
        log.debug("Regex scan: %d files scanned, %d raw findings", file_count, len(findings))
        return findings

    # ── TruffleHog ────────────────────────────────────────────────────────────

    def _run_trufflehog(self, path: str) -> List[SecretFinding]:
        try:
            result = subprocess.run(
                [self._trufflehog, "filesystem", path, "--json", "--no-update"],
                capture_output=True, text=True, timeout=120
            )
            findings = []
            import uuid as _uuid
            for line in result.stdout.splitlines():
                line = line.strip()
                if not line:
                    continue
                try:
                    data = json.loads(line)
                    det = data.get("DetectorName", data.get("detector_name", "unknown"))
                    raw = data.get("RawV2") or data.get("Raw") or data.get("raw", "")
                    src_meta = data.get("SourceMetadata") or {}
                    file_path = ""
                    line_num = 0
                    if isinstance(src_meta, dict):
                        data_inner = src_meta.get("Data", {})
                        if isinstance(data_inner, dict):
                            fs = data_inner.get("Filesystem", {})
                            if isinstance(fs, dict):
                                file_path = fs.get("file", "")
                                line_num = fs.get("line", 0)
                    findings.append(SecretFinding(
                        id=str(_uuid.uuid4())[:8],
                        secret_type=det.lower().replace(" ", "_"),
                        severity="high",
                        confidence=0.90,
                        file_path=file_path,
                        line_number=line_num,
                        matched_text=(raw[:50] if raw else ""),
                        context="",
                        tool="trufflehog",
                    ))
                except Exception:
                    pass
            return findings
        except subprocess.TimeoutExpired:
            log.warning("TruffleHog timed out")
            return []
        except Exception as exc:
            log.debug("TruffleHog error: %s", exc)
            return []

    # ── Gitleaks ──────────────────────────────────────────────────────────────

    def _run_gitleaks(self, path: str) -> List[SecretFinding]:
        try:
            with tempfile.NamedTemporaryFile(suffix=".json", delete=False) as f:
                report_file = f.name
            result = subprocess.run(
                [self._gitleaks, "detect", "--source", path,
                 "--report-format", "json", "--report-path", report_file,
                 "--no-git", "--exit-code", "0"],
                capture_output=True, text=True, timeout=120
            )
            findings = []
            import uuid as _uuid
            if Path(report_file).exists():
                try:
                    data = json.loads(Path(report_file).read_text())
                    if isinstance(data, list):
                        for item in data:
                            findings.append(SecretFinding(
                                id=str(_uuid.uuid4())[:8],
                                secret_type=item.get("RuleID", item.get("Description", "unknown")).lower(),
                                severity="high",
                                confidence=0.88,
                                file_path=item.get("File", ""),
                                line_number=item.get("StartLine", 0),
                                matched_text=item.get("Match", item.get("Secret", ""))[:50],
                                context=item.get("Line", "")[:200],
                                tool="gitleaks",
                            ))
                except Exception:
                    pass
                finally:
                    Path(report_file).unlink(missing_ok=True)
            return findings
        except subprocess.TimeoutExpired:
            log.warning("Gitleaks timed out")
            return []
        except Exception as exc:
            log.debug("Gitleaks error: %s", exc)
            return []

    # ── Helpers ───────────────────────────────────────────────────────────────

    @staticmethod
    def _find_tool(name: str) -> Optional[str]:
        import shutil
        path = shutil.which(name)
        if not path:
            local = Path.home() / ".local" / "bin" / name
            if local.exists():
                return str(local)
        return path


# Global singleton
mobile_secret_scanner = MobileSecretScanner()
