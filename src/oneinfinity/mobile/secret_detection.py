"""
Mobile Secret Detection Engine
================================
Advanced secret detection for mobile applications.
Provides base regex/TruffleHog/Gitleaks scanning (MobileSecretScanner)
plus AI-powered analysis, binary scanning, and comprehensive reporting.
Integrates TruffleHog and Gitleaks.
"""

from __future__ import annotations

import json
import logging
import re
import shutil
import subprocess
import tempfile
import time
import uuid
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Optional, Tuple

from oneinfinity.mobile.tool_registry import UnifiedFinding, tool_registry

log = logging.getLogger("oneinfinity.mobile.secret_detection")


# ─────────────────────────────────────────────────────────────────────────────
#  Base secret pattern library (formerly mobile/secret_scanner.py)
# ─────────────────────────────────────────────────────────────────────────────

_SECRET_PATTERNS: List[Tuple[str, str, str, float]] = [
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

_SCAN_EXTENSIONS = {
    ".java", ".kt", ".smali", ".xml", ".json", ".js", ".ts",
    ".yaml", ".yml", ".properties", ".gradle", ".plist",
    ".strings", ".swift", ".m", ".h", ".conf", ".config",
    ".env", ".txt", ".html", ".php", ".py", ".rb", ".dex",
}

_BINARY_EXTENSIONS = {".dex", ".so", ".dylib"}
_SKIP_PATTERNS = {"node_modules", ".git", "test", "__pycache__"}


def _extract_strings(data: bytes, min_len: int = 6) -> str:
    """Extract printable ASCII strings from binary data (like `strings` command)."""
    result = []
    current: List[int] = []
    for byte in data:
        if 0x20 <= byte <= 0x7E:
            current.append(byte)
        else:
            if len(current) >= min_len:
                result.append(bytes(current).decode("ascii"))
            current = []
    if len(current) >= min_len:
        result.append(bytes(current).decode("ascii"))
    return "\n".join(result)


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
    """Base scanner: regex + TruffleHog + Gitleaks."""

    def __init__(self) -> None:
        self._trufflehog = self._find_tool("trufflehog")
        self._gitleaks = self._find_tool("gitleaks")

    def scan(self, extract_path: str, app_id: str = "") -> List[SecretFinding]:
        root = Path(extract_path)
        if not root.exists():
            raise FileNotFoundError(f"Extract path not found: {extract_path}")
        findings: List[SecretFinding] = []
        seen: set = set()
        for f in self._regex_scan(root):
            key = f"{f.file_path}:{f.line_number}:{f.secret_type}"
            if key not in seen:
                seen.add(key)
                findings.append(f)
        if self._trufflehog:
            for f in self._run_trufflehog(extract_path):
                key = f"{f.file_path}:{f.line_number}:{f.secret_type}"
                if key not in seen:
                    seen.add(key)
                    findings.append(f)
        if self._gitleaks:
            for f in self._run_gitleaks(extract_path):
                key = f"{f.file_path}:{f.secret_type}"
                if key not in seen:
                    seen.add(key)
                    findings.append(f)
        return findings

    def _regex_scan(self, root: Path) -> List[SecretFinding]:
        findings = []
        for path in root.rglob("*"):
            if not path.is_file():
                continue
            if any(skip in str(path) for skip in _SKIP_PATTERNS):
                continue
            if path.suffix.lower() not in _SCAN_EXTENSIONS and path.suffix != "":
                continue
            if path.stat().st_size > 5 * 1024 * 1024:
                continue
            try:
                content = (_extract_strings(path.read_bytes()) if path.suffix.lower() in _BINARY_EXTENSIONS
                           else path.read_text(encoding="utf-8", errors="ignore"))
            except Exception:
                continue
            lines = content.splitlines()
            for pat, stype, sev, conf in _COMPILED_PATTERNS:
                for match in pat.finditer(content):
                    line_num = content[:match.start()].count("\n") + 1
                    ctx_start = max(0, line_num - 2)
                    context = "\n".join(lines[ctx_start:min(len(lines), line_num + 2)])
                    findings.append(SecretFinding(
                        id=str(uuid.uuid4())[:8], secret_type=stype, severity=sev,
                        confidence=conf, file_path=str(path.relative_to(root)),
                        line_number=line_num, matched_text=match.group()[:100],
                        context=context, tool="regex",
                    ))
        return findings

    def _run_trufflehog(self, path: str) -> List[SecretFinding]:
        try:
            result = subprocess.run(
                [self._trufflehog, "filesystem", path, "--json", "--no-update"],
                capture_output=True, text=True, timeout=120)
            findings = []
            for line in result.stdout.splitlines():
                if not line.strip():
                    continue
                try:
                    data = json.loads(line)
                    det = data.get("DetectorName", data.get("detector_name", "unknown"))
                    raw = data.get("RawV2") or data.get("Raw") or data.get("raw", "")
                    src_meta = data.get("SourceMetadata") or {}
                    file_path, line_num = "", 0
                    if isinstance(src_meta, dict):
                        fs = src_meta.get("Data", {}).get("Filesystem", {})
                        if isinstance(fs, dict):
                            file_path, line_num = fs.get("file", ""), fs.get("line", 0)
                    findings.append(SecretFinding(
                        id=str(uuid.uuid4())[:8],
                        secret_type=det.lower().replace(" ", "_"),
                        severity="high", confidence=0.90,
                        file_path=file_path, line_number=line_num,
                        matched_text=raw[:50] if raw else "", tool="trufflehog",
                    ))
                except Exception:
                    pass
            return findings
        except Exception:
            return []

    def _run_gitleaks(self, path: str) -> List[SecretFinding]:
        try:
            with tempfile.NamedTemporaryFile(suffix=".json", delete=False) as f:
                report_file = f.name
            subprocess.run(
                [self._gitleaks, "detect", "--source", path,
                 "--report-format", "json", "--report-path", report_file,
                 "--no-git", "--exit-code", "0"],
                capture_output=True, text=True, timeout=120)
            findings = []
            if Path(report_file).exists():
                try:
                    data = json.loads(Path(report_file).read_text())
                    if isinstance(data, list):
                        for item in data:
                            findings.append(SecretFinding(
                                id=str(uuid.uuid4())[:8],
                                secret_type=item.get("RuleID", item.get("Description", "unknown")).lower(),
                                severity="high", confidence=0.88,
                                file_path=item.get("File", ""),
                                line_number=item.get("StartLine", 0),
                                matched_text=item.get("Match", item.get("Secret", ""))[:50],
                                context=item.get("Line", "")[:200], tool="gitleaks",
                            ))
                except Exception:
                    pass
                finally:
                    Path(report_file).unlink(missing_ok=True)
            return findings
        except Exception:
            return []

    @staticmethod
    def _find_tool(name: str) -> Optional[str]:
        import shutil as _shutil
        p = _shutil.which(name)
        if not p:
            local = Path.home() / ".local" / "bin" / name
            if local.exists():
                return str(local)
        return p


# Module-level singleton (backward-compatible name)
mobile_secret_scanner = MobileSecretScanner()


# ─────────────────────────────────────────────────────────────────────────────


# ─────────────────────────────────────────────────────────────────────────────
#  Additional regex patterns (extend mobile_secret_scanner)
# ─────────────────────────────────────────────────────────────────────────────

_EXTRA_PATTERNS: List[Tuple[str, str, str, float]] = [
    # Google Maps API key
    (r'AIza[0-9A-Za-z\-_]{35}', "google_maps_api_key", "high", 0.95),
    # Firebase Realtime Database URL
    (r'https://[a-zA-Z0-9\-]+\.firebaseio\.com', "firebase_db_url", "medium", 0.85),
    # Firebase API key in google-services.json
    (r'"current_key"\s*:\s*"([^"]+)"', "firebase_current_key", "high", 0.92),
    # GCP Service Account private_key_id
    (r'"private_key_id"\s*:\s*"([^"]+)"', "gcp_service_account_key_id", "critical", 0.97),
    # GCP Service Account private key (PEM block)
    (r'"private_key"\s*:\s*"-----BEGIN', "gcp_service_account_private_key", "critical", 0.99),
    # Slack Incoming Webhook
    (r'https://hooks\.slack\.com/services/[A-Za-z0-9/]+', "slack_webhook", "high", 0.98),
    # SendGrid API key
    (r'SG\.[A-Za-z0-9\-_]{22}\.[A-Za-z0-9\-_]{43}', "sendgrid_api_key", "critical", 0.99),
    # Mailgun API key
    (r'key-[0-9a-zA-Z]{32}', "mailgun_api_key", "high", 0.90),
    # Heroku API key (UUID format)
    (r'(?<![0-9a-fA-F])[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}(?![0-9a-fA-F])', "heroku_api_key", "high", 0.55),
    # Shopify private app / admin API tokens
    (r'shpss_[0-9a-fA-F]{32}', "shopify_shared_secret", "critical", 0.99),
    (r'shpat_[0-9a-fA-F]{32}', "shopify_access_token", "critical", 0.99),
    # Docker config.json base64 auth
    (r'"auth"\s*:\s*"[A-Za-z0-9+/]{20,}={0,2}"', "docker_auth_base64", "critical", 0.88),
    # Android Keystore password in gradle
    (r'(?i)(?:storePassword|keyPassword|keystorePassword)\s*[=:]\s*["\']([^"\']{4,})["\']', "android_keystore_password", "critical", 0.92),
    # Android signing key alias in gradle
    (r'(?i)keyAlias\s*[=:]\s*["\']([^"\']+)["\']', "android_key_alias", "medium", 0.80),
    # Twilio auth token (34-char alphanumeric)
    (r'(?i)(?:twilio|tw)[_\-]?auth[_\-]?token\s*[=:"\s]+([A-Za-z0-9]{32})', "twilio_auth_token", "critical", 0.93),
    # Braintree / PayPal tokenization key
    (r'(?i)braintree[_\-]?(?:token|key|secret)\s*[=:"\s]+([A-Za-z0-9_\-]{20,})', "braintree_key", "critical", 0.88),
    # Datadog API key
    (r'(?i)datadog[_\-]?(?:api[_\-]?)?key\s*[=:"\s]+([a-f0-9]{32})', "datadog_api_key", "high", 0.87),
    # Sentry DSN
    (r'https://[a-f0-9]{32}@(?:o[0-9]+\.)?ingest\.sentry\.io/[0-9]+', "sentry_dsn", "medium", 0.95),
    # Amplitude API key (32 hex chars)
    (r'(?i)amplitude[_\-]?(?:api[_\-]?)?key\s*[=:"\s]+([a-f0-9]{32})', "amplitude_api_key", "medium", 0.85),
    # Apple Push Notification auth key
    (r'-----BEGIN PRIVATE KEY-----[\s\S]{100,500}-----END PRIVATE KEY-----', "apple_apns_key", "critical", 0.97),
    # Mapbox token
    (r'pk\.eyJ1Ijoi[A-Za-z0-9_\-]+\.[A-Za-z0-9_\-]+', "mapbox_public_token", "medium", 0.92),
    (r'sk\.eyJ1Ijoi[A-Za-z0-9_\-]+\.[A-Za-z0-9_\-]+', "mapbox_secret_token", "high", 0.97),
    # Intercom app ID / secret
    (r'(?i)intercom[_\-]?(?:app[_\-]?id|secret)\s*[=:"\s]+([A-Za-z0-9]{8,})', "intercom_key", "high", 0.82),
    # Algolia API key
    (r'(?i)algolia[_\-]?(?:api[_\-]?)?key\s*[=:"\s]+([A-Za-z0-9]{32})', "algolia_api_key", "high", 0.87),
]

_COMPILED_EXTRA = [
    (re.compile(pat, re.MULTILINE | re.DOTALL), stype, sev, conf)
    for pat, stype, sev, conf in _EXTRA_PATTERNS
]

# False-positive heuristics
_FP_VALUE_PATTERNS = [
    re.compile(r'(?i)(example|placeholder|test|demo|sample|dummy|xxx+|aaa+|your[_\-]?key|insert[_\-]?key)'),
    re.compile(r'^0{8,}$'),                      # all zeros
    re.compile(r'^f{8,}$'),                      # all 0xff
    re.compile(r'lorem\s+ipsum', re.I),
    re.compile(r'(?i)test[_\-]?(key|secret|token|password)'),
    re.compile(r'(?i)(?:REPLACE|CHANGEME|FIXME|TODO)\b'),
]

_FP_FILE_PATTERNS = [
    re.compile(r'(?i)(test|spec|mock|fixture|example)'),
    re.compile(r'(?i)README'),
]

_SEVERITY_CVSS: Dict[str, float] = {
    "critical": 9.0,
    "high": 7.5,
    "medium": 5.5,
    "low": 2.5,
    "info": 0.0,
}


# ─────────────────────────────────────────────────────────────────────────────
#  Configuration & Report types
# ─────────────────────────────────────────────────────────────────────────────

@dataclass
class SecretScanConfig:
    min_confidence: float = 0.7
    include_low: bool = False
    run_trufflehog: bool = True
    run_gitleaks: bool = True
    run_regex: bool = True
    scan_binaries: bool = True


@dataclass
class SecretReport:
    app_id: str
    total_findings: int = 0
    critical: int = 0
    high: int = 0
    medium: int = 0
    low: int = 0
    findings_by_type: Dict[str, int] = field(default_factory=dict)
    top_findings: List[SecretFinding] = field(default_factory=list)
    scan_duration: float = 0.0
    all_findings: List[SecretFinding] = field(default_factory=list)

    def to_dict(self) -> dict:
        return {
            "app_id": self.app_id,
            "total_findings": self.total_findings,
            "critical": self.critical,
            "high": self.high,
            "medium": self.medium,
            "low": self.low,
            "findings_by_type": self.findings_by_type,
            "top_findings": [f.to_dict() for f in self.top_findings],
            "scan_duration": round(self.scan_duration, 2),
        }


# ─────────────────────────────────────────────────────────────────────────────
#  Main Detector
# ─────────────────────────────────────────────────────────────────────────────

class MobileSecretDetector:
    """
    Advanced mobile secret detection that wraps and extends MobileSecretScanner
    with additional patterns, binary scanning, asset scanning, and
    smarter false-positive filtering.
    """

    def __init__(self, config: Optional[SecretScanConfig] = None) -> None:
        self.config = config or SecretScanConfig()
        self._base_scanner = MobileSecretScanner()

    # ── Public API ────────────────────────────────────────────────────────────

    def scan_app(self, extracted_dir: str, app_id: str = "") -> SecretReport:
        """
        Run all configured scanners against the extracted app directory.
        Deduplicates results and returns a SecretReport.
        """
        start = time.monotonic()
        root = Path(extracted_dir)
        if not root.exists():
            log.error("Extracted directory not found: %s", extracted_dir)
            return SecretReport(app_id=app_id, scan_duration=0.0)

        log.info("Starting secret scan: dir=%s app_id=%s", extracted_dir, app_id)

        all_raw: List[SecretFinding] = []

        # 1. Base scanner (TruffleHog + Gitleaks + base regex)
        if self.config.run_regex or self.config.run_trufflehog or self.config.run_gitleaks:
            try:
                base_findings = self._base_scanner.scan(extracted_dir, app_id)
                all_raw.extend(base_findings)
                log.info("Base scanner: %d raw findings", len(base_findings))
            except Exception as exc:
                log.warning("Base scanner error: %s", exc)

        # 2. Extra regex patterns
        if self.config.run_regex:
            extra = self._scan_extra_patterns(root)
            all_raw.extend(extra)
            log.info("Extra patterns: %d raw findings", len(extra))

        # 3. Binary string extraction (strings tool)
        if self.config.scan_binaries:
            binary_findings = self._scan_with_strings_tool(extracted_dir)
            all_raw.extend(binary_findings)
            log.info("Binary strings: %d raw findings", len(binary_findings))

        # 4. Assets directory
        asset_findings = self._scan_assets(extracted_dir)
        all_raw.extend(asset_findings)
        log.info("Assets: %d raw findings", len(asset_findings))

        # 5. Gradle configs
        gradle_findings = self._scan_gradle_configs(extracted_dir)
        all_raw.extend(gradle_findings)
        log.info("Gradle: %d raw findings", len(gradle_findings))

        # Deduplicate: key = file + line + type + value prefix
        seen: set = set()
        deduped: List[SecretFinding] = []
        for f in all_raw:
            key = (
                str(f.file_path),
                str(f.line_number),
                f.secret_type,
                f.matched_text[:16],
            )
            if key in seen:
                continue
            seen.add(key)
            deduped.append(f)

        # Classify severity and filter false positives
        refined: List[SecretFinding] = []
        for f in deduped:
            if self._is_false_positive(f):
                log.debug("FP filtered: %s in %s", f.secret_type, f.file_path)
                continue
            self._classify_severity(f)
            if f.severity == "low" and not self.config.include_low:
                continue
            if f.confidence < self.config.min_confidence:
                continue
            refined.append(f)

        # Build report
        report = self._build_report(app_id, refined, time.monotonic() - start)
        log.info(
            "Secret scan complete in %.1fs: total=%d critical=%d high=%d medium=%d low=%d",
            report.scan_duration, report.total_findings,
            report.critical, report.high, report.medium, report.low,
        )
        return report

    # ── Extra pattern scanner ─────────────────────────────────────────────────

    def _scan_extra_patterns(self, root: Path) -> List[SecretFinding]:
        """Apply the extended _EXTRA_PATTERNS on all scannable files."""
        findings: List[SecretFinding] = []
        scan_exts = {
            ".java", ".kt", ".xml", ".json", ".js", ".ts", ".yaml", ".yml",
            ".properties", ".gradle", ".plist", ".strings", ".swift", ".m",
            ".h", ".conf", ".config", ".env", ".txt", ".rb", ".py",
        }
        skip_dirs = {"test", "androidTest", "__pycache__", "node_modules", ".git"}

        for fpath in root.rglob("*"):
            if not fpath.is_file():
                continue
            if any(skip in fpath.parts for skip in skip_dirs):
                continue
            if fpath.suffix.lower() not in scan_exts:
                continue
            if fpath.stat().st_size > 5 * 1024 * 1024:
                continue
            try:
                content = fpath.read_text(encoding="utf-8", errors="ignore")
            except Exception:
                continue

            lines = content.splitlines()
            for pattern, stype, sev, conf in _COMPILED_EXTRA:
                for match in pattern.finditer(content):
                    line_num = content[: match.start()].count("\n") + 1
                    ctx_start = max(0, line_num - 3)
                    ctx_end = min(len(lines), line_num + 2)
                    context = "\n".join(lines[ctx_start:ctx_end])
                    # Use first capturing group if present, else full match
                    matched = match.group(1) if match.lastindex else match.group()
                    findings.append(SecretFinding(
                        id=str(uuid.uuid4())[:8],
                        secret_type=stype,
                        severity=sev,
                        confidence=conf,
                        file_path=str(fpath.relative_to(root)),
                        line_number=line_num,
                        matched_text=matched[:100],
                        context=context[:300],
                        tool="regex_extended",
                    ))

        return findings

    # ── Binary strings scanner ────────────────────────────────────────────────

    def _scan_with_strings_tool(self, extracted_dir: str) -> List[SecretFinding]:
        """
        Use the system `strings` binary to extract printable strings from .dex
        and .so files, then apply secret patterns.  Falls back to Python
        _extract_strings() if the tool is unavailable.
        """
        root = Path(extracted_dir)
        findings: List[SecretFinding] = []
        strings_bin = shutil.which("strings")
        binary_exts = _BINARY_EXTENSIONS | {".so", ".dylib", ".apk"}

        for fpath in root.rglob("*"):
            if not fpath.is_file():
                continue
            if fpath.suffix.lower() not in binary_exts:
                continue
            if fpath.stat().st_size > 50 * 1024 * 1024:  # skip very large binaries
                continue

            # Extract printable strings
            content = ""
            if strings_bin:
                try:
                    result = subprocess.run(
                        [strings_bin, "-n", "8", str(fpath)],
                        capture_output=True, text=True, timeout=30,
                    )
                    content = result.stdout
                except (subprocess.TimeoutExpired, Exception) as exc:
                    log.debug("strings tool failed for %s: %s", fpath.name, exc)
                    # Fallback to Python implementation
                    try:
                        content = _extract_strings(fpath.read_bytes(), min_len=8)
                    except Exception:
                        continue
            else:
                try:
                    content = _extract_strings(fpath.read_bytes(), min_len=8)
                except Exception:
                    continue

            if not content:
                continue

            # Apply both base and extra patterns
            all_patterns = list(_COMPILED_EXTRA)
            # Import base patterns lazily to avoid circular
            try:
                _BASE = _COMPILED_PATTERNS
                all_patterns = list(_BASE) + all_patterns
            except ImportError:
                pass

            lines = content.splitlines()
            for pattern, stype, sev, conf in all_patterns:
                for match in pattern.finditer(content):
                    line_num = content[: match.start()].count("\n") + 1
                    ctx_start = max(0, line_num - 2)
                    ctx_end = min(len(lines), line_num + 2)
                    context = "\n".join(lines[ctx_start:ctx_end])
                    matched = match.group(1) if match.lastindex else match.group()
                    findings.append(SecretFinding(
                        id=str(uuid.uuid4())[:8],
                        secret_type=stype,
                        severity=sev,
                        confidence=max(conf - 0.05, 0.5),  # slightly lower confidence for binary
                        file_path=str(fpath.relative_to(root)),
                        line_number=line_num,
                        matched_text=matched[:100],
                        context=context[:300],
                        tool="binary_strings",
                    ))

        return findings

    # ── Assets scanner ────────────────────────────────────────────────────────

    def _scan_assets(self, extracted_dir: str) -> List[SecretFinding]:
        """
        Deep scan of assets/ directory: JSON configs, XML, .env files.
        Extra patterns for Firebase google-services.json, AWS credential files.
        """
        root = Path(extracted_dir)
        findings: List[SecretFinding] = []

        # Target directories that commonly hold secrets
        target_dirs = ["assets", "res", "raw", "values", "config", "configs"]
        target_files = [
            "google-services.json",
            "GoogleService-Info.plist",
            "aws-credentials",
            "credentials.json",
            ".env",
            "firebase.json",
            "serviceAccount.json",
            "keystore.json",
        ]

        scanned_paths: set = set()

        def _scan_file(fpath: Path) -> List[SecretFinding]:
            if str(fpath) in scanned_paths:
                return []
            scanned_paths.add(str(fpath))
            file_findings: List[SecretFinding] = []
            try:
                content = fpath.read_text(encoding="utf-8", errors="ignore")
            except Exception:
                return []

            lines = content.splitlines()

            # Special: google-services.json structure
            if fpath.name == "google-services.json":
                try:
                    data = json.loads(content)
                    # Extract API keys from clients array
                    for client in data.get("client", []):
                        for api_key_obj in client.get("api_key", []):
                            key = api_key_obj.get("current_key", "")
                            if key:
                                file_findings.append(SecretFinding(
                                    id=str(uuid.uuid4())[:8],
                                    secret_type="firebase_google_services_api_key",
                                    severity="high",
                                    confidence=0.99,
                                    file_path=str(fpath.relative_to(root)),
                                    line_number=0,
                                    matched_text=key[:100],
                                    context=f"google-services.json client.api_key.current_key",
                                    tool="asset_scanner",
                                ))
                    # Project number
                    project_info = data.get("project_info", {})
                    if project_info.get("firebase_url"):
                        file_findings.append(SecretFinding(
                            id=str(uuid.uuid4())[:8],
                            secret_type="firebase_db_url",
                            severity="medium",
                            confidence=0.98,
                            file_path=str(fpath.relative_to(root)),
                            line_number=0,
                            matched_text=project_info["firebase_url"][:100],
                            context="google-services.json project_info.firebase_url",
                            tool="asset_scanner",
                        ))
                except (json.JSONDecodeError, Exception):
                    pass

            # Apply all patterns
            all_patterns = list(_COMPILED_EXTRA)
            try:
                _BASE = _COMPILED_PATTERNS
                all_patterns = list(_BASE) + all_patterns
            except ImportError:
                pass

            for pattern, stype, sev, conf in all_patterns:
                for match in pattern.finditer(content):
                    line_num = content[: match.start()].count("\n") + 1
                    ctx_start = max(0, line_num - 2)
                    ctx_end = min(len(lines), line_num + 2)
                    context = "\n".join(lines[ctx_start:ctx_end])
                    matched = match.group(1) if match.lastindex else match.group()
                    file_findings.append(SecretFinding(
                        id=str(uuid.uuid4())[:8],
                        secret_type=stype,
                        severity=sev,
                        confidence=conf,
                        file_path=str(fpath.relative_to(root)),
                        line_number=line_num,
                        matched_text=matched[:100],
                        context=context[:300],
                        tool="asset_scanner",
                    ))

            return file_findings

        # Scan target directories
        for tdir in target_dirs:
            dir_path = root / tdir
            if dir_path.is_dir():
                for fpath in dir_path.rglob("*"):
                    if fpath.is_file():
                        findings.extend(_scan_file(fpath))

        # Scan named target files anywhere in the tree
        for fname in target_files:
            for fpath in root.rglob(fname):
                if fpath.is_file():
                    findings.extend(_scan_file(fpath))

        return findings

    # ── Gradle config scanner ─────────────────────────────────────────────────

    def _scan_gradle_configs(self, extracted_dir: str) -> List[SecretFinding]:
        """
        Scan build.gradle, gradle.properties, and local.properties for
        hardcoded API keys, signing passwords, and keystore configs.
        """
        root = Path(extracted_dir)
        findings: List[SecretFinding] = []

        gradle_patterns = [
            re.compile(r'(?i)(?:storePassword|storePass)\s*[=:]\s*["\']?([^"\'\n\r]{4,})["\']?'),
            re.compile(r'(?i)(?:keyPassword|keyPass)\s*[=:]\s*["\']?([^"\'\n\r]{4,})["\']?'),
            re.compile(r'(?i)keyAlias\s*[=:]\s*["\']?([^"\'\n\r]{2,})["\']?'),
            re.compile(r'(?i)storeFile\s*[=:]\s*["\']?([^"\'\n\r]{2,})["\']?'),
            re.compile(r'(?i)(?:apiKey|api_key|API_KEY)\s*[=:]\s*["\']?([A-Za-z0-9_\-]{16,})["\']?'),
            re.compile(r'(?i)(?:signingKeyId|signingPassword|signingSecretKeyRingFile)\s*[=:]\s*["\']?([^"\'\n\r]{4,})["\']?'),
            re.compile(r'(?i)RELEASE_(?:STORE_PASSWORD|KEY_PASSWORD|KEY_ALIAS)\s*[=:]\s*["\']?([^"\'\n\r]{4,})["\']?'),
            re.compile(r'(?i)(?:sonatype|ossrh)\.(?:username|password)\s*[=:]\s*["\']?([^"\'\n\r]{4,})["\']?'),
        ]

        _type_map = {
            "storepassword": "android_keystore_store_password",
            "storepass": "android_keystore_store_password",
            "keypassword": "android_keystore_key_password",
            "keypass": "android_keystore_key_password",
            "keyalias": "android_key_alias",
            "storefile": "android_keystore_path",
            "apikey": "gradle_api_key",
            "api_key": "gradle_api_key",
            "api_key": "gradle_api_key",
            "signingkeyid": "gradle_signing_key",
            "signingpassword": "gradle_signing_password",
        }

        gradle_files = (
            list(root.rglob("build.gradle"))
            + list(root.rglob("build.gradle.kts"))
            + list(root.rglob("gradle.properties"))
            + list(root.rglob("local.properties"))
            + list(root.rglob("gradle-wrapper.properties"))
            + list(root.rglob("signing.properties"))
        )

        for fpath in gradle_files:
            if not fpath.is_file():
                continue
            try:
                content = fpath.read_text(encoding="utf-8", errors="ignore")
            except Exception:
                continue
            lines = content.splitlines()
            for pattern in gradle_patterns:
                for match in pattern.finditer(content):
                    line_num = content[: match.start()].count("\n") + 1
                    ctx_start = max(0, line_num - 2)
                    ctx_end = min(len(lines), line_num + 2)
                    context = "\n".join(lines[ctx_start:ctx_end])
                    matched = match.group(1) if match.lastindex else match.group()
                    # Skip obvious variable references
                    if matched.startswith("${") or matched.startswith("System."):
                        continue
                    # Infer type from matched property name
                    full_match_lower = match.group().lower()
                    stype = "gradle_secret"
                    for key_fragment, stype_val in _type_map.items():
                        if key_fragment in full_match_lower:
                            stype = stype_val
                            break
                    severity = "critical" if "password" in stype else "high" if "key" in stype else "medium"
                    findings.append(SecretFinding(
                        id=str(uuid.uuid4())[:8],
                        secret_type=stype,
                        severity=severity,
                        confidence=0.88,
                        file_path=str(fpath.relative_to(root)),
                        line_number=line_num,
                        matched_text=matched[:100],
                        context=context[:300],
                        tool="gradle_scanner",
                    ))

        return findings

    # ── Severity classifier ───────────────────────────────────────────────────

    def _classify_severity(self, finding: SecretFinding) -> str:
        """
        Re-evaluate severity based on contextual signals.
        Mutates finding.severity in place and returns the new value.
        """
        original = finding.severity
        matched = finding.matched_text.lower()
        context = (finding.context + finding.file_path).lower()

        # Downgrade: test/example values
        if self._is_false_positive(finding):
            finding.severity = "low"
            return "low"

        # Downgrade: test-looking strings
        test_patterns = [
            "test_", "_test", "test.", ".test", "example", "sample",
            "placeholder", "dummy", "fake", "mock",
        ]
        if any(tp in matched for tp in test_patterns):
            if original in ("critical", "high"):
                finding.severity = "medium"
                return "medium"

        # Downgrade: known Google test key prefix
        if finding.secret_type == "google_maps_api_key" and matched.startswith("aiza"):
            if "test" in context or "debug" in context:
                finding.severity = "low"
                return "low"

        # Upgrade: production-sounding context boosts confidence
        prod_signals = ["production", "prod", "live", "release", "main"]
        if any(sig in context for sig in prod_signals):
            if original == "medium":
                finding.severity = "high"
            elif original == "high":
                finding.severity = "critical"

        return finding.severity

    def _is_false_positive(self, finding: SecretFinding) -> bool:
        """
        Return True if this finding is likely a false positive.
        Checks: placeholder values, test files, documentation strings.
        """
        matched = finding.matched_text
        file_path = finding.file_path

        # Check matched value against FP value patterns
        for pat in _FP_VALUE_PATTERNS:
            if pat.search(matched):
                return True

        # Check file path against FP file patterns
        for pat in _FP_FILE_PATTERNS:
            if pat.search(file_path):
                return True

        # Empty or very short matches
        if not matched or len(matched.strip()) < 4:
            return True

        # All same character (e.g., "AAAAAAAAAA")
        if len(set(matched)) <= 2 and len(matched) > 6:
            return True

        # Documentation/comment-only context
        context = finding.context.lower()
        doc_signals = ["//", "#", "/*", "*", "<!--", "example:", "e.g.", "see also", "documentation"]
        if all(line.strip().startswith(tuple(doc_signals)) for line in context.splitlines() if line.strip()):
            return True

        return False

    # ── Report building ───────────────────────────────────────────────────────

    def _build_report(
        self,
        app_id: str,
        findings: List[SecretFinding],
        duration: float,
    ) -> SecretReport:
        """Aggregate findings into a SecretReport."""
        counts: Dict[str, int] = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
        by_type: Dict[str, int] = {}

        for f in findings:
            sev = f.severity.lower()
            counts[sev] = counts.get(sev, 0) + 1
            by_type[f.secret_type] = by_type.get(f.secret_type, 0) + 1

        # Sort by severity for top findings
        sev_order = {"critical": 5, "high": 4, "medium": 3, "low": 2, "info": 1}
        sorted_findings = sorted(findings, key=lambda f: sev_order.get(f.severity, 0), reverse=True)

        return SecretReport(
            app_id=app_id,
            total_findings=len(findings),
            critical=counts["critical"],
            high=counts["high"],
            medium=counts["medium"],
            low=counts["low"],
            findings_by_type=by_type,
            top_findings=sorted_findings[:20],
            all_findings=findings,
            scan_duration=duration,
        )

    # ── Conversion helpers ────────────────────────────────────────────────────

    def to_unified_findings(
        self, report: SecretReport, target: str = ""
    ) -> List[UnifiedFinding]:
        """Convert all SecretFinding objects in the report to UnifiedFinding format."""
        unified: List[UnifiedFinding] = []
        for sf in report.all_findings:
            sev = sf.severity.lower()
            if sev not in {"critical", "high", "medium", "low", "info"}:
                sev = "medium"

            cvss = _SEVERITY_CVSS.get(sev, 5.0)
            # Calibrate CVSS by confidence
            cvss = round(cvss * sf.confidence, 1)

            secret_title = sf.secret_type.replace("_", " ").title()
            unified.append(UnifiedFinding(
                target=target or report.app_id,
                vulnerability=f"Hardcoded Secret: {secret_title}",
                attack_type="hardcoded_secret",
                tool=f"mobile_secret_detection ({sf.tool})",
                severity=sev,
                evidence=(
                    f"Secret type: {sf.secret_type}\n"
                    f"File: {sf.file_path}:{sf.line_number}\n"
                    f"Preview: {sf.matched_text[:20]}...\n"
                    f"Context:\n{sf.context[:300]}"
                ),
                file_path=sf.file_path,
                line_number=sf.line_number,
                payload=sf.matched_text[:50],
                confidence=sf.confidence,
                cvss=cvss,
                remediation=(
                    f"Remove the hardcoded {sf.secret_type} from source code immediately. "
                    "Store secrets in Android Keystore / iOS Keychain or environment-specific "
                    "configuration injected at build time. Rotate the exposed credential."
                ),
                tags=["mobile", "hardcoded_secret", sf.secret_type, "CWE-798", sf.tool],
            ))

        return unified

    def generate_report_text(self, report: SecretReport) -> str:
        """Generate a human-readable summary of secret findings."""
        lines = [
            f"# Mobile Secret Detection Report",
            f"",
            f"**App ID:** {report.app_id}",
            f"**Scan Duration:** {report.scan_duration:.2f}s",
            f"**Total Findings:** {report.total_findings}",
            f"",
            f"## Severity Summary",
            f"- Critical: {report.critical}",
            f"- High:     {report.high}",
            f"- Medium:   {report.medium}",
            f"- Low:      {report.low}",
            f"",
        ]

        if report.findings_by_type:
            lines.append("## Findings by Type")
            for stype, count in sorted(report.findings_by_type.items(), key=lambda x: -x[1]):
                lines.append(f"- {stype}: {count}")
            lines.append("")

        if report.top_findings:
            lines.append("## Top Findings")
            for i, f in enumerate(report.top_findings[:10], 1):
                lines.append(f"### {i}. {f.secret_type.replace('_', ' ').title()}")
                lines.append(f"**Severity:** {f.severity.upper()}")
                lines.append(f"**Confidence:** {f.confidence:.0%}")
                lines.append(f"**Location:** `{f.file_path}:{f.line_number}`")
                lines.append(f"**Tool:** {f.tool}")
                preview = f.matched_text
                if len(preview) > 12:
                    preview = f"{preview[:8]}...{preview[-4:]}"
                lines.append(f"**Preview:** `{preview}`")
                if f.context:
                    lines.append(f"**Context:**")
                    lines.append("```")
                    lines.append(f.context[:200])
                    lines.append("```")
                lines.append("")

        if report.total_findings == 0:
            lines.append("No secrets detected. The application appears to have no hardcoded credentials.")

        return "\n".join(lines)


# ─────────────────────────────────────────────────────────────────────────────
#  Module singleton
# ─────────────────────────────────────────────────────────────────────────────

mobile_secret_detector = MobileSecretDetector()
