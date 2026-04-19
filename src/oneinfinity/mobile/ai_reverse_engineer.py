"""
Mobile AI Reverse Engineering Engine
======================================
Analyzes decompiled Android/iOS application source code using AI
to discover hidden attack surfaces, insecure patterns, and business logic flaws.
Integrates with JADX/APKTool output and uses Claude/OpenAI for analysis.
"""

from __future__ import annotations

import json
import logging
import re
import uuid
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

from oneinfinity.mobile.tool_registry import UnifiedFinding

log = logging.getLogger("oneinfinity.mobile.ai_reverse_engineer")

try:
    import anthropic
    HAS_ANTHROPIC = True
except ImportError:
    HAS_ANTHROPIC = False
    log.debug("anthropic SDK not installed — AI analysis via Anthropic unavailable")

try:
    import openai
    HAS_OPENAI = True
except ImportError:
    HAS_OPENAI = False
    log.debug("openai SDK not installed — AI analysis via OpenAI unavailable")


# ─────────────────────────────────────────────────────────────────────────────
#  Configuration & Data Classes
# ─────────────────────────────────────────────────────────────────────────────

@dataclass
class ReverseEngineeringConfig:
    use_ai: bool = True
    ai_provider: str = "anthropic"       # "anthropic" | "openai"
    max_files: int = 50
    max_file_size: int = 50000           # bytes — skip larger source files
    model: str = "claude-sonnet-4-6"


@dataclass
class AppModel:
    package_name: str = ""
    activities: List[str] = field(default_factory=list)
    services: List[str] = field(default_factory=list)
    receivers: List[str] = field(default_factory=list)
    providers: List[str] = field(default_factory=list)
    api_endpoints: List[str] = field(default_factory=list)
    auth_classes: List[str] = field(default_factory=list)
    crypto_classes: List[str] = field(default_factory=list)
    network_classes: List[str] = field(default_factory=list)
    hidden_endpoints: List[str] = field(default_factory=list)
    admin_functions: List[str] = field(default_factory=list)
    vuln_patterns: List[Dict[str, Any]] = field(default_factory=list)
    business_logic_flaws: List[str] = field(default_factory=list)
    attack_surface_score: float = 0.0

    def to_dict(self) -> Dict[str, Any]:
        return {
            "package_name": self.package_name,
            "activities": self.activities,
            "services": self.services,
            "receivers": self.receivers,
            "providers": self.providers,
            "api_endpoints": self.api_endpoints,
            "auth_classes": self.auth_classes,
            "crypto_classes": self.crypto_classes,
            "network_classes": self.network_classes,
            "hidden_endpoints": self.hidden_endpoints,
            "admin_functions": self.admin_functions,
            "vuln_patterns": self.vuln_patterns,
            "business_logic_flaws": self.business_logic_flaws,
            "attack_surface_score": self.attack_surface_score,
        }


# ─────────────────────────────────────────────────────────────────────────────
#  Rule-based pattern definitions
# ─────────────────────────────────────────────────────────────────────────────

# (regex_pattern, attack_type, title, severity, cwe, cvss, recommendation)
_RULE_PATTERNS: List[Tuple[str, str, str, str, str, float, str]] = [
    (
        r'String\.format\s*\([^)]*(?:SELECT|INSERT|UPDATE|DELETE|DROP|WHERE)[^)]*\)',
        "sql_injection",
        "SQL Injection via String.format()",
        "critical",
        "CWE-89",
        9.3,
        "Use parameterized queries / PreparedStatement instead of String.format() for SQL construction.",
    ),
    (
        r'\.setJavaScriptEnabled\s*\(\s*true\s*\)',
        "webview_javascript",
        "WebView JavaScript Enabled",
        "high",
        "CWE-79",
        7.5,
        "Disable JavaScript unless strictly required; audit all addJavascriptInterface() calls.",
    ),
    (
        r'\.addJavascriptInterface\s*\(',
        "webview_javascript_interface",
        "WebView addJavascriptInterface — Potential Code Injection",
        "high",
        "CWE-749",
        8.0,
        "Restrict addJavascriptInterface() usage; validate all JS-to-Java call origins.",
    ),
    (
        r'new\s+SecretKeySpec\s*\(\s*new\s+byte\s*\[\s*\]\s*\{',
        "hardcoded_crypto_key",
        "Hardcoded Cryptographic Key in SecretKeySpec",
        "critical",
        "CWE-321",
        9.0,
        "Derive keys from a secure source (Android Keystore) — never embed key material in source code.",
    ),
    (
        r'MessageDigest\.getInstance\s*\(\s*["\']MD5["\']\s*\)',
        "weak_hash_md5",
        "MD5 Used for Password Hashing",
        "high",
        "CWE-327",
        7.5,
        "Replace MD5 with bcrypt, scrypt, or Argon2 for password storage.",
    ),
    (
        r'(?i)(?:new\s+DESede|DES/|new\s+DESedeKeySpec)',
        "weak_encryption_des",
        "Weak Encryption Algorithm — DES/3DES",
        "high",
        "CWE-326",
        7.0,
        "Replace DES/3DES with AES-256-GCM.",
    ),
    (
        r'(?i)/ECB/',
        "ecb_mode",
        "ECB Mode Encryption — Deterministic Ciphertext",
        "high",
        "CWE-327",
        7.0,
        "Use AES/GCM/NoPadding or AES/CBC/PKCS5Padding with a random IV.",
    ),
    (
        r'\.openFileOutput\s*\([^,]+,\s*(?:Context\.)?MODE_WORLD',
        "insecure_file_storage",
        "World-Readable/Writable File Created",
        "high",
        "CWE-732",
        7.5,
        "Use MODE_PRIVATE for openFileOutput(); never use MODE_WORLD_READABLE or MODE_WORLD_WRITEABLE.",
    ),
    (
        r'getSharedPreferences\s*\([^)]+\)[\s\S]{0,200}?putString\s*\(\s*["\'](?:password|passwd|secret|token|key)["\']',
        "insecure_credential_storage",
        "Credentials Stored in SharedPreferences",
        "critical",
        "CWE-312",
        8.5,
        "Store credentials in Android Keystore / EncryptedSharedPreferences.",
    ),
    (
        r'Log\.[deiw]\s*\([^)]*(?:password|passwd|token|secret|credential|apikey|api_key)[^)]*\)',
        "sensitive_data_logging",
        "Sensitive Data Written to Logcat",
        "high",
        "CWE-532",
        6.5,
        "Remove all Log statements that include credentials, tokens, or keys before release.",
    ),
    (
        r'WebView[\s\S]{0,100}?loadUrl\s*\([^)]*javascript:',
        "javascript_injection",
        "JavaScript Injection via WebView.loadUrl()",
        "high",
        "CWE-79",
        7.5,
        "Sanitize all dynamic values passed to WebView.loadUrl(); prefer evaluateJavascript() with validation.",
    ),
    (
        r'(?:Runtime\.getRuntime\(\)\.exec|new\s+ProcessBuilder)\s*\(',
        "command_injection",
        "Potential Command Injection — Runtime.exec() / ProcessBuilder",
        "critical",
        "CWE-78",
        9.3,
        "Never pass unsanitized user input to Runtime.exec() or ProcessBuilder. Use allowlists.",
    ),
    (
        r'new\s+Random\s*\(\s*\)',
        "insecure_random",
        "Insecure Random Number Generator (java.util.Random)",
        "medium",
        "CWE-330",
        5.0,
        "Use SecureRandom for all security-sensitive random number generation.",
    ),
    (
        r'Intent\s*\([^)]+\)[\s\S]{0,300}?getData\s*\(\s*\)\.toString\s*\(\s*\)',
        "open_redirect_intent",
        "Potential Open Redirect via Intent getData()",
        "medium",
        "CWE-601",
        5.5,
        "Validate Intent data URIs against an allowlist of trusted schemes/hosts.",
    ),
    (
        r'(?:Build\.DEBUG|BuildConfig\.DEBUG)\s*(?:==\s*true|&&|\|\|)',
        "debug_mode_active",
        "Debug Mode Condition Active in Production Code",
        "medium",
        "CWE-489",
        4.5,
        "Remove or guard debug code paths with proper release build checks.",
    ),
]

_COMPILED_RULES = [
    (re.compile(pat, re.MULTILINE | re.DOTALL), atype, title, sev, cwe, cvss_score, rec)
    for pat, atype, title, sev, cwe, cvss_score, rec in _RULE_PATTERNS
]

# Class-name keyword classifiers
_AUTH_KEYWORDS = re.compile(
    r'(?i)(login|authenticate|auth(?:entication|orize)?|token|session|credential|password|oauth|jwt|sso|signin|logout)',
)
_CRYPTO_KEYWORDS = re.compile(
    r'(?i)(cipher|encrypt|decrypt|hash|sign|verify|(?<!\w)key(?!\w)|crypto|aes|rsa|hmac|digest)',
)
_NETWORK_KEYWORDS = re.compile(
    r'(?i)(retrofit|okhttp|volley|httpurl|urlconnection|httpclient|apiservice|apiclient|networkcall|restclient)',
)

_CLASS_RE = re.compile(r'(?:public|private|protected)?\s+(?:class|interface|enum)\s+(\w+)', re.MULTILINE)
_METHOD_RE = re.compile(r'(?:public|private|protected|static|final|\s)+[\w<>\[\]]+\s+(\w+)\s*\(', re.MULTILINE)
_ENDPOINT_RE = re.compile(r'["\'](?:/api/|/v\d+/|/rest/|/graphql)[^\s"\'<>]{0,150}["\']')


# ─────────────────────────────────────────────────────────────────────────────
#  Main Engine
# ─────────────────────────────────────────────────────────────────────────────

class MobileAIReverseEngineer:
    """
    Analyzes decompiled Android/iOS source trees to discover hidden attack
    surfaces, insecure coding patterns, and business logic flaws.
    """

    def __init__(self, config: Optional[ReverseEngineeringConfig] = None) -> None:
        self.config = config or ReverseEngineeringConfig()

    # ── Public interface ──────────────────────────────────────────────────────

    def analyze(
        self,
        decompiled_dir: str,
        package_name: str = "",
        platform: str = "android",
    ) -> Tuple[AppModel, List[UnifiedFinding]]:
        """
        Main orchestrator.

        1. Build the AppModel from source tree (classes, endpoints, etc.)
        2. Run rule-based static analysis on all Java/Kotlin files.
        3. Optionally run AI analysis on the most interesting files.
        4. Calculate attack surface score.

        Returns (AppModel, List[UnifiedFinding]).
        """
        log.info("Starting AI reverse engineering: dir=%s platform=%s", decompiled_dir, platform)
        root = Path(decompiled_dir)
        if not root.exists():
            log.error("Decompiled directory does not exist: %s", decompiled_dir)
            return AppModel(package_name=package_name), []

        app_model = self._build_app_model(decompiled_dir)
        if package_name:
            app_model.package_name = package_name

        java_files = self._collect_java_files(root)
        log.info("Collected %d source files for analysis", len(java_files))

        findings: List[UnifiedFinding] = []

        # Rule-based analysis (always runs)
        rule_findings = self._rule_based_analysis(java_files, app_model)
        findings.extend(rule_findings)
        log.info("Rule-based analysis: %d findings", len(rule_findings))

        # AI analysis (optional)
        if self.config.use_ai and (HAS_ANTHROPIC or HAS_OPENAI):
            try:
                ai_findings = self._ai_analyze_batch(java_files, app_model)
                findings.extend(ai_findings)
                log.info("AI analysis: %d findings", len(ai_findings))
            except Exception as exc:
                log.warning("AI analysis failed: %s", exc)
        elif self.config.use_ai:
            log.warning("AI analysis requested but no AI SDK installed (anthropic/openai)")

        app_model.attack_surface_score = self._calculate_attack_surface_score(findings)
        log.info(
            "Reverse engineering complete: score=%.1f total_findings=%d",
            app_model.attack_surface_score,
            len(findings),
        )
        return app_model, findings

    # ── App model building ────────────────────────────────────────────────────

    def _build_app_model(self, decompiled_dir: str) -> AppModel:
        """Parse Java files to build a comprehensive AppModel."""
        root = Path(decompiled_dir)
        model = AppModel()

        java_files = self._collect_java_files(root)

        model.auth_classes = self._find_auth_classes(java_files)
        model.crypto_classes = self._find_crypto_classes(java_files)
        model.network_classes = self._find_network_classes(java_files)

        seen_endpoints: set = set()
        seen_activities: set = set()
        seen_services: set = set()
        seen_receivers: set = set()
        seen_providers: set = set()

        for fpath in java_files:
            try:
                text = fpath.read_text(encoding="utf-8", errors="ignore")
            except Exception:
                continue

            for cls_match in _CLASS_RE.finditer(text):
                cls_name = cls_match.group(1)
                snippet = text[cls_match.start(): min(cls_match.start() + 300, len(text))]
                if re.search(r'extends\s+(?:\w+\.)*Activity', snippet) and cls_name not in seen_activities:
                    seen_activities.add(cls_name)
                    model.activities.append(cls_name)
                elif re.search(r'extends\s+(?:\w+\.)*(?:Service|IntentService|JobService)', snippet) and cls_name not in seen_services:
                    seen_services.add(cls_name)
                    model.services.append(cls_name)
                elif re.search(r'extends\s+(?:\w+\.)*(?:BroadcastReceiver)', snippet) and cls_name not in seen_receivers:
                    seen_receivers.add(cls_name)
                    model.receivers.append(cls_name)
                elif re.search(r'extends\s+(?:\w+\.)*ContentProvider', snippet) and cls_name not in seen_providers:
                    seen_providers.add(cls_name)
                    model.providers.append(cls_name)

            # API endpoint strings
            for m in _ENDPOINT_RE.finditer(text):
                ep = m.group().strip('"\'')
                if ep not in seen_endpoints:
                    seen_endpoints.add(ep)
                    model.api_endpoints.append(ep)

            # Package name from source if not set
            if not model.package_name:
                pkg_m = re.search(r'^package\s+([\w.]+)\s*;', text, re.MULTILINE)
                if pkg_m:
                    model.package_name = pkg_m.group(1).rsplit('.', 1)[0]

        return model

    def _collect_java_files(self, root: Path) -> List[Path]:
        """Collect .java and .kt files up to max_files limit."""
        extensions = {".java", ".kt"}
        files: List[Path] = []
        skip_dirs = {"test", "androidTest", "res", "assets", "__pycache__", "node_modules", ".git"}

        for path in root.rglob("*"):
            if not path.is_file():
                continue
            if any(skip in path.parts for skip in skip_dirs):
                continue
            if path.suffix.lower() not in extensions:
                continue
            if path.stat().st_size > self.config.max_file_size:
                continue
            files.append(path)

        return files[: self.config.max_files * 2]

    # ── Class classification ──────────────────────────────────────────────────

    def _find_auth_classes(self, java_files: List[Path]) -> List[str]:
        """Return class names whose content or name matches auth-related keywords."""
        auth_classes: List[str] = []
        seen: set = set()
        for fpath in java_files:
            try:
                text = fpath.read_text(encoding="utf-8", errors="ignore")
            except Exception:
                continue
            for cls_match in _CLASS_RE.finditer(text):
                cls_name = cls_match.group(1)
                if cls_name in seen:
                    continue
                window_start = max(0, cls_match.start() - 20)
                window = text[window_start: min(cls_match.end() + 500, len(text))]
                if _AUTH_KEYWORDS.search(cls_name) or _AUTH_KEYWORDS.search(window):
                    seen.add(cls_name)
                    auth_classes.append(cls_name)
        return auth_classes

    def _find_crypto_classes(self, java_files: List[Path]) -> List[str]:
        """Return class names whose content or name matches cryptography keywords."""
        crypto_classes: List[str] = []
        seen: set = set()
        for fpath in java_files:
            try:
                text = fpath.read_text(encoding="utf-8", errors="ignore")
            except Exception:
                continue
            for cls_match in _CLASS_RE.finditer(text):
                cls_name = cls_match.group(1)
                if cls_name in seen:
                    continue
                window_start = max(0, cls_match.start() - 20)
                window = text[window_start: min(cls_match.end() + 500, len(text))]
                if _CRYPTO_KEYWORDS.search(cls_name) or _CRYPTO_KEYWORDS.search(window):
                    seen.add(cls_name)
                    crypto_classes.append(cls_name)
        return crypto_classes

    def _find_network_classes(self, java_files: List[Path]) -> List[str]:
        """Return class names whose content or name matches network/HTTP keywords."""
        network_classes: List[str] = []
        seen: set = set()
        for fpath in java_files:
            try:
                text = fpath.read_text(encoding="utf-8", errors="ignore")
            except Exception:
                continue
            for cls_match in _CLASS_RE.finditer(text):
                cls_name = cls_match.group(1)
                if cls_name in seen:
                    continue
                window_start = max(0, cls_match.start() - 20)
                window = text[window_start: min(cls_match.end() + 500, len(text))]
                if _NETWORK_KEYWORDS.search(cls_name) or _NETWORK_KEYWORDS.search(window):
                    seen.add(cls_name)
                    network_classes.append(cls_name)
        return network_classes

    # ── Rule-based analysis ───────────────────────────────────────────────────

    def _rule_based_analysis(
        self, java_files: List[Path], app_model: AppModel
    ) -> List[UnifiedFinding]:
        """
        Scan all source files against _COMPILED_RULES.
        Returns a list of UnifiedFinding objects.
        """
        findings: List[UnifiedFinding] = []
        seen_keys: set = set()

        for fpath in java_files:
            try:
                text = fpath.read_text(encoding="utf-8", errors="ignore")
            except Exception:
                continue

            cls_match = _CLASS_RE.search(text)
            cls_name = cls_match.group(1) if cls_match else fpath.stem

            for pattern, atype, title, severity, cwe, cvss_score, rec in _COMPILED_RULES:
                for match in pattern.finditer(text):
                    line_num = text[: match.start()].count("\n") + 1
                    lines = text.splitlines()
                    ctx_start = max(0, line_num - 3)
                    ctx_end = min(len(lines), line_num + 2)
                    context_snippet = "\n".join(lines[ctx_start:ctx_end])

                    dedup_key = (str(fpath), atype, line_num)
                    if dedup_key in seen_keys:
                        continue
                    seen_keys.add(dedup_key)

                    finding = UnifiedFinding(
                        target=app_model.package_name or str(fpath.name),
                        vulnerability=title,
                        attack_type=atype,
                        tool="mobile_ai_reverse_engineer_rules",
                        severity=severity,
                        evidence=(
                            f"File: {fpath}\nLine: {line_num}\n\n{context_snippet}"
                        ),
                        file_path=str(fpath),
                        line_number=line_num,
                        payload=match.group()[:200],
                        confidence=0.85,
                        cvss=cvss_score,
                        remediation=rec,
                        tags=[atype, cwe, "static_analysis", "mobile"],
                    )

                    # Populate vuln_patterns on app_model
                    app_model.vuln_patterns.append({
                        "class": cls_name,
                        "method": self._nearest_method(text, match.start()),
                        "pattern": atype,
                        "severity": severity,
                    })

                    findings.append(finding)

        return findings

    @staticmethod
    def _nearest_method(text: str, pos: int) -> str:
        """Return the closest method name before position pos."""
        snippet = text[:pos]
        matches = list(_METHOD_RE.finditer(snippet))
        if matches:
            return matches[-1].group(1)
        return "unknown"

    # ── AI analysis ───────────────────────────────────────────────────────────

    def _ai_analyze_batch(
        self, java_files: List[Path], app_model: AppModel
    ) -> List[UnifiedFinding]:
        """
        Select the most security-relevant files and send them to the AI for
        deep analysis.  Returns findings parsed from the AI JSON response.
        """
        priority_names: set = set(
            app_model.auth_classes + app_model.crypto_classes + app_model.network_classes
        )

        prioritized: List[Path] = []
        others: List[Path] = []
        for fpath in java_files:
            if fpath.stem in priority_names:
                prioritized.append(fpath)
            else:
                others.append(fpath)

        selected = (prioritized + others)[: self.config.max_files]

        files_content: List[Tuple[str, str]] = []
        for fpath in selected:
            try:
                content = fpath.read_text(encoding="utf-8", errors="ignore")
                if len(content) > self.config.max_file_size:
                    content = content[: self.config.max_file_size] + "\n// [TRUNCATED]"
                files_content.append((fpath.name, content))
            except Exception:
                continue

        if not files_content:
            return []

        prompt = self._build_ai_prompt(files_content, app_model)

        response = ""
        if self.config.ai_provider == "anthropic" and HAS_ANTHROPIC:
            response = self._call_anthropic(prompt)
        elif HAS_OPENAI:
            response = self._call_openai(prompt)
        elif HAS_ANTHROPIC:
            response = self._call_anthropic(prompt)
        else:
            log.warning("No AI provider available")
            return []

        return self._parse_ai_findings(response, app_model.package_name)

    def _call_anthropic(self, prompt: str) -> str:
        """Call Anthropic Claude and return the text response."""
        client = anthropic.Anthropic()
        message = client.messages.create(
            model=self.config.model,
            max_tokens=4096,
            messages=[{"role": "user", "content": prompt}],
        )
        return message.content[0].text if message.content else ""

    def _call_openai(self, prompt: str) -> str:
        """Call OpenAI and return the text response."""
        client = openai.OpenAI()
        response = client.chat.completions.create(
            model="gpt-4o-mini",
            messages=[{"role": "user", "content": prompt}],
            max_tokens=4096,
            temperature=0.1,
        )
        return response.choices[0].message.content or ""

    def _build_ai_prompt(
        self,
        files_content: List[Tuple[str, str]],
        app_model: AppModel,
    ) -> str:
        """
        Build the AI analysis prompt.  Instructs the model to return a JSON
        array of findings covering hidden endpoints, auth bypasses, admin
        backdoors, crypto issues, and business logic flaws.
        """
        files_section = "\n\n".join(
            f"=== FILE: {name} ===\n{content}"
            for name, content in files_content
        )

        app_context = (
            f"Package: {app_model.package_name}\n"
            f"Auth classes: {', '.join(app_model.auth_classes[:10]) or 'none identified'}\n"
            f"Crypto classes: {', '.join(app_model.crypto_classes[:10]) or 'none identified'}\n"
            f"Network classes: {', '.join(app_model.network_classes[:10]) or 'none identified'}\n"
            f"Known API endpoints: {', '.join(app_model.api_endpoints[:20]) or 'none identified'}\n"
        )

        return f"""You are an expert mobile application security researcher performing a deep static code analysis.

## Application Context
{app_context}

## Source Files to Analyze
{files_section}

## Analysis Instructions
Carefully examine the source code above and identify security vulnerabilities. Focus on:

1. **Hidden API Endpoints** — URL strings not documented, admin/debug endpoints, internal service URLs
2. **Authentication Bypasses** — hardcoded credentials, role checks that can be bypassed, weak token validation, missing auth checks
3. **Hidden Admin / Debug Functionality** — functions gated by secret flags, debug backdoors, test accounts
4. **Insecure Cryptography** — predictable IVs (e.g., all-zero byte arrays), keys derived from constants, weak algorithms
5. **Business Logic Flaws** — price/quantity manipulation (no server-side validation), race conditions, missing authorization on sensitive actions
6. **Token Validation Weaknesses** — JWT alg=none acceptance, missing expiry checks, predictable token generation
7. **Insecure Data Handling** — unencrypted PII in logs, SQL from user input, intent data used without validation

## Output Format
Return ONLY a valid JSON array (no markdown, no explanation) with this exact schema:

[
  {{
    "vulnerability": "Short descriptive title",
    "severity": "critical|high|medium|low",
    "attack_type": "snake_case_type",
    "description": "Detailed explanation of the vulnerability",
    "evidence": "Exact code snippet or class/method reference",
    "remediation": "How to fix this",
    "cwe": "CWE-XXX",  # placeholder shown to AI — it fills in the real CWE ID
    "cvss": 7.5,
    "location": "FileName.java:lineNumber or ClassName.methodName()"
  }}
]

If no findings are identified, return an empty array: []
Do not include any text outside the JSON array.
"""

    def _parse_ai_findings(
        self, response: str, package_name: str
    ) -> List[UnifiedFinding]:
        """Parse the AI JSON response into UnifiedFinding objects."""
        if not response:
            return []

        json_text = response.strip()
        fence_match = re.search(r'```(?:json)?\s*([\s\S]+?)\s*```', json_text)
        if fence_match:
            json_text = fence_match.group(1)
        start = json_text.find("[")
        end = json_text.rfind("]")
        if start == -1 or end == -1:
            log.warning("AI response did not contain a JSON array")
            return []
        json_text = json_text[start: end + 1]

        try:
            items = json.loads(json_text)
        except json.JSONDecodeError as exc:
            log.warning("Failed to parse AI JSON response: %s", exc)
            return []

        findings: List[UnifiedFinding] = []
        valid_severities = {"critical", "high", "medium", "low", "info"}
        for item in items:
            if not isinstance(item, dict):
                continue
            severity = str(item.get("severity", "medium")).lower()
            if severity not in valid_severities:
                severity = "medium"
            try:
                cvss_val = float(item.get("cvss", 0.0))
            except (TypeError, ValueError):
                cvss_val = 0.0

            findings.append(
                UnifiedFinding(
                    target=package_name or "unknown",
                    vulnerability=str(item.get("vulnerability", "AI-Detected Finding")),
                    attack_type=str(item.get("attack_type", "ai_detected")),
                    tool="mobile_ai_reverse_engineer_ai",
                    severity=severity,
                    evidence=str(item.get("evidence", "")),
                    file_path=str(item.get("location", "")),
                    line_number=0,
                    payload="",
                    confidence=0.75,
                    cvss=cvss_val,
                    remediation=str(item.get("remediation", "")),
                    tags=["ai_analysis", str(item.get("cwe", "")), "mobile"],
                )
            )

        return findings

    # ── Scoring ───────────────────────────────────────────────────────────────

    def _calculate_attack_surface_score(self, findings: List[UnifiedFinding]) -> float:
        """
        Compute a 0-10 attack surface score based on finding severity distribution.
        Critical=4, High=3, Medium=2, Low=1, Info=0.1 points each, capped at 10.
        """
        severity_weights = {
            "critical": 4.0,
            "high": 3.0,
            "medium": 2.0,
            "low": 1.0,
            "info": 0.1,
        }
        raw_score = sum(
            severity_weights.get(f.severity.lower(), 0.5) for f in findings
        )
        normalised = min(raw_score / 25.0 * 10.0, 10.0)
        return round(normalised, 2)


# ─────────────────────────────────────────────────────────────────────────────
#  Module singleton
# ─────────────────────────────────────────────────────────────────────────────

mobile_ai_reverse_engineer = MobileAIReverseEngineer()
