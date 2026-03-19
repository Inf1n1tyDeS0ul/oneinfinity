"""
Secret Detector — production-hardened with:
  - Adaptive entropy thresholds (3.8 base, scales with string length up to 4.5)
  - value_hash field (SHA-256 of raw secret, safe to store — no plaintext)
  - Richer false-positive filtering
"""
import re
import math
import hashlib
import logging
from typing import List, Dict, Any

logger = logging.getLogger(__name__)

# ── Pattern registry ──────────────────────────────────────────────────────────
SECRET_PATTERNS = {
    "aws_access_key_id":       re.compile(r"(?i)(?:aws_access_key_id|aws_access_key|access_key).*?['\"]?(AKIA[0-9A-Z]{16})['\"]?"),
    "aws_secret_access_key":   re.compile(r"(?i)(?:aws_secret_access_key|aws_secret_key|secret_key).*?['\"]([0-9a-zA-Z/+]{40})['\"]"),
    "azure_key":               re.compile(r"AccountKey=([A-Za-z0-9+/=]{64,})"),
    "github_pat":              re.compile(r"(github_pat_[0-9a-zA-Z]{36}|ghp_[0-9a-zA-Z]{36})"),
    "github_oauth":            re.compile(r"(gho_[0-9a-zA-Z]{36})"),
    "github_action_secret":    re.compile(r"\${{\s*secrets\.([A-Z0-9_]+)\s*}}"),
    "google_api":              re.compile(r"(AIza[0-9A-Za-z\-_]{35})"),
    "google_oauth":            re.compile(r"(ya29\.[0-9A-Za-z\-_]+)"),
    "gcp_service_account":     re.compile(
        r"(?i)(?:gcp_credentials|google_application_credentials).*?['\"]?({.*?private_key.*?})['\"]?",
        re.DOTALL,
    ),
    "stripe_standard":         re.compile(r"(sk_live_[0-9a-zA-Z]{24})"),
    "stripe_restricted":       re.compile(r"(rk_live_[0-9a-zA-Z]{24})"),
    "twilio_api_key":          re.compile(r"(SK[0-9a-fA-F]{32})"),
    "sendgrid_api_key":        re.compile(r"(SG\.[0-9a-zA-Z\-_]{22}\.[0-9a-zA-Z\-_]{43})"),
    "slack_token":             re.compile(r"(xox[baprs]-[0-9]{12}-[0-9]{12}-[0-9a-zA-Z]{24})"),
    "openai_api_key":          re.compile(r"(sk-[a-zA-Z0-9]{48})"),
    "huggingface_token":       re.compile(r"(hf_[a-zA-Z0-9]{34})"),
    "slack_webhook":           re.compile(
        r"(https://hooks\.slack\.com/services/T[a-zA-Z0-9_]{8}/B[a-zA-Z0-9_]{8}/[a-zA-Z0-9_]{24})"
    ),
    "firebase_url":            re.compile(r"([\w-]+\.firebaseio\.com)"),
    "firebase_server_key":     re.compile(r"(AAAA[A-Za-z0-9_-]{7}:[A-Za-z0-9_-]{140})"),
    "mongodb_uri":             re.compile(r"(?i)(mongodb(?:\+srv)?://[^\s'\"]{10,})"),
    "postgres_uri":            re.compile(r"(?i)(postgres(?:ql)?://[^\s'\"]{10,})"),
    "mysql_uri":               re.compile(r"(?i)(mysql://[^\s'\"]{10,})"),
    "redis_uri":               re.compile(r"(?i)(redis[s]?://[^\s'\"]{6,})"),
    "rsa_private_key":         re.compile(
        r"(-----BEGIN RSA PRIVATE KEY-----.*?-----END RSA PRIVATE KEY-----)", re.DOTALL
    ),
    "ssh_private_key":         re.compile(
        r"(-----BEGIN OPENSSH PRIVATE KEY-----.*?-----END OPENSSH PRIVATE KEY-----)", re.DOTALL
    ),
    "generic_private_key":     re.compile(
        r"(-----BEGIN PRIVATE KEY-----.*?-----END PRIVATE KEY-----)", re.DOTALL
    ),
    "generic_api_key":         re.compile(
        r"(?i)(?:api_key|apikey|secret|token|password|passwd|pwd)[\s]*[:=][\s]*['\"]([a-zA-Z0-9\-_=+\/]{16,64})['\"]"
    ),
}

# Highly specific types: pattern prefix alone (AKIA, sk_live_, etc.) virtually guarantees
# a real credential format — skip all entropy/keyword FP filters for these.
_HIGH_SPECIFICITY_TYPES = frozenset([
    "aws_access_key_id", "aws_secret_access_key",
    "github_pat", "github_oauth",
    "google_api", "google_oauth",
    "gcp_service_account",
    "stripe_standard", "stripe_restricted",
    "twilio_api_key", "sendgrid_api_key",
    "slack_token", "openai_api_key", "huggingface_token",
    "slack_webhook", "firebase_server_key",
    "rsa_private_key", "ssh_private_key", "generic_private_key",
])

# Structured/multi-line types: entropy is meaningless, skip entropy gate
_STRUCTURED_TYPES = {"gcp_service_account", "rsa_private_key", "ssh_private_key", "generic_private_key"}

# ── Entropy helpers ───────────────────────────────────────────────────────────

def shannon_entropy(data: str) -> float:
    """Shannon entropy (bits) of *data*."""
    if not data:
        return 0.0
    freq = {}
    for ch in data:
        freq[ch] = freq.get(ch, 0) + 1
    n = len(data)
    return -sum((c / n) * math.log2(c / n) for c in freq.values())


def adaptive_entropy_threshold(value: str) -> float:
    """
    Compute the minimum entropy a secret of this length must have to pass.

    Rationale:
      - Short strings (≤20 chars) need entropy ≥ 3.8 — low bar because they are
        naturally less entropic but still may be real tokens.
      - Long strings (≥100 chars) need entropy ≥ 4.5 — high bar because long
        high-entropy strings that are real secrets always exceed this; long low-
        entropy strings are typically prose or base64-padded noise.
      - Linear interpolation between the two endpoints.
    """
    base = 3.8
    ceil = 4.5
    if len(value) <= 20:
        return base
    # Slope: (4.5 - 3.8) / (100 - 20) = 0.00875 per char
    return min(ceil, base + (len(value) - 20) * (ceil - base) / 80)


# ── False-positive keyword sets ───────────────────────────────────────────────
_FP_VALUE_KEYWORDS = frozenset([
    "placeholder", "example", "your_", "insert", "fake", "dummy", "xxxx",
    "changeme", "replace", "none", "null", "undefined", "todo", "fixme",
    "your-", "<your", "<insert", "1234567890", "abcdefgh",
])
_FP_CONTEXT_KEYWORDS = frozenset(["test", "mock", "sample", "demo", "fixture", "spec"])
_OBVIOUS_WEAK_VALUES = frozenset(["test", "12345", "password", "secret", "admin", "root"])


class SecretDetector:
    """Scans text content for exposed secrets using regex patterns + adaptive entropy."""

    def __init__(self):
        self.patterns = SECRET_PATTERNS

    def scan_content(
        self,
        content: str,
        file_path: str = "",
        include_raw_value: bool = False,
    ) -> List[Dict[str, Any]]:
        """
        Scan *content* for secrets.  Each finding includes:
          - type, value_preview, value_hash, line_number, file_path, snippet, entropy

        Parameters
        ----------
        include_raw_value
            When True, the plaintext secret is added as ``_raw_value`` so that
            the live validation engine can verify it.  Callers MUST strip this
            field before persisting findings to any store.
        """
        findings: List[Dict[str, Any]] = []
        if not content:
            return findings

        lines = content.split("\n")

        for name, pattern in self.patterns.items():
            for match in pattern.finditer(content):
                # Prefer capturing group 1 (the credential itself), fall back to full match
                try:
                    secret_value = match.group(1)
                except IndexError:
                    secret_value = match.group(0)

                if not secret_value:
                    continue

                # Line number (0-indexed → 1-indexed)
                line_idx = content.count("\n", 0, match.start())
                start_line = max(0, line_idx - 2)
                end_line = min(len(lines), line_idx + 3)
                snippet = "\n".join(lines[start_line:end_line])

                entropy = shannon_entropy(secret_value)

                if self._is_likely_false_positive(name, secret_value, snippet, entropy):
                    continue

                # Safe preview — never store the full secret in findings
                if len(secret_value) > 8:
                    preview = f"{secret_value[:4]}...{secret_value[-4:]}"
                else:
                    preview = secret_value[:2] + "..." if len(secret_value) > 2 else secret_value

                # Stable hash for deduplication (SHA-256 of raw value, hex-truncated)
                value_hash = hashlib.sha256(secret_value.encode("utf-8", errors="replace")).hexdigest()

                entry: Dict[str, Any] = {
                    "type":          name,
                    "value_preview": preview,
                    "value_hash":    value_hash,
                    "line_number":   line_idx + 1,
                    "file_path":     file_path,
                    "snippet":       snippet,
                    "entropy":       round(entropy, 3),
                }
                # _raw_value is pipeline-internal; MUST be stripped before persist
                if include_raw_value:
                    entry["_raw_value"] = secret_value
                findings.append(entry)

        return findings

    # ── False-positive filtering ─────────────────────────────────────────────

    def _is_likely_false_positive(
        self,
        secret_type: str,
        value: str,
        context: str,
        entropy: float,
    ) -> bool:
        """Return True if this match is almost certainly not a real credential.

        Design note: high-specificity types (AWS, Stripe, GitHub PAT, etc.) bypass
        all keyword and entropy filters — their pattern prefix (AKIA, sk_live_, ghp_)
        is strong enough evidence on its own.  Only catch-all types like
        ``generic_api_key`` are subject to the full filter stack.
        """
        # High-specificity prefix patterns need no further validation
        if secret_type in _HIGH_SPECIFICITY_TYPES:
            return False

        # GitHub action secret references (${{ secrets.X }}) are variable refs, not literals
        if secret_type == "github_action_secret":
            return True

        lowered = value.lower()

        # 1. Obvious placeholder/example values (catch-all types only)
        if any(kw in lowered for kw in _FP_VALUE_KEYWORDS):
            return True

        # 2. Obviously weak literal values
        if lowered in _OBVIOUS_WEAK_VALUES:
            return True

        # 3. Adaptive entropy gate for non-structured catch-all types
        if secret_type not in _STRUCTURED_TYPES:
            threshold = adaptive_entropy_threshold(value)
            if entropy < threshold:
                logger.debug(
                    "FP filter: %s entropy=%.2f < threshold=%.2f value='%s...'",
                    secret_type, entropy, threshold, value[:10],
                )
                return True

        # 4. Explicit test-file context + obviously-weak value
        ctx_lower = context.lower()
        is_test_ctx = any(kw in ctx_lower for kw in _FP_CONTEXT_KEYWORDS) and "prod" not in ctx_lower
        if is_test_ctx and lowered in _OBVIOUS_WEAK_VALUES:
            return True

        return False
