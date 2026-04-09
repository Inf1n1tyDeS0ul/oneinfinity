"""
SecretScorer — ownership-aware, validation-backed severity engine.

Severity matrix
---------------
                        live_verified=True      live_verified=False
  ownership HIGH        CRITICAL                type-based base
  ownership MEDIUM      HIGH                    type-based base
  ownership LOW         HIGH (not CRITICAL)     capped at LOW for generic types,
                                                one tier down for high-specificity

High-specificity types (pattern prefix virtually guarantees a real credential):
  aws_access_key_id, aws_secret_access_key, gcp_service_account, azure_key,
  github_pat, github_oauth, stripe_standard, rsa_private_key, ssh_private_key

These always retain their base severity in third-party repos (never auto-LOW).
Generic types (generic_api_key, google_api, etc.) are capped at LOW when
ownership confidence is LOW, because keyword-matching alone is unreliable.
"""

from typing import Dict, Any

_TIERS = ["low", "medium", "high", "critical"]

# Base severity by secret type (fallback when ownership/validation unavailable)
SEVERITY_MAP: Dict[str, str] = {
    # Critical — direct cloud / infra compromise or high financial risk
    "aws_access_key_id":      "critical",
    "aws_secret_access_key":  "critical",
    "gcp_service_account":    "critical",
    "azure_key":              "critical",
    "stripe_standard":        "critical",
    "rsa_private_key":        "critical",
    "ssh_private_key":        "critical",
    "github_pat":             "critical",
    "github_oauth":           "critical",

    # High — database access, communication abuse, moderate financial risk
    "mongodb_uri":            "high",
    "postgres_uri":           "high",
    "mysql_uri":              "high",
    "redis_uri":              "high",
    "twilio_api_key":         "high",
    "sendgrid_api_key":       "high",
    "slack_token":            "high",
    "openai_api_key":         "high",
    "huggingface_token":      "high",

    # Medium — limited impact, generic APIs
    "stripe_restricted":      "medium",
    "google_api":             "medium",
    "google_oauth":           "medium",
    "firebase_url":           "medium",
    "slack_webhook":          "medium",
    "github_action_secret":   "medium",

    # Low — informational
    "generic_api_key":        "low",
}

# Types whose pattern prefix alone strongly implies a real credential
_HIGH_SPECIFICITY: frozenset = frozenset([
    "aws_access_key_id", "aws_secret_access_key",
    "gcp_service_account", "azure_key",
    "stripe_standard", "stripe_restricted",
    "github_pat", "github_oauth",
    "rsa_private_key", "ssh_private_key", "generic_private_key",
    "twilio_api_key", "sendgrid_api_key",
    "openai_api_key", "huggingface_token",
    "slack_token",
])

# Context phrases that suggest a test / non-production credential
_TEST_PHRASES = frozenset([
    "test", "demo", "example", "dummy", "placeholder",
    "mock", "sample", "fixture", "fake",
])


def _tier_up(severity: str, steps: int = 1) -> str:
    idx = _TIERS.index(severity) if severity in _TIERS else 0
    return _TIERS[min(idx + steps, len(_TIERS) - 1)]


def _tier_down(severity: str, steps: int = 1) -> str:
    idx = _TIERS.index(severity) if severity in _TIERS else 0
    return _TIERS[max(idx - steps, 0)]


def calculate_severity(
    secret_type: str,
    ownership_confidence: str,
    live_verified: bool,
    snippet: str = "",
) -> str:
    """
    Compute final severity from (secret type, ownership, live validation).

    Parameters
    ----------
    secret_type          : detector type name (e.g. "aws_access_key_id")
    ownership_confidence : "HIGH" | "MEDIUM" | "LOW"
    live_verified        : True if the credential was confirmed active
    snippet              : surrounding code context (for test-env downgrade)

    Returns
    -------
    "critical" | "high" | "medium" | "low"
    """
    conf_upper = ownership_confidence.upper()

    # ── Context analysis ──────────────────────────────────────────────────────
    ctx = snippet.lower()
    is_test_ctx = any(kw in ctx for kw in _TEST_PHRASES) and "prod" not in ctx
    is_prod_ctx = ("prod" in ctx or "live" in ctx or "production" in ctx) and not is_test_ctx

    # ── Live-validated paths ───────────────────────────────────────────────────
    if live_verified:
        if conf_upper == "HIGH":
            return "low" if is_test_ctx else "critical"
        # MEDIUM or LOW ownership but confirmed live
        return "low" if is_test_ctx else "high"

    # ── Not live-validated — use type-based base + ownership adjustment ────────
    base = SEVERITY_MAP.get(secret_type, "low")

    if is_test_ctx:
        base = _tier_down(base)  # downgrade by one tier for test context

    if conf_upper == "HIGH":
        # First-party repo: keep base severity (it's already accurate)
        return base

    if conf_upper == "MEDIUM":
        # Third-party but domain used at runtime — retain base, slight nudge down
        # for generic types only
        if secret_type not in _HIGH_SPECIFICITY:
            return _tier_down(base)
        return base

    # LOW confidence — third-party with weak signal
    if secret_type in _HIGH_SPECIFICITY:
        # Real credential format in someone else's repo → one tier down, UNLESS it's a
        # clear production context (prod/live in snippet) which restores full severity.
        if is_prod_ctx:
            return base
        return _tier_down(base)
    else:
        # Generic type in unrelated repo → low normally, but tier-up if prod context
        if is_prod_ctx:
            return _tier_up("low")  # low → medium
        return "low"


class SecretScorer:
    """Evaluates risk and severity of exposed secrets."""

    def score(self, finding: Dict[str, Any]) -> Dict[str, Any]:
        """
        Assign severity, confidence, and impact to a finding.

        Uses ownership_confidence and live_verified (set by the ownership engine
        and validation engine respectively) when present; falls back to
        type-based heuristics for backward compatibility.
        """
        secret_type          = finding.get("type", "generic_api_key")
        snippet              = finding.get("snippet", "")
        ownership_confidence = finding.get("ownership_confidence", "LOW")
        live_verified        = finding.get("live_verified", False)

        severity = calculate_severity(
            secret_type,
            ownership_confidence,
            live_verified,
            snippet,
        )

        # Confidence score (used by AI validation gate and final filtering)
        confidence = 0.8 if secret_type in _HIGH_SPECIFICITY else 0.5

        # Context adjustments to confidence (mirrors legacy scorer behaviour)
        ctx = snippet.lower()
        if any(kw in ctx for kw in _TEST_PHRASES) and "prod" not in ctx:
            confidence -= 0.3
        if "prod" in ctx or "live" in ctx:
            confidence += 0.1
        if live_verified:
            confidence = min(1.0, confidence + 0.2)
        if ownership_confidence == "HIGH":
            confidence = min(1.0, confidence + 0.1)

        confidence = max(0.0, min(1.0, confidence))

        finding["severity"]   = severity
        finding["confidence"] = confidence
        finding["impact"]     = self._generate_impact_statement(secret_type)
        return finding

    @staticmethod
    def _generate_impact_statement(secret_type: str) -> str:
        _IMPACTS = {
            "aws_access_key_id":     "Potential unauthorized access to AWS infrastructure leading to data exfiltration or resource hijacking.",
            "aws_secret_access_key": "Potential unauthorized access to AWS infrastructure leading to data exfiltration or resource hijacking.",
            "github_pat":            "Potential compromise of source code, supply chain attacks, or unauthorized modifications to repositories.",
            "stripe_standard":       "Potential unauthorized financial transactions, refunds, or exposure of customer payment metadata.",
            "twilio_api_key":        "Potential abuse of communication services (SMS/Voice) leading to financial loss or phishing campaigns.",
            "openai_api_key":        "Potential resource exhaustion and financial loss via unauthorized API consumption.",
            "mongodb_uri":           "Direct access to backend database potentially leading to total data compromise or ransomware.",
            "ssh_private_key":       "Potential unauthorized remote access to underlying servers or infrastructure.",
            "gcp_service_account":   "Potential access to GCS, BigQuery, Pub/Sub, and other GCP services bound to this service account.",
            "azure_key":             "Potential read/write access to Azure Blob Storage containers and queues.",
            "postgres_uri":          "Potential read access to all tables visible to the connection user; possible schema alteration.",
            "redis_uri":             "Potential access to in-memory sessions, PII, or job queues; possible RCE in unpatched Redis.",
            "sendgrid_api_key":      "Potential bulk email abuse for phishing using a trusted sending domain.",
            "slack_token":           "Potential read access to all channels; possible exfiltration of messages and files.",
        }
        return _IMPACTS.get(
            secret_type,
            "Potential unauthorized access to associated services or data exposure.",
        )
