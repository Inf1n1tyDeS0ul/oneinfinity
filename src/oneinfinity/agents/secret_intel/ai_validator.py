"""
AI Validation Engine — enriches findings with:
  - severity + confidence  (existing)
  - exploitability (0–1)   (new)
  - blast_radius (LOW/MEDIUM/HIGH/CRITICAL) (new)
  - reasoning              (existing, improved prompt)
"""
import json
import logging
from typing import Dict, Any

logger = logging.getLogger(__name__)

# Fallback blast-radius heuristic when AI is unavailable
_BLAST_RADIUS_BY_TYPE: Dict[str, str] = {
    "aws_access_key_id":     "CRITICAL",
    "aws_secret_access_key": "CRITICAL",
    "gcp_service_account":   "CRITICAL",
    "azure_key":             "CRITICAL",
    "rsa_private_key":       "CRITICAL",
    "ssh_private_key":       "CRITICAL",
    "github_pat":            "HIGH",
    "github_oauth":          "HIGH",
    "stripe_standard":       "HIGH",
    "mongodb_uri":           "HIGH",
    "postgres_uri":          "HIGH",
    "mysql_uri":             "HIGH",
    "redis_uri":             "MEDIUM",
    "openai_api_key":        "MEDIUM",
    "twilio_api_key":        "MEDIUM",
    "sendgrid_api_key":      "MEDIUM",
    "slack_token":           "MEDIUM",
    "google_api":            "LOW",
    "slack_webhook":         "LOW",
    "firebase_url":          "LOW",
}

_EXPLOITABILITY_BY_SEVERITY: Dict[str, float] = {
    "critical": 0.90,
    "high":     0.70,
    "medium":   0.45,
    "low":      0.20,
}


class AIValidationEngine:
    """
    Uses a model orchestrator for contextual validation.
    Falls back gracefully to heuristic values if AI is unavailable.
    """

    def __init__(self, model_orchestrator=None):
        self.orchestrator = model_orchestrator
        self.enabled = model_orchestrator is not None

    def validate(self, finding: Dict[str, Any]) -> Dict[str, Any]:
        if not self.enabled:
            return self._heuristic_enrich(finding, reason="AI validation disabled — model orchestrator not configured")

        snippet      = finding.get("snippet", "")
        secret_type  = finding.get("type", "unknown")
        repo_name    = finding.get("repo", "unknown")
        entropy      = finding.get("entropy", 0.0)
        cross_asset  = finding.get("cross_asset_reuse", False)

        prompt = f"""You are an expert security engineer performing triage on an exposed secret finding.

Secret Type  : {secret_type}
Repository   : {repo_name}
Entropy      : {entropy:.2f}
Cross-Asset  : {"YES — same key found in multiple repos/files" if cross_asset else "No"}

Code Snippet :
```
{snippet[:800]}
```

Apply the following severity logic:
  - Cloud credentials (AWS/GCP/Azure) in public repos               → CRITICAL
  - DB connection strings with credentials                           → CRITICAL
  - Private keys (RSA/SSH/PGP)                                       → CRITICAL
  - Payment keys (Stripe live)                                       → CRITICAL
  - GitHub PAT / OAuth tokens                                        → CRITICAL
  - Same key reused across multiple assets                          → escalate one level
  - Communication/analytics API keys with limited blast radius       → MEDIUM
  - Keys in test/mock/placeholder context (low entropy)              → LOW
  - References to secret variables (e.g. ${{secrets.KEY}})            → skip (not a real secret)

Respond ONLY with a single JSON object — no markdown fences, no explanation outside JSON:
{{
  "severity":        "CRITICAL" | "HIGH" | "MEDIUM" | "LOW",
  "confidence":      <float 0.0–1.0>,
  "exploitability":  <float 0.0–1.0, likelihood attacker can use this credential>,
  "blast_radius":    "CRITICAL" | "HIGH" | "MEDIUM" | "LOW",
  "reasoning":       "<one or two sentences>"
}}"""

        try:
            from oneinfinity.model_orchestrator import ModelTier
            task = {"description": "Validate exposed secret finding", "prompt": prompt}
            response = self.orchestrator.execute(task, force_tier=ModelTier.FAST)

            # Strip accidental markdown fences
            content = response.content.strip()
            if "```" in content:
                # Extract first JSON block
                parts = content.split("```")
                for part in parts:
                    stripped = part.strip().lstrip("json").strip()
                    if stripped.startswith("{"):
                        content = stripped
                        break

            result = json.loads(content)

            finding["ai_validated"]    = True
            finding["severity"]        = result.get("severity", finding.get("severity", "low")).lower()
            finding["confidence"]      = float(result.get("confidence", 0.5))
            finding["exploitability"]  = float(result.get("exploitability", 0.5))
            finding["blast_radius"]    = result.get("blast_radius", "MEDIUM").upper()
            finding["ai_reasoning"]    = result.get("reasoning", "")
            finding["ai_is_real"]      = finding["confidence"] >= 0.5

        except json.JSONDecodeError as exc:
            logger.warning("AI response was not valid JSON: %s — falling back to heuristics.", exc)
            return self._heuristic_enrich(finding, reason=f"AI JSON parse error: {exc}")

        except Exception as exc:
            logger.warning("AI validation failed: %s — falling back to heuristics.", exc)
            return self._heuristic_enrich(finding, reason=f"AI error: {exc}")

        return finding

    # ── Heuristic fallback ────────────────────────────────────────────────────

    def _heuristic_enrich(self, finding: Dict[str, Any], reason: str = "") -> Dict[str, Any]:
        """
        Populate exploitability and blast_radius using static heuristics when
        the AI model is unavailable.  Never blocks the pipeline.
        """
        stype    = finding.get("type", "generic_api_key")
        severity = finding.get("severity", "low").lower()

        finding.setdefault("ai_validated", False)
        finding.setdefault("ai_is_real", finding.get("confidence", 0.0) >= 0.5)
        finding["ai_reasoning"]   = reason or "Heuristic enrichment (no AI)"
        finding["exploitability"] = _EXPLOITABILITY_BY_SEVERITY.get(severity, 0.3)
        finding["blast_radius"]   = _BLAST_RADIUS_BY_TYPE.get(stype, "LOW")

        # If cross-asset reuse, bump blast_radius
        if finding.get("cross_asset_reuse"):
            order = ["LOW", "MEDIUM", "HIGH", "CRITICAL"]
            current = finding["blast_radius"]
            idx = order.index(current) if current in order else 0
            finding["blast_radius"] = order[min(idx + 1, len(order) - 1)]

        return finding
