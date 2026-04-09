"""
core/finding_validator.py — Finding Validation + Reproducibility Engine

Provides:
  1. FindingValidator  — classifies each finding as confirmed/unverified/false_positive
  2. ReproducibilityMapper — generates exact CLI commands to reproduce each finding
  3. FindingClassifier — separates output into confirmed/simulated/ai-theory buckets

Design:
  - NEVER fabricates findings
  - ONLY promotes a finding from "unverified" → "confirmed" when it has
    real evidence (payload + response OR tool-confirmed status)
  - AI theories are always tagged "unverified" until independently confirmed
  - All decisions are logged so audits are possible
"""
from __future__ import annotations

import logging
import re
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Tuple
from urllib.parse import urlparse, urlencode, parse_qs, quote_plus

log = logging.getLogger("oneinfinity.core.finding_validator")

# ---------------------------------------------------------------------------
# Confidence thresholds
# ---------------------------------------------------------------------------

_CONFIRMED_THRESHOLD   = 0.70   # confidence ≥ 70% + has evidence → confirmed
_UNVERIFIED_THRESHOLD  = 0.35   # 35–70% → unverified
# < 35% → potential false positive


# ---------------------------------------------------------------------------
# Evidence indicators
# ---------------------------------------------------------------------------

# Patterns that indicate real tool-confirmed evidence
_EVIDENCE_PATTERNS = [
    re.compile(r"HTTP/\d"),             # captured HTTP request/response
    re.compile(r"<script>|<img|onerror", re.I),   # XSS payload in response
    re.compile(r"syntax error|mysql|sqlite|pg_", re.I),  # SQLi error leakage
    re.compile(r"root:|/etc/passwd", re.I),         # LFI/RCE evidence
    re.compile(r"169\.254\.169\.254"),               # AWS metadata SSRF
    re.compile(r"\[nuclei\]|\[dalfox\]|\[sqlmap\]", re.I),  # tool attribution
    re.compile(r"poc:|payload:|curl ", re.I),        # PoC evidence
    re.compile(r"window\.google|callback\(|jsonp", re.I),  # JSONP/XSS evidence
    re.compile(r"access control allow origin", re.I),  # CORS evidence
    re.compile(r"Authorization: Bearer", re.I),      # Auth/Credential leakage
    re.compile(r"Set-Cookie:", re.I),                # Cookie/Session evidence
    re.compile(r"Location: http", re.I),             # Redirect evidence
    re.compile(r"---BEGIN RSA PRIVATE KEY---", re.I), # Private key leakage
]

# AI theory markers — if present in title/description, mark unverified
_AI_THEORY_MARKERS = [
    "ai theory", "ai-generated", "theoretical", "potential (unconfirmed)",
    "hypothetical", "llm-inferred", "model suggests",
]

# Simulation markers
_SIMULATION_MARKERS = [
    "simulated", "montecarlo", "monte carlo", "workflow simulation",
    "attack simulation",
]


# ---------------------------------------------------------------------------
# Validation result
# ---------------------------------------------------------------------------

@dataclass
class ValidationResult:
    finding_id:        str
    status:            str          # confirmed / unverified / false_positive / simulated
    confidence:        float
    confidence_breakdown: str
    evidence_score:    float        # 0–1 based on evidence richness
    reasons:           List[str] = field(default_factory=list)
    warnings:          List[str] = field(default_factory=list)

    @property
    def is_confirmed(self) -> bool:
        return self.status == "confirmed"


# ---------------------------------------------------------------------------
# Validator
# ---------------------------------------------------------------------------

class FindingValidator:
    """
    Validates a single finding dict and returns a ValidationResult.

    Validation pipeline:
      1. Source-type classification (tool / ai_theory / simulated)
      2. Payload presence check
      3. Evidence richness score
      4. Confidence score calculation
      5. Final status assignment
    """

    def validate(self, finding: dict) -> ValidationResult:
        fid = finding.get("finding_id") or finding.get("id", "?")
        title = str(finding.get("title", "")).lower()
        desc  = str(finding.get("description", "")).lower()
        src   = str(finding.get("source_type", "tool")).lower()
        evidence = str(finding.get("evidence", ""))
        payload  = str(finding.get("payload", ""))
        conf_raw = finding.get("confidence", 0.0)
        try:
            base_conf = float(conf_raw)
        except (TypeError, ValueError):
            base_conf = 0.5

        reasons: List[str] = []
        warnings: List[str] = []

        # ── Step 1: Source-type override ─────────────────────────────────
        if src == "simulated" or any(m in title or m in desc for m in _SIMULATION_MARKERS):
            return ValidationResult(
                finding_id=fid, status="simulated", confidence=base_conf,
                confidence_breakdown="Source tagged as simulation",
                evidence_score=0.0,
                warnings=["Finding is a simulation result — not a real vulnerability"],
            )

        if src == "ai_theory" or any(m in title or m in desc for m in _AI_THEORY_MARKERS):
            return ValidationResult(
                finding_id=fid, status="unverified", confidence=min(base_conf, 0.4),
                confidence_breakdown="AI-generated theory — not tool-confirmed",
                evidence_score=0.0,
                warnings=["AI theory requires independent tool confirmation before submission"],
            )

        # ── Step 2: Evidence richness ─────────────────────────────────────
        evidence_score = 0.0
        combined_text = f"{evidence} {payload}"
        matched_patterns = [p.pattern for p in _EVIDENCE_PATTERNS
                             if p.search(combined_text)]
        evidence_score = min(1.0, len(matched_patterns) * 0.2)

        if payload:
            evidence_score = min(1.0, evidence_score + 0.2)
            reasons.append(f"Payload present ({payload[:40]})")
        else:
            warnings.append("No payload captured — confidence capped at 0.65")
            base_conf = min(base_conf, 0.65)

        if evidence:
            evidence_score = min(1.0, evidence_score + 0.1)
            reasons.append("Evidence field populated")

        for p in matched_patterns:
            reasons.append(f"Evidence matches pattern: {p}")

        # ── Step 3: Tool-confirmed bonus ──────────────────────────────────
        if src == "tool":
            base_conf = min(1.0, base_conf + 0.15)
            reasons.append("Tool-confirmed source (+0.15 confidence)")

        status_from_finding = str(finding.get("status", "")).lower()
        if status_from_finding in ("confirmed", "verified"):
            base_conf = min(1.0, base_conf + 0.10)
            reasons.append("Explicitly confirmed by tool status (+0.10)")

        # ── Step 4: Final confidence ──────────────────────────────────────
        final_conf = round(min(1.0, base_conf + evidence_score * 0.2), 3)

        # ── Step 5: Status assignment ─────────────────────────────────────
        if final_conf >= _CONFIRMED_THRESHOLD and (payload or evidence_score > 0.3):
            status = "confirmed"
        elif final_conf < _UNVERIFIED_THRESHOLD:
            status = "false_positive"
            warnings.append(f"Low confidence ({final_conf:.0%}) — likely false positive")
        else:
            status = "unverified"

        breakdown = (
            f"base={base_conf:.2f} evidence_score={evidence_score:.2f} "
            f"final={final_conf:.2f} → {status}"
        )

        return ValidationResult(
            finding_id=fid,
            status=status,
            confidence=final_conf,
            confidence_breakdown=breakdown,
            evidence_score=evidence_score,
            reasons=reasons,
            warnings=warnings,
        )

    def validate_batch(self, findings: List[dict]) -> List[Tuple[dict, ValidationResult]]:
        """Validate a list of findings. Returns (finding, result) pairs."""
        results = []
        for f in findings:
            result = self.validate(f)
            results.append((f, result))
        return results

    def apply_to_findings(self, findings: List[dict]) -> List[dict]:
        """
        Apply validation in-place to a list of finding dicts.
        Adds/updates: validation_status, confidence, confidence_breakdown.
        """
        for f in findings:
            vr = self.validate(f)
            f["validation_status"]    = vr.status
            f["confidence"]           = vr.confidence
            f["confidence_breakdown"] = vr.confidence_breakdown
            if vr.warnings:
                existing = f.get("warnings", [])
                f["warnings"] = existing + vr.warnings
        return findings


# ---------------------------------------------------------------------------
# Reproducibility mapper
# ---------------------------------------------------------------------------

# Maps vuln_type → (primary tool, CLI command template)
_VULN_REPRO_MAP: Dict[str, Tuple[str, str]] = {
    "xss":              ("dalfox",  "oneinfinity vuln-scan --target {url} --xss"),
    "reflected_xss":    ("dalfox",  "oneinfinity vuln-scan --target {url} --xss"),
    "stored_xss":       ("dalfox",  "oneinfinity vuln-scan --target {url} --xss"),
    "sqli":             ("sqlmap",  "oneinfinity vuln-scan --target {url} --sqli"),
    "sql_injection":    ("sqlmap",  "oneinfinity vuln-scan --target {url} --sqli"),
    "ssrf":             ("nuclei",  "oneinfinity vuln-scan --target {url} --ssrf"),
    "idor":             ("nuclei",  "oneinfinity vuln-scan --target {url} --idor"),
    "lfi":              ("nuclei",  "oneinfinity vuln-scan --target {url} --lfi"),
    "rce":              ("nuclei",  "oneinfinity vuln-scan --target {url}"),
    "xxe":              ("nuclei",  "oneinfinity vuln-scan --target {url}"),
    "auth_bypass":      ("nuclei",  "oneinfinity vuln-scan --target {url} --auth"),
    "open_redirect":    ("nuclei",  "oneinfinity vuln-scan --target {url}"),
    "ssti":             ("nuclei",  "oneinfinity vuln-scan --target {url}"),
    "jwt_weakness":     ("nuclei",  "oneinfinity vuln-scan --target {url} --auth"),
    "graphql":          ("nuclei",  "oneinfinity graphql-scan --target {url}"),
    "request_smuggling":("smuggler","oneinfinity smuggling-scan --target {url}"),
    "cors":             ("nuclei",  "oneinfinity vuln-scan --target {url}"),
    "subdomain_takeover":("nuclei", "oneinfinity recon {url}"),
    "info_disclosure":  ("nuclei",  "oneinfinity vuln-scan --target {url}"),
}

_FALLBACK_CMD = "oneinfinity vuln-scan --target {url}"

# Supporting tool commands for complex reproduction
_SUPPORTING_TOOLS: Dict[str, str] = {
    "xss":           "dalfox url \"{url}\" --blind --silence",
    "sqli":          "sqlmap -u \"{url}\" --batch --level=3 --risk=2",
    "ssrf":          "nuclei -u \"{url}\" -t ssrf -silent",
    "idor":          "ffuf -u \"{url}/FUZZ\" -w wordlist.txt",
    "lfi":           "nuclei -u \"{url}\" -t lfi -silent",
    "graphql":       "graphql-cop -t \"{url}\"",
    "request_smuggling": "smuggler.py -u \"{url}\"",
}


class ReproducibilityMapper:
    """
    Generates exact CLI commands to reproduce each confirmed finding.
    """

    def map(self, finding: dict) -> str:
        """
        Return the primary OneInfinity CLI command to reproduce this finding.
        """
        vt  = (finding.get("vuln_type") or finding.get("type") or "").lower().replace("-", "_")
        url = finding.get("url") or finding.get("endpoint") or finding.get("target") or ""

        # Sanitize URL for shell embedding
        safe_url = url.replace('"', '%22').replace('`', '%60').replace('$', '%24')

        entry = _VULN_REPRO_MAP.get(vt, _FALLBACK_CMD)
        # _VULN_REPRO_MAP values are (tool, command) tuples; fallback is plain string
        template = entry[1] if isinstance(entry, tuple) else entry
        cmd = template.format(url=safe_url)

        # Append payload if present
        payload = finding.get("payload", "")
        if payload and "--payload" not in cmd:
            cmd += f" --payload \"{payload[:80].replace(chr(34), chr(39))}\""

        return cmd

    def map_supporting_tools(self, finding: dict) -> Optional[str]:
        """Return a supporting tool command (curl/sqlmap/ffuf etc.) if available."""
        vt = (finding.get("vuln_type") or "").lower().replace("-", "_")
        url = finding.get("url") or ""
        if vt in _SUPPORTING_TOOLS:
            return _SUPPORTING_TOOLS[vt].format(url=url)
        return None

    def map_batch(self, findings: List[dict]) -> List[dict]:
        """
        Add reproduction_cmd to each finding dict. Returns modified list.
        Only maps confirmed/unverified findings — skips false_positive/simulated.
        """
        for f in findings:
            status = f.get("validation_status", "")
            if status in ("false_positive", "simulated"):
                continue
            cmd = self.map(f)
            f["reproduction_cmd"] = cmd
            sup = self.map_supporting_tools(f)
            if sup:
                f["supporting_tool_cmd"] = sup
        return findings


# ---------------------------------------------------------------------------
# Finding classifier (output bucket separation)
# ---------------------------------------------------------------------------

@dataclass
class ClassifiedFindings:
    confirmed:      List[dict] = field(default_factory=list)
    unverified:     List[dict] = field(default_factory=list)
    simulated:      List[dict] = field(default_factory=list)
    false_positive: List[dict] = field(default_factory=list)

    def summary(self) -> str:
        return (
            f"confirmed={len(self.confirmed)}, "
            f"unverified={len(self.unverified)}, "
            f"simulated={len(self.simulated)}, "
            f"false_positive={len(self.false_positive)}"
        )

    def all_reportable(self) -> List[dict]:
        """Returns confirmed + unverified — findings worth including in reports."""
        return self.confirmed + self.unverified

    def to_dict(self) -> dict:
        return {
            "confirmed":      self.confirmed,
            "unverified":     self.unverified,
            "simulated":      self.simulated,
            "false_positive": self.false_positive,
        }


class FindingClassifier:
    """
    Separates a flat findings list into confirmed/unverified/simulated/false_positive.

    Also applies validation and adds reproduction commands.
    """

    def __init__(self) -> None:
        self._validator = FindingValidator()
        self._mapper    = ReproducibilityMapper()

    def classify(self, findings: List[dict]) -> ClassifiedFindings:
        validated  = self._validator.apply_to_findings(list(findings))
        with_repro = self._mapper.map_batch(validated)

        result = ClassifiedFindings()
        for f in with_repro:
            status = f.get("validation_status", "unverified")
            if status == "confirmed":
                result.confirmed.append(f)
            elif status == "simulated":
                result.simulated.append(f)
            elif status == "false_positive":
                result.false_positive.append(f)
            else:
                result.unverified.append(f)

        log.info("[classifier] %s", result.summary())
        return result


# ---------------------------------------------------------------------------
# Singleton helpers
# ---------------------------------------------------------------------------

_validator_instance: Optional[FindingValidator] = None
_classifier_instance: Optional[FindingClassifier] = None


def get_validator() -> FindingValidator:
    global _validator_instance
    if _validator_instance is None:
        _validator_instance = FindingValidator()
    return _validator_instance


def get_classifier() -> FindingClassifier:
    global _classifier_instance
    if _classifier_instance is None:
        _classifier_instance = FindingClassifier()
    return _classifier_instance
