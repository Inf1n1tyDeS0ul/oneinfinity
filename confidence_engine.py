"""
confidence_engine.py — Multi-factor confidence scoring for OneInfinity findings.

Scoring model:
  Base confidence is set by source_type:
    tool      → 0.80  (scanner confirmed)
    manual    → 0.75  (analyst-added)
    simulated → 0.55  (simulation engine)
    ai_theory → 0.40  (AI hypothesis)

  Modifiers applied on top:
    +0.10 — evidence string ≥ 50 chars (non-trivial)
    +0.10 — multiple tools agree on same vuln_type
    +0.10 — CVSS ≥ 8.0 (high-impact pattern found)
    +0.15 — validation_status == "confirmed"
    -0.20 — validation_status == "rejected"
    +0.05 — HTTP status code evidence present
    +0.05 — payload attached (reproducible)
    -0.10 — confidence < 0.5 in original finding

  Final score clamped to [0.10, 1.00].

Severity auto-upgrade rules:
  confirmed + CVSS ≥ 9.0  → escalate to critical (if not already)
  confirmed + CVSS ≥ 7.0  → escalate to high     (if medium or below)
  rejected                → downgrade to info and mark false_positive

Usage:
    engine = ConfidenceEngine()
    updated = engine.score_findings(findings)
"""
from __future__ import annotations

import logging
from dataclasses import dataclass
from typing import Any, Dict, List, Optional

log = logging.getLogger("oi.confidence")

# ---------------------------------------------------------------------------
# Source type base scores
# ---------------------------------------------------------------------------

_SOURCE_BASE: Dict[str, float] = {
    "tool":      0.80,
    "manual":    0.75,
    "simulated": 0.55,
    "ai_theory": 0.40,
}

# ---------------------------------------------------------------------------
# CVSS → severity mapping
# ---------------------------------------------------------------------------

CVSS_SEVERITY = [
    (9.0, "critical"),
    (7.0, "high"),
    (4.0, "medium"),
    (0.1, "low"),
    (0.0, "info"),
]


def cvss_to_severity(cvss: float) -> str:
    for threshold, label in CVSS_SEVERITY:
        if cvss >= threshold:
            return label
    return "info"


# ---------------------------------------------------------------------------
# Scoring engine
# ---------------------------------------------------------------------------

@dataclass
class ScoreBreakdown:
    finding_id: str
    old_confidence: float
    new_confidence: float
    old_severity: str
    new_severity: str
    modifiers: List[str]
    auto_upgraded: bool = False
    auto_downgraded: bool = False


class ConfidenceEngine:
    """
    Compute and apply confidence scores across a batch of findings.
    Optionally auto-upgrades/downgrades severity based on final confidence.
    """

    def __init__(self, auto_upgrade: bool = True):
        self._auto_upgrade = auto_upgrade

    # ------------------------------------------------------------------ #
    # Public API
    # ------------------------------------------------------------------ #

    def score(self, finding: dict, all_findings: Optional[List[dict]] = None) -> ScoreBreakdown:
        """Score a single finding, optionally using the full finding set for tool-agreement bonus."""
        fid         = finding.get("finding_id", finding.get("id", "?"))
        source_type = finding.get("source_type", "tool")
        try:
            old_conf = float(finding.get("confidence", 0.5))
        except (TypeError, ValueError):
            old_conf = 0.5
        old_sev     = finding.get("severity", "info").lower()
        try:
            cvss = float(finding.get("cvss", 0.0))
        except (TypeError, ValueError):
            cvss = 0.0
        evidence    = finding.get("evidence", "")
        payload     = finding.get("payload", "")
        val_status  = finding.get("validation_status", "")
        vuln_type   = finding.get("vuln_type", "")
        http_status = finding.get("http_status", 0) or finding.get("validation_latency_ms", 0)

        # 1. Base score from source type
        base  = _SOURCE_BASE.get(source_type, 0.50)
        mods  = [f"base[{source_type}]={base:.2f}"]
        score = base

        # 2. Evidence quality
        if len(evidence) >= 50:
            score += 0.10
            mods.append("+0.10 [evidence≥50chars]")

        # 3. Payload attached (reproducible)
        if payload and len(payload) > 5:
            score += 0.05
            mods.append("+0.05 [payload attached]")

        # 4. High CVSS
        if cvss >= 8.0:
            score += 0.10
            mods.append(f"+0.10 [CVSS={cvss:.1f}≥8.0]")

        # 5. HTTP status evidence
        val_ev = finding.get("validation_evidence", "")
        if val_ev and ("HTTP" in val_ev or "status" in val_ev.lower()):
            score += 0.05
            mods.append("+0.05 [http_evidence]")

        # 6. Tool agreement (other findings with same vuln_type from different tool)
        if all_findings and vuln_type:
            tools_seen = {
                f.get("tool", "")
                for f in all_findings
                if f.get("vuln_type") == vuln_type and f.get("tool") != finding.get("tool")
            }
            if tools_seen:
                score += 0.10
                mods.append(f"+0.10 [multi-tool agreement: {len(tools_seen)} other tools]")

        # 7. Validation status modifier
        if val_status == "confirmed":
            score += 0.15
            mods.append("+0.15 [validated=confirmed]")
        elif val_status == "rejected":
            score -= 0.20
            mods.append("-0.20 [validated=rejected]")

        # 8. Low original confidence penalty
        if old_conf < 0.5:
            score -= 0.10
            mods.append(f"-0.10 [orig_confidence={old_conf:.2f}<0.50]")

        # Clamp
        score = round(max(0.10, min(1.00, score)), 3)

        # 9. Severity auto-upgrade/downgrade
        new_sev     = old_sev
        auto_up     = False
        auto_down   = False

        if self._auto_upgrade:
            if val_status == "rejected":
                new_sev   = "info"
                auto_down = True
                mods.append("severity→info [rejected]")
            elif val_status == "confirmed":
                derived_sev = cvss_to_severity(cvss)
                sev_rank    = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
                if sev_rank.get(derived_sev, 4) < sev_rank.get(old_sev, 4):
                    new_sev  = derived_sev
                    auto_up  = True
                    mods.append(f"severity→{new_sev} [confirmed+CVSS={cvss:.1f}]")
            elif score >= 0.85 and cvss >= 8.0:
                derived_sev = cvss_to_severity(cvss)
                sev_rank    = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
                if sev_rank.get(derived_sev, 4) < sev_rank.get(old_sev, 4):
                    new_sev  = derived_sev
                    auto_up  = True
                    mods.append(f"severity→{new_sev} [score={score:.2f}+CVSS={cvss:.1f}]")

        return ScoreBreakdown(fid, old_conf, score, old_sev, new_sev, mods, auto_up, auto_down)

    def score_findings(self, findings: List[dict]) -> List[dict]:
        """
        Score all findings. Returns updated list with new confidence + severity values.
        Adds 'confidence_breakdown' key for transparency.
        """
        updated = []
        for f in findings:
            bd = self.score(f, all_findings=findings)
            f  = dict(f)
            f["confidence"]            = bd.new_confidence
            f["severity"]              = bd.new_severity
            f["confidence_breakdown"]  = " | ".join(bd.modifiers)
            if bd.auto_upgraded:
                f["severity_upgraded"] = True
            if bd.auto_downgraded:
                f["severity_downgraded"] = True
                f["status"]             = "false_positive"
            updated.append(f)
        return updated

    def summary(self, findings: List[dict]) -> Dict[str, Any]:
        """Return a high-level confidence summary."""
        scored = self.score_findings(findings)
        by_src: Dict[str, int] = {}
        by_status: Dict[str, int] = {}
        avg_conf = 0.0
        for f in scored:
            src = f.get("source_type", "unknown")
            by_src[src] = by_src.get(src, 0) + 1
            vs = f.get("validation_status", "unverified")
            by_status[vs] = by_status.get(vs, 0) + 1
            avg_conf += f.get("confidence", 0)
        if scored:
            avg_conf /= len(scored)
        return {
            "total_findings":    len(scored),
            "avg_confidence":    round(avg_conf, 3),
            "by_source_type":    by_src,
            "by_validation":     by_status,
            "high_confidence":   sum(1 for f in scored if f.get("confidence", 0) >= 0.75),
            "low_confidence":    sum(1 for f in scored if f.get("confidence", 0) < 0.50),
            "auto_upgraded":     sum(1 for f in scored if f.get("severity_upgraded")),
            "auto_downgraded":   sum(1 for f in scored if f.get("severity_downgraded")),
        }
