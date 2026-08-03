"""
src/oneinfinity/findings/post_scan_verifier.py
Phase 3 — Self-Improvement: Post-Scan Verifier (Pillar 1.2 / CyberGym pattern)

Modeled after CyberGym's verify_agent_result.py — after a scan completes,
asynchronously verify a sample of findings by replaying their payloads against
the live target and checking for confirmation signals.

Design constraints (AGENTS.md single-process rule):
  - Runs as a FastAPI BackgroundTask, NOT a new Docker container or process.
  - Uses existing FindingValidationEngine (no duplicate validation logic).
  - Writes results back via DBManager.sync_update_finding_judge().
  - Never blocks the scan pipeline — always fire-and-forget.

CyberGym analog:
  CyberGym: PoC submission server validates exploits against challenge binaries.
  oneinfinity: PostScanVerifier replays HTTP payloads against live web targets.
  Both: emit a verified=True/False verdict that promotes or demotes the finding.
"""
from __future__ import annotations

import logging
import random
import time
import uuid
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional

log = logging.getLogger("oneinfinity.post_scan_verifier")


@dataclass
class VerificationResult:
    """Result of replaying one finding's payload."""
    finding_id: str
    validated: bool
    confidence: float
    evidence: str
    elapsed_s: float = 0.0
    error: Optional[str] = None

    def to_dict(self) -> dict:
        return {
            "validated":   self.validated,
            "confidence":  self.confidence,
            "evidence":    self.evidence,
            "elapsed_s":   self.elapsed_s,
            "error":       self.error,
        }


class PostScanVerifier:
    """
    Post-scan finding verification via payload replay.

    After a scan completes, verifies a random sample of findings by:
      1. Replaying the exact payload against the live target
      2. Comparing the response to the baseline
      3. Checking for confirmation signals (error messages, timing, OOB callbacks)
      4. Updating confirmed_tier in postgres via sync_update_finding_judge()

    Sample rate: 20% of findings (or all if < 10 findings). Bounded by max_findings.
    """

    def __init__(
        self,
        sample_rate: float = 0.20,
        max_findings: int = 50,
        timeout: int = 10,
    ):
        self.sample_rate = sample_rate
        self.max_findings = max_findings
        self.timeout = timeout

    def verify_scan(
        self,
        scan_id: str,
        target: str,
        auth_headers: Optional[Dict[str, str]] = None,
    ) -> List[VerificationResult]:
        """
        Verify a random sample of findings from a completed scan.

        Reads findings from postgres, samples them, replays payloads,
        updates confirmed_tier back to postgres.

        Safe to call from a BackgroundTask — never raises.
        """
        try:
            from oneinfinity.findings.result_ingestion_engine import get_ingestion_engine
            findings = get_ingestion_engine().get_findings(scan_id=scan_id) or []
        except Exception as exc:
            log.warning("PostScanVerifier: failed to fetch findings for %s: %s", scan_id, exc)
            return []

        if not findings:
            log.info("PostScanVerifier: no findings to verify for scan %s", scan_id)
            return []

        # Sample: always verify at least 1, at most max_findings
        n_sample = max(1, min(
            self.max_findings,
            int(len(findings) * self.sample_rate) if len(findings) >= 10 else len(findings)
        ))
        sample = random.sample(findings, min(n_sample, len(findings)))

        log.info(
            "PostScanVerifier: verifying %d/%d findings for scan %s",
            len(sample), len(findings), scan_id,
        )

        results = []
        for finding in sample:
            result = self._verify_one(finding, auth_headers)
            results.append(result)
            self._persist_result(finding, result)

        confirmed = sum(1 for r in results if r.validated)
        log.info(
            "PostScanVerifier: %s — %d/%d confirmed, %d/%d unconfirmed",
            scan_id, confirmed, len(results), len(results) - confirmed, len(results),
        )
        return results

    def verify_finding(
        self,
        finding: dict,
        auth_headers: Optional[Dict[str, str]] = None,
    ) -> VerificationResult:
        """
        Verify a single finding dict and update its confirmed_tier in postgres.
        Returns the VerificationResult.
        """
        result = self._verify_one(finding, auth_headers)
        self._persist_result(finding, result)
        return result

    # ── Internal ─────────────────────────────────────────────────────────────

    def _verify_one(
        self,
        finding: dict,
        auth_headers: Optional[Dict[str, str]] = None,
    ) -> VerificationResult:
        """Replay one finding's payload and return a VerificationResult."""
        finding_id = finding.get("finding_id", str(uuid.uuid4())[:12])
        t0 = time.monotonic()

        try:
            from oneinfinity.findings.finding_validation_engine import FindingValidationEngine
            vr = FindingValidationEngine().validate(finding)
            elapsed = time.monotonic() - t0

            # Map ValidationResult to confirmed_tier
            validated = bool(vr.validated) if hasattr(vr, "validated") else bool(
                vr.get("validated", False) if isinstance(vr, dict) else False
            )
            confidence = float(
                vr.confidence if hasattr(vr, "confidence") else
                vr.get("confidence", 0.5) if isinstance(vr, dict) else 0.5
            )
            evidence = str(
                vr.evidence if hasattr(vr, "evidence") else
                vr.get("evidence", "") if isinstance(vr, dict) else ""
            )

            return VerificationResult(
                finding_id=finding_id,
                validated=validated,
                confidence=confidence,
                evidence=evidence,
                elapsed_s=round(elapsed, 3),
            )

        except Exception as exc:
            elapsed = time.monotonic() - t0
            log.debug("PostScanVerifier._verify_one failed [%s]: %s", finding_id, exc)
            return VerificationResult(
                finding_id=finding_id,
                validated=False,
                confidence=float(finding.get("confidence", 0.5)),
                evidence="Verification failed — see error",
                elapsed_s=round(elapsed, 3),
                error=str(exc),
            )

    @staticmethod
    def _persist_result(finding: dict, result: VerificationResult) -> None:
        """Write verification result back to postgres as judge verdict."""
        finding_id = finding.get("finding_id")
        if not finding_id:
            return
        try:
            from oneinfinity.core.db_manager import get_db_manager_sync
            db = get_db_manager_sync()
            if db is None:
                return

            # Map validation result to confirmed_tier
            if result.validated:
                tier = "CONFIRMED"
            elif result.error:
                tier = "CANDIDATE"   # couldn't verify — keep as candidate
            else:
                tier = "INFERRED"    # active replay, not validated

            db.sync_update_finding_judge(
                finding_id=finding_id,
                confirmed_tier=tier,
                judge_verdict={
                    "confirmed":          result.validated,
                    "confidence":         result.confidence,
                    "validation_method":  "payload_replay",
                    "evidence":           result.evidence[:500],
                    "elapsed_s":          result.elapsed_s,
                    "error":              result.error,
                    "judged_at":          time.time(),
                    "model_used":         "post_scan_verifier",
                },
            )
        except Exception as exc:
            log.debug("PostScanVerifier._persist_result failed [%s]: %s", finding_id, exc)


# ── Module-level API ──────────────────────────────────────────────────────────

_verifier: Optional[PostScanVerifier] = None


def get_verifier() -> PostScanVerifier:
    """Return the module-level PostScanVerifier singleton."""
    global _verifier
    if _verifier is None:
        _verifier = PostScanVerifier()
    return _verifier
