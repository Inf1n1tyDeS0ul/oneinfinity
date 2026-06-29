"""Signature replay vulnerability detector — SWC-121."""
from __future__ import annotations
import re
from dataclasses import dataclass
from typing import List


@dataclass
class VulnMatch:
    swc_id: str
    title: str
    severity: str
    line: int
    evidence: str
    description: str


class SignatureReplayDetector:
    SWC = "SWC-121"
    TITLE = "Signature Replay Attack"
    SEVERITY = "high"

    _SIG_USE = [
        re.compile(r"ecrecover\s*\(", re.IGNORECASE),
        re.compile(r"ECDSA\.recover\s*\(", re.IGNORECASE),
        re.compile(r"SignatureChecker\.isValidSignatureNow\s*\(", re.IGNORECASE),
    ]
    _REPLAY_GUARDS = [
        re.compile(r"nonce|usedSignatures|executed|_usedHashes", re.IGNORECASE),
        re.compile(r"block\.chainid|chainId|DOMAIN_SEPARATOR", re.IGNORECASE),
    ]

    def detect(self, source: str) -> List[VulnMatch]:
        findings: List[VulnMatch] = []
        lines = source.split("\n")
        for i, line in enumerate(lines, 1):
            for pat in self._SIG_USE:
                if pat.search(line):
                    # Check surrounding 20 lines for nonce/replay guard
                    context = "\n".join(lines[max(0, i - 5) : i + 20])
                    if not any(g.search(context) for g in self._REPLAY_GUARDS):
                        findings.append(VulnMatch(
                            swc_id=self.SWC,
                            title=self.TITLE,
                            severity=self.SEVERITY,
                            line=i,
                            evidence=line.strip(),
                            description=(
                                "Signature verification found without nonce or used-signature tracking. "
                                "Same signature can be replayed to execute the operation multiple times."
                            ),
                        ))
                    break
        return findings
