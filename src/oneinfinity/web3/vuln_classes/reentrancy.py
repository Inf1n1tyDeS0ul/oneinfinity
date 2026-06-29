"""Reentrancy vulnerability detector — SWC-107."""
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


class ReentrancyDetector:
    SWC = "SWC-107"
    TITLE = "Reentrancy"
    SEVERITY = "high"

    # Pattern: external call BEFORE state update
    _CALL_PATTERNS = [
        re.compile(r"\.call\{[^}]*value[^}]*\}\(", re.MULTILINE),
        re.compile(r"\.transfer\(", re.MULTILINE),
        re.compile(r"\.send\(", re.MULTILINE),
        re.compile(r"\.call\.value\(", re.MULTILINE),
    ]
    _STATE_AFTER_CALL = re.compile(
        r"(?:\.call|\.transfer|\.send)[^;]+;[^}]{0,500}(?:balances|mapping|uint|bool)[^=]*=[^;]+;",
        re.DOTALL,
    )

    def detect(self, source: str) -> List[VulnMatch]:
        findings: List[VulnMatch] = []
        lines = source.split("\n")
        for i, line in enumerate(lines, 1):
            for pat in self._CALL_PATTERNS:
                if pat.search(line):
                    # Heuristic: check if state var updated after call in next 20 lines
                    context = "\n".join(lines[i - 1 : i + 20])
                    has_state_update = bool(re.search(
                        r"(balances|_balance|amount|shares)\s*[-+]?=", context
                    ))
                    if has_state_update or "nonReentrant" not in context:
                        findings.append(VulnMatch(
                            swc_id=self.SWC,
                            title=self.TITLE,
                            severity=self.SEVERITY,
                            line=i,
                            evidence=line.strip(),
                            description=(
                                "External call may allow reentrancy. "
                                "State update occurs after external call or "
                                "nonReentrant modifier is missing."
                            ),
                        ))
                        break
        return findings
