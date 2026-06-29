"""Flash loan attack surface detector — SWC-107 variant."""
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


class FlashLoanDetector:
    SWC = "SWC-107"
    TITLE = "Flash Loan Attack Surface"
    SEVERITY = "critical"

    _FL_RECEIVERS = [
        re.compile(r"function\s+executeOperation\s*\(", re.IGNORECASE),      # Aave
        re.compile(r"function\s+uniswapV[23]?FlashCallback\s*\(", re.IGNORECASE),
        re.compile(r"function\s+pancakeCall\s*\(", re.IGNORECASE),
        re.compile(r"function\s+callbackWithBalance\s*\(", re.IGNORECASE),
        re.compile(r"IFlashLoanReceiver|IFlashBorrower", re.IGNORECASE),
    ]
    _BALANCE_CHECKS = [re.compile(r"require.*balance|assert.*balance", re.IGNORECASE)]

    def detect(self, source: str) -> List[VulnMatch]:
        findings: List[VulnMatch] = []
        lines = source.split("\n")
        for i, line in enumerate(lines, 1):
            for pat in self._FL_RECEIVERS:
                if pat.search(line):
                    context = "\n".join(lines[i - 1 : i + 30])
                    has_check = any(c.search(context) for c in self._BALANCE_CHECKS)
                    severity = "medium" if has_check else self.SEVERITY
                    findings.append(VulnMatch(
                        swc_id=self.SWC,
                        title=self.TITLE,
                        severity=severity,
                        line=i,
                        evidence=line.strip(),
                        description=(
                            "Flash loan callback detected. "
                            + ("Balance check found — lower risk." if has_check
                               else "No balance validation found — verify price oracle independence.")
                        ),
                    ))
                    break
        return findings
