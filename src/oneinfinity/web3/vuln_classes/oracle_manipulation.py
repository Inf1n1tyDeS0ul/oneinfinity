"""Oracle manipulation vulnerability detector — SWC-116 variant."""
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


class OracleManipulationDetector:
    SWC = "SWC-116"
    TITLE = "Oracle Price Manipulation"
    SEVERITY = "critical"

    _SPOT_PRICE_PATTERNS = [
        re.compile(r"getReserves\(\)", re.IGNORECASE),
        re.compile(r"token0\.balanceOf\(address\(this\)\)", re.IGNORECASE),
        re.compile(r"getAmountsOut\(", re.IGNORECASE),
        re.compile(r"slot0\(\)", re.IGNORECASE),           # Uniswap V3 spot
        re.compile(r"latestAnswer\(\)", re.IGNORECASE),    # Chainlink (OK if TWAP)
        re.compile(r"price\s*=\s*.*reserve", re.IGNORECASE),
    ]
    _TWAP_GUARDS = [re.compile(r"twap|TWAP|consult\(|observe\(", re.IGNORECASE)]

    def detect(self, source: str) -> List[VulnMatch]:
        findings: List[VulnMatch] = []
        lines = source.split("\n")
        for i, line in enumerate(lines, 1):
            for pat in self._SPOT_PRICE_PATTERNS:
                if pat.search(line):
                    # Check for TWAP guard in surrounding context
                    context = "\n".join(lines[max(0, i - 5) : i + 5])
                    if not any(g.search(context) for g in self._TWAP_GUARDS):
                        findings.append(VulnMatch(
                            swc_id=self.SWC,
                            title=self.TITLE,
                            severity=self.SEVERITY,
                            line=i,
                            evidence=line.strip(),
                            description=(
                                "Spot price used for critical calculation without TWAP protection. "
                                "Susceptible to flash loan price manipulation."
                            ),
                        ))
                    break
        return findings
