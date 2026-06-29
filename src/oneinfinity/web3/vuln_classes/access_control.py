"""Access control vulnerability detector — SWC-105."""
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


class AccessControlDetector:
    SWC = "SWC-105"
    TITLE = "Missing Access Control"
    SEVERITY = "high"

    _PRIVILEGED_FUNCTIONS = [
        re.compile(r"function\s+\w*(mint|burn|pause|upgrade|setOwner|withdraw|drain|initialize)\w*\s*\(", re.IGNORECASE),
        re.compile(r"function\s+\w*(admin|owner|gov|privileged)\w*\s*\(", re.IGNORECASE),
        re.compile(r"selfdestruct\s*\(", re.IGNORECASE),
    ]
    _ACCESS_GUARDS = [
        re.compile(r"onlyOwner|onlyAdmin|onlyRole|require\s*\(\s*msg\.sender\s*==\s*owner", re.IGNORECASE),
        re.compile(r"Ownable|AccessControl|hasRole\(", re.IGNORECASE),
    ]

    def detect(self, source: str) -> List[VulnMatch]:
        findings: List[VulnMatch] = []
        lines = source.split("\n")
        i = 0
        while i < len(lines):
            line = lines[i]
            for pat in self._PRIVILEGED_FUNCTIONS:
                if pat.search(line):
                    # Look at next 10 lines for access guard
                    context = "\n".join(lines[i : i + 10])
                    if not any(g.search(context) for g in self._ACCESS_GUARDS):
                        # Skip view/pure functions
                        if not re.search(r"\b(view|pure)\b", context[:200]):
                            findings.append(VulnMatch(
                                swc_id=self.SWC,
                                title=self.TITLE,
                                severity=self.SEVERITY,
                                line=i + 1,
                                evidence=line.strip(),
                                description=(
                                    "Privileged function lacks access control modifier. "
                                    "Any caller can execute this function."
                                ),
                            ))
                    break
            i += 1
        return findings
