"""slither_wrapper.py — Slither static analysis integration for smart contracts."""
from __future__ import annotations

import json
import logging
import subprocess
import tempfile
from dataclasses import dataclass, field
from pathlib import Path
from typing import List, Optional

log = logging.getLogger("oneinfinity.web3.slither")

SWC_MAP = {
    "reentrancy": "SWC-107",
    "integer-overflow": "SWC-101",
    "unchecked-send": "SWC-104",
    "tx-origin": "SWC-115",
    "timestamp": "SWC-116",
    "assembly": "SWC-111",
    "low-level-calls": "SWC-104",
    "suicidal": "SWC-106",
    "uninitialized-local": "SWC-109",
    "controlled-delegatecall": "SWC-112",
}

SEVERITY_MAP = {
    "High": "high",
    "Medium": "medium",
    "Low": "low",
    "Informational": "info",
    "Optimization": "info",
}


@dataclass
class SlitherFinding:
    check: str
    impact: str
    confidence: str
    description: str
    elements: list = field(default_factory=list)

    @property
    def severity(self) -> str:
        return SEVERITY_MAP.get(self.impact, "info")

    @property
    def swc_id(self) -> str:
        return SWC_MAP.get(self.check, "")

    def to_dict(self) -> dict:
        return {
            "check": self.check,
            "severity": self.severity,
            "swc_id": self.swc_id,
            "description": self.description,
            "confidence": self.confidence,
        }


def is_available() -> bool:
    try:
        result = subprocess.run(
            ["slither", "--version"],
            capture_output=True, text=True, timeout=5,
        )
        return result.returncode == 0
    except (FileNotFoundError, subprocess.TimeoutExpired):
        return False


def run(sol_file: str, timeout: int = 120) -> List[SlitherFinding]:
    """Run Slither on a Solidity file and return structured findings."""
    if not is_available():
        log.info("slither not installed — skipping static analysis (pip install slither-analyzer)")
        return []

    with tempfile.NamedTemporaryFile(suffix=".json", delete=False) as tmp:
        out_path = tmp.name

    try:
        result = subprocess.run(
            [
                "slither", sol_file,
                "--json", out_path,
                "--exclude-informational",
                "--disable-color",
            ],
            capture_output=True, text=True, timeout=timeout,
        )
        try:
            data = json.loads(Path(out_path).read_text())
        except Exception:
            log.warning("Slither JSON output missing or malformed for %s", sol_file)
            return []

        findings = []
        for det in data.get("results", {}).get("detectors", []):
            findings.append(SlitherFinding(
                check=det.get("check", ""),
                impact=det.get("impact", ""),
                confidence=det.get("confidence", ""),
                description=det.get("description", ""),
                elements=det.get("elements", []),
            ))
        log.info("Slither: %d findings for %s", len(findings), sol_file)
        return findings

    except subprocess.TimeoutExpired:
        log.warning("Slither timed out on %s", sol_file)
        return []
    finally:
        try:
            Path(out_path).unlink()
        except Exception:
            pass
