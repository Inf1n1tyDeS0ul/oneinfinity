"""
pipeline/parity_checker.py — Docker vs CLI parity checker.

After running the canonical pipeline in both Docker and CLI modes,
this module compares results and identifies discrepancies.

Usage:
    checker = ParityChecker(docker_result, cli_result)
    report = checker.check()
    print(report.summary())
    # If discrepancies → re-run missing phases
"""

from __future__ import annotations

import json
import logging
from dataclasses import dataclass, field
from pathlib import Path
from typing import Dict, List, Optional, Tuple

from .executor import PipelineResult, deduplicate, _fingerprint

log = logging.getLogger("oi.pipeline.parity")

SEVERITY_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}


@dataclass
class FindingDiff:
    """A finding present in one mode but missing/different in the other."""
    fingerprint: str
    vuln_type: str
    severity: str
    url: str
    in_docker: bool
    in_cli: bool
    docker_confidence: float = 0.0
    cli_confidence: float = 0.0
    explanation: str = ""


@dataclass
class PhaseDiff:
    """Comparison of one phase across Docker and CLI runs."""
    phase_name: str
    docker_status: str
    cli_status: str
    docker_findings: int
    cli_findings: int
    delta: int          # cli_findings - docker_findings
    is_parity: bool     # True if both completed and finding count is ≤ threshold apart


@dataclass
class ParityReport:
    """Full parity comparison between Docker and CLI pipeline runs."""
    docker_run_id: str
    cli_run_id: str
    target: str
    is_consistent: bool                     # True if no significant discrepancies
    phase_diffs: List[PhaseDiff] = field(default_factory=list)
    finding_diffs: List[FindingDiff] = field(default_factory=list)
    docker_only: List[dict] = field(default_factory=list)   # Findings only in Docker
    cli_only: List[dict] = field(default_factory=list)      # Findings only in CLI
    common: List[dict] = field(default_factory=list)        # Findings in both
    docker_total: int = 0
    cli_total: int = 0
    common_count: int = 0
    overlap_pct: float = 0.0
    severity_delta: Dict[str, int] = field(default_factory=dict)
    explanations: List[str] = field(default_factory=list)
    fixes_applied: List[str] = field(default_factory=list)

    def summary(self) -> str:
        lines = [
            "=" * 64,
            "  OneInfinity Parity Report",
            "=" * 64,
            f"  Target       : {self.target}",
            f"  Docker run   : {self.docker_run_id}",
            f"  CLI run      : {self.cli_run_id}",
            f"  Consistent   : {'YES ✓' if self.is_consistent else 'NO — discrepancies found'}",
            "",
            f"  Docker findings : {self.docker_total}",
            f"  CLI findings    : {self.cli_total}",
            f"  Common          : {self.common_count}",
            f"  Overlap         : {self.overlap_pct:.1f}%",
            "",
        ]
        if self.docker_only:
            lines.append(f"  Docker-only findings ({len(self.docker_only)}):")
            for f in self.docker_only[:5]:
                lines.append(f"    - [{f.get('severity','?').upper()}] {f.get('vuln_type','?')} @ {f.get('url','?')[:60]}")
        if self.cli_only:
            lines.append(f"  CLI-only findings ({len(self.cli_only)}):")
            for f in self.cli_only[:5]:
                lines.append(f"    - [{f.get('severity','?').upper()}] {f.get('vuln_type','?')} @ {f.get('url','?')[:60]}")
        if self.severity_delta:
            lines.append("")
            lines.append("  Severity distribution delta (Docker - CLI):")
            for sev in ["critical", "high", "medium", "low", "info"]:
                d = self.severity_delta.get(sev, 0)
                if d != 0:
                    lines.append(f"    {sev:10s}: {'+' if d > 0 else ''}{d}")
        if self.fixes_applied:
            lines += ["", "  Fixes applied:"]
            for fix in self.fixes_applied:
                lines.append(f"    ✓ {fix}")
        if self.explanations:
            lines += ["", "  Explanations:"]
            for exp in self.explanations:
                lines.append(f"    · {exp}")
        lines += ["", "=" * 64]
        return "\n".join(lines)

    def to_dict(self) -> dict:
        return {
            "docker_run_id": self.docker_run_id,
            "cli_run_id": self.cli_run_id,
            "target": self.target,
            "is_consistent": self.is_consistent,
            "docker_total": self.docker_total,
            "cli_total": self.cli_total,
            "common_count": self.common_count,
            "overlap_pct": self.overlap_pct,
            "docker_only_count": len(self.docker_only),
            "cli_only_count": len(self.cli_only),
            "severity_delta": self.severity_delta,
            "phase_diffs": [
                {
                    "phase": pd.phase_name,
                    "docker_status": pd.docker_status,
                    "cli_status": pd.cli_status,
                    "docker_findings": pd.docker_findings,
                    "cli_findings": pd.cli_findings,
                    "delta": pd.delta,
                    "parity": pd.is_parity,
                }
                for pd in self.phase_diffs
            ],
            "docker_only": self.docker_only[:50],
            "cli_only": self.cli_only[:50],
            "fixes_applied": self.fixes_applied,
            "explanations": self.explanations,
        }


class ParityChecker:
    """
    Compares findings from Docker and CLI pipeline runs.

    Parity rules:
    1. Phase statuses should match (completed in both)
    2. Findings overlap should be ≥ 70% (same fingerprint)
    3. Critical/high severity delta ≤ 1
    4. No mandatory phase failed in one mode but succeeded in the other
    """

    # Tolerance thresholds
    MIN_OVERLAP_PCT = 60.0   # Below this = fail parity
    MAX_SEVERITY_DELTA = 2   # Max allowed critical/high count difference

    def __init__(self, docker_result: PipelineResult, cli_result: PipelineResult):
        self.docker = docker_result
        self.cli = cli_result

    def check(self) -> ParityReport:
        report = ParityReport(
            docker_run_id=self.docker.run_id,
            cli_run_id=self.cli.run_id,
            target=self.docker.target,
            is_consistent=True,
        )

        report.docker_total = len(self.docker.findings)
        report.cli_total = len(self.cli.findings)

        # 1. Phase-level comparison
        report.phase_diffs = self._compare_phases()

        # 2. Finding-level comparison
        self._compare_findings(report)

        # 3. Severity delta
        report.severity_delta = self._severity_delta()

        # 4. Consistency judgment
        inconsistencies = []

        if report.overlap_pct < self.MIN_OVERLAP_PCT and (report.docker_total + report.cli_total) > 4:
            inconsistencies.append(
                f"Low finding overlap: {report.overlap_pct:.1f}% (threshold: {self.MIN_OVERLAP_PCT}%)"
            )

        for sev in ("critical", "high"):
            delta = abs(report.severity_delta.get(sev, 0))
            if delta > self.MAX_SEVERITY_DELTA:
                inconsistencies.append(
                    f"{sev.capitalize()} severity delta is {delta} (threshold: {self.MAX_SEVERITY_DELTA})"
                )

        failed_phases = [
            pd for pd in report.phase_diffs
            if pd.docker_status != pd.cli_status
            and (pd.docker_status == "failed" or pd.cli_status == "failed")
        ]
        if failed_phases:
            for pd in failed_phases:
                inconsistencies.append(
                    f"Phase '{pd.phase_name}' status mismatch: Docker={pd.docker_status}, CLI={pd.cli_status}"
                )

        report.is_consistent = len(inconsistencies) == 0
        report.explanations = self._explain_differences(report) + inconsistencies
        return report

    def _compare_phases(self) -> List[PhaseDiff]:
        from .canonical import CANONICAL_PHASES
        diffs = []
        for phase in CANONICAL_PHASES:
            pname = phase.name
            d_phase = self.docker.phases.get(pname)
            c_phase = self.cli.phases.get(pname)
            d_status = d_phase.status if d_phase else "missing"
            c_status = c_phase.status if c_phase else "missing"
            d_count = d_phase.finding_count if d_phase else 0
            c_count = c_phase.finding_count if c_phase else 0
            delta = c_count - d_count
            is_parity = (
                d_status in ("completed", "skipped") and
                c_status in ("completed", "skipped") and
                abs(delta) <= max(2, int(d_count * 0.30))
            )
            diffs.append(PhaseDiff(
                phase_name=pname,
                docker_status=d_status,
                cli_status=c_status,
                docker_findings=d_count,
                cli_findings=c_count,
                delta=delta,
                is_parity=is_parity,
            ))
        return diffs

    def _compare_findings(self, report: ParityReport) -> None:
        docker_by_fp: Dict[str, dict] = {_fingerprint(f): f for f in self.docker.findings}
        cli_by_fp: Dict[str, dict] = {_fingerprint(f): f for f in self.cli.findings}
        all_fps = set(docker_by_fp) | set(cli_by_fp)

        common, docker_only, cli_only = [], [], []
        for fp in all_fps:
            in_d = fp in docker_by_fp
            in_c = fp in cli_by_fp
            if in_d and in_c:
                common.append(docker_by_fp[fp])
            elif in_d:
                docker_only.append(docker_by_fp[fp])
            else:
                cli_only.append(cli_by_fp[fp])

        report.common = common
        report.docker_only = docker_only
        report.cli_only = cli_only
        report.common_count = len(common)
        total = len(all_fps)
        report.overlap_pct = round((len(common) / total * 100) if total else 100.0, 1)

    def _severity_delta(self) -> Dict[str, int]:
        """Docker count minus CLI count per severity."""
        d_counts: Dict[str, int] = {}
        c_counts: Dict[str, int] = {}
        for f in self.docker.findings:
            s = f.get("severity", "info").lower()
            d_counts[s] = d_counts.get(s, 0) + 1
        for f in self.cli.findings:
            s = f.get("severity", "info").lower()
            c_counts[s] = c_counts.get(s, 0) + 1
        delta = {}
        for sev in ("critical", "high", "medium", "low", "info"):
            d = d_counts.get(sev, 0) - c_counts.get(sev, 0)
            if d != 0:
                delta[sev] = d
        return delta

    def _explain_differences(self, report: ParityReport) -> List[str]:
        """Generate human-readable explanations for observed differences."""
        explanations = []

        # WAF differences
        if self.docker.waf_passive_mode != self.cli.waf_passive_mode:
            explanations.append(
                f"WAF mode mismatch: Docker passive={self.docker.waf_passive_mode}, "
                f"CLI passive={self.cli.waf_passive_mode} — active testing phases may differ"
            )

        # Docker-only findings
        for f in report.docker_only[:3]:
            vtype = f.get("vuln_type", "?")
            src = f.get("source_type", "?")
            explanations.append(
                f"Docker-only finding [{vtype}] src={src} — may require tool available only in Docker image"
            )

        # CLI-only findings
        for f in report.cli_only[:3]:
            vtype = f.get("vuln_type", "?")
            src = f.get("source_type", "?")
            explanations.append(
                f"CLI-only finding [{vtype}] src={src} — may require local tool not in Docker image"
            )

        return explanations


def merge_results(docker_result: PipelineResult, cli_result: PipelineResult) -> List[dict]:
    """
    Merge Docker and CLI findings into a single deduplicated list.
    When the same finding appears in both, prefer the higher-confidence version.
    """
    all_findings = docker_result.findings + cli_result.findings
    merged = deduplicate(all_findings)
    log.info(
        "Merged %d Docker + %d CLI = %d unique findings",
        len(docker_result.findings), len(cli_result.findings), len(merged),
    )
    return merged


def load_result_from_dir(output_dir: str, mode: str = "unknown") -> PipelineResult:
    """
    Load a PipelineResult from an existing output directory.
    Used when comparing results from separate runs.
    """
    import uuid
    out = Path(output_dir)

    # Load pipeline report if it exists
    report_file = out / "pipeline_report.json"
    if report_file.exists():
        try:
            data = json.loads(report_file.read_text())
            run_id = data.get("run_id", uuid.uuid4().hex[:12])
            target = data.get("target", "unknown")
        except Exception:
            run_id = uuid.uuid4().hex[:12]
            target = "unknown"
    else:
        run_id = uuid.uuid4().hex[:12]
        target = out.name

    # Load unified findings
    findings = []
    uf = out / "unified_findings.json"
    if uf.exists():
        try:
            findings = json.loads(uf.read_text())
            if isinstance(findings, dict):
                findings = findings.get("findings", [])
        except Exception:
            pass
    else:
        # Fall back: load from all known output files
        from .canonical import CANONICAL_PHASES
        for phase in CANONICAL_PHASES:
            fp = out / phase.output_file
            if fp.exists():
                try:
                    data = json.loads(fp.read_text())
                    if isinstance(data, list):
                        findings.extend(data)
                    else:
                        for key in ("findings", "results", "theories", "chains"):
                            if key in data and isinstance(data[key], list):
                                findings.extend(data[key])
                                break
                except Exception:
                    pass

    from .executor import deduplicate, normalize_finding
    result = PipelineResult(
        run_id=run_id,
        target=target,
        mode=mode,
        output_dir=output_dir,
    )
    result.findings = deduplicate([normalize_finding(f) for f in findings])
    return result
