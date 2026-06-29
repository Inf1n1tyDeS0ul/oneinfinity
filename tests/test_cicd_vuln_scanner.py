"""tests/test_cicd_vuln_scanner.py — Unit tests for CI/CD vulnerability scanner."""
from __future__ import annotations
import os
import tempfile
import pytest


def _write_workflow(content: str, dirname: str, filename: str = "ci.yml") -> str:
    """Write a workflow file inside dirname/.github/workflows/."""
    wf_dir = os.path.join(dirname, ".github", "workflows")
    os.makedirs(wf_dir, exist_ok=True)
    path = os.path.join(wf_dir, filename)
    with open(path, "w") as f:
        f.write(content)
    return dirname


def test_cicd_scanner_imports():
    from oneinfinity.scan.cicd_vuln_scanner import CICDVulnerabilityScanner, CICDFinding
    scanner = CICDVulnerabilityScanner()
    assert scanner is not None


def test_detect_injection_in_workflow():
    """${{ github.event.issue.title }} in run: is a critical injection."""
    from oneinfinity.scan.cicd_vuln_scanner import CICDVulnerabilityScanner

    content = """\
name: Dangerous
on: [issue_comment]
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - run: echo "${{ github.event.issue.title }}"
"""
    with tempfile.TemporaryDirectory() as tmp:
        _write_workflow(content, tmp)
        scanner = CICDVulnerabilityScanner()
        report = scanner.scan_directory(tmp)
    assert len(report.findings) > 0
    assert any("injection" in f.category.lower() for f in report.findings)


def test_detect_secret_in_workflow():
    """Hardcoded secret-like patterns should be flagged."""
    from oneinfinity.scan.cicd_vuln_scanner import CICDVulnerabilityScanner

    content = """\
name: SecretLeak
jobs:
  build:
    env:
      AWS_SECRET_ACCESS_KEY: AKIAIOSFODNN7EXAMPLE
    steps:
      - run: aws s3 ls
"""
    with tempfile.TemporaryDirectory() as tmp:
        _write_workflow(content, tmp)
        scanner = CICDVulnerabilityScanner()
        report = scanner.scan_directory(tmp)
    secret_findings = [f for f in report.findings if "secret" in f.category.lower() or "credential" in f.category.lower()]
    assert len(secret_findings) > 0


def test_finding_to_dict_has_url_and_endpoint():
    """CICDFinding.to_dict() must include 'url' and 'endpoint' keys for ingestion."""
    from oneinfinity.scan.cicd_vuln_scanner import CICDFinding
    import uuid

    finding = CICDFinding(
        finding_id=str(uuid.uuid4()),
        title="Test Injection",
        severity="critical",
        category="injection",
        description="Test",
        file_path=".github/workflows/ci.yml",
        line_number=5,
        evidence="echo ${{ expr }}",
    )
    d = finding.to_dict()
    assert "url" in d, "to_dict() must include 'url' key"
    assert "endpoint" in d, "to_dict() must include 'endpoint' key"
    assert d["url"] == ".github/workflows/ci.yml"


def test_safe_workflow_has_no_injection_or_secret_findings():
    """A clean workflow should have no injection or secret findings (supply_chain warnings are acceptable)."""
    from oneinfinity.scan.cicd_vuln_scanner import CICDVulnerabilityScanner

    content = """\
name: Safe
on: [push]
jobs:
  test:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - run: pytest
"""
    with tempfile.TemporaryDirectory() as tmp:
        _write_workflow(content, tmp)
        scanner = CICDVulnerabilityScanner()
        report = scanner.scan_directory(tmp)
    critical_findings = [f for f in report.findings if f.category in ("injection", "secret")]
    assert len(critical_findings) == 0
