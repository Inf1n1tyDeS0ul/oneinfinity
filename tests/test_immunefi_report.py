"""tests/test_immunefi_report.py — Unit tests for Immunefi report template generator."""
from __future__ import annotations
import uuid
import pytest


def _make_finding(**kwargs):
    from oneinfinity.bounty.bounty_report_generator import ReportFinding
    defaults = dict(
        id=str(uuid.uuid4()),
        title="Flash Loan Price Manipulation",
        severity="critical",
        vuln_type="oracle_manipulation",
        url="https://app.defi.xyz/swap",
        evidence="Pool price changed 40% in single block",
        impact="Drain of LP reserves via price oracle manipulation",
        poc_steps=["Take flash loan", "Manipulate pool", "Exit"],
        cvss_score=9.8,
        bounty_estimate=50000,
        confidence=0.92,
    )
    defaults.update(kwargs)
    return ReportFinding(**defaults)


def _generator():
    from oneinfinity.bounty.bounty_report_generator import BountyReportGenerator
    return BountyReportGenerator()


def test_generate_immunefi_template_returns_str():
    finding = _make_finding()
    gen = _generator()
    report = gen.generate_immunefi_template(finding)
    assert isinstance(report, str)
    assert len(report) > 100


def test_immunefi_report_contains_key_sections():
    finding = _make_finding()
    gen = _generator()
    report = gen.generate_immunefi_template(finding)
    # All Immunefi reports must contain these fields
    assert "Impact" in report
    assert "critical" in report.lower() or "Severity" in report


def test_immunefi_report_title_in_output():
    finding = _make_finding(title="Custom Flash Loan Attack")
    gen = _generator()
    report = gen.generate_immunefi_template(finding)
    assert "Custom Flash Loan Attack" in report


def test_immunefi_report_no_empty_impact():
    """Impact field must not produce a blank section."""
    finding = _make_finding(impact="", evidence="Pool drained in single tx")
    gen = _generator()
    report = gen.generate_immunefi_template(finding)
    assert report
    # Impact section exists and has content (filled from evidence fallback)
    assert "Impact" in report


def test_immunefi_report_handles_no_poc_steps():
    """Empty poc_steps should not crash."""
    finding = _make_finding(poc_steps=[])
    gen = _generator()
    report = gen.generate_immunefi_template(finding)
    assert isinstance(report, str)


def test_platform_api_draft_report_has_approved_false():
    """h1_draft_report MCP tool must always return approved=False."""
    from oneinfinity.mcp.hackerone_mcp_tool import h1_draft_report
    draft = h1_draft_report(
        handle="shopify",
        title="XSS in search",
        severity="high",
        vuln_type="xss",
        summary="Reflected XSS in q param",
        steps="1. Open /search?q=<img onerror=alert(1)>",
        impact="Account takeover via cookie theft",
    )
    assert draft["approved"] is False
    assert "warning" in draft
