"""
GitHub Findings Validator and Deduplicator
Validates leaked secrets and removes false positives.
"""

import re
from typing import List, Dict, Set
from dataclasses import dataclass


@dataclass
class ValidationResult:
    """Result of finding validation."""
    is_valid: bool
    confidence: float
    reason: str = ""


class FindingsValidator:
    """
    Validates GitHub reconnaissance findings.
    Filters false positives and assigns confidence scores.
    """

    # Patterns indicating test/example code (false positives)
    FALSE_POSITIVE_PATTERNS = [
        r"example",
        r"sample",
        r"test",
        r"dummy",
        r"fake",
        r"placeholder",
        r"TODO",
        r"FIXME",
        r"xxx+",
        r"000+",
        r"111+",
        r"abc+",
        r"your[_-]?\w+",  # your_api_key, your-token
        r"insert[_-]?\w+",
        r"<[^>]+>",  # HTML/XML tags
        r"\{\{.*\}\}",  # Template variables
        r"\$\{.*\}",  # Shell variables
    ]

    # File paths indicating test code
    TEST_PATHS = [
        "test/", "tests/", "spec/", "specs/",
        "__tests__/", "fixtures/", "mocks/",
        "examples/", "sample/", "demo/",
        ".github/workflows/", # CI/CD examples
    ]

    # Known safe/example domains
    SAFE_DOMAINS = [
        "example.com", "example.org", "test.com",
        "localhost", "127.0.0.1", "0.0.0.0",
    ]

    def __init__(self):
        self.seen_findings: Set[str] = set()

    def validate_finding(self, finding: Dict) -> ValidationResult:
        """
        Validate single finding.
        Returns confidence score and whether it's likely real.
        """
        confidence = finding.get("confidence", 0.5)

        # Check file path for test indicators
        file_path = finding.get("file_path", "").lower()
        for test_path in self.TEST_PATHS:
            if test_path in file_path:
                return ValidationResult(
                    is_valid=False,
                    confidence=0.1,
                    reason=f"Test/example file path: {test_path}"
                )

        # Check matched text for false positive patterns
        matched_text = finding.get("matched_text", "")
        if isinstance(finding.get("matches"), list) and finding["matches"]:
            matched_text += " ".join(finding["matches"][:3])

        for pattern in self.FALSE_POSITIVE_PATTERNS:
            if re.search(pattern, matched_text, re.IGNORECASE):
                return ValidationResult(
                    is_valid=False,
                    confidence=0.2,
                    reason=f"False positive pattern: {pattern}"
                )

        # Check for safe domains
        for domain in self.SAFE_DOMAINS:
            if domain in matched_text.lower():
                return ValidationResult(
                    is_valid=False,
                    confidence=0.1,
                    reason=f"Example domain: {domain}"
                )

        # Check for very short secrets (likely examples)
        if len(matched_text) < 20 and any(c in matched_text.lower() for c in ["test", "demo", "example"]):
            return ValidationResult(
                is_valid=False,
                confidence=0.2,
                reason="Short suspicious text"
            )

        # Boost confidence for production-looking files
        prod_indicators = ["config/", "prod", "production", "deploy"]
        if any(ind in file_path for ind in prod_indicators):
            confidence = min(1.0, confidence + 0.2)

        return ValidationResult(
            is_valid=True,
            confidence=confidence,
            reason="Passed validation checks"
        )

    def deduplicate_findings(self, findings: List[Dict]) -> List[Dict]:
        """
        Remove duplicate findings based on content hash.
        Keeps highest confidence version of duplicates.
        """
        unique_findings = {}

        for finding in findings:
            # Create unique key from repository + file + matched text
            repo = finding.get("repo_full_name") or finding.get("repository", "")
            file_path = finding.get("file_path", "")
            matched = finding.get("matched_text", "")
            if isinstance(finding.get("matches"), list) and finding["matches"]:
                matched = finding["matches"][0]

            key = f"{repo}:{file_path}:{matched[:50]}"

            if key not in unique_findings:
                unique_findings[key] = finding
            else:
                # Keep higher confidence version
                existing_conf = unique_findings[key].get("confidence", 0)
                new_conf = finding.get("confidence", 0)
                if new_conf > existing_conf:
                    unique_findings[key] = finding

        return list(unique_findings.values())

    def filter_and_validate(self, findings: List[Dict]) -> List[Dict]:
        """
        Complete validation pipeline: deduplicate + validate + filter.
        Returns only high-confidence valid findings.
        """
        # Deduplicate first
        unique = self.deduplicate_findings(findings)

        # Validate and filter
        validated = []
        for finding in unique:
            result = self.validate_finding(finding)

            if result.is_valid and result.confidence >= 0.4:
                # Update finding with validation results
                finding["confidence"] = result.confidence
                finding["validation_status"] = "validated"
                validated.append(finding)

        return validated

    def prioritize_findings(self, findings: List[Dict]) -> List[Dict]:
        """
        Sort findings by risk priority.
        Critical + high confidence first.
        """
        def get_priority_score(finding: Dict) -> float:
            severity_scores = {
                "critical": 100,
                "high": 80,
                "medium": 50,
                "low": 20,
            }
            severity = finding.get("severity", "medium")
            confidence = finding.get("confidence", 0.5)

            base_score = severity_scores.get(severity, 50)
            return base_score * confidence

        return sorted(findings, key=get_priority_score, reverse=True)


def enhance_findings_with_context(findings: List[Dict], domain_data: Dict) -> List[Dict]:
    """
    Add additional context to findings from domain intelligence.
    Helps analysts understand impact.
    """
    repos_map = {}
    for repo_name in domain_data.get("repo_names", []):
        repos_map[repo_name] = True

    for finding in findings:
        repo = finding.get("repo_full_name") or finding.get("repository", "")

        # Mark if finding is in a main/official repository
        if repo in repos_map:
            finding["is_official_repo"] = True
            finding["confidence"] = min(1.0, finding.get("confidence", 0.5) + 0.1)

        # Add risk context
        if finding.get("severity") == "critical" and finding.get("confidence", 0) > 0.7:
            finding["risk_level"] = "immediate_action_required"
        elif finding.get("severity") in ["critical", "high"] and finding.get("confidence", 0) > 0.5:
            finding["risk_level"] = "high_priority"
        else:
            finding["risk_level"] = "review_recommended"

    return findings
