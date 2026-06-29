"""
Tests for ValidationOrchestrator

Covers:
1. Static validation
2. Context validation
3. Live validation with retry
4. Hybrid validation (all strategies)
5. Confidence scoring
6. Caching
7. Different vulnerability types
"""

import pytest
from unittest.mock import Mock, patch, MagicMock

from oneinfinity.agents.validation_orchestrator import (
    ValidationOrchestrator,
    Finding,
    ValidationResult,
    ValidationStrategy,
)


@pytest.fixture
def orchestrator():
    """Create orchestrator instance for testing."""
    return ValidationOrchestrator()


@pytest.fixture
def sqli_finding():
    """Sample SQL injection finding."""
    return Finding(
        id="test-001",
        type="sqli",
        target="https://example.com/login",
        payload="' OR '1'='1",
        evidence="SQL syntax error: You have an error in your SQL syntax",
        severity="high",
        tech_stack=["mysql", "php"],
    )


@pytest.fixture
def xss_finding():
    """Sample XSS finding."""
    return Finding(
        id="test-002",
        type="xss",
        target="https://example.com/search",
        payload="<script>alert(1)</script>",
        evidence="<script>alert(1)</script> reflected in response",
        severity="medium",
        tech_stack=["html", "javascript"],
    )


def test_static_validation_sqli_high_confidence(orchestrator, sqli_finding):
    """Test static validation detects SQL error patterns."""
    score = orchestrator._static_validation(sqli_finding)

    assert score >= 0.6, "Should detect SQL error pattern (score >= 0.6)"
    assert score <= 1.0, "Score should be normalized"


def test_static_validation_no_patterns(orchestrator):
    """Test static validation with unknown vuln type."""
    finding = Finding(
        id="test-003",
        type="unknown",
        target="https://example.com",
        payload="test",
        evidence="no patterns here",
        severity="low",
    )

    score = orchestrator._static_validation(finding)

    assert score == 0.5, "Should return neutral score for unknown types"


def test_context_validation_compatible_tech(orchestrator, sqli_finding):
    """Test context validation with compatible tech stack."""
    score = orchestrator._context_validation(sqli_finding)

    assert score > 0.8, "MySQL should be highly compatible with SQLi"


def test_context_validation_incompatible_tech(orchestrator):
    """Test context validation with incompatible tech stack."""
    finding = Finding(
        id="test-004",
        type="sqli",
        target="https://example.com",
        payload="' OR 1=1--",
        evidence="test",
        severity="high",
        tech_stack=["mongodb", "nosql"],  # Incompatible with SQLi
    )

    score = orchestrator._context_validation(finding)

    assert score < 0.2, "MongoDB should be incompatible with SQLi"


def test_context_validation_no_tech_stack(orchestrator):
    """Test context validation with missing tech stack."""
    finding = Finding(
        id="test-005",
        type="sqli",
        target="https://example.com",
        payload="test",
        evidence="test",
        severity="high",
        tech_stack=[],
    )

    score = orchestrator._context_validation(finding)

    assert score == 0.5, "Should return neutral score when no tech stack"


@patch('requests.Session.get')
def test_live_validation_sqli_success(mock_get, orchestrator, sqli_finding):
    """Test live validation with successful SQLi detection."""
    # Mock response with SQL error
    mock_response = Mock()
    mock_response.text = "SQL syntax error in your query"
    mock_response.status_code = 200
    mock_get.return_value = mock_response

    success, retries = orchestrator._live_validation_with_retry(sqli_finding)

    assert success is True, "Should detect SQL error in response"
    assert retries == 0, "Should succeed on first attempt"


@patch('requests.Session.get')
def test_live_validation_retry_logic(mock_get, orchestrator, sqli_finding):
    """Test retry logic with transient failures."""
    # First 2 attempts fail, 3rd succeeds
    mock_response_fail = Mock()
    mock_response_fail.text = "normal response"
    mock_response_fail.status_code = 200

    mock_response_success = Mock()
    mock_response_success.text = "SQL syntax error"
    mock_response_success.status_code = 200

    mock_get.side_effect = [
        mock_response_fail,
        mock_response_fail,
        mock_response_success,
    ]

    success, retries = orchestrator._live_validation_with_retry(sqli_finding)

    assert success is True, "Should eventually succeed"
    assert retries == 2, "Should retry twice before success"


@patch('requests.Session.get')
def test_live_validation_max_retries(mock_get, orchestrator, sqli_finding):
    """Test max retries exceeded."""
    # All attempts fail
    mock_response = Mock()
    mock_response.text = "normal response"
    mock_response.status_code = 200
    mock_get.return_value = mock_response

    success, retries = orchestrator._live_validation_with_retry(sqli_finding)

    assert success is False, "Should fail after max retries"
    assert retries == orchestrator.MAX_RETRIES, "Should exhaust all retries"


@patch('requests.Session.get')
def test_hybrid_validation_high_confidence(mock_get, orchestrator, sqli_finding):
    """Test hybrid validation with high confidence finding."""
    # Mock successful live validation
    mock_response = Mock()
    mock_response.text = "SQL syntax error"
    mock_response.status_code = 200
    mock_get.return_value = mock_response

    result = orchestrator._validate_hybrid(sqli_finding)

    assert result.valid is True, "Should validate as true"
    assert result.confidence >= orchestrator.THRESHOLD_MEDIUM, "Should have medium+ confidence"
    assert result.live_validation is True, "Live validation should succeed"
    assert result.static_score >= 0.6, "Static score should be positive"
    assert result.context_score > 0.8, "Context score should be high"


@patch('requests.Session.get')
def test_hybrid_validation_skips_live_when_low_static(mock_get, orchestrator):
    """Test hybrid validation skips live test for low static+context score."""
    finding = Finding(
        id="test-006",
        type="sqli",
        target="https://example.com",
        payload="test",
        evidence="no SQL errors",  # Low static score
        severity="low",
        tech_stack=["mongodb"],  # Incompatible (low context score)
    )

    result = orchestrator._validate_hybrid(finding)

    assert result.live_validation is False, "Should skip live validation"
    assert result.confidence < orchestrator.THRESHOLD_MEDIUM, "Should have low confidence"
    assert result.valid is False, "Should not validate"
    mock_get.assert_not_called(), "Should not make HTTP request"


def test_xss_validation(orchestrator, xss_finding):
    """Test XSS-specific validation."""
    score = orchestrator._static_validation(xss_finding)

    assert score >= 0.6, "Should detect XSS pattern in evidence (score >= 0.6)"


def test_confidence_threshold_medium(orchestrator):
    """Test validation fails below medium threshold."""
    result = ValidationResult(
        finding_id="test-007",
        valid=False,
        confidence=0.60,  # Below THRESHOLD_MEDIUM (0.65)
    )

    # Manually compute validity based on threshold
    result.valid = result.confidence >= orchestrator.THRESHOLD_MEDIUM

    assert result.valid is False, "Should not validate below threshold"


def test_confidence_threshold_high(orchestrator):
    """Test validation succeeds above high threshold."""
    result = ValidationResult(
        finding_id="test-008",
        valid=True,
        confidence=0.85,  # Above THRESHOLD_HIGH (0.80)
    )

    result.valid = result.confidence >= orchestrator.THRESHOLD_MEDIUM

    assert result.valid is True, "Should validate above threshold"


def test_validation_caching(orchestrator, sqli_finding):
    """Test validation result caching."""
    # First validation
    with patch('requests.Session.get') as mock_get:
        mock_response = Mock()
        mock_response.text = "SQL error"
        mock_response.status_code = 200
        mock_get.return_value = mock_response

        result1 = orchestrator.validate_finding(sqli_finding)
        initial_call_count = mock_get.call_count

        # Second validation (should use cache, no new HTTP calls)
        result2 = orchestrator.validate_finding(sqli_finding)

        # Should not make new HTTP calls (cached)
        assert mock_get.call_count == initial_call_count, "Should cache result (no new HTTP calls)"
        assert result1.finding_id == result2.finding_id
        assert result1.confidence == result2.confidence


def test_get_validation_result_from_cache(orchestrator, sqli_finding):
    """Test retrieving cached validation result."""
    # Validate first
    with patch('requests.Session.get') as mock_get:
        mock_response = Mock()
        mock_response.text = "SQL error"
        mock_get.return_value = mock_response

        orchestrator.validate_finding(sqli_finding)

    # Retrieve from cache
    result = orchestrator.get_validation_result(sqli_finding.id)

    assert result is not None, "Should find cached result"
    assert result.finding_id == sqli_finding.id


def test_selective_validation_static_only(orchestrator, sqli_finding):
    """Test selective validation with only static strategy."""
    result = orchestrator._validate_selective(
        sqli_finding,
        [ValidationStrategy.STATIC]
    )

    assert result.static_score is not None, "Should have static score"
    assert result.context_score is None, "Should not have context score"
    assert result.live_validation is None, "Should not have live validation"


def test_selective_validation_context_only(orchestrator, sqli_finding):
    """Test selective validation with only context strategy."""
    result = orchestrator._validate_selective(
        sqli_finding,
        [ValidationStrategy.CONTEXT]
    )

    assert result.static_score is None, "Should not have static score"
    assert result.context_score is not None, "Should have context score"
    assert result.live_validation is None, "Should not have live validation"


@patch('requests.Session.get')
def test_validation_result_to_dict(mock_get, orchestrator, sqli_finding):
    """Test ValidationResult serialization."""
    mock_response = Mock()
    mock_response.text = "SQL error"
    mock_get.return_value = mock_response

    result = orchestrator.validate_finding(sqli_finding)
    result_dict = result.to_dict()

    assert "finding_id" in result_dict
    assert "valid" in result_dict
    assert "confidence" in result_dict
    assert "live_validation" in result_dict
    assert "static_score" in result_dict
    assert "context_score" in result_dict
    assert "retry_count" in result_dict
    assert "duration_ms" in result_dict
    assert isinstance(result_dict["confidence"], float)


def test_singleton_get_orchestrator():
    """Test singleton pattern for get_orchestrator."""
    from oneinfinity.agents.validation_orchestrator import get_orchestrator

    orch1 = get_orchestrator()
    orch2 = get_orchestrator()

    assert orch1 is orch2, "Should return same instance"


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
