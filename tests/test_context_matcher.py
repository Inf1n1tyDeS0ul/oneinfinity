"""
Tests for Context-Aware Payload Matcher.
"""
import pytest
from oneinfinity.arsenal.context_matcher import (
    ContextMatcher,
    Payload,
    TargetContext,
    get_context_matcher,
)


@pytest.fixture
def matcher():
    """Create fresh ContextMatcher instance."""
    return ContextMatcher()


@pytest.fixture
def sample_payloads():
    """Sample payloads for testing."""
    return [
        Payload(
            content="' OR '1'='1",
            vuln_type="sqli",
            tech_stack=["php", "mysql"],
            complexity="simple",
            success_rate=0.7,
        ),
        Payload(
            content="' UNION SELECT NULL--",
            vuln_type="sqli",
            tech_stack=["php", "mysql"],
            waf_bypasses=["cloudflare"],
            complexity="medium",
            success_rate=0.6,
        ),
        Payload(
            content="1' AND (SELECT * FROM (SELECT(SLEEP(5)))a)--",
            vuln_type="sqli",
            tech_stack=["mysql"],
            complexity="complex",
            success_rate=0.5,
        ),
    ]


# ── Basic Selection Tests ────────────────────────────────────────────────────

def test_select_best_payload_basic(matcher, sample_payloads):
    """Test basic payload selection."""
    context = TargetContext(vuln_type="sqli", tech_stack=["php", "mysql"])

    payload = matcher.select_best_payload(sample_payloads, context)

    assert payload is not None
    assert payload.vuln_type == "sqli"


def test_select_from_empty_list(matcher):
    """Test selection with no payloads."""
    context = TargetContext(vuln_type="sqli")

    payload = matcher.select_best_payload([], context)

    assert payload is None


def test_select_single_payload(matcher):
    """Test selection with single payload."""
    payloads = [Payload(content="test", vuln_type="xss")]
    context = TargetContext(vuln_type="xss")

    payload = matcher.select_best_payload(payloads, context)

    assert payload is not None
    assert payload.content == "test"


# ── Tech Stack Matching Tests ────────────────────────────────────────────────

def test_tech_stack_perfect_match(matcher, sample_payloads):
    """Test perfect tech stack match gets highest score."""
    context = TargetContext(
        vuln_type="sqli",
        tech_stack=["php", "mysql"],
    )

    payload = matcher.select_best_payload(sample_payloads, context)

    # Should select first payload (perfect tech match, simple, high success)
    assert payload.content == "' OR '1'='1"


def test_tech_stack_partial_match(matcher):
    """Test partial tech stack matching."""
    payloads = [
        Payload(content="p1", vuln_type="sqli", tech_stack=["php", "mysql"]),
        Payload(content="p2", vuln_type="sqli", tech_stack=["python", "postgresql"]),
    ]
    context = TargetContext(vuln_type="sqli", tech_stack=["php"])

    payload = matcher.select_best_payload(payloads, context)

    # Should prefer PHP payload
    assert payload.content == "p1"


def test_tech_stack_no_match(matcher):
    """Test selection when no tech stack matches."""
    payloads = [
        Payload(content="p1", vuln_type="xss", tech_stack=["php"]),
        Payload(content="p2", vuln_type="xss", tech_stack=["python"]),
    ]
    context = TargetContext(vuln_type="xss", tech_stack=["java"])

    payload = matcher.select_best_payload(payloads, context)

    # Should still select something (neutral scoring)
    assert payload is not None


# ── WAF Compatibility Tests ──────────────────────────────────────────────────

def test_waf_bypass_match(matcher, sample_payloads):
    """Test WAF bypass capability scoring."""
    context = TargetContext(
        vuln_type="sqli",
        tech_stack=["php", "mysql"],
        waf="cloudflare",
    )

    payload = matcher.select_best_payload(sample_payloads, context)

    # Should prefer payload with cloudflare bypass
    assert "UNION" in payload.content


def test_no_waf_detected(matcher, sample_payloads):
    """Test selection when no WAF detected."""
    context = TargetContext(
        vuln_type="sqli",
        tech_stack=["php"],
        waf=None,
    )

    payload = matcher.select_best_payload(sample_payloads, context)

    # All payloads equally good for WAF, other factors decide
    assert payload is not None


def test_waf_generic(matcher):
    """Test generic WAF handling."""
    payloads = [
        Payload(content="p1", vuln_type="xss", tags=["waf-bypass"]),
        Payload(content="p2", vuln_type="xss", tags=[]),
    ]
    context = TargetContext(vuln_type="xss", waf="generic_waf")

    payload = matcher.select_best_payload(payloads, context)

    # Should prefer payload with waf-bypass tag
    assert payload.content == "p1"


# ── Filter Evasion Tests ─────────────────────────────────────────────────────

def test_filter_evasion_no_blocks(matcher, sample_payloads):
    """Test filter evasion when no blocks detected."""
    context = TargetContext(
        vuln_type="sqli",
        tech_stack=["php"],
        blocked_patterns=set(),
    )

    payload = matcher.select_best_payload(sample_payloads, context)

    # All payloads equally good, other factors decide
    assert payload is not None


def test_filter_evasion_with_blocks(matcher):
    """Test filter evasion with blocked patterns."""
    payloads = [
        Payload(content="' OR 1=1--", vuln_type="sqli"),
        Payload(content="' UNION SELECT", vuln_type="sqli"),
        Payload(content="1' AND SLEEP(5)--", vuln_type="sqli"),
    ]
    context = TargetContext(
        vuln_type="sqli",
        blocked_patterns={"OR", "UNION"},
    )

    payload = matcher.select_best_payload(payloads, context)

    # Should avoid payloads with blocked patterns
    assert "SLEEP" in payload.content


def test_filter_evasion_all_blocked(matcher):
    """Test when all payloads contain blocked patterns."""
    payloads = [
        Payload(content="' OR 1=1", vuln_type="sqli"),
        Payload(content="' OR 2=2", vuln_type="sqli"),
    ]
    context = TargetContext(
        vuln_type="sqli",
        blocked_patterns={"OR"},
    )

    payload = matcher.select_best_payload(payloads, context)

    # Should still select best available (lowest penalty)
    assert payload is not None


# ── Historical Success Tests ─────────────────────────────────────────────────

def test_historical_success_high_rate(matcher):
    """Test payload with high success rate preferred."""
    payloads = [
        Payload(content="p1", vuln_type="xss", success_rate=0.3),
        Payload(content="p2", vuln_type="xss", success_rate=0.9),
    ]
    context = TargetContext(vuln_type="xss")

    payload = matcher.select_best_payload(payloads, context)

    # Should prefer high success rate
    assert payload.content == "p2"


def test_historical_success_learning(matcher):
    """Test learning from feedback updates success history."""
    payloads = [Payload(content="test", vuln_type="sqli")]
    context = TargetContext(vuln_type="sqli", tech_stack=["php"])

    # Provide successful feedback
    feedback = {"success": True, "payload_id": "test"}
    matcher.adaptive_selection(payloads, context, feedback)

    # Check history updated
    stats = matcher.get_stats()
    assert stats["success_history_entries"] > 0


# ── Complexity Matching Tests ────────────────────────────────────────────────

def test_complexity_escalation_first_attempt(matcher):
    """Test simple payload preferred on first attempt."""
    payloads = [
        Payload(content="simple", vuln_type="xss", complexity="simple"),
        Payload(content="complex", vuln_type="xss", complexity="complex"),
    ]
    context = TargetContext(vuln_type="xss", previous_attempts=0)

    payload = matcher.select_best_payload(payloads, context)

    # Should start with simple
    assert payload.content == "simple"


def test_complexity_escalation_after_failures(matcher):
    """Test complex payload preferred after failures."""
    payloads = [
        Payload(content="simple", vuln_type="xss", complexity="simple"),
        Payload(content="complex", vuln_type="xss", complexity="complex"),
    ]
    context = TargetContext(vuln_type="xss", previous_attempts=5)

    payload = matcher.select_best_payload(payloads, context)

    # Should escalate to complex
    assert payload.content == "complex"


def test_complexity_medium_after_two_attempts(matcher):
    """Test medium complexity preferred after 2 attempts."""
    payloads = [
        Payload(content="simple", vuln_type="xss", complexity="simple"),
        Payload(content="medium", vuln_type="xss", complexity="medium"),
        Payload(content="complex", vuln_type="xss", complexity="complex"),
    ]
    context = TargetContext(vuln_type="xss", previous_attempts=2)

    payload = matcher.select_best_payload(payloads, context)

    # Should use medium
    assert payload.content == "medium"


# ── Tech Stack Detection Tests ───────────────────────────────────────────────

def test_detect_tech_stack_php(matcher):
    """Test PHP detection from headers."""
    headers = {"X-Powered-By": "PHP/7.4.3"}
    body = ""

    detected = matcher.detect_tech_stack(headers, body)

    assert "php" in detected


def test_detect_tech_stack_python(matcher):
    """Test Python detection."""
    headers = {"Server": "uvicorn"}
    body = "FastAPI application"

    detected = matcher.detect_tech_stack(headers, body)

    assert "python" in detected


def test_detect_tech_stack_multiple(matcher):
    """Test multiple tech detection."""
    headers = {"X-Powered-By": "Express"}
    body = "<!-- Powered by Node.js -->"

    detected = matcher.detect_tech_stack(headers, body)

    assert "node" in detected


# ── WAF Detection Tests ──────────────────────────────────────────────────────

def test_detect_waf_cloudflare(matcher):
    """Test Cloudflare WAF detection."""
    headers = {"CF-Ray": "abc123"}

    waf = matcher.detect_waf(headers, 200, "")

    assert waf == "cloudflare"


def test_detect_waf_aws(matcher):
    """Test AWS WAF detection."""
    headers = {"X-Amzn-Trace-Id": "xyz"}

    waf = matcher.detect_waf(headers, 200, "")

    assert waf == "aws"


def test_detect_waf_generic_403(matcher):
    """Test generic WAF detection on 403."""
    headers = {}
    body = "Access Blocked by Security Policy"

    waf = matcher.detect_waf(headers, 403, body)

    assert waf == "generic_waf"


def test_no_waf_detected(matcher):
    """Test when no WAF present."""
    headers = {"Server": "nginx"}

    waf = matcher.detect_waf(headers, 200, "")

    assert waf is None


# ── Adaptive Selection Tests ─────────────────────────────────────────────────

def test_adaptive_selection_with_feedback(matcher):
    """Test adaptive selection processes feedback."""
    payloads = [Payload(content="test", vuln_type="xss")]
    context = TargetContext(vuln_type="xss")
    feedback = {
        "success": False,
        "blocked_patterns": ["alert", "script"],
    }

    payload = matcher.adaptive_selection(payloads, context, feedback)

    # Should update context with blocked patterns
    assert "alert" in context.blocked_patterns
    assert "script" in context.blocked_patterns


def test_adaptive_selection_no_feedback(matcher, sample_payloads):
    """Test adaptive selection without feedback."""
    context = TargetContext(vuln_type="sqli")

    payload = matcher.adaptive_selection(sample_payloads, context, None)

    assert payload is not None


# ── Performance Test ─────────────────────────────────────────────────────────

def test_selection_performance(matcher):
    """Test selection completes in <100ms for 10k payloads."""
    import time

    # Create 10k payloads
    payloads = [
        Payload(content=f"payload_{i}", vuln_type="xss")
        for i in range(10000)
    ]
    context = TargetContext(vuln_type="xss")

    start = time.time()
    payload = matcher.select_best_payload(payloads, context)
    elapsed_ms = (time.time() - start) * 1000

    assert payload is not None
    assert elapsed_ms < 100, f"Selection took {elapsed_ms:.1f}ms (expected <100ms)"


# ── Singleton Test ───────────────────────────────────────────────────────────

def test_singleton_get_context_matcher():
    """Test singleton pattern for ContextMatcher."""
    matcher1 = get_context_matcher()
    matcher2 = get_context_matcher()

    assert matcher1 is matcher2


# ── Stats Test ───────────────────────────────────────────────────────────────

def test_get_stats(matcher):
    """Test stats collection."""
    stats = matcher.get_stats()

    assert "cached_payloads" in stats
    assert "success_history_entries" in stats
    assert "avg_success_rate" in stats
    assert 0.0 <= stats["avg_success_rate"] <= 1.0
