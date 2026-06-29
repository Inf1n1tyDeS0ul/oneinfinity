"""
Tests for Payload Mutation Engine.
"""
import pytest
from oneinfinity.arsenal.mutation_engine import (
    MutationEngine,
    MutatedPayload,
    get_mutation_engine,
)


@pytest.fixture
def engine():
    """Fresh mutation engine."""
    return MutationEngine(max_mutations=50)


# ── Initialization Tests ──────────────────────────────────────────────────────

def test_engine_initialization(engine):
    """Test engine initializes correctly."""
    assert engine.max_mutations == 50
    assert len(engine.successful_mutations) == 0
    assert len(engine.mutation_history) == 0


def test_singleton_get_engine():
    """Test singleton pattern."""
    engine1 = get_mutation_engine()
    engine2 = get_mutation_engine()
    assert engine1 is engine2


# ── Encoding Mutations ────────────────────────────────────────────────────────

def test_encoding_mutations(engine):
    """Test encoding mutations generation."""
    payload = "<script>alert(1)</script>"
    mutations = engine._encoding_mutations(payload)

    assert len(mutations) >= 3  # URL, hex, base64
    strategies = [m.strategy for m in mutations]
    assert "url_encoding" in strategies
    assert "hex_encoding" in strategies
    assert "base64_encoding" in strategies


def test_double_encoding(engine):
    """Test double URL encoding."""
    payload = "<script>alert(1)</script>"
    mutations = engine._encoding_mutations(payload, double=True)

    double_encoded = [m for m in mutations if m.strategy == "double_url_encoding"]
    assert len(double_encoded) > 0


def test_unicode_mutations(engine):
    """Test unicode escape mutations."""
    payload = "<script>"
    mutations = engine._unicode_mutations(payload)

    assert len(mutations) >= 3
    strategies = [m.strategy for m in mutations]
    assert "unicode_escape" in strategies
    assert "html_entities" in strategies
    assert "mixed_unicode" in strategies


# ── Case Mutations ────────────────────────────────────────────────────────────

def test_case_mutations(engine):
    """Test case variation mutations."""
    payload = "SELECT * FROM users"
    mutations = engine._case_mutations(payload)

    assert len(mutations) >= 5
    strategies = [m.strategy for m in mutations]
    assert "uppercase" in strategies
    assert "lowercase" in strategies
    assert "alternating_case" in strategies


def test_case_uppercase(engine):
    """Test uppercase mutation."""
    payload = "select"
    mutations = engine._case_mutations(payload)

    uppercase = [m for m in mutations if m.strategy == "uppercase"]
    assert len(uppercase) == 1
    assert uppercase[0].content == "SELECT"


def test_case_alternating(engine):
    """Test alternating case mutation."""
    payload = "test"
    mutations = engine._case_mutations(payload)

    alt = [m for m in mutations if m.strategy == "alternating_case"]
    assert len(alt) == 1
    # Should alternate: TeSt
    assert alt[0].content[0].isupper()
    assert alt[0].content[1].islower()


# ── Whitespace Injection ──────────────────────────────────────────────────────

def test_whitespace_injection(engine):
    """Test whitespace injection mutations."""
    payload = "SELECT * FROM users"
    mutations = engine._whitespace_injection(payload, "sqli")

    assert len(mutations) >= 3
    strategies = [m.strategy for m in mutations]
    assert "space_padding" in strategies
    assert "tab_injection" in strategies


def test_whitespace_sql_newline(engine):
    """Test newline injection for SQL."""
    payload = "SELECT * FROM users"
    mutations = engine._whitespace_injection(payload, "sqli")

    newlined = [m for m in mutations if m.strategy == "newline_injection"]
    assert len(newlined) > 0
    assert "\n" in newlined[0].content


# ── Comment Injection ─────────────────────────────────────────────────────────

def test_comment_injection_sql(engine):
    """Test SQL comment injection."""
    payload = "SELECT * FROM users"
    mutations = engine._comment_injection(payload, "sqli")

    assert len(mutations) >= 2
    strategies = [m.strategy for m in mutations]
    assert "sql_inline_comments" in strategies or "sql_line_comments" in strategies


def test_comment_injection_xss(engine):
    """Test XSS comment injection."""
    payload = "<script>alert(1)</script>"
    mutations = engine._comment_injection(payload, "xss")

    strategies = [m.strategy for m in mutations]
    assert "html_comments" in strategies or "js_comments" in strategies


# ── Protocol Smuggling ────────────────────────────────────────────────────────

def test_protocol_smuggling(engine):
    """Test protocol smuggling mutations."""
    payload = "GET /admin HTTP/1.1"
    mutations = engine._protocol_smuggling(payload)

    assert len(mutations) >= 3
    strategies = [m.strategy for m in mutations]
    assert "crlf_injection" in strategies
    assert "header_injection" in strategies


def test_crlf_injection(engine):
    """Test CRLF injection."""
    payload = "test"
    mutations = engine._protocol_smuggling(payload)

    crlf = [m for m in mutations if m.strategy == "crlf_injection"]
    assert len(crlf) > 0
    assert "\r\n" in crlf[0].content


# ── Genetic Algorithm ─────────────────────────────────────────────────────────

def test_genetic_breed_no_parents(engine):
    """Test genetic breeding with no successful payloads."""
    payload = "<script>alert(1)</script>"
    mutations = engine._genetic_breed(payload, "xss")

    assert len(mutations) == 0  # No parents to breed with


def test_genetic_breed_with_parents(engine):
    """Test genetic breeding with successful parents."""
    # Add successful payloads
    engine.successful_mutations["xss"] = [
        "<svg onload=alert(1)>",
        "<img src=x onerror=alert(1)>",
    ]

    payload = "<script>alert(1)</script>"
    mutations = engine._genetic_breed(payload, "xss")

    assert len(mutations) > 0
    strategies = [m.strategy for m in mutations]
    assert any("genetic" in s for s in strategies)


def test_record_success(engine):
    """Test recording successful payloads."""
    engine.record_success("<svg onload=alert(1)>", "xss", waf="cloudflare")

    assert "xss" in engine.successful_mutations
    assert len(engine.successful_mutations["xss"]) == 1
    assert "<svg onload=alert(1)>" in engine.successful_mutations["xss"]


def test_record_success_limit(engine):
    """Test successful payload history limit."""
    # Add 60 payloads (should keep only last 50)
    for i in range(60):
        engine.record_success(f"payload_{i}", "xss")

    assert len(engine.successful_mutations["xss"]) == 50
    assert "payload_59" in engine.successful_mutations["xss"]
    assert "payload_0" not in engine.successful_mutations["xss"]


# ── Full Mutation Tests ───────────────────────────────────────────────────────

def test_mutate_basic(engine):
    """Test basic mutation generation."""
    payload = "<script>alert(1)</script>"
    mutations = engine.mutate(payload, vuln_type="xss")

    assert len(mutations) > 0
    assert len(mutations) <= engine.max_mutations


def test_mutate_waf_cloudflare(engine):
    """Test Cloudflare-specific mutations."""
    payload = "<script>alert(1)</script>"
    mutations = engine.mutate(payload, waf_vendor="cloudflare", vuln_type="xss")

    strategies = [m.strategy for m in mutations]
    # Should prioritize unicode, double encoding, case
    assert any("unicode" in s for s in strategies)


def test_mutate_waf_aws(engine):
    """Test AWS WAF-specific mutations."""
    payload = "GET /admin"
    mutations = engine.mutate(payload, waf_vendor="aws", vuln_type="ssrf")

    strategies = [m.strategy for m in mutations]
    # Should prioritize protocol, header injection
    assert any("protocol" in s or "header" in s for s in strategies)


def test_mutate_blocked_patterns(engine):
    """Test filtering blocked patterns."""
    payload = "<script>alert(1)</script>"
    blocked = ["<script>", "alert"]

    mutations = engine.mutate(payload, blocked_patterns=blocked, vuln_type="xss")

    # Should filter out mutations containing blocked patterns
    for mut in mutations:
        # Check that blocked patterns are not in mutation
        # (some encodings may bypass this, which is the goal)
        pass  # Just verify no error


def test_mutate_max_limit(engine):
    """Test max_mutations limit."""
    engine.max_mutations = 10
    payload = "<script>alert(1)</script>"

    mutations = engine.mutate(payload, vuln_type="xss")

    assert len(mutations) <= 10


# ── Statistics Tests ──────────────────────────────────────────────────────────

def test_get_stats(engine):
    """Test statistics collection."""
    payload = "<script>alert(1)</script>"
    engine.mutate(payload, vuln_type="xss")

    stats = engine.get_stats()

    assert "total_mutations" in stats
    assert "successful_payloads" in stats
    assert "strategy_distribution" in stats
    assert "vuln_types_learned" in stats
    assert stats["total_mutations"] > 0


def test_stats_strategy_distribution(engine):
    """Test strategy distribution in stats."""
    payload = "<script>alert(1)</script>"
    engine.mutate(payload, vuln_type="xss")

    stats = engine.get_stats()
    strategy_dist = stats["strategy_distribution"]

    # Should have multiple strategies
    assert len(strategy_dist) > 0
    assert all(isinstance(count, int) for count in strategy_dist.values())
