"""
Integration Tests: Week 2 + Week 3 Features
============================================
Tests full workflow integration across:
- GraphChainDetector + AttackGraphBuilder
- ContextMatcher + OffensiveRouter
- MutationEngine + OffensiveRouter
- RealtimeLearner + Event Bus
"""
import pytest
import time
from oneinfinity.attack_graph_core.builder import AttackGraphBuilder
from oneinfinity.attack_graph_core.graph_chain_detector import GraphChainDetector
from oneinfinity.arsenal.context_matcher import ContextMatcher, Payload, TargetContext
from oneinfinity.arsenal.mutation_engine import MutationEngine
from oneinfinity.orchestration.offensive_router import OffensiveRouter
from oneinfinity.learning.realtime_learner import RealtimeLearner
from oneinfinity.orchestration.event_bus import publish, EventType


# ── Graph Chain Detection Integration ────────────────────────────────────────

def test_graph_chain_full_workflow():
    """Test full workflow: findings → graph → chains."""
    # Create findings with exploit chain
    findings = [
        {
            "id": 1,
            "vuln_type": "idor",
            "host": "api.test.com",
            "endpoint": "https://api.test.com/users/{id}",
            "severity": "medium",
            "confidence": "high",
            "cvss_score": 5.5,
        },
        {
            "id": 2,
            "vuln_type": "jwt_weak_secret",
            "host": "api.test.com",
            "endpoint": "https://api.test.com/auth/token",
            "severity": "high",
            "confidence": "high",
            "cvss_score": 7.8,
        },
        {
            "id": 3,
            "vuln_type": "rce",
            "host": "api.test.com",
            "endpoint": "https://api.test.com/admin/exec",
            "severity": "critical",
            "confidence": "high",
            "cvss_score": 9.8,
        },
    ]

    # Build graph
    builder = AttackGraphBuilder(target="api.test.com")
    builder.from_findings(findings)

    # Add chain edges
    builder.add_chain_edge("finding_1", "finding_2", label="escalate", confidence="high")
    builder.add_chain_edge("finding_2", "finding_3", label="exploit", confidence="high")

    # Detect chains
    graph = builder.build(detect_chains=True)

    # Verify chains detected
    assert "detected_chains" in graph.metadata
    chains = graph.metadata["detected_chains"]
    assert len(chains) > 0

    # Verify chain properties
    chain = chains[0]
    assert chain["length"] == 3
    assert chain["objective"] == "rce"
    assert chain["exploitability"] > 0.3


def test_chain_detector_with_empty_graph():
    """Test chain detector with no findings."""
    builder = AttackGraphBuilder(target="empty.com")
    graph = builder.build(detect_chains=True)

    assert graph.metadata.get("chain_count", 0) == 0
    assert graph.metadata.get("detected_chains", []) == []


# ── Context Matcher + Offensive Router Integration ───────────────────────────

def test_context_matcher_offensive_router():
    """Test ContextMatcher integration with OffensiveRouter."""
    router = OffensiveRouter()

    # Create payload selection scenario
    context = {
        "vuln_type": "xss",
        "tech_stack": ["php", "mysql"],
        "waf": "cloudflare",
        "blocked_patterns": [],
        "severity": "high"
    }

    # Execute task (forces embedded arsenal)
    result = router.execute_offensive_task(
        task_type="exploit",
        context=context,
        prefer_llm=False
    )

    assert result["source"] in ("embedded", "mutation")
    assert result["task_type"] == "exploit"
    assert "result" in result


def test_offensive_router_with_blocked_payload():
    """Test mutation generation when payload blocked."""
    router = OffensiveRouter()

    context = {
        "vuln_type": "sqli",
        "tech_stack": ["php", "mysql"],
        "waf": "cloudflare",
        "blocked": True,  # Trigger mutation
        "blocked_patterns": ["OR", "UNION"],
        "severity": "high"
    }

    result = router.execute_offensive_task(
        task_type="exploit",
        context=context,
        prefer_llm=False,
        mutate_if_blocked=True
    )

    # Should use mutation engine
    assert result["source"] in ("mutation", "embedded")


# ── Mutation Engine Integration ──────────────────────────────────────────────

def test_mutation_engine_waf_specific():
    """Test mutation engine with WAF-specific strategies."""
    engine = MutationEngine()

    payload = "<script>alert(1)</script>"

    # Cloudflare mutations
    cf_mutations = engine.mutate(
        payload=payload,
        waf_vendor="cloudflare",
        vuln_type="xss"
    )

    assert len(cf_mutations) > 0
    # Should prioritize unicode, double encoding
    strategies = [m.strategy for m in cf_mutations]
    assert any("unicode" in s or "encoding" in s for s in strategies)


def test_mutation_engine_genetic_breeding():
    """Test genetic algorithm with successful payloads."""
    engine = MutationEngine()

    # Record successful payloads
    engine.record_success("<svg onload=alert(1)>", "xss")
    engine.record_success("<img src=x onerror=alert(1)>", "xss")

    # Generate mutations (genetic should be included)
    payload = "<script>alert(1)</script>"
    mutations = engine.mutate(
        payload=payload,
        waf_vendor="imperva",  # Prefers genetic
        vuln_type="xss"
    )

    strategies = [m.strategy for m in mutations]
    assert any("genetic" in s for s in strategies)


# ── Real-Time Learner Integration ────────────────────────────────────────────

@pytest.mark.asyncio
async def test_realtime_learner_event_integration():
    """Test RealtimeLearner receives and processes events."""
    learner = RealtimeLearner()
    initial_adaptations = learner.adaptation_count

    # Emit event
    publish(
        event_type=EventType.NEW_VULNERABILITY,
        data={
            "finding_id": "int_test_1",
            "vuln_type": "xss",
            "confidence": 0.9,
            "tool": "nuclei",
            "status": "confirmed"
        }
    )

    # Wait for async processing
    await asyncio.sleep(0.3)

    # Verify learning occurred
    assert learner.adaptation_count > initial_adaptations
    assert "nuclei" in learner.tool_confidence


@pytest.mark.asyncio
async def test_learner_tool_confidence_tracking():
    """Test tool confidence updates over multiple events."""
    learner = RealtimeLearner()

    # Clear existing data
    learner.tool_confidence.clear()

    # Emit multiple events for same tool
    for i in range(5):
        publish(
            event_type=EventType.NEW_VULNERABILITY,
            data={
                "finding_id": f"conf_test_{i}",
                "vuln_type": "sqli",
                "confidence": 0.8,
                "tool": "sqlmap",
                "status": "confirmed"
            }
        )

    # Poll with timeout instead of fixed sleep
    timeout = 2.0
    start = time.time()
    while time.time() - start < timeout:
        if "sqlmap" in learner.tool_confidence:
            tc = learner.tool_confidence["sqlmap"]
            if tc.success_count == 5:
                break
        await asyncio.sleep(0.1)

    # Verify tool confidence increased
    assert "sqlmap" in learner.tool_confidence
    tc = learner.tool_confidence["sqlmap"]
    assert tc.success_count == 5
    assert tc.confidence > 0.8  # Should increase from baseline


# ── Cross-Feature Integration ────────────────────────────────────────────────

def test_full_offensive_pipeline():
    """Test full offensive pipeline: context → selection → mutation."""
    matcher = ContextMatcher()
    engine = MutationEngine()

    # Step 1: Create target context
    context = TargetContext(
        vuln_type="sqli",
        tech_stack=["php", "mysql"],
        waf="cloudflare",
        blocked_patterns=set(),
        previous_attempts=0
    )

    # Step 2: Select payload
    payloads = [
        Payload(content="' OR 1=1--", vuln_type="sqli", tech_stack=["php", "mysql"]),
        Payload(content="' UNION SELECT NULL--", vuln_type="sqli", tech_stack=["php"]),
    ]

    selected = matcher.select_best_payload(payloads, context)
    assert selected is not None

    # Step 3: Generate mutations
    mutations = engine.mutate(
        payload=selected.content,
        waf_vendor="cloudflare",
        vuln_type="sqli"
    )

    assert len(mutations) > 0


def test_learning_feedback_loop():
    """Test learning feedback loop updates future selections."""
    learner = RealtimeLearner()
    initial_pattern_count = learner.pattern_count

    # Simulate successful exploitation
    publish(
        event_type=EventType.EXPLOIT_ATTEMPTED,
        data={
            "vuln_type": "xss",
            "payload": "<svg onload=alert(1)>",
            "success": True,
            "tool": "custom"
        }
    )

    # Poll with timeout
    timeout = 2.0
    start = time.time()
    while time.time() - start < timeout:
        if learner.pattern_count > initial_pattern_count:
            break
        time.sleep(0.1)

    # Verify pattern learned
    assert learner.pattern_count > initial_pattern_count


# ── Performance Tests ─────────────────────────────────────────────────────────

def test_chain_detection_performance():
    """Test chain detection completes in reasonable time."""
    # Create large graph
    findings = [
        {
            "id": i,
            "vuln_type": "xss" if i % 3 == 0 else "sqli",
            "host": f"host{i}.com",
            "endpoint": f"https://host{i}.com/test",
            "severity": "medium",
            "confidence": "high",
            "cvss_score": 5.0 + (i % 5)
        }
        for i in range(100)
    ]

    builder = AttackGraphBuilder(target="perf.test.com")
    builder.from_findings(findings)

    start = time.time()
    graph = builder.build(detect_chains=True)
    elapsed = time.time() - start

    # Should complete in <5 seconds for 100 nodes
    assert elapsed < 5.0


def test_mutation_generation_performance():
    """Test mutation engine generates 50 mutations quickly."""
    engine = MutationEngine(max_mutations=50)
    payload = "<script>alert(document.domain)</script>"

    start = time.time()
    mutations = engine.mutate(payload, waf_vendor="cloudflare", vuln_type="xss")
    elapsed = time.time() - start

    assert len(mutations) > 0
    assert elapsed < 0.5  # Should be very fast


def test_context_matcher_large_set_performance():
    """Test context matcher handles large payload sets."""
    matcher = ContextMatcher()

    # Create 1000 payloads
    payloads = [
        Payload(content=f"payload_{i}", vuln_type="xss")
        for i in range(1000)
    ]

    context = TargetContext(vuln_type="xss")

    start = time.time()
    selected = matcher.select_best_payload(payloads, context)
    elapsed = time.time() - start

    assert selected is not None
    assert elapsed < 0.1  # <100ms for 1000 payloads


# ── Error Handling Tests ──────────────────────────────────────────────────────

def test_chain_detector_handles_malformed_findings():
    """Test chain detector gracefully handles bad data."""
    findings = [
        {"id": 1, "vuln_type": "xss"},  # Missing required fields
        {"vuln_type": "sqli"},  # Missing ID
        {},  # Empty
    ]

    builder = AttackGraphBuilder(target="bad.com")
    builder.from_findings(findings)
    graph = builder.build(detect_chains=True)

    # Should not crash
    assert graph.metadata.get("chain_count", 0) >= 0


def test_mutation_engine_handles_empty_payload():
    """Test mutation engine with empty payload."""
    engine = MutationEngine()

    mutations = engine.mutate(payload="", vuln_type="xss")

    # Should return empty or minimal mutations
    assert isinstance(mutations, list)


def test_offensive_router_handles_missing_context():
    """Test offensive router with minimal context."""
    router = OffensiveRouter()

    result = router.execute_offensive_task(
        task_type="exploit",
        context={},  # Empty context
        prefer_llm=False
    )

    assert "result" in result
    assert "source" in result


# ── Import for async tests ────────────────────────────────────────────────────

import asyncio
