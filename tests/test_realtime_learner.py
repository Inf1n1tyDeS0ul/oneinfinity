"""
Tests for Real-Time Learning Engine.
"""
import pytest
import time
from oneinfinity.learning.realtime_learner import (
    RealtimeLearner,
    ToolConfidence,
    LearningEvent,
    get_learner,
)


@pytest.fixture
def learner():
    """Fresh learner instance."""
    return RealtimeLearner()


# ── Initialization Tests ──────────────────────────────────────────────────────

def test_learner_initialization(learner):
    """Test learner initializes correctly."""
    assert learner.scan_count == 0
    assert learner.adaptation_count == 0
    assert learner.pattern_count == 0
    assert len(learner.tool_confidence) == 0
    assert len(learner.learning_events) == 0


def test_singleton_get_learner():
    """Test singleton pattern."""
    learner1 = get_learner()
    learner2 = get_learner()
    assert learner1 is learner2


# ── Tool Confidence Tests ─────────────────────────────────────────────────────

def test_tool_confidence_success(learner):
    """Test tool confidence increases with success."""
    learner._update_tool_confidence("nuclei", success=True)

    tc = learner.tool_confidence["nuclei"]
    assert tc.success_count == 1
    assert tc.failure_count == 0
    assert tc.confidence > 0.8  # Should increase


def test_tool_confidence_failure(learner):
    """Test tool confidence decreases with failure."""
    learner._update_tool_confidence("sqlmap", success=False)
    learner._update_tool_confidence("sqlmap", success=False)

    tc = learner.tool_confidence["sqlmap"]
    assert tc.failure_count == 2
    assert tc.confidence < 0.8  # Should decrease


def test_tool_confidence_false_positive(learner):
    """Test false positive tracking."""
    learner._update_tool_confidence("dalfox", false_positive=True)

    tc = learner.tool_confidence["dalfox"]
    assert tc.false_positive_count == 1


def test_tool_confidence_mixed(learner):
    """Test mixed success/failure updates."""
    tool = "httpx"

    learner._update_tool_confidence(tool, success=True)
    learner._update_tool_confidence(tool, success=True)
    learner._update_tool_confidence(tool, success=False)

    tc = learner.tool_confidence[tool]
    assert tc.success_count == 2
    assert tc.failure_count == 1
    assert tc.success_rate == 2/3
    assert 0.7 < tc.confidence < 0.9


def test_tool_confidence_calculation():
    """Test ToolConfidence success rate calculation."""
    tc = ToolConfidence(tool_name="test")
    assert tc.success_rate == 0.5  # No data = 50%

    tc.success_count = 7
    tc.failure_count = 3
    assert tc.success_rate == 0.7


# ── Event Handler Tests ───────────────────────────────────────────────────────

@pytest.mark.asyncio
async def test_on_finding_validated_success(learner):
    """Test finding validation handler (confirmed)."""
    event = type('obj', (object,), {
        'data': {
            'finding_id': 'test_1',
            'vuln_type': 'xss',
            'confidence': 0.9,
            'tool': 'nuclei',
            'status': 'confirmed'
        }
    })

    await learner._on_finding_validated(event)

    assert learner.adaptation_count == 1
    assert 'nuclei' in learner.tool_confidence
    assert learner.tool_confidence['nuclei'].success_count == 1
    assert len(learner.learning_events) == 1
    assert learner.learning_events[0].impact == "positive"


@pytest.mark.asyncio
async def test_on_finding_validated_false_positive(learner):
    """Test finding validation handler (false positive)."""
    event = type('obj', (object,), {
        'data': {
            'finding_id': 'test_2',
            'vuln_type': 'sqli',
            'confidence': 0.5,
            'tool': 'sqlmap',
            'status': 'false_positive'
        }
    })

    await learner._on_finding_validated(event)

    assert 'sqlmap' in learner.tool_confidence
    assert learner.tool_confidence['sqlmap'].false_positive_count == 1
    assert learner.learning_events[0].impact == "negative"


@pytest.mark.asyncio
async def test_on_exploit_attempted_success(learner):
    """Test exploit attempt handler (successful)."""
    event = type('obj', (object,), {
        'data': {
            'vuln_type': 'rce',
            'payload': 'ls -la',
            'success': True,
            'tool': 'custom'
        }
    })

    await learner._on_exploit_attempted(event)

    assert learner.pattern_count == 1
    assert 'custom' in learner.tool_confidence
    assert learner.tool_confidence['custom'].success_count == 1


@pytest.mark.asyncio
async def test_on_exploit_attempted_failure(learner):
    """Test exploit attempt handler (failed)."""
    event = type('obj', (object,), {
        'data': {
            'vuln_type': 'xss',
            'payload': '<script>alert(1)</script>',
            'success': False,
            'tool': 'dalfox'
        }
    })

    await learner._on_exploit_attempted(event)

    assert learner.pattern_count == 0  # No pattern added for failure
    assert 'dalfox' in learner.tool_confidence
    assert learner.tool_confidence['dalfox'].failure_count == 1


@pytest.mark.asyncio
async def test_on_chain_detected(learner):
    """Test chain detection handler."""
    event = type('obj', (object,), {
        'data': {
            'chain_name': 'idor_to_rce',
            'steps': ['vuln:idor_1', 'vuln:jwt_2', 'vuln:rce_3'],
            'exploitability_score': 0.85
        }
    })

    await learner._on_chain_detected(event)

    assert learner.pattern_count == 1
    assert learner.adaptation_count == 1
    assert len(learner.learning_events) == 1
    assert learner.learning_events[0].event_type == "chain_detected"


@pytest.mark.asyncio
async def test_on_tool_failed(learner):
    """Test tool failure handler."""
    event = type('obj', (object,), {
        'data': {
            'tool': 'masscan',
            'reason': 'timeout'
        }
    })

    await learner._on_tool_failed(event)

    assert 'masscan' in learner.tool_confidence
    assert learner.tool_confidence['masscan'].failure_count == 1
    assert learner.learning_events[0].impact == "negative"


# ── Metrics Tests ─────────────────────────────────────────────────────────────

def test_get_tool_confidence_map(learner):
    """Test tool confidence map export."""
    learner._update_tool_confidence("tool1", success=True)
    learner._update_tool_confidence("tool2", success=False)

    conf_map = learner.get_tool_confidence_map()

    assert "tool1" in conf_map
    assert "tool2" in conf_map
    assert conf_map["tool1"] > conf_map["tool2"]


def test_compute_improvement_rate(learner):
    """Test improvement rate calculation."""
    assert learner.compute_improvement_rate() == 0.0  # No scans

    learner.scan_count = 5
    learner.adaptation_count = 15

    rate = learner.compute_improvement_rate()
    assert rate == 3.0  # 15 adaptations / 5 scans


def test_on_scan_complete(learner):
    """Test scan completion handler."""
    learner.on_scan_complete()
    assert learner.scan_count == 1

    learner.on_scan_complete()
    assert learner.scan_count == 2


def test_get_learning_velocity(learner):
    """Test learning velocity calculation."""
    # No events = 0 velocity
    assert learner.get_learning_velocity() == 0.0

    # Add events with time spread
    now = time.time()
    learner.learning_events = [
        LearningEvent("e1", "test", now, {}, "positive"),
        LearningEvent("e2", "test", now + 3600, {}, "positive"),  # 1 hour later
    ]

    velocity = learner.get_learning_velocity()
    assert velocity > 0  # Some events per hour


def test_get_learning_events(learner):
    """Test learning events export."""
    learner.learning_events = [
        LearningEvent("e1", "finding_validated", time.time(), {"tool": "nuclei"}, "positive"),
        LearningEvent("e2", "tool_failed", time.time(), {"tool": "sqlmap"}, "negative"),
    ]

    events = learner.get_learning_events(limit=10)

    assert len(events) == 2
    assert events[0]["event_type"] == "finding_validated"
    assert events[1]["impact"] == "negative"


def test_get_learning_events_limit(learner):
    """Test learning events limit."""
    # Add 150 events
    for i in range(150):
        learner.learning_events.append(
            LearningEvent(f"e{i}", "test", time.time(), {}, "neutral")
        )

    events = learner.get_learning_events(limit=100)
    assert len(events) == 100  # Should return last 100
