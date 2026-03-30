"""Tests for false-positive hotspot fixes."""
import sys, os
sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))

from zero_day_engine import ZeroDayEngine, ResponseProfile, _TIMING_THRESHOLD_MS, _SIZE_DEVIATION_PCT, _CONFIDENCE_FLOOR, _MEANINGFUL_PAYLOAD_CHARS

def _make_baseline(status=200, length=500, time_ms=100.0):
    return ResponseProfile(url="http://test.local/api", status_code=status,
                           content_length=length, response_time_ms=time_ms)

def _make_probe(status=200, length=500, time_ms=100.0, payload="test", param="q"):
    return ResponseProfile(url="http://test.local/api", status_code=status,
                           content_length=length, response_time_ms=time_ms,
                           payload=payload, parameter=param)

def make_engine():
    return ZeroDayEngine(target="test.local")

# FP Fix 1: status code — 200→301 must NOT fire
def test_redirect_status_change_does_not_fire():
    e = make_engine()
    baseline = _make_baseline(status=200)
    probe = _make_probe(status=301)
    anomalies = e.analyze_responses(baseline, probe)
    status_anomalies = [a for a in anomalies if a.anomaly_type == "StatusCodeChange"]
    assert len(status_anomalies) == 0, "301 redirect should not trigger StatusCodeChange"

# FP Fix 1: status code — 200→500 MUST fire
def test_200_to_500_fires():
    e = make_engine()
    baseline = _make_baseline(status=200)
    probe = _make_probe(status=500)
    anomalies = e.analyze_responses(baseline, probe)
    status_anomalies = [a for a in anomalies if a.anomaly_type == "StatusCodeChange"]
    assert len(status_anomalies) == 1

# FP Fix 2: timing — delta below new threshold (6000ms) must not fire
def test_timing_below_threshold_does_not_fire():
    e = make_engine()
    baseline = _make_baseline(time_ms=100.0)
    probe = _make_probe(time_ms=5000.0)  # delta=4900ms, below 6000ms threshold
    anomalies = e.analyze_responses(baseline, probe)
    timing = [a for a in anomalies if a.anomaly_type == "TimingAnomaly"]
    assert len(timing) == 0

# FP Fix 2: timing — delta above threshold (6000ms) MUST fire
def test_timing_above_threshold_fires():
    e = make_engine()
    baseline = _make_baseline(time_ms=100.0)
    probe = _make_probe(time_ms=7000.0)  # delta=6900ms, above 6000ms threshold
    anomalies = e.analyze_responses(baseline, probe)
    timing = [a for a in anomalies if a.anomaly_type == "TimingAnomaly"]
    assert len(timing) == 1

# FP Fix 3: confidence floor — constant exists and equals 0.4
def test_confidence_floor_constant():
    assert _CONFIDENCE_FLOOR == 0.4

# FP Fix 4: reflection — short non-special payloads don't fire
def test_reflection_non_special_payload_does_not_fire():
    e = make_engine()
    baseline = _make_baseline()
    baseline.body_snippet = ""
    probe = _make_probe(payload="abc")   # no < > " ' — not meaningful
    probe.body_snippet = "abc is here"
    anomalies = e.analyze_responses(baseline, probe)
    reflection = [a for a in anomalies if a.anomaly_type == "ReflectionDetected"]
    assert len(reflection) == 0, "Non-special payload should not trigger ReflectionDetected"

# FP Fix 4: reflection — payload with < fires
def test_reflection_special_payload_fires():
    e = make_engine()
    baseline = _make_baseline()
    baseline.body_snippet = ""
    probe = _make_probe(payload='<script>x</script>')
    probe.body_snippet = '<script>x</script> present'
    anomalies = e.analyze_responses(baseline, probe)
    reflection = [a for a in anomalies if a.anomaly_type == "ReflectionDetected"]
    assert len(reflection) == 1

# FP Fix 5: meaningful payload chars constant exists
def test_meaningful_payload_chars_constant():
    assert '<' in _MEANINGFUL_PAYLOAD_CHARS
    assert '>' in _MEANINGFUL_PAYLOAD_CHARS
    assert '"' in _MEANINGFUL_PAYLOAD_CHARS

def test_401_to_200_fires_auth_bypass():
    """Auth bypass (401→200) MUST still be detected after FP fixes."""
    e = make_engine()
    baseline = _make_baseline(status=401)
    probe = _make_probe(status=200)
    anomalies = e.analyze_responses(baseline, probe)
    status_anomalies = [a for a in anomalies if a.anomaly_type == "StatusCodeChange"]
    assert len(status_anomalies) == 1, "401→200 auth bypass must trigger StatusCodeChange"
