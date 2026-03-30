# OneInfinity — Full OWASP WSTG v4.2 Coverage Design

**Date:** 2026-03-30
**Status:** Approved
**Scope:** Close all OWASP Web Security Testing Guide v4.2 gaps, harden existing false-positive hotspots, embed new checks into existing pipeline phases without breaking anything.

---

## 1. Background

OneInfinity currently covers 50+ vulnerability types across injection, authentication, authorization, logic, crypto, API, mobile, and AI domains. A systematic comparison against OWASP WSTG v4.2 (~100 test cases across 12 categories) identified 23 missing checks and 3 existing false-positive hotspots that undermine result quality.

---

## 2. Goals

1. Implement all 23 missing OWASP WSTG v4.2 checks with both passive detection and active confirmation.
2. Fix false-positive hotspots in `zero_day_engine.py`, time-blind SQLi threshold, and SSRF OOB confirmation.
3. Every finding includes a `check_id` mapped to its WSTG section (e.g., `WSTG-SESS-05`).
4. No regressions — existing findings on a known target (Juice Shop) must remain unchanged.
5. Zero false positives on a clean target (httpbin.org / plain nginx).

---

## 3. Architecture

```
modules/owasp_gap_checks.py          ← NEW: all 23 gap check implementations
        ├── passive_check_*()        ← observe headers/config, return finding
        └── active_check_*()         ← send probe, confirm exploitability

finding_validation_engine.py         ← EXTEND: validate_* methods for each gap check
pipeline/executor.py                 ← EXTEND: dispatch gap checks into existing phases
modules/capability_map.py            ← EXTEND: register 23 new vuln types

zero_day_engine.py                   ← FP FIX: tighten anomaly confidence thresholds
pipeline/executor.py (SQLi)          ← FP FIX: raise time-blind threshold + baseline subtraction
tool_wrappers.py (SSRF)              ← FP FIX: require OOB callback confirmation
```

**Principle:** All changes are additive except the three targeted FP fixes. No existing file is deleted. No existing check logic is removed.

---

## 4. New File: `modules/owasp_gap_checks.py`

### Data Contract

Every gap check returns a `GapCheckResult`:

```python
@dataclass
class GapCheckResult:
    check_id: str          # WSTG ID e.g. "WSTG-SESS-05"
    passive_finding: bool  # observed via passive analysis
    active_confirmed: bool # confirmed via active probe
    confidence: float      # 0.0–1.0
    evidence: str          # exact request/response snippet
    needs_validation: bool # True if active_confirmed=False
```

**Emission rules:**
- `HIGH/CRITICAL` only if `active_confirmed=True` AND `confidence >= 0.7`
- Passive-only findings emit as `INFO` or `LOW` with `needs_manual_verification=True`
- Findings with `confidence < 0.4` are suppressed entirely

---

## 5. Gap Check Inventory & Phase Mapping

### `deep_recon` phase

| WSTG ID | Check | Passive | Active Confirmation |
|---|---|---|---|
| WSTG-CONF-07 | Weak TLS/cipher suite | Check TLS version + cipher via `ssl` module | Force TLS 1.0/RC4 handshake — confirm server accepts |
| WSTG-CONF-07 | Expired/self-signed cert | Parse cert validity + issuer | N/A — cert facts are facts |
| WSTG-CONF-04 | Backup/archive file discovery | — | ffuf with `.bak .old .zip ~ .tar.gz .sql` wordlist; confirm 200 + non-empty body |
| WSTG-CONF-07 | SSL cert SAN enumeration | Extract SANs from cert | — |

### `auth_session` phase

| WSTG ID | Check | Passive | Active Confirmation |
|---|---|---|---|
| WSTG-SESS-02 | Cookie attribute audit | Parse `Set-Cookie` for missing `HttpOnly`, `Secure`, `SameSite` | Send request over HTTP — confirm `Secure`-less cookie transmitted |
| WSTG-SESS-05 | CSRF token validation | Detect forms/state-change endpoints without CSRF token | Replay POST without token — confirm 200/302 vs 403 |
| WSTG-SESS-03 | Session fixation | Detect if session ID changes after login | Login twice, compare pre/post-login session IDs |
| WSTG-SESS-07 | Session timeout | — | Re-use session after idle — confirm still valid or expired |
| WSTG-IDNT-04 | Account enumeration (timing) | — | Valid vs invalid username to login/reset; flag if time delta >100ms |
| WSTG-ATHN-07 | Password policy testing | — | Attempt registration with `a`, `aa`, `password`, `12345` — observe acceptance |
| WSTG-ATHN-10 | SAML assertion validation | Check for unsigned assertions in SAML responses | Modify assertion, replay — confirm accepted or rejected |

### `active_testing` phase

| WSTG ID | Check | Passive | Active Confirmation |
|---|---|---|---|
| WSTG-INPV-06 | LDAP injection | Detect LDAP-backed login indicators | Inject `*)(uid=*))(|(uid=*` — compare response vs baseline |
| WSTG-INPV-10 | Mail header injection | Detect mail-sending forms | Inject `\r\nBcc: canary@test.com` — flag if no rejection |
| WSTG-INPV-11 | Code injection (PHP/Node eval) | Detect `eval`-pattern error responses | Inject `system('id')`, `exec('id')` — confirm output |
| — | CSV injection | Detect CSV export endpoints | Inject `=HYPERLINK("http://oob","x")` — confirm OOB callback or formula in export |
| WSTG-CLNT-11 | postMessage hijacking | Detect `postMessage` usage in JS | Craft cross-origin message to known listeners — observe DOM change |
| WSTG-CLNT-12 | Web Storage security | Scan JS for `localStorage.setItem` with sensitive key names | — |
| — | Insecure RNG | Scan tokens for low-entropy patterns (sequential IDs, timestamp-based) | Chi-squared entropy test on 10 sampled tokens |

### `vuln_scan` phase

| WSTG ID | Check | Passive | Active Confirmation |
|---|---|---|---|
| WSTG-CRYP-04 | Weak encryption detection | Scan JS/responses for `MD5(`, `DES(`, `ECB`, `base64` as crypto | — (static analysis) |
| WSTG-CRYP-04 | Hardcoded crypto keys | Extend trufflehog/gitleaks patterns for AES keys, IV constants | — |
| WSTG-CRYP-02 | Padding oracle | Detect CBC mode cookies/tokens | Send modified ciphertext with bit-flip — measure error response difference |
| — | Service worker abuse | Detect SW registration in JS | Check SW scope covers sensitive paths |
| — | WebRTC IP leakage | Detect WebRTC usage in JS | — (passive only — requires browser context) |
| — | gRPC/SOAP endpoint detection | Detect `Content-Type: application/grpc`, WSDL links | Fetch WSDL, enumerate operations |

---

## 6. False-Positive Hotspot Fixes

### `zero_day_engine.py`

| Anomaly Type | Current Behavior | Fixed Behavior |
|---|---|---|
| Status code | Any change flagged | Only `200→403/401/500`; ignore `301/302` |
| Response size | >10% deviation | >25% deviation AND consistent across 3 repeats |
| Timing | Any delta >threshold | >2s delta AND p95 consistent across 3 samples |
| Reflection | Any echoed input | Only meaningful payloads (not arbitrary strings) |
| Confidence floor | 0.0 allowed | Suppress anything below 0.4 |

### `pipeline/executor.py` — Time-Blind SQLi

| Current | Fixed |
|---|---|
| Threshold: 4s | Threshold: 6s |
| No baseline | Measure baseline first; flag only if `injected > baseline + 5s` |
| Single attempt | Must reproduce on 2 of 3 attempts |

### `tool_wrappers.py` — SSRF OOB

| Current | Fixed |
|---|---|
| Fires when request is sent | Fires only when OOB callback received (`oob_callback_received: true`) |
| No OOB server = confirmed finding | No OOB server = `confidence: low` + `needs_manual_verification: true` |
| No validation step | `validate_ssrf_oob()` added to `finding_validation_engine.py` |

---

## 7. `finding_validation_engine.py` Extensions

New `validate_*` methods to add:

```
validate_csrf()            — replay POST without token, check response code
validate_cookie_attrs()    — confirm cookie transmitted over HTTP
validate_session_fixation()— compare session IDs pre/post login
validate_ldap_injection()  — compare injected vs baseline response
validate_weak_tls()        — attempt forced downgrade handshake
validate_ssrf_oob()        — poll OOB server for callback
validate_padding_oracle()  — measure response delta on bit-flipped ciphertext
validate_account_enum()    — statistical timing comparison (valid vs invalid)
validate_csv_injection()   — confirm OOB or formula in export
```

---

## 8. `modules/capability_map.py` Extensions

Register 23 new vuln type entries, each with:
- `check_id` (WSTG reference)
- `phase` (which pipeline phase runs it)
- `confidence_profile` (passive vs active)
- `tools` (inline Python or external binary)
- `false_positive_risk` (low/medium/high)

---

## 9. QA Plan

### Test Target
OWASP Juice Shop: `docker run -p 3000:3000 bkimminich/juice-shop`

### Phase 1 — Regression
- Baseline scan of Juice Shop before changes
- Post-change scan must produce same or higher confidence on all existing findings
- Zero new FPs on clean endpoints

### Phase 2 — Gap Coverage Verification

| Check | Expected on Juice Shop |
|---|---|
| CSRF | Flag `/api/Users` POST |
| Cookie attrs | Flag missing `HttpOnly` on session cookie |
| Session fixation | Flag if session ID unchanged post-login |
| Account enumeration | Flag timing delta on `/rest/user/login` |
| LDAP injection | Flag LDAP login endpoint |
| Backup files | Flag `main.js.map` source map exposure |
| CSV injection | Flag `/api/Complaints` export |
| postMessage | Flag Juice Shop postMessage usage |
| Web Storage | Flag `localStorage` token storage |

### Phase 3 — FP Hotspot Verification
- zero_day_engine on clean target: expect zero findings
- Time-blind SQLi: `SLEEP(1)` must not fire; `SLEEP(7)` must fire
- SSRF: only fires `confirmed` when OOB callback received

### Phase 4 — End-to-End
- God mode on Juice Shop: gap findings appear in attack graph
- No duplicate findings (SHA-256 dedup covers new check_ids)
- All findings include WSTG reference ID

### Definition of Done
- All 23 gap checks fire on Juice Shop where applicable
- Zero findings on clean httpbin.org target
- Existing finding count on Juice Shop unchanged
- All findings include `check_id` mapped to WSTG section

---

## 10. Files Changed

| File | Change Type |
|---|---|
| `modules/owasp_gap_checks.py` | NEW |
| `finding_validation_engine.py` | EXTEND (add 9 validate_* methods) |
| `pipeline/executor.py` | EXTEND (phase dispatch) + FP FIX (SQLi threshold) |
| `modules/capability_map.py` | EXTEND (23 new vuln types) |
| `zero_day_engine.py` | FP FIX (tighten thresholds) |
| `tool_wrappers.py` | FP FIX (SSRF OOB confirmation) |

**Total: 1 new file, 5 targeted edits.**

---

## 11. Out of Scope

- Mobile app gap checks (separate effort)
- AI/LLM security gap checks (separate effort)
- gRPC deep fuzzing (detection only — full fuzzing is a separate phase)
- WebRTC active exploitation (passive detection only due to browser context requirement)
