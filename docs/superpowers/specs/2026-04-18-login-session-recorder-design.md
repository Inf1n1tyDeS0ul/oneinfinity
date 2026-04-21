# Login Session Recorder — Design Spec
**Date:** 2026-04-18  
**Status:** Approved  
**Scope:** Authenticated scanning via recorded login sessions (Acunetix-style)

---

## 1. Problem Statement

The existing OneInfinity scanner operates unauthenticated. Authenticated surfaces — IDOR, broken access control, JWT vulnerabilities, post-login business logic, MFA bypass, OAuth flaws — are invisible without a valid session. This feature adds session recording, injection, and an authenticated test suite that runs alongside the existing swarm.

---

## 2. Architecture

New package: `src/oneinfinity/auth/` (7 files, self-contained).  
Existing code changes: surgical additions to `god_mode_engine.py`, `swarm_intelligence_engine.py`, `pipeline/executor.py`, `web/backend/main.py`, and the scan launch UI component. No existing behaviour is removed or broken.

```
LoginFormDetector
      │ LoginFormResult
      ▼
LoginSessionRecorder ──── mitmproxy (optional secondary layer)
      │ LoginSession (JSON + HAR)
      ▼
SessionManager (~/.oneinfinity/sessions/)
      │ LoginSession
      ▼
AuthSessionContext
      ├── inject_requests()
      ├── inject_httpx()
      ├── inject_playwright()
      ├── inject_subprocess_env()
      ├── is_session_expired()
      └── refresh() ── SessionReplay
            │
      ┌─────┴──────┐
      ▼            ▼
 Swarm agents  AuthTestMission (16 categories)
 (auth inject)
```

---

## 3. Components

### 3.1 `login_form_detector.py`
Wraps `ApplicationCrawler`. Fetches target URL, detects `<form>` with password field.

**Output:** `LoginFormResult`
```python
@dataclass
class LoginFormResult:
    has_login_form: bool
    login_url: str
    username_field: str   # name attr of username input
    password_field: str   # name attr of password input
    form_action: str
    form_method: str      # GET | POST
```

### 3.2 `login_session_recorder.py`
Three modes, selected automatically:

| Mode | Trigger | Behaviour |
|------|---------|-----------|
| `record_auto` | credentials provided | Auto-fill form, submit, capture session |
| `record_interactive` | no credentials, DISPLAY available | Open headed Playwright, wait for user "Done" signal |
| Skip | no credentials, no DISPLAY | Log warning, return None — scan continues unauthenticated |

**Playwright HAR recording:** `browser.new_context(record_har_path=..., record_har_mode="full")` captures all requests/responses during the login flow.

**Captured data per session:**
- Cookies (all domains)
- `localStorage` + `sessionStorage` (via `page.evaluate`)
- `IndexedDB` snapshot (via `page.evaluate`)
- Full HAR file (request/response bodies, headers, timings)
- Auth headers detected in captured requests (Authorization, X-Auth-Token, X-API-Key)

**mitmproxy secondary layer:** If `mitmproxy` is importable, spin up `DumpMaster` on a free local port, route Playwright through it, merge captured flows into the session. Activated automatically — user needs only to `pip install mitmproxy`. Adds WebSocket frames and extension traffic that Playwright HAR may miss.

### 3.3 `session_manager.py`
Storage: `~/.oneinfinity/sessions/`

| Save path | When |
|-----------|------|
| `auto-<sha256(target)[:8]>.json` | Auto-save per target |
| `<name>.json` | Named save (user-specified) |

Both paths can coexist for the same target. Auto-path is loaded automatically on next scan of same target. Named sessions are selected explicitly via `--auth-session <name>` (CLI) or dropdown (UI).

Methods: `save(session, name=None)`, `load(target=None, name=None)`, `list_all()`, `delete(session_id)`, `exists(target)`.

### 3.4 `auth_session_context.py`
Central injector. Loaded from a `LoginSession`.

```python
class AuthSessionContext:
    def inject_requests(self, s: requests.Session) -> None
    def inject_httpx(self, c: httpx.Client) -> None
    def inject_playwright(self, ctx: BrowserContext) -> None
    def inject_subprocess_env(self, env: dict) -> dict
    def is_session_expired(self, response) -> bool
    def refresh(self, recorder: LoginSessionRecorder) -> bool
```

**Expiry detection:** 401/403 status, or redirect URL contains login keywords (`/login`, `/signin`, `/auth`).

**Refresh flow:**
1. `session_replay.replay(har_login_sequence)` → try to re-authenticate
2. Success → update cookies/tokens in context, continue scan
3. Failure (MFA changed, site down) → emit event:
   - CLI: print `[!] Session expired — manual re-auth required. Scan paused.`
   - UI: WebSocket push `{ type: "auth_expired", scan_id }` → UI overlay prompts re-record

### 3.5 `session_replay.py`
Replays HAR login sequence using `httpx` with cookie jar. Handles redirects. Extracts fresh cookies/tokens from final response. Updates parent `AuthSessionContext`.

### 3.6 `authenticated_test_suite.py`
16 test categories. Each returns `list[Finding]`. Accepts `(target, endpoints, auth_context)`. Findings written to `auth_test_findings.json` in the scan output directory.

| # | Category | Key Checks |
|---|----------|-----------|
| 1 | Session Management | Fixation, timeout, concurrent sessions, logout invalidation |
| 2 | Cookie Security | Missing HttpOnly / Secure / SameSite flags |
| 3 | Access Control | Forced browsing, unauthenticated access to auth-only endpoints |
| 4 | IDOR | Enumerate IDs ±1/±10/random in all authenticated endpoints |
| 5 | CSRF | State-changing requests without CSRF token validation |
| 6 | JWT | `alg:none`, weak secret brute-force, expired token reuse, scope bypass |
| 7 | GraphQL Auth | Introspection behind login, field-level auth, batching abuse |
| 8 | API Discovery | JS parsing + link crawl of authenticated pages only |
| 9 | Sensitive Data | PII / secrets / internal keys in authenticated API responses |
| 10 | Rate Limiting | Login, password reset, OTP endpoints |
| 11 | Business Logic | Price manipulation, workflow skip, negative quantities |
| 12 | OAuth / SSO | Token revocation, scope enforcement, redirect_uri manipulation |
| 13 | MFA Bypass | Code reuse, brute-force, response manipulation |
| 14 | Password Operations | Change without old password, no re-auth for sensitive actions |
| 15 | Account Takeover | Chained IDOR + session manipulation flows |
| 16 | Injection (Auth) | SQLi / XSS / SSTI on fields visible only after login |

### 3.7 `__init__.py`
Exports: `LoginFormDetector`, `LoginSessionRecorder`, `SessionManager`, `AuthSessionContext`.

---

## 4. LoginSession JSON Schema

```json
{
  "session_id": "abc12345",
  "name": "myapp-admin",
  "target": "https://app.example.com",
  "target_hash": "a3f9b2c1",
  "recorded_at": "2026-04-18T09:00:00Z",
  "login_url": "https://app.example.com/login",
  "cookies": [{"name": "session", "value": "...", "domain": "..."}],
  "auth_headers": {"Authorization": "Bearer eyJ..."},
  "local_storage": {"token": "eyJ..."},
  "session_storage": {},
  "indexeddb_snapshot": {},
  "har_path": "~/.oneinfinity/sessions/abc12345.har",
  "recorder": "playwright",
  "mitmproxy_flow_path": null,
  "expiry_detected_at": null,
  "replayed_at": null
}
```

---

## 5. Data Flows

### 5.1 CLI Auto-Trigger

```
oneinfinity scan --target <url> --mode god_mode [--auth-session <name>]
    → Recon phase completes
    → LoginFormDetector.detect(target)
        → has_login_form?
            yes → SessionManager.load(target) OR load by name
                → session exists? → AuthSessionContext(session)
                → no session?
                    → credentials in env/config? → record_auto()
                    → no credentials + DISPLAY? → record_interactive()
                    → no credentials + no DISPLAY? → skip, warn
            no → continue unauthenticated
    → ctx["auth_context"] set if session obtained
    → SwarmMission runs with auth injected
    → AuthTestMission runs with auth injected (skipped silently if no auth_context)
```

### 5.2 UI Scan Launch

```
Scan config panel
    → "Detect Login Form" (auto on target URL entry)
    → If form detected: show "Record Login Session" button
    → Click → POST /api/auth/record → headed browser opens
    → User logs in → clicks "Done"
    → POST /api/auth/record/{session_id}/done → session saved
    → Dropdown: "Use session: <name>" populated
    → POST /api/scans { ..., auth_session_id: "abc12345" }
    → Scan runs with AuthSessionContext
```

### 5.3 Session Expiry + Re-auth

```
Scan module gets 401/403 or login redirect
    → auth_context.is_session_expired() → True
    → session_replay.replay(har) → success?
        yes → update cookies/tokens → continue scan
        no  → CLI: pause + print warning
              UI: WebSocket push "auth_expired"
              User re-records → scan resumes
```

---

## 6. Existing Code Changes (Surgical)

| File | Change | Lines added |
|------|--------|-------------|
| `god_mode_engine.py` | Auth detection + `ctx["auth_context"]` injection after recon; add `AuthTestMission` class | ~60 |
| `swarm_intelligence_engine.py` | `inject_requests()` + `inject_playwright()` on agent http_session before dispatch | ~15 |
| `pipeline/executor.py` | Accept `auth_context` param; call `phase_runner.set_auth()` if available | ~20 |
| `web/backend/main.py` | 6 new `/api/auth/*` endpoints; `auth_session_id` in scan request body | ~120 |
| Frontend scan launch component | "Record" button + overlay + session picker dropdown | ~80 lines JSX |

**Nothing removed. No existing endpoint modified. No existing scan flow broken.**

---

## 7. New API Endpoints

| Method | Path | Description |
|--------|------|-------------|
| `POST` | `/api/auth/detect` | Detect login form on target URL |
| `POST` | `/api/auth/record` | Start headed browser recording; returns `session_id` |
| `POST` | `/api/auth/record/{session_id}/done` | Finalize recording, save session |
| `GET` | `/api/auth/sessions` | List all saved sessions |
| `GET` | `/api/auth/sessions/{id}` | Get session details (cookies redacted) |
| `DELETE` | `/api/auth/sessions/{id}` | Delete session file |

---

## 8. Environment Variables / CLI Flags

| Var / Flag | Purpose |
|------------|---------|
| `ONEINFINITY_USERNAME` | Auto-fill username in `record_auto` mode |
| `ONEINFINITY_PASSWORD` | Auto-fill password in `record_auto` mode |
| `--auth-session <name>` | Load named session for this scan |
| `--no-auth` | Skip auth detection entirely |
| `ONEINFINITY_MITMPROXY=1` | Force-enable mitmproxy secondary layer even if auto-detect fails |

---

## 9. Error Handling

| Scenario | Behaviour |
|----------|-----------|
| Playwright not installed | `record_interactive` logs error, returns None, scan continues unauthenticated |
| No DISPLAY in CLI | `record_interactive` skipped, warning logged, scan continues unauthenticated |
| Auto-fill fails (wrong field names) | Falls back to `record_interactive` if DISPLAY available |
| Session file corrupted | `SessionManager.load()` returns None, scan continues unauthenticated |
| mitmproxy not installed | Secondary layer silently skipped |
| Re-auth replay fails | CLI pauses with message; UI sends WebSocket notification |
| AuthTestMission — no auth_context | Silent skip, no error, no findings written |

---

## 10. Testing Strategy

- Unit tests for `LoginFormDetector` against known HTML fixtures
- Unit tests for `deduplicate_findings` in auth test suite output
- Unit tests for `SessionManager` save/load/list/delete with temp dirs
- Integration test: `record_auto` against a local Flask login form
- Integration test: `AuthSessionContext.inject_requests` — verify cookies present in outgoing request
- Integration test: `is_session_expired` — mock 401 response
- No changes to existing test suite
