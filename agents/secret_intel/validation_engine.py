"""
ValidationEngine — live-validates discovered secrets against their respective APIs.

Design principles
-----------------
  SAFE     All checks are read-only. No account modifications, no charges,
           no writes of any kind.
  TIMEOUT  Hard 3-second wall-clock limit enforced via a ThreadPoolExecutor future.
  ASYNC    Non-blocking from the pipeline's perspective; each call runs in a
           dedicated thread pool and returns within _TIMEOUT_S seconds.
  OPTIONAL Disabled cleanly when ValidationEngine(enabled=False) is used.
  GRACEFUL Any exception marks validation_error=True and continues the pipeline.

Secret access
-------------
Findings carry a `_raw_value` field set by SecretDetector (when
include_raw_value=True). This field MUST be stripped before findings are
persisted — this is done in agent.py immediately after _score_all() returns.

Output fields added to each finding
------------------------------------
  live_verified          bool  — True only if the credential was confirmed active
  validation_type        str   — service name, "skipped_*", "no_validator", etc.
  validation_latency_ms  int   — wall-clock ms for the validation attempt
  validation_error       str   — present only when an unexpected exception occurred
"""

import base64
import json
import logging
import socket
import time
import urllib.error
import urllib.request
from concurrent.futures import ThreadPoolExecutor, TimeoutError as FuturesTimeout
from typing import Any, Dict, Optional, Tuple

logger = logging.getLogger(__name__)

_TIMEOUT_S = 3.0
_POOL      = ThreadPoolExecutor(max_workers=4, thread_name_prefix="live-validate")


# ── Timeout helper ─────────────────────────────────────────────────────────────

def _timed(fn, *args) -> Tuple[bool, int]:
    """
    Run *fn(*args)* in the shared thread pool with a hard _TIMEOUT_S wall limit.
    Returns (result, latency_ms).  Raises TimeoutError on breach.
    """
    t0  = time.monotonic()
    fut = _POOL.submit(fn, *args)
    try:
        result     = fut.result(timeout=_TIMEOUT_S)
        latency_ms = int((time.monotonic() - t0) * 1000)
        return bool(result), latency_ms
    except FuturesTimeout:
        fut.cancel()
        raise TimeoutError(f"timed out after {_TIMEOUT_S}s")


# ── Per-service validators (all read-only) ─────────────────────────────────────

def _check_github(token: str) -> bool:
    """GET /user — confirms the token is valid and unexpired."""
    req = urllib.request.Request(
        "https://api.github.com/user",
        headers={
            "Authorization": f"token {token}",
            "Accept":        "application/vnd.github.v3+json",
            "User-Agent":    "OneInfinity-Validator/1.0",
        },
    )
    try:
        with urllib.request.urlopen(req, timeout=3) as resp:
            return resp.status == 200
    except urllib.error.HTTPError as exc:
        # 401 / 403 = definitively invalid; other HTTP errors = inconclusive → False
        return False
    except Exception:
        return False


def _check_aws(access_key: str, secret_key: str = "") -> bool:
    """
    STS GetCallerIdentity — the only AWS call that always succeeds for valid creds
    regardless of IAM policy. Requires boto3; gracefully skips if absent.
    """
    try:
        import boto3
        session = boto3.Session(
            aws_access_key_id=access_key,
            aws_secret_access_key=secret_key or "placeholder",
            region_name="us-east-1",
        )
        session.client("sts").get_caller_identity()
        return True
    except ImportError:
        logger.debug("boto3 not installed — AWS live check skipped")
        return False
    except Exception:
        return False


def _check_stripe(api_key: str) -> bool:
    """GET /v1/charges?limit=1 — read-only; confirms key is active."""
    creds = base64.b64encode(f"{api_key}:".encode()).decode()
    req   = urllib.request.Request(
        "https://api.stripe.com/v1/charges?limit=1",
        headers={
            "Authorization": f"Basic {creds}",
            "User-Agent":    "OneInfinity-Validator/1.0",
        },
    )
    try:
        with urllib.request.urlopen(req, timeout=3) as resp:
            return resp.status == 200
    except urllib.error.HTTPError as exc:
        return exc.code not in (401, 403)
    except Exception:
        return False


def _check_openai(api_key: str) -> bool:
    """GET /v1/models — read-only list; confirms key is active."""
    req = urllib.request.Request(
        "https://api.openai.com/v1/models",
        headers={
            "Authorization": f"Bearer {api_key}",
            "User-Agent":    "OneInfinity-Validator/1.0",
        },
    )
    try:
        with urllib.request.urlopen(req, timeout=3) as resp:
            return resp.status == 200
    except urllib.error.HTTPError as exc:
        return exc.code not in (401, 403)
    except Exception:
        return False


def _check_sendgrid(api_key: str) -> bool:
    """GET /v3/scopes — read-only; confirms key is active."""
    req = urllib.request.Request(
        "https://api.sendgrid.com/v3/scopes",
        headers={
            "Authorization": f"Bearer {api_key}",
            "User-Agent":    "OneInfinity-Validator/1.0",
        },
    )
    try:
        with urllib.request.urlopen(req, timeout=3) as resp:
            return resp.status == 200
    except urllib.error.HTTPError as exc:
        return exc.code not in (401, 403)
    except Exception:
        return False


def _check_slack(token: str) -> bool:
    """auth.test — read-only Slack API call."""
    req = urllib.request.Request(
        "https://slack.com/api/auth.test",
        headers={
            "Authorization": f"Bearer {token}",
            "User-Agent":    "OneInfinity-Validator/1.0",
        },
    )
    try:
        with urllib.request.urlopen(req, timeout=3) as resp:
            data = json.loads(resp.read().decode())
            return bool(data.get("ok"))
    except Exception:
        return False


def _check_redis(uri: str) -> bool:
    """
    Attempt AUTH (if password present) or PING (no-auth) over a raw TCP socket.
    No data is read or written beyond the handshake.
    """
    try:
        clean    = uri.replace("rediss://", "").replace("redis://", "")
        password: Optional[str] = None
        if "@" in clean:
            userinfo, hostpart = clean.rsplit("@", 1)
            password = userinfo.split(":", 1)[-1] if ":" in userinfo else userinfo
        else:
            hostpart = clean
        host_port = hostpart.split("/")[0]
        host      = host_port.split(":")[0] if ":" in host_port else host_port
        port      = int(host_port.split(":")[1]) if ":" in host_port else 6379

        with socket.create_connection((host, port), timeout=3) as sock:
            sock.settimeout(3)
            if password:
                sock.sendall(f"AUTH {password}\r\n".encode())
                resp = sock.recv(128).decode(errors="replace")
                return resp.startswith("+OK")
            else:
                sock.sendall(b"PING\r\n")
                resp = sock.recv(128).decode(errors="replace")
                return "+PONG" in resp
    except Exception:
        return False


def _check_postgres(uri: str) -> bool:
    """
    Attempt a connection (read-only intent).
    Requires psycopg2; gracefully skips if absent.
    """
    try:
        import psycopg2
        conn = psycopg2.connect(uri, connect_timeout=3)
        conn.close()
        return True
    except ImportError:
        logger.debug("psycopg2 not installed — Postgres live check skipped")
        return False
    except Exception:
        return False


# ── Validator dispatch table ───────────────────────────────────────────────────

_DISPATCH: Dict[str, Tuple[str, Any]] = {
    "github_pat":        ("github",   _check_github),
    "github_oauth":      ("github",   _check_github),
    "stripe_standard":   ("stripe",   _check_stripe),
    "stripe_restricted": ("stripe",   _check_stripe),
    "openai_api_key":    ("openai",   _check_openai),
    "sendgrid_api_key":  ("sendgrid", _check_sendgrid),
    "slack_token":       ("slack",    _check_slack),
    "redis_uri":         ("redis",    _check_redis),
    "postgres_uri":      ("postgres", _check_postgres),
    # AWS handled specially — needs both key + secret from context
    "aws_access_key_id": ("aws",      None),
}


# ── Public engine ──────────────────────────────────────────────────────────────

class ValidationEngine:
    """
    Stateless live-validation engine.

    Usage
    -----
        engine  = ValidationEngine(enabled=True)
        finding = engine.validate(finding)
        # finding now carries: live_verified, validation_type, validation_latency_ms
        # _raw_value is NOT removed here — caller must strip it after this call.
    """

    def __init__(self, enabled: bool = True):
        self.enabled = enabled

    def validate(self, finding: Dict[str, Any]) -> Dict[str, Any]:
        """
        Attempt live validation of *finding*.

        Reads `_raw_value` (the full plaintext secret, pipeline-internal only).
        If absent, marks the finding as skipped rather than failing.
        """
        if not self.enabled:
            return self._stamp(finding, False, "disabled", 0)

        secret_type = finding.get("type", "")
        raw_value   = finding.get("_raw_value")

        if not raw_value:
            return self._stamp(finding, False, "skipped_no_raw_value", 0)

        entry = _DISPATCH.get(secret_type)
        if entry is None:
            return self._stamp(finding, False, "no_validator", 0)

        vtype, vfn = entry

        # AWS special case: single access key cannot be validated without its secret
        if secret_type == "aws_access_key_id":
            return self._stamp(finding, False, "aws_requires_key_pair", 0)

        try:
            verified, latency_ms = _timed(vfn, raw_value)
            logger.info(
                "LiveValidation: type=%s result=%s latency=%dms",
                secret_type, "LIVE" if verified else "invalid", latency_ms,
            )
            return self._stamp(finding, verified, vtype, latency_ms)

        except TimeoutError:
            logger.warning(
                "LiveValidation: %s timed out (>%.1fs)", secret_type, _TIMEOUT_S
            )
            return self._stamp(finding, False, f"{vtype}_timeout",
                               int(_TIMEOUT_S * 1000))

        except Exception as exc:
            logger.warning("LiveValidation: %s error: %s", secret_type, exc)
            finding["validation_error"] = str(exc)
            return self._stamp(finding, False, f"{vtype}_error", 0)

    # ── Internal helpers ───────────────────────────────────────────────────────

    @staticmethod
    def _stamp(
        finding: Dict[str, Any],
        verified: bool,
        vtype: str,
        latency_ms: int,
    ) -> Dict[str, Any]:
        finding["live_verified"]         = verified
        finding["validation_type"]       = vtype
        finding["validation_latency_ms"] = latency_ms
        return finding
