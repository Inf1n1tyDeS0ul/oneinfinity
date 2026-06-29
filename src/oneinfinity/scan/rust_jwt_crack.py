"""
rust_jwt_crack.py — Python wrapper for the oi-jwt-crack Rust binary.

Architecture
────────────
oi-jwt-crack is a Rayon-parallel JWT HS256/384/512 secret brute-forcer built
in Rust.  It vastly outperforms the Python top-20 secret list in
jwt_vulnerability_scanner.py — capable of >2M candidates/sec on modern
hardware.

The binary:
  - Accepts --token <jwt> and --wordlist <path> (or piped stdin)
  - Emits NDJSON to stdout: type=result|progress|summary|error
  - Exits 0 regardless of whether the secret was found

This wrapper:
  1. Locates the compiled binary (src/rust/oi-jwt-crack/target/release/oi-jwt-crack)
  2. Runs it as a subprocess with a wordlist path or in-memory wordlist (via temp file)
  3. Parses NDJSON output into JWTCrackResult objects
  4. Returns a JWTFinding compatible dict on success

Integration with jwt_vulnerability_scanner.py
──────────────────────────────────────────────
JWTVulnerabilityScanner.test_weak_secret() uses a Python top-20 list.
Call rust_jwt_crack.crack_token(token, url, wordlist_path=...) for a full
rockyou-scale attack.  On a found secret, the result is a JWTFinding-compatible
dict that can be appended directly to JWTVulnerabilityScanner findings.

Usage
─────
    from oneinfinity.scan.rust_jwt_crack import RustJwtCrack

    cracker = RustJwtCrack()
    finding = await cracker.crack_token(
        token="eyJ...",
        url="https://example.com/api/users/me",
        wordlist_path="/usr/share/wordlists/rockyou.txt",
    )
    if finding:
        print(finding.to_dict())
"""
from __future__ import annotations

import asyncio
import hashlib
import json
import logging
import os
import subprocess
import tempfile
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional

log = logging.getLogger("oneinfinity.rust_jwt_crack")

_TOOL_NAME = "rust_jwt_crack"

# Binary: built from src/rust/oi-jwt-crack/ via `cargo build --release`
_REPO_ROOT = Path(__file__).resolve().parents[4]
_BINARY = _REPO_ROOT / "src" / "rust" / "oi-jwt-crack" / "target" / "release" / "oi-jwt-crack"

# Default wordlist bundled with the repo (common JWT weak secrets, ~10k entries)
_DEFAULT_WORDLIST = _REPO_ROOT / "src" / "rust" / "oi-jwt-crack" / "wordlists" / "jwt_secrets.txt"

# Fallback in-memory wordlist (mirrors jwt_vulnerability_scanner._WEAK_SECRETS + extras)
_BUILTIN_SECRETS: List[str] = [
    "secret", "password", "123456", "your-256-bit-secret", "your-secret-key",
    "mysecretkey", "jwt-secret", "secretkey", "changeme", "change-me",
    "default", "test", "admin", "qwerty", "letmein", "welcome", "monkey",
    "dragon", "master", "abc123", "password123", "admin123", "root",
    "secret123", "jwt", "token", "key", "private", "public_key",
    "-----BEGIN PUBLIC KEY-----", "-----BEGIN CERTIFICATE-----",
    "supersecret", "verysecret", "topsecret", "mypassword", "pass",
    "1234567890", "0987654321", "abcdefgh", "asdfghjkl", "qwertyuiop",
    "hunter2", "trustno1", "iloveyou", "sunshine", "princess",
    "access_secret", "access_token_secret", "refresh_secret",
    "api_secret", "api_key", "app_secret", "auth_secret",
    "RANDOM_SECRET_KEY", "SECRET_KEY", "APP_SECRET", "SESSION_SECRET",
    "supersecretkey", "ultrasecret", "megasecret",
]


# ─── Result dataclass ─────────────────────────────────────────────────────────

@dataclass
class JWTCrackResult:
    """Result of a successful JWT secret crack."""
    token: str
    secret: str
    alg: str
    cracked_payload: Dict[str, Any]
    attempts: int
    elapsed_ms: int
    # JWTFinding-compatible fields
    finding_id: str = ""
    vuln_type: str = "jwt_weak_secret"
    title: str = ""
    severity: str = "critical"
    url: str = ""
    original_token: str = ""
    forged_token: str = ""
    attack_vector: str = "weak_secret_brute_rust"
    evidence: str = ""
    confidence: float = 0.99
    exploitation_steps: List[str] = field(default_factory=list)
    tool: str = _TOOL_NAME
    source_type: str = "active"

    def to_dict(self) -> Dict[str, Any]:
        return {
            "finding_id": self.finding_id,
            "vuln_type": self.vuln_type,
            "title": self.title,
            "severity": self.severity,
            "url": self.url,
            "original_token": self.original_token,
            "forged_token": self.forged_token,
            "attack_vector": self.attack_vector,
            "evidence": self.evidence,
            "confidence": self.confidence,
            "exploitation_steps": self.exploitation_steps,
            "tool": self.tool,
            "source_type": self.source_type,
            # Extra Rust-specific fields
            "secret": self.secret,
            "alg": self.alg,
            "cracked_payload": self.cracked_payload,
            "attempts": self.attempts,
            "elapsed_ms": self.elapsed_ms,
        }


# ─── Main wrapper class ────────────────────────────────────────────────────────

class RustJwtCrack:
    """
    Python facade over the oi-jwt-crack Rust binary.

    Provides async and sync interfaces.  Falls back gracefully when the binary
    is not yet compiled.  Accepts either a wordlist file path or an in-memory
    list of candidates (written to a temp file for the subprocess).

    Performance notes
    ─────────────────
    - ~2M candidates/sec on Apple M4 Pro (all-core Rayon)
    - rockyou.txt (14M lines) cracks in ~7 seconds
    - Built-in fallback list (~50 entries) runs in <1ms
    """

    def __init__(self, timeout: int = 120, threads: int = 0, progress_every: int = 500_000):
        self._timeout = timeout
        self._threads = threads          # 0 = all logical CPUs
        self._progress_every = progress_every

    # ── Public API ─────────────────────────────────────────────────────────

    async def crack_token(
        self,
        token: str,
        url: str,
        wordlist_path: Optional[str] = None,
        extra_candidates: Optional[List[str]] = None,
    ) -> Optional[JWTCrackResult]:
        """
        Attempt to crack the HMAC secret of a JWT token.

        Parameters
        ──────────
        token:            Full JWT string (header.payload.signature).
        url:              The URL this token was captured from (for finding.url).
        wordlist_path:    Path to a newline-delimited wordlist file.
                          Falls back to _DEFAULT_WORDLIST, then built-in list.
        extra_candidates: Additional secrets to prepend to the wordlist.

        Returns
        ───────
        JWTCrackResult if the secret is found, None otherwise.
        Gracefully returns None if the binary is absent (not yet built).
        """
        loop = asyncio.get_event_loop()
        return await loop.run_in_executor(
            None,
            self._crack_sync,
            token,
            url,
            wordlist_path,
            extra_candidates or [],
        )

    def crack_token_sync(
        self,
        token: str,
        url: str,
        wordlist_path: Optional[str] = None,
        extra_candidates: Optional[List[str]] = None,
    ) -> Optional[JWTCrackResult]:
        """Synchronous variant of crack_token()."""
        return self._crack_sync(token, url, wordlist_path, extra_candidates or [])

    # ── Internal helpers ───────────────────────────────────────────────────

    def _resolve_wordlist(
        self,
        wordlist_path: Optional[str],
        extra_candidates: List[str],
    ) -> Optional[str]:
        """
        Resolve the wordlist to use.  Priority:
        1. Caller-supplied wordlist_path (if file exists)
        2. Repo default wordlist (src/rust/oi-jwt-crack/wordlists/jwt_secrets.txt)
        3. Built-in Python list written to a temp file

        Returns the resolved file path string.
        """
        if wordlist_path and Path(wordlist_path).is_file():
            if extra_candidates:
                return self._prepend_candidates(wordlist_path, extra_candidates)
            return wordlist_path

        if _DEFAULT_WORDLIST.is_file():
            if extra_candidates:
                return self._prepend_candidates(str(_DEFAULT_WORDLIST), extra_candidates)
            return str(_DEFAULT_WORDLIST)

        # Fall back to built-in list + extras
        all_candidates = extra_candidates + _BUILTIN_SECRETS
        return self._write_temp_wordlist(all_candidates)

    @staticmethod
    def _prepend_candidates(base_path: str, extras: List[str]) -> str:
        """Write extras + base_path contents to a temp file; return temp path."""
        with open(base_path) as fh:
            base_lines = fh.read()
        combined = "\n".join(extras) + "\n" + base_lines
        tmp = tempfile.NamedTemporaryFile(
            mode="w", suffix=".txt", prefix="oi-jwt-", delete=False
        )
        tmp.write(combined)
        tmp.flush()
        tmp.close()
        return tmp.name

    @staticmethod
    def _write_temp_wordlist(candidates: List[str]) -> str:
        """Write a candidate list to a temp file; return path."""
        tmp = tempfile.NamedTemporaryFile(
            mode="w", suffix=".txt", prefix="oi-jwt-", delete=False
        )
        tmp.write("\n".join(candidates) + "\n")
        tmp.flush()
        tmp.close()
        return tmp.name

    def _crack_sync(
        self,
        token: str,
        url: str,
        wordlist_path: Optional[str],
        extra_candidates: List[str],
    ) -> Optional[JWTCrackResult]:
        """Run the Rust binary synchronously; parse output."""
        if not _BINARY.is_file():
            log.warning(
                "rust_jwt_crack: binary not found at %s. "
                "Build with: cd src/rust && cargo build --release -p oi-jwt-crack",
                _BINARY,
            )
            return None

        wl_path = self._resolve_wordlist(wordlist_path, extra_candidates)
        if not wl_path:
            log.warning("rust_jwt_crack: could not resolve wordlist")
            return None

        cmd = [
            str(_BINARY),
            "--token", token,
            "--wordlist", wl_path,
            "--stop-on-first", "true",
            "--progress-every", str(self._progress_every),
        ]
        if self._threads > 0:
            cmd += ["--threads", str(self._threads)]

        try:
            proc = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=self._timeout,
                env={**os.environ, "RUST_LOG": "error"},
            )
        except subprocess.TimeoutExpired:
            log.error("rust_jwt_crack: binary timed out after %ds", self._timeout)
            return None
        except Exception as exc:
            log.error("rust_jwt_crack: subprocess error: %s", exc)
            return None
        finally:
            # Clean up temp wordlist if we created one
            if wl_path != wordlist_path and wl_path != str(_DEFAULT_WORDLIST):
                try:
                    os.unlink(wl_path)
                except OSError:
                    pass

        if proc.returncode != 0:
            log.error(
                "rust_jwt_crack: binary exited %d: %s",
                proc.returncode, proc.stderr[:400],
            )
            return None

        return self._parse_output(proc.stdout, token, url)

    @staticmethod
    def _parse_output(raw: str, token: str, url: str) -> Optional[JWTCrackResult]:
        """Parse NDJSON from oi-jwt-crack stdout, return first result record."""
        result: Optional[Dict[str, Any]] = None

        for line in raw.splitlines():
            line = line.strip()
            if not line:
                continue
            try:
                obj = json.loads(line)
            except json.JSONDecodeError:
                continue
            if not isinstance(obj, dict):
                continue

            rec_type = obj.get("type", "")
            if rec_type == "progress":
                log.debug(
                    "rust_jwt_crack: progress — %s attempts @ %s k/s",
                    obj.get("attempts"), obj.get("rate_kps"),
                )
            elif rec_type == "error":
                log.error("rust_jwt_crack: binary error — %s", obj.get("message"))
            elif rec_type == "summary":
                log.info(
                    "rust_jwt_crack: %s attempts in %sms (found=%s)",
                    obj.get("attempts"), obj.get("elapsed_ms"), obj.get("found"),
                )
            elif rec_type == "result":
                result = obj

        if not result:
            return None

        secret = result.get("secret", "")
        alg = result.get("alg", "HS256")
        cracked_payload = result.get("cracked_payload") or {}
        attempts = int(result.get("attempts", 0))
        elapsed_ms = int(result.get("elapsed_ms", 0))

        finding_id = hashlib.md5(
            f"jwt_rust_crack_{url}_{secret}".encode()
        ).hexdigest()[:16]

        # Truncate token for display
        token_display = token[:50] + "..." if len(token) > 50 else token

        return JWTCrackResult(
            token=token,
            secret=secret,
            alg=alg,
            cracked_payload=cracked_payload,
            attempts=attempts,
            elapsed_ms=elapsed_ms,
            finding_id=finding_id,
            vuln_type="jwt_weak_secret",
            title=f"JWT Weak Secret Found (Rust brute-force): {secret!r}",
            severity="critical",
            url=url,
            original_token=token_display,
            forged_token="[re-sign with discovered secret]",
            attack_vector="weak_secret_brute_rust",
            evidence=(
                f"JWT secret cracked in {attempts:,} attempts ({elapsed_ms}ms) "
                f"using Rust brute-forcer. Secret: {secret!r}. "
                f"Algorithm: {alg}. "
                f"Cracked claims: {json.dumps(cracked_payload)[:200]}"
            ),
            confidence=0.99,
            exploitation_steps=[
                f"1. Secret cracked: {secret!r} (algorithm: {alg})",
                "2. Re-sign any payload with this secret using PyJWT or python-jose",
                "3. Modify claims (role, sub, exp) to escalate privileges",
                "4. Use forged token in Authorization: Bearer header",
                "5. Rotate secret immediately — treat all issued tokens as compromised",
            ],
            tool=_TOOL_NAME,
        )

    @staticmethod
    def is_available() -> bool:
        """Return True if the Rust binary is compiled and executable."""
        return _BINARY.is_file()


# ─── Convenience function ─────────────────────────────────────────────────────

async def crack_token(
    token: str,
    url: str,
    wordlist_path: Optional[str] = None,
    extra_candidates: Optional[List[str]] = None,
) -> Optional[JWTCrackResult]:
    """Module-level convenience wrapper."""
    cracker = RustJwtCrack()
    return await cracker.crack_token(
        token=token,
        url=url,
        wordlist_path=wordlist_path,
        extra_candidates=extra_candidates,
    )
