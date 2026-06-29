"""Nim binary runner — single subprocess interface for all Phase 3 binaries."""
from __future__ import annotations

import hashlib
import json
import logging
import os
import subprocess
from pathlib import Path
from typing import Any

log = logging.getLogger(__name__)

# Binary allowlist — MUST stay within this directory.
# File is at src/oneinfinity/infra/nim_runner.py
# parents[0]=infra, parents[1]=oneinfinity, parents[2]=src, parents[3]=repo_root
_REPO_ROOT = Path(__file__).resolve().parents[3]
_BIN_DIR = _REPO_ROOT / "src" / "nim" / "bin"
_CHECKSUMS_PATH = _REPO_ROOT / "checksums.json"

# Allowlist of valid binary names — no other names are accepted
_ALLOWED_BINARIES: frozenset[str] = frozenset({
    "oi-shell-gen",
    "oi-bypass-gen",
    "oi-payloads",
    "oi-post-exploit",
    "oi-fuzzer",
    "oi-privesc-gen",
})


class NimIntegrityError(RuntimeError):
    """Binary SHA-256 does not match checksums.json, or policy violation."""


class NimExecutionError(RuntimeError):
    """Binary exited with non-zero status or timed out."""


def _load_checksums() -> dict[str, Any]:
    if not _CHECKSUMS_PATH.exists():
        return {}
    with open(_CHECKSUMS_PATH) as f:
        data = json.load(f)
    # Support both {"binaries": {...}} and flat {"name": {...}} schema
    return data.get("binaries", data)  # type: ignore[return-value]


def _validate_binary_path(binary: str) -> Path:
    """Resolve binary path and ensure it stays within _BIN_DIR (no traversal).

    Raises NimIntegrityError for invalid names or path traversal attempts.
    """
    # Reject path separators and parent-directory references
    if (
        os.sep in binary
        or "/" in binary
        or ".." in binary
        or (os.altsep and os.altsep in binary)
    ):
        raise NimIntegrityError(f"Invalid binary name (path traversal attempt): {binary!r}")

    # Enforce allowlist
    if binary not in _ALLOWED_BINARIES:
        raise NimIntegrityError(f"Binary not in allowlist: {binary!r}")

    bin_dir_resolved = _BIN_DIR.resolve()
    path = (bin_dir_resolved / binary).resolve()

    # Confirm resolved path is still within _BIN_DIR
    try:
        path.relative_to(bin_dir_resolved)
    except ValueError:
        raise NimIntegrityError(f"Binary path escapes bin dir: {path}")

    return path


def _verify_sha256(path: Path, expected: str) -> bool:
    """Compute SHA-256 of file and compare to expected hex digest."""
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(65536), b""):
            h.update(chunk)
    return h.hexdigest() == expected


def run_nim_binary(
    binary: str,
    args: list[str] | None = None,
    timeout: int = 30,
) -> list[dict[str, Any]]:
    """Run a Nim binary with integrity check; return parsed NDJSON results.

    Parameters
    ----------
    binary:
        Bare binary name (no path separators). Must be in _ALLOWED_BINARIES.
    args:
        CLI arguments passed to the binary.
    timeout:
        Seconds to wait before raising NimExecutionError.

    Returns
    -------
    List of result dicts — only lines where ``event == "result"`` are included.

    Raises
    ------
    NimIntegrityError
        SHA-256 mismatch, path traversal, allowlist violation, or
        production blocks ONEINFINITY_SKIP_INTEGRITY.
    NimExecutionError
        Binary exits non-zero or times out.
    FileNotFoundError
        Binary not compiled/present in src/nim/bin/.
    """
    if args is None:
        args = []

    path = _validate_binary_path(binary)

    if not path.exists():
        # PATH fallback: check whether the binary is on the system PATH
        import shutil as _shutil
        path_bin = _shutil.which(binary)
        if path_bin:
            log.debug("nim_runner: %s not in BIN_DIR, using PATH binary: %s", binary, path_bin)
            path = Path(path_bin)
        else:
            raise FileNotFoundError(f"Nim binary not found: {path} (also not on PATH)")

    # Integrity policy
    skip_integrity = os.environ.get("ONEINFINITY_SKIP_INTEGRITY", "0") == "1"
    is_production = os.environ.get("ONEINFINITY_ENV", "") == "production"

    if is_production and skip_integrity:
        raise NimIntegrityError(
            "ONEINFINITY_SKIP_INTEGRITY is blocked in production (ONEINFINITY_ENV=production)"
        )

    if not skip_integrity:
        checksums = _load_checksums()
        entry = checksums.get(binary)
        if entry is None:
            raise NimIntegrityError(f"No checksum entry for binary: {binary!r}")
        expected_sha = entry if isinstance(entry, str) else entry.get("sha256", "")
        if not expected_sha:
            raise NimIntegrityError(f"Empty checksum entry for binary: {binary!r}")
        if not _verify_sha256(path, expected_sha):
            raise NimIntegrityError(
                f"SHA-256 mismatch for {binary!r} — binary may be tampered"
            )

    # Filter empty args
    clean_args = [a for a in args if a]

    try:
        proc_result = subprocess.run(
            [str(path)] + clean_args,
            capture_output=True,
            text=True,
            timeout=timeout,
        )
    except subprocess.TimeoutExpired as exc:
        raise NimExecutionError(f"{binary} timed out after {timeout}s") from exc

    if proc_result.returncode != 0:
        raise NimExecutionError(
            f"{binary} exited {proc_result.returncode}: {proc_result.stderr[:2000]}"
        )

    # Parse NDJSON — collect only event=result lines; skip non-JSON and other events
    results: list[dict[str, Any]] = []
    for raw_line in proc_result.stdout.splitlines():
        line = raw_line.strip()
        if not line:
            continue
        try:
            obj = json.loads(line)
        except json.JSONDecodeError:
            log.warning("nim_runner: skipping non-JSON line from %s", binary)
            continue
        if isinstance(obj, dict) and obj.get("event") == "result":
            results.append(obj)

    return results
