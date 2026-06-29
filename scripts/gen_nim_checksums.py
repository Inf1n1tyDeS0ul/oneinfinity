#!/usr/bin/env python3
"""Generate / update checksums.json for all Phase 3 Nim binaries.

Usage:
    python3 scripts/gen_nim_checksums.py

Scans src/nim/bin/ for the 6 expected binaries, computes their SHA-256
digests, and writes / merges the results into checksums.json at repo root.
"""
import hashlib
import json
import sys
from datetime import datetime, timezone
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
BIN_DIR = REPO_ROOT / "src" / "nim" / "bin"
CHECKSUMS_PATH = REPO_ROOT / "checksums.json"

EXPECTED_BINARIES = [
    "oi-shell-gen",
    "oi-bypass-gen",
    "oi-payloads",
    "oi-post-exploit",
    "oi-fuzzer",
    "oi-privesc-gen",
]


def sha256_file(path: Path) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(65536), b""):
            h.update(chunk)
    return h.hexdigest()


def load_existing() -> dict:
    if CHECKSUMS_PATH.exists():
        with open(CHECKSUMS_PATH) as f:
            return json.load(f)
    return {}


def main() -> int:
    if not BIN_DIR.exists():
        print(f"ERROR: binary directory does not exist: {BIN_DIR}", file=sys.stderr)
        return 1

    existing = load_existing()
    # Support both flat schema and {"binaries": {...}} schema; normalise to flat
    if "binaries" in existing:
        binaries_section = existing["binaries"]
    else:
        binaries_section = existing

    now_iso = datetime.now(timezone.utc).isoformat()
    found = []
    missing = []

    for name in EXPECTED_BINARIES:
        path = BIN_DIR / name
        if not path.exists():
            missing.append(name)
            print(f"  MISSING  {name}")
            continue
        digest = sha256_file(path)
        binaries_section[name] = {
            "sha256": digest,
            "built_at": now_iso,
            "path": str(path.relative_to(REPO_ROOT)),
        }
        found.append(name)
        print(f"  OK       {name}  {digest[:16]}...")

    # Also scan for any other binaries present in bin/ (forward-compat)
    for path in sorted(BIN_DIR.iterdir()):
        if path.name not in EXPECTED_BINARIES and path.is_file():
            digest = sha256_file(path)
            binaries_section[path.name] = {
                "sha256": digest,
                "built_at": now_iso,
                "path": str(path.relative_to(REPO_ROOT)),
            }
            print(f"  EXTRA    {path.name}  {digest[:16]}...")

    # Write back (always flat schema; nim_runner.py handles both)
    output = binaries_section
    with open(CHECKSUMS_PATH, "w") as f:
        json.dump(output, f, indent=2)
        f.write("\n")

    print(f"\nWrote {len(found)} entries to {CHECKSUMS_PATH}")
    if missing:
        print(f"WARNING: {len(missing)} binaries not yet compiled: {missing}")
        return 0  # Not a fatal error — binaries may be compiled later

    return 0


if __name__ == "__main__":
    sys.exit(main())
