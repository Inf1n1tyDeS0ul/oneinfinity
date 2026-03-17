#!/usr/bin/env python3
"""
Deprecated compatibility wrapper.

The CLI entry point has been renamed from `bounty` to `oneinfinity`.
"""

from __future__ import annotations

import sys


def main() -> None:
    from oneinfinity import main as _main  # type: ignore

    # Best-effort notice; keep stdout/stderr behavior compatible otherwise.
    if "--quiet" not in sys.argv and "-q" not in sys.argv:
        print("[!] Deprecated: use `oneinfinity` instead of `bounty`.", file=sys.stderr)
    _main()


if __name__ == "__main__":
    main()

