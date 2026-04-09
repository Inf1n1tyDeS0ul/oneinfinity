#!/usr/bin/env python3
"""
oneinfinity — AI-Powered Offensive Security Research Framework
==============================================================
Development entry-point shim. The full CLI now lives in:
  src/oneinfinity/cli/main.py  (router + argparse)
  src/oneinfinity/cli/commands/*.py  (domain handlers)

For installed usage: the 'oneinfinity' binary is defined in pyproject.toml
[project.scripts] and runs oneinfinity.cli.main:main directly.
"""
import sys
import os

# Ensure src/ is on sys.path when invoked as 'python3 run.py'
_SRC = os.path.join(os.path.dirname(os.path.abspath(__file__)), "src")
if _SRC not in sys.path:
    sys.path.insert(0, _SRC)

from oneinfinity.cli.main import main

if __name__ == "__main__":
    main()
