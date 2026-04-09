"""
CLI command handlers for internal domain.
Each public function is cmd_* (handler) or register() (argparse setup).
"""
from __future__ import annotations
import sys
import os
import asyncio
import logging
from pathlib import Path
from oneinfinity.cli._helpers import (
    CLI_COMMAND, WORKSPACE_DIRNAME, LEGACY_WORKSPACE_DIRNAME,
    get_workspace_root, find_program_dir, get_program_dir,
)

log = logging.getLogger(__name__)

def cmd__internal_register(args):
    """oneinfinity _internal_register <target> — internal phase."""
    from oneinfinity.pipeline.executor import CanonicalExecutor
    from pathlib import Path
    out = getattr(args, "output", ".") or "."
    exec = CanonicalExecutor()
    exec._inline_target_registration(args.target, Path(out))


def cmd__internal_deep_recon(args):
    """oneinfinity _internal_deep_recon <target> — internal phase."""
    from oneinfinity.pipeline.executor import CanonicalExecutor
    from pathlib import Path
    out = getattr(args, "output", ".") or "."
    exec = CanonicalExecutor()
    exec._inline_deep_recon(args.target, Path(out), {})


def cmd__internal_auth_session(args):
    """oneinfinity _internal_auth_session <target> — internal phase."""
    from oneinfinity.pipeline.executor import CanonicalExecutor
    from pathlib import Path
    out = getattr(args, "output", ".") or "."
    exec = CanonicalExecutor()
    exec._inline_auth_session(args.target, Path(out), {})


if __name__ == "__main__":
    main()




def register(subparsers):
    """Register internal commands with the CLI argument parser."""
    pass
