"""
Shared CLI helpers used by both cli/main.py and cli/commands/*.py.
Kept here to avoid circular imports.
"""
from __future__ import annotations
import sys
from pathlib import Path

CLI_COMMAND = "oneinfinity"
WORKSPACE_DIRNAME = "oneinfinity-workspace"
LEGACY_WORKSPACE_DIRNAME = "bounty-workspace"


def get_workspace_root() -> Path:
    from oneinfinity.path_manager import workspace_root
    return workspace_root()


def find_program_dir() -> Path | None:
    current = Path.cwd()
    for path in [current, *current.parents]:
        if (path / "scope.yaml").exists():
            return path
    return None


def get_program_dir(require: bool = True) -> Path:
    d = find_program_dir()
    if d:
        return d
    if require:
        from oneinfinity.modules.utils import err, info
        err("No scope.yaml found in current directory or parents.")
        info(f"Run: {CLI_COMMAND} setup <program-name>")
        info(f"Then: cd {get_workspace_root()}/<program-name>")
        sys.exit(1)
    return Path.cwd()
