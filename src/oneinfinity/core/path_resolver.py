"""
path_resolver.py — Central dynamic path resolution for OneInfinity.

NO hardcoded usernames or absolute paths. Everything is derived from:
- The location of this file (project root)
- Environment variables (with portable defaults)
- Standard system locations

Import pattern:
    from oneinfinity.core.path_resolver import get_tool_binary, get_project_root, ONEINFINITY_HOME
"""
from __future__ import annotations
import os
import shutil
import sys
from functools import lru_cache
from pathlib import Path


@lru_cache(maxsize=1)
def get_project_root() -> Path:
    """Return the project root (directory containing pyproject.toml)."""
    candidate = Path(__file__).resolve()
    for _ in range(10):
        candidate = candidate.parent
        if (candidate / 'pyproject.toml').exists():
            return candidate
    # Fallback: current working directory
    return Path.cwd()


@lru_cache(maxsize=1)
def get_tool_search_paths() -> list[str]:
    """Return ordered list of directories to search for tool binaries.

    Order:
    1. Active Python venv bin/ (sys.prefix)
    2. User local bin (~/.local/bin)
    3. Go bin (~/go/bin)
    4. Cargo bin (~/.cargo/bin)
    5. Homebrew (ARM: /opt/homebrew/bin, Intel: /usr/local/bin)
    6. System locations (/usr/local/bin, /usr/bin, /bin)
    7. Custom ONEINFINITY_TOOL_PATH env var entries
    """
    home = Path.home()
    paths = []

    # 1. Active venv
    if hasattr(sys, 'real_prefix') or (hasattr(sys, 'base_prefix') and sys.base_prefix != sys.prefix):
        paths.append(str(Path(sys.prefix) / 'bin'))

    # 2-4. User tool managers
    paths.extend([
        str(home / '.local' / 'bin'),
        str(home / 'go' / 'bin'),
        str(home / '.cargo' / 'bin'),
    ])

    # 5. Homebrew (macOS)
    paths.extend(['/opt/homebrew/bin', '/usr/local/bin'])

    # 6. System
    paths.extend(['/usr/bin', '/bin', '/usr/sbin', '/sbin'])

    # 7. Custom override
    custom = os.environ.get('ONEINFINITY_TOOL_PATH', '')
    if custom:
        paths = custom.split(':') + paths

    # Deduplicate preserving order
    seen: set[str] = set()
    result: list[str] = []
    for p in paths:
        if p not in seen and Path(p).is_dir():
            seen.add(p)
            result.append(p)
    return result


def get_tool_binary(name: str, alternatives: list[str] | None = None) -> str | None:
    """Find a tool binary using portable path resolution.

    Never returns a hardcoded path. Returns None if not found.

    Args:
        name: Primary binary name (e.g. 'frida')
        alternatives: Additional names to try (e.g. ['frida-ps'])
    """
    search_paths = get_tool_search_paths()
    search_env = os.pathsep.join(search_paths) + os.pathsep + os.environ.get('PATH', '')

    names = [name] + (alternatives or [])
    for n in names:
        found = shutil.which(n, path=search_env)
        if found:
            return found
    return None


# ── Key project directories (all derived, never hardcoded) ────────────────────

@lru_cache(maxsize=1)
def get_oneinfinity_home() -> Path:
    """User data directory. Defaults to ~/.oneinfinity, overrideable via ONEINFINITY_HOME."""
    raw = os.environ.get('ONEINFINITY_HOME', '')
    if raw:
        return Path(raw).expanduser()
    return Path.home() / '.oneinfinity'


@lru_cache(maxsize=1)
def get_wordlist_path() -> str | None:
    """Find a usable wordlist. Returns None if none found."""
    candidates = [
        os.environ.get('ONEINFINITY_WORDLIST', ''),
        str(get_oneinfinity_home() / 'wordlists' / 'common.txt'),
        str(Path.home() / '.local' / 'share' / 'wordlists' / 'common.txt'),
        '/opt/homebrew/share/seclists/Discovery/Web-Content/common.txt',
        '/usr/share/seclists/Discovery/Web-Content/common.txt',
        '/usr/share/wordlists/dirb/common.txt',
        '/usr/share/wordlists/rockyou.txt',
    ]
    for p in candidates:
        if p and Path(p).exists():
            return p
    return None


# Convenience aliases
PROJECT_ROOT = get_project_root()
ONEINFINITY_HOME = get_oneinfinity_home()
