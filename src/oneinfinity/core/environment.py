"""
environment.py — Runtime environment validation and setup.

Provides clear, actionable errors when tools are missing.
Never fails silently. Never assumes a specific OS or user.
"""
from __future__ import annotations
import os
import shutil
import sys
import platform
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional

from oneinfinity.core.path_resolver import get_tool_binary, get_tool_search_paths


@dataclass
class ToolStatus:
    name: str
    available: bool
    path: Optional[str] = None
    version: Optional[str] = None
    install_hint: str = ''


# Install hints per tool and platform
_INSTALL_HINTS = {
    'nuclei': 'go install github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest',
    'subfinder': 'go install github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest',
    'httpx': 'go install github.com/projectdiscovery/httpx/cmd/httpx@latest',
    'katana': 'go install github.com/projectdiscovery/katana/cmd/katana@latest',
    'dalfox': 'go install github.com/hahwul/dalfox/v2@latest',
    'sqlmap': 'pip install sqlmap  # or: brew install sqlmap',
    'ffuf': 'go install github.com/ffuf/ffuf/v2@latest',
    'feroxbuster': 'brew install feroxbuster  # or: cargo install feroxbuster',
    'frida': 'pip install frida-tools',
    'objection': 'pip install objection',
    'apkleaks': 'pip install apkleaks',
    'jadx': 'brew install jadx  # or: download from github.com/skylot/jadx',
    'nmap': 'brew install nmap  # or: apt install nmap',
    'garak': 'pip install garak',
    'hydra': 'brew install hydra  # or: apt install hydra',
}


def check_tool(name: str) -> ToolStatus:
    """Check if a tool is available and get its path."""
    path = get_tool_binary(name)
    if not path:
        return ToolStatus(
            name=name,
            available=False,
            install_hint=_INSTALL_HINTS.get(name, f'Please install {name}')
        )
    # Try to get version
    version = None
    try:
        import subprocess
        r = subprocess.run([path, '--version'], capture_output=True, text=True, timeout=3)
        out = (r.stdout + r.stderr).strip().split('\n')[0]
        version = out[:60] if out else None
    except Exception:
        pass
    return ToolStatus(name=name, available=True, path=path, version=version)


def check_environment(tools: list[str] = None, verbose: bool = False) -> dict[str, ToolStatus]:
    """Check all tools and return status dict."""
    if tools is None:
        tools = list(_INSTALL_HINTS.keys())
    results = {}
    for tool in tools:
        results[tool] = check_tool(tool)
        if verbose:
            st = results[tool]
            icon = '\u2705' if st.available else '\u274c'
            print(f'  {icon} {tool:<20} {st.path or st.install_hint}')
    return results


def get_missing_tools(tools: list[str] = None) -> list[ToolStatus]:
    """Return list of missing tools with install hints."""
    return [s for s in check_environment(tools).values() if not s.available]


def assert_tool_available(name: str) -> str:
    """Return tool path or raise clear error with install hint."""
    st = check_tool(name)
    if not st.available:
        raise RuntimeError(
            f"Required tool '{name}' not found.\n"
            f"Install with: {st.install_hint}\n"
            f"Search paths: {get_tool_search_paths()[:3]}..."
        )
    return st.path


# Platform detection (portable)
IS_MACOS = platform.system() == 'Darwin'
IS_LINUX = platform.system() == 'Linux'
IS_WINDOWS = platform.system() == 'Windows'
