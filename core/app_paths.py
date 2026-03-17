from __future__ import annotations

from pathlib import Path

from path_manager import data_root


def app_home() -> Path:
    """Backward-compatible wrapper around the new centralized path manager."""
    return data_root()


def ensure_app_home() -> Path:
    return data_root()
