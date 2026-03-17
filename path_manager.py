from __future__ import annotations

import logging
import os
import re
import shutil
import time
from pathlib import Path
from typing import Iterable, Optional

log = logging.getLogger("oneinfinity.path_manager")

DEFAULT_HOME_DIRNAME = ".oneinfinity"
ENV_HOME_VAR = "ONEINFINITY_HOME"

_PROJECT_ROOT = Path(__file__).resolve().parent
_MIGRATED = False


def project_root() -> Path:
    return _PROJECT_ROOT


def _resolve_home() -> Path:
    env = os.environ.get(ENV_HOME_VAR)
    base = Path(env).expanduser() if env else (Path.home() / DEFAULT_HOME_DIRNAME)
    return _ensure_not_in_project(base)


def _ensure_not_in_project(path: Path) -> Path:
    try:
        resolved = path.expanduser().resolve(strict=False)
    except Exception:
        resolved = path.expanduser().absolute()
    proj = project_root().resolve()
    if _is_within(resolved, proj):
        fallback = Path.home() / DEFAULT_HOME_DIRNAME
        log.warning(
            "%s points inside the project directory; using %s instead.",
            ENV_HOME_VAR,
            fallback,
        )
        return fallback
    return path


def _is_within(path: Path, root: Path) -> bool:
    try:
        path.relative_to(root)
        return True
    except ValueError:
        return False


def _storage_paths() -> tuple[Path, Path, Path, Path]:
    root = _resolve_home()
    return root, root / "raw", root / "logs", root / "databases"


def ensure_storage_dirs() -> None:
    root, raw, logs, databases = _storage_paths()
    root.mkdir(parents=True, exist_ok=True)
    raw.mkdir(parents=True, exist_ok=True)
    logs.mkdir(parents=True, exist_ok=True)
    databases.mkdir(parents=True, exist_ok=True)
    _ensure_migrated()


def data_root() -> Path:
    ensure_storage_dirs()
    return _storage_paths()[0]


def raw_dir() -> Path:
    ensure_storage_dirs()
    return _storage_paths()[1]


def logs_dir() -> Path:
    ensure_storage_dirs()
    return _storage_paths()[2]


def databases_dir() -> Path:
    ensure_storage_dirs()
    return _storage_paths()[3]


def db_path(name: str) -> Path:
    if not name.endswith(".db"):
        name = f"{name}.db"
    return databases_dir() / name


def attack_graph_db_path() -> Path:
    return db_path("attack_graph.db")


def findings_db_path() -> Path:
    return db_path("findings.db")


def knowledge_base_db_path() -> Path:
    return db_path("knowledge_base.db")


def research_db_path() -> Path:
    return db_path("research.db")


def recon_cache_db_path() -> Path:
    return db_path("recon_cache.db")


# ── Per-target canonical path helpers ────────────────────────────────────────

_TARGET_SUBDIRS = ("recon", "scans", "findings", "logs")


def _safe_target_name(target: str) -> str:
    """Convert a URL or domain to a safe filesystem directory name.

    Examples:
        "https://example.com/path" → "example.com"
        "api.example.com:8443"     → "api.example.com_8443"
    """
    name = target
    # Strip scheme
    if "://" in name:
        name = name.split("://", 1)[1]
    # Strip path, query, fragment — keep host:port only
    name = name.split("/")[0].split("?")[0].split("#")[0]
    # Replace characters illegal in directory names but keep dots and hyphens
    name = re.sub(r"[^\w.\-]", "_", name)
    return name or "unknown"


def _ensure_target_subdirs(root: Path) -> None:
    """Create the standard subdirectory layout under a target root."""
    for subdir in _TARGET_SUBDIRS:
        (root / subdir).mkdir(parents=True, exist_ok=True)


def resolve_target_path(target: str) -> Path:
    """Return the canonical data directory for *target*.

    Resolution order (first that exists wins):
      1. ``<workspace_root>/<safe_target_name>/``   (workspace — created by CLI / planner)
      2. ``<raw_dir>/<safe_target_name>/``           (global fallback)

    The chosen directory is guaranteed to exist with the four standard
    subdirectories: ``recon/``, ``scans/``, ``findings/``, ``logs/``.
    """
    safe_name = _safe_target_name(target)
    # Workspace preferred when it already exists
    ws_candidate = workspace_root() / safe_name
    if ws_candidate.exists():
        _ensure_target_subdirs(ws_candidate)
        return ws_candidate
    # Global raw dir fallback
    raw_candidate = raw_dir() / safe_name
    _ensure_target_subdirs(raw_candidate)
    return raw_candidate


def get_target_path(target: str, subdir: Optional[str] = None) -> Path:
    """Return the canonical path for *target*, optionally entering *subdir*.

    Parameters
    ----------
    target:
        URL or domain being scanned.
    subdir:
        One of ``"recon"``, ``"scans"``, ``"findings"``, ``"logs"`` or *None*
        to get the target root itself.

    The returned path is guaranteed to exist.
    """
    base = resolve_target_path(target)
    if subdir:
        p = base / subdir
        p.mkdir(parents=True, exist_ok=True)
        return p
    return base


def workspace_root() -> Path:
    env = os.environ.get("ONEINFINITY_WORKSPACE")
    if env:
        path = _ensure_not_in_project(Path(env).expanduser())
    else:
        path = raw_dir() / "workspaces"
    path.mkdir(parents=True, exist_ok=True)
    return path


def resolve_output_dir(output_dir: Optional[str | Path], target: Optional[str] = None) -> Path:
    if output_dir:
        path = Path(output_dir).expanduser()
        if not path.is_absolute():
            path = raw_dir() / path
    else:
        path = raw_dir() / target if target else raw_dir()

    try:
        resolved = path.resolve(strict=False)
    except Exception:
        resolved = path.absolute()
    if _is_within(resolved, project_root().resolve()):
        path = raw_dir() / (target or path.name)

    path.mkdir(parents=True, exist_ok=True)
    return path


def migrate_project_data(project_dir: Optional[Path] = None) -> list[tuple[Path, Path]]:
    project_dir = (project_dir or project_root()).resolve()
    _, raw, logs, databases = _storage_paths()
    moved: list[tuple[Path, Path]] = []

    dir_map = {
        "recon": raw / "recon",
        "raw": raw,
        "logs": logs,
        "databases": databases,
        "pipelines": raw / "pipelines",
        "reports": raw / "reports",
        "scans": raw / "scans",
        "swarm_results": raw / "swarm_results",
        "graphs": raw / "graphs",
        "mobile": raw / "mobile",
        "tools": raw / "tools",
        "bounty-workspace": raw / "bounty-workspace",
        "oneinfinity-workspace": raw / "workspaces",
    }

    for name, dest in dir_map.items():
        src = project_dir / name
        if src.exists() and src.is_dir():
            _merge_move_dir(src, dest)
            moved.append((src, dest))

    db_renames = {
        "knowledge.db": "knowledge_base.db",
    }
    db_files = [
        "attack_graph.db",
        "findings.db",
        "knowledge_base.db",
        "knowledge.db",
        "research.db",
        "recon_cache.db",
        "evolution.db",
        "event_bus.db",
        "traffic.db",
        "model_usage.db",
        "prompt_evolution.db",
        "mobile.db",
    ]

    for name in db_files:
        src = project_dir / name
        if not src.exists() or not src.is_file():
            continue
        dest_name = db_renames.get(name, name)
        dest = databases / dest_name
        dest = _unique_destination(dest)
        dest.parent.mkdir(parents=True, exist_ok=True)
        shutil.move(str(src), str(dest))
        moved.append((src, dest))

    return moved


def _ensure_migrated() -> None:
    global _MIGRATED
    if _MIGRATED:
        return
    _MIGRATED = True
    try:
        migrate_project_data()
    except Exception as exc:
        log.warning("Project data migration failed: %s", exc)


def _unique_destination(dest: Path) -> Path:
    if not dest.exists():
        return dest
    ts = time.strftime("%Y%m%d%H%M%S")
    suffix = f".migrated.{ts}"
    return dest.with_name(dest.name + suffix)


def _merge_move_dir(src: Path, dest: Path) -> None:
    dest.mkdir(parents=True, exist_ok=True)
    for item in src.iterdir():
        target = dest / item.name
        if target.exists():
            if item.is_dir() and target.is_dir():
                _merge_move_dir(item, target)
                continue
            target = _unique_destination(target)
        shutil.move(str(item), str(target))
    try:
        src.rmdir()
    except OSError:
        pass
