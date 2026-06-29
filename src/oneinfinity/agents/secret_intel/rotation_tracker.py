"""
rotation_tracker.py — Temporal Secret Exposure & Rotation Detection

Tracks the lifecycle of every confirmed secret across scans:

  NEW        — first time we see this secret hash at this location
  CONFIRMED  — seen again; still present, still exposed
  ROTATED    — the raw content of the location changed (new hash ≠ old hash)
               but the location (repo + file_url) is the same
  STALE      — location disappeared (repo deleted, file removed, 404)

Rotation detection without storing raw secrets
-----------------------------------------------
  Each secret is identified by:
    domain_fingerprint  = SHA-256(secret_type + ":" + sha256_of_value)
                          ^ double-hashed so no raw value is ever stored

  Each observed location is identified by:
    location_id = SHA-256(repo_url + ":" + file_path)

  On each scan we compare the current domain_fingerprint for a location
  against the stored one. If the location_id exists but the fingerprint
  changed → ROTATED.  If the fingerprint is the same → CONFIRMED.

Integration
-----------
  Called from SecretIntelAgent Phase 9 (ingestion) after live validation:

    from oneinfinity.agents.secret_intel.rotation_tracker import get_tracker
    tracker = get_tracker()
    status = tracker.record(finding)          # "NEW" | "CONFIRMED" | "ROTATED" | "STALE"
    finding["rotation_status"] = status

EventBus events emitted (non-blocking):
    SECRET_ROTATED   — on ROTATED status (rotation confirmed, domain_fingerprint changed)
    NEW_SECRET_FOUND — on NEW status (novel secret, first ever seen)

Persistence:
    JSON file at raw_dir() / "memory" / "rotation_tracker.json"
    Thread-safe; atomic rename-write to prevent corruption.
"""

from __future__ import annotations

import hashlib
import json
import logging
import os
import tempfile
import threading
import time
from pathlib import Path
from typing import Dict, Any, Optional

log = logging.getLogger("oneinfinity.secret_intel.rotation_tracker")

# Rotation statuses
STATUS_NEW        = "NEW"
STATUS_CONFIRMED  = "CONFIRMED"
STATUS_ROTATED    = "ROTATED"
STATUS_STALE      = "STALE"


def _sha256(value: str) -> str:
    return hashlib.sha256(value.encode()).hexdigest()


def _domain_fingerprint(secret_type: str, value_hash: str) -> str:
    """
    Double-hash fingerprint: SHA-256(secret_type + ":" + value_hash).
    No raw secret value ever reaches this function.
    `value_hash` must already be SHA-256(raw_value) — enforced by caller.
    """
    return _sha256(f"{secret_type}:{value_hash}")


def _location_id(repo_url: str, file_url: str) -> str:
    """Stable identifier for a (repo, file) pair."""
    return _sha256(f"{repo_url}:{file_url}")


# ---------------------------------------------------------------------------
# Persistence helpers
# ---------------------------------------------------------------------------

def _default_store_path() -> Path:
    try:
        from oneinfinity.infra.path_manager import raw_dir
        return raw_dir() / "memory" / "rotation_tracker.json"
    except Exception:
        return Path(os.path.expanduser("~/.oneinfinity/memory/rotation_tracker.json"))


def _load(path: Path) -> dict:
    if path.exists():
        try:
            return json.loads(path.read_text())
        except Exception as exc:
            log.warning("rotation_tracker: failed to load store (%s) — starting fresh", exc)
    return {"locations": {}}


def _save(path: Path, data: dict) -> None:
    """Atomic write: write to temp then rename."""
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, tmp = tempfile.mkstemp(dir=str(path.parent), prefix=".rt_tmp_")
    try:
        with os.fdopen(fd, "w") as fh:
            json.dump(data, fh, indent=2)
        os.replace(tmp, str(path))
    except Exception:
        try:
            os.unlink(tmp)
        except OSError:
            pass
        raise


# ---------------------------------------------------------------------------
# RotationTracker
# ---------------------------------------------------------------------------

class RotationTracker:
    """
    Thread-safe tracker for secret rotation detection across scans.
    """

    def __init__(self, store_path: Optional[Path] = None) -> None:
        self._path = store_path or _default_store_path()
        self._lock = threading.RLock()
        self._data: dict = _load(self._path)

    # ── Public API ────────────────────────────────────────────────────────────

    def record(self, finding: Dict[str, Any]) -> str:
        """
        Record a validated finding and return its rotation status.

        Parameters
        ----------
        finding : dict
            Must contain at minimum:
              value_hash  — SHA-256 of the raw secret (never the raw value)
              type        — secret type string (e.g. "aws_access_key_id")
              repo        — GitHub repo full name
              file_url    — raw file URL

        Returns
        -------
        str
            One of NEW | CONFIRMED | ROTATED | STALE
        """
        value_hash = finding.get("value_hash", "")
        secret_type = finding.get("type", "unknown")
        repo_url = finding.get("repo_url") or finding.get("repo", "")
        file_url = finding.get("file_url") or finding.get("url", "")

        if not value_hash or not file_url:
            log.debug("rotation_tracker.record: missing value_hash or file_url — skipping")
            return STATUS_NEW

        fp = _domain_fingerprint(secret_type, value_hash)
        loc_id = _location_id(repo_url, file_url)

        with self._lock:
            locations: dict = self._data.setdefault("locations", {})
            entry = locations.get(loc_id)

            now = time.time()

            if entry is None:
                # First time we have ever seen this location
                locations[loc_id] = {
                    "domain_fingerprint": fp,
                    "secret_type": secret_type,
                    "repo_url": repo_url,
                    "file_url": file_url,
                    "first_seen": now,
                    "last_seen": now,
                    "scan_count": 1,
                    "rotation_count": 0,
                    "status": STATUS_NEW,
                }
                status = STATUS_NEW
            elif entry["domain_fingerprint"] == fp:
                # Same fingerprint — still the same secret
                entry["last_seen"] = now
                entry["scan_count"] = entry.get("scan_count", 0) + 1
                entry["status"] = STATUS_CONFIRMED
                status = STATUS_CONFIRMED
            else:
                # Fingerprint changed — the secret was rotated (or replaced)
                old_fp = entry["domain_fingerprint"]
                entry["domain_fingerprint"] = fp
                entry["last_seen"] = now
                entry["scan_count"] = entry.get("scan_count", 0) + 1
                entry["rotation_count"] = entry.get("rotation_count", 0) + 1
                entry["status"] = STATUS_ROTATED
                entry.setdefault("rotation_history", []).append({
                    "old_fingerprint": old_fp,
                    "new_fingerprint": fp,
                    "rotated_at": now,
                })
                status = STATUS_ROTATED
                log.info(
                    "Secret rotated: type=%s repo=%s file=%s (rotation #%d)",
                    secret_type, repo_url, file_url[:60], entry["rotation_count"],
                )

            self._save_async()

        # Emit event bus events (best-effort, non-blocking)
        self._emit(status, finding, fp, loc_id)

        return status

    def mark_stale(self, repo_url: str, file_url: str) -> bool:
        """
        Mark a location as stale (file removed or repo gone).
        Returns True if the location was known.
        """
        loc_id = _location_id(repo_url, file_url)
        with self._lock:
            entry = self._data.get("locations", {}).get(loc_id)
            if entry:
                entry["status"] = STATUS_STALE
                entry["stale_since"] = time.time()
                self._save_async()
                return True
        return False

    def get_stats(self) -> Dict[str, Any]:
        """Return aggregated statistics for the monitoring dashboard."""
        with self._lock:
            locations = self._data.get("locations", {})
            by_status: Dict[str, int] = {
                STATUS_NEW: 0,
                STATUS_CONFIRMED: 0,
                STATUS_ROTATED: 0,
                STATUS_STALE: 0,
            }
            by_type: Dict[str, int] = {}
            total_rotations = 0

            for entry in locations.values():
                st = entry.get("status", STATUS_NEW)
                by_status[st] = by_status.get(st, 0) + 1
                stype = entry.get("secret_type", "unknown")
                by_type[stype] = by_type.get(stype, 0) + 1
                total_rotations += entry.get("rotation_count", 0)

            return {
                "total_locations": len(locations),
                "by_status": by_status,
                "by_type": by_type,
                "total_rotations_detected": total_rotations,
            }

    def get_active_exposures(self, max_age_days: float = 30.0) -> list:
        """
        Return all CONFIRMED locations not older than max_age_days.
        Used by the monitoring dashboard for 'always-on surveillance'.
        """
        cutoff = time.time() - max_age_days * 86400
        with self._lock:
            return [
                {**entry, "location_id": loc_id}
                for loc_id, entry in self._data.get("locations", {}).items()
                if entry.get("status") == STATUS_CONFIRMED
                and entry.get("last_seen", 0) >= cutoff
            ]

    # ── Internal ──────────────────────────────────────────────────────────────

    def _save_async(self) -> None:
        """Persist in background thread to avoid blocking the scanner."""
        data_copy = json.loads(json.dumps(self._data))  # cheap deep copy
        path = self._path

        def _write() -> None:
            try:
                _save(path, data_copy)
            except Exception as exc:
                log.warning("rotation_tracker: background save failed: %s", exc)

        t = threading.Thread(target=_write, daemon=True)
        t.start()

    def _emit(self, status: str, finding: dict, fp: str, loc_id: str) -> None:
        """Publish EventBus events for notable status changes (best-effort)."""
        try:
            from oneinfinity.orchestration.event_bus import get_bus, EventType
            bus = get_bus()
            if status == STATUS_NEW:
                bus.publish(
                    event_type=EventType.NEW_SECRET_FOUND,
                    source="rotation_tracker",
                    data={
                        "secret_type": finding.get("type"),
                        "repo": finding.get("repo"),
                        "severity": finding.get("severity", "high"),
                        "location_id": loc_id,
                        "domain_fingerprint": fp,
                    },
                )
            elif status == STATUS_ROTATED:
                bus.publish(
                    event_type=EventType.SECRET_ROTATED,
                    source="rotation_tracker",
                    data={
                        "secret_type": finding.get("type"),
                        "repo": finding.get("repo"),
                        "location_id": loc_id,
                        "domain_fingerprint": fp,
                        "message": (
                            f"Secret {finding.get('type')} in {finding.get('repo')} "
                            "was rotated — new credential detected at same location"
                        ),
                    },
                )
        except Exception as _e:
            log.debug("rotation_tracker._emit: event bus publish failed: %s", _e)


# ---------------------------------------------------------------------------
# Module-level singleton
# ---------------------------------------------------------------------------

_TRACKER_INSTANCE: Optional[RotationTracker] = None
_TRACKER_LOCK = threading.Lock()


def get_tracker(store_path: Optional[Path] = None) -> RotationTracker:
    """Return (or lazily create) the module-level RotationTracker singleton."""
    global _TRACKER_INSTANCE
    if _TRACKER_INSTANCE is None:
        with _TRACKER_LOCK:
            if _TRACKER_INSTANCE is None:
                _TRACKER_INSTANCE = RotationTracker(store_path)
    return _TRACKER_INSTANCE
