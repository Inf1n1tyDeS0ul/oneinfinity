"""
Mobile Upload Manager
=====================
Handles APK/IPA file upload, storage, extraction, and metadata tracking.

Storage layout:
    ~/.oneinfinity/raw/mobile/
        uploads/          ← raw APK/IPA files
        extracted/        ← extracted package contents
        analysis/         ← analysis results JSON

Features:
  - Accept APK (Android) and IPA (iOS) files
  - Validate file type by magic bytes and extension
  - Extract to working directory (zipfile-based for both formats)
  - Parse basic metadata (package name, version, platform)
  - Track uploads in PostgreSQL
  - CLI and API compatible
"""

from __future__ import annotations

import hashlib
import json
import logging
import shutil
import uuid
import zipfile
from dataclasses import asdict, dataclass, field
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Optional

from oneinfinity.path_manager import raw_dir

log = logging.getLogger("oneinfinity.mobile.upload")

MOBILE_ROOT = raw_dir() / "mobile"
UPLOADS_DIR = MOBILE_ROOT / "uploads"
EXTRACTED_DIR = MOBILE_ROOT / "extracted"
ANALYSIS_DIR = MOBILE_ROOT / "analysis"

for d in (UPLOADS_DIR, EXTRACTED_DIR, ANALYSIS_DIR):
    d.mkdir(parents=True, exist_ok=True)


def _require_pg():
    """Return DBManager in PG mode, or raise if unavailable."""
    try:
        from oneinfinity.core.db_manager import get_db_manager_sync
        mgr = get_db_manager_sync()
        if mgr is not None and mgr.mode in ("distributed", "postgres"):
            return mgr
    except Exception as exc:
        raise RuntimeError(f"PostgreSQL is required but DBManager unavailable: {exc}") from exc
    raise RuntimeError(
        "PostgreSQL is required. Set DB_MODE=postgres or DB_MODE=distributed."
    )


@dataclass
class MobileApp:
    id: str                        = field(default_factory=lambda: str(uuid.uuid4())[:12])
    filename: str                  = ""
    platform: str                  = ""        # android | ios
    package_name: str              = ""
    app_name: str                  = ""
    version_name: str              = ""
    version_code: str              = ""
    min_sdk: str                   = ""
    target_sdk: str                = ""
    file_size: int                 = 0
    sha256: str                    = ""
    upload_path: str               = ""
    extract_path: str              = ""
    uploaded_at: str               = field(default_factory=lambda: datetime.utcnow().isoformat())
    analysis_status: str           = "uploaded"
    metadata: Dict                 = field(default_factory=dict)

    def to_dict(self) -> Dict:
        d = asdict(self)
        d["metadata"] = json.dumps(d["metadata"])
        return d

    @classmethod
    def from_row(cls, row) -> "MobileApp":
        d = dict(row)
        try:
            d["metadata"] = json.loads(d.get("metadata") or "{}")
        except Exception:
            d["metadata"] = {}
        return cls(**d)

    def to_json(self) -> Dict:
        return asdict(self)


class MobileUploadManager:
    """Manages APK/IPA uploads, extraction and metadata. PostgreSQL is a hard requirement."""

    # ── Upload ────────────────────────────────────────────────────────────────

    def upload(self, source_path: str, original_filename: str = "") -> MobileApp:
        """Register and store an APK or IPA file. Returns MobileApp dataclass."""
        src = Path(source_path)
        if not src.exists():
            raise FileNotFoundError(f"File not found: {source_path}")

        fname = original_filename or src.name
        platform = self._detect_platform(src, fname)
        sha = self._sha256(src)

        existing = self._find_by_sha256(sha)
        if existing:
            log.info("Duplicate upload detected: %s (id=%s)", fname, existing.id)
            return existing

        app_id = str(uuid.uuid4())[:12]
        dest = UPLOADS_DIR / f"{app_id}_{fname}"
        shutil.copy2(str(src), str(dest))

        app = MobileApp(
            id=app_id,
            filename=fname,
            platform=platform,
            file_size=dest.stat().st_size,
            sha256=sha,
            upload_path=str(dest),
        )

        extract_dir = EXTRACTED_DIR / app_id
        extract_dir.mkdir(parents=True, exist_ok=True)
        app.extract_path = str(extract_dir)
        app.analysis_status = "extracting"
        self._store(app)

        try:
            self._extract(dest, extract_dir)
            self._parse_metadata(app, extract_dir)
            app.analysis_status = "extracted"
        except Exception as exc:
            log.error("Extraction failed for %s: %s", fname, exc)
            app.analysis_status = "extract_failed"
            app.metadata["extract_error"] = str(exc)

        self._store(app)
        log.info("Uploaded: %s (%s) id=%s", fname, platform, app_id)
        return app

    # ── Query ─────────────────────────────────────────────────────────────────

    def get(self, app_id: str) -> Optional[MobileApp]:
        rows = _require_pg().sync_pg_execute_read(
            "SELECT * FROM mobile_apps WHERE id = %s", (app_id,)
        )
        return MobileApp.from_row(rows[0]) if rows else None

    def list_apps(self, platform: Optional[str] = None, limit: int = 100) -> List[MobileApp]:
        if platform:
            rows = _require_pg().sync_pg_execute_read(
                "SELECT * FROM mobile_apps WHERE platform = %s ORDER BY uploaded_at DESC LIMIT %s",
                (platform, limit),
            )
        else:
            rows = _require_pg().sync_pg_execute_read(
                "SELECT * FROM mobile_apps ORDER BY uploaded_at DESC LIMIT %s", (limit,)
            )
        return [MobileApp.from_row(r) for r in rows]

    def update_status(self, app_id: str, status: str) -> None:
        _require_pg().sync_pg_execute_write(
            "UPDATE mobile_apps SET analysis_status=%s WHERE id=%s", (status, app_id)
        )

    def delete(self, app_id: str) -> None:
        app = self.get(app_id)
        if not app:
            return
        for p in (app.upload_path, app.extract_path):
            if p and Path(p).exists():
                if Path(p).is_dir():
                    shutil.rmtree(p, ignore_errors=True)
                else:
                    Path(p).unlink(missing_ok=True)
        _require_pg().sync_pg_execute_write(
            "DELETE FROM mobile_apps WHERE id=%s", (app_id,)
        )

    # ── Extraction ────────────────────────────────────────────────────────────

    def _extract(self, src: Path, dest: Path) -> None:
        log.debug("Extracting %s → %s", src, dest)
        with zipfile.ZipFile(str(src), "r") as z:
            for member in z.namelist():
                clean = member.lstrip("/").replace("..", "_")
                target = dest / clean
                if str(target).startswith(str(dest)):
                    try:
                        z.extract(member, str(dest))
                    except Exception:
                        pass
        log.debug("Extracted %d files to %s", len(list(dest.rglob("*"))), dest)

    # ── Metadata parsing ──────────────────────────────────────────────────────

    def _parse_metadata(self, app: MobileApp, extract_dir: Path) -> None:
        if app.platform == "android":
            self._parse_apk_metadata(app, extract_dir)
        elif app.platform == "ios":
            self._parse_ipa_metadata(app, extract_dir)

    def _parse_apk_metadata(self, app: MobileApp, extract_dir: Path) -> None:
        import subprocess
        upload_path = app.upload_path
        try:
            result = subprocess.run(
                ["aapt", "dump", "badging", upload_path],
                capture_output=True, text=True, timeout=30
            )
            if result.returncode == 0:
                self._parse_aapt_output(app, result.stdout)
                return
        except (FileNotFoundError, subprocess.TimeoutExpired):
            pass
        try:
            result = subprocess.run(
                ["aapt2", "dump", "badging", upload_path],
                capture_output=True, text=True, timeout=30
            )
            if result.returncode == 0:
                self._parse_aapt_output(app, result.stdout)
                return
        except (FileNotFoundError, subprocess.TimeoutExpired):
            pass
        manifest = extract_dir / "AndroidManifest.xml"
        if manifest.exists():
            try:
                content = manifest.read_bytes()
                text = content.decode("utf-8", errors="ignore")
                import re
                pkg = re.search(r'package="([^"]+)"', text)
                if pkg:
                    app.package_name = pkg.group(1)
                ver_name = re.search(r'versionName="([^"]+)"', text)
                if ver_name:
                    app.version_name = ver_name.group(1)
            except Exception:
                pass
        if not app.package_name:
            fname = Path(app.filename).stem
            if "." in fname:
                app.package_name = fname

    def _parse_aapt_output(self, app: MobileApp, output: str) -> None:
        import re
        m = re.search(r"package: name='([^']+)'", output)
        if m:
            app.package_name = m.group(1)
        m = re.search(r"versionName='([^']+)'", output)
        if m:
            app.version_name = m.group(1)
        m = re.search(r"versionCode='([^']+)'", output)
        if m:
            app.version_code = m.group(1)
        m = re.search(r"sdkVersion:'([^']+)'", output)
        if m:
            app.min_sdk = m.group(1)
        m = re.search(r"targetSdkVersion:'([^']+)'", output)
        if m:
            app.target_sdk = m.group(1)
        m = re.search(r"application-label:'([^']+)'", output)
        if m:
            app.app_name = m.group(1)

    def _parse_ipa_metadata(self, app: MobileApp, extract_dir: Path) -> None:
        import plistlib
        for plist_path in extract_dir.rglob("Info.plist"):
            if "Payload" in str(plist_path):
                try:
                    with open(plist_path, "rb") as f:
                        plist = plistlib.load(f)
                    app.package_name = plist.get("CFBundleIdentifier", "")
                    app.app_name = plist.get("CFBundleDisplayName") or plist.get("CFBundleName", "")
                    app.version_name = plist.get("CFBundleShortVersionString", "")
                    app.version_code = plist.get("CFBundleVersion", "")
                    app.min_sdk = str(plist.get("MinimumOSVersion", ""))
                    app.metadata.update({
                        "bundle_id": app.package_name,
                        "supported_platforms": plist.get("CFBundleSupportedPlatforms", []),
                        "capabilities": list(plist.keys()),
                    })
                    break
                except Exception as exc:
                    log.debug("plist parse error: %s", exc)

    # ── Helpers ───────────────────────────────────────────────────────────────

    def _detect_platform(self, path: Path, fname: str) -> str:
        ext = Path(fname).suffix.lower()
        if ext == ".apk":
            return "android"
        if ext == ".ipa":
            return "ios"
        try:
            with zipfile.ZipFile(str(path), "r") as z:
                names = z.namelist()
                if any("AndroidManifest.xml" in n for n in names):
                    return "android"
                if any("Payload/" in n and ".app/" in n for n in names):
                    return "ios"
        except Exception:
            pass
        return "unknown"

    def _sha256(self, path: Path) -> str:
        h = hashlib.sha256()
        with open(path, "rb") as f:
            for chunk in iter(lambda: f.read(65536), b""):
                h.update(chunk)
        return h.hexdigest()

    def _find_by_sha256(self, sha: str) -> Optional[MobileApp]:
        rows = _require_pg().sync_pg_execute_read(
            "SELECT * FROM mobile_apps WHERE sha256 = %s", (sha,)
        )
        return MobileApp.from_row(rows[0]) if rows else None

    def _store(self, app: MobileApp) -> None:
        d = app.to_dict()
        cols = list(d.keys())
        col_list = ", ".join(cols)
        placeholders = ", ".join("%s" for _ in cols)
        updates = ", ".join(f"{c}=%s" for c in cols if c != "id")
        update_vals = [d[c] for c in cols if c != "id"]
        _require_pg().sync_pg_execute_write(
            f"INSERT INTO mobile_apps ({col_list}) VALUES ({placeholders}) "
            f"ON CONFLICT (id) DO UPDATE SET {updates}",
            tuple(d.values()) + tuple(update_vals),
        )

    def get_extract_path(self, app_id: str) -> Optional[Path]:
        app = self.get(app_id)
        if app and app.extract_path:
            return Path(app.extract_path)
        return None


# Global singleton
mobile_upload_manager = MobileUploadManager()
