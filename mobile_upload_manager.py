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
  - Track uploads in SQLite
  - CLI and API compatible
"""

from __future__ import annotations

import hashlib
import json
import logging
import os
import shutil
import sqlite3
import threading
import uuid
import zipfile
from dataclasses import asdict, dataclass, field
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Optional, Tuple

from path_manager import raw_dir

log = logging.getLogger("oneinfinity.mobile.upload")

MOBILE_ROOT = raw_dir() / "mobile"
UPLOADS_DIR = MOBILE_ROOT / "uploads"
EXTRACTED_DIR = MOBILE_ROOT / "extracted"
ANALYSIS_DIR = MOBILE_ROOT / "analysis"
DB_PATH = MOBILE_ROOT / "mobile.db"

for d in (UPLOADS_DIR, EXTRACTED_DIR, ANALYSIS_DIR):
    d.mkdir(parents=True, exist_ok=True)

# Magic bytes for file type detection
_APK_MAGIC = b"PK\x03\x04"   # ZIP
_IPA_MAGIC = b"PK\x03\x04"   # ZIP (IPA is also a ZIP)


@dataclass
class MobileApp:
    id: str                        = field(default_factory=lambda: str(uuid.uuid4())[:12])
    filename: str                  = ""
    platform: str                  = ""        # android | ios
    package_name: str              = ""        # e.g. com.example.app
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
    analysis_status: str           = "uploaded"  # uploaded|extracting|analyzing|done|failed
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
        d = asdict(self)
        return d


_CREATE_TABLE = """
CREATE TABLE IF NOT EXISTS mobile_apps (
    id               TEXT PRIMARY KEY,
    filename         TEXT,
    platform         TEXT,
    package_name     TEXT,
    app_name         TEXT,
    version_name     TEXT,
    version_code     TEXT,
    min_sdk          TEXT,
    target_sdk       TEXT,
    file_size        INTEGER DEFAULT 0,
    sha256           TEXT,
    upload_path      TEXT,
    extract_path     TEXT,
    uploaded_at      TEXT,
    analysis_status  TEXT DEFAULT 'uploaded',
    metadata         TEXT DEFAULT '{}'
);
CREATE INDEX IF NOT EXISTS idx_package ON mobile_apps(package_name);
CREATE INDEX IF NOT EXISTS idx_platform ON mobile_apps(platform);
"""


class MobileUploadManager:
    """Manages APK/IPA uploads, extraction and metadata."""

    def __init__(self, db_path: Path = DB_PATH) -> None:
        self._db_path = db_path
        self._local = threading.local()
        self._lock = threading.Lock()
        self._init_db()

    def _init_db(self) -> None:
        con = self._conn()
        con.executescript(_CREATE_TABLE)
        con.commit()

    def _conn(self) -> sqlite3.Connection:
        if not getattr(self._local, "conn", None):
            self._local.conn = sqlite3.connect(str(self._db_path), check_same_thread=False)
            self._local.conn.row_factory = sqlite3.Row
            self._local.conn.execute("PRAGMA journal_mode=WAL")
        return self._local.conn

    # ── Upload ────────────────────────────────────────────────────────────────

    def upload(self, source_path: str, original_filename: str = "") -> MobileApp:
        """
        Register and store an APK or IPA file.
        source_path: path to the file on disk (already uploaded/copied)
        Returns MobileApp dataclass.
        """
        src = Path(source_path)
        if not src.exists():
            raise FileNotFoundError(f"File not found: {source_path}")

        fname = original_filename or src.name
        platform = self._detect_platform(src, fname)

        # Compute SHA-256
        sha = self._sha256(src)

        # Check for duplicate
        existing = self._find_by_sha256(sha)
        if existing:
            log.info("Duplicate upload detected: %s (id=%s)", fname, existing.id)
            return existing

        # Copy to uploads dir
        app_id = str(uuid.uuid4())[:12]
        dest = UPLOADS_DIR / f"{app_id}_{fname}"
        shutil.copy2(str(src), str(dest))

        # Build app record
        app = MobileApp(
            id=app_id,
            filename=fname,
            platform=platform,
            file_size=dest.stat().st_size,
            sha256=sha,
            upload_path=str(dest),
        )

        # Extract and parse metadata
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
        row = self._conn().execute(
            "SELECT * FROM mobile_apps WHERE id=?", (app_id,)
        ).fetchone()
        return MobileApp.from_row(row) if row else None

    def list_apps(self, platform: Optional[str] = None, limit: int = 100) -> List[MobileApp]:
        if platform:
            rows = self._conn().execute(
                "SELECT * FROM mobile_apps WHERE platform=? ORDER BY uploaded_at DESC LIMIT ?",
                (platform, limit)
            ).fetchall()
        else:
            rows = self._conn().execute(
                "SELECT * FROM mobile_apps ORDER BY uploaded_at DESC LIMIT ?", (limit,)
            ).fetchall()
        return [MobileApp.from_row(r) for r in rows]

    def update_status(self, app_id: str, status: str) -> None:
        with self._lock:
            self._conn().execute(
                "UPDATE mobile_apps SET analysis_status=? WHERE id=?", (status, app_id)
            )
            self._conn().commit()

    def delete(self, app_id: str) -> None:
        app = self.get(app_id)
        if not app:
            return
        # Remove files
        for p in (app.upload_path, app.extract_path):
            if p and Path(p).exists():
                if Path(p).is_dir():
                    shutil.rmtree(p, ignore_errors=True)
                else:
                    Path(p).unlink(missing_ok=True)
        with self._lock:
            self._conn().execute("DELETE FROM mobile_apps WHERE id=?", (app_id,))
            self._conn().commit()

    # ── Extraction ────────────────────────────────────────────────────────────

    def _extract(self, src: Path, dest: Path) -> None:
        """Extract APK or IPA (both are ZIP archives)."""
        log.debug("Extracting %s → %s", src, dest)
        with zipfile.ZipFile(str(src), "r") as z:
            # Safety: only extract safe members
            for member in z.namelist():
                # Skip absolute paths and path traversal
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
        """Parse AndroidManifest.xml and extract basic APK metadata."""
        import subprocess

        # Try aapt first (fastest)
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

        # Try aapt2
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

        # Fallback: read AndroidManifest.xml (may be binary XML)
        manifest = extract_dir / "AndroidManifest.xml"
        if manifest.exists():
            try:
                content = manifest.read_bytes()
                # Try to extract package name from binary XML
                # Binary AndroidManifest.xml has the string pool after the header
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

        # Extract package name from path as last resort
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
        """Parse IPA Info.plist for metadata."""
        import plistlib
        # Find Info.plist inside Payload/*.app/
        plist_files = list(extract_dir.rglob("Info.plist"))
        for plist_path in plist_files:
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
        # Check internal structure
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
        row = self._conn().execute(
            "SELECT * FROM mobile_apps WHERE sha256=?", (sha,)
        ).fetchone()
        return MobileApp.from_row(row) if row else None

    def _store(self, app: MobileApp) -> None:
        d = app.to_dict()
        cols = ", ".join(d.keys())
        placeholders = ", ".join("?" for _ in d)
        sql = f"INSERT OR REPLACE INTO mobile_apps ({cols}) VALUES ({placeholders})"
        with self._lock:
            self._conn().execute(sql, list(d.values()))
            self._conn().commit()

    def get_extract_path(self, app_id: str) -> Optional[Path]:
        app = self.get(app_id)
        if app and app.extract_path:
            return Path(app.extract_path)
        return None


# Global singleton
mobile_upload_manager = MobileUploadManager()
