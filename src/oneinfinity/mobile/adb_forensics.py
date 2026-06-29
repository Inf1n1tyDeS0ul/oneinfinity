import adbutils
import logging
import re
import shlex
import threading
import time
import os
from typing import Dict, List, Optional

logger = logging.getLogger(__name__)

class AegisForensicEngine:
    """
    Advanced Forensic Engine for Android.
    Automates 9 DFIR areas: Sandbox, Logcat, Memory, Network, Environment, Artifacts, etc.
    """
    def __init__(self):
        try:
            self.adb = adbutils.adb
        except Exception:
            self.adb = None

    def list_devices(self) -> List[Dict]:
        if not self.adb:
            return []
        try:
            # Use adb.list() to get all devices including offline, with real state
            return [{"serial": info.serial, "state": info.state} for info in self.adb.list()]
        except Exception:
            return []

    def install_system_ca(self, serial: str, cert_path: str = "~/.mitmproxy/mitmproxy-ca-cert.pem") -> bool:
        """
        Pushes and installs CA cert into system trust store (requires root).
        """
        full_cert_path = os.path.expanduser(cert_path)
        if not os.path.exists(full_cert_path):
            logger.error(f"CA Cert not found at {full_cert_path}")
            return False

        try:
            device = self.adb.device(serial=serial)
            # Calculate OpenSSL hash for Android system store (e.g. c8750f0d.0)
            result = subprocess.run(
                ["openssl", "x509", "-inform", "PEM", "-subject_hash_old", "-in", str(full_cert_path)],
                capture_output=True, text=True, check=True
            )
            cert_hash = result.stdout.strip().split('\n')[0]
            dest_name = f"{cert_hash}.0"
            
            logger.info(f"Aegis: Installing CA {dest_name} to system store...")
            
            # 1. Push to temp
            device.push(full_cert_path, f"/data/local/tmp/{dest_name}")
            
            # 2. Remount /system as RW and move cert
            # Note: Modern Android needs different remount strategies; this covers most rooted setups
            cmds = [
                "su -c 'mount -o rw,remount /'",
                f"su -c 'cp /data/local/tmp/{dest_name} /system/etc/security/cacerts/'",
                f"su -c 'chmod 644 /system/etc/security/cacerts/{dest_name}'",
                "su -c 'mount -o ro,remount /'"
            ]
            for cmd in cmds:
                device.shell(cmd)
            
            logger.info("Aegis: CA Cert installed successfully.")
            return True
        except Exception as e:
            logger.error(f"Aegis CA Install failed: {e}")
            return False

    def run_audit(self, serial: str, package_name: str, on_signal: Optional[callable] = None) -> List[Dict]:
        """
        Run a multi-threaded, comprehensive forensic audit.
        """
        if not self.adb:
            return [{"category": "error", "message": "ADB not available"}]
            
        def emit(type_str, payload, level="info"):
            if on_signal:
                on_signal({"type": type_str, "payload": payload, "level": level})

        emit("SYSTEM", "AEGIS_DIAGNOSTIC_ENV_INITIALIZED")
        findings = []
        device = None
        logcat_stream = None
        stop_event = threading.Event()
        logcat_findings = []

        try:
            device = self.adb.device(serial=serial)
            
            # 1. Start Logcat Sentinel in background
            sentinel = LogcatSentinel(package_name)
            emit("SYSTEM", "LOGCAT_SENTINEL_ACTIVE")
            
            # Open stream in main thread to avoid race conditions with cleanup
            try:
                logcat_stream = device.shell("logcat -v time", stream=True)
            except Exception as e:
                logger.error(f"Failed to start logcat stream: {e}")
            
            def monitor_logcat(stream):
                try:
                    if not stream:
                        return
                    for line in stream:
                        if stop_event.is_set():
                            break
                        hit = sentinel.process_line(line)
                        if hit:
                            logcat_findings.append(hit)
                            emit("LOGCAT", f"{hit['type']}: {hit['payload']}")
                except Exception as e:
                    logger.debug(f"Logcat monitor thread failed: {e}")
                finally:
                    if stream:
                        try:
                            stream.close()
                        except Exception:
                            pass

            logcat_thread = threading.Thread(target=monitor_logcat, args=(logcat_stream,), daemon=True)
            logcat_thread.start()

            # 2. Run synchronous checks
            # 2.1 Environment Integrity
            try:
                emit("SYSTEM", "ENVIRONMENT_CHECK_START")
                integrity = EnvironmentIntegrity(device, package_name)
                res = integrity.check_all()
                findings.extend(res)
                for f in res: emit("ARTIFACTS", f"Env: {f['type']}")
                emit("SYSTEM", "ENVIRONMENT_CHECK_COMPLETE")
            except Exception as e:
                logger.error(f"EnvironmentIntegrity failed: {e}")

            # 2.2 System Artifacts
            try:
                emit("SYSTEM", "ARTIFACT_SCAN_START")
                artifacts = SystemArtifacts(device)
                res = artifacts.check_clipboard()
                findings.extend(res)
                for f in res: emit("ARTIFACTS", f"Artifact: {f['type']}")
                emit("SYSTEM", "ARTIFACT_SCAN_COMPLETE")
            except Exception as e:
                logger.error(f"SystemArtifacts failed: {e}")

            # 2.3 Sandbox Exploration (Root/Non-Root aware)
            try:
                emit("SYSTEM", "SANDBOX_EXPLORATION_START")
                explorer = SandboxExplorer(device, package_name)
                res = explorer.explore()
                findings.extend(res)
                emit("SYSTEM", "SANDBOX_EXPLORATION_COMPLETE")
            except Exception as e:
                logger.error(f"SandboxExplorer failed: {e}")

            # 2.4 Memory Forensics (Dump & Scour)
            try:
                emit("SYSTEM", "MEMORY_FORENSICS_START")
                scour = MemoryScour(device, package_name)
                res = scour.scour_memory()
                findings.extend(res)
                for f in res: emit("MEMORY", f"Memory: {f['type']}")
                emit("SYSTEM", "MEMORY_FORENSICS_COMPLETE")
            except Exception as e:
                logger.error(f"MemoryScour failed: {e}")

            # 2.5 Dynamic Code Loading Check (DEX Forensics)
            try:
                emit("SYSTEM", "DEX_FORENSICS_START")
                dex_checker = DexForensics(device, package_name)
                res = dex_checker.check_dynamic_loading()
                findings.extend(res)
                for f in res: emit("ARTIFACTS", f"DEX: {f['type']}")
                emit("SYSTEM", "DEX_FORENSICS_COMPLETE")
            except Exception as e:
                logger.error(f"DexForensics failed: {e}")

            # 3. Give Logcat some time to catch events during interactions
            time.sleep(1) 
            emit("SYSTEM", "AEGIS_DIAGNOSTIC_TEARDOWN")
            
            return findings
        except Exception as e:
            logger.error(f"Audit failed for {serial}: {e}")
            return findings
        finally:
            # Guarantee cleanup
            stop_event.set()
            if logcat_stream:
                try:
                    logcat_stream.close()
                except Exception:
                    pass
            
            # Aggregate logcat hits (even if audit failed mid-way)
            if logcat_findings:
                seen = set()
                for hit in logcat_findings:
                    if hit["payload"] not in seen:
                        findings.append(hit)
                        seen.add(hit["payload"])

    async def extract_backup(self, serial: str, package: str, output_dir: str) -> dict:
        """
        Extract and analyse an ADB backup for *package* on device *serial*.

        Steps
        -----
        1. ``adb backup -noapk <package>`` → ``<output_dir>/backup.ab``
        2. Convert the .ab (Android Backup) container to .tar using the
           known format: skip the 24-byte plaintext header, then inflate
           the remaining zlib stream.
        3. Walk the extracted tar and flag:
           - SQLite databases (.db, .sqlite)
           - Shared-preferences XMLs (shared_prefs/**/*.xml)
           - Credential files (*.key, *.pem, *.pfx, *.p12, *.jks, credentials*)
           - Token/auth files (token*, auth*, session*, secret*)

        Returns
        -------
        {
            "files_found":      <int>,
            "sensitive_files":  [<relative-path>, ...],
            "databases":        [<relative-path>, ...],
            "shared_prefs":     [<relative-path>, ...],
            "credential_files": [<relative-path>, ...],
            "backup_path":      <str>,
            "tar_path":         <str>,
            "error":            <str|None>,
        }
        """
        import asyncio
        import io
        import struct
        import subprocess as _sp
        import tarfile
        import zlib

        os.makedirs(output_dir, exist_ok=True)
        backup_path = os.path.join(output_dir, "backup.ab")
        tar_path    = os.path.join(output_dir, "backup.tar")

        result: dict = {
            "files_found":      0,
            "sensitive_files":  [],
            "databases":        [],
            "shared_prefs":     [],
            "credential_files": [],
            "backup_path":      backup_path,
            "tar_path":         tar_path,
            "error":            None,
        }

        # ── 1. Trigger ADB backup ──────────────────────────────────────────────
        logger.info("extract_backup: triggering adb backup package=%s serial=%s", package, serial)
        try:
            # -noapk: skip the APK itself; -f: output file
            cmd = ["adb", "-s", serial, "backup", "-noapk", package, "-f", backup_path]
            proc = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            try:
                _, stderr = await asyncio.wait_for(proc.communicate(), timeout=60)
            except asyncio.TimeoutError:
                proc.kill()
                result["error"] = "adb backup timed out after 60 s"
                logger.error("extract_backup: %s", result["error"])
                return result
            if not os.path.exists(backup_path) or os.path.getsize(backup_path) < 25:
                result["error"] = f"backup.ab absent or empty (adb stderr: {stderr.decode()[:200]})"
                logger.error("extract_backup: %s", result["error"])
                return result
        except Exception as exc:
            result["error"] = f"adb backup failed: {exc}"
            logger.error("extract_backup: %s", result["error"])
            return result

        # ── 2. Convert .ab → .tar (skip 24-byte header + zlib inflate) ─────────
        # Android Backup format:
        #   ANDROID BACKUP\n  (15 bytes)
        #   <version>\n       (2 bytes, e.g. "5\n")
        #   <compressed>\n    (2 bytes, "1\n" or "0\n")
        #   <encryption>\n    (5 bytes, "none\n")
        # Total plain-text header = variable; we scan for the first zlib magic (0x78).
        try:
            with open(backup_path, "rb") as f:
                raw = f.read()

            # Find zlib stream start: 0x789C, 0x7801, 0x78DA, or 0x785E
            zlib_offset = -1
            for i in range(min(64, len(raw) - 1)):
                if raw[i] == 0x78 and raw[i + 1] in (0x01, 0x5E, 0x9C, 0xDA):
                    zlib_offset = i
                    break

            if zlib_offset == -1:
                # Possibly uncompressed: try direct tar extraction from byte 24
                tar_data = raw[24:]
            else:
                tar_data = zlib.decompress(raw[zlib_offset:])

            with open(tar_path, "wb") as f:
                f.write(tar_data)

            logger.info(
                "extract_backup: inflated %d bytes → tar (%d bytes)",
                len(raw), len(tar_data),
            )
        except Exception as exc:
            result["error"] = f".ab → .tar conversion failed: {exc}"
            logger.error("extract_backup: %s", result["error"])
            return result

        # ── 3. Inspect extracted tar ───────────────────────────────────────────
        _DB_EXTS        = {".db", ".sqlite", ".sqlite3", ".db3"}
        _CRED_PATTERNS  = re.compile(
            r"(\.key|\.pem|\.pfx|\.p12|\.jks|credential|secret|token|auth|session)",
            re.IGNORECASE,
        )
        _SHAREDPREF_RE  = re.compile(r"shared_prefs/.*\.xml$", re.IGNORECASE)

        try:
            with tarfile.open(tar_path, "r:*") as tf:
                members = tf.getmembers()
                result["files_found"] = len(members)

                for member in members:
                    name = member.name
                    ext  = os.path.splitext(name)[1].lower()

                    if ext in _DB_EXTS:
                        result["databases"].append(name)
                        result["sensitive_files"].append(name)

                    elif _SHAREDPREF_RE.search(name):
                        result["shared_prefs"].append(name)
                        result["sensitive_files"].append(name)

                    elif _CRED_PATTERNS.search(name):
                        result["credential_files"].append(name)
                        result["sensitive_files"].append(name)

                # De-duplicate sensitive_files while preserving order
                seen_set: set = set()
                deduped = []
                for p in result["sensitive_files"]:
                    if p not in seen_set:
                        seen_set.add(p)
                        deduped.append(p)
                result["sensitive_files"] = deduped

        except tarfile.TarError as exc:
            result["error"] = f"tar extraction failed: {exc}"
            logger.error("extract_backup: %s", result["error"])

        logger.info(
            "extract_backup: done files=%d sensitive=%d dbs=%d",
            result["files_found"],
            len(result["sensitive_files"]),
            len(result["databases"]),
        )
        return result

class LogcatSentinel:
    """
    Monitors logcat for sensitive data leaks with advanced redaction.
    """
    def __init__(self, package_name: str):
        self.package_name = package_name
        self.patterns = [
            (re.compile(r"email[:= ]+(['\"]?)([\w\.-]+@[\w\.-]+\.\w+)\1", re.I), "pii_leak"),
            (re.compile(r"bearer [a-zA-Z0-9\._\-]{10,}", re.I), "token_leak"),
            (re.compile(r"password[:= ]+(['\"]?)([^\s'\"&]{4,})\1", re.I), "credential_leak"),
            (re.compile(r"/data/user/0/[a-zA-Z0-9\._\-]+", re.I), "path_leak"),
            # Telecom specific PII
            (re.compile(r"(msisdn|phone)[:= ]+(['\"]?)([0-9+]{10,15})\2", re.I), "pii_leak_msisdn"),
            (re.compile(r"(imei|imsi|iccid)[:= ]+(['\"]?)([0-9]{15,20})\2", re.I), "pii_leak_hardware_id"),
            (re.compile(r"customer_id[:= ]+(['\"]?)([a-zA-Z0-9\-_]{5,})\1", re.I), "pii_leak_customer_id"),
        ]

    def process_line(self, line: str) -> Optional[Dict]:
        for pattern, category in self.patterns:
            match = pattern.search(line)
            if match:
                payload = match.group(0)
                # Advanced Redaction
                if category == "pii_leak" and "@" in payload:
                    # Match only the email part for cleaner redaction
                    email_match = re.search(r"[\w\.-]+@[\w\.-]+\.\w+", payload)
                    if email_match:
                        email = email_match.group(0)
                        parts = email.split("@")
                        local = parts[0]
                        redacted = (local[:2] + "..." + local[-1:] if len(local) > 3 else "...") + "@" + parts[1]
                        payload = payload.replace(email, redacted)
                elif category in ["token_leak", "credential_leak"]:
                    payload = payload[:15] + "...[REDACTED]"
                
                return {
                    "category": "logcat_leak",
                    "type": category,
                    "payload": payload,
                    "evidence": f"Detected in logcat: {payload}"
                }
        return None

class SandboxExplorer:
    """
    Handles sandbox forensics. Hardened for large directories.
    """
    def __init__(self, device: adbutils.AdbDevice, package_name: str, timeout: int = 30):
        self.device = device
        self.package_name = package_name
        self.timeout = timeout

    def explore(self) -> List[Dict]:
        findings = []
        is_rooted = self.device.shell("which su").strip() != ""
        
        if is_rooted:
            path = f"/data/data/{self.package_name}"
            # Use su -c for root access on hardened devices
            inner_cmd = f"timeout {self.timeout} ls -R {shlex.quote(path)} | head -n 1000"
            output = self.device.shell(f"su -c {shlex.quote(inner_cmd)}")
            
            # --- PATCH: Automatic DB Extraction ---
            db_path = f"{path}/databases/instabug.db"
            local_dest = f"data_local/extracted_dbs/{self.package_name}_instabug.db"
            os.makedirs("data_local/extracted_dbs", exist_ok=True)
            
            # Use cat via su to bypass pull restrictions
            self.device.shell(f"su -c 'cat {db_path} > /data/local/tmp/dump.db'")
            self.device.sync.pull("/data/local/tmp/dump.db", local_dest)
            
            findings.append({
                "category": "sandbox_access",
                "method": "root_ls_and_cat",
                "severity": "HIGH",
                "description": f"Full sandbox access achieved. Database extracted to {local_dest}",
                "data": output
            })
        else:
            findings.append({
                "category": "sandbox_access",
                "method": "adb_backup",
                "severity": "MEDIUM",
                "status": "pending_confirmation",
                "description": "Device not rooted. Manual ADB backup required."
            })
        return findings

class EnvironmentIntegrity:
    def __init__(self, device: adbutils.AdbDevice, package_name: str):
        self.device = device
        self.package_name = package_name

    def check_all(self) -> List[Dict]:
        findings = []
        # Global debuggable
        if self.device.shell("getprop ro.debuggable").strip() == "1":
            findings.append({"category": "env_integrity", "type": "global_debug", "severity": "HIGH", "description": "System-wide debugging enabled."})
        
        # App backup allowed
        pkg_info = self.device.shell(f"dumpsys package {shlex.quote(self.package_name)}")
        if "allowBackup=true" in pkg_info:
            findings.append({"category": "env_integrity", "type": "backup_allowed", "severity": "MEDIUM", "description": "App allows data backup."})
            
        return findings

class SystemArtifacts:
    def __init__(self, device: adbutils.AdbDevice):
        self.device = device

    def check_clipboard(self) -> List[Dict]:
        # Check if we can get anything from clipboard service
        clip = self.device.shell("service call clipboard 2 s16 com.android.shell")
        if clip and "Result: Parcel" in clip and len(clip) > 50:
            return [{
                "category": "system_artifact",
                "type": "clipboard_leak",
                "severity": "MEDIUM",
                "description": "Sensitive data detected in global clipboard."
            }]
        return []

class DexForensics:
    """
    Monitors for dynamic code loading (DEX) and suspicious bytecode activity.
    """
    def __init__(self, device: adbutils.AdbDevice, package_name: str):
        self.device = device
        self.package_name = package_name

    def check_dynamic_loading(self) -> List[Dict]:
        findings = []
        try:
            cmd = f"find /data/data/{shlex.quote(self.package_name)} -name '*.dex' -o -name '*.jar'"
            out = self.device.shell(cmd)
            # Filter out permission denied lines and keep only actual file paths
            files = [
                l for l in out.strip().splitlines()
                if l.strip() and "Permission denied" not in l and "No such file" not in l
            ]
            if files:
                findings.append({
                    "category": "dynamic_code",
                    "type": "runtime_bytecode_found",
                    "severity": "MEDIUM",
                    "description": f"Found {len(files)} dynamic bytecode files (.dex/.jar) in sandbox.",
                    "data": "\n".join(files)
                })
        except Exception:
            pass
        return findings

class MemoryScour:
    """
    Advanced memory forensics: Dump and Scour.
    """
    def __init__(self, device: adbutils.AdbDevice, package_name: str):
        self.device = device
        self.package_name = package_name

    def scour_memory(self) -> List[Dict]:
        findings = []
        try:
            pid = self.device.shell(f"pidof {shlex.quote(self.package_name)}").strip()
            if not pid:
                return []
            
            # Just initiate and return status for now as strings-on-device might be missing
            dump_path = f"/data/local/tmp/{self.package_name}.hprof"
            self.device.shell(f"am dumpheap {pid} {dump_path}")
            
            findings.append({
                "category": "memory_forensics",
                "type": "heap_dump_initiated",
                "severity": "INFO",
                "path": dump_path,
                "description": f"Heap dump initiated for {self.package_name}."
            })
        except Exception:
            pass
        return findings

class PackageHarvester:
    """
    Exfiltrates installed packages from Android devices.
    """
    def __init__(self, device: adbutils.AdbDevice):
        self.device = device

    def list_packages(self) -> List[Dict[str, str]]:
        """
        List all installed packages with their remote paths.
        Runs 'pm list packages -f'
        """
        packages = []
        try:
            # pm list packages -f output format: package:/path/to/base.apk=com.example.app
            output = self.device.shell("pm list packages -f")
            for line in output.splitlines():
                line = line.strip()
                if line.startswith("package:"):
                    line = line.replace("package:", "")
                    if "=" in line:
                        path, name = line.rsplit("=", 1)
                        packages.append({"name": name, "path": path})
        except Exception as e:
            logger.error(f"Failed to list packages: {e}")
        return packages

    def pull_package(self, package_name: str, dest_path: str) -> bool:
        """
        Pulls the APK for a given package name.
        Uses a robust subprocess fallback for large files.
        """
        try:
            # Find the path first
            path_info = self.device.shell(f"pm path {shlex.quote(package_name)}").strip()
            if not path_info.startswith("package:"):
                logger.error(f"Could not find path for package {package_name}")
                return False

            # Take only the first line in case of multiple paths (split APKs not yet fully supported as unified)
            remote_path = path_info.splitlines()[0].replace("package:", "").strip()

            logger.info(f"Exfiltrating {package_name} from {remote_path} to {dest_path}")

            # Fallback to subprocess for better stability on large pulls (like Telekom app ~400MB)
            import subprocess
            cmd = ["adb", "-s", self.device.serial, "pull", remote_path, dest_path]
            try:
                # 60 second timeout for large APKs
                res = subprocess.run(cmd, capture_output=True, text=True, timeout=120)
                if res.returncode == 0 and os.path.exists(dest_path):
                    return True
            except subprocess.TimeoutExpired:
                logger.error(f"Pull timed out for {package_name}")
            except Exception as e:
                logger.error(f"Subprocess pull failed: {e}")

            # Native adbutils fallback
            self.device.pull(remote_path, dest_path)
            return os.path.exists(dest_path)
        except Exception as e:
            logger.error(f"Failed to pull package {package_name}: {e}")
            return False
