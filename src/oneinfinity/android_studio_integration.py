"""
Android Studio / Emulator Integration — launch AVD emulator, install APK,
attach Frida instrumentation, manage debug sessions.
"""

import os
import re
import shutil
import subprocess
import time
import logging
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional

from oneinfinity.path_manager import raw_dir

logger = logging.getLogger(__name__)

ANDROID_HOME_CANDIDATES = [
    os.environ.get("ANDROID_HOME", ""),
    os.environ.get("ANDROID_SDK_ROOT", ""),
    os.path.expanduser("~/Android/Sdk"),
    os.path.expanduser("~/android-sdk"),
    "/opt/android-sdk",
    "/usr/local/android-sdk",
]


def _find_android_home() -> Optional[str]:
    for candidate in ANDROID_HOME_CANDIDATES:
        if candidate and os.path.isdir(candidate):
            return candidate
    return None


def _find_tool(*names) -> Optional[str]:
    """Find a tool by name in PATH, then in Android SDK directories."""
    for name in names:
        path = shutil.which(name)
        if path:
            return path
    android_home = _find_android_home()
    if android_home:
        search_dirs = [
            os.path.join(android_home, "platform-tools"),
            os.path.join(android_home, "tools"),
            os.path.join(android_home, "tools", "bin"),
            os.path.join(android_home, "emulator"),
        ]
        for d in search_dirs:
            for name in names:
                full = os.path.join(d, name)
                if os.path.isfile(full) and os.access(full, os.X_OK):
                    return full
    return None


@dataclass
class EmulatorSession:
    avd_name: str
    device_id: str = ""
    pid: int = 0
    process: object = None
    running: bool = False

    def stop(self):
        if self.process:
            try:
                self.process.terminate()
            except Exception:
                pass
        self.running = False


@dataclass
class AndroidStudioResult:
    success: bool = False
    device_id: str = ""
    avd_name: str = ""
    apk_installed: bool = False
    frida_server_running: bool = False
    frida_pid: int = 0
    errors: list = field(default_factory=list)
    notes: list = field(default_factory=list)

    def to_dict(self):
        return {
            "success": self.success,
            "device_id": self.device_id,
            "avd_name": self.avd_name,
            "apk_installed": self.apk_installed,
            "frida_server_running": self.frida_server_running,
            "frida_pid": self.frida_pid,
            "errors": self.errors,
            "notes": self.notes,
        }


class AndroidStudioIntegration:
    """
    Manages Android emulator lifecycle, APK installation, and Frida server setup.
    All methods gracefully handle missing tools.
    """

    def __init__(self):
        self.adb = _find_tool("adb")
        self.emulator = _find_tool("emulator")
        self.avdmanager = _find_tool("avdmanager")
        self.frida_server_path = None
        self._active_session: Optional[EmulatorSession] = None

    # ── AVD Management ────────────────────────────────────────────────────────

    def list_avds(self) -> list:
        """List available Android Virtual Devices."""
        if not self.emulator:
            return []
        try:
            r = subprocess.run(
                [self.emulator, "-list-avds"],
                capture_output=True, text=True, timeout=15
            )
            return [line.strip() for line in r.stdout.strip().split("\n") if line.strip()]
        except Exception as e:
            logger.warning(f"list_avds error: {e}")
            return []

    def create_avd(self, name: str, package: str = "system-images;android-30;google_apis;x86_64",
                   device: str = "pixel_4") -> bool:
        """Create an AVD. Requires sdkmanager to have the system image installed."""
        if not self.avdmanager:
            logger.warning("avdmanager not found")
            return False
        try:
            r = subprocess.run(
                ["bash", "-c", f"echo no | {self.avdmanager} create avd -n {name} -k '{package}' -d {device} --force"],
                capture_output=True, text=True, timeout=120
            )
            return r.returncode == 0
        except Exception as e:
            logger.warning(f"create_avd error: {e}")
            return False

    # ── Emulator Launch ───────────────────────────────────────────────────────

    def launch_emulator(self, avd_name: str = None, wait: bool = True,
                        timeout: int = 120) -> Optional[EmulatorSession]:
        """Launch an Android emulator. If avd_name is None, picks first available."""
        if not self.emulator or not self.adb:
            logger.warning("emulator or adb not found — cannot launch emulator")
            return None

        if avd_name is None:
            avds = self.list_avds()
            if not avds:
                logger.warning("No AVDs found")
                return None
            avd_name = avds[0]

        session = EmulatorSession(avd_name=avd_name)

        try:
            proc = subprocess.Popen(
                [self.emulator, "-avd", avd_name, "-no-snapshot-save",
                 "-no-audio", "-no-window", "-gpu", "swiftshader_indirect"],
                stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL
            )
            session.process = proc
            session.pid = proc.pid
        except Exception as e:
            logger.error(f"Emulator launch failed: {e}")
            return None

        if wait:
            device_id = self._wait_for_boot(timeout=timeout)
            if device_id:
                session.device_id = device_id
                session.running = True
                self._active_session = session
            else:
                session.process.terminate()
                return None
        else:
            session.running = True
            self._active_session = session

        return session

    def _wait_for_boot(self, timeout: int = 120) -> Optional[str]:
        """Wait for emulator to finish booting, return device_id or None."""
        deadline = time.time() + timeout
        while time.time() < deadline:
            try:
                r = subprocess.run(
                    [self.adb, "devices"], capture_output=True, text=True, timeout=5
                )
                for line in r.stdout.split("\n")[1:]:
                    if "\tdevice" in line:
                        device_id = line.split("\t")[0].strip()
                        if "emulator" in device_id:
                            # Check boot complete
                            br = subprocess.run(
                                [self.adb, "-s", device_id, "shell",
                                 "getprop", "sys.boot_completed"],
                                capture_output=True, text=True, timeout=5
                            )
                            if br.stdout.strip() == "1":
                                logger.info(f"Emulator booted: {device_id}")
                                return device_id
            except Exception:
                pass
            time.sleep(5)
        return None

    def stop_emulator(self, session: EmulatorSession = None):
        session = session or self._active_session
        if not session:
            return
        if self.adb and session.device_id:
            try:
                subprocess.run(
                    [self.adb, "-s", session.device_id, "emu", "kill"],
                    capture_output=True, timeout=10
                )
            except Exception:
                pass
        session.stop()

    # ── APK Install ───────────────────────────────────────────────────────────

    def install_apk(self, apk_path: str, device_id: str = None) -> bool:
        if not self.adb:
            return False
        device_id = device_id or self._get_connected_device()
        if not device_id:
            return False
        try:
            cmd = [self.adb, "-s", device_id, "install", "-r", "-g", apk_path]
            r = subprocess.run(cmd, capture_output=True, text=True, timeout=120)
            if r.returncode == 0 and "Success" in r.stdout:
                logger.info(f"APK installed: {apk_path}")
                return True
            logger.warning(f"APK install failed: {r.stderr}")
            return False
        except Exception as e:
            logger.error(f"install_apk error: {e}")
            return False

    def uninstall_package(self, package: str, device_id: str = None) -> bool:
        if not self.adb:
            return False
        device_id = device_id or self._get_connected_device()
        if not device_id:
            return False
        try:
            r = subprocess.run(
                [self.adb, "-s", device_id, "uninstall", package],
                capture_output=True, text=True, timeout=30
            )
            return r.returncode == 0
        except Exception:
            return False

    # ── Frida Server ──────────────────────────────────────────────────────────

    def setup_frida_server(self, device_id: str = None, arch: str = "x86_64") -> bool:
        """Download and push frida-server to the emulator."""
        device_id = device_id or self._get_connected_device()
        if not device_id or not self.adb:
            return False

        # Check if frida-server already running
        if self._check_frida_server(device_id):
            logger.info("Frida server already running")
            return True

        # Try to find local frida-server
        frida_server_local = self._find_local_frida_server(arch)
        if not frida_server_local:
            logger.warning("frida-server binary not found locally — cannot set up Frida on device")
            return False

        try:
            # Push frida-server
            subprocess.run(
                [self.adb, "-s", device_id, "push", frida_server_local, "/data/local/tmp/frida-server"],
                capture_output=True, timeout=60
            )
            # Make executable
            subprocess.run(
                [self.adb, "-s", device_id, "shell", "chmod", "755", "/data/local/tmp/frida-server"],
                capture_output=True, timeout=10
            )
            # Start frida-server in background
            subprocess.Popen(
                [self.adb, "-s", device_id, "shell", "/data/local/tmp/frida-server", "&"],
                stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL
            )
            time.sleep(2)
            return self._check_frida_server(device_id)
        except Exception as e:
            logger.error(f"Frida server setup error: {e}")
            return False

    def _check_frida_server(self, device_id: str) -> bool:
        try:
            r = subprocess.run(
                [self.adb, "-s", device_id, "shell", "ps", "-A"],
                capture_output=True, text=True, timeout=10
            )
            return "frida-server" in r.stdout
        except Exception:
            return False

    def _find_local_frida_server(self, arch: str) -> Optional[str]:
        tools_dir = raw_dir() / "tools"
        candidates = [
            f"frida-server-{arch}",
            "frida-server",
            str(tools_dir / f"frida-server-{arch}"),
            str(tools_dir / "frida-server"),
        ]
        for c in candidates:
            if os.path.isfile(c) and os.access(c, os.X_OK):
                return c
        return None

    # ── Debug Session ─────────────────────────────────────────────────────────

    def start_debug_session(self, package: str, device_id: str = None,
                             result: AndroidStudioResult = None) -> AndroidStudioResult:
        """Full setup: ensure device, install frida-server, verify app is running."""
        if result is None:
            result = AndroidStudioResult()

        device_id = device_id or self._get_connected_device()
        if not device_id:
            result.errors.append("No device connected")
            return result

        result.device_id = device_id

        # Frida server
        frida_ok = self.setup_frida_server(device_id)
        result.frida_server_running = frida_ok
        if not frida_ok:
            result.notes.append("Frida server not available — some dynamic tests will be skipped")

        # Get frida PID
        if frida_ok:
            try:
                r = subprocess.run(
                    [self.adb, "-s", device_id, "shell", "ps", "-A"],
                    capture_output=True, text=True, timeout=10
                )
                for line in r.stdout.split("\n"):
                    if "frida-server" in line:
                        parts = line.split()
                        if len(parts) > 1:
                            try:
                                result.frida_pid = int(parts[1])
                            except ValueError:
                                pass

            except Exception:
                pass

        result.success = bool(device_id)
        return result

    def forward_port(self, local_port: int, remote_port: int, device_id: str = None) -> bool:
        """Forward a device port to localhost (e.g., for Burp proxy)."""
        if not self.adb:
            return False
        device_id = device_id or self._get_connected_device()
        if not device_id:
            return False
        try:
            r = subprocess.run(
                [self.adb, "-s", device_id, "reverse",
                 f"tcp:{remote_port}", f"tcp:{local_port}"],
                capture_output=True, timeout=10
            )
            return r.returncode == 0
        except Exception:
            return False

    def install_burp_cert(self, cert_path: str, device_id: str = None) -> bool:
        """Install Burp/custom CA cert as system trusted cert on rooted emulator."""
        if not self.adb:
            return False
        device_id = device_id or self._get_connected_device()
        if not device_id or not os.path.exists(cert_path):
            return False
        try:
            # Compute cert hash
            r = subprocess.run(
                ["openssl", "x509", "-inform", "DER", "-subject_hash_old",
                 "-in", cert_path],
                capture_output=True, text=True, timeout=10
            )
            cert_hash = r.stdout.split("\n")[0].strip()
            cert_name = f"{cert_hash}.0"

            subprocess.run(
                [self.adb, "-s", device_id, "remount"], capture_output=True, timeout=10
            )
            subprocess.run(
                [self.adb, "-s", device_id, "push", cert_path,
                 f"/system/etc/security/cacerts/{cert_name}"],
                capture_output=True, timeout=15
            )
            subprocess.run(
                [self.adb, "-s", device_id, "shell", "chmod", "644",
                 f"/system/etc/security/cacerts/{cert_name}"],
                capture_output=True, timeout=10
            )
            return True
        except Exception as e:
            logger.warning(f"Cert install error: {e}")
            return False

    def set_proxy(self, host: str, port: int, device_id: str = None) -> bool:
        """Configure system-wide HTTP proxy on the device."""
        if not self.adb:
            return False
        device_id = device_id or self._get_connected_device()
        if not device_id:
            return False
        try:
            r = subprocess.run(
                [self.adb, "-s", device_id, "shell", "settings", "put",
                 "global", "http_proxy", f"{host}:{port}"],
                capture_output=True, timeout=10
            )
            return r.returncode == 0
        except Exception:
            return False

    def clear_proxy(self, device_id: str = None) -> bool:
        if not self.adb:
            return False
        device_id = device_id or self._get_connected_device()
        if not device_id:
            return False
        try:
            subprocess.run(
                [self.adb, "-s", device_id, "shell", "settings", "put",
                 "global", "http_proxy", ":0"],
                capture_output=True, timeout=10
            )
            return True
        except Exception:
            return False

    # ── Helpers ───────────────────────────────────────────────────────────────

    def _get_connected_device(self) -> Optional[str]:
        if not self.adb:
            return None
        try:
            r = subprocess.run(
                [self.adb, "devices"], capture_output=True, text=True, timeout=5
            )
            for line in r.stdout.split("\n")[1:]:
                if "\tdevice" in line:
                    return line.split("\t")[0].strip()
        except Exception:
            pass
        return None

    def get_device_info(self, device_id: str = None) -> dict:
        if not self.adb:
            return {}
        device_id = device_id or self._get_connected_device()
        if not device_id:
            return {}
        props = {}
        try:
            r = subprocess.run(
                [self.adb, "-s", device_id, "shell", "getprop"],
                capture_output=True, text=True, timeout=10
            )
            for m in re.finditer(r'\[([^\]]+)\]:\s*\[([^\]]*)\]', r.stdout):
                props[m.group(1)] = m.group(2)
        except Exception:
            pass
        return {
            "device_id": device_id,
            "android_version": props.get("ro.build.version.release", ""),
            "sdk_version": props.get("ro.build.version.sdk", ""),
            "model": props.get("ro.product.model", ""),
            "manufacturer": props.get("ro.product.manufacturer", ""),
            "is_rooted": self._check_rooted(device_id),
        }

    def _check_rooted(self, device_id: str) -> bool:
        try:
            r = subprocess.run(
                [self.adb, "-s", device_id, "shell", "which", "su"],
                capture_output=True, text=True, timeout=5
            )
            return bool(r.stdout.strip())
        except Exception:
            return False


android_studio_integration = AndroidStudioIntegration()
