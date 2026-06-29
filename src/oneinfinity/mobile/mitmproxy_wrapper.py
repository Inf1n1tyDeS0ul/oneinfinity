"""
mitmproxy Wrapper — One&Infinity
=================================
Manages a background mitmproxy instance for live traffic interception, 
AI-driven analysis, and automated payload injection.
"""

import os
import json
import logging
import subprocess
import threading
import time
from typing import Optional, Dict, List, Any

from oneinfinity.scan.traffic_capture_engine import traffic_capture_engine

log = logging.getLogger("oneinfinity.mobile.mitm")

class MitmproxyWrapper:
    def __init__(self, port: int = 8082):
        self.port = port
        self.proc = None
        self.addon_path = "/tmp/oneinfinity_mitm_addon.py"
        self.log_file = "/tmp/oneinfinity_live_traffic.jsonl"
        self._tail_thread = None
        self._stop_event = threading.Event()

    def _generate_addon(self, mode: str = "analyze"):
        """Generates a dynamic python addon for mitmproxy."""
        content = f'''
import json
import time
from mitmproxy import http

# One&Infinity Live Addon
def response(flow: http.HTTPFlow) -> None:
    # 1. Log flow for AI analysis
    try:
        req_body = flow.request.text or ""
    except Exception:
        req_body = ""

    try:
        resp_body = flow.response.text or ""
    except Exception:
        resp_body = ""

    entry = {{
        "method": flow.request.method,
        "url": flow.request.pretty_url,
        "headers": dict(flow.request.headers),
        "body": req_body,
        "response_status": flow.response.status_code,
        "response_headers": dict(flow.response.headers),
        "response_body": resp_body,
        "source": "mobile_live_proxy",
        "timestamp": time.time()
    }}

    # Save to shared file for the background tail thread
    with open("{self.log_file}", "a") as f:
        f.write(json.dumps(entry) + "\\n")
'''
        with open(self.addon_path, "w") as f:
            f.write(content)

    def _tail_log_to_db(self):
        """Background thread to sync file log into PostgreSQL."""
        log.info("Mitmproxy Bridge: Starting tail thread...")
        last_pos = 0
        while not self._stop_event.is_set():
            if os.path.exists(self.log_file):
                with open(self.log_file, "r") as f:
                    f.seek(last_pos)
                    for line in f:
                        try:
                            data = json.loads(line)
                            traffic_capture_engine.capture(
                                method=data["method"],
                                url=data["url"],
                                headers=data["headers"],
                                body=data["body"],
                                response_status=data["response_status"],
                                response_headers=data["response_headers"],
                                response_body=data["response_body"],
                                source=data["source"]
                            )
                        except Exception as e:
                            log.error(f"Mitmproxy Bridge error: {e}")
                    last_pos = f.tell()
            time.sleep(1)

    def setup_device(self, device_id: str):
        """Automatically configure the device to use this proxy."""
        if not device_id:
            return
        log.info(f"Mitmproxy: Configuring device {device_id} proxy...")
        try:
            # 1. Reverse port forward (Device localhost:8082 -> Host localhost:8082)
            subprocess.run(["adb", "-s", device_id, "reverse", "tcp:8082", "tcp:8082"], check=True)
            # 2. Set global HTTP proxy to localhost:8082
            subprocess.run(["adb", "-s", device_id, "shell", "settings", "put", "global", "http_proxy", "localhost:8082"], check=True)
            log.info("Mitmproxy: Device proxy configured successfully.")
        except Exception as e:
            log.error(f"Mitmproxy: Failed to configure device proxy: {e}")

    def cleanup_device(self, device_id: str):
        """Remove proxy settings from the device."""
        if not device_id:
            return
        log.info(f"Mitmproxy: Cleaning up device {device_id} proxy...")
        try:
            subprocess.run(["adb", "-s", device_id, "shell", "settings", "put", "global", "http_proxy", ":0"], check=True)
            subprocess.run(["adb", "-s", device_id, "reverse", "--remove", "tcp:8082"], check=True)
        except Exception:
            pass

    def start(self, mode: str = "analyze", device_id: str = ""):
        """Start mitmproxy in the background."""
        self._generate_addon(mode)
        log.info(f"Starting mitmproxy on port {self.port} (mode: {mode})...")
        
        # Clear previous traffic
        if os.path.exists(self.log_file):
            os.remove(self.log_file)

        # Setup device if ID provided
        if device_id:
            self.setup_device(device_id)

        cmd = ["mitmdump", "-p", str(self.port), "-s", self.addon_path, "--set", "block_global=false"]
        self.proc = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        
        # Start the sync thread
        self._stop_event.clear()
        self._tail_thread = threading.Thread(target=self._tail_log_to_db, daemon=True)
        self._tail_thread.start()

    def stop(self, device_id: str = ""):
        """Stop the background proxy."""
        self._stop_event.set()
        if device_id:
            self.cleanup_device(device_id)
        if self.proc:
            self.proc.terminate()
            log.info("mitmproxy stopped.")

    def get_live_traffic(self) -> List[Dict]:
        """Proxy method to fetch from DB instead of file now."""
        return [r.to_json() for r in traffic_capture_engine.list(source="mobile_live_proxy", limit=50)]

# Singleton
mitm_proxy = MitmproxyWrapper()
