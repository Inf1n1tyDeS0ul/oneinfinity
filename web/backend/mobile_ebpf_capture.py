"""
Layer 3: eBPF-based 100% TLS capture via ecapture

ecapture attaches eBPF uprobes to SSL_write/SSL_read across ALL processes and
ALL SSL libraries loaded on the device — including Chrome's bundled BoringSSL,
apps with anti-Frida, and any custom TLS stack.

Architecture:
  1. Push ecapture ARM64 binary to /data/local/tmp/ecapture
  2. Run: ecapture tls -i wlan0 --keylogfile /data/local/tmp/ssl_keys.log
  3. Stream stdout (ecapture prints decrypted TLS records line by line)
  4. Simultaneously run tcpdump to capture the encrypted PCAP
  5. Periodically merge keys.log + PCAP via tshark for full HTTP/2 flows
  6. Feed all decrypted flows into mobile_traffic_store

ecapture project: https://github.com/gojue/ecapture
Required: Android 5.8+ kernel with eBPF, root access
"""

import asyncio
import os
import re
import shutil
import subprocess
import time
from typing import Dict, List, Optional

# Active eBPF capture workers
_workers: Dict[str, dict] = {}

# ecapture binary path — user must place the ARM64 binary here
ECAPTURE_LOCAL_PATH = os.path.expanduser("~/Tools/ecapture/ecapture_arm64")
# Also check the extracted directory name variant
if not os.path.exists(ECAPTURE_LOCAL_PATH):
    _alt = os.path.expanduser("~/Tools/ecapture/ecapture-v2.4.2-android-arm64/ecapture")
    if os.path.exists(_alt):
        ECAPTURE_LOCAL_PATH = _alt
ECAPTURE_DEVICE_PATH = "/data/local/tmp/ecapture"

PCAP_DEVICE_PATH = "/data/local/tmp/oi_capture.pcap"
KEYLOG_DEVICE_PATH = "/data/local/tmp/oi_ssl_keys.log"


def _get_adb_serial() -> str:
    """Get ADB serial of the first connected device."""
    try:
        r = subprocess.run(["adb", "devices"], capture_output=True, text=True, timeout=5)
        for line in r.stdout.splitlines()[1:]:
            parts = line.strip().split()
            if len(parts) >= 2 and parts[1] == "device":
                return parts[0]
    except Exception:
        pass
    return ""


def _adb(device_id: str) -> List[str]:
    # device_id is Android ID — resolve to ADB serial
    serial = _get_adb_serial()
    base = ["adb"]
    if serial:
        base += ["-s", serial]
    return base


async def push_ecapture_binary(device_id: str) -> dict:
    """Push ecapture binary to device if not already present."""
    if not os.path.exists(ECAPTURE_LOCAL_PATH):
        return {
            "success": False,
            "error": f"ecapture binary not found at {ECAPTURE_LOCAL_PATH}. "
                     f"Download from https://github.com/gojue/ecapture/releases "
                     f"(android_arm64 build) and place at {ECAPTURE_LOCAL_PATH}"
        }

    adb = _adb(device_id)
    loop = asyncio.get_event_loop()

    def _push():
        r = subprocess.run(
            adb + ["push", ECAPTURE_LOCAL_PATH, ECAPTURE_DEVICE_PATH],
            capture_output=True, text=True, timeout=30
        )
        if r.returncode != 0:
            return {"success": False, "error": r.stderr}
        subprocess.run(
            adb + ["shell", "su", "-c", f"chmod +x {ECAPTURE_DEVICE_PATH}"],
            timeout=10
        )
        return {"success": True}

    return await loop.run_in_executor(None, _push)


async def start_ebpf_capture(device_id: str, interface: str = "wlan0") -> dict:
    if device_id in _workers and _workers[device_id].get("ecapture_proc") is not None:
        p = _workers[device_id]["ecapture_proc"]
        if p.poll() is None:
            return {"status": "already_running", "device_id": device_id}

    adb = _adb(device_id)

    # Check/push ecapture binary
    check = subprocess.run(
        adb + ["shell", "su", "-c", f"ls {ECAPTURE_DEVICE_PATH}"],
        capture_output=True, text=True, timeout=10
    )
    if ECAPTURE_DEVICE_PATH not in check.stdout:
        result = await push_ecapture_binary(device_id)
        if not result.get("success"):
            return {"status": "error", "error": result.get("error")}

    # Start ecapture — streams decrypted TLS records to stdout
    ecapture_cmd = " ".join([
        ECAPTURE_DEVICE_PATH,
        "tls",
        "-m text",           # text mode = decrypted TLS payload (default)
        f"-i {interface}",
        f"--keylogfile {KEYLOG_DEVICE_PATH}",
    ])
    ecap_proc = subprocess.Popen(
        adb + ["shell", "su", "-c", ecapture_cmd],
        stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, text=True, bufsize=1
    )

    # Start tcpdump alongside for PCAP
    tcpdump_cmd = f"tcpdump -i {interface} -w {PCAP_DEVICE_PATH} -nn"
    tcpdump_proc = subprocess.Popen(
        adb + ["shell", "su", "-c", tcpdump_cmd],
        stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL
    )

    _workers[device_id] = {
        "ecapture_proc": ecap_proc,
        "tcpdump_proc": tcpdump_proc,
        "interface": interface,
        "started_at": time.time(),
        "device_id": device_id,
    }

    # Start async reader
    asyncio.create_task(_stream_ecapture(device_id, ecap_proc))
    # Start periodic PCAP+keylog merge
    asyncio.create_task(_periodic_tshark_merge(device_id))

    return {"status": "started", "device_id": device_id, "interface": interface}


async def stop_ebpf_capture(device_id: str) -> dict:
    worker = _workers.pop(device_id, None)
    if not worker:
        return {"status": "not_running", "device_id": device_id}

    for key in ("ecapture_proc", "tcpdump_proc"):
        p = worker.get(key)
        if p and p.poll() is None:
            p.terminate()

    return {"status": "stopped", "device_id": device_id}


async def get_ebpf_status(device_id: str) -> dict:
    worker = _workers.get(device_id)
    if not worker:
        return {"status": "stopped", "device_id": device_id}
    running = worker["ecapture_proc"].poll() is None
    return {
        "status": "running" if running else "stopped",
        "device_id": device_id,
        "interface": worker.get("interface"),
        "started_at": worker.get("started_at"),
    }


async def get_keylog(device_id: str) -> str:
    """Pull current SSLKEYLOGFILE from device."""
    adb = _adb(device_id)
    local_path = f"/tmp/oi_sslkeys_{device_id}.log"
    r = subprocess.run(
        adb + ["pull", KEYLOG_DEVICE_PATH, local_path],
        capture_output=True, timeout=15
    )
    if r.returncode != 0:
        return ""
    try:
        with open(local_path) as f:
            return f.read()
    except Exception:
        return ""


# ── ecapture stdout parser ────────────────────────────────────────────────────

# ecapture v2.4.2 output line format:
# INF lines: timestamp [INF] key=value key=value
#   PID:9118, Comm:NetworkService, TID:11974, FD:360, Tuple: [src]:0->[dst]:443
# SSL_write/read payload lines (with --text):
#   timestamp [INF] {plaintext data}  probe=OpenSSL
_ECAP_CONN_RE = re.compile(
    r'PID:(\d+),\s*Comm:([^,]+),\s*TID:\d+,\s*FD:\d+,\s*Tuple:\s*\[([^\]]*)\]:(\d+)->(?:\[([^\]]*)\]|([^:]+)):(\d+)',
    re.IGNORECASE
)
# Strip ANSI escape codes
_ANSI_RE = re.compile(r'\x1b\[[0-9;]*m')


def _strip_ansi(s: str) -> str:
    return _ANSI_RE.sub('', s)


async def _stream_ecapture(device_id: str, proc: subprocess.Popen):
    from .mobile_agent_api import store_traffic

    loop = asyncio.get_event_loop()
    # Track connections: (pid, fd) -> {src_ip, src_port, dst_ip, dst_port, process}
    connections: dict = {}
    # Pending plaintext buffers: (pid, fd) -> [lines]
    payload_buf: dict = {}

    try:
        while proc.poll() is None:
            raw_line = await loop.run_in_executor(None, proc.stdout.readline)
            if not raw_line:
                await asyncio.sleep(0.05)
                continue

            line = _strip_ansi(raw_line.rstrip('\n'))
            if not line:
                continue

            # Connection tuple line: extract src→dst with PID+FD key
            cm = _ECAP_CONN_RE.search(line)
            if cm:
                pid = int(cm.group(1))
                comm = cm.group(2).strip()
                src_ip = cm.group(3) or ""
                dst_ip = cm.group(5) or cm.group(6) or ""
                dst_port = int(cm.group(7))
                conn_key = (pid, dst_ip, dst_port)
                connections[conn_key] = {
                    "pid": pid,
                    "process": comm,
                    "src_ip": src_ip,
                    "dst_ip": dst_ip.replace("::ffff:", ""),
                    "dst_port": dst_port,
                    "timestamp": time.time(),
                }
                continue

            # Plaintext payload line — contains HTTP data
            # ecapture --text mode outputs TLS payload after connection tuple
            if "GET " in line or "POST " in line or "PUT " in line or \
               "DELETE " in line or "HTTP/" in line or "Host:" in line:
                # Associate with the most recent connection entry
                # Find most recent connection matching this content
                best_conn = None
                for conn in connections.values():
                    if not best_conn or conn["timestamp"] > best_conn["timestamp"]:
                        best_conn = conn
                if best_conn:
                    key = (best_conn["pid"], best_conn["dst_ip"], best_conn["dst_port"])
                    payload_buf.setdefault(key, []).append(line)

                    # Flush when we have a complete HTTP message
                    buf = payload_buf[key]
                    combined = '\n'.join(buf)
                    if '\r\n\r\n' in combined or '\n\n' in combined or len(buf) > 20:
                        await _emit_ecapture_flow(device_id, best_conn, combined)
                        payload_buf[key] = []

    except Exception as e:
        print(f"[ebpf] Stream error for {device_id}: {e}")


async def _emit_ecapture_flow(device_id: str, meta: dict, text: str):
    from .mobile_agent_api import store_traffic
    from .mobile_ssl_interceptor import _parse_http_request, _parse_http_response

    package = meta.get("process", "unknown")
    dst_ip = meta.get("dst_ip", "")
    dst_port = meta.get("dst_port", 443)

    req = _parse_http_request(text)
    if req:
        # Reconstruct full URL if only a path was found
        if req.get("url", "").startswith("/") and dst_ip:
            host = req.get("headers", {}).get("Host") or req.get("headers", {}).get("host") or f"{dst_ip}:{dst_port}"
            scheme = "https" if dst_port == 443 else "http"
            req["url"] = f"{scheme}://{host}{req['url']}"
        req["_process"] = package
        await store_traffic(
            device_id, req,
            {"status_code": 0, "headers": {}, "body": ""},
            source="ebpf", decrypted=True
        )
    elif "HTTP/" in text:
        resp = _parse_http_response(text)
        if resp:
            await store_traffic(
                device_id,
                {"method": "RESPONSE", "url": f"https://{dst_ip}:{dst_port}", "headers": {}, "body": ""},
                resp,
                source="ebpf", decrypted=True
            )
    else:
        # Connection metadata only — still valuable for traffic map
        if dst_ip and dst_port:
            await store_traffic(
                device_id,
                {"method": "CONNECT", "url": f"https://{dst_ip}:{dst_port}",
                 "headers": {}, "body": "", "_process": package},
                {"status_code": 0, "headers": {}, "body": ""},
                source="ebpf", decrypted=False
            )


# ── Periodic PCAP + keylog merge via tshark ───────────────────────────────────

async def _periodic_tshark_merge(device_id: str):
    """Every 30s: pull PCAP + keylog, run tshark, ingest decrypted flows."""
    adb = _adb(device_id)
    tshark = shutil.which("tshark")
    if not tshark:
        return  # tshark not available — skip offline merge

    while device_id in _workers:
        await asyncio.sleep(30)
        try:
            pcap_local = f"/tmp/oi_cap_{device_id}.pcap"
            keys_local = f"/tmp/oi_sslkeys_{device_id}.log"

            subprocess.run(adb + ["pull", PCAP_DEVICE_PATH, pcap_local],
                           capture_output=True, timeout=15)
            subprocess.run(adb + ["pull", KEYLOG_DEVICE_PATH, keys_local],
                           capture_output=True, timeout=15)

            if not os.path.exists(pcap_local) or not os.path.exists(keys_local):
                continue

            result = subprocess.run(
                [tshark, "-r", pcap_local,
                 "-o", f"tls.keylog_file:{keys_local}",
                 "-Y", "http or http2",
                 "-T", "fields",
                 "-e", "frame.time_epoch",
                 "-e", "http.request.method",
                 "-e", "http.request.full_uri",
                 "-e", "http.response.code",
                 "-e", "http2.headers.method",
                 "-e", "http2.headers.path",
                 "-e", "http2.headers.authority",
                 "-e", "http2.headers.status",
                 "-E", "separator=|"],
                capture_output=True, text=True, timeout=30
            )

            from .mobile_agent_api import store_traffic
            for line in result.stdout.splitlines():
                parts = line.split("|")
                if len(parts) < 3:
                    continue
                ts = float(parts[0]) if parts[0] else time.time()
                method = parts[1] or parts[4] or ""
                url = parts[2] or ""
                status = int(parts[3]) if parts[3].isdigit() else \
                         int(parts[7]) if len(parts) > 7 and parts[7].isdigit() else 0

                if method and url:
                    await store_traffic(
                        device_id,
                        {"method": method, "url": url, "headers": {}, "body": ""},
                        {"status_code": status, "headers": {}, "body": ""},
                        source="ebpf_tshark", decrypted=True
                    )
        except Exception as e:
            print(f"[ebpf] tshark merge error: {e}")


def list_ebpf_workers() -> List[dict]:
    return [
        {"device_id": did, "interface": w.get("interface"),
         "running": w["ecapture_proc"].poll() is None,
         "started_at": w.get("started_at")}
        for did, w in _workers.items()
    ]
