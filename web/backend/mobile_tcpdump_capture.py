"""
Root-based traffic capture via tcpdump over ADB.

Uses tcpdump on wlan0 (or any interface) on the connected Android device.
Parses tcpdump output into traffic entries and feeds them into store_traffic.

Requires: device is rooted, adb connected, tcpdump available on device.
"""

import asyncio
import subprocess
import re
import time
from typing import Optional
from datetime import datetime

# Active capture processes keyed by device_id
_captures: dict[str, subprocess.Popen] = {}


async def start_tcpdump_capture(device_id: str, interface: str = "wlan0", port_filter: str = "port 80 or port 443") -> dict:
    if device_id in _captures:
        proc = _captures[device_id]
        if proc.poll() is None:
            return {"status": "already_running", "device_id": device_id}

    cmd = [
        "adb", "shell",
        f"su -c 'tcpdump -i {interface} -l -nn -tttt {port_filter} 2>/dev/null'"
    ]

    proc = subprocess.Popen(
        cmd, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, text=True, bufsize=1
    )
    _captures[device_id] = proc

    # Start async reader in background
    asyncio.create_task(_stream_tcpdump(device_id, proc))

    return {"status": "started", "device_id": device_id, "interface": interface, "filter": port_filter}


async def stop_tcpdump_capture(device_id: str) -> dict:
    proc = _captures.pop(device_id, None)
    if proc:
        proc.terminate()
        return {"status": "stopped", "device_id": device_id}
    return {"status": "not_running", "device_id": device_id}


async def _stream_tcpdump(device_id: str, proc: subprocess.Popen):
    from .mobile_agent_api import store_traffic

    loop = asyncio.get_event_loop()
    pending: dict[str, dict] = {}  # connKey -> partial entry

    try:
        while proc.poll() is None:
            line = await loop.run_in_executor(None, proc.stdout.readline)
            if not line:
                await asyncio.sleep(0.05)
                continue

            entry = _parse_tcpdump_line(line.strip())
            if not entry:
                continue

            conn_key = entry["conn_key"]

            if entry["direction"] == "outbound":
                pending[conn_key] = {
                    "method": "CONNECT" if entry["dst_port"] == 443 else "GET",
                    "url": f"{'https' if entry['dst_port'] == 443 else 'http'}://{entry['dst_ip']}:{entry['dst_port']}",
                    "version": "TLS" if entry["dst_port"] == 443 else "HTTP/1.1",
                    "headers": {},
                    "body": "",
                    "flags": entry["flags"],
                    "length": entry["length"],
                    "src_ip": entry["src_ip"],
                    "src_port": entry["src_port"],
                    "dst_ip": entry["dst_ip"],
                    "dst_port": entry["dst_port"],
                    "timestamp": entry["timestamp"],
                }
            elif entry["direction"] == "inbound" and conn_key in pending:
                req = pending.pop(conn_key)
                resp = {
                    "status_code": 200 if entry["flags"] in (".", "P.") else 0,
                    "status_message": "TLS encrypted" if req["version"] == "TLS" else "HTTP",
                    "headers": {},
                    "body": f"length={entry['length']} flags={entry['flags']}",
                    "length": entry["length"],
                    "flags": entry["flags"],
                }
                await store_traffic(device_id, req, resp, source="tcpdump", decrypted=False)

    except Exception as e:
        print(f"[tcpdump] Stream error for {device_id}: {e}")
    finally:
        _captures.pop(device_id, None)


# Matches: 2026-06-01 12:33:45.384179 IP 10.0.0.1.12345 > 142.251.157.119.443: Flags [F.], seq ..., length 0
_LINE_RE = re.compile(
    r"(\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}\.\d+) IP "
    r"([\d.]+)\.(\d+) > ([\d.]+)\.(\d+): "
    r"Flags \[([^\]]+)\].*length (\d+)"
)


def _parse_tcpdump_line(line: str) -> Optional[dict]:
    m = _LINE_RE.match(line)
    if not m:
        return None

    ts_str, src_ip, src_port, dst_ip, dst_port, flags, length = m.groups()
    src_port, dst_port, length = int(src_port), int(dst_port), int(length)

    # Determine direction: outbound = device IP is source, inbound = device IP is dest
    # Device IP on wlan0 typically starts with 10.x or 192.168.x
    direction = "outbound" if dst_port in (80, 443) else "inbound"

    # Reverse key for pairing: outbound conn_key = src->dst, inbound = dst->src (reversed)
    if direction == "outbound":
        conn_key = f"{src_ip}:{src_port}-{dst_ip}:{dst_port}"
    else:
        conn_key = f"{dst_ip}:{dst_port}-{src_ip}:{src_port}"

    return {
        "timestamp": ts_str,
        "src_ip": src_ip,
        "src_port": src_port,
        "dst_ip": dst_ip,
        "dst_port": dst_port,
        "flags": flags,
        "length": length,
        "direction": direction,
        "conn_key": conn_key,
    }


def list_captures() -> list:
    return [
        {"device_id": did, "running": proc.poll() is None}
        for did, proc in _captures.items()
    ]
