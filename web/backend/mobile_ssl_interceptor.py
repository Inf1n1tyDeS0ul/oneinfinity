"""
Layer 2 SSL Interceptor — reassembles Frida ssl_read/ssl_write emissions
into complete HTTP messages and feeds them into the unified traffic store.

Called by mobile_frida_api.ingest_frida_output() when it sees ssl_write/
ssl_read tagged [FRIDA_FINDING] lines.

Also handles ssl_write_intercept events: pauses the flow, routes to the
existing mobile_breakpoint_api pending map so BreakpointPanel.jsx can
edit and release it.
"""

import json
import re
import time
from collections import defaultdict
from typing import Optional, Dict, List

# Per-session (device_id + package_name) stream buffers
# key: (device_id, session_id, direction) -> list of data chunks
_streams: Dict[tuple, List[str]] = defaultdict(list)
_stream_ts: Dict[tuple, float] = {}

# HTTP method detection
_HTTP_REQUEST_RE = re.compile(
    r'^(GET|POST|PUT|DELETE|PATCH|HEAD|OPTIONS|CONNECT) .+ HTTP/\d',
    re.MULTILINE
)
_HTTP_RESPONSE_RE = re.compile(r'^HTTP/\d[\.\d]* \d{3}', re.MULTILINE)


def process_ssl_emission(device_id: str, session_id: str, package_name: str,
                         tag: str, data: dict) -> None:
    """Entry point called from ingest_frida_output."""
    if tag == 'ssl_write':
        _accumulate(device_id, session_id, 'outbound', data.get('data', ''))
    elif tag == 'ssl_read':
        _accumulate(device_id, session_id, 'inbound', data.get('data', ''))
    elif tag == 'ssl_write_intercept':
        _handle_intercept(device_id, session_id, package_name, data)
    elif tag == 'keylog':
        _handle_keylog(device_id, data.get('line', ''))


def _accumulate(device_id: str, session_id: str, direction: str, chunk: str) -> None:
    if not chunk:
        return
    key = (device_id, session_id, direction)
    _streams[key].append(chunk)
    _stream_ts[key] = time.time()

    # Try to extract complete HTTP messages
    combined = ''.join(_streams[key])
    _try_extract_http(device_id, session_id, direction, combined, key)


def _try_extract_http(device_id: str, session_id: str, direction: str,
                      text: str, key: tuple) -> None:
    import asyncio
    from .mobile_agent_api import store_traffic

    # Find HTTP request in outbound stream
    if direction == 'outbound':
        m = _HTTP_REQUEST_RE.search(text)
        if not m:
            return
        start = m.start()
        # Check if headers are complete (double CRLF present)
        header_end = text.find('\r\n\r\n', start)
        if header_end == -1:
            header_end = text.find('\n\n', start)
        if header_end == -1:
            return

        # Extract complete request
        req_text = text[start:]
        parsed = _parse_http_request(req_text)
        if not parsed:
            return

        _streams[key] = []  # reset buffer

        # Store as pending request waiting for response
        req_key = (device_id, session_id, 'pending_req')
        _streams[req_key] = [json.dumps(parsed)]

        # Immediately store with empty response (will be updated when response arrives)
        loop = asyncio.new_event_loop()
        try:
            loop.run_until_complete(store_traffic(
                device_id, parsed,
                {"status_code": 0, "headers": {}, "body": "waiting for response..."},
                source="frida_ssl", decrypted=True, session_id=session_id
            ))
        except Exception:
            pass
        finally:
            loop.close()

    elif direction == 'inbound':
        m = _HTTP_RESPONSE_RE.search(text)
        if not m:
            return
        header_end = text.find('\r\n\r\n', m.start())
        if header_end == -1:
            return

        parsed_resp = _parse_http_response(text[m.start():])
        if not parsed_resp:
            return

        _streams[key] = []

        # Pair with pending request
        req_key = (device_id, session_id, 'pending_req')
        pending = _streams.get(req_key, [])
        req = {}
        if pending:
            try:
                req = json.loads(pending[0])
                _streams[req_key] = []
            except Exception:
                pass

        loop = asyncio.new_event_loop()
        try:
            loop.run_until_complete(store_traffic(
                device_id,
                req or {"method": "UNKNOWN", "url": "unknown", "headers": {}, "body": ""},
                parsed_resp,
                source="frida_ssl", decrypted=True, session_id=session_id
            ))
        except Exception:
            pass
        finally:
            loop.close()


def _parse_http_request(text: str) -> Optional[dict]:
    try:
        lines = text.split('\n')
        first = lines[0].strip()
        parts = first.split(' ', 2)
        if len(parts) < 2:
            return None
        method, path = parts[0], parts[1]

        headers = {}
        host = ''
        i = 1
        while i < len(lines):
            line = lines[i].strip()
            if not line:
                break
            if ':' in line:
                k, _, v = line.partition(':')
                headers[k.strip()] = v.strip()
                if k.strip().lower() == 'host':
                    host = v.strip()
            i += 1

        body_lines = lines[i+1:] if i + 1 < len(lines) else []
        body = '\n'.join(body_lines).strip()

        url = path if path.startswith('http') else f"https://{host}{path}" if host else path

        return {"method": method, "url": url, "headers": headers, "body": body}
    except Exception:
        return None


def _parse_http_response(text: str) -> Optional[dict]:
    try:
        lines = text.split('\n')
        first = lines[0].strip()
        parts = first.split(' ', 2)
        if len(parts) < 2:
            return None
        status_code = int(parts[1]) if parts[1].isdigit() else 0

        headers = {}
        i = 1
        while i < len(lines):
            line = lines[i].strip()
            if not line:
                break
            if ':' in line:
                k, _, v = line.partition(':')
                headers[k.strip()] = v.strip()
            i += 1

        body = '\n'.join(lines[i+1:]).strip() if i + 1 < len(lines) else ''
        return {"status_code": status_code, "headers": headers, "body": body}
    except Exception:
        return None


def _handle_intercept(device_id: str, session_id: str, package_name: str, data: dict) -> None:
    """Route ssl_write_intercept to the breakpoint pending map."""
    try:
        from .mobile_breakpoint_api import ingest_breakpoint_hit
        call_id = data.get('call_id', '')
        msg = {
            "breakpoint_id": f"ssl_{call_id}",
            "url": f"ssl://{package_name}",
            "method": "SSL_write",
            "headers": {"X-Package": package_name, "X-Session": session_id},
            "raw_size": data.get('len', 0),
            "raw_data": data.get('data', ''),
            "source": "frida_ssl",
        }
        ingest_breakpoint_hit(device_id, msg)
    except Exception as e:
        print(f"[ssl-interceptor] intercept routing error: {e}")


def _handle_keylog(device_id: str, line: str) -> None:
    """Append NSS key log line to per-device keylog file."""
    if not line:
        return
    keylog_path = f"/tmp/oi_sslkeys_{device_id}.log"
    try:
        with open(keylog_path, 'a') as f:
            f.write(line + '\n')
    except Exception:
        pass
