"""
AI Endpoint Probe — discovers the actual chatbot API format and endpoint
when it's not a standard OpenAI-compatible /v1/chat/completions URL.

Handles:
  - Azure OpenAI  (different URL scheme, api-key header)
  - Microsoft Copilot / Bot Framework
  - Custom internal REST APIs
  - WebSocket-based chatbots
  - Cookie-based (session) auth instead of Bearer

Usage:
  python endpoint_probe.py --target https://chatbot.internal.com --auth "Bearer ..."
"""

from __future__ import annotations

import argparse
import json
import re
import sys
import urllib.error
import urllib.parse
import urllib.request
from typing import Optional


def _req(url: str, method: str = "GET", body: Optional[bytes] = None,
         headers: dict = None, timeout: int = 10) -> tuple[int, str, dict]:
    """Returns (status, body_text, response_headers)."""
    hdrs = {"User-Agent": "Mozilla/5.0 (compatible; oneinfinity-probe/1.0)"}
    if headers:
        hdrs.update(headers)
    req = urllib.request.Request(url, data=body, headers=hdrs, method=method)
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            return resp.status, resp.read(65536).decode("utf-8", errors="ignore"), dict(resp.headers)
    except urllib.error.HTTPError as e:
        return e.code, e.read(4096).decode("utf-8", errors="ignore"), dict(e.headers)
    except Exception as exc:
        return 0, str(exc), {}


# Common AI chatbot endpoint path patterns
_API_PATHS = [
    # OpenAI-compatible
    "/v1/chat/completions",
    "/api/v1/chat/completions",
    "/openai/deployments/{model}/chat/completions",   # Azure OpenAI
    "/api/chat/completions",
    # Microsoft Bot Framework / Copilot
    "/api/messages",
    "/v3/directline/conversations",
    "/api/conversations",
    # Generic chat APIs
    "/api/chat",
    "/api/query",
    "/api/ask",
    "/chat",
    "/ask",
    "/query",
    "/api/message",
    "/api/completion",
    "/v1/completions",
    # Azure AI
    "/api/v1/query",
    "/qna",
    "/knowledgebases/query",
    # SSE streaming / enterprise portal patterns
    "/api-endpoint/ai_agent/chat_streaming/sse",
    "/api-endpoint/ai_agent/chat",
    "/api-endpoint/chat",
    "/api-endpoint/message",
    # Common enterprise internal AI patterns
    "/api/ai/chat",
    "/api/ai/completions",
    "/api/assistant/chat",
    "/api/assistant/message",
    "/services/chat",
    "/services/ai/chat",
]

# Test payloads for different formats
_TEST_PAYLOADS = [
    # OpenAI format
    {"model": "gpt-4", "messages": [{"role": "user", "content": "hello"}], "max_tokens": 10},
    # Azure OpenAI format (same body, different URL)
    {"messages": [{"role": "user", "content": "hello"}], "max_tokens": 10},
    # Fragment-based format
    {"messages": [{"fragments": [{"text": "hello"}]}], "agentId": "", "stream": False},
    # Simple query format
    {"query": "hello", "top": 1},
    # Bot Framework activity
    {"type": "message", "text": "hello"},
    # Direct question format
    {"question": "hello"},
    {"prompt": "hello", "max_tokens": 10},
    {"input": "hello"},
    {"message": "hello"},
]


def probe_endpoint(base_url: str, auth_header: str = "", model: str = "gpt-4") -> dict:
    """
    Probe a target to discover its API format.
    Returns a dict with: endpoint, format, auth_method, sample_request, sample_response
    """
    base_url = base_url.rstrip("/")
    common_headers = {"Content-Type": "application/json"}
    if auth_header:
        common_headers["Authorization"] = auth_header

    result = {
        "base_url": base_url,
        "discovered_endpoint": None,
        "format": None,
        "auth_method": None,
        "sample_request": None,
        "sample_response": None,
        "probed_paths": [],
        "notes": [],
    }

    # 1. Check root for redirect or auth page
    status, body, headers = _req(base_url)
    result["probed_paths"].append({"path": "/", "status": status})
    if status == 401 or status == 403:
        result["notes"].append(f"Root returns {status} — auth required as expected")
    elif status == 302 or status == 301:
        location = headers.get("Location", "")
        if "login.microsoftonline.com" in location or "microsoftonline" in location:
            result["auth_method"] = "microsoft_sso"
            result["notes"].append(f"Confirmed Microsoft SSO redirect to: {location[:80]}")
        elif "login" in location.lower() or "sso" in location.lower():
            result["auth_method"] = "sso_redirect"
            result["notes"].append(f"SSO redirect detected: {location[:80]}")

    # 2. Check for Azure OpenAI pattern in URL
    if "openai.azure.com" in base_url or "cognitiveservices" in base_url:
        result["format"] = "azure_openai"
        result["auth_method"] = "api-key or Bearer"
        # Azure OpenAI endpoint pattern
        az_path = f"/openai/deployments/{model}/chat/completions?api-version=2024-02-01"
        result["notes"].append(f"Azure OpenAI URL pattern detected — try: {base_url}{az_path}")
        return result

    # 3. Try known paths with auth
    for path in _API_PATHS:
        path_filled = path.replace("{model}", model)
        url = base_url + path_filled

        # Try each payload format
        for payload in _TEST_PAYLOADS:
            body_bytes = json.dumps(payload).encode()
            status, body_text, resp_headers = _req(
                url, method="POST", body=body_bytes, headers=common_headers
            )
            result["probed_paths"].append({"path": path_filled, "status": status, "payload_type": list(payload.keys())[0]})

            if status in (200, 201):
                # Try to parse response
                try:
                    resp_json = json.loads(body_text)
                    # Detect format from response structure
                    if "choices" in resp_json:
                        fmt = "openai_compatible"
                        content = resp_json["choices"][0].get("message", {}).get("content", "") or resp_json["choices"][0].get("text", "")
                    elif "answer" in resp_json:
                        fmt = "qna_maker"
                        content = resp_json["answer"]
                    elif "text" in resp_json:
                        fmt = "simple_text"
                        content = resp_json["text"]
                    elif "response" in resp_json:
                        fmt = "custom_response"
                        content = resp_json["response"]
                    elif "message" in resp_json:
                        fmt = "custom_message"
                        content = resp_json["message"]
                    else:
                        fmt = "unknown_json"
                        content = str(resp_json)[:100]
                except (json.JSONDecodeError, KeyError):
                    fmt = "non_json"
                    content = body_text[:100]

                result["discovered_endpoint"] = url
                result["format"] = fmt
                result["sample_request"] = payload
                result["sample_response"] = body_text[:300]
                result["notes"].append(f"✅ Found: {url} [{fmt}]")
                return result

            elif status == 401:
                result["notes"].append(f"401 at {path_filled} — endpoint exists but auth rejected")
                result["notes"].append("Check: token scope, api-key header (Ocp-Apim-Subscription-Key), or cookie auth")
            elif status == 405:
                # Method not allowed — endpoint exists but may need GET or different method
                result["notes"].append(f"405 at {path_filled} — endpoint exists (wrong method?)")

    # 4. Check for cookie-based auth (no Authorization header worked)
    if not result["discovered_endpoint"] and not auth_header:
        result["notes"].append("No endpoint found without auth — try Method B (browser token extraction)")

    return result


def _cli():
    p = argparse.ArgumentParser(description="Probe AI chatbot endpoint format")
    p.add_argument("target", help="Base URL e.g. https://chatbot.internal.com")
    p.add_argument("--auth", default="", help="Bearer token (Authorization header value)")
    p.add_argument("--model", default="gpt-4")
    p.add_argument("--json", action="store_true")
    args = p.parse_args()

    result = probe_endpoint(args.target, args.auth, args.model)

    if args.json:
        print(json.dumps(result, indent=2))
    else:
        print(f"\n[*] Endpoint Probe: {result['base_url']}")
        print(f"    Auth method    : {result['auth_method'] or 'unknown'}")
        print(f"    Discovered URL : {result['discovered_endpoint'] or 'NOT FOUND'}")
        print(f"    Format         : {result['format'] or 'unknown'}")
        if result["notes"]:
            print(f"\n    Notes:")
            for n in result["notes"]:
                print(f"      {n}")
        if result["discovered_endpoint"]:
            print(f"\n[+] Use in OneInfinity campaign:")
            print(f"    Target URL   : {result['discovered_endpoint']}")
            print(f"    Endpoint Path: (already included in URL above — use '/' as path)")

        probed = [p for p in result["probed_paths"] if p["status"] not in (0, 404, 405)]
        if probed:
            print(f"\n    Interesting paths probed ({len(probed)}):")
            for p in probed[:10]:
                print(f"      {p['status']} {p['path']}")


if __name__ == "__main__":
    _cli()
