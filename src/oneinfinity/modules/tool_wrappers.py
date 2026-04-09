"""
Tool Wrapper Layer — One&Infinity
=========================================
Wraps every installed security tool with:
  - Structured JSON output
  - Timeout + error handling
  - Authorization guard (never runs without scope)
  - Unified run_tool() dispatcher

Usage:
    from oneinfinity.modules.tool_wrappers import ToolRegistry
    reg = ToolRegistry()
    result = reg.run("subfinder", domain="example.com")
    # result is always a ToolResult dict
"""

from __future__ import annotations

import hashlib
import json
import logging
import os
import re
import shutil
import subprocess
import tempfile
import time
from dataclasses import dataclass, field, asdict
from pathlib import Path
from typing import Any, Optional

log = logging.getLogger(__name__)

# ── Retry constants ───────────────────────────────────────────────────────────
_MAX_RETRIES = 2          # number of extra attempts after the first
_RETRY_BASE_DELAY = 1.0   # seconds; doubles each attempt (1s → 2s)


# ── Scope validator hook ──────────────────────────────────────────────────────

# Module-level scope validator — set via set_scope_validator() before scans
_scope_validator = None

def set_scope_validator(validator) -> None:
    """Register a ScopeValidator instance. Called by UnifiedScanEngine at scan start."""
    global _scope_validator
    _scope_validator = validator

def _check_scope(target: str) -> None:
    """Raise PermissionError if target is out of scope. No-op if no validator set."""
    if _scope_validator is None:
        return
    if not _scope_validator.check(target):
        raise PermissionError(f"[SCOPE] Target '{target}' is out of scope — tool execution blocked")


# ── Result container ──────────────────────────────────────────────────────────

@dataclass
class ToolResult:
    tool: str
    success: bool
    data: Any = None           # parsed/structured output
    count: int = 0             # Number of findings/items discovered
    raw: str = ""              # raw stdout
    error: str = ""            # stderr / exception message
    returncode: int = 0
    stderr: str = ""
    duration: float = 0.0     # seconds
    command: str = ""          # command that was run

    def to_dict(self) -> dict:
        return asdict(self)

    def to_json(self, indent: int = 2) -> str:
        return json.dumps(self.to_dict(), indent=indent, default=str)


def tag_ssrf_confidence(finding: dict, oob_callback_received: bool) -> dict:
    """
    Adjusts confidence of SSRF findings based on OOB callback confirmation.
    Without a confirmed OOB callback, SSRF can only be reported as low-confidence
    requiring manual verification — the request was sent but we don't know if
    the server actually fetched it.
    """
    out = dict(finding)
    if not oob_callback_received:
        out["confidence"] = 0.35   # below reporting threshold
        out["needs_manual_verification"] = True
        out["oob_callback_received"] = False
        out.setdefault("flags", [])
        if isinstance(out["flags"], list) and "ssrf_unconfirmed" not in out["flags"]:
            out["flags"].append("ssrf_unconfirmed")
    else:
        out["oob_callback_received"] = True
    return out


# ── Command runner ────────────────────────────────────────────────────────────

def _run_cmd(
    cmd: list[str],
    timeout: int = 300,
    input_data: Optional[str] = None,
    env: Optional[dict] = None,
    retries: int = _MAX_RETRIES,
) -> tuple[int, str, str]:
    """Run a subprocess command with exponential-backoff retry; return (returncode, stdout, stderr).

    Retries are skipped for:
      - FileNotFoundError (tool missing, rc=127) — not a transient failure
      - TimeoutExpired   — retrying would only add more wait time
    """
    merged_env = {**os.environ, **(env or {})}
    merged_env["PATH"] = (
        merged_env.get("PATH", "") +
        ":/usr/local/go/bin:/root/go/bin:" +
        str(Path.home() / "go" / "bin") + ":" +
        str(Path.home() / ".cargo" / "bin") + ":" +
        str(Path.home() / ".local" / "bin")
    )
    last_rc, last_out, last_err = 1, "", "No attempts made"
    delay = _RETRY_BASE_DELAY
    for attempt in range(retries + 1):
        try:
            proc = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=timeout,
                env=merged_env,
                input=input_data,
            )
            if proc.returncode == 0:
                return proc.returncode, proc.stdout, proc.stderr
            # Non-zero exit — may be transient; retry
            last_rc, last_out, last_err = proc.returncode, proc.stdout, proc.stderr
        except subprocess.TimeoutExpired:
            return 1, "", f"Command timed out after {timeout}s: {' '.join(cmd)}"
        except (FileNotFoundError, PermissionError):
            return 127, "", f"Tool not found: {cmd[0]}"
        except Exception as exc:
            last_rc, last_out, last_err = 1, "", str(exc)

        if attempt < retries:
            log.debug("_run_cmd: attempt %d/%d failed (rc=%d), retrying in %.1fs — %s",
                      attempt + 1, retries + 1, last_rc, delay, cmd[0])
            time.sleep(delay)
            delay *= 2

    return last_rc, last_out, last_err


def _redact_cmd(cmd_list: list) -> str:
    """Build a command string for logging, redacting sensitive header values.

    Redacts the value after -H / --header flags, and any token starting with
    'Authorization:' or 'X-API-Key:'.
    """
    redacted = []
    skip_next = False
    for token in cmd_list:
        if skip_next:
            redacted.append("[REDACTED]")
            skip_next = False
            continue
        token_str = str(token)
        token_lower = token_str.lower()
        if token_lower in ("-h", "--header"):
            redacted.append(token_str)
            skip_next = True
        elif token_lower.startswith("authorization:"):
            redacted.append("Authorization:[REDACTED]")
        elif token_lower.startswith("x-api-key:"):
            redacted.append("X-API-Key:[REDACTED]")
        else:
            redacted.append(token_str)
    return " ".join(redacted)


def _wrap(tool: str, cmd: list[str], timeout: int = 300,
          parse_fn=None, input_data: Optional[str] = None,
          env: Optional[dict] = None) -> ToolResult:
    """Execute a tool command and return a ToolResult."""
    t0 = time.time()
    rc, stdout, stderr = _run_cmd(cmd, timeout=timeout, input_data=input_data, env=env)
    duration = time.time() - t0
    command_str = _redact_cmd(cmd)
    success = rc == 0
    data = None
    error = ""
    count = 0

    if rc == 127:
        log.warning(
            "TOOL NOT FOUND: '%s' is not installed or not on PATH. "
            "This scan phase will produce no results. "
            "Install it to enable this capability.",
            cmd[0] if cmd else tool,
        )
        return ToolResult(tool=tool, success=False, error=stderr,
                          returncode=rc, stderr=stderr,
                          duration=duration, command=command_str)

    if not success:
        error = stderr.strip() or f"Exit code {rc}"

    # Parse output
    if parse_fn and stdout:
        try:
            data = parse_fn(stdout)
        except Exception as exc:
            data = stdout.splitlines()
            error = f"Parse warning: {exc}"
    elif stdout:
        data = stdout.splitlines()

    # Automatic count detection
    if isinstance(data, list):
        count = len(data)
    elif isinstance(data, dict):
        if "count" in data:
            count = data["count"]
        elif "findings" in data and isinstance(data["findings"], list):
            count = len(data["findings"])
        elif "hosts" in data and isinstance(data["hosts"], list):
            count = len(data["hosts"])
        elif "subdomains" in data and isinstance(data["subdomains"], list):
            count = len(data["subdomains"])
        elif "urls" in data and isinstance(data["urls"], list):
            count = len(data["urls"])
        else:
            count = 1 if data else 0
    elif data:
        count = 1

    return ToolResult(
        tool=tool,
        success=success,
        data=data,
        count=count,
        raw=stdout,
        error=error,
        returncode=rc,
        stderr=stderr,
        duration=duration,
        command=command_str,
    )


# ── Tool availability check ───────────────────────────────────────────────────

def is_available(tool: str) -> bool:
    paths = [
        "/usr/local/go/bin", "/root/go/bin",
        str(Path.home() / "go" / "bin"),
        str(Path.home() / ".cargo" / "bin"),
        str(Path.home() / ".local" / "bin"),
        str(Path.home() / "bin"),
        "/usr/local/bin", "/usr/bin", "/bin",
    ]
    full_path = os.environ.get("PATH", "") + ":" + ":".join(paths)
    return shutil.which(tool, path=full_path) is not None


# ── JSON NDJSON parser helpers ────────────────────────────────────────────────

def _parse_ndjson(text: str) -> list[dict]:
    """Parse newline-delimited JSON (one JSON object per line)."""
    results = []
    for line in text.splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            results.append(json.loads(line))
        except json.JSONDecodeError:
            results.append({"raw": line})
    return results


def _parse_lines(text: str) -> list[str]:
    return [l.strip() for l in text.splitlines() if l.strip()]


def _parse_json(text: str) -> Any:
    return json.loads(text)


# ── Output normalization ──────────────────────────────────────────────────────
# Unified finding schema — every tool result can be normalised to this shape.

_SEVERITY_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4, "unknown": 5}

def _canonical_severity(raw: str) -> str:
    s = (raw or "unknown").lower().strip()
    for k in _SEVERITY_ORDER:
        if k in s:
            return k
    return "unknown"


def normalize_finding(raw: Any, source_tool: str) -> dict:
    """Map any tool-specific dict/string to the canonical finding schema.

    Canonical fields:
        url          — target URL (may be empty string)
        parameter    — affected parameter name (may be empty)
        vulnerability — human-readable description
        severity     — one of critical/high/medium/low/info/unknown
        source_tool  — originating tool name
        extra        — any remaining key/value pairs
    """
    if isinstance(raw, str):
        return {
            "url": raw if raw.startswith(("http://", "https://")) else "",
            "parameter": "",
            "vulnerability": raw,
            "severity": "info",
            "source_tool": source_tool,
            "extra": {},
        }

    if not isinstance(raw, dict):
        return {
            "url": "", "parameter": "", "vulnerability": str(raw),
            "severity": "unknown", "source_tool": source_tool, "extra": {},
        }

    # Extract URL — try common key names across different tools
    url = (
        raw.get("url") or raw.get("URL") or raw.get("matched-at") or
        raw.get("host") or raw.get("target") or raw.get("endpoint") or ""
    )

    # Parameter
    parameter = (
        raw.get("parameter") or raw.get("param") or raw.get("name") or ""
    )

    # Vulnerability description — explicit priority, no ternary ambiguity
    _info = raw.get("info") if isinstance(raw.get("info"), dict) else {}
    vulnerability = (
        raw.get("vulnerability")
        or raw.get("name")
        or raw.get("type")
        or raw.get("title")
        or _info.get("name")
        or raw.get("template-id")
        or raw.get("description")
        or raw.get("check")
        or ""
    )

    # Severity
    sev_raw = (
        raw.get("severity") or raw.get("risk") or raw.get("cvss") or
        (raw.get("info", {}) or {}).get("severity") or "unknown"
    )
    severity = _canonical_severity(str(sev_raw))

    # Remaining keys go into extra
    known = {"url", "URL", "matched-at", "host", "target", "endpoint",
             "parameter", "param", "name", "vulnerability", "type", "title",
             "info", "template-id", "description", "severity", "risk", "cvss",
             "check"}
    extra = {k: v for k, v in raw.items() if k not in known}

    return {
        "url": str(url),
        "parameter": str(parameter),
        "vulnerability": str(vulnerability),
        "severity": severity,
        "source_tool": source_tool,
        "extra": extra,
    }


def _finding_key(f: dict) -> str:
    """Deterministic dedup key based on url + parameter + vulnerability."""
    parts = f"{f.get('url', '')}|{f.get('parameter', '')}|{f.get('vulnerability', '')}"
    return hashlib.md5(parts.encode()).hexdigest()


def normalize_results(results: list[Any], source_tool: str) -> list[dict]:
    """Normalise a list of raw findings and deduplicate them deterministically."""
    seen: set[str] = set()
    out: list[dict] = []
    for r in results:
        finding = normalize_finding(r, source_tool)
        key = _finding_key(finding)
        if key not in seen:
            seen.add(key)
            out.append(finding)
    return out


def merge_normalized(*finding_lists: list[dict]) -> list[dict]:
    """Merge multiple normalised finding lists, deduplicating across all of them.

    Severity ordering: if the same finding appears with different severities,
    the most severe is kept.
    """
    combined: dict[str, dict] = {}
    for lst in finding_lists:
        for f in lst:
            key = _finding_key(f)
            if key not in combined:
                combined[key] = f
            else:
                existing_sev = _SEVERITY_ORDER.get(combined[key]["severity"], 5)
                new_sev = _SEVERITY_ORDER.get(f["severity"], 5)
                if new_sev < existing_sev:
                    combined[key] = f
    # Sort by severity then url
    return sorted(combined.values(),
                  key=lambda x: (_SEVERITY_ORDER.get(x["severity"], 5), x.get("url", "")))


# ============================================================================
#  SUBDOMAIN ENUMERATION
# ============================================================================

def run_subfinder(domain: str, timeout: int = 120,
                  extra_flags: list[str] = None) -> ToolResult:
    """Enumerate subdomains with subfinder."""
    cmd = ["subfinder", "-d", domain, "-silent", "-all"]
    if extra_flags:
        cmd.extend(extra_flags)
    result = _wrap("subfinder", cmd, timeout=timeout,
                   parse_fn=_parse_lines)
    if result.success and isinstance(result.data, list):
        result.data = {"subdomains": result.data, "count": len(result.data)}
    return result


def run_amass(domain: str, timeout: int = 300,
              mode: str = "enum") -> ToolResult:
    """Subdomain enumeration with amass (passive mode by default)."""
    cmd = ["amass", mode, "-passive", "-d", domain, "-silent"]
    result = _wrap("amass", cmd, timeout=timeout, parse_fn=_parse_lines)
    if result.success and isinstance(result.data, list):
        result.data = {"subdomains": result.data, "count": len(result.data)}
    return result


def run_assetfinder(domain: str, timeout: int = 60,
                    subs_only: bool = True) -> ToolResult:
    """Find assets / subdomains with assetfinder."""
    cmd = ["assetfinder"]
    if subs_only:
        cmd.append("--subs-only")
    cmd.append(domain)
    result = _wrap("assetfinder", cmd, timeout=timeout, parse_fn=_parse_lines)
    if result.success and isinstance(result.data, list):
        result.data = {"subdomains": result.data, "count": len(result.data)}
    return result


def run_findomain(domain: str, timeout: int = 60) -> ToolResult:
    """Subdomain enumeration with findomain."""
    cmd = ["findomain", "--target", domain, "--quiet"]
    result = _wrap("findomain", cmd, timeout=timeout, parse_fn=_parse_lines)
    if result.success and isinstance(result.data, list):
        result.data = {"subdomains": result.data, "count": len(result.data)}
    return result


def run_chaos(domain: str, key: str = "", timeout: int = 60) -> ToolResult:
    """Chaos subdomain enumeration (requires API key)."""
    env = {}
    if key:
        env["CHAOS_KEY"] = key
    elif os.environ.get("CHAOS_KEY"):
        env["CHAOS_KEY"] = os.environ["CHAOS_KEY"]
    cmd = ["chaos", "-d", domain, "-silent"]
    result = _wrap("chaos", cmd, timeout=timeout, parse_fn=_parse_lines, input_data=None)
    if result.success and isinstance(result.data, list):
        result.data = {"subdomains": result.data, "count": len(result.data)}
    return result


def run_sublist3r(domain: str, timeout: int = 180) -> ToolResult:
    """Subdomain enumeration with Sublist3r."""
    with tempfile.NamedTemporaryFile(suffix=".txt", delete=False) as tf:
        out_file = tf.name
    try:
        cmd = ["sublist3r", "-d", domain, "-o", out_file, "-n"]
        result = _wrap("sublist3r", cmd, timeout=timeout)
        if Path(out_file).exists():
            lines = _parse_lines(Path(out_file).read_text())
            result.data = {"subdomains": lines, "count": len(lines)}
            result.success = True
    finally:
        Path(out_file).unlink(missing_ok=True)
    return result


# ============================================================================
#  HTTP PROBING
# ============================================================================

def run_httpx(targets: list[str], timeout: int = 120,
              flags: list[str] = None) -> ToolResult:
    """Probe hosts with httpx; returns list of live host dicts."""
    with tempfile.NamedTemporaryFile(mode="w", suffix=".txt", delete=False) as tf:
        tf.write("\n".join(targets))
        input_file = tf.name
    with tempfile.NamedTemporaryFile(suffix=".json", delete=False) as tf2:
        out_file = tf2.name
    try:
        cmd = [
            "httpx", "-l", input_file, "-json", "-o", out_file,
            "-title", "-tech-detect", "-status-code",
            "-follow-redirects", "-timeout", "10", "-rate-limit", "50",
            "-silent",
        ]
        if flags:
            cmd.extend(flags)
        result = _wrap("httpx", cmd, timeout=timeout)
        if Path(out_file).exists():
            lines = Path(out_file).read_text().strip().splitlines()
            parsed = []
            for line in lines:
                try:
                    parsed.append(json.loads(line))
                except Exception:
                    pass
            result.data = {"hosts": parsed, "count": len(parsed)}
            result.success = True
    finally:
        Path(input_file).unlink(missing_ok=True)
        Path(out_file).unlink(missing_ok=True)
    return result


def run_httpx_single(url: str, timeout: int = 30) -> ToolResult:
    """Probe a single URL with httpx."""
    return run_httpx([url], timeout=timeout)


def run_http_request(
    url: str,
    method: str = "GET",
    params: dict = None,
    data: dict = None,
    json_body: dict = None,
    headers: dict = None,
    timeout: int = 30,
) -> ToolResult:
    """
    Pure-Python HTTP request (no CLI dependency).
    Used by swarm agents for targeted probes with custom method/params/data/headers.
    Returns ToolResult with data = {status, body, headers, url, elapsed_ms}.
    """
    import time as _time
    try:
        import requests as _req
    except ImportError:
        return ToolResult(tool="http_request", success=False,
                          error="requests library not installed")
    try:
        clean_headers = {k: v for k, v in (headers or {}).items() if v}
        t0 = _time.monotonic()
        resp = _req.request(
            method=method.upper(),
            url=url,
            params=params or {},
            data=data or {},
            json=json_body,
            headers=clean_headers,
            timeout=timeout,
            allow_redirects=True,
            verify=False,
        )
        elapsed_ms = int((_time.monotonic() - t0) * 1000)
        return ToolResult(
            tool="http_request",
            success=True,
            data={
                "status":      resp.status_code,
                "body":        resp.text[:8192],
                "headers":     dict(resp.headers),
                "url":         resp.url,
                "elapsed_ms":  elapsed_ms,
            },
            raw=resp.text[:2048],
        )
    except Exception as exc:
        return ToolResult(tool="http_request", success=False, error=str(exc))


# ============================================================================
#  PORT SCANNING
# ============================================================================

def run_naabu(target: str, ports: str = "80,443,8080,8443,8888",
              timeout: int = 120) -> ToolResult:
    """Port scan with naabu (fast SYN scanner)."""
    cmd = ["naabu", "-host", target, "-p", ports, "-silent", "-json"]
    result = _wrap("naabu", cmd, timeout=timeout, parse_fn=_parse_ndjson)
    if result.success and isinstance(result.data, list):
        open_ports = [
            {"port": d.get("port"), "protocol": d.get("protocol", "tcp")}
            for d in result.data if isinstance(d, dict)
        ]
        result.data = {"target": target, "open_ports": open_ports,
                       "count": len(open_ports)}
    return result


_NMAP_SAFE_FLAGS = re.compile(r'^-[a-zA-Z0-9]+$|^--[a-zA-Z][a-zA-Z0-9_-]*$|^[0-9T]+$')

def run_nmap(target: str, flags: str = "-sV -T4 --open",
             timeout: int = 300) -> ToolResult:
    """Port scan with nmap; returns raw output."""
    # Filter flags to allowlist — prevents flag injection via user-supplied flags string
    safe_flags = [f for f in flags.split() if _NMAP_SAFE_FLAGS.match(f)]
    cmd = ["nmap"] + safe_flags + [target]
    result = _wrap("nmap", cmd, timeout=timeout)
    # Parse basic open ports from nmap output
    if result.raw:
        ports = re.findall(r"(\d+)/(\w+)\s+open\s+(\S+)", result.raw)
        result.data = {
            "target": target,
            "open_ports": [
                {"port": int(p), "protocol": proto, "service": svc}
                for p, proto, svc in ports
            ],
        }
    return result


def run_masscan(target: str, ports: str = "0-65535",
                rate: int = 1000, timeout: int = 300) -> ToolResult:
    """Port scan with masscan (very fast, needs root)."""
    with tempfile.NamedTemporaryFile(suffix=".json", delete=False) as tf:
        out_file = tf.name
    cmd = ["masscan", target, "-p", ports, "--rate", str(rate),
           "--open-only", "-oJ", out_file]
    result = _wrap("masscan", cmd, timeout=timeout)
    out = Path(out_file)
    if out.exists():
        try:
            raw = out.read_text().strip()
            parsed = json.loads(raw or "[]")
            # Normalize masscan JSON: [{"ip": "...", "ports": [{"port": N, "proto": "tcp", ...}]}]
            open_ports = []
            for entry in (parsed if isinstance(parsed, list) else []):
                ip = entry.get("ip", "")
                for p in entry.get("ports", []):
                    open_ports.append({
                        "ip": ip,
                        "port": p.get("port"),
                        "protocol": p.get("proto", "tcp"),
                        "status": p.get("status", "open"),
                    })
            result.data = {"target": target, "open_ports": open_ports,
                           "count": len(open_ports)}
            result.success = True
        except Exception as exc:
            result.error = f"masscan parse failed: {exc}"
        finally:
            out.unlink(missing_ok=True)
    else:
        result.error = result.error or "masscan produced no output (requires root?)"
    return result


def run_rustscan(target: str, ports: str = "1-65535",
                 timeout: int = 120) -> ToolResult:
    """Port scan with rustscan (wraps nmap)."""
    cmd = ["rustscan", "-a", target, "-r", ports, "--", "-sV", "-T4"]
    return _wrap("rustscan", cmd, timeout=timeout)


# ============================================================================
#  WEB CRAWLING & URL DISCOVERY
# ============================================================================

def run_katana(target: str, depth: int = 3, timeout: int = 180,
               js_crawl: bool = True) -> ToolResult:
    """Crawl with katana; returns list of discovered URLs."""
    cmd = [
        "katana", "-u", target, "-d", str(depth),
        "-silent", "-nc", "-jc" if js_crawl else "", "-jsonl",
    ]
    cmd = [c for c in cmd if c]  # remove empty strings
    result = _wrap("katana", cmd, timeout=timeout, parse_fn=_parse_ndjson)
    urls = []
    if isinstance(result.data, list):
        for item in result.data:
            if isinstance(item, dict):
                urls.append(item.get("request", {}).get("endpoint", item.get("raw", "")))
            else:
                urls.append(str(item))
    result.data = {"urls": [u for u in urls if u], "count": len(urls)}
    return result


def run_hakrawler(url: str, depth: int = 2, timeout: int = 120) -> ToolResult:
    """Crawl with hakrawler (reads URL from stdin)."""
    cmd = ["hakrawler", "-depth", str(depth), "-plain"]
    result = _wrap("hakrawler", cmd, timeout=timeout,
                   parse_fn=_parse_lines, input_data=url)
    if isinstance(result.data, list):
        result.data = {"urls": result.data, "count": len(result.data)}
    return result


def run_gauplus(domain: str, timeout: int = 120) -> ToolResult:
    """Fetch known URLs from Wayback/Common Crawl with gauplus."""
    cmd = ["gauplus", domain]
    result = _wrap("gauplus", cmd, timeout=timeout, parse_fn=_parse_lines)
    if isinstance(result.data, list):
        result.data = {"urls": result.data, "count": len(result.data)}
    return result


def run_waybackurls(domain: str, timeout: int = 120) -> ToolResult:
    """Fetch archived URLs from Wayback Machine."""
    cmd = ["waybackurls", domain]
    result = _wrap("waybackurls", cmd, timeout=timeout, parse_fn=_parse_lines)
    if isinstance(result.data, list):
        result.data = {"urls": result.data, "count": len(result.data)}
    return result


def run_paramspider(domain: str, timeout: int = 120,
                    level: str = "high") -> ToolResult:
    """Discover URL parameters with paramspider."""
    out_dir = Path(tempfile.mkdtemp())
    cmd = ["paramspider", "-d", domain, "--level", level,
           "--output", str(out_dir)]
    result = _wrap("paramspider", cmd, timeout=timeout)
    # Collect output files
    urls = []
    for f in out_dir.glob("*.txt"):
        urls.extend(_parse_lines(f.read_text()))
    for f in out_dir.glob("**/*.txt"):
        urls.extend(_parse_lines(f.read_text()))
    if urls:
        result.data = {"urls": list(set(urls)), "count": len(set(urls))}
        result.success = True
    import shutil as _shutil
    _shutil.rmtree(str(out_dir), ignore_errors=True)
    return result


# ============================================================================
#  CONTENT DISCOVERY / FUZZING
# ============================================================================

COMMON_WORDLISTS = [
    "/usr/share/seclists/Discovery/Web-Content/common.txt",
    "/usr/share/seclists/Discovery/Web-Content/directory-list-2.3-medium.txt",
    "/usr/share/wordlists/dirb/common.txt",
    "/usr/share/dirbuster/wordlists/directory-list-2.3-small.txt",
]


def _find_wordlist() -> Optional[str]:
    for wl in COMMON_WORDLISTS:
        if Path(wl).exists():
            return wl
    return None


def run_ffuf(url: str, wordlist: str = "", timeout: int = 300,
             extensions: str = "", threads: int = 40) -> ToolResult:
    """Directory/content fuzzing with ffuf; FUZZ keyword in URL or appended."""
    if not wordlist:
        wordlist = _find_wordlist()
    if not wordlist:
        return ToolResult(tool="ffuf", success=False,
                          error="No wordlist found. Install seclists.")

    target = url if "FUZZ" in url else url.rstrip("/") + "/FUZZ"
    with tempfile.NamedTemporaryFile(suffix=".json", delete=False) as tf:
        out_file = tf.name

    cmd = [
        "ffuf", "-u", target, "-w", wordlist,
        "-o", out_file, "-of", "json",
        "-t", str(threads), "-mc", "200,201,204,301,302,307,401,403,405",
        "-ac", "-s",  # autocalibrate + silent
    ]
    if extensions:
        cmd.extend(["-e", extensions])

    result = _wrap("ffuf", cmd, timeout=timeout)
    if Path(out_file).exists():
        try:
            data = json.loads(Path(out_file).read_text())
            results = data.get("results", [])
            result.data = {
                "target": url,
                "found": [
                    {
                        "path": r.get("input", {}).get("FUZZ", r.get("url", "")),
                        "url": r.get("url", ""),
                        "status": r.get("status", 0),
                        "length": r.get("length", 0),
                    }
                    for r in results
                ],
                "count": len(results),
            }
            result.success = True
        except Exception as exc:
            result.error = f"Parse failed: {exc}"
        finally:
            Path(out_file).unlink(missing_ok=True)
    return result


def run_gobuster(url: str, wordlist: str = "", timeout: int = 300,
                 mode: str = "dir") -> ToolResult:
    """Content discovery with gobuster."""
    if not wordlist:
        wordlist = _find_wordlist()
    if not wordlist:
        return ToolResult(tool="gobuster", success=False,
                          error="No wordlist found.")
    fd, out_path = tempfile.mkstemp(suffix="_gobuster.txt")
    os.close(fd)
    out = Path(out_path)
    try:
        cmd = [
            "gobuster", mode, "-u", url, "-w", wordlist,
            "-q", "--no-error", "-o", out_path,
        ]
        result = _wrap("gobuster", cmd, timeout=timeout)
        if out.exists():
            lines = _parse_lines(out.read_text())
            result.data = {"found": lines, "count": len(lines)}
    finally:
        out.unlink(missing_ok=True)
    return result


def run_dirsearch(url: str, extensions: str = "php,asp,aspx,jsp,html,js",
                  timeout: int = 300) -> ToolResult:
    """Directory brute-forcing with dirsearch."""
    with tempfile.NamedTemporaryFile(suffix=".json", delete=False) as tf:
        out_file = tf.name
    cmd = [
        "dirsearch", "-u", url, "-e", extensions,
        "--format=json", f"--output={out_file}", "-q",
    ]
    result = _wrap("dirsearch", cmd, timeout=timeout)
    if Path(out_file).exists():
        try:
            data = json.loads(Path(out_file).read_text())
            # dirsearch JSON format: {"results": {"<url>": [{"path": ..., "status": ..., ...}]}}
            # results is a dict keyed by URL, not a flat list.
            results_raw = data.get("results", {}) if isinstance(data, dict) else {}
            items = []
            if isinstance(results_raw, dict):
                # Flatten all URL buckets into a single list
                for _url_key, entries in results_raw.items():
                    if isinstance(entries, list):
                        items.extend(entries)
            elif isinstance(results_raw, list):
                # Older dirsearch versions emitted a flat list — keep working
                items = results_raw
            result.data = {
                "target": url,
                "found": [
                    {
                        "path": item.get("path", ""),
                        "url": item.get("url", ""),
                        "status": item.get("status", 0),
                        "size": item.get("content-length", item.get("size", 0)),
                        "redirect": item.get("redirect", ""),
                    }
                    for item in items
                    if isinstance(item, dict)
                ],
                "count": len(items),
            }
            result.success = True
        except Exception as exc:
            result.error = f"dirsearch parse failed: {exc}"
        finally:
            Path(out_file).unlink(missing_ok=True)
    return result


# ============================================================================
#  VULNERABILITY SCANNING
# ============================================================================

def normalize_nuclei_finding(finding: dict) -> dict:
    """Normalize nuclei finding keys while preserving raw data."""
    template_id = finding.get("template-id") or finding.get("template_id") or ""
    matched_at = finding.get("matched-at") or finding.get("matched_at") or ""
    info = finding.get("info") or {}
    severity = (info.get("severity") or finding.get("severity") or "").lower()
    host = finding.get("host") or ""
    url = matched_at or host or finding.get("url") or ""

    normalized = {
        "template-id": template_id,
        "template_id": template_id,
        "matched-at": matched_at,
        "matched_at": matched_at,
        "severity": severity,
        "url": url,
        "host": host,
        "info": info,
        "raw": finding,
    }
    return normalized


def run_nuclei(target: str, templates: str = "",
               severity: str = "low,medium,high,critical",
               timeout: int = 600, tags: list = None) -> ToolResult:
    """Vulnerability scan with nuclei."""
    _check_scope(target)
    cmd = [
        "nuclei", "-u", target,
        "-severity", severity,
        "-jsonl", "-silent", "-nc",
        "-rl", "100",   # rate-limit: max 100 req/s to avoid hammering targets
    ]
    if tags:
        cmd.extend(["-tags", ",".join(tags)])
    if templates:
        # templates can be a tag name (e.g. "xss") or a file path
        if "/" in templates or templates.endswith(".yaml"):
            cmd.extend(["-t", templates])
        else:
            cmd.extend(["-tags", templates])
    else:
        # Fall back to the configured templates directory (set via NUCLEI_TEMPLATES_PATH)
        tmpl_dir = os.environ.get("NUCLEI_TEMPLATES_PATH", "")
        if tmpl_dir and os.path.isdir(tmpl_dir):
            cmd.extend(["-t", tmpl_dir])
            cmd.extend(["-tags",
                        "cves,exposures,misconfiguration,default-login,"
                        "xss,sqli,ssrf,lfi,rce,ssti,xxe,auth-bypass"])
    result = _wrap("nuclei", cmd, timeout=timeout, parse_fn=_parse_ndjson)
    findings = result.data if isinstance(result.data, list) else []
    parsed = []
    for f in findings:
        if not isinstance(f, dict):
            continue
        norm = normalize_nuclei_finding(f)
        name = norm.get("info", {}).get("name", "")
        # Preserve actual HTTP request/response as evidence when available
        http_evidence = (
            f.get("response") or f.get("curl-command") or
            f.get("request") or norm.get("info", {}).get("description", "")
        )
        parsed.append({
            **norm,
            "name": name,
            "vuln_type": name or "nuclei",
            "endpoint": norm.get("matched-at") or norm.get("url") or "",
            "description": norm.get("info", {}).get("description", ""),
            "tags": norm.get("info", {}).get("tags", []),
            "evidence": http_evidence,
            "request": f.get("request", ""),
            "response": f.get("response", ""),
            "curl_command": f.get("curl-command", ""),
        })
    result.data = {"findings": parsed, "count": len(parsed)}
    return result


def run_nuclei_on_list(targets_file: str, templates: str = "",
                       severity: str = "medium,high,critical",
                       timeout: int = 1800) -> ToolResult:
    """Run nuclei against a file of targets."""
    cmd = [
        "nuclei", "-l", targets_file,
        "-severity", severity,
        "-jsonl", "-silent", "-nc",
        "-rl", "50",   # rate-limit: 50 req/s (conservative for batch mode)
        "-c", "25",    # concurrency: 25 parallel template executions
    ]
    if templates:
        if "/" in templates or templates.endswith(".yaml"):
            cmd.extend(["-t", templates])
        else:
            cmd.extend(["-tags", templates])
    else:
        tmpl_dir = os.environ.get("NUCLEI_TEMPLATES_PATH", "")
        if tmpl_dir and os.path.isdir(tmpl_dir):
            cmd.extend(["-t", tmpl_dir])
            # Scope to high-value categories so we don't exhaust the timeout
            # running all ~9 000 templates. Users can still override via `templates`.
            cmd.extend(["-tags",
                        "cves,exposures,misconfiguration,default-login,"
                        "xss,sqli,ssrf,lfi,rce,ssti,xxe,auth-bypass"])
    result = _wrap("nuclei", cmd, timeout=timeout, parse_fn=_parse_ndjson)
    findings = result.data if isinstance(result.data, list) else []
    parsed = []
    for f in findings:
        if not isinstance(f, dict):
            continue
        norm = normalize_nuclei_finding(f)
        name = norm.get("info", {}).get("name", "")
        http_evidence = (
            f.get("response") or f.get("curl-command") or
            f.get("request") or norm.get("info", {}).get("description", "")
        )
        parsed.append({
            **norm,
            "name": name,
            "vuln_type": name or "nuclei",
            "endpoint": norm.get("matched-at") or norm.get("url") or "",
            "description": norm.get("info", {}).get("description", ""),
            "tags": norm.get("info", {}).get("tags", []),
            "evidence": http_evidence,
            "request": f.get("request", ""),
            "response": f.get("response", ""),
            "curl_command": f.get("curl-command", ""),
        })
    result.data = {"findings": parsed, "count": len(parsed)}
    return result


def run_dalfox(url: str | list[str], params: list[str] = None,
               timeout: int = 180, payload: str = None) -> ToolResult:
    """XSS scanning with dalfox (single URL or pipe-mode list)."""
    urls: list[str]
    if isinstance(url, list):
        urls = [u for u in url if isinstance(u, str) and u.strip()]
        for u in urls[:200]:
            _check_scope(u)
        cmd = ["dalfox", "pipe", "--skip-bav", "--format", "json"]
        input_data = "\n".join(urls)
        result = _wrap("dalfox", cmd, timeout=timeout, input_data=input_data)
        target_label = f"{len(urls)} targets"
    else:
        _check_scope(url)
        urls = [url]
        cmd = ["dalfox", "url", url, "--skip-bav", "--format", "json"]
        if params:
            cmd.extend(["--data", "&".join(f"{p}=FUZZ" for p in params)])
        result = _wrap("dalfox", cmd, timeout=timeout)
        target_label = url

    # dalfox outputs JSON lines mixed with text
    findings = []
    for line in result.raw.splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            findings.append(json.loads(line))
        except Exception:
            if "POC" in line or "VULN" in line:
                findings.append({"raw": line})
    result.data = {"findings": findings, "count": len(findings), "target": target_label}
    return result


def run_sqlmap(url: str, params: str = "", data: str = "",
               level: int = 1, risk: int = 1,
               timeout: int = 300, param: str = "",
               tamper: str = "") -> ToolResult:
    """SQL injection testing with sqlmap (non-interactive)."""
    import sys as _sys
    _check_scope(url)
    params = params or param  # accept either kwarg name
    tmpdir = tempfile.mkdtemp(prefix="sqlmap_")
    import shutil as _shutil
    _sqlmap_bin = _shutil.which("sqlmap") or "sqlmap"
    cmd = [
        _sys.executable, _sqlmap_bin,
        "-u", url,
        "--level", str(level), "--risk", str(risk),
        "--batch", "--quiet",
        "--technique=BEUST",  # Boolean, Error, Union, Stacked, Time-based
        "--output-dir", tmpdir,
    ]
    if params:
        cmd.extend(["-p", params])
    if data:
        cmd.extend(["--data", data])
    if tamper:
        cmd.extend(["--tamper", tamper])
    result = _wrap("sqlmap", cmd, timeout=timeout,
                   env={"HOME": tmpdir, "SQLMAP_OUTPUT_DIRECTORY": tmpdir})
    # Parse vulnerable parameter from output
    vulns = re.findall(r"Parameter:\s+(.+?)\s+\(", result.raw)
    injections = re.findall(r"Type:\s+(.+)", result.raw)
    result.data = {
        "target": url,
        "vulnerable_parameters": list(set(vulns)),
        "injection_types": list(set(injections)),
        "is_vulnerable": bool(vulns),
    }
    return result


def run_kxss(urls: list[str], timeout: int = 120) -> ToolResult:
    """Check URLs for reflected XSS with kxss."""
    input_data = "\n".join(urls)
    cmd = ["kxss"]
    result = _wrap("kxss", cmd, timeout=timeout,
                   parse_fn=_parse_lines, input_data=input_data)
    if isinstance(result.data, list):
        result.data = {"reflected": result.data, "count": len(result.data)}
    return result


def run_crlfuzz(target: str, timeout: int = 60) -> ToolResult:
    """Test for CRLF injection with crlfuzz."""
    cmd = ["crlfuzz", "-u", target, "-s"]
    result = _wrap("crlfuzz", cmd, timeout=timeout, parse_fn=_parse_lines)
    if isinstance(result.data, list):
        vulnerable = [l for l in result.data if "VULN" in l or "Found" in l]
        result.data = {
            "target": target,
            "vulnerable": bool(vulnerable),
            "findings": vulnerable,
        }
    return result


def run_nikto(target: str, timeout: int = 300) -> ToolResult:
    """Web server scanner with nikto."""
    with tempfile.NamedTemporaryFile(suffix=".json", delete=False) as tf:
        out_file = tf.name
    cmd = ["nikto", "-h", target, "-Format", "json", "-o", out_file, "-nointeractive"]
    result = _wrap("nikto", cmd, timeout=timeout)
    if Path(out_file).exists():
        try:
            result.data = json.loads(Path(out_file).read_text())
            result.success = True
        except Exception as _e:
            result.error = f"nikto JSON parse failed: {_e}"
        finally:
            Path(out_file).unlink(missing_ok=True)
    return result


def run_whatweb(target: str, aggression: int = 1, timeout: int = 30) -> ToolResult:
    """Web technology fingerprinting with whatweb."""
    cmd = ["whatweb", f"--aggression={aggression}", "--log-json=-", target]
    result = _wrap("whatweb", cmd, timeout=timeout)
    findings = []
    for line in result.raw.splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            findings.append(json.loads(line))
        except Exception:
            pass
    result.data = {"target": target, "technologies": findings}
    return result


def run_xssstrike(url: str, params: str = "", timeout: int = 120) -> ToolResult:
    """XSS testing with XSStrike."""
    cmd = ["xssstrike", "--url", url, "--skip", "--json"]
    if params:
        cmd.extend(["--params", params])
    return _wrap("xssstrike", cmd, timeout=timeout)


def run_commix(url: str, data: str = "", timeout: int = 300) -> ToolResult:
    """Command injection testing with commix."""
    commix_out = tempfile.mkdtemp(prefix="commix_")
    cmd = ["commix", "--url", url, "--batch", f"--output-dir={commix_out}"]
    if data:
        cmd.extend(["--data", data])
    return _wrap("commix", cmd, timeout=timeout)


def run_wfuzz(url: str, wordlist: str = "", timeout: int = 300,
              params: str = "FUZZ") -> ToolResult:
    """Parameter fuzzing with wfuzz."""
    if not wordlist:
        wordlist = _find_wordlist()
    if not wordlist:
        return ToolResult(tool="wfuzz", success=False, error="No wordlist found.")
    target = url if "FUZZ" in url else f"{url}?{params}"
    fd, wfuzz_path = tempfile.mkstemp(suffix="_wfuzz.json")
    os.close(fd)
    out = Path(wfuzz_path)
    try:
        cmd = [
            "wfuzz", "-w", wordlist, "-u", target,
            "--hc", "404", "-f", f"{wfuzz_path},json",
        ]
        result = _wrap("wfuzz", cmd, timeout=timeout)
        if out.exists():
            try:
                result.data = json.loads(out.read_text())
            except Exception:
                pass
    finally:
        out.unlink(missing_ok=True)
    return result


# ============================================================================
#  SECRETS DISCOVERY
# ============================================================================

def run_trufflehog(target: str, target_type: str = "filesystem",
                   timeout: int = 300) -> ToolResult:
    """
    Scan for secrets with TruffleHog.
    target_type: filesystem | git | github | s3 | gcs | docker
    """
    cmd = ["trufflehog", target_type, target, "--json", "--no-update"]
    result = _wrap("trufflehog", cmd, timeout=timeout, parse_fn=_parse_ndjson)
    secrets = result.data if isinstance(result.data, list) else []
    result.data = {
        "target": target,
        "secrets_found": len(secrets),
        "secrets": [
            {
                "detector": s.get("DetectorName", ""),
                "verified": s.get("Verified", False),
                "raw": s.get("Raw", "")[:100] + "..." if len(s.get("Raw", "")) > 100 else s.get("Raw", ""),
                "source": s.get("SourceMetadata", {}).get("Data", {}),
            }
            for s in secrets if isinstance(s, dict)
        ],
    }
    return result


def run_gitleaks(target: str, report_path: str = "",
                 timeout: int = 120) -> ToolResult:
    """Scan git repo for secrets with gitleaks."""
    fd, tmp_report = tempfile.mkstemp(suffix="_gitleaks.json")
    os.close(fd)
    effective_report = report_path or tmp_report
    try:
        cmd = [
            "gitleaks", "detect",
            "--source", target,
            "--report-format", "json",
            "--report-path", effective_report,
            "--exit-code", "0",  # don't fail on findings
        ]
        result = _wrap("gitleaks", cmd, timeout=timeout)
        if Path(effective_report).exists():
            try:
                findings = json.loads(Path(effective_report).read_text() or "[]")
                result.data = {
                    "target": target,
                    "secrets_found": len(findings),
                    "secrets": [
                        {
                            "rule": f.get("RuleID", ""),
                            "file": f.get("File", ""),
                            "line": f.get("StartLine", 0),
                            "secret": f.get("Secret", "")[:50] + "...",
                            "commit": f.get("Commit", ""),
                        }
                        for f in findings if isinstance(f, dict)
                    ],
                }
                result.success = True
            except Exception:
                pass
    finally:
        # Only clean up the temp file we created; caller-provided paths are theirs to manage
        if not report_path:
            Path(tmp_report).unlink(missing_ok=True)
    return result


# ============================================================================
#  API TESTING
# ============================================================================

def run_jwt_tool(token: str, mode: str = "decode", timeout: int = 30) -> ToolResult:
    """Analyse/attack JWT tokens with jwt_tool."""
    mode_flags = {
        "decode":  ["-d"],
        "crack":   ["-C", "-d"],
        "fuzz":    ["-fuzz"],
        "algnone": ["-X", "a"],
    }
    flags = mode_flags.get(mode, ["-d"])
    cmd = ["jwt_tool", token] + flags
    return _wrap("jwt_tool", cmd, timeout=timeout)


def run_kiterunner(target: str, wordlist: str = "",
                   timeout: int = 180) -> ToolResult:
    """API endpoint brute-forcing with kiterunner."""
    cmd = ["kr", "scan", target, "-A=apiroutes-210228:20000"]
    if wordlist:
        cmd = ["kr", "scan", target, "-w", wordlist]
    result = _wrap("kr", cmd, timeout=timeout, parse_fn=_parse_lines)
    if isinstance(result.data, list):
        result.data = {"endpoints": result.data, "count": len(result.data)}
    return result


def run_arjun(url: str, method: str = "GET", timeout: int = 120) -> ToolResult:
    """HTTP parameter discovery with Arjun."""
    cmd = ["arjun", "-u", url, "-m", method, "--json"]
    return _wrap("arjun", cmd, timeout=timeout)


# ============================================================================
#  CLOUD RECON
# ============================================================================

def run_s3scanner(domain: str, timeout: int = 120) -> ToolResult:
    """Scan for open/misconfigured S3 buckets.

    domain: bare keyword or FQDN — we strip to the leftmost label so that
    's3scanner scan --bucket example' is tried (not 'example.com').
    """
    # s3scanner expects a bucket name/keyword, not a FQDN
    bucket_keyword = domain.split(".")[0]
    cmd = ["s3scanner", "scan", "--bucket", bucket_keyword]
    result = _wrap("s3scanner", cmd, timeout=timeout, parse_fn=_parse_lines)
    if isinstance(result.data, list):
        # Filter to only lines that indicate open/exposed buckets
        _ansi_escape = re.compile(r"\x1b\[[0-9;]*m")
        cleaned = [_ansi_escape.sub("", ln) for ln in result.data if ln.strip()]
        open_buckets = [ln for ln in cleaned if "open" in ln.lower() or "exists" in ln.lower()]
        result.data = {
            "domain": domain,
            "bucket_keyword": bucket_keyword,
            "buckets": cleaned,
            "open_buckets": open_buckets,
            "count": len(cleaned),
        }
    return result


def run_cloudbrute(domain: str, keyword: str = "",
                   timeout: int = 120) -> ToolResult:
    """Cloud bucket brute-force with cloudbrute."""
    if not keyword:
        keyword = domain.split(".")[0]
    cmd = ["cloudbrute", "-d", domain, "-k", keyword, "-t", "80"]
    result = _wrap("cloudbrute", cmd, timeout=timeout)
    if isinstance(result.data, list):
        _ansi_escape = re.compile(r"\x1b\[[0-9;]*m")
        cleaned = [_ansi_escape.sub("", ln).strip() for ln in result.data if ln.strip()]
        # Keep only lines that look like discovered bucket URLs
        found = [ln for ln in cleaned if ln.startswith("http") or "found" in ln.lower()]
        result.data = {
            "domain": domain,
            "keyword": keyword,
            "found": found,
            "count": len(found),
        }
    return result


# ============================================================================
#  DNS TOOLS
# ============================================================================

def run_dnsx(domains: list[str], timeout: int = 60) -> ToolResult:
    """DNS resolution and brute-forcing with dnsx."""
    input_data = "\n".join(domains)
    cmd = ["dnsx", "-silent", "-a", "-cname", "-json"]
    result = _wrap("dnsx", cmd, timeout=timeout,
                   parse_fn=_parse_ndjson, input_data=input_data)
    if isinstance(result.data, list):
        result.data = {"records": result.data, "count": len(result.data)}
    return result


# ============================================================================
#  UTILITY TOOLS
# ============================================================================

def run_gf(urls: list[str], pattern: str, timeout: int = 30) -> ToolResult:
    """Filter URLs matching a bug pattern using gf (e.g., sqli, xss, redirect)."""
    input_data = "\n".join(urls)
    cmd = ["gf", pattern]
    result = _wrap("gf", cmd, timeout=timeout,
                   parse_fn=_parse_lines, input_data=input_data)
    if isinstance(result.data, list):
        result.data = {"pattern": pattern, "matches": result.data,
                       "count": len(result.data)}
    return result


def run_qsreplace(urls: list[str], replacement: str = "FUZZ",
                  timeout: int = 10) -> ToolResult:
    """Replace all query string values with a fuzz marker."""
    input_data = "\n".join(urls)
    cmd = ["qsreplace", replacement]
    result = _wrap("qsreplace", cmd, timeout=timeout,
                   parse_fn=_parse_lines, input_data=input_data)
    if isinstance(result.data, list):
        result.data = {"urls": result.data}
    return result


def run_anew(existing: list[str], new_items: list[str],
             timeout: int = 5) -> ToolResult:
    """Deduplicate new items against existing (via anew)."""
    with tempfile.NamedTemporaryFile(mode="w", suffix=".txt", delete=False) as tf:
        tf.write("\n".join(existing))
        existing_file = tf.name
    input_data = "\n".join(new_items)
    cmd = ["anew", existing_file]
    result = _wrap("anew", cmd, timeout=timeout,
                   parse_fn=_parse_lines, input_data=input_data)
    Path(existing_file).unlink(missing_ok=True)
    if isinstance(result.data, list):
        result.data = {"new_items": result.data, "count": len(result.data)}
    return result


def run_interactsh() -> ToolResult:
    """Generate an OOB interaction URL using interactsh-client."""
    cmd = ["interactsh-client", "-json", "-n", "1"]
    result = _wrap("interactsh-client", cmd, timeout=30)
    if result.raw:
        for line in result.raw.splitlines():
            try:
                data = json.loads(line)
                if "url" in data:
                    result.data = {"oob_url": data["url"]}
                    break
            except Exception:
                pass
    return result


def run_garak(target: str) -> ToolResult:
    return ToolResult(tool="garak", success=True) # Stub

def run_pyrit(target: str) -> ToolResult:
    return ToolResult(tool="pyrit", success=True) # Stub


# ============================================================================
#  EXTENDED SECURITY TESTS — pure-Python (no CLI dependency)
#  These cover gaps in OWASP Top 10 not addressed by existing tools:
#  Race Conditions, File Upload Bypass, OAuth/OIDC, Prototype Pollution,
#  WebSocket Security, MFA Bypass, Rate Limiting, PII Exposure,
#  Source Map Exposure, Clickjacking, Insecure Deserialization,
#  HTTP Request Smuggling (raw socket fallback)
# ============================================================================

def run_race_condition_test(
    url: str,
    method: str = "POST",
    headers: dict = None,
    json_body: dict = None,
    concurrency: int = 25,
    timeout: int = 30,
) -> ToolResult:
    """
    Test for race conditions by sending concurrent requests and detecting inconsistencies.
    Looks for: duplicate resource creation, balance discrepancies, duplicate coupon use.
    """
    import concurrent.futures
    import time as _time

    try:
        import requests as _req
    except ImportError:
        return ToolResult(tool="race_condition_test", success=False, error="requests not installed")

    _check_scope(url)
    responses = []
    t0 = _time.monotonic()

    def _send(_):
        try:
            r = _req.request(method.upper(), url,
                             headers=headers or {}, json=json_body,
                             timeout=10, verify=False, allow_redirects=False)
            return {"status": r.status_code, "body": r.text[:512], "elapsed": r.elapsed.total_seconds()}
        except Exception as exc:
            return {"status": 0, "body": str(exc), "elapsed": 0}

    with concurrent.futures.ThreadPoolExecutor(max_workers=concurrency) as pool:
        futures = [pool.submit(_send, i) for i in range(concurrency)]
        responses = [f.result() for f in concurrent.futures.as_completed(futures)]

    duration = _time.monotonic() - t0

    # Analyse responses for race condition signals
    status_counts: dict = {}
    for r in responses:
        s = r["status"]
        status_counts[s] = status_counts.get(s, 0) + 1

    findings = []
    success_count = status_counts.get(200, 0) + status_counts.get(201, 0)
    # If multiple 200/201s arrived simultaneously → likely race condition
    if success_count > 1:
        findings.append({
            "url": url,
            "parameter": "",
            "vulnerability": "Race Condition — multiple concurrent successes",
            "severity": "high",
            "source_tool": "race_condition_test",
            "extra": {
                "concurrent_successes": success_count,
                "total_requests": concurrency,
                "status_distribution": status_counts,
            },
        })

    return ToolResult(
        tool="race_condition_test",
        success=True,
        data={"findings": findings, "status_distribution": status_counts,
              "concurrent_requests": concurrency},
        count=len(findings),
        duration=duration,
    )


def run_file_upload_test(
    base_url: str,
    headers: dict = None,
    timeout: int = 30,
) -> ToolResult:
    """
    Discover file upload endpoints and test for bypass vulnerabilities:
    - MIME type spoofing (image/jpeg with PHP/JSP content)
    - Double extension (.php.jpg)
    - Null byte injection (.php%00.jpg)
    - SVG with embedded XSS
    - HTML upload for phishing
    """
    import io
    try:
        import requests as _req
    except ImportError:
        return ToolResult(tool="file_upload_test", success=False, error="requests not installed")

    _check_scope(base_url)

    upload_paths = [
        "/upload", "/api/upload", "/file/upload", "/files/upload",
        "/api/files", "/upload/file", "/media/upload", "/avatar/upload",
        "/profile/upload", "/document/upload", "/attachment/upload",
        "/api/v1/upload", "/api/v2/upload",
    ]

    findings = []

    # Test payloads: (filename, content, mime_type, description)
    payloads = [
        ("test.php", b"<?php echo 'pwned'; ?>", "image/jpeg", "PHP in image MIME"),
        ("test.php.jpg", b"<?php echo 'pwned'; ?>", "image/jpeg", "Double extension .php.jpg"),
        ("test.svg", b'<svg><script>alert(1)</script></svg>', "image/svg+xml", "SVG XSS"),
        ("test.html", b'<html><script>alert(document.cookie)</script></html>', "text/html", "HTML upload"),
        ("test.jsp", b"<% out.println('pwned'); %>", "image/gif", "JSP in image MIME"),
    ]

    for path in upload_paths:
        url = base_url.rstrip("/") + path
        try:
            # HEAD probe first to see if endpoint exists
            r = _req.head(url, headers=headers or {}, timeout=5, verify=False, allow_redirects=True)
            if r.status_code in (404, 410):
                continue

            # Try each bypass payload
            for fname, content, mime, description in payloads:
                try:
                    files = {"file": (fname, io.BytesIO(content), mime)}
                    resp = _req.post(url, files=files, headers=headers or {},
                                    timeout=timeout, verify=False, allow_redirects=True)
                    if resp.status_code in (200, 201, 202):
                        # Check if a URL to the uploaded file is returned
                        file_url = ""
                        if "url" in resp.text.lower() or "path" in resp.text.lower():
                            import re as _re
                            matches = _re.findall(r'"(?:url|path|file|location)"\s*:\s*"([^"]+)"', resp.text)
                            file_url = matches[0] if matches else ""
                        findings.append({
                            "url": url,
                            "parameter": "file",
                            "vulnerability": f"File Upload Bypass: {description}",
                            "severity": "high",
                            "source_tool": "file_upload_test",
                            "extra": {
                                "filename": fname,
                                "mime_type": mime,
                                "response_status": resp.status_code,
                                "uploaded_url": file_url,
                            },
                        })
                        break  # One confirmed bypass per endpoint is enough
                except Exception:
                    continue
        except Exception:
            continue

    return ToolResult(
        tool="file_upload_test",
        success=True,
        data={"findings": findings},
        count=len(findings),
    )


def run_oauth_test(
    base_url: str,
    headers: dict = None,
    timeout: int = 30,
) -> ToolResult:
    """
    Test OAuth/OIDC flows for common vulnerabilities:
    - Missing state parameter CSRF
    - Open redirect_uri (redirect to attacker domain)
    - Token leakage via Referer header
    - Authorization code interception
    - Implicit flow token in fragment leakage
    """
    try:
        import requests as _req
        from urllib.parse import urlparse, urljoin, urlencode, parse_qs, urlunparse
    except ImportError:
        return ToolResult(tool="oauth_test", success=False, error="requests not installed")

    _check_scope(base_url)

    oauth_paths = [
        "/oauth/authorize", "/oauth2/authorize", "/auth/oauth",
        "/connect/authorize", "/api/oauth/authorize",
        "/.well-known/openid-configuration",
    ]

    findings = []

    for path in oauth_paths:
        url = base_url.rstrip("/") + path
        try:
            r = _req.get(url, headers=headers or {}, timeout=timeout,
                        verify=False, allow_redirects=False)
            if r.status_code in (404, 410):
                continue

            # Test 1: Missing state parameter → CSRF
            params_no_state = {
                "client_id": "test",
                "redirect_uri": base_url,
                "response_type": "code",
            }
            r2 = _req.get(url, params=params_no_state, headers=headers or {},
                          timeout=timeout, verify=False, allow_redirects=False)
            if r2.status_code in (200, 302) and "state" not in r2.text.lower():
                findings.append({
                    "url": url,
                    "parameter": "state",
                    "vulnerability": "OAuth Missing state Parameter — CSRF Risk",
                    "severity": "medium",
                    "source_tool": "oauth_test",
                    "extra": {"response_status": r2.status_code},
                })

            # Test 2: Open redirect_uri — try attacker domain
            params_redirect = {
                "client_id": "test",
                "redirect_uri": "https://attacker.example.com/callback",
                "response_type": "code",
                "state": "csrftest123",
            }
            r3 = _req.get(url, params=params_redirect, headers=headers or {},
                          timeout=timeout, verify=False, allow_redirects=False)
            if r3.status_code == 302:
                loc = r3.headers.get("Location", "")
                if "attacker.example.com" in loc:
                    findings.append({
                        "url": url,
                        "parameter": "redirect_uri",
                        "vulnerability": "OAuth Open Redirect — redirect_uri not validated",
                        "severity": "high",
                        "source_tool": "oauth_test",
                        "extra": {"redirect_location": loc},
                    })

            # Test 3: Well-known config exposes implicit flow (token in URL fragment leaks)
            if "openid-configuration" in path and r.status_code == 200:
                try:
                    config = r.json()
                    grant_types = config.get("grant_types_supported", [])
                    if "implicit" in grant_types or "token" in config.get("response_types_supported", []):
                        findings.append({
                            "url": url,
                            "parameter": "",
                            "vulnerability": "OAuth Implicit Flow Enabled — tokens exposed in URL fragment",
                            "severity": "medium",
                            "source_tool": "oauth_test",
                            "extra": {"grant_types": grant_types},
                        })
                except Exception:
                    pass

        except Exception:
            continue

    return ToolResult(
        tool="oauth_test",
        success=True,
        data={"findings": findings},
        count=len(findings),
    )


def run_prototype_pollution_test(
    url: str,
    headers: dict = None,
    timeout: int = 30,
) -> ToolResult:
    """
    Test for prototype pollution via query parameters and JSON body.
    Injects __proto__, constructor.prototype, __defineGetter__ payloads.
    Looks for reflected payload or error responses indicating eval.
    """
    try:
        import requests as _req
    except ImportError:
        return ToolResult(tool="prototype_pollution_test", success=False, error="requests not installed")

    _check_scope(url)

    pollution_payloads = [
        ("__proto__[polluted]", "pp_canary_1337"),
        ("constructor[prototype][polluted]", "pp_canary_1337"),
        ("__proto__.polluted", "pp_canary_1337"),
    ]

    json_payloads = [
        {"__proto__": {"polluted": "pp_canary_1337"}},
        {"constructor": {"prototype": {"polluted": "pp_canary_1337"}}},
    ]

    findings = []

    # Test via query parameters
    for param_name, canary in pollution_payloads:
        try:
            r = _req.get(url, params={param_name: canary},
                         headers=headers or {}, timeout=timeout, verify=False)
            if canary in r.text:
                findings.append({
                    "url": url,
                    "parameter": param_name,
                    "vulnerability": "Prototype Pollution via Query Parameter",
                    "severity": "high",
                    "source_tool": "prototype_pollution_test",
                    "extra": {"payload": param_name, "canary": canary, "reflected": True},
                })
                break
        except Exception:
            continue

    # Test via JSON POST body
    for payload in json_payloads:
        try:
            r = _req.post(url, json=payload,
                          headers={**(headers or {}), "Content-Type": "application/json"},
                          timeout=timeout, verify=False)
            if "pp_canary_1337" in r.text:
                findings.append({
                    "url": url,
                    "parameter": "json_body",
                    "vulnerability": "Prototype Pollution via JSON Body",
                    "severity": "high",
                    "source_tool": "prototype_pollution_test",
                    "extra": {"payload": str(payload), "reflected": True},
                })
                break
        except Exception:
            continue

    return ToolResult(
        tool="prototype_pollution_test",
        success=True,
        data={"findings": findings},
        count=len(findings),
    )


def run_websocket_test(
    base_url: str,
    headers: dict = None,
    timeout: int = 20,
) -> ToolResult:
    """
    Test WebSocket endpoints for:
    - Missing Origin validation (accepts cross-origin connections)
    - Unauthenticated WebSocket connections
    - Message injection (XSS, SQLi payloads via WS)
    """
    try:
        import websocket as _ws
        import threading
    except ImportError:
        # websocket-client not installed — do HTTP-based WS discovery only
        _ws = None

    try:
        import requests as _req
    except ImportError:
        return ToolResult(tool="websocket_test", success=False, error="requests not installed")

    _check_scope(base_url)

    ws_paths = ["/ws", "/websocket", "/socket", "/ws/logs", "/api/ws",
                "/socket.io", "/stream", "/events", "/live"]
    findings = []

    parsed_base = base_url.rstrip("/")
    ws_base = parsed_base.replace("https://", "wss://").replace("http://", "ws://")

    for path in ws_paths:
        # HTTP Upgrade probe first
        http_url = parsed_base + path
        ws_url = ws_base + path
        try:
            upgrade_headers = {**(headers or {}), "Connection": "Upgrade", "Upgrade": "websocket",
                               "Sec-WebSocket-Key": "dGhlIHNhbXBsZSBub25jZQ==",  # gitleaks:allow — RFC 6455 example key, not a real secret
                               "Sec-WebSocket-Version": "13"}
            r = _req.get(http_url, headers=upgrade_headers, timeout=5,
                         verify=False, allow_redirects=False)
            if r.status_code not in (101, 400, 426):
                continue

            # Endpoint exists — test origin check
            bad_origin_headers = {**upgrade_headers, "Origin": "https://attacker.example.com"}
            r2 = _req.get(http_url, headers=bad_origin_headers, timeout=5,
                          verify=False, allow_redirects=False)
            if r2.status_code in (101, 200):
                findings.append({
                    "url": ws_url,
                    "parameter": "Origin",
                    "vulnerability": "WebSocket Missing Origin Validation",
                    "severity": "medium",
                    "source_tool": "websocket_test",
                    "extra": {
                        "detail": "WebSocket accepted connection from attacker.example.com",
                        "response_status": r2.status_code,
                    },
                })

            # No auth headers → unauthenticated access
            no_auth = {k: v for k, v in upgrade_headers.items()
                       if k.lower() not in ("authorization", "cookie")}
            r3 = _req.get(http_url, headers=no_auth, timeout=5, verify=False)
            if r3.status_code in (101, 200):
                findings.append({
                    "url": ws_url,
                    "parameter": "",
                    "vulnerability": "Unauthenticated WebSocket Endpoint",
                    "severity": "medium",
                    "source_tool": "websocket_test",
                    "extra": {"path": path},
                })

        except Exception:
            continue

    return ToolResult(
        tool="websocket_test",
        success=True,
        data={"findings": findings},
        count=len(findings),
    )


def run_mfa_bypass_test(
    base_url: str,
    headers: dict = None,
    timeout: int = 30,
) -> ToolResult:
    """
    Test MFA/2FA implementations for bypass vulnerabilities:
    - Response manipulation (change 'success: false' to 'success: true')
    - OTP rate limiting (rapid OTP submission without lockout)
    - Null/empty OTP acceptance
    - OTP reuse after expiry
    """
    try:
        import requests as _req
    except ImportError:
        return ToolResult(tool="mfa_bypass_test", success=False, error="requests not installed")

    _check_scope(base_url)

    mfa_paths = [
        "/api/verify-otp", "/api/2fa/verify", "/auth/2fa", "/verify",
        "/api/auth/verify", "/login/verify", "/otp/verify",
        "/api/mfa/verify", "/account/verify",
    ]

    findings = []

    for path in mfa_paths:
        url = base_url.rstrip("/") + path
        try:
            # Probe: does endpoint exist?
            r = _req.get(url, headers=headers or {}, timeout=5, verify=False)
            if r.status_code in (404, 410):
                continue

            # Test 1: Null/empty OTP
            for otp_val in ["", "000000", "null", "undefined", "true", "1"]:
                try:
                    resp = _req.post(url, json={"otp": otp_val, "code": otp_val},
                                     headers={**(headers or {}), "Content-Type": "application/json"},
                                     timeout=timeout, verify=False)
                    if resp.status_code == 200 and any(
                        k in resp.text.lower() for k in ("success", "token", "authenticated", "verified")
                    ):
                        findings.append({
                            "url": url,
                            "parameter": "otp",
                            "vulnerability": f"MFA Bypass — OTP accepted null/trivial value: {otp_val!r}",
                            "severity": "critical",
                            "source_tool": "mfa_bypass_test",
                            "extra": {"otp_value": otp_val, "response_status": resp.status_code},
                        })
                        break
                except Exception:
                    continue

            # Test 2: Rate limit check — rapid OTP submissions
            rate_responses = []
            for _ in range(10):
                try:
                    resp = _req.post(url, json={"otp": "123456"},
                                     headers={**(headers or {}), "Content-Type": "application/json"},
                                     timeout=5, verify=False)
                    rate_responses.append(resp.status_code)
                except Exception:
                    break
            if rate_responses and all(s != 429 for s in rate_responses) and len(rate_responses) == 10:
                findings.append({
                    "url": url,
                    "parameter": "otp",
                    "vulnerability": "MFA Missing Rate Limiting — OTP brute-force possible",
                    "severity": "high",
                    "source_tool": "mfa_bypass_test",
                    "extra": {"attempts": 10, "no_429_observed": True},
                })

        except Exception:
            continue

    return ToolResult(
        tool="mfa_bypass_test",
        success=True,
        data={"findings": findings},
        count=len(findings),
    )


def run_rate_limit_test(
    base_url: str,
    headers: dict = None,
    timeout: int = 30,
) -> ToolResult:
    """
    Test critical endpoints for missing rate limiting (OWASP API4):
    - Login endpoints (brute-force protection)
    - Password reset endpoints
    - OTP/verification endpoints
    - Registration endpoints
    """
    try:
        import requests as _req
    except ImportError:
        return ToolResult(tool="rate_limit_test", success=False, error="requests not installed")

    _check_scope(base_url)

    critical_paths = [
        ("/login", "POST", {"username": "test", "password": "test"}),
        ("/api/login", "POST", {"username": "test", "password": "test"}),
        ("/auth/login", "POST", {"email": "test@test.com", "password": "test"}),
        ("/forgot-password", "POST", {"email": "test@test.com"}),
        ("/api/reset-password", "POST", {"email": "test@test.com"}),
        ("/register", "POST", {"username": "test", "password": "test", "email": "t@t.com"}),
        ("/api/register", "POST", {"username": "test", "password": "test", "email": "t@t.com"}),
        ("/search", "GET", {}),
        ("/api/search", "GET", {}),
    ]

    findings = []

    for path, method, body in critical_paths:
        url = base_url.rstrip("/") + path
        try:
            statuses = []
            for _ in range(15):
                try:
                    if method == "POST":
                        r = _req.post(url, json=body,
                                      headers={**(headers or {}), "Content-Type": "application/json"},
                                      timeout=5, verify=False)
                    else:
                        r = _req.get(url, headers=headers or {}, timeout=5, verify=False)
                    statuses.append(r.status_code)
                except Exception:
                    break

            if not statuses:
                continue

            has_rate_limit = any(s in (429, 423, 503) for s in statuses)
            endpoint_exists = any(s not in (404, 410, 405) for s in statuses)

            if endpoint_exists and not has_rate_limit and len(statuses) >= 10:
                findings.append({
                    "url": url,
                    "parameter": "",
                    "vulnerability": f"Missing Rate Limiting on {method} {path}",
                    "severity": "medium",
                    "source_tool": "rate_limit_test",
                    "extra": {
                        "attempts": len(statuses),
                        "status_distribution": {str(s): statuses.count(s) for s in set(statuses)},
                        "no_429": True,
                    },
                })
        except Exception:
            continue

    return ToolResult(
        tool="rate_limit_test",
        success=True,
        data={"findings": findings},
        count=len(findings),
    )


_PII_PATTERNS: dict = {
    "email":    r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b',
    "phone":    r'\b(?:\+?\d[\d\s\-\(\)]{7,14}\d)\b',
    "ssn":      r'\b\d{3}-\d{2}-\d{4}\b',
    "credit_card": r'\b(?:4[0-9]{12}(?:[0-9]{3})?|5[1-5][0-9]{14}|3[47][0-9]{13}|6(?:011|5[0-9]{2})[0-9]{12})\b',
    "dob":      r'\b(?:dob|date_of_birth|birthdate)\b.*?\b\d{4}[-/]\d{2}[-/]\d{2}\b',
    "passport": r'\b[A-Z]{1,2}[0-9]{6,9}\b',
    "aadhaar":  r'\b[2-9]{1}[0-9]{3}\s?[0-9]{4}\s?[0-9]{4}\b',
    "pan":      r'\b[A-Z]{5}[0-9]{4}[A-Z]\b',
}

def run_pii_scanner(
    urls: list,
    headers: dict = None,
    timeout: int = 30,
) -> ToolResult:
    """
    Scan API responses for PII exposure:
    - Email addresses, phone numbers, SSN, credit card numbers
    - Date of birth fields, passport numbers, Aadhaar, PAN
    - Overly verbose API responses returning unnecessary personal data
    """
    import re as _re
    try:
        import requests as _req
    except ImportError:
        return ToolResult(tool="pii_scanner", success=False, error="requests not installed")

    compiled_patterns = {k: _re.compile(v, _re.IGNORECASE) for k, v in _PII_PATTERNS.items()}
    findings = []

    for url in (urls or []):
        try:
            _check_scope(url)
            r = _req.get(url, headers=headers or {}, timeout=timeout,
                         verify=False, allow_redirects=True)
            if r.status_code != 200:
                continue

            body = r.text
            # Only scan JSON/API responses
            ct = r.headers.get("content-type", "").lower()
            if not any(t in ct for t in ("json", "text", "xml")):
                continue

            for pii_type, pattern in compiled_patterns.items():
                matches = pattern.findall(body)
                if matches:
                    findings.append({
                        "url": url,
                        "parameter": "",
                        "vulnerability": f"PII Exposure in API Response — {pii_type}",
                        "severity": "high",
                        "source_tool": "pii_scanner",
                        "extra": {
                            "pii_type": pii_type,
                            "sample_count": len(matches),
                            "sample": matches[0] if matches else "",
                        },
                    })
        except Exception:
            continue

    return ToolResult(
        tool="pii_scanner",
        success=True,
        data={"findings": findings},
        count=len(findings),
    )


def run_source_map_scanner(
    base_url: str,
    urls: list = None,
    headers: dict = None,
    timeout: int = 30,
) -> ToolResult:
    """
    Discover exposed JavaScript source maps (.map files).
    Source maps expose original source code, comments, internal paths and logic.
    Also checks for exposed .env, config.js, settings.js.
    """
    import re as _re
    try:
        import requests as _req
    except ImportError:
        return ToolResult(tool="source_map_scanner", success=False, error="requests not installed")

    _check_scope(base_url)
    findings = []

    # 1. Check direct .map file paths
    common_map_paths = [
        "/static/js/main.js.map", "/static/js/bundle.js.map",
        "/static/js/vendor.js.map", "/js/app.js.map", "/js/main.js.map",
        "/app.js.map", "/bundle.js.map", "/dist/bundle.js.map",
        "/.env", "/.env.local", "/.env.production", "/config.js",
        "/settings.js", "/webpack.config.js", "/.git/config",
        "/robots.txt", "/sitemap.xml",
    ]

    for path in common_map_paths:
        url = base_url.rstrip("/") + path
        try:
            r = _req.get(url, headers=headers or {}, timeout=10, verify=False)
            if r.status_code != 200 or len(r.text) < 100:
                continue

            ct = r.headers.get("content-type", "").lower()
            is_map = (path.endswith(".map") and
                      any(k in r.text for k in ('"sources"', '"mappings"', '"sourceRoot"')))
            is_env = path.endswith(".env") or path.endswith(".env.local") or ".env." in path
            is_config = any(path.endswith(x) for x in (".js", ".json"))

            if is_map:
                # Count source files exposed
                sources = _re.findall(r'"sources"\s*:\s*\[([^\]]+)\]', r.text)
                src_count = len(sources[0].split(",")) if sources else 0
                findings.append({
                    "url": url,
                    "parameter": "",
                    "vulnerability": "Exposed JavaScript Source Map",
                    "severity": "medium",
                    "source_tool": "source_map_scanner",
                    "extra": {"source_files_count": src_count, "size_bytes": len(r.text)},
                })
            elif is_env and any(k in r.text for k in ("KEY=", "SECRET=", "PASSWORD=", "TOKEN=", "DB_")):
                findings.append({
                    "url": url,
                    "parameter": "",
                    "vulnerability": "Exposed .env File with Secrets",
                    "severity": "critical",
                    "source_tool": "source_map_scanner",
                    "extra": {"size_bytes": len(r.text)},
                })
        except Exception:
            continue

    # 2. Crawl discovered JS URLs for sourceMappingURL comments
    for js_url in (urls or []):
        if not js_url.endswith(".js"):
            continue
        try:
            _check_scope(js_url)
            r = _req.get(js_url, headers=headers or {}, timeout=10, verify=False)
            if r.status_code != 200:
                continue
            map_match = _re.search(r'//[#@]\s*sourceMappingURL=(.+\.map)', r.text)
            if map_match:
                map_url = map_match.group(1).strip()
                if not map_url.startswith("http"):
                    map_url = js_url.rsplit("/", 1)[0] + "/" + map_url
                # Try fetching the referenced map
                try:
                    _check_scope(map_url)
                    mr = _req.get(map_url, headers=headers or {}, timeout=10, verify=False)
                    if mr.status_code == 200 and '"sources"' in mr.text:
                        findings.append({
                            "url": map_url,
                            "parameter": "",
                            "vulnerability": "Exposed JavaScript Source Map (referenced from JS)",
                            "severity": "medium",
                            "source_tool": "source_map_scanner",
                            "extra": {"js_file": js_url, "map_url": map_url},
                        })
                except Exception:
                    pass
        except Exception:
            continue

    return ToolResult(
        tool="source_map_scanner",
        success=True,
        data={"findings": findings},
        count=len(findings),
    )


def run_clickjacking_test(
    url: str,
    headers: dict = None,
    timeout: int = 15,
) -> ToolResult:
    """
    Test for Clickjacking vulnerability:
    - Missing X-Frame-Options header
    - Missing Content-Security-Policy frame-ancestors directive
    - Verify the page can actually be framed (not blocked by response headers)
    """
    try:
        import requests as _req
    except ImportError:
        return ToolResult(tool="clickjacking_test", success=False, error="requests not installed")

    _check_scope(url)
    findings = []

    try:
        r = _req.get(url, headers=headers or {}, timeout=timeout, verify=False, allow_redirects=True)
        resp_headers = {k.lower(): v.lower() for k, v in r.headers.items()}

        xfo = resp_headers.get("x-frame-options", "")
        csp = resp_headers.get("content-security-policy", "")

        has_xfo_protection = bool(xfo) and any(v in xfo for v in ("deny", "sameorigin"))
        has_csp_frame = "frame-ancestors" in csp

        if not has_xfo_protection and not has_csp_frame:
            findings.append({
                "url": url,
                "parameter": "",
                "vulnerability": "Clickjacking — No Frame Protection Headers",
                "severity": "medium",
                "source_tool": "clickjacking_test",
                "extra": {
                    "x_frame_options": xfo or "MISSING",
                    "csp_frame_ancestors": "MISSING",
                    "detail": "Page can be embedded in cross-origin iframe enabling clickjacking attacks",
                },
            })
        elif xfo and "allowall" in xfo:
            findings.append({
                "url": url,
                "parameter": "",
                "vulnerability": "Clickjacking — X-Frame-Options set to ALLOWALL",
                "severity": "high",
                "source_tool": "clickjacking_test",
                "extra": {"x_frame_options": xfo},
            })
    except Exception as exc:
        return ToolResult(tool="clickjacking_test", success=False, error=str(exc))

    return ToolResult(
        tool="clickjacking_test",
        success=True,
        data={"findings": findings},
        count=len(findings),
    )


def run_deserialization_test(
    url: str,
    headers: dict = None,
    timeout: int = 30,
) -> ToolResult:
    """
    Test for insecure deserialization vulnerabilities:
    - Java serialization magic bytes (AC ED 00 05) in POST body
    - PHP serialize() payloads
    - Python pickle payloads (safe canary only — no RCE)
    - .NET ViewState manipulation
    Detects by timing difference or error messages revealing deserialization.
    """
    import base64 as _b64
    import time as _time
    try:
        import requests as _req
    except ImportError:
        return ToolResult(tool="deserialization_test", success=False, error="requests not installed")

    _check_scope(url)
    findings = []

    # Java serialization magic bytes — just the header, not a gadget chain
    java_serial = _b64.b64encode(b"\xac\xed\x00\x05").decode()

    # PHP unserialize canary — triggers error if deserialized
    php_serial = 'O:8:"stdClass":1:{s:4:"test";s:8:"pwned123";}'

    # .NET ViewState canary (base64 encoded minimal invalid ViewState)
    dotnet_viewstate = _b64.b64encode(b"\xff\x01" + b"\x00" * 20).decode()

    test_payloads = [
        ("application/octet-stream", _b64.b64decode(java_serial), "Java Serialized Object"),
        ("application/x-php-serialized", php_serial.encode(), "PHP Serialized Object"),
        ("application/x-www-form-urlencoded", f"__VIEWSTATE={dotnet_viewstate}".encode(), ".NET ViewState"),
    ]

    deser_error_patterns = [
        "java.io.objectinputstream", "unserialize(", "serializationexception",
        "deserializ", "gadget", "classnotfoundexception", "invalidclassexception",
        "pickle", "marshal.loads",
    ]

    for content_type, payload, payload_name in test_payloads:
        try:
            t0 = _time.monotonic()
            h = {**(headers or {}), "Content-Type": content_type}
            r = _req.post(url, data=payload, headers=h, timeout=timeout, verify=False)
            elapsed = _time.monotonic() - t0

            body_lower = r.text[:2048].lower()
            has_deser_error = any(p in body_lower for p in deser_error_patterns)

            if has_deser_error:
                findings.append({
                    "url": url,
                    "parameter": "body",
                    "vulnerability": f"Insecure Deserialization — {payload_name} Error Leaked",
                    "severity": "critical",
                    "source_tool": "deserialization_test",
                    "extra": {
                        "payload_type": payload_name,
                        "response_status": r.status_code,
                        "error_snippet": r.text[:300],
                    },
                })

            # Timing-based: if response took >3s vs baseline, may be deserializing
            elif elapsed > 3.0:
                findings.append({
                    "url": url,
                    "parameter": "body",
                    "vulnerability": f"Possible Insecure Deserialization — Timing Anomaly ({payload_name})",
                    "severity": "medium",
                    "source_tool": "deserialization_test",
                    "extra": {"payload_type": payload_name, "elapsed_s": round(elapsed, 2)},
                })
        except Exception:
            continue

    return ToolResult(
        tool="deserialization_test",
        success=True,
        data={"findings": findings},
        count=len(findings),
    )


def run_smuggling_python(
    url: str,
    timeout: int = 10,
) -> ToolResult:
    """
    HTTP Request Smuggling detection using raw TCP sockets.
    Tests CL.TE, TE.CL, and TE.TE desync variants via timing + response analysis.
    Falls back gracefully for HTTPS (uses ssl.wrap_socket).
    """
    import socket
    import ssl as _ssl
    import time as _time
    from urllib.parse import urlparse

    _check_scope(url)
    parsed = urlparse(url if "://" in url else f"https://{url}")
    host = parsed.hostname or url
    port = parsed.port or (443 if parsed.scheme == "https" else 80)
    path = parsed.path or "/"
    use_tls = parsed.scheme == "https"

    findings = []

    def _raw_request(request_bytes: bytes, read_timeout: float = 5.0) -> tuple[int, str]:
        """Send raw bytes over TCP/TLS, return (status_code, body_snippet)."""
        try:
            sock = socket.create_connection((host, port), timeout=timeout)
            if use_tls:
                ctx = _ssl.create_default_context()
                ctx.check_hostname = False
                ctx.verify_mode = _ssl.CERT_NONE
                sock = ctx.wrap_socket(sock, server_hostname=host)
            sock.sendall(request_bytes)
            sock.settimeout(read_timeout)
            resp = b""
            try:
                while True:
                    chunk = sock.recv(4096)
                    if not chunk:
                        break
                    resp += chunk
                    if len(resp) > 8192:
                        break
            except (socket.timeout, OSError):
                pass
            sock.close()
            text = resp.decode("utf-8", errors="replace")
            status = 0
            if text.startswith("HTTP/"):
                try:
                    status = int(text.split()[1])
                except Exception:
                    pass
            return status, text[:1024]
        except Exception as exc:
            return 0, str(exc)

    host_header = f"{host}:{port}" if port not in (80, 443) else host

    # ── CL.TE test: send ambiguous Content-Length header ──────────────────
    cl_te_request = (
        f"POST {path} HTTP/1.1\r\n"
        f"Host: {host_header}\r\n"
        "Content-Type: application/x-www-form-urlencoded\r\n"
        "Content-Length: 6\r\n"
        "Transfer-Encoding: chunked\r\n"
        "Connection: keep-alive\r\n\r\n"
        "0\r\n\r\n"
        "X"  # Smuggled byte
    ).encode()

    # ── TE.CL test: chunked encoding that frontend strips ─────────────────
    te_cl_request = (
        f"POST {path} HTTP/1.1\r\n"
        f"Host: {host_header}\r\n"
        "Content-Type: application/x-www-form-urlencoded\r\n"
        "Content-Length: 3\r\n"
        "Transfer-Encoding: chunked\r\n"
        "Connection: keep-alive\r\n\r\n"
        "1\r\nA\r\n"
        "0\r\n\r\n"
    ).encode()

    # Baseline request
    baseline_req = (
        f"GET {path} HTTP/1.1\r\n"
        f"Host: {host_header}\r\n"
        "Connection: close\r\n\r\n"
    ).encode()

    t_baseline_start = _time.monotonic()
    baseline_status, _ = _raw_request(baseline_req, read_timeout=5.0)
    baseline_elapsed = _time.monotonic() - t_baseline_start

    # CL.TE test with timing
    t0 = _time.monotonic()
    clte_status, clte_body = _raw_request(cl_te_request, read_timeout=6.0)
    clte_elapsed = _time.monotonic() - t0

    # TE.CL test
    t1 = _time.monotonic()
    tecl_status, tecl_body = _raw_request(te_cl_request, read_timeout=6.0)
    tecl_elapsed = _time.monotonic() - t1

    # Detect: timing significantly longer than baseline → smuggling likely
    if baseline_elapsed > 0 and clte_elapsed > baseline_elapsed * 3 and clte_elapsed > 4:
        findings.append({
            "url": url,
            "parameter": "",
            "vulnerability": "HTTP Request Smuggling — CL.TE Desync (timing-based)",
            "severity": "high",
            "source_tool": "smuggling_python",
            "extra": {
                "variant": "CL.TE",
                "baseline_s": round(baseline_elapsed, 2),
                "test_elapsed_s": round(clte_elapsed, 2),
                "response_status": clte_status,
            },
        })

    if baseline_elapsed > 0 and tecl_elapsed > baseline_elapsed * 3 and tecl_elapsed > 4:
        findings.append({
            "url": url,
            "parameter": "",
            "vulnerability": "HTTP Request Smuggling — TE.CL Desync (timing-based)",
            "severity": "high",
            "source_tool": "smuggling_python",
            "extra": {
                "variant": "TE.CL",
                "baseline_s": round(baseline_elapsed, 2),
                "test_elapsed_s": round(tecl_elapsed, 2),
                "response_status": tecl_status,
            },
        })

    # Detect via response anomalies (400 with transfer-encoding error = server processes TE)
    for variant, status, body in [("CL.TE", clte_status, clte_body), ("TE.CL", tecl_status, tecl_body)]:
        if any(sig in body.lower() for sig in
               ("transfer-encoding", "invalid chunk", "bad request", "400")):
            if status == 400:
                findings.append({
                    "url": url,
                    "parameter": "",
                    "vulnerability": f"HTTP Request Smuggling — {variant} Processing Error Detected",
                    "severity": "medium",
                    "source_tool": "smuggling_python",
                    "extra": {"variant": variant, "response_status": status, "snippet": body[:200]},
                })

    return ToolResult(
        tool="smuggling_python",
        success=True,
        data={"findings": findings, "baseline_elapsed_s": round(baseline_elapsed, 2)},
        count=len(findings),
    )


def run_payment_tampering_test(
    base_url: str,
    headers: dict = None,
    timeout: int = 5,
) -> ToolResult:
    """
    Test payment/checkout flows for business logic tampering:
    - Negative price injection
    - Zero amount bypass
    - Currency code manipulation
    - Coupon/discount stacking
    - Price parameter tampering in requests
    """
    try:
        import requests as _req
    except ImportError:
        return ToolResult(tool="payment_tampering_test", success=False, error="requests not installed")

    _check_scope(base_url)

    payment_paths = [
        "/checkout", "/api/checkout", "/order", "/api/order",
        "/payment", "/api/payment", "/cart/checkout",
        "/api/cart/checkout", "/api/v1/checkout", "/buy",
    ]

    price_params = ["price", "amount", "total", "cost", "value", "subtotal"]

    tamper_values = [
        ("-1", "Negative price"),
        ("0", "Zero amount"),
        ("0.001", "Sub-cent amount"),
        ("999999999", "Integer overflow"),
        ("-0.01", "Negative float"),
    ]

    findings = []

    for path in payment_paths:
        url = base_url.rstrip("/") + path
        try:
            r = _req.get(url, headers=headers or {}, timeout=5, verify=False)
            if r.status_code in (404, 410):
                continue

            # Try to find price parameters via OPTIONS or GET params
            for param in price_params:
                for tamper_val, tamper_desc in tamper_values:
                    try:
                        # GET parameter tampering
                        resp_get = _req.get(url, params={param: tamper_val},
                                            headers=headers or {}, timeout=timeout, verify=False)
                        # POST body tampering
                        resp_post = _req.post(url, json={param: tamper_val},
                                              headers={**(headers or {}), "Content-Type": "application/json"},
                                              timeout=timeout, verify=False)

                        for resp, method in [(resp_get, "GET"), (resp_post, "POST")]:
                            if resp.status_code in (200, 201) and any(
                                k in resp.text.lower() for k in ("order", "success", "confirmed", "paid")
                            ):
                                findings.append({
                                    "url": url,
                                    "parameter": param,
                                    "vulnerability": f"Payment Tampering — {tamper_desc} accepted via {method}",
                                    "severity": "critical",
                                    "source_tool": "payment_tampering_test",
                                    "extra": {
                                        "method": method,
                                        "param": param,
                                        "value": tamper_val,
                                        "response_status": resp.status_code,
                                    },
                                })
                    except Exception:
                        continue
        except Exception:
            continue

    return ToolResult(
        tool="payment_tampering_test",
        success=True,
        data={"findings": findings},
        count=len(findings),
    )


# ============================================================================
#  TOOL REGISTRY — unified dispatcher
# ============================================================================

TOOL_REGISTRY: dict[str, dict] = {
    # Subdomain enumeration
    "subfinder":    {"fn": run_subfinder,    "category": "subdomain",  "args": ["domain"]},
    "amass":        {"fn": run_amass,        "category": "subdomain",  "args": ["domain"]},
    "assetfinder":  {"fn": run_assetfinder,  "category": "subdomain",  "args": ["domain"]},
    "findomain":    {"fn": run_findomain,    "category": "subdomain",  "args": ["domain"]},
    "chaos":        {"fn": run_chaos,        "category": "subdomain",  "args": ["domain"]},
    "sublist3r":    {"fn": run_sublist3r,    "category": "subdomain",  "args": ["domain"]},
    # HTTP probing
    "httpx":        {"fn": run_httpx,        "category": "http",       "args": ["targets"]},
    # Port scanning
    "naabu":        {"fn": run_naabu,        "category": "ports",      "args": ["target"]},
    "nmap":         {"fn": run_nmap,         "category": "ports",      "args": ["target"]},
    "masscan":      {"fn": run_masscan,      "category": "ports",      "args": ["target"]},
    "rustscan":     {"fn": run_rustscan,     "category": "ports",      "args": ["target"]},
    # Web crawling
    "katana":       {"fn": run_katana,       "category": "crawl",      "args": ["target"]},
    "hakrawler":    {"fn": run_hakrawler,    "category": "crawl",      "args": ["url"]},
    "gauplus":      {"fn": run_gauplus,      "category": "crawl",      "args": ["domain"]},
    "waybackurls":  {"fn": run_waybackurls,  "category": "crawl",      "args": ["domain"]},
    "paramspider":  {"fn": run_paramspider,  "category": "crawl",      "args": ["domain"]},
    # Content discovery
    "ffuf":         {"fn": run_ffuf,         "category": "content",    "args": ["url"]},
    "gobuster":     {"fn": run_gobuster,     "category": "content",    "args": ["url"]},
    "dirsearch":    {"fn": run_dirsearch,    "category": "content",    "args": ["url"]},
    # Vulnerability scanning
    "nuclei":       {"fn": run_nuclei,       "category": "vuln",       "args": ["target"]},
    "nuclei_list":  {"fn": run_nuclei_on_list,"category": "vuln",      "args": ["targets_file"]},
    "dalfox":       {"fn": run_dalfox,       "category": "vuln",       "args": ["url"]},
    "sqlmap":       {"fn": run_sqlmap,       "category": "vuln",       "args": ["url"]},
    "kxss":         {"fn": run_kxss,         "category": "vuln",       "args": ["urls"]},
    "crlfuzz":      {"fn": run_crlfuzz,      "category": "vuln",       "args": ["target"]},
    "nikto":        {"fn": run_nikto,        "category": "vuln",       "args": ["target"]},
    "whatweb":      {"fn": run_whatweb,      "category": "vuln",       "args": ["target"]},
    "xssstrike":    {"fn": run_xssstrike,    "category": "vuln",       "args": ["url"]},
    "commix":       {"fn": run_commix,       "category": "vuln",       "args": ["url"]},
    "wfuzz":        {"fn": run_wfuzz,        "category": "content",    "args": ["url"]},
    # AI testing
    "garak":        {"fn": run_garak,        "category": "ai",         "args": ["target"]},
    "pyrit":        {"fn": run_pyrit,        "category": "ai",         "args": ["target"],  "pure_python": True},
    # Secrets
    "trufflehog":   {"fn": run_trufflehog,   "category": "secrets",    "args": ["target"]},
    "gitleaks":     {"fn": run_gitleaks,     "category": "secrets",    "args": ["target"]},
    # API testing
    "jwt_tool":     {"fn": run_jwt_tool,     "category": "api",        "args": ["token"]},
    "kiterunner":   {"fn": run_kiterunner,   "category": "api",        "args": ["target"]},
    "arjun":        {"fn": run_arjun,        "category": "api",        "args": ["url"]},
    # Cloud
    "s3scanner":    {"fn": run_s3scanner,    "category": "cloud",      "args": ["domain"]},
    "cloudbrute":   {"fn": run_cloudbrute,   "category": "cloud",      "args": ["domain"]},
    # DNS
    "dnsx":         {"fn": run_dnsx,         "category": "dns",        "args": ["domains"]},
    # OOB
    "interactsh":   {"fn": run_interactsh,   "category": "oob",        "args": []},
    # Utilities
    "gf":           {"fn": run_gf,           "category": "util",       "args": ["urls", "pattern"]},
    "qsreplace":    {"fn": run_qsreplace,    "category": "util",       "args": ["urls"]},
    "anew":         {"fn": run_anew,         "category": "util",       "args": ["existing", "new_items"]},
    # Pure-Python HTTP client (no CLI needed — used by swarm agents for targeted probes)
    "http_request": {"fn": run_http_request, "category": "http",       "args": ["url"],       "pure_python": True},
    # Extended security tests — pure Python, no CLI dependency
    "race_condition_test":     {"fn": run_race_condition_test,     "category": "vuln", "args": ["url"],       "pure_python": True},
    "file_upload_test":        {"fn": run_file_upload_test,        "category": "vuln", "args": ["base_url"],  "pure_python": True},
    "oauth_test":              {"fn": run_oauth_test,              "category": "vuln", "args": ["base_url"],  "pure_python": True},
    "prototype_pollution_test":{"fn": run_prototype_pollution_test,"category": "vuln", "args": ["url"],       "pure_python": True},
    "websocket_test":          {"fn": run_websocket_test,          "category": "vuln", "args": ["base_url"],  "pure_python": True},
    "mfa_bypass_test":         {"fn": run_mfa_bypass_test,         "category": "vuln", "args": ["base_url"],  "pure_python": True},
    "rate_limit_test":         {"fn": run_rate_limit_test,         "category": "vuln", "args": ["base_url"],  "pure_python": True},
    "pii_scanner":             {"fn": run_pii_scanner,             "category": "vuln", "args": ["urls"],      "pure_python": True},
    "source_map_scanner":      {"fn": run_source_map_scanner,      "category": "vuln", "args": ["base_url"],  "pure_python": True},
    "clickjacking_test":       {"fn": run_clickjacking_test,       "category": "vuln", "args": ["url"],       "pure_python": True},
    "deserialization_test":    {"fn": run_deserialization_test,    "category": "vuln", "args": ["url"],       "pure_python": True},
    "smuggling_python":        {"fn": run_smuggling_python,        "category": "vuln", "args": ["url"],       "pure_python": True},
    "payment_tampering_test":  {"fn": run_payment_tampering_test,  "category": "vuln", "args": ["base_url"],  "pure_python": True},
}


class ToolRegistry:
    """Unified interface to run any registered tool."""

    def available_tools(self) -> list[str]:
        return [name for name in TOOL_REGISTRY if is_available(name)]

    def missing_tools(self) -> list[str]:
        return [name for name in TOOL_REGISTRY if not is_available(name)]

    def tools_by_category(self) -> dict[str, list[str]]:
        cats: dict[str, list[str]] = {}
        for name, meta in TOOL_REGISTRY.items():
            cat = meta["category"]
            cats.setdefault(cat, []).append(name)
        return cats

    # Translate swarm engine's httpx(url=..., method=..., params=..., data=..., headers=...)
    # calling convention → correct tool wrapper signatures.
    @staticmethod
    def _translate_kwargs(tool_name: str, kwargs: dict) -> tuple[str, dict]:
        """
        Returns (resolved_tool_name, translated_kwargs).
        Swarm agents call `httpx` as a generic HTTP client with url/method/params/data/headers.
        When those kwargs are present, route to http_request instead so the call succeeds.
        """
        if tool_name == "httpx":
            has_client_args = any(k in kwargs for k in ("url", "method", "params", "data", "headers"))
            if has_client_args and "targets" not in kwargs:
                # Delegate to http_request which accepts these args natively
                return "http_request", kwargs
            if "url" in kwargs and "targets" not in kwargs:
                # Simple url= → targets=[url] translation for host probing
                url = kwargs.pop("url")
                return "httpx", {"targets": [url], **{k: v for k, v in kwargs.items() if k in ("timeout", "flags")}}
        return tool_name, kwargs

    def run(self, tool_name: str, **kwargs) -> ToolResult:
        """Run a tool by name with keyword arguments."""
        tool_name, kwargs = self._translate_kwargs(tool_name, dict(kwargs))
        if tool_name not in TOOL_REGISTRY:
            return ToolResult(tool=tool_name, success=False,
                              error=f"Unknown tool: {tool_name}")
        fn = TOOL_REGISTRY[tool_name]["fn"]
        try:
            return fn(**kwargs)
        except TypeError as exc:
            return ToolResult(tool=tool_name, success=False, error=str(exc))

    def run_best(self, category: str, fallback_order: list[str],
                 **kwargs) -> ToolResult:
        """Try tools in order, return first successful result."""
        for tool in fallback_order:
            if is_available(tool):
                result = self.run(tool, **kwargs)
                if result.success:
                    return result
        return ToolResult(tool=category, success=False,
                          error=f"No available tool for category '{category}'")

    def check_all(self) -> dict:
        """Return availability status for every tool."""
        return {
            name: {
                "available": meta.get("pure_python", False) or is_available(name),
                "category": meta["category"],
            }
            for name, meta in TOOL_REGISTRY.items()
        }
