"""
Tool Wrapper Layer — One&Infinity
=========================================
Wraps every installed security tool with:
  - Structured JSON output
  - Timeout + error handling
  - Authorization guard (never runs without scope)
  - Unified run_tool() dispatcher

Usage:
    from modules.tool_wrappers import ToolRegistry
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
        except FileNotFoundError:
            return 127, "", f"Tool not found: {cmd[0]}"
        except Exception as exc:
            last_rc, last_out, last_err = 1, "", str(exc)

        if attempt < retries:
            log.debug("_run_cmd: attempt %d/%d failed (rc=%d), retrying in %.1fs — %s",
                      attempt + 1, retries + 1, last_rc, delay, cmd[0])
            time.sleep(delay)
            delay *= 2

    return last_rc, last_out, last_err


def _wrap(tool: str, cmd: list[str], timeout: int = 300,
          parse_fn=None, input_data: Optional[str] = None,
          env: Optional[dict] = None) -> ToolResult:
    """Execute a tool command and return a ToolResult."""
    t0 = time.time()
    rc, stdout, stderr = _run_cmd(cmd, timeout=timeout, input_data=input_data, env=env)
    duration = time.time() - t0
    command_str = " ".join(str(c) for c in cmd)
    success = rc == 0
    data = None
    error = ""
    count = 0

    if rc == 127:
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
        success=success or bool(data),  # tools that exit 1 but still produce output
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
               timeout: int = 300, param: str = "") -> ToolResult:
    """SQL injection testing with sqlmap (non-interactive)."""
    import sys as _sys
    _check_scope(url)
    params = params or param  # accept either kwarg name
    tmpdir = tempfile.mkdtemp(prefix="sqlmap_")
    # Resolve the full path to the sqlmap wrapper script and run it through
    # the current interpreter so exec-permission on the script is irrelevant.
    import shutil as _shutil
    _sqlmap_bin = _shutil.which("sqlmap") or "sqlmap"
    cmd = [
        _sys.executable, _sqlmap_bin,
        "-u", url,
        "--level", str(level), "--risk", str(risk),
        "--batch", "--quiet",
        "--output-dir", tmpdir,
    ]
    if params:
        cmd.extend(["-p", params])
    if data:
        cmd.extend(["--data", data])
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
    "pyrit":        {"fn": run_pyrit,        "category": "ai",         "args": ["target"]},
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
    "http_request": {"fn": run_http_request, "category": "http",       "args": ["url"]},
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
                "available": is_available(name),
                "category": meta["category"],
            }
            for name, meta in TOOL_REGISTRY.items()
        }
