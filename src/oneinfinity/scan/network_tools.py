"""
network_tools.py — wrappers for Go network tools (oi-credential-spray, oi-service-cve-mapper).

Both binaries are expected on PATH or in the same Go bin paths as other oi-* tools.
Falls back gracefully when binaries are absent so the scan pipeline still runs.
"""
from __future__ import annotations

import json
import logging
import os
import shutil
import subprocess
import tempfile
import time
from dataclasses import dataclass
from typing import List, Optional

log = logging.getLogger(__name__)

# ── Binary resolution ─────────────────────────────────────────────────────────

_GOBIN_PATHS = [
    os.path.expanduser("~/go/bin"),
    "/usr/local/go/bin",
    "/usr/local/bin",
    "/usr/bin",
]


def _find_binary(name: str) -> Optional[str]:
    """Locate a Go binary by checking GOBIN, PATH, and known install directories."""
    # Try shutil.which against the augmented PATH first
    path_env = os.pathsep.join(
        [os.environ.get("PATH", ""), *_GOBIN_PATHS]
    )
    found = shutil.which(name, path=path_env)
    if found:
        return found
    # Direct path probes (built-in-place by CI)
    here = os.path.dirname(os.path.abspath(__file__))
    repo_root = os.path.normpath(os.path.join(here, "..", "..", ".."))
    candidates = [
        os.path.join(repo_root, "src", "go", name, name),
        os.path.join(repo_root, "src", "go", name, name.replace("-", "_")),
    ]
    for c in candidates:
        if os.path.isfile(c) and os.access(c, os.X_OK):
            return c
    return None


# ── Credential spray ──────────────────────────────────────────────────────────

def run_credential_spray(
    target: str,
    userlist: list,
    passlist: list,
    services: list = None,
    rate: int = 10,
    timeout: int = 60,
) -> list:
    """Run oi-credential-spray against *target*.

    Parameters
    ----------
    target:   ``host`` or ``host:port`` to spray.
    userlist: list of username strings.
    passlist: list of password strings.
    services: list of service names (ssh, ftp, http-basic, smb, rdp,
              mysql, postgres, redis, mongodb). Defaults to all.
    rate:     max requests per second (default 10).
    timeout:  overall timeout in seconds (default 60).

    Returns
    -------
    List of finding dicts matching the NDJSON schema:
    ``{service, host, port, username, password, success, note?, ts}``
    """
    binary = _find_binary("oi-credential-spray")
    if not binary:
        log.warning("oi-credential-spray not found — skipping credential spray")
        return []

    if not userlist or not passlist:
        log.debug("credential_spray: empty user or password list — skipping")
        return []

    # Parse host:port if combined
    host = target
    port_override = 0
    if ":" in target:
        parts = target.rsplit(":", 1)
        if parts[1].isdigit():
            host, port_override = parts[0], int(parts[1])

    svc_str = ",".join(services) if services else "ssh,ftp,http-basic,smb,rdp,mysql,postgres,redis,mongodb"

    t0 = time.monotonic()
    with tempfile.TemporaryDirectory(prefix="oi-spray-") as tmpdir:
        user_file = os.path.join(tmpdir, "users.txt")
        pass_file = os.path.join(tmpdir, "passwords.txt")
        with open(user_file, "w") as f:
            f.write("\n".join(userlist))
        with open(pass_file, "w") as f:
            f.write("\n".join(passlist))

        cmd = [
            binary,
            "-host", host,
            "-users", user_file,
            "-passwords", pass_file,
            "-services", svc_str,
            "-rate", str(rate),
            "-timeout", str(timeout),
        ]
        if port_override:
            cmd.extend(["-port", str(port_override)])

        try:
            proc = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=timeout + 10,
            )
        except subprocess.TimeoutExpired:
            log.warning("oi-credential-spray timed out after %ds", timeout)
            return []
        except Exception as exc:
            log.warning("oi-credential-spray execution error: %s", exc)
            return []

    elapsed = time.monotonic() - t0
    findings: list = []
    for line in proc.stdout.splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            findings.append(json.loads(line))
        except json.JSONDecodeError:
            log.debug("credential_spray: non-JSON line: %s", line[:120])

    successes = sum(1 for f in findings if f.get("success"))
    log.info(
        "credential_spray: %d findings (%d successes) in %.1fs — %s",
        len(findings), successes, elapsed, target,
    )
    return findings


# ── CVE mapper ────────────────────────────────────────────────────────────────

def run_service_cve_mapper(banners: list) -> list:
    """Match service banners against the embedded CVE database.

    Parameters
    ----------
    banners: list of dicts with keys ``host``, ``port``, ``banner``, ``service``.
             Missing keys default to empty string / 0.

    Returns
    -------
    List of CVE finding dicts:
    ``{host, port, service, version, cve_id, cvss, description, vuln_type, banner?, ts}``
    """
    binary = _find_binary("oi-service-cve-mapper")
    if not binary:
        log.warning("oi-service-cve-mapper not found — skipping CVE mapping")
        return []

    if not banners:
        return []

    # Normalise input — ensure required fields are present
    ndjson_lines: list[str] = []
    for b in banners:
        record = {
            "host":    str(b.get("host", "")),
            "port":    int(b.get("port", 0)),
            "banner":  str(b.get("banner", "")),
            "service": str(b.get("service", "")),
        }
        ndjson_lines.append(json.dumps(record))

    stdin_data = "\n".join(ndjson_lines) + "\n"

    try:
        proc = subprocess.run(
            [binary],
            input=stdin_data,
            capture_output=True,
            text=True,
            timeout=30,
        )
    except subprocess.TimeoutExpired:
        log.warning("oi-service-cve-mapper timed out")
        return []
    except Exception as exc:
        log.warning("oi-service-cve-mapper error: %s", exc)
        return []

    findings: list = []
    for line in proc.stdout.splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            findings.append(json.loads(line))
        except json.JSONDecodeError:
            log.debug("cve_mapper: non-JSON output: %s", line[:120])

    if proc.returncode != 0 and proc.stderr:
        log.debug("oi-service-cve-mapper stderr: %s", proc.stderr[:500])

    log.info("cve_mapper: %d CVE findings from %d banners", len(findings), len(banners))
    return findings
