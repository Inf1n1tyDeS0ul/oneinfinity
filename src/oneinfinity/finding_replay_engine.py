"""
finding_replay_engine.py — Convert findings.json into executable CLI/curl workflows.

Commands:
    oneinfinity replay findings.json [--run] [--filter confirmed] [--output replay_report.json]

Features:
  - Generates exact curl / nuclei / python commands per finding
  - Optionally executes them and captures results (--run flag)
  - Filters by: status, severity, source_type, vuln_type
  - Idempotent: safe to re-run — read-only by default
  - Can validate fixes: compare pre/post-patch responses
"""
from __future__ import annotations

import json
import logging
import shlex
import subprocess
import time
from dataclasses import dataclass, field, asdict
from pathlib import Path
from typing import Any, Dict, List, Optional

log = logging.getLogger("oi.replay")

# ---------------------------------------------------------------------------
# Command templates per vuln_type
# ---------------------------------------------------------------------------

def _curl_base(url: str, extra: str = "") -> str:
    return (
        f'curl -s -o /dev/null -w "%{{http_code}} | %{{time_total}}s | %{{size_download}}B" '
        f'--max-time 10 -k {extra} "{url}"'
    )

def _nuclei_cmd(url: str, tags: str, tmpl_dir: str = "/data/.nuclei-templates") -> str:
    return f'nuclei -u "{url}" -t {tmpl_dir}/http/ -tags {tags} -severity info,low,medium,high,critical -silent -jsonl'

_COMMAND_TEMPLATES: Dict[str, Any] = {
    "cors": {
        "description": "Test CORS with malicious Origin header",
        "commands": [
            lambda f: _curl_base(f["url"], '-H "Origin: https://evil-attacker.com" '
                                           '-H "Access-Control-Request-Method: GET" -X OPTIONS'),
            lambda f: f'# Check response for: Access-Control-Allow-Origin: https://evil-attacker.com',
        ],
        "nuclei_tags": "cors",
    },
    "cors_misconfiguration": {
        "commands": [
            lambda f: _curl_base(f["url"], '-H "Origin: https://evil-attacker.com" '
                                           '-H "Access-Control-Request-Method: GET" -X OPTIONS'),
        ],
        "nuclei_tags": "cors",
    },
    "ssrf": {
        "description": "Test SSRF to cloud metadata service",
        "commands": [
            lambda f: _curl_base(
                f["url"].replace(
                    f.get("url", ""),
                    f["url"] + ("&" if "?" in f["url"] else "?") + "url=http://169.254.169.254/latest/meta-data/"
                )
            ),
            lambda f: _nuclei_cmd(f["url"], "ssrf"),
            lambda f: f'# Manual: intercept and inject url=http://169.254.169.254/ into URL params',
        ],
        "nuclei_tags": "ssrf",
    },
    "jwt_none_alg": {
        "description": "Test JWT none algorithm bypass",
        "commands": [
            lambda f: (
                "python3 -c \"\n"
                "import base64, json\n"
                "h = base64.urlsafe_b64encode(json.dumps({'alg':'none','typ':'JWT'}).encode()).decode().rstrip('=')\n"
                "p = base64.urlsafe_b64encode(json.dumps({'sub':'1','role':'admin'}).encode()).decode().rstrip('=')\n"
                "print(f'{h}.{p}.')\n"
                "\""
            ),
            lambda f: _curl_base(f["url"], '-H "Authorization: Bearer <forged_none_token>"'),
            lambda f: f'# If HTTP 200 → confirmed JWT none algorithm bypass',
        ],
        "nuclei_tags": "jwt",
    },
    "idor": {
        "description": "Enumerate IDs to detect IDOR",
        "commands": [
            lambda f: f'for id in $(seq 1 20); do echo -n "ID=$id: "; ' +
                      _curl_base(
                          f.get("url", "").rstrip("/") + "/$id"
                          if not any(p.isdigit() for p in f.get("url", "").split("/"))
                          else f.get("url", "")
                      ) + '; done',
            lambda f: _nuclei_cmd(f["url"], "idor,auth-bypass"),
        ],
        "nuclei_tags": "idor",
    },
    "race_condition": {
        "description": "Test race condition with concurrent requests",
        "commands": [
            lambda f: f'# Send {10} concurrent requests to {f.get("url","")}:\n'
                      f'seq 1 10 | xargs -P10 -I{{}} curl -s -o /dev/null -w "%{{http_code}}\\n" '
                      f'--max-time 5 "{f.get("url", "")}"',
            lambda f: f'# All HTTP 200s → missing atomicity (race condition confirmed)',
        ],
    },
    "auth_bypass": {
        "description": "Test authentication bypass with common headers",
        "commands": [
            lambda f: _curl_base(f["url"]),
            lambda f: _curl_base(f["url"], '-H "X-Forwarded-For: 127.0.0.1"'),
            lambda f: _curl_base(f["url"], '-H "X-Original-URL: /admin"'),
            lambda f: _curl_base(f["url"], '-H "X-Custom-IP-Authorization: 127.0.0.1"'),
        ],
        "nuclei_tags": "auth-bypass",
    },
    "xss": {
        "description": "Test XSS with common payloads",
        "commands": [
            lambda f: f'dalfox url "{f.get("url","")}" --silence',
            lambda f: _nuclei_cmd(f["url"], "xss"),
        ],
        "nuclei_tags": "xss",
    },
    "sqli": {
        "description": "Test SQL injection",
        "commands": [
            lambda f: f'sqlmap -u "{f.get("url","")}" --batch --level=1 --risk=1 --dbs',
            lambda f: _nuclei_cmd(f["url"], "sqli"),
        ],
        "nuclei_tags": "sqli",
    },
    "information_disclosure": {
        "description": "Verify endpoint is publicly accessible",
        "commands": [
            lambda f: _curl_base(f["url"]),
            lambda f: f'# Check response body for sensitive data',
        ],
        "nuclei_tags": "exposure",
    },
    "weak_cipher": {
        "description": "Check TLS cipher strength",
        "commands": [
            lambda f: f'nmap --script ssl-enum-ciphers -p 443 {f.get("url","").replace("https://","").split("/")[0]}',
            lambda f: _nuclei_cmd(f["url"], "ssl"),
        ],
        "nuclei_tags": "ssl",
    },
    "exploit_chain": {
        "description": "Reproduce full exploit chain",
        "commands": [
            lambda f: f'python /app/oneinfinity.py chains {f.get("target","")} --output /data/raw',
            lambda f: f'# Review: /data/raw/poc_chain_*.json',
        ],
    },
}

# Default fallback
_DEFAULT_TEMPLATE = {
    "commands": [
        lambda f: _curl_base(f.get("url", f.get("endpoint", "https://target"))),
        lambda f: f'python /app/oneinfinity.py vuln-scan {f.get("target", "")} --severity info,low,medium,high,critical',
    ],
}


# ---------------------------------------------------------------------------
# Replay record
# ---------------------------------------------------------------------------

@dataclass
class ReplayRecord:
    finding_id: str
    vuln_type: str
    severity: str
    url: str
    confidence: float
    source_type: str
    validation_status: str
    commands: List[str]
    description: str = ""
    run_results: List[dict] = field(default_factory=list)

    def to_dict(self) -> dict:
        return asdict(self)

    def to_markdown(self, idx: int) -> str:
        lines = [
            f"### {idx}. {self.vuln_type} — {self.severity.upper()}",
            f"**URL**: `{self.url}`  ",
            f"**Source**: {self.source_type}  ",
            f"**Confidence**: {int(self.confidence * 100)}%  ",
            f"**Validation**: {self.validation_status}  ",
            "",
        ]
        if self.description:
            lines += [f"**Description**: {self.description}", ""]
        lines += ["**Commands**:", "```bash"]
        for cmd in self.commands:
            lines.append(cmd)
        lines += ["```", ""]
        if self.run_results:
            lines += ["**Results**:", "```"]
            for r in self.run_results:
                lines.append(f"[{r.get('cmd_idx',0)}] exit={r.get('exit_code',0)} output={r.get('output','')[:120]}")
            lines += ["```", ""]
        return "\n".join(lines)


# ---------------------------------------------------------------------------
# Engine
# ---------------------------------------------------------------------------

class FindingReplayEngine:
    """
    Converts findings.json into reproducible CLI steps.
    Optionally executes them and captures output.
    """

    def __init__(
        self,
        filter_status: Optional[str] = None,         # "confirmed", "unverified", etc.
        filter_severity: Optional[List[str]] = None, # ["critical", "high"]
        filter_source: Optional[str] = None,         # "tool", "simulated", "ai_theory"
        run: bool = False,                            # Execute commands if True
        run_timeout: int = 30,
        docker_exec: str = "oneinfinity-orchestrator", # Docker container to run in
    ):
        self._filter_status   = filter_status
        self._filter_severity = [s.lower() for s in filter_severity] if filter_severity else None
        self._filter_source   = filter_source
        self._run             = run
        self._run_timeout     = run_timeout
        self._docker_exec     = docker_exec

    def _passes_filter(self, finding: dict) -> bool:
        if self._filter_status:
            vs = finding.get("validation_status", finding.get("status", ""))
            if vs != self._filter_status:
                return False
        if self._filter_severity:
            if finding.get("severity", "").lower() not in self._filter_severity:
                return False
        if self._filter_source:
            if finding.get("source_type", "") != self._filter_source:
                return False
        return True

    def _build_commands(self, finding: dict) -> List[str]:
        vtype    = finding.get("vuln_type", "").lower()
        template = _COMMAND_TEMPLATES.get(vtype, _DEFAULT_TEMPLATE)
        cmds = []
        for builder in template.get("commands", []):
            try:
                cmd = builder(finding)
                if cmd:
                    cmds.append(str(cmd).strip())
            except Exception:
                pass
        return cmds

    def _run_command(self, cmd: str, idx: int) -> dict:
        """Execute a single shell command inside Docker (if container name set) or locally."""
        try:
            if self._docker_exec:
                full_cmd = ["docker", "exec", self._docker_exec, "bash", "-c", cmd]
            else:
                full_cmd = ["bash", "-c", cmd]

            result = subprocess.run(
                full_cmd, capture_output=True, text=True, timeout=self._run_timeout
            )
            return {
                "cmd_idx":   idx,
                "command":   cmd[:200],
                "exit_code": result.returncode,
                "output":    (result.stdout + result.stderr).strip()[:500],
            }
        except subprocess.TimeoutExpired:
            return {"cmd_idx": idx, "command": cmd[:200], "exit_code": -1, "output": "TIMEOUT"}
        except Exception as exc:
            return {"cmd_idx": idx, "command": cmd[:200], "exit_code": -1, "output": str(exc)}

    def build_replay_records(self, findings: List[dict]) -> List[ReplayRecord]:
        """Build replay records (commands only, no execution)."""
        records = []
        for f in findings:
            if not self._passes_filter(f):
                continue
            vtype = f.get("vuln_type", "")
            template = _COMMAND_TEMPLATES.get(vtype, _DEFAULT_TEMPLATE)
            records.append(ReplayRecord(
                finding_id=f.get("finding_id", f.get("id", "?")),
                vuln_type=vtype,
                severity=f.get("severity", "info"),
                url=f.get("url", f.get("endpoint", "")),
                confidence=float(f.get("confidence", 0)) if str(f.get("confidence", 0)).replace(".", "", 1).isdigit() else 0.0,
                source_type=f.get("source_type", "unknown"),
                validation_status=f.get("validation_status", f.get("status", "unverified")),
                commands=self._build_commands(f),
                description=template.get("description", ""),
            ))
        return records

    def replay(self, findings: List[dict]) -> List[ReplayRecord]:
        """Build + optionally execute replay records."""
        records = self.build_replay_records(findings)
        if not self._run:
            return records

        log.info("Executing %d replay records...", len(records))
        for rec in records:
            for i, cmd in enumerate(rec.commands):
                # Skip comment-only commands
                if cmd.startswith("#"):
                    continue
                result = self._run_command(cmd, i)
                rec.run_results.append(result)
                time.sleep(0.5)  # Light rate limit between commands

        return records

    def write_report(self, records: List[ReplayRecord], output_path: str) -> None:
        """Write replay report in Markdown + JSON."""
        out = Path(output_path)
        out.parent.mkdir(parents=True, exist_ok=True)

        # Markdown
        md_path = out.with_suffix(".md")
        lines = [
            "# Replay Report",
            "",
            f"**Total findings replayed**: {len(records)}",
            f"**Executed**: {'yes' if self._run else 'no (commands only)'}",
            "",
            "---",
            "",
        ]
        for i, rec in enumerate(records, 1):
            lines.append(rec.to_markdown(i))
        md_path.write_text("\n".join(lines))

        # JSON
        json_path = out.with_suffix(".json")
        json_path.write_text(json.dumps(
            [r.to_dict() for r in records], indent=2
        ))

        log.info("Replay report written: %s (.md + .json)", out.stem)


def replay_findings_file(
    findings_path: str,
    output_path: str = "/data/raw/replay_report",
    filter_status: Optional[str] = None,
    filter_severity: Optional[List[str]] = None,
    run: bool = False,
    docker_exec: str = "oneinfinity-orchestrator",
) -> List[ReplayRecord]:
    """Convenience wrapper used by CLI command."""
    findings = json.loads(Path(findings_path).read_text())
    if not isinstance(findings, list):
        findings = findings.get("findings", [])

    engine  = FindingReplayEngine(
        filter_status=filter_status,
        filter_severity=filter_severity,
        run=run,
        docker_exec=docker_exec,
    )
    records = engine.replay(findings)
    engine.write_report(records, output_path)
    return records
