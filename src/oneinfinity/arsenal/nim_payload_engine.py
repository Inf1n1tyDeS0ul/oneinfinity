"""
nim_payload_engine.py — Unified Python wrapper for all 6 Nim offensive tools.

All Nim binaries emit NDJSON to stdout; this module delegates execution to
``src/oneinfinity/infra/nim_runner.run_nim_binary`` which handles:
  - path validation / allowlist enforcement
  - SHA-256 integrity checks (skipped when ONEINFINITY_SKIP_INTEGRITY=1)
  - subprocess invocation and NDJSON result parsing

Each public method returns ``list[dict]`` — empty list when the binary is
absent, never raises on missing binary.

Accepted env vars (forwarded to nim_runner):
  ONEINFINITY_SKIP_INTEGRITY=1   — skip SHA-256 check (dev/test mode)
  ONEINFINITY_STUB_BYPASS=1      — disable Nim anti-analysis heuristics
  ONEINFINITY_ENV=production     — blocks SKIP_INTEGRITY flag
"""
from __future__ import annotations

import logging
import os
import shutil
from pathlib import Path
from typing import Any

log = logging.getLogger(__name__)

# _REPO_ROOT is four levels up from this file:
#   src/oneinfinity/arsenal/nim_payload_engine.py
#   parents[0]=arsenal, parents[1]=oneinfinity, parents[2]=src, parents[3]=repo_root
_REPO_ROOT = Path(__file__).resolve().parents[3]
_BIN_DIR = _REPO_ROOT / "src" / "nim" / "bin"

# lazy import guard — nim_runner lives in the same package tree
def _run(binary: str, args: list[str], timeout: int = 30) -> list[dict[str, Any]]:
    """Delegate to nim_runner; return [] on FileNotFoundError (binary absent)."""
    try:
        from oneinfinity.infra.nim_runner import run_nim_binary, NimIntegrityError, NimExecutionError
        return run_nim_binary(binary, args, timeout=timeout)
    except FileNotFoundError:
        log.debug("nim_payload_engine: binary absent — %s", binary)
        return []
    except (NimIntegrityError, NimExecutionError) as exc:
        log.warning("nim_payload_engine: %s failed — %s", binary, exc)
        return []
    except Exception as exc:  # pragma: no cover
        log.error("nim_payload_engine: unexpected error from %s — %s", binary, exc)
        return []


class NimPayloadEngine:
    """Unified wrapper for all Phase 3 Nim binaries.

    All methods return ``list[dict]`` — empty list when the binary is absent
    or the run fails; never raises on missing binaries.
    """

    BIN_DIR: Path = _BIN_DIR

    # ── availability ──────────────────────────────────────────────────────────

    @classmethod
    def is_available(cls) -> bool:
        """True when at least one core binary is compiled into BIN_DIR or on PATH."""
        core = ("oi-payloads", "oi-shell-gen", "oi-bypass-gen")
        # Primary: check BIN_DIR
        if any((cls.BIN_DIR / b).exists() for b in core):
            return True
        # Fallback: PATH lookup
        return any(shutil.which(b) is not None for b in core)

    # ── oi-payloads ───────────────────────────────────────────────────────────

    def generate_payload(
        self,
        payload_type: str,
        context: str = "html",
    ) -> list[dict[str, Any]]:
        """Generate polymorphic offensive payloads via ``oi-payloads``.

        Parameters
        ----------
        payload_type:
            Vulnerability class: xss | sqli | ssrf | cmdi | path | xxe |
            ssti | redirect
        context:
            Injection context hint passed as ``--context``.  Defaults to
            "html".

        Returns
        -------
        List of result dicts with keys: event, payload, vuln_type, context,
        encoding, waf_score.  Normalized finding shape also included.
        """
        args = [
            f"--type={payload_type}",
            f"--context={context}",
        ]
        raw = _run("oi-payloads", args)
        findings: list[dict[str, Any]] = []
        for r in raw:
            findings.append({
                "vuln_type": payload_type,
                "severity": "info",
                "tool": "oi-payloads",
                "url": "",
                "evidence": r.get("payload", ""),
                "target": context,
                "encoding": r.get("encoding", ""),
                "waf_score": r.get("waf_score", 0),
                "raw": r,
            })
        return findings

    # ── oi-shell-gen ──────────────────────────────────────────────────────────

    def generate_shell(
        self,
        arch: str = "x64",
        fmt: str = "exe",
        obfuscate: bool = False,
    ) -> list[dict[str, Any]]:
        """Generate shell payloads via ``oi-shell-gen``.

        Parameters
        ----------
        arch:
            Target architecture: x64 | x86 | arm64
        fmt:
            Output format: exe | elf | shellcode
        obfuscate:
            When True, produce XOR-obfuscated variants (flag: ``--obfuscate``).

        Returns
        -------
        List of result dicts with keys: event, payload, arch, format,
        obfuscated, entropy.  Normalized finding shape also included.

        Note
        ----
        ``oi-shell-gen`` does not accept lhost/lport — it generates generic
        shellcode templates.  LHOST/LPORT substitution happens at deployment
        time using the ``payload`` template string.
        """
        args = [
            f"--arch={arch}",
            f"--format={fmt}",
        ]
        if obfuscate:
            args.append("--obfuscate")
        raw = _run("oi-shell-gen", args)
        findings: list[dict[str, Any]] = []
        for r in raw:
            findings.append({
                "vuln_type": "shell_payload",
                "severity": "critical",
                "tool": "oi-shell-gen",
                "url": "",
                "evidence": r.get("payload", ""),
                "target": f"{arch}/{fmt}",
                "arch": r.get("arch", arch),
                "format": r.get("format", fmt),
                "obfuscated": r.get("obfuscated", False),
                "entropy": r.get("entropy", 0.0),
                "xor_key": r.get("xor_key", ""),
                "raw": r,
            })
        return findings

    # ── oi-bypass-gen ─────────────────────────────────────────────────────────

    def generate_bypass(
        self,
        url: str,
        bypass_type: str = "all",  # reserved for future oi-bypass-gen --type flag
    ) -> list[dict[str, Any]]:
        """Generate 403/WAF bypass variants via ``oi-bypass-gen``.

        Parameters
        ----------
        url:
            Target path/URL to generate bypass variants for
            (passed as ``--target``).
        bypass_type:
            Reserved; oi-bypass-gen currently generates all techniques
            unconditionally.

        Returns
        -------
        List of finding dicts with canonical shape:
        ``{vuln_type, severity, tool, url, payload, evidence, target}``.
        """
        # Set ONEINFINITY_STUB_BYPASS so anti-analysis doesn't trip in test environments
        env_stub = os.environ.get("ONEINFINITY_STUB_BYPASS", "0")
        if env_stub != "1":
            # Callers can set the env var; we respect it if already set
            pass

        args = [f"--target={url}"]
        raw = _run("oi-bypass-gen", args)
        findings: list[dict[str, Any]] = []
        for r in raw:
            bypass_val = r.get("bypass", "")
            technique = r.get("technique", "unknown")
            findings.append({
                "vuln_type": "403_bypass_found",
                "severity": "high",
                "tool": "oi-bypass-gen",
                "url": url,
                "payload": bypass_val,
                "evidence": f"technique={technique} payload={bypass_val}",
                "target": r.get("target", url),
                "technique": technique,
                "raw": r,
            })
        return findings

    # ── oi-privesc-gen ────────────────────────────────────────────────────────

    def privesc_check(
        self,
        target_info: dict[str, Any] | None = None,
    ) -> list[dict[str, Any]]:
        """Generate privilege escalation templates via ``oi-privesc-gen``.

        Parameters
        ----------
        target_info:
            Optional context dict.  Recognised keys:
              - ``os`` (str): target OS — linux | darwin | windows (default: linux)
              - ``technique`` (str): sudo | suid | cron | path | capabilities | all
                (default: all)

        Returns
        -------
        List of result dicts with keys: event, command, technique, os,
        prereq, risk.  Normalized finding shape also included.
        """
        if target_info is None:
            target_info = {}

        os_name = str(target_info.get("os", "linux"))
        technique = str(target_info.get("technique", "all"))
        args = [
            f"--os={os_name}",
            f"--technique={technique}",
        ]
        raw = _run("oi-privesc-gen", args)
        findings: list[dict[str, Any]] = []
        for r in raw:
            risk = r.get("risk", "high")
            findings.append({
                "vuln_type": "privesc_technique",
                "severity": risk,
                "tool": "oi-privesc-gen",
                "url": "",
                "evidence": r.get("command", ""),
                "target": os_name,
                "technique": r.get("technique", technique),
                "prereq": r.get("prereq", ""),
                "command": r.get("command", ""),
                "raw": r,
            })
        return findings

    # ── oi-post-exploit ───────────────────────────────────────────────────────

    def post_exploit(
        self,
        stage: str = "all",
        target: str = "",
    ) -> list[dict[str, Any]]:
        """Generate post-exploitation stager metadata via ``oi-post-exploit``.

        Parameters
        ----------
        stage:
            Stager stage filter: persistence | privesc | credential | all
            (passed as ``--stage``).  Default "all" returns every stager.
        target:
            Human-readable target label stored in result findings.

        Returns
        -------
        List of result dicts with keys: event, technique, os, payload, stage.
        Normalized finding shape also included.
        """
        args = []
        if stage and stage != "all":
            args.append(f"--stage={stage}")
        raw = _run("oi-post-exploit", args)
        findings: list[dict[str, Any]] = []
        for r in raw:
            findings.append({
                "vuln_type": "post_exploit_stager",
                "severity": "critical",
                "tool": "oi-post-exploit",
                "url": "",
                "evidence": r.get("payload", ""),
                "target": target or r.get("os", ""),
                "technique": r.get("technique", ""),
                "os": r.get("os", ""),
                "stage": r.get("stage", stage),
                "raw": r,
            })
        return findings

    # ── oi-fuzzer (bonus) ─────────────────────────────────────────────────────

    def fuzz(
        self,
        target: str = "",
        fuzz_type: str = "all",
    ) -> list[dict[str, Any]]:
        """Generate fuzz payloads via ``oi-fuzzer``.

        Parameters
        ----------
        target:
            Target label stored in result findings.
        fuzz_type:
            Fuzz category hint passed as ``--type`` when non-empty.

        Returns
        -------
        List of result dicts (tool-specific schema). Empty when binary absent.
        """
        args = []
        if fuzz_type and fuzz_type != "all":
            args.append(f"--type={fuzz_type}")
        raw = _run("oi-fuzzer", args)
        findings: list[dict[str, Any]] = []
        for r in raw:
            # oi-fuzzer.nim emits {"event":"result","prompt":...,"technique":...}
            # "payload" key absent — use "prompt" with "payload" as fallback
            evidence = r.get("prompt") or r.get("payload") or str(r)
            findings.append({
                "vuln_type": "fuzz_payload",
                "severity": "info",
                "tool": "oi-fuzzer",
                "url": "",
                "payload": evidence,
                "evidence": evidence,
                "technique": r.get("technique", ""),
                "entropy": r.get("entropy", 0.0),
                "target": target,
                "raw": r,
            })
        return findings
