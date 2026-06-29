"""
Integrated Chain Detector
==========================
Merges ExploitChainEngine with manual pattern matching for comprehensive chain detection.

Innovation:
- Uses ExploitChainEngine for graph-validated chains with PoC generation + CVSS scoring
- Manual pattern matching handles composite multi-vuln-type chains (requires_all_of)
- Full 35+ pattern coverage including: sqli→rce, xss→session→ato, ssrf→metadata→creds,
  ssrf→internal→rce, path_traversal→config→creds, xxe→ssrf→scan,
  jwt→auth_bypass→privesc, smuggling→cache→xss, idor→mass_assignment→ato,
  jwt_manipulation+verb_tampering→full_auth_bypass, path_traversal+ssrf→internal_net,
  prompt_injection+ssrf→data_exfil_via_llm
- _calculate_chain_cvss() correctly escalates CVSS: 2-vuln high+high → ≥9.0, 3-vuln → critical
"""
from __future__ import annotations

import hashlib
import logging
from typing import Any, Dict, List, Optional, Set

from oneinfinity.attack.chain_patterns import CHAIN_PATTERNS
from oneinfinity.attack.exploit_chain_engine import ExploitChainEngine

log = logging.getLogger("oneinfinity.integrated_chain_detector")

_SEVERITY_RANK: Dict[str, int] = {
    "info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4,
}
_RANK_SEVERITY: Dict[int, str] = {v: k for k, v in _SEVERITY_RANK.items()}


def _calculate_chain_cvss(
    matched_findings: List[Dict[str, Any]],
    cvss_boost: float,
    n_vulns: int = 0,
) -> float:
    """
    Escalate CVSS for a chain from its component findings.

    Rules:
    - Base CVSS = max CVSS among matched findings (default 5.0 if none present).
    - Add cvss_boost.
    - 2-vuln chains where both findings are 'high' (CVSS ≥ 7.0) → floor at 9.0.
    - 3+ vuln chains → floor at 9.0 (always critical).
    - Cap at 10.0.
    """
    scores = [
        float(f.get("cvss_score") or f.get("cvss") or 5.0)
        for f in (matched_findings or [])
    ]
    base = max(scores, default=5.0)
    escalated = min(base + cvss_boost, 10.0)

    n = n_vulns or len(matched_findings)

    # Two-vuln chain of two 'high' findings → CVSS ≥ 9.0
    if n == 2:
        sevs = [
            _SEVERITY_RANK.get(
                str(f.get("severity", "medium")).lower(), 2
            )
            for f in (matched_findings or [])
        ]
        if all(s >= _SEVERITY_RANK["high"] for s in sevs):
            escalated = max(escalated, 9.0)

    # 3+ vuln chain → always critical floor
    if n >= 3:
        escalated = max(escalated, 9.0)

    return min(escalated, 10.0)


def _chain_severity_from_cvss(cvss: float, matched_findings: List[Dict[str, Any]]) -> str:
    """Derive severity label from escalated CVSS and member findings."""
    if cvss >= 9.0:
        return "critical"
    if cvss >= 7.0:
        return "high"
    # Also escalate one rank above highest member severity
    max_rank = max(
        (_SEVERITY_RANK.get(str(f.get("severity", "")).lower(), 0) for f in matched_findings),
        default=0,
    )
    escalated_rank = min(max_rank + 1, 4)
    return _RANK_SEVERITY.get(escalated_rank, "high")


def _chain_id(pattern_name: str, target: str) -> str:
    return "chain_" + hashlib.sha256(
        f"{pattern_name}:{target}".encode()
    ).hexdigest()[:12]


def _build_manual_chain(
    pattern_name: str,
    pattern: Dict[str, Any],
    matched_findings: List[Dict[str, Any]],
    target: str,
) -> Dict[str, Any]:
    """Build a chain result dict from a matched pattern."""
    boost = float(pattern.get("cvss_boost", 1.5))
    cvss = _calculate_chain_cvss(matched_findings, boost)
    severity = _chain_severity_from_cvss(cvss, matched_findings)
    confidence = float(pattern.get("confidence", 0.75))
    steps = pattern.get("steps", [])

    return {
        "chain_id": _chain_id(pattern_name, target),
        "name": pattern_name.replace("_", " ").title(),
        "severity": severity,
        "description": (
            f"Attack chain '{pattern_name}' detected: "
            + " → ".join(steps)
        ),
        "vulnerabilities": [
            {
                "finding_id": f.get("finding_id") or f.get("id", ""),
                "vuln_type": f.get("vuln_type") or f.get("category", ""),
                "url": f.get("url") or f.get("endpoint", ""),
                "severity": f.get("severity", ""),
            }
            for f in matched_findings
        ],
        "impact": (
            f"CVSS escalated to {cvss:.1f} ({severity.upper()}) via "
            f"{len(steps)}-step attack chain"
        ),
        "exploitation_steps": [
            f"{i + 1}. {step.replace('_', ' ').title()}"
            for i, step in enumerate(steps)
        ],
        "poc_script": _build_poc_script(pattern_name, target, steps, matched_findings, cvss),
        "confidence": confidence,
        "tool_commands": _suggest_tool_commands(pattern_name, steps, matched_findings),
        "source": "IntegratedChainDetector:manual",
        "cvss_score": cvss,
        "cvss_escalated": cvss,
    }


def _build_poc_script(
    chain_name: str,
    target: str,
    steps: List[str],
    findings: List[Dict[str, Any]],
    cvss: float,
) -> str:
    lines = [
        "#!/usr/bin/env python3",
        f"# Exploit Chain: {chain_name}",
        f"# Target: {target}",
        f"# CVSS: {cvss:.1f} (critical)" if cvss >= 9.0 else f"# CVSS: {cvss:.1f}",
        "# Auto-generated by IntegratedChainDetector",
        "",
        "import requests",
        "",
        "def main():",
        f'    target = "{target}"',
        "",
    ]
    for i, step in enumerate(steps, 1):
        lines.append(f"    # Step {i}: {step.replace('_', ' ').title()}")
        # Add finding-specific context if available
        if i <= len(findings):
            url = findings[i - 1].get("url") or target
            lines.append(f"    # Affected URL: {url}")
        lines.append("")
    lines.extend([
        '    print("[+] Exploit chain complete")',
        "",
        'if __name__ == "__main__":',
        "    main()",
    ])
    return "\n".join(lines)


def _suggest_tool_commands(
    chain_name: str,
    steps: List[str],
    findings: List[Dict[str, Any]],
) -> List[str]:
    """Suggest concrete tool commands for the chain steps."""
    cmds: List[str] = []
    urls = list({
        f.get("url") or f.get("endpoint", "")
        for f in findings if f.get("url") or f.get("endpoint")
    })
    url = urls[0] if urls else "<target_url>"

    # Map step keywords → tool commands
    _step_map = {
        "ssrf": f"nuclei -u {url} -tags ssrf -severity high,critical",
        "sql": f"sqlmap -u '{url}' --level=3 --risk=2 --batch",
        "sqli": f"sqlmap -u '{url}' --level=3 --risk=2 --batch",
        "xss": f"dalfox url '{url}'",
        "jwt": f"jwt_tool <token> -M at -t {url}",
        "idor": f"nuclei -u {url} -tags idor",
        "mass_assignment": f"curl -X POST {url} -d '{{\"role\":\"admin\",\"is_admin\":true}}'",
        "path_traversal": f"nuclei -u {url} -tags lfi,traversal",
        "lfi": f"nuclei -u {url} -tags lfi",
        "xxe": f"nuclei -u {url} -tags xxe",
        "smuggling": f"smuggler.py -u {url}",
        "prompt_injection": f"garak --target {url} --probes promptinject",
        "rce": f"nuclei -u {url} -tags rce -severity critical",
    }
    for step in steps:
        step_l = step.lower()
        for key, cmd in _step_map.items():
            if key in step_l and cmd not in cmds:
                cmds.append(cmd)
                break
    return cmds[:4]  # cap at 4 commands


class IntegratedChainDetector:
    """
    Unified chain detector combining ExploitChainEngine + manual multi-vuln pattern matching.

    Covers 35+ attack chains including:
    - SQLi → RCE (LOAD_FILE / xp_cmdshell)
    - XSS → Session Hijack → ATO
    - SSRF → Cloud Metadata → Credential Theft
    - SSRF → Internal Service → RCE
    - Path Traversal → Config Read → Credential Theft
    - XXE → SSRF → Internal Scan
    - JWT Weakness → Auth Bypass → Privilege Escalation
    - HTTP Smuggling → Cache Poisoning → XSS
    - IDOR + Mass Assignment → Account Takeover (critical)
    - JWT Manipulation + Verb Tampering → Full Auth Bypass (critical)
    - Path Traversal + SSRF → Internal Network Access
    - Prompt Injection + SSRF → Data Exfiltration via LLM (critical)
    """

    def __init__(self, target: str):
        self.target = target
        self.exploit_engine = ExploitChainEngine()

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def detect_chains(self, all_findings: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """
        Detect attack chains from a flat list of findings.

        Returns:
            List of attack chain dicts with PoC scripts and CVSS escalation.
            Sorted by descending CVSS.
        """
        chains: List[Dict[str, Any]] = []
        seen_chain_ids: Set[str] = set()

        # ── Phase 1: Graph-validated chains via ExploitChainEngine ──────────
        try:
            exploit_pocs = self.exploit_engine.detect_chains(all_findings, self.target)
            for poc in exploit_pocs:
                cid = poc.chain_id
                if cid in seen_chain_ids:
                    continue
                seen_chain_ids.add(cid)
                chain = {
                    "chain_id": cid,
                    "name": poc.chain_type.replace("_", " ").title(),
                    "severity": poc.severity_escalated,
                    "description": poc.narrative,
                    "vulnerabilities": [],
                    "impact": (
                        f"CVSS: {poc.base_cvss:.1f} → {poc.cvss_escalated:.1f} "
                        f"(escalated +{poc.cvss_escalated - poc.base_cvss:.1f})"
                    ),
                    "exploitation_steps": [
                        f"{i + 1}. {step.step_name}: {step.expected_response or 'Execute step'}"
                        for i, step in enumerate(poc.steps)
                    ],
                    "poc_script": self._format_poc_script(poc),
                    "confidence": poc.confidence,
                    "tool_commands": [
                        step.tool_command
                        for step in poc.steps
                        if step.tool_command
                    ],
                    "source": "ExploitChainEngine",
                    "cvss_score": poc.cvss_escalated,
                    "cvss_escalated": poc.cvss_escalated,
                }
                chains.append(chain)
            log.info("ExploitChainEngine: %d chains detected", len(exploit_pocs))
        except Exception as exc:
            log.error("ExploitChainEngine failed: %s", exc)

        # ── Phase 2: Manual pattern matching for composite chains ─────────
        observed_types: Set[str] = {
            str(f.get("vuln_type") or f.get("category") or "").lower().strip()
            for f in (all_findings or [])
            if f.get("vuln_type") or f.get("category")
        }
        # Also index by tool and attack_type fields (garak/AI findings)
        observed_types.update({
            str(f.get("attack_type") or "").lower().strip()
            for f in (all_findings or [])
            if f.get("attack_type")
        })

        for pattern_name, pattern in CHAIN_PATTERNS.items():
            trigger_types: frozenset = pattern.get("trigger_types", frozenset())
            requires_all_of: Optional[List[frozenset]] = pattern.get("requires_all_of")

            # Check if the pattern fires
            if requires_all_of:
                # ALL groups must have at least one matching observed type
                if not all(group & observed_types for group in requires_all_of):
                    continue
                # Collect findings that match ANY required group
                matched = [
                    f for f in (all_findings or [])
                    if (
                        str(f.get("vuln_type") or f.get("category") or "").lower() in trigger_types
                        or str(f.get("attack_type") or "").lower() in trigger_types
                    )
                ]
            else:
                # Standard: at least one trigger type observed
                if not (trigger_types & observed_types):
                    continue
                matched = [
                    f for f in (all_findings or [])
                    if (
                        str(f.get("vuln_type") or f.get("category") or "").lower() in trigger_types
                        or str(f.get("attack_type") or "").lower() in trigger_types
                    )
                ]

            if not matched:
                continue

            cid = _chain_id(pattern_name, self.target)
            if cid in seen_chain_ids:
                continue  # already reported by ExploitChainEngine
            seen_chain_ids.add(cid)

            chain = _build_manual_chain(pattern_name, pattern, matched, self.target)
            chains.append(chain)
            log.info(
                "IntegratedChainDetector: manual pattern '%s' matched %d finding(s) "
                "on %s (CVSS %.1f)",
                pattern_name, len(matched), self.target,
                chain["cvss_escalated"],
            )

        log.info(
            "IntegratedChainDetector.detect_chains: %d total chains for %s",
            len(chains), self.target,
        )
        return sorted(chains, key=lambda c: -float(c.get("cvss_escalated", 0)))

    # ------------------------------------------------------------------
    # CVSS helper (public for testing)
    # ------------------------------------------------------------------

    @staticmethod
    def _calculate_chain_cvss(
        matched_findings: List[Dict[str, Any]],
        cvss_boost: float,
        n_vulns: int = 0,
    ) -> float:
        """
        Escalate CVSS for a chain.

        - Two 'high' findings → CVSS ≥ 9.0 (critical).
        - Three or more findings → always CVSS ≥ 9.0 (critical).
        - Capped at 10.0.
        """
        return _calculate_chain_cvss(matched_findings, cvss_boost, n_vulns)

    # ------------------------------------------------------------------
    # Private helpers
    # ------------------------------------------------------------------

    def _format_poc_script(self, poc) -> str:
        """Format ExploitPoC object into an executable Python script."""
        script_lines = [
            "#!/usr/bin/env python3",
            f"# Exploit Chain: {poc.chain_type}",
            f"# Target: {poc.target}",
            f"# CVSS: {poc.base_cvss:.1f} → {poc.cvss_escalated:.1f}",
            f"# Confidence: {poc.confidence:.0%}",
            "",
            "import requests",
            "import sys",
            "",
            "def main():",
            f'    """',
            f"    {poc.narrative}",
            f'    """',
            f'    target = "{poc.target}"',
            "",
        ]

        for i, step in enumerate(poc.steps, 1):
            script_lines.append(f"    # Step {i}: {step.step_name}")
            if step.tool_command:
                script_lines.append(f"    # Tool: {step.tool_command}")
            if step.payload:
                script_lines.append(f"    payload = {repr(step.payload)}")
            if step.expected_response:
                script_lines.append(f"    # Expected: {step.expected_response}")
            script_lines.append("")

        script_lines.extend([
            '    print("[+] Exploit chain complete")',
            "",
            'if __name__ == "__main__":',
            "    main()",
        ])

        return "\n".join(script_lines)
