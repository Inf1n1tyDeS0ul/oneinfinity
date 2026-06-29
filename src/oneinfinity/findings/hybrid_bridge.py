import json
import logging
import os
from pathlib import Path
from typing import List, Dict

log = logging.getLogger("oneinfinity.hybrid_bridge")

class HybridBridge:
    """
    Connects OneInfinity's Technical Validation with Agentic Reasoning.
    Supports any reasoning agent (Claude, Gemini, OpenAI, Ollama, etc.) 
    by generating a standardized Reasoning Manifest.
    """
    def __init__(self, target: str, output_dir: Path):
        self.target = target
        self.output_dir = output_dir
        # Try multiple common paths for findings
        self.findings_paths = [
            output_dir / "findings" / "confirmed_findings.json",
            output_dir / "confirmed_findings.json",
            Path(os.path.expanduser(f"~/.oneinfinity/raw/{target}")) / "confirmed_findings.json"
        ]

    def _find_confirmed_findings(self) -> Path | None:
        for path in self.findings_paths:
            if path.exists():
                return path
        return None

    def escalate(self):
        findings_path = self._find_confirmed_findings()
        if not findings_path:
            print(f"[-] No confirmed findings found for {self.target}")
            return

        try:
            findings = json.loads(findings_path.read_text())
        except Exception as e:
            log.error(f"Failed to read findings: {e}")
            return

        # Filter for high-value classes that benefit from reasoning
        candidates = [f for f in findings if f.get("severity") in ("high", "critical")]

        if not candidates:
            print(f"[*] No high-severity findings for {self.target}. Logic check skipped.")
            return

        print(f"\n[+] Escalating {len(candidates)} findings to Reasoning Agent (7-Question Gate)...")
        
        for finding in candidates:
            self._generate_reasoning_prompt(finding)

    def _generate_reasoning_prompt(self, f: Dict):
        """
        Creates the 'Reasoning Manifest' for the Agentic layer.
        This prompt is designed to be used by any LLM-based reasoning agent.
        """
        prompt = f"""
╔══════════════════════════════════════════════════════════════════════════════╗
║  HYBRID BRIDGE: 7-QUESTION GATE ESCALATION                                   ║
╚══════════════════════════════════════════════════════════════════════════════╝
TARGET: {self.target}
VULN:   {f.get('vuln_type')}
URL:    {f.get('url', f.get('matched_at', f.get('endpoint', 'N/A')))}
SEVERITY: {f.get('severity')}
EVIDENCE: {str(f.get('evidence', f.get('description', ''))).strip()[:500]}...

INSTRUCTIONS FOR REASONING AGENT:
You are acting as a Senior Security Researcher. Apply the "7-Question Gate" to this finding:

1. Can it be exploited NOW without further complex setup?
2. Does it affect a REAL user or sensitive data?
3. Is there a CONCRETE business impact (Financial, PII, RCE)?
4. Is it within a typical Bug Bounty scope for this target?
5. Does it bypass a primary security control?
6. Is the technical root cause clearly demonstrated in the evidence?
7. Would a human triager agree this is a valid, high-impact finding?

FINAL ACTION:
- If ALL 7 are YES: Output 'DECISION: PROCEED' and draft a professional Bug Bounty report.
- If ANY is NO: Output 'DECISION: REJECT', explain why, and list the missing criteria.

(Note: This finding was technically verified by OneInfinity. Your job is logical/business validation.)
"""
        print(prompt)
        # Optionally save to a manifest file for automated agent pickup
        manifest_path = self.output_dir / "reasoning_manifests"
        manifest_path.mkdir(parents=True, exist_ok=True)
        vuln_safe = "".join([c if c.isalnum() else "_" for c in str(f.get('vuln_type'))])
        (manifest_path / f"manifest_{vuln_safe}_{int(os.getloadavg()[0]*100)}.txt").write_text(prompt)

if __name__ == "__main__":
    import sys
    if len(sys.argv) > 1:
        target = sys.argv[1]
        # Resolve output directory
        out = Path(os.path.expanduser(f"~/.oneinfinity/raw/{target}"))
        bridge = HybridBridge(target, out)
        bridge.escalate()
    else:
        print("Usage: python hybrid_bridge.py <target>")
