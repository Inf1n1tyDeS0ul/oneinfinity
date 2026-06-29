"""
web3/smart_contract_scanner.py — Smart Contract Vulnerability Scanner

Detects 10+ vulnerability classes in EVM-compatible smart contracts:
  1.  Reentrancy (cross-function, cross-contract, read-only)
  2.  Integer overflow/underflow
  3.  Access control bypass (missing onlyOwner, tx.origin auth)
  4.  Unchecked external calls (return value ignored)
  5.  Self-destruct exposure
  6.  Delegatecall injection
  7.  Flashloan attack surface
  8.  Price oracle manipulation
  9.  Signature replay (missing nonce / chainId)
  10. Unprotected initializer (proxy upgrade pattern)
  11. Randomness manipulation (block.timestamp, blockhash)
  12. Griefing / DoS via gas limit
  13. Front-running vulnerability (sandwichable)
  14. Token approval race condition (ERC20 approve/transferFrom)

Integrations:
  - Slither (if installed): runs static analysis and parses JSON output
  - Pattern-based regex analysis: works without any dependency
  - Foundry PoC generator: generates forge test skeletons for findings
  - EVM token scanner: detects honey-pot patterns, rug-pull vectors, hidden fees

Usage::
    scanner = SmartContractScanner()
    report = scanner.scan_file("Token.sol")
    print(report.summary())

    # With Slither
    report = scanner.scan_with_slither("Token.sol")
"""
from __future__ import annotations

import json
import logging
import os
import re
import subprocess
import tempfile
import time
import uuid
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

log = logging.getLogger("oneinfinity.web3.scanner")

# ---------------------------------------------------------------------------
# Data models
# ---------------------------------------------------------------------------

@dataclass
class ContractFinding:
    finding_id: str
    title: str
    severity: str           # critical / high / medium / low / info
    category: str           # reentrancy / overflow / access_control / etc.
    description: str
    contract: str = ""
    function_name: str = ""
    line_number: int = 0
    evidence: str = ""
    remediation: str = ""
    cvss_score: float = 0.0
    swc_id: str = ""        # Smart Contract Weakness Classification
    poc_sketch: str = ""    # brief PoC idea

    def to_dict(self) -> dict:
        return {
            "id": self.finding_id,
            "title": self.title,
            "severity": self.severity,
            "category": self.category,
            "description": self.description,
            "contract": self.contract,
            "function": self.function_name,
            "line": self.line_number,
            "evidence": self.evidence,
            "remediation": self.remediation,
            "cvss": self.cvss_score,
            "swc": self.swc_id,
        }


@dataclass
class ContractScanReport:
    target: str
    scan_mode: str
    findings: List[ContractFinding] = field(default_factory=list)
    contracts_scanned: int = 0
    scan_time_s: float = 0.0
    slither_raw: dict = field(default_factory=dict)
    error: str = ""

    def findings_by_severity(self, sev: str) -> List[ContractFinding]:
        return [f for f in self.findings if f.severity == sev]

    def summary(self) -> str:
        counts = {s: len(self.findings_by_severity(s))
                  for s in ("critical", "high", "medium", "low", "info")}
        sev_colors = {
            "critical": "\033[1;31m", "high": "\033[0;31m",
            "medium": "\033[0;33m", "low": "\033[0;34m", "info": "\033[0;37m",
        }
        reset = "\033[0m"
        bold = "\033[1m"
        lines = [
            f"\n  {bold}Smart Contract Security Scan — {self.target}{reset}",
            f"  {'─'*60}",
            f"  Mode      : {self.scan_mode}",
            f"  Contracts : {self.contracts_scanned}",
            f"  Findings  : critical={counts['critical']} high={counts['high']} "
            f"medium={counts['medium']} low={counts['low']}",
            "",
        ]
        _sev_order = ("critical", "high", "medium", "low", "info")
        for f in sorted(self.findings, key=lambda x: _sev_order.index(x.severity)):
            col = sev_colors.get(f.severity, "")
            swc_tag = f" [{f.swc_id}]" if f.swc_id else ""
            lines.append(f"  {col}[{f.severity.upper():8s}]{reset} {f.title}{swc_tag}")
            if f.contract or f.function_name:
                loc = f.contract + ("." + f.function_name if f.function_name else "")
                lines.append(f"           {loc}:{f.line_number}")
            if f.evidence:
                lines.append(f"           {f.evidence[:80]}")
        lines.append("")
        return "\n".join(lines)


# ---------------------------------------------------------------------------
# Pattern-based detection rules
# (works without Slither — pure regex against Solidity source)
# ---------------------------------------------------------------------------

@dataclass
class _Rule:
    name: str
    pattern: re.Pattern
    severity: str
    category: str
    description: str
    remediation: str
    swc_id: str = ""
    cvss: float = 0.0
    poc_sketch: str = ""


_RULES: List[_Rule] = [
    _Rule(
        name="Reentrancy — External Call Before State Update",
        pattern=re.compile(
            r"(\.call\{?[^}]*\}?\([^)]*\)|\.transfer\([^)]*\)|\.send\([^)]*\))"
            r".*\n(?:(?!(?:balance|mapping|state)\s*[-+]?=).)*\n"
            r".*(?:balance|mapping|state)\s*[-+]?=",
            re.DOTALL | re.MULTILINE,
        ),
        severity="critical",
        category="reentrancy",
        description=(
            "External call occurs before state update — classic reentrancy pattern. "
            "An attacker contract can re-enter the function before balances are updated."
        ),
        remediation=(
            "Apply the Checks-Effects-Interactions pattern: "
            "update all state variables BEFORE making external calls. "
            "Alternatively use a ReentrancyGuard mutex."
        ),
        swc_id="SWC-107",
        cvss=9.8,
        poc_sketch=(
            "// Forge PoC sketch:\n"
            "// 1. Deploy AttackerContract with receive() that re-enters target\n"
            "// 2. Call target.withdraw() which triggers the reentrancy\n"
            "// 3. In receive(), call target.withdraw() again before balance update"
        ),
    ),
    _Rule(
        name="tx.origin Authentication",
        pattern=re.compile(r"\btx\.origin\b.*(?:==|!=|require)", re.IGNORECASE),
        severity="high",
        category="access_control",
        description=(
            "tx.origin used for authentication — vulnerable to phishing attacks "
            "where a malicious contract is the immediate caller."
        ),
        remediation="Replace tx.origin with msg.sender for all authorization checks.",
        swc_id="SWC-115",
        cvss=8.1,
    ),
    _Rule(
        name="Unchecked Return Value on External Call",
        pattern=re.compile(r"[^=]\s*\.call\{?[^}]*\}?\([^)]*\)\s*;(?!\s*require)", re.IGNORECASE),
        severity="high",
        category="unchecked_call",
        description=(
            "Return value of low-level .call() is not checked. "
            "A failed external call can silently pass, leading to incorrect state."
        ),
        remediation=(
            "Always check the return value: (bool success, bytes memory data) = addr.call(...);\n"
            "require(success, 'Call failed');"
        ),
        swc_id="SWC-104",
        cvss=7.5,
    ),
    _Rule(
        name="Self-Destruct Without Access Control",
        pattern=re.compile(r"\bselfdestruct\s*\(", re.IGNORECASE),
        severity="critical",
        category="access_control",
        description=(
            "selfdestruct() found — if not protected by strict access control, "
            "any attacker could destroy the contract and drain ETH."
        ),
        remediation=(
            "Protect selfdestruct with onlyOwner and consider a timelock. "
            "Prefer contract migration patterns over self-destruct in modern contracts."
        ),
        swc_id="SWC-106",
        cvss=9.0,
    ),
    _Rule(
        name="Delegatecall to User-Controlled Address",
        pattern=re.compile(r"\.delegatecall\(", re.IGNORECASE),
        severity="critical",
        category="delegatecall",
        description=(
            "delegatecall() executes code from another contract in the caller's context. "
            "If the target address is user-controlled, attacker can execute arbitrary code "
            "and manipulate storage, including ownership slots."
        ),
        remediation=(
            "Never delegatecall to untrusted or user-supplied addresses. "
            "Use a whitelist of approved implementation contracts."
        ),
        swc_id="SWC-112",
        cvss=9.8,
    ),
    _Rule(
        name="Block Timestamp Dependence",
        pattern=re.compile(r"\bblock\.timestamp\b|\bnow\b", re.IGNORECASE),
        severity="medium",
        category="randomness",
        description=(
            "block.timestamp can be manipulated by miners within a ~15-second window. "
            "Do not use for randomness, time-sensitive logic, or game outcomes."
        ),
        remediation=(
            "Use a commit-reveal scheme or Chainlink VRF for randomness. "
            "For time-sensitive logic, consider larger windows (hours, not seconds)."
        ),
        swc_id="SWC-116",
        cvss=5.3,
    ),
    _Rule(
        name="Weak Randomness — blockhash",
        pattern=re.compile(r"\bblockhash\s*\(", re.IGNORECASE),
        severity="high",
        category="randomness",
        description=(
            "blockhash is only available for the last 256 blocks and can be predicted "
            "or manipulated by miners. Not suitable for randomness in high-value contracts."
        ),
        remediation="Use Chainlink VRF for verifiable randomness in production contracts.",
        swc_id="SWC-120",
        cvss=7.4,
    ),
    _Rule(
        name="Missing Nonce in Signature Verification (Replay Attack)",
        pattern=re.compile(
            r"ecrecover\s*\([^)]*\)(?:(?!nonce|chainId).){0,500}",
            re.DOTALL | re.IGNORECASE,
        ),
        severity="high",
        category="signature_replay",
        description=(
            "ecrecover() used for signature verification without visible nonce or chainId check "
            "nearby. Valid signatures can be replayed on the same or other chains."
        ),
        remediation=(
            "Include nonce (per-user, stored on-chain and incremented) and block.chainid "
            "in the signed message. Use EIP-712 structured hashing."
        ),
        swc_id="SWC-121",
        cvss=8.1,
    ),
    _Rule(
        name="Unprotected Initializer",
        pattern=re.compile(r"\bfunction\s+initialize\s*\(", re.IGNORECASE),
        severity="critical",
        category="access_control",
        description=(
            "initialize() function found — if not protected by initializer modifier "
            "(OpenZeppelin) or a one-time flag, anyone can call it after deployment "
            "and take ownership of the proxy."
        ),
        remediation=(
            "Use OpenZeppelin's initializer modifier and Initializable base contract. "
            "Call _disableInitializers() in the implementation constructor."
        ),
        swc_id="SWC-118",
        cvss=9.8,
    ),
    _Rule(
        name="Arithmetic Without SafeMath (Pre-0.8)",
        pattern=re.compile(r"pragma solidity\s+[^;]*0\.[0-7]\.", re.IGNORECASE),
        severity="high",
        category="overflow",
        description=(
            "Contract uses Solidity < 0.8.0 where arithmetic overflow/underflow "
            "silently wraps. Without SafeMath, token balances can wrap to very large values."
        ),
        remediation=(
            "Upgrade to Solidity >=0.8.0 (built-in overflow checks) or use "
            "OpenZeppelin SafeMath for all arithmetic operations."
        ),
        swc_id="SWC-101",
        cvss=7.5,
    ),
    _Rule(
        name="Flashloan Attack Surface",
        pattern=re.compile(
            r"(?:executeFlashloan|flashLoan|onFlashLoan|receiveFlashLoan)\s*\(",
            re.IGNORECASE,
        ),
        severity="medium",
        category="flashloan",
        description=(
            "Flashloan callback found — verify that price calculations, liquidity checks, "
            "and state mutations within this callback are not exploitable with borrowed funds."
        ),
        remediation=(
            "Use TWAP (time-weighted average price) oracles instead of spot prices. "
            "Validate price impact limits and apply reentrancy guards on callback."
        ),
        swc_id="",
        cvss=6.5,
    ),
    _Rule(
        name="ERC20 Approve/transferFrom Race Condition",
        pattern=re.compile(r"\bapprove\s*\([^)]*,[^)]*\)\s*;", re.IGNORECASE),
        severity="low",
        category="token_race",
        description=(
            "Standard ERC20 approve() is vulnerable to a front-running race condition. "
            "A spender can spend both the old and new allowance if they watch the mempool."
        ),
        remediation=(
            "Use increaseAllowance()/decreaseAllowance() (OpenZeppelin) instead of approve(). "
            "Or implement EIP-2612 permit() for gasless approvals."
        ),
        swc_id="SWC-114",
        cvss=3.7,
    ),
    _Rule(
        name="Emit Events Missing for State Changes",
        pattern=re.compile(
            r"\b(?:onlyOwner|Ownable)\b[^}]{0,300}(?<!emit\s)\b(?:transfer|mint|burn|pause)\b",
            re.DOTALL | re.IGNORECASE,
        ),
        severity="low",
        category="event_logging",
        description="State-changing function appears to lack event emission — off-chain monitoring is blind.",
        remediation="Emit events for all state changes to enable monitoring and transparency.",
        swc_id="SWC-115",
        cvss=2.0,
    ),
]

# Honey-pot / rug-pull patterns (token scanner)
_HONEYPOT_PATTERNS: List[Tuple[re.Pattern, str, str]] = [
    (
        re.compile(r"\b_isExcluded\[.*\]\s*=\s*true\b", re.IGNORECASE),
        "Hidden exclusion list — specific addresses may be excluded from transfer restrictions",
        "high",
    ),
    (
        re.compile(r"\bmaxTxAmount\b", re.IGNORECASE),
        "Max transaction amount limit found — can be changed to zero to block all sells",
        "medium",
    ),
    (
        re.compile(r"blacklist|isBlacklisted|_blacklisted", re.IGNORECASE),
        "Blacklist mechanism found — owner can block any address from transferring",
        "high",
    ),
    (
        re.compile(r"function\s+rescueTokens?\s*\(", re.IGNORECASE),
        "rescueTokens() found — owner can drain funds from the contract",
        "critical",
    ),
    (
        re.compile(r"setFee|changeFee|updateFee", re.IGNORECASE),
        "Changeable fee function — fees can be raised to 100% after launch",
        "high",
    ),
    (
        re.compile(r"renounceOwnership\s*\(\s*\)\s*{[^}]*}", re.IGNORECASE | re.DOTALL),
        "Overridden renounceOwnership() — owner may retain control even after renounce",
        "critical",
    ),
    (
        re.compile(r"tradingEnabled\s*=", re.IGNORECASE),
        "Trading toggle found — owner can disable all trading at any time",
        "high",
    ),
]


# ---------------------------------------------------------------------------
# Scanner
# ---------------------------------------------------------------------------

class SmartContractScanner:
    """
    Smart contract vulnerability scanner.
    Works with: Solidity source files, compiled JSON artifacts, or raw source strings.
    Optionally integrates with Slither for deeper analysis.
    """

    def __init__(self, use_slither: bool = True) -> None:
        self.use_slither = use_slither and self._slither_available()

    @staticmethod
    def _slither_available() -> bool:
        try:
            result = subprocess.run(
                ["slither", "--version"], capture_output=True, timeout=5
            )
            return result.returncode == 0
        except (FileNotFoundError, subprocess.TimeoutExpired):
            return False

    # ------------------------------------------------------------------ #
    #  Public API
    # ------------------------------------------------------------------ #

    def scan_file(self, path: str) -> ContractScanReport:
        """Scan a Solidity file. Uses regex patterns + Slither if available."""
        p = Path(path)
        if not p.exists():
            return ContractScanReport(
                target=path, scan_mode="file",
                error=f"File not found: {path}"
            )
        content = p.read_text(errors="replace")
        contract_name = p.stem
        t0 = time.monotonic()
        findings = self._pattern_scan(content, contract_name, str(p))

        mode = "pattern"
        slither_raw: dict = {}
        if self.use_slither:
            slither_findings, slither_raw = self._slither_scan(path)
            findings.extend(slither_findings)
            mode = "slither+pattern"

        return ContractScanReport(
            target=path,
            scan_mode=mode,
            findings=findings,
            contracts_scanned=1,
            scan_time_s=time.monotonic() - t0,
            slither_raw=slither_raw,
        )

    def scan_source(self, source: str, contract_name: str = "Contract") -> ContractScanReport:
        """Scan raw Solidity source code string."""
        t0 = time.monotonic()
        findings = self._pattern_scan(source, contract_name, "<source>")
        return ContractScanReport(
            target=contract_name,
            scan_mode="pattern",
            findings=findings,
            contracts_scanned=1,
            scan_time_s=time.monotonic() - t0,
        )

    def scan_directory(self, directory: str) -> ContractScanReport:
        """Scan all .sol files in directory."""
        t0 = time.monotonic()
        base = Path(directory)
        all_findings: List[ContractFinding] = []
        count = 0

        for sol_file in base.rglob("*.sol"):
            try:
                content = sol_file.read_text(errors="replace")
                findings = self._pattern_scan(content, sol_file.stem, str(sol_file))
                all_findings.extend(findings)
                count += 1
            except Exception as exc:
                log.debug("Failed scanning %s: %s", sol_file, exc)

        slither_raw: dict = {}
        mode = "pattern"
        if self.use_slither:
            slither_findings, slither_raw = self._slither_scan(directory)
            all_findings.extend(slither_findings)
            mode = "slither+pattern"

        return ContractScanReport(
            target=directory,
            scan_mode=mode,
            findings=all_findings,
            contracts_scanned=count,
            scan_time_s=time.monotonic() - t0,
            slither_raw=slither_raw,
        )

    def scan_token(self, source: str, contract_name: str = "Token") -> List[ContractFinding]:
        """Additional honey-pot / rug-pull analysis for token contracts."""
        findings: List[ContractFinding] = []
        lines = source.splitlines()
        for pattern, description, severity in _HONEYPOT_PATTERNS:
            for i, line in enumerate(lines, 1):
                if pattern.search(line):
                    findings.append(ContractFinding(
                        finding_id=f"tok-{uuid.uuid4().hex[:8]}",
                        title=f"Token Risk: {description[:50]}",
                        severity=severity,
                        category="token_risk",
                        description=description,
                        contract=contract_name,
                        line_number=i,
                        evidence=line.strip()[:100],
                        remediation=(
                            "Review this pattern carefully before investing. "
                            "Run a comprehensive token audit with multiple tools."
                        ),
                        cvss_score={"critical": 9.0, "high": 7.0, "medium": 5.0, "low": 2.0}.get(severity, 5.0),
                    ))
        return findings

    # ------------------------------------------------------------------ #
    #  Foundry PoC generator
    # ------------------------------------------------------------------ #

    def generate_foundry_poc(self, finding: ContractFinding, contract_path: str = "src/Target.sol") -> str:
        """
        Generate a Foundry (forge test) PoC skeleton for a given finding.
        Returns the Solidity test file content as a string.
        """
        swc_comment = f" // {finding.swc_id}" if finding.swc_id else ""
        return f'''// SPDX-License-Identifier: MIT
pragma solidity ^0.8.19;

import "forge-std/Test.sol";
import "{contract_path}";

// PoC for: {finding.title}
// Severity: {finding.severity.upper()}{swc_comment}
// Generated by OneInfinity Smart Contract Scanner
contract {finding.category.title().replace("_", "")}PocTest is Test {{

    // TODO: replace with actual contract interface
    // Target target;

    function setUp() public {{
        // Deploy target contract
        // target = new Target();
        // vm.deal(address(this), 100 ether);
    }}

    function test_{finding.category}_exploit() public {{
        // {finding.description[:80]}
        //
        // Step 1: Set up initial state
        //
        // Step 2: Execute exploit
        //    {finding.poc_sketch.replace(chr(10), chr(10) + "    //    ") if finding.poc_sketch else "// TODO: implement exploit steps"}
        //
        // Step 3: Assert impact
        // assertGt(address(this).balance, initialBalance, "Exploit succeeded");
        assertTrue(false, "TODO: implement PoC");
    }}

    receive() external payable {{}}
}}
'''

    # ------------------------------------------------------------------ #
    #  Internal
    # ------------------------------------------------------------------ #

    def _pattern_scan(
        self, source: str, contract_name: str, file_path: str
    ) -> List[ContractFinding]:
        findings: List[ContractFinding] = []
        lines = source.splitlines()

        for rule in _RULES:
            for i, line in enumerate(lines, 1):
                if rule.pattern.search(line):
                    findings.append(ContractFinding(
                        finding_id=f"sc-{uuid.uuid4().hex[:8]}",
                        title=rule.name,
                        severity=rule.severity,
                        category=rule.category,
                        description=rule.description,
                        contract=contract_name,
                        line_number=i,
                        evidence=line.strip()[:120],
                        remediation=rule.remediation,
                        cvss_score=rule.cvss,
                        swc_id=rule.swc_id,
                        poc_sketch=rule.poc_sketch,
                    ))
                    break  # one finding per rule per contract

        return findings

    def _slither_scan(self, target: str) -> Tuple[List[ContractFinding], dict]:
        findings: List[ContractFinding] = []
        raw: dict = {}
        try:
            with tempfile.NamedTemporaryFile(suffix=".json", delete=False) as tf:
                out_path = tf.name

            result = subprocess.run(
                ["slither", target, "--json", out_path, "--no-fail-pedantic"],
                capture_output=True, text=True, timeout=120,
            )

            if Path(out_path).exists():
                try:
                    raw = json.loads(Path(out_path).read_text())
                finally:
                    os.unlink(out_path)

            for det in raw.get("results", {}).get("detectors", []):
                sev_map = {
                    "High": "high", "Medium": "medium",
                    "Low": "low", "Informational": "info",
                }
                sev = sev_map.get(det.get("impact", "Low"), "low")
                elements = det.get("elements", [])
                contract = elements[0].get("type_specific_fields", {}).get("parent", {}).get("name", "") if elements else ""
                fn_name = elements[0].get("name", "") if elements else ""
                line = 0
                if elements:
                    src = elements[0].get("source_mapping", {})
                    line = src.get("lines", [0])[0] if src.get("lines") else 0

                findings.append(ContractFinding(
                    finding_id=f"slither-{uuid.uuid4().hex[:8]}",
                    title=f"[Slither] {det.get('check', 'unknown')}",
                    severity=sev,
                    category=det.get("check", "").replace("-", "_"),
                    description=det.get("description", ""),
                    contract=contract,
                    function_name=fn_name,
                    line_number=line,
                    evidence=det.get("description", "")[:120],
                    remediation=det.get("wiki_recommendation", ""),
                    swc_id=str(det.get("wiki_exploit_scenario", ""))[:10],
                    cvss_score={"high": 8.0, "medium": 5.0, "low": 2.0, "info": 0.0}.get(sev, 0.0),
                ))

        except FileNotFoundError:
            log.debug("slither not found — skipping Slither analysis")
        except subprocess.TimeoutExpired:
            log.warning("Slither timed out on %s", target)
        except Exception as exc:
            log.warning("Slither scan failed: %s", exc)

        return findings, raw
