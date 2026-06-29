"""evm_token_scanner.py — EVM token red flag scanner for rug pull / honeypot detection."""
from __future__ import annotations

import json
import logging
import urllib.request
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional

log = logging.getLogger("oneinfinity.web3.evm_token")


@dataclass
class TokenFlag:
    name: str
    severity: str   # critical, high, medium, low
    description: str
    evidence: str = ""


@dataclass
class TokenScanResult:
    contract_address: str
    chain: str
    is_honeypot: bool
    flags: List[TokenFlag] = field(default_factory=list)
    can_buy: bool = True
    can_sell: bool = True
    buy_tax_pct: float = 0.0
    sell_tax_pct: float = 0.0
    liquidity_locked: bool = False
    ownership_renounced: bool = False
    is_proxy: bool = False
    total_supply: int = 0
    holder_count: int = 0
    top10_concentration_pct: float = 0.0

    @property
    def risk_score(self) -> int:
        """0-100 risk score. >70 = high risk."""
        score = 0
        if self.is_honeypot:
            score += 50
        if not self.liquidity_locked:
            score += 20
        if not self.ownership_renounced:
            score += 15
        if self.sell_tax_pct > 10:
            score += 10
        if self.top10_concentration_pct > 80:
            score += 10
        for f in self.flags:
            if f.severity == "critical":
                score += 10
            elif f.severity == "high":
                score += 5
        return min(score, 100)

    def summary(self) -> str:
        lines = [
            f"Token: {self.contract_address} [{self.chain}]",
            f"Risk Score: {self.risk_score}/100",
            f"Honeypot: {'YES ⚠️' if self.is_honeypot else 'No'}",
            f"Can Buy: {self.can_buy} | Can Sell: {self.can_sell}",
            f"Buy Tax: {self.buy_tax_pct:.1f}% | Sell Tax: {self.sell_tax_pct:.1f}%",
            f"Liquidity Locked: {self.liquidity_locked}",
            f"Ownership Renounced: {self.ownership_renounced}",
        ]
        for flag in self.flags:
            lines.append(f"  [{flag.severity.upper()}] {flag.name}: {flag.description}")
        return "\n".join(lines)


class EVMTokenScanner:
    """
    Scan EVM tokens for rug pull indicators and honeypot patterns.

    Uses HoneypotIs API (free, no key required) and token-sniffer-style heuristics.
    Falls back to source code pattern matching if on-chain APIs unavailable.
    """

    HONEYPOT_API = "https://api.honeypot.is/v2/IsHoneypot"
    TOKENSNIFFER_API = "https://tokensniffer.com/api/v2/tokens"

    # Dangerous function signatures in bytecode/source
    DANGER_PATTERNS = [
        ("blacklist", "high", "Token has blacklist function — can block sells"),
        ("whitelist", "medium", "Token has whitelist — restricted trading"),
        ("setMaxTxAmount", "medium", "Max transaction limit can be changed"),
        ("pause", "high", "Trading can be paused by owner"),
        ("mint", "high", "Owner can mint unlimited tokens"),
        ("burn.*owner", "medium", "Owner can burn arbitrary holder tokens"),
        ("setTaxFee", "high", "Tax rate can be changed by owner"),
        ("renounceOwnership.*false", "critical", "Ownership renounce disabled"),
        ("selfdestruct", "critical", "Contract can self-destruct (rug)"),
        ("delegatecall", "high", "Proxy delegatecall — can swap implementation"),
    ]

    def __init__(self, rpc_url: str = "", chain: str = "ethereum"):
        self.rpc_url = rpc_url
        self.chain = chain

    def scan_address(self, contract_address: str) -> TokenScanResult:
        """Scan a token contract address for red flags."""
        result = TokenScanResult(
            contract_address=contract_address,
            chain=self.chain,
            is_honeypot=False,
        )

        # 1. Try HoneypotIs API
        try:
            url = f"{self.HONEYPOT_API}?address={contract_address}&chainID=1"
            req = urllib.request.Request(url, headers={"Accept": "application/json"})
            with urllib.request.urlopen(req, timeout=10) as resp:
                data = json.loads(resp.read())
            hp = data.get("honeypotResult", {})
            sim = data.get("simulationResult", {})
            result.is_honeypot = hp.get("isHoneypot", False)
            result.can_buy = sim.get("canBuy", True)
            result.can_sell = not result.is_honeypot and sim.get("sellTax", 0) < 90
            result.buy_tax_pct = float(sim.get("buyTax", 0) or 0)
            result.sell_tax_pct = float(sim.get("sellTax", 0) or 0)

            if result.is_honeypot:
                result.flags.append(TokenFlag(
                    name="Honeypot Detected",
                    severity="critical",
                    description=hp.get("honeypotReason", "Cannot sell tokens"),
                    evidence=str(hp),
                ))
            if result.sell_tax_pct > 10:
                result.flags.append(TokenFlag(
                    name="High Sell Tax",
                    severity="high" if result.sell_tax_pct > 25 else "medium",
                    description=f"Sell tax is {result.sell_tax_pct:.1f}%",
                ))
        except Exception as exc:
            log.debug("HoneypotIs API unavailable: %s", exc)

        # 2. Liquidity and ownership checks (heuristic)
        result.ownership_renounced = self._check_ownership_renounced(contract_address)
        result.liquidity_locked = self._check_liquidity_locked(contract_address)

        if not result.ownership_renounced:
            result.flags.append(TokenFlag(
                name="Ownership Not Renounced",
                severity="high",
                description="Owner retains admin privileges — can modify contract behavior",
            ))
        if not result.liquidity_locked:
            result.flags.append(TokenFlag(
                name="Liquidity Not Verified Locked",
                severity="medium",
                description="Cannot verify liquidity lock — rug pull risk",
            ))

        return result

    def scan_source(self, source_code: str, contract_address: str = "") -> TokenScanResult:
        """Scan Solidity source code for red flag patterns."""
        result = TokenScanResult(
            contract_address=contract_address or "source_analysis",
            chain=self.chain,
            is_honeypot=False,
        )
        import re
        for pattern, severity, description in self.DANGER_PATTERNS:
            if re.search(pattern, source_code, re.IGNORECASE):
                result.flags.append(TokenFlag(
                    name=pattern.replace(".*", " ").title(),
                    severity=severity,
                    description=description,
                    evidence=f"Pattern '{pattern}' found in source",
                ))

        # Honeypot heuristics from source
        if re.search(r"_isBlacklisted\[.*\]\s*=\s*true", source_code):
            result.is_honeypot = True
            result.flags.insert(0, TokenFlag(
                name="Honeypot Pattern",
                severity="critical",
                description="Blacklist assignment pattern — likely honeypot",
            ))
        return result

    def _check_ownership_renounced(self, address: str) -> bool:
        """Check if contract ownership has been renounced (owner == 0x0)."""
        if not self.rpc_url:
            return False
        try:
            # eth_call: owner() → address(0)?
            payload = json.dumps({
                "jsonrpc": "2.0", "id": 1, "method": "eth_call",
                "params": [{"to": address, "data": "0x8da5cb5b"}, "latest"],  # owner()
            }).encode()
            req = urllib.request.Request(
                self.rpc_url, data=payload,
                headers={"Content-Type": "application/json"},
            )
            with urllib.request.urlopen(req, timeout=5) as resp:
                result_hex = json.loads(resp.read()).get("result", "")
            # Owner is address(0) if last 40 chars are all zeros
            return result_hex.endswith("0" * 40)
        except Exception:
            return False

    def _check_liquidity_locked(self, address: str) -> bool:
        """Check if LP tokens are locked in known locker contracts via eth_call."""
        if not self.rpc_url:
            return False
        # Known locker contracts
        LOCKERS = [
            "0x663a5c229c09b049e36dcc11a9b0d4a8eb9db214",  # Unicrypt v2
            "0x71b5759d73262fbb223956913ecf4ecd9f5a2a97",  # PinkLock
            "0xE2fE530C047f2d85298b07D9333C05737f1435fB",  # Team Finance
        ]
        # Get the Uniswap V2 pair address for this token
        # Factory.getPair(token, WETH) -> pair_address
        UNISWAP_V2_FACTORY = "0x5C69bEe701ef814a2B6a3EDD4B1652CB9cc5aA6f"
        WETH = "0xC02aaA39b223FE8D0A0e5C4F27eAD9083C756Cc2"
        try:
            # ABI-encode getPair(address,address)
            def _encode_addr(addr):
                return addr[2:].lower().zfill(64)
            data = "0xe6a43905" + _encode_addr(address) + _encode_addr(WETH)
            payload = json.dumps({
                "jsonrpc": "2.0", "id": 1, "method": "eth_call",
                "params": [{"to": UNISWAP_V2_FACTORY, "data": data}, "latest"],
            }).encode()
            req = urllib.request.Request(self.rpc_url, data=payload,
                                          headers={"Content-Type": "application/json"})
            with urllib.request.urlopen(req, timeout=5) as resp:
                pair_hex = json.loads(resp.read()).get("result", "0x")
            pair_addr = "0x" + pair_hex[-40:]
            if int(pair_addr, 16) == 0:
                return False  # no pair exists
            # balanceOf(locker) on pair contract
            SIG_BALANCE_OF = "0x70a08231"
            for locker in LOCKERS:
                data2 = SIG_BALANCE_OF + _encode_addr(locker)
                payload2 = json.dumps({
                    "jsonrpc": "2.0", "id": 2, "method": "eth_call",
                    "params": [{"to": pair_addr, "data": data2}, "latest"],
                }).encode()
                req2 = urllib.request.Request(self.rpc_url, data=payload2,
                                               headers={"Content-Type": "application/json"})
                with urllib.request.urlopen(req2, timeout=5) as resp2:
                    bal_hex = json.loads(resp2.read()).get("result", "0x0")
                if int(bal_hex, 16) > 0:
                    return True
            return False
        except Exception as exc:
            log.debug("_check_liquidity_locked: %s", exc)
            return False
