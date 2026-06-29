"""solana_scanner.py — Solana SPL token and program security scanner."""
from __future__ import annotations

import json
import logging
import os as _os
import urllib.request
from dataclasses import dataclass, field
from typing import List, Optional

log = logging.getLogger("oneinfinity.web3.solana")

SOLANA_MAINNET_RPC = _os.environ.get("ONEINFINITY_SOLANA_RPC", "https://api.mainnet-beta.solana.com")


@dataclass
class SolanaFlag:
    name: str
    severity: str
    description: str
    evidence: str = ""


@dataclass
class SolanaTokenResult:
    mint_address: str
    flags: List[SolanaFlag] = field(default_factory=list)
    mint_authority: Optional[str] = None
    freeze_authority: Optional[str] = None
    is_mintable: bool = False
    is_freezable: bool = False
    supply: int = 0
    decimals: int = 9

    @property
    def risk_score(self) -> int:
        score = 0
        if self.is_mintable:
            score += 40
        if self.is_freezable:
            score += 30
        for f in self.flags:
            if f.severity == "critical":
                score += 15
            elif f.severity == "high":
                score += 10
        return min(score, 100)

    def summary(self) -> str:
        lines = [
            f"Solana Token: {self.mint_address}",
            f"Risk Score: {self.risk_score}/100",
            f"Mint Authority: {self.mint_authority or 'None (renounced)'}",
            f"Freeze Authority: {self.freeze_authority or 'None (renounced)'}",
            f"Is Mintable: {self.is_mintable}",
            f"Is Freezable: {self.is_freezable}",
            f"Supply: {self.supply / (10 ** self.decimals):.2f}",
        ]
        for flag in self.flags:
            lines.append(f"  [{flag.severity.upper()}] {flag.name}: {flag.description}")
        return "\n".join(lines)


class SolanaScanner:
    """Scanner for Solana SPL token authority and program security checks."""

    def __init__(self, rpc_url: str = ""):
        self.rpc_url = rpc_url or SOLANA_MAINNET_RPC

    def _rpc(self, method: str, params: list) -> dict:
        payload = json.dumps({
            "jsonrpc": "2.0",
            "id": 1,
            "method": method,
            "params": params,
        }).encode()
        req = urllib.request.Request(
            self.rpc_url,
            data=payload,
            headers={"Content-Type": "application/json"},
        )
        with urllib.request.urlopen(req, timeout=15) as resp:
            return json.loads(resp.read())

    def scan_token(self, mint_address: str) -> SolanaTokenResult:
        """Scan a Solana SPL token mint account for authority and security issues."""
        result = SolanaTokenResult(mint_address=mint_address)

        try:
            data = self._rpc(
                "getAccountInfo",
                [mint_address, {"encoding": "jsonParsed"}],
            )
            info = (
                data.get("result", {})
                .get("value", {})
                .get("data", {})
                .get("parsed", {})
                .get("info", {})
            )

            result.supply = int(info.get("supply", 0))
            result.decimals = int(info.get("decimals", 9))
            result.mint_authority = info.get("mintAuthority")
            result.freeze_authority = info.get("freezeAuthority")
            result.is_mintable = result.mint_authority is not None
            result.is_freezable = result.freeze_authority is not None

            if result.is_mintable:
                result.flags.append(SolanaFlag(
                    name="Active Mint Authority",
                    severity="critical",
                    description=(
                        f"Mint authority ({result.mint_authority[:8]}...) can "
                        "create unlimited tokens — extreme rug pull risk"
                    ),
                    evidence=f"mintAuthority: {result.mint_authority}",
                ))
            if result.is_freezable:
                result.flags.append(SolanaFlag(
                    name="Active Freeze Authority",
                    severity="high",
                    description=(
                        f"Freeze authority ({result.freeze_authority[:8]}...) can "
                        "freeze any holder account — honeypot risk"
                    ),
                    evidence=f"freezeAuthority: {result.freeze_authority}",
                ))

        except Exception as exc:
            log.warning("Solana scan_token(%s) failed: %s", mint_address, exc)
            result.flags.append(SolanaFlag(
                name="RPC Error",
                severity="info",
                description=f"Could not fetch on-chain data: {exc}",
            ))

        return result

    def check_program_upgradeable(self, program_id: str) -> dict:
        """Check if a Solana program is upgradeable (proxy risk)."""
        try:
            data = self._rpc(
                "getAccountInfo",
                [program_id, {"encoding": "jsonParsed"}],
            )
            info = (
                data.get("result", {})
                .get("value", {})
                .get("data", {})
                .get("parsed", {})
                .get("info", {})
            )
            upgrade_authority = info.get("upgradeAuthority")
            return {
                "upgradeable": upgrade_authority is not None,
                "upgrade_authority": upgrade_authority,
                "risk": "high" if upgrade_authority else "low",
            }
        except Exception as exc:
            log.warning("Solana check_program_upgradeable(%s) failed: %s", program_id, exc)
            return {"upgradeable": None, "error": str(exc)}
