"""Web3 / smart contract security scanners."""
from oneinfinity.web3.smart_contract_scanner import SmartContractScanner
from oneinfinity.web3.slither_wrapper import SlitherFinding, run as slither_run, is_available as slither_available
from oneinfinity.web3.foundry_poc_generator import FoundryPoC, generate as foundry_generate
from oneinfinity.web3.evm_token_scanner import EVMTokenScanner, TokenScanResult, TokenFlag
from oneinfinity.web3.solana_scanner import SolanaScanner, SolanaTokenResult, SolanaFlag

__all__ = [
    "SmartContractScanner",
    "SlitherFinding",
    "slither_run",
    "slither_available",
    "FoundryPoC",
    "foundry_generate",
    "EVMTokenScanner",
    "TokenScanResult",
    "TokenFlag",
    "SolanaScanner",
    "SolanaTokenResult",
    "SolanaFlag",
]
