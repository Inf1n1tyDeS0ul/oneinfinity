"""Credential attack pipeline: spray, wordlist generation, OSINT, breach checking."""
from oneinfinity.attack.credential.spray_engine import (
    CredentialSprayEngine,
    SprayReport,
    SprayAttempt,
    WordlistGenerator,
    EmployeeOSINT,
    HIBPChecker,
    VENDOR_DEFAULTS,
)

__all__ = [
    "CredentialSprayEngine",
    "SprayReport",
    "SprayAttempt",
    "WordlistGenerator",
    "EmployeeOSINT",
    "HIBPChecker",
    "VENDOR_DEFAULTS",
]
