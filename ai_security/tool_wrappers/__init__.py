"""
AI Security Tool Wrappers.

Each wrapper implements a common async interface:
    async def run(target: str, config: dict) -> List[AIVulnFinding]

Wrappers gracefully degrade if the tool is not installed,
falling back to built-in testing logic.
"""

from .garak_wrapper import GarakWrapper
from .pyrit_wrapper import PyRITWrapper
from .giskard_wrapper import GiskardWrapper
from .purple_llama_wrapper import PurpleLlamaWrapper
from .rebuff_wrapper import RebuffWrapper
from .art_wrapper import ARTWrapper

__all__ = [
    "GarakWrapper",
    "PyRITWrapper",
    "GiskardWrapper",
    "PurpleLlamaWrapper",
    "RebuffWrapper",
    "ARTWrapper",
]
