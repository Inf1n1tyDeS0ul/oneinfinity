import pathlib

API_JS = pathlib.Path(
    "/home/devendra-yadav/oneinfinity/web/frontend/src/utils/api.js"
).read_text()

DEAD_ALIASES = ["cvssCalculate", "dedupCheck", "methodologyGet", "wafBypassPayloads"]

CORRECT_ALIASES = ["utilsCvss", "utilsDedup", "utilsMethodology", "utilsWafBypass"]


def test_dead_api_aliases_removed():
    """Dead aliases calling /utilities/* (non-existent routes) must be removed."""
    for alias in DEAD_ALIASES:
        assert alias not in API_JS, (
            f"Dead API alias '{alias}' still in api.js — it calls /utilities/* "
            "which doesn't exist in the backend. Remove it."
        )


def test_correct_aliases_still_present():
    """The correct aliases calling /utils/* must still exist after cleanup."""
    for alias in CORRECT_ALIASES:
        assert alias in API_JS, (
            f"Correct alias '{alias}' was accidentally removed from api.js. "
            "Only remove the dead /utilities/* aliases, not the working /utils/* ones."
        )
