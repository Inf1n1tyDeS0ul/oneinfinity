# tests/test_research_kb_removed.py
"""
Static checks: ResearchKnowledgeBase and sqlite3 are fully gone from
research_mode_controller.py, and show_research_stats() uses ResearchRepository.
These tests fail before deletion and pass after.
"""
import ast
from pathlib import Path


def _source():
    return Path("research_mode_controller.py").read_text()


def test_no_research_knowledge_base_class():
    source = _source()
    assert "class ResearchKnowledgeBase" not in source, (
        "ResearchKnowledgeBase class must be deleted from research_mode_controller.py"
    )


def test_no_sqlite3_import():
    source = _source()
    tree = ast.parse(source)
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                assert alias.name != "sqlite3", \
                    "sqlite3 must not be imported in research_mode_controller.py"
        if isinstance(node, ast.ImportFrom):
            assert node.module != "sqlite3", \
                "sqlite3 must not be imported in research_mode_controller.py"


def test_show_research_stats_uses_get_research_repo():
    source = _source()
    assert "ResearchKnowledgeBase" not in source
    assert "get_research_repo" in source, \
        "show_research_stats must use get_research_repo"
    assert "asyncio.run" in source, \
        "show_research_stats must wrap async fetch in asyncio.run"
