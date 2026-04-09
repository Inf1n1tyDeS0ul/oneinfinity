# tests/test_adversarial_pg.py
"""Tests verifying EvolutionDB routes writes/reads through DBManager in PG mode."""
import sys
import os
from unittest.mock import MagicMock, patch

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if REPO_ROOT not in sys.path:
    sys.path.insert(0, REPO_ROOT)


def _make_pg_mgr():
    mgr = MagicMock()
    mgr.mode = "postgres"
    mgr.sync_pg_execute_write = MagicMock(return_value=1)
    mgr.sync_pg_execute_read = MagicMock(return_value=[])
    return mgr


def _make_gene():
    from ai_security.adversarial_prompt_evolution import PromptGene
    return PromptGene(
        prompt_id="pg-001",
        text="test payload",
        attack_type="xss",
        source="seed",
        parent_ids=[],
        generation=0,
        mutation_type="none",
    )


def test_save_gene_calls_pg_execute_write(tmp_path):
    """save_gene() must call sync_pg_execute_write with prompt_genes SQL in PG mode."""
    from ai_security.adversarial_prompt_evolution import EvolutionDB
    mock_mgr = _make_pg_mgr()

    with patch("ai_security.adversarial_prompt_evolution.EvolutionDB._pg", return_value=mock_mgr):
        db = EvolutionDB(db_path=tmp_path / "evolution.db")
        db.save_gene(_make_gene())

    assert mock_mgr.sync_pg_execute_write.called, "sync_pg_execute_write should be called"
    sqls = [c[0][0] for c in mock_mgr.sync_pg_execute_write.call_args_list]
    assert any("prompt_genes" in s for s in sqls), \
        f"At least one SQL should target prompt_genes, got: {sqls}"


def test_record_result_calls_pg_execute_write(tmp_path):
    """record_result() must call sync_pg_execute_write with test_results SQL in PG mode."""
    from ai_security.adversarial_prompt_evolution import EvolutionDB
    mock_mgr = _make_pg_mgr()

    with patch("ai_security.adversarial_prompt_evolution.EvolutionDB._pg", return_value=mock_mgr):
        db = EvolutionDB(db_path=tmp_path / "evolution.db")
        db.record_result(
            prompt_id="p-001",
            target="http://example.com",
            response_hash="abc123",
            success=True,
            score=0.9,
            attack_type="xss",
            mutation_type="paraphrase",
        )

    sqls = [c[0][0] for c in mock_mgr.sync_pg_execute_write.call_args_list]
    assert any("test_results" in s for s in sqls), \
        f"At least one SQL should target test_results, got: {sqls}"


def test_save_gene_raises_when_pg_unavailable(tmp_path):
    """When _pg() raises, save_gene() must propagate the RuntimeError."""
    from ai_security.adversarial_prompt_evolution import EvolutionDB

    with patch("ai_security.adversarial_prompt_evolution.EvolutionDB._pg",
               side_effect=RuntimeError("PostgreSQL is required")):
        db = EvolutionDB(db_path=tmp_path / "evolution.db")
        try:
            db.save_gene(_make_gene())
            assert False, "Expected RuntimeError"
        except RuntimeError as exc:
            assert "PostgreSQL" in str(exc)
