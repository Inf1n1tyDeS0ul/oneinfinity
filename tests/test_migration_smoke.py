# tests/test_migration_smoke.py
import pathlib

def test_migration_script_is_executable():
    """Migration script must exist and be syntactically valid Python."""
    import ast
    path = pathlib.Path("/home/devendra-yadav/oneinfinity/scripts/migrate_sqlite_to_pg.py")
    assert path.exists()
    ast.parse(path.read_text())  # syntax check

def test_init_postgres_script_is_executable():
    """Init script must exist and be syntactically valid."""
    import ast
    path = pathlib.Path("/home/devendra-yadav/oneinfinity/scripts/init_postgres.py")
    assert path.exists()
    ast.parse(path.read_text())

def test_migration_dry_run_without_postgres(tmp_path):
    """Migration dry run must gracefully fail with no Postgres URL."""
    import subprocess, sys
    result = subprocess.run(
        [sys.executable, "scripts/migrate_sqlite_to_pg.py", "--dry-run"],
        capture_output=True, text=True,
        cwd="/home/devendra-yadav/oneinfinity",
        env={"PATH": "/usr/bin:/bin:/usr/local/bin"},  # no POSTGRES_URL
    )
    assert result.returncode != 0  # must exit non-zero when no POSTGRES_URL
    assert "POSTGRES_URL" in result.stderr or "POSTGRES_URL" in result.stdout
