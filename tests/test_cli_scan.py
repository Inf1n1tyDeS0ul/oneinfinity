# tests/test_cli_scan.py
import subprocess, sys, os, pathlib

PROJECT_ROOT = pathlib.Path(__file__).parent.parent
ONEINFINITY = str(PROJECT_ROOT / "oneinfinity")


def test_scan_without_yes_warns_user():
    """Running scan without --yes must print a warning to stderr."""
    result = subprocess.run(
        [sys.executable, ONEINFINITY, "scan", "example.com"],
        capture_output=True,
        text=True,
        cwd=str(PROJECT_ROOT),
        input="n\n",
        timeout=15,
        env={**os.environ, "OI_AUTO_YES": ""},  # ensure auto-yes is off
    )
    combined = result.stdout + result.stderr
    # Must contain some warning about the no-scan behavior
    has_warning = (
        "WARNING" in combined.upper()
        or "warning" in combined.lower()
        or "--yes" in combined
        or "no scan" in combined.lower()
        or "script" in combined.lower()
        or "does not" in combined.lower()
    )
    assert has_warning, (
        f"No warning shown when running scan without --yes.\n"
        f"stdout: {result.stdout[:500]}\n"
        f"stderr: {result.stderr[:500]}"
    )


def test_scan_without_yes_mentions_yes_flag():
    """Warning must tell user about the --yes flag."""
    result = subprocess.run(
        [sys.executable, ONEINFINITY, "scan", "example.com"],
        capture_output=True,
        text=True,
        cwd=str(PROJECT_ROOT),
        input="n\n",
        timeout=15,
        env={**os.environ, "OI_AUTO_YES": ""},
    )
    combined = result.stdout + result.stderr
    assert "--yes" in combined, (
        f"Warning should mention --yes flag but didn't.\n"
        f"Output: {combined[:500]}"
    )
