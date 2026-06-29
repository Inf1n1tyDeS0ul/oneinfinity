"""
test_phase5_libafl.py — tests for LibAFL oi-fuzzer and fuzzer_driver.py.
"""
import os
import shutil
import subprocess
import pathlib
import pytest


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _have_cargo() -> bool:
    return shutil.which("cargo") is not None


def _fuzzer_bin_exists() -> bool:
    """Check if the oi-fuzzer binary has been built."""
    candidates = [
        "src/rust/target/release/oi-fuzzer",
        "src/rust/oi-fuzzer/target/release/oi-fuzzer",
    ]
    return any(pathlib.Path(p).exists() for p in candidates)


def _have_fuzzer_on_path() -> bool:
    return shutil.which("oi-fuzzer") is not None


# ---------------------------------------------------------------------------
# oi-fuzzer crate structure
# ---------------------------------------------------------------------------

class TestFuzzerCrateStructure:
    def test_fuzzer_cargo_toml_exists(self):
        assert (
            pathlib.Path("src/rust/oi-fuzzer/Cargo.toml").exists()
        ), "src/rust/oi-fuzzer/Cargo.toml missing"

    def test_fuzzer_main_rs_exists(self):
        assert (
            pathlib.Path("src/rust/oi-fuzzer/src/main.rs").exists()
        ), "src/rust/oi-fuzzer/src/main.rs missing"

    def test_fuzzer_is_bin_not_lib(self):
        content = pathlib.Path("src/rust/oi-fuzzer/Cargo.toml").read_text()
        assert "[[bin]]" in content or 'name = "oi-fuzzer"' in content

    def test_fuzzer_not_linked_into_oneinfinity_core(self):
        """oi-fuzzer must be a separate crate — not in oneinfinity_core's Cargo.toml."""
        core_toml = pathlib.Path("src/rust/oneinfinity_core/Cargo.toml").read_text()
        assert "oi-fuzzer" not in core_toml

    def test_fuzzer_has_panic_unwind(self):
        content = pathlib.Path("src/rust/oi-fuzzer/Cargo.toml").read_text()
        assert 'panic = "unwind"' in content

    def test_fuzzer_main_rs_has_clap_or_arg_parsing(self):
        content = pathlib.Path("src/rust/oi-fuzzer/src/main.rs").read_text()
        assert "clap" in content or "args" in content.lower() or "Args" in content

    def test_fuzzer_main_rs_outputs_json(self):
        content = pathlib.Path("src/rust/oi-fuzzer/src/main.rs").read_text()
        assert "json" in content.lower() or "serde" in content or "println" in content

    def test_fuzzer_main_rs_has_corpus_or_finding_output(self):
        content = pathlib.Path("src/rust/oi-fuzzer/src/main.rs").read_text()
        assert "corpus" in content or "finding" in content or "type" in content


# ---------------------------------------------------------------------------
# oi-fuzzer build
# ---------------------------------------------------------------------------

@pytest.mark.skipif(not _have_cargo(), reason="cargo not available")
class TestFuzzerBuild:
    def test_fuzzer_cargo_build_release(self):
        """oi-fuzzer must compile with cargo build --release."""
        result = subprocess.run(
            ["cargo", "build", "--release", "--manifest-path",
             "src/rust/oi-fuzzer/Cargo.toml"],
            capture_output=True, text=True, timeout=300,
            cwd=str(pathlib.Path.cwd())
        )
        assert result.returncode == 0, (
            f"cargo build failed:\nSTDOUT:\n{result.stdout[-2000:]}\n"
            f"STDERR:\n{result.stderr[-2000:]}"
        )

    def test_fuzzer_binary_produced(self):
        """After build, the oi-fuzzer binary must exist."""
        assert _fuzzer_bin_exists(), "oi-fuzzer binary not found after build"


# ---------------------------------------------------------------------------
# oi-fuzzer runtime (when binary is built)
# ---------------------------------------------------------------------------

@pytest.mark.skipif(not _fuzzer_bin_exists(), reason="oi-fuzzer not built")
class TestFuzzerRuntime:
    def _bin(self):
        for p in [
            "src/rust/oi-fuzzer/target/release/oi-fuzzer",
            "src/rust/target/release/oi-fuzzer",
        ]:
            if pathlib.Path(p).exists():
                return p
        pytest.skip("oi-fuzzer binary not found")

    def test_fuzzer_help_exits_cleanly(self):
        result = subprocess.run(
            [self._bin(), "--help"],
            capture_output=True, text=True, timeout=10
        )
        assert result.returncode in (0, 1), "help flag must exit 0 or 1"

    def test_fuzzer_short_run_outputs_ndjson(self):
        """A short deterministic run must produce valid NDJSON lines."""
        import json as _json
        result = subprocess.run(
            [self._bin(), "--target", "http", "--iterations", "5",
             "--timeout-secs", "10"],
            capture_output=True, text=True, timeout=30
        )
        assert result.returncode == 0, f"oi-fuzzer exited {result.returncode}: {result.stderr}"
        lines = [l for l in result.stdout.splitlines() if l.strip()]
        assert len(lines) >= 1, "oi-fuzzer produced no output"
        for line in lines:
            item = _json.loads(line)  # must be valid JSON
            assert "type" in item

    def test_fuzzer_corpus_items_have_data_field(self):
        import json as _json
        result = subprocess.run(
            [self._bin(), "--target", "http", "--iterations", "5",
             "--timeout-secs", "10"],
            capture_output=True, text=True, timeout=30
        )
        lines = [l for l in result.stdout.splitlines() if l.strip()]
        corpus = [_json.loads(l) for l in lines
                  if _json.loads(l).get("type") in ("corpus", "finding")]
        # stats lines are valid output but don't carry data — only corpus/finding must
        for item in corpus:
            assert "data" in item or "payload" in item, f"Corpus item missing data: {item}"


# ---------------------------------------------------------------------------
# fuzzer_driver.py
# ---------------------------------------------------------------------------

class TestFuzzerDriverModule:
    def test_fuzzer_driver_importable(self):
        from src.oneinfinity.scan.fuzzer_driver import FuzzerDriver
        assert FuzzerDriver is not None

    def test_fuzzer_driver_disabled_by_default(self):
        os.environ.pop("ONEINFINITY_RUST_FUZZER", None)
        from src.oneinfinity.scan.fuzzer_driver import FuzzerDriver
        driver = FuzzerDriver(target="http", timeout_secs=5, iterations=3)
        result = driver.run()
        assert result == [], f"Expected [] when disabled, got {result}"

    def test_fuzzer_driver_returns_list(self):
        from src.oneinfinity.scan.fuzzer_driver import FuzzerDriver
        driver = FuzzerDriver()
        result = driver.run()
        assert isinstance(result, list)

    def test_fuzzer_driver_flag_zero_disables(self, monkeypatch):
        monkeypatch.setenv("ONEINFINITY_RUST_FUZZER", "0")
        from src.oneinfinity.scan import fuzzer_driver as fd_mod
        import importlib
        importlib.reload(fd_mod)
        driver = fd_mod.FuzzerDriver()
        assert driver.run() == []

    def test_fuzzer_driver_missing_binary_returns_empty(self, monkeypatch):
        """When oi-fuzzer is not on PATH, FuzzerDriver.run() must return []."""
        monkeypatch.setenv("ONEINFINITY_RUST_FUZZER", "1")
        monkeypatch.setenv("OI_FUZZER_BIN", "/nonexistent/oi-fuzzer")
        from src.oneinfinity.scan import fuzzer_driver as fd_mod
        import importlib
        importlib.reload(fd_mod)
        driver = fd_mod.FuzzerDriver()
        result = driver.run()
        assert result == []

    @pytest.mark.skipif(not _fuzzer_bin_exists(), reason="oi-fuzzer not built")
    def test_fuzzer_driver_with_binary_produces_list_of_dicts(self, monkeypatch):
        """When oi-fuzzer is available and flag=1, run() must return list of dicts."""
        bin_path = next(
            (p for p in ["src/rust/oi-fuzzer/target/release/oi-fuzzer",
                          "src/rust/target/release/oi-fuzzer"]
             if pathlib.Path(p).exists()),
            None
        )
        if bin_path is None:
            pytest.skip("binary not found")
        monkeypatch.setenv("ONEINFINITY_RUST_FUZZER", "1")
        monkeypatch.setenv("OI_FUZZER_BIN", str(pathlib.Path(bin_path).resolve()))
        from src.oneinfinity.scan import fuzzer_driver as fd_mod
        import importlib
        importlib.reload(fd_mod)
        driver = fd_mod.FuzzerDriver(target="http", timeout_secs=15, iterations=5)
        result = driver.run()
        assert isinstance(result, list)
        for item in result:
            assert isinstance(item, dict)
            assert "type" in item
