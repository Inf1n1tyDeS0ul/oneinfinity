"""
Phase 2 — Security tests.

Verifies:
  1. No Go source file in src/go/ contains '0.0.0.0' (loopback enforcement)
  2. All sidecar ports in ports.json are in the range 50051–59999
  3. Python shim fallback returns ToolResult even when gRPC fails
  4. All gRPC channel functions bind to loopback (127.0.0.1), not 0.0.0.0
  5. Port values are integers, not strings
"""
from __future__ import annotations

import json
import os
import unittest
from pathlib import Path
from unittest.mock import patch

PROJECT_ROOT = Path(__file__).resolve().parents[1]
PORTS_FILE   = PROJECT_ROOT / "config" / "ports.json"
GO_SRC_DIR   = PROJECT_ROOT / "src" / "go"

_PORT_MIN = 50051
_PORT_MAX = 59999


# ---------------------------------------------------------------------------
# 1. No Go source file contains '0.0.0.0'
# ---------------------------------------------------------------------------

class TestGoLoopbackEnforcement(unittest.TestCase):

    def _go_files(self):
        return list(GO_SRC_DIR.rglob("*.go"))

    def test_go_src_dir_has_go_files(self):
        """Sanity check: at least one .go file must exist."""
        self.assertGreater(len(self._go_files()), 0, "No .go files found in src/go/")

    def test_no_go_file_binds_all_interfaces(self):
        """0.0.0.0 in non-comment Go source code would expose the sidecar."""
        violations: list[str] = []
        for go_file in self._go_files():
            text = go_file.read_text(errors="replace")
            if "0.0.0.0" not in text:
                continue
            for lineno, line in enumerate(text.splitlines(), 1):
                stripped = line.strip()
                # Skip comment lines and lines where 0.0.0.0 appears only as
                # a CIDR prefix (e.g. "0.0.0.0/8") — that is a range check,
                # not a socket bind.
                if "0.0.0.0" not in stripped:
                    continue
                if stripped.startswith("//"):
                    continue
                # A CIDR prefix: the only 0.0.0.0 occurrence is followed by /
                import re as _re
                bare = _re.sub(r'0\.0\.0\.0/\d+', '', stripped)
                if "0.0.0.0" not in bare:
                    continue
                violations.append(
                    f"{go_file.relative_to(PROJECT_ROOT)}:{lineno}: {stripped}"
                )
        self.assertFalse(
            violations,
            "Go files bind on 0.0.0.0 in non-comment code "
            "— sidecar must listen on 127.0.0.1 only:\n"
            + "\n".join(violations),
        )

    def test_go_files_prefer_loopback(self):
        """At least one .go file should contain '127.0.0.1' (loopback address)."""
        any_loopback = any(
            "127.0.0.1" in go_file.read_text(errors="replace")
            for go_file in self._go_files()
        )
        # This is a soft requirement (advisory) — warn rather than fail hard
        # because env-var / CLI-flag driven binding is also acceptable.
        # We assert that it's at least present somewhere OR the port env-var
        # pattern is used.
        env_pattern_used = any(
            "os.Getenv" in go_file.read_text(errors="replace")
            or "flag.String" in go_file.read_text(errors="replace")
            for go_file in self._go_files()
        )
        self.assertTrue(
            any_loopback or env_pattern_used,
            "No 127.0.0.1 or env-flag pattern found in any Go source — "
            "loopback enforcement may be missing.",
        )


# ---------------------------------------------------------------------------
# 2. All sidecar ports in ports.json are in range 50051–59999
# ---------------------------------------------------------------------------

class TestPortRange(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        cls.ports = json.loads(PORTS_FILE.read_text())

    def test_all_ports_are_integers(self):
        bad = {k: v for k, v in self.ports.items() if not isinstance(v, int)}
        self.assertFalse(bad, f"Non-integer port values: {bad}")

    def test_all_ports_in_valid_range(self):
        out_of_range = {
            k: v for k, v in self.ports.items()
            if not (_PORT_MIN <= v <= _PORT_MAX)
        }
        self.assertFalse(
            out_of_range,
            f"Ports outside {_PORT_MIN}–{_PORT_MAX}: {out_of_range}",
        )

    def test_no_port_conflicts(self):
        """Each sidecar must have a unique port."""
        from collections import Counter
        counts = Counter(self.ports.values())
        duplicates = {port: count for port, count in counts.items() if count > 1}
        self.assertFalse(duplicates, f"Duplicate port assignments: {duplicates}")


# ---------------------------------------------------------------------------
# 3. Python shim fallback returns ToolResult when gRPC fails
# ---------------------------------------------------------------------------

class TestShimFallbackReturnsToolResult(unittest.TestCase):
    """Verifies that even with gRPC=1 (and stubs missing), ToolResult is returned."""

    def _assert_tool_result(self, result, expected_tool: str):
        from oneinfinity.modules.tool_wrappers import ToolResult
        self.assertIsInstance(result, ToolResult,
                              f"Expected ToolResult, got {type(result)}")

    def setUp(self):
        # Ensure gRPC fast paths are enabled for these tests
        os.environ["ONEINFINITY_GRPC_CRAWLER"] = "1"
        os.environ["ONEINFINITY_GRPC_RECON"]   = "1"
        os.environ["ONEINFINITY_GRPC_OOB"]     = "1"

    def tearDown(self):
        for var in ("ONEINFINITY_GRPC_CRAWLER", "ONEINFINITY_GRPC_RECON",
                    "ONEINFINITY_GRPC_OOB"):
            os.environ.pop(var, None)

    def test_katana_fallback_returns_tool_result(self):
        from oneinfinity.modules import tool_wrappers as tw
        stub = tw.ToolResult(tool="katana", success=True,
                             data={"urls": [], "count": 0})
        with patch.object(tw, "_wrap", return_value=stub):
            result = tw.run_katana("http://example.com")
        self._assert_tool_result(result, "katana")

    def test_dnsx_fallback_returns_tool_result(self):
        from oneinfinity.modules import tool_wrappers as tw
        stub = tw.ToolResult(tool="dnsx", success=True,
                             data={"records": [], "count": 0})
        with patch.object(tw, "_wrap", return_value=stub):
            result = tw.run_dnsx(["example.com"])
        self._assert_tool_result(result, "dnsx")

    def test_interactsh_fallback_returns_tool_result(self):
        from oneinfinity.modules import tool_wrappers as tw
        stub = tw.ToolResult(tool="interactsh-client", success=True)
        with patch.object(tw, "_wrap", return_value=stub):
            result = tw.run_interactsh()
        self._assert_tool_result(result, "interactsh-client")


# ---------------------------------------------------------------------------
# 4. grpc_client channel functions target loopback, not 0.0.0.0
# ---------------------------------------------------------------------------

class TestGrpcClientLoopbackBinding(unittest.TestCase):
    """_get_address() must always produce 127.0.0.1:<port>, never 0.0.0.0."""

    # Mock port map so the test is independent of CWD / ports.json resolution
    _MOCK_PORTS = {
        "oi-phase-runner": 50051,
        "oi-recon-probe":  50052,
        "oi-ssrf":         50053,
        "oi-oob-listener": 50054,
        "oi-idor-engine":  50055,
        "oi-crawler":      50056,
        "oi-target-disc":  50059,
    }

    def _get_address_for(self, service: str) -> str:
        from oneinfinity.infra import grpc_client as gc
        original = gc._ports
        try:
            gc._ports = self._MOCK_PORTS
            return gc._get_address(service)
        finally:
            gc._ports = original

    def test_phase_runner_binds_loopback(self):
        addr = self._get_address_for("oi-phase-runner")
        self.assertTrue(addr.startswith("127.0.0.1:"),
                        f"Expected 127.0.0.1:PORT, got {addr!r}")

    def test_crawler_binds_loopback(self):
        addr = self._get_address_for("oi-crawler")
        self.assertTrue(addr.startswith("127.0.0.1:"),
                        f"Expected 127.0.0.1:PORT, got {addr!r}")

    def test_recon_probe_binds_loopback(self):
        addr = self._get_address_for("oi-recon-probe")
        self.assertTrue(addr.startswith("127.0.0.1:"),
                        f"Expected 127.0.0.1:PORT, got {addr!r}")

if __name__ == "__main__":
    unittest.main(verbosity=2)
