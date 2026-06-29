"""
Phase 2 — Python gRPC shim tests.

Tests that:
  - All 8 shim functions are importable and callable
  - ONEINFINITY_GRPC_CRAWLER=0 takes the subprocess path
  - ONEINFINITY_GRPC_CRAWLER=1 attempts gRPC then falls back gracefully
  - ONEINFINITY_GRPC_RECON=0  works for run_subfinder, run_amass, run_dnsx
  - ONEINFINITY_GRPC_OOB=0    works for run_interactsh
  - Audit log line "[GRPC:<sidecar>] fast path active" is emitted on GRPC=1
"""
from __future__ import annotations

import logging
import os
import sys
import types
import unittest
from unittest.mock import MagicMock, patch

# ---------------------------------------------------------------------------
# Helpers to fake subprocess._wrap so tool binaries don't need to be installed
# ---------------------------------------------------------------------------

def _make_tool_result(tool: str, success: bool = True, data=None):
    """Import ToolResult dynamically after sys.path is set up."""
    from oneinfinity.modules.tool_wrappers import ToolResult
    return ToolResult(tool=tool, success=success, data=data or {})


def _patch_wrap(tool: str, data=None):
    """Return a context-manager that stubs _wrap() in tool_wrappers."""
    from oneinfinity.modules import tool_wrappers as tw
    result = _make_tool_result(tool, success=True, data=data or {})
    return patch.object(tw, "_wrap", return_value=result)


# ---------------------------------------------------------------------------
# 1. Importability checks
# ---------------------------------------------------------------------------

class TestShimImports(unittest.TestCase):

    def test_tool_wrappers_importable(self):
        import oneinfinity.modules.tool_wrappers  # noqa: F401

    def test_run_katana_importable(self):
        from oneinfinity.modules.tool_wrappers import run_katana
        self.assertTrue(callable(run_katana))

    def test_run_hakrawler_importable(self):
        from oneinfinity.modules.tool_wrappers import run_hakrawler
        self.assertTrue(callable(run_hakrawler))

    def test_run_subfinder_importable(self):
        from oneinfinity.modules.tool_wrappers import run_subfinder
        self.assertTrue(callable(run_subfinder))

    def test_run_amass_importable(self):
        from oneinfinity.modules.tool_wrappers import run_amass
        self.assertTrue(callable(run_amass))

    def test_run_dnsx_importable(self):
        from oneinfinity.modules.tool_wrappers import run_dnsx
        self.assertTrue(callable(run_dnsx))

    def test_run_interactsh_importable(self):
        from oneinfinity.modules.tool_wrappers import run_interactsh
        self.assertTrue(callable(run_interactsh))

    def test_normalize_finding_importable(self):
        from oneinfinity.modules.tool_wrappers import normalize_finding
        self.assertTrue(callable(normalize_finding))

    def test_tool_registry_importable(self):
        from oneinfinity.modules.tool_wrappers import TOOL_REGISTRY
        self.assertIsInstance(TOOL_REGISTRY, dict)
        self.assertGreater(len(TOOL_REGISTRY), 0)


# ---------------------------------------------------------------------------
# 2. GRPC_CRAWLER=0 — subprocess path for run_katana
# ---------------------------------------------------------------------------

class TestKatanaSubprocessPath(unittest.TestCase):
    """When ONEINFINITY_GRPC_CRAWLER is 0 (or absent), _wrap() must be called."""

    def setUp(self):
        os.environ.pop("ONEINFINITY_GRPC_CRAWLER", None)

    def test_katana_grpc0_calls_wrap(self):
        from oneinfinity.modules import tool_wrappers as tw
        result_stub = _make_tool_result("katana", data={"urls": [], "count": 0})
        with patch.object(tw, "_wrap", return_value=result_stub) as mock_wrap:
            os.environ["ONEINFINITY_GRPC_CRAWLER"] = "0"
            result = tw.run_katana("http://example.com")
        mock_wrap.assert_called_once()
        self.assertEqual(result.tool, "katana")

    def test_katana_absent_flag_calls_wrap(self):
        from oneinfinity.modules import tool_wrappers as tw
        result_stub = _make_tool_result("katana", data={"urls": [], "count": 0})
        with patch.object(tw, "_wrap", return_value=result_stub) as mock_wrap:
            result = tw.run_katana("http://example.com")
        mock_wrap.assert_called_once()
        self.assertIsNotNone(result)


# ---------------------------------------------------------------------------
# 3. GRPC_CRAWLER=1 — attempts gRPC, falls back to subprocess gracefully
# ---------------------------------------------------------------------------

class TestKatanaGrpcFallback(unittest.TestCase):
    """ONEINFINITY_GRPC_CRAWLER=1: fast path is attempted, exception triggers fallback."""

    def setUp(self):
        os.environ["ONEINFINITY_GRPC_CRAWLER"] = "1"

    def tearDown(self):
        os.environ.pop("ONEINFINITY_GRPC_CRAWLER", None)

    def test_katana_grpc1_falls_back_returns_tool_result(self):
        """Even with GRPC=1 (stubs not compiled), a ToolResult must be returned."""
        from oneinfinity.modules import tool_wrappers as tw
        from oneinfinity.modules.tool_wrappers import ToolResult
        result_stub = _make_tool_result("katana", data={"urls": [], "count": 0})
        with patch.object(tw, "_wrap", return_value=result_stub):
            result = tw.run_katana("http://example.com")
        self.assertIsInstance(result, ToolResult)

    def test_katana_grpc1_no_exception_raised(self):
        """Fallback must absorb the ImportError; caller sees a clean ToolResult."""
        from oneinfinity.modules import tool_wrappers as tw
        result_stub = _make_tool_result("katana", data={"urls": ["http://x.com"], "count": 1})
        with patch.object(tw, "_wrap", return_value=result_stub):
            try:
                result = tw.run_katana("http://example.com")
            except Exception as exc:
                self.fail(f"run_katana raised unexpectedly: {exc}")


# ---------------------------------------------------------------------------
# 4. GRPC_RECON=0 — subprocess paths for run_subfinder, run_amass, run_dnsx
# ---------------------------------------------------------------------------

class TestReconSubprocessPath(unittest.TestCase):

    def setUp(self):
        os.environ["ONEINFINITY_GRPC_RECON"] = "0"

    def tearDown(self):
        os.environ.pop("ONEINFINITY_GRPC_RECON", None)

    def test_subfinder_grpc0_calls_wrap(self):
        from oneinfinity.modules import tool_wrappers as tw
        result_stub = _make_tool_result("subfinder", data={"subdomains": [], "count": 0})
        with patch.object(tw, "_wrap", return_value=result_stub) as mock_wrap:
            tw.run_subfinder("example.com")
        mock_wrap.assert_called_once()

    def test_amass_grpc0_calls_wrap(self):
        from oneinfinity.modules import tool_wrappers as tw
        result_stub = _make_tool_result("amass", data={"subdomains": [], "count": 0})
        with patch.object(tw, "_wrap", return_value=result_stub) as mock_wrap:
            tw.run_amass("example.com")
        mock_wrap.assert_called_once()

    def test_dnsx_grpc0_calls_wrap(self):
        from oneinfinity.modules import tool_wrappers as tw
        result_stub = _make_tool_result("dnsx", data={"records": [], "count": 0})
        with patch.object(tw, "_wrap", return_value=result_stub) as mock_wrap:
            tw.run_dnsx(["example.com"])
        mock_wrap.assert_called_once()


# ---------------------------------------------------------------------------
# 5. GRPC_OOB=0 — subprocess path for run_interactsh
# ---------------------------------------------------------------------------

class TestOobSubprocessPath(unittest.TestCase):

    def setUp(self):
        os.environ["ONEINFINITY_GRPC_OOB"] = "0"

    def tearDown(self):
        os.environ.pop("ONEINFINITY_GRPC_OOB", None)

    def test_interactsh_grpc0_calls_wrap(self):
        from oneinfinity.modules import tool_wrappers as tw
        result_stub = _make_tool_result("interactsh-client")
        with patch.object(tw, "_wrap", return_value=result_stub) as mock_wrap:
            result = tw.run_interactsh()
        mock_wrap.assert_called_once()
        self.assertIsNotNone(result)


# ---------------------------------------------------------------------------
# 6. Audit log "[GRPC:<sidecar>] fast path active" emitted when GRPC=1
# ---------------------------------------------------------------------------

class TestGrpcAuditLog(unittest.TestCase):
    """Verify the INFO-level audit log is emitted before the fallback occurs."""

    def _capture_logs(self, logger_name: str, level=logging.DEBUG):
        """Return a list that accumulates log messages during the test."""
        messages: list[str] = []

        class _Handler(logging.Handler):
            def emit(self, record):
                messages.append(self.format(record))

        handler = _Handler()
        handler.setLevel(level)
        log = logging.getLogger(logger_name)
        log.addHandler(handler)
        original_level = log.level
        log.setLevel(level)
        return messages, log, handler, original_level

    def tearDown(self):
        os.environ.pop("ONEINFINITY_GRPC_CRAWLER", None)
        os.environ.pop("ONEINFINITY_GRPC_OOB", None)
        os.environ.pop("ONEINFINITY_GRPC_RECON", None)

    def test_crawler_fast_path_log_emitted(self):
        """run_katana with GRPC=1 must log '[GRPC:crawler] fast path active'."""
        from oneinfinity.modules import tool_wrappers as tw
        messages, log_obj, handler, orig_level = self._capture_logs(
            "oneinfinity.modules.tool_wrappers", logging.DEBUG
        )
        result_stub = _make_tool_result("katana", data={"urls": [], "count": 0})
        try:
            os.environ["ONEINFINITY_GRPC_CRAWLER"] = "1"
            with patch.object(tw, "_wrap", return_value=result_stub):
                tw.run_katana("http://example.com")
        finally:
            log_obj.removeHandler(handler)
            log_obj.setLevel(orig_level)
        combined = "\n".join(messages)
        self.assertIn("GRPC:crawler", combined,
                      f"Expected '[GRPC:crawler]' in log output. Got:\n{combined}")

    def test_oob_fast_path_log_emitted(self):
        """run_interactsh with GRPC=1 must log '[GRPC:oob] fast path active'."""
        from oneinfinity.modules import tool_wrappers as tw
        messages, log_obj, handler, orig_level = self._capture_logs(
            "oneinfinity.modules.tool_wrappers", logging.DEBUG
        )
        result_stub = _make_tool_result("interactsh-client")
        try:
            os.environ["ONEINFINITY_GRPC_OOB"] = "1"
            with patch.object(tw, "_wrap", return_value=result_stub):
                tw.run_interactsh()
        finally:
            log_obj.removeHandler(handler)
            log_obj.setLevel(orig_level)
        combined = "\n".join(messages)
        self.assertIn("GRPC:oob", combined,
                      f"Expected '[GRPC:oob]' in log output. Got:\n{combined}")

    def test_recon_fast_path_log_emitted(self):
        """run_dnsx with GRPC=1 must log '[GRPC:recon] fast path active'."""
        from oneinfinity.modules import tool_wrappers as tw
        messages, log_obj, handler, orig_level = self._capture_logs(
            "oneinfinity.modules.tool_wrappers", logging.DEBUG
        )
        result_stub = _make_tool_result("dnsx", data={"records": [], "count": 0})
        try:
            os.environ["ONEINFINITY_GRPC_RECON"] = "1"
            with patch.object(tw, "_wrap", return_value=result_stub):
                tw.run_dnsx(["example.com"])
        finally:
            log_obj.removeHandler(handler)
            log_obj.setLevel(orig_level)
        combined = "\n".join(messages)
        self.assertIn("GRPC:recon", combined,
                      f"Expected '[GRPC:recon]' in log output. Got:\n{combined}")


if __name__ == "__main__":
    unittest.main(verbosity=2)
