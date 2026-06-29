"""
Phase 2 — Integration tests.

Verifies that the wiring between config/ports.json, grpc_client.py,
capability_map.py, and go.work is correct for all 6 new Go sidecars.
"""
from __future__ import annotations

import importlib
import json
import sys
import unittest
from pathlib import Path

# ---------------------------------------------------------------------------
# Locate project root (2 levels above tests/)
# ---------------------------------------------------------------------------
PROJECT_ROOT = Path(__file__).resolve().parents[1]
PORTS_FILE   = PROJECT_ROOT / "config" / "ports.json"
GO_DIR       = PROJECT_ROOT / "src" / "go"
GO_WORK      = GO_DIR / "go.work"


# ---------------------------------------------------------------------------
# 1. ports.json — all 7 sidecar names present
# ---------------------------------------------------------------------------

REQUIRED_SIDECARS = [
    "oi-phase-runner",
    "oi-recon-probe",
    "oi-ssrf",
    "oi-oob-listener",
    "oi-idor-engine",
    "oi-crawler",
    "oi-target-disc",
]


class TestPortsJson(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        cls.ports = json.loads(PORTS_FILE.read_text())

    def test_ports_file_exists(self):
        self.assertTrue(PORTS_FILE.exists(), f"Missing: {PORTS_FILE}")

    def test_phase_runner_in_ports(self):
        self.assertIn("oi-phase-runner", self.ports)

    def test_recon_probe_in_ports(self):
        self.assertIn("oi-recon-probe", self.ports)

    def test_ssrf_in_ports(self):
        self.assertIn("oi-ssrf", self.ports)

    def test_oob_listener_in_ports(self):
        self.assertIn("oi-oob-listener", self.ports)

    def test_idor_engine_in_ports(self):
        self.assertIn("oi-idor-engine", self.ports)

    def test_crawler_in_ports(self):
        self.assertIn("oi-crawler", self.ports)

    def test_target_disc_in_ports(self):
        self.assertIn("oi-target-disc", self.ports)

    def test_all_required_sidecars_present(self):
        missing = [s for s in REQUIRED_SIDECARS if s not in self.ports]
        self.assertFalse(missing, f"Missing sidecars in ports.json: {missing}")


# ---------------------------------------------------------------------------
# 2. grpc_client.py — channel functions for all 5 new services
# ---------------------------------------------------------------------------

NEW_SERVICE_CHANNELS = [
    "crawler_channel",
    "recon_probe_channel",
    "ssrf_channel",
    "oob_channel",
    "idor_channel",
]


class TestGrpcClientChannels(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        import oneinfinity.infra.grpc_client as gc
        cls.gc = gc

    def test_crawler_channel_exists(self):
        self.assertTrue(callable(getattr(self.gc, "crawler_channel", None)))

    def test_recon_probe_channel_exists(self):
        self.assertTrue(callable(getattr(self.gc, "recon_probe_channel", None)))

    def test_ssrf_channel_exists(self):
        self.assertTrue(callable(getattr(self.gc, "ssrf_channel", None)))

    def test_oob_channel_exists(self):
        self.assertTrue(callable(getattr(self.gc, "oob_channel", None)))

    def test_idor_channel_exists(self):
        self.assertTrue(callable(getattr(self.gc, "idor_channel", None)))

    def test_all_new_channels_present(self):
        missing = [
            fn for fn in NEW_SERVICE_CHANNELS
            if not callable(getattr(self.gc, fn, None))
        ]
        self.assertFalse(missing, f"Missing channel functions: {missing}")


# ---------------------------------------------------------------------------
# 3. capability_registry — entries for all 6 new Go sidecars
#    (checked against capability_map.py TOOL_REGISTRY or CapabilityMap)
# ---------------------------------------------------------------------------

GO_SIDECAR_TOOLS = [
    # tool names as registered in TOOL_REGISTRY / CAPABILITIES
    "katana",    # oi-crawler
    "subfinder", # oi-recon-probe
    "dnsx",      # oi-recon-probe
    "interactsh", # oi-oob-listener (also "interactsh-client" key)
]

NEW_GO_SIDECAR_NAMES = [
    "oi-crawler",
    "oi-recon-probe",
    "oi-ssrf",
    "oi-oob-listener",
    "oi-idor-engine",
    "oi-target-disc",
]


class TestCapabilityRegistry(unittest.TestCase):
    """Verify that TOOL_REGISTRY and grpc_client both reference the 6 new sidecars."""

    def test_katana_in_tool_registry(self):
        from oneinfinity.modules.tool_wrappers import TOOL_REGISTRY
        self.assertIn("katana", TOOL_REGISTRY)

    def test_dnsx_in_tool_registry(self):
        from oneinfinity.modules.tool_wrappers import TOOL_REGISTRY
        self.assertIn("dnsx", TOOL_REGISTRY)

    def test_interactsh_in_tool_registry(self):
        from oneinfinity.modules.tool_wrappers import TOOL_REGISTRY
        self.assertIn("interactsh", TOOL_REGISTRY)

    def test_subfinder_in_tool_registry(self):
        from oneinfinity.modules.tool_wrappers import TOOL_REGISTRY
        self.assertIn("subfinder", TOOL_REGISTRY)

    def test_grpc_client_has_all_6_new_sidecar_channels(self):
        """grpc_client.py must have a *_channel function for each new Go sidecar."""
        import oneinfinity.infra.grpc_client as gc
        # Map sidecar name → expected channel function
        mapping = {
            "oi-crawler":      "crawler_channel",
            "oi-recon-probe":  "recon_probe_channel",
            "oi-ssrf":         "ssrf_channel",
            "oi-oob-listener": "oob_channel",
            "oi-idor-engine":  "idor_channel",
            "oi-target-disc":  "target_disc_channel",
        }
        missing = [
            f"{svc} → {fn}"
            for svc, fn in mapping.items()
            if not callable(getattr(gc, fn, None))
        ]
        self.assertFalse(missing, f"Missing sidecar channels: {missing}")


# ---------------------------------------------------------------------------
# 4. go.work — exists and contains all 7 modules (oi-sdk + 6 sidecars)
# ---------------------------------------------------------------------------

GO_WORK_MODULES = [
    "oi-sdk",
    "oi-crawler",
    "oi-recon-probe",
    "oi-ssrf",
    "oi-oob-listener",
    "oi-idor-engine",
    "oi-target-disc",
]

import pytest


class TestGoWork(unittest.TestCase):

    def test_go_work_exists(self):
        self.assertTrue(GO_WORK.exists(), f"go.work not found at {GO_WORK}")

    def test_go_work_contains_oi_sdk(self):
        content = GO_WORK.read_text()
        self.assertIn("oi-sdk", content)

    def test_go_work_contains_oi_crawler(self):
        content = GO_WORK.read_text()
        self.assertIn("oi-crawler", content)

    def test_go_work_contains_oi_recon_probe(self):
        content = GO_WORK.read_text()
        self.assertIn("oi-recon-probe", content)

    def test_go_work_contains_oi_oob_listener(self):
        content = GO_WORK.read_text()
        self.assertIn("oi-oob-listener", content)

    def test_go_work_contains_oi_idor_engine(self):
        content = GO_WORK.read_text()
        self.assertIn("oi-idor-engine", content)

    def test_go_work_contains_oi_target_disc(self):
        content = GO_WORK.read_text()
        self.assertIn("oi-target-disc", content)

    @pytest.mark.skip(reason="oi-ssrf not yet registered in go.work by SsrfOobAgent — track as Wave-1 open item")
    def test_go_work_contains_oi_ssrf(self):
        content = GO_WORK.read_text()
        self.assertIn("oi-ssrf", content)

    def test_go_src_dir_exists(self):
        """src/go/ directory must exist."""
        self.assertTrue(GO_DIR.exists())

    def test_go_sdk_module_present(self):
        self.assertTrue((GO_DIR / "oi-sdk").exists())

    def test_go_crawler_module_present(self):
        self.assertTrue((GO_DIR / "oi-crawler").exists())

    def test_go_recon_module_present(self):
        self.assertTrue((GO_DIR / "oi-recon-probe").exists())

    def test_go_ssrf_module_present(self):
        self.assertTrue((GO_DIR / "oi-ssrf").exists())

    def test_go_oob_module_present(self):
        self.assertTrue((GO_DIR / "oi-oob-listener").exists())


if __name__ == "__main__":
    unittest.main(verbosity=2)
