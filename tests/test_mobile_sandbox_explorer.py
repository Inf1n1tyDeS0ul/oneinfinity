import pytest
pytest.importorskip("adbutils")
import unittest
from unittest.mock import MagicMock
from oneinfinity.mobile.adb_forensics import SandboxExplorer

class TestSandboxExplorer(unittest.TestCase):
    def setUp(self):
        self.mock_device = MagicMock()
        self.package_name = "com.example.app"
        self.explorer = SandboxExplorer(self.mock_device, self.package_name)

    def test_explore_rooted(self):
        # Mock 'which su' to return a path (rooted)
        # and 'ls -R' to return some data
        def shell_mock(cmd):
            if "which su" in cmd: return "/system/bin/su"
            if "ls -R" in cmd: return "file1\nfile2"
            return ""
        self.mock_device.shell.side_effect = shell_mock
    
        findings = self.explorer.explore()
    
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0]["method"], "root_ls")
        self.assertIn("file1", findings[0]["data"])

    def test_explore_non_rooted(self):
        # Mock 'which su' to return empty (not rooted)
        self.mock_device.shell.return_value = ""
    
        findings = self.explorer.explore()
    
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0]["method"], "adb_backup")
        self.assertEqual(findings[0]["status"], "pending_confirmation")
