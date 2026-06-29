import unittest
from unittest.mock import MagicMock, patch
from oneinfinity.orchestration.god_mode_engine import ReportMission, GodModeSession
import time

class TestGodModeVerification(unittest.TestCase):
    def setUp(self):
        self.session = GodModeSession(
            scan_id="test-scan",
            target="https://example.com",
            start_time=time.time()
        )
        self.mission = ReportMission()

    @patch("oneinfinity.findings.result_ingestion_engine.get_ingestion_engine")
    @patch("oneinfinity.orchestration.enforcement_controller.get_enforcement_controller")
    @patch("oneinfinity.core.deduplicator.Deduplicator")
    @patch("oneinfinity.attack.autonomous_exploit_engine.AutonomousExploitEngine")
    def test_report_mission_verifies_critical_findings(self, mock_exploit_engine_class, mock_dedup_class, mock_enforcement_controller_func, mock_get_ingestion):
        # Setup findings
        critical_finding = {
            "id": "finding-1",
            "vuln_type": "sqli",
            "confidence": 0.9,
            "url": "https://example.com/vuln"
        }
        low_confidence_finding = {
            "id": "finding-2",
            "vuln_type": "xss",
            "confidence": 0.5,
            "url": "https://example.com/xss"
        }
        
        mock_ingestion = mock_get_ingestion.return_value
        mock_ingestion.get_findings.return_value = [critical_finding, low_confidence_finding]
        
        mock_enforcement = mock_enforcement_controller_func.return_value
        mock_enforcement.validate_findings.return_value = [critical_finding, low_confidence_finding]
        
        mock_dedup = mock_dedup_class.return_value
        mock_dedup.filter_new.return_value = [critical_finding, low_confidence_finding]
        
        mock_exploit_engine = mock_exploit_engine_class.return_value
        mock_exploit_engine.validate_finding.return_value = {
            "status": "confirmed",
            "confidence": 1.0,
            "validated": True,
            "evidence": "Exploited successfully"
        }

        # Run mission
        self.mission.run_sync(self.session)

        # Verify AutonomousExploitEngine was called only for critical finding
        mock_exploit_engine.validate_finding.assert_called_once_with(critical_finding)
        
        # Verify finding was updated
        self.assertEqual(critical_finding["confidence"], 1.0)
        self.assertTrue(critical_finding["poc_verified"])
        
        # Verify insight was recorded
        self.assertTrue(any(i["trigger"] == "Autonomous Verification" for i in self.session.insights))

if __name__ == "__main__":
    unittest.main()
