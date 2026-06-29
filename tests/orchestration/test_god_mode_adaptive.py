import unittest
from unittest.mock import MagicMock, patch
import time
import threading
from oneinfinity.orchestration.god_mode_engine import GodModeConductor, GodModeSession, Mission

class TestGodModeAdaptive(unittest.TestCase):
    def setUp(self):
        self.conductor = GodModeConductor()
        self.session = GodModeSession(
            scan_id="test-scan",
            target="https://example.com",
            start_time=time.time()
        )
        self.conductor._session = self.session
        # Setup mock missions
        self.conductor._missions = [
            MagicMock(spec=Mission, name="full_scan"),
            MagicMock(spec=Mission, name="research"),
            MagicMock(spec=Mission, name="swarm"),
        ]
        for m in self.conductor._missions:
            m.status = "pending"
        
        self.conductor._missions[0].name = "full_scan"
        self.conductor._missions[1].name = "research"
        self.conductor._missions[2].name = "swarm"

    @patch("oneinfinity.findings.result_ingestion_engine.get_ingestion_engine")
    @patch("oneinfinity.scan.chain_suggestion_engine.ChainSuggestionEngine")
    def test_convergence_loop_injects_suggestions(self, mock_suggest_engine_class, mock_get_ingestion):
        # Setup mocks
        mock_ingestion = MagicMock()
        mock_get_ingestion.return_value = mock_ingestion
        mock_ingestion.get_findings.return_value = [{"vuln_type": "sqli"}]

        mock_suggest_engine = mock_suggest_engine_class.return_value
        
        from oneinfinity.scan.chain_suggestion_engine import ChainSuggestion
        suggestion = ChainSuggestion(
            chain_name="SQLi to RCE",
            chain_severity="critical",
            missing_vuln_types=["file_read"],
            present_vuln_types=["sqli"],
            completion_percentage=50.0,
            recommended_scanner="path_traversal_scanner",
            confidence=0.9,
            priority_score=8.5,
            exploitation_impact="RCE"
        )
        mock_suggest_engine.suggest_next_tests.return_value = [suggestion]

        # Mock convergence to exit after one loop
        self.conductor._convergence = MagicMock()
        self.conductor._convergence.is_converged.return_value = True

        # Mock _unlock_mission_by_scanner_name
        self.conductor._unlock_mission_by_scanner_name = MagicMock()

        # Run convergence loop (should exit after one tick due to is_converged=True)
        # We need to ensure it doesn't wait too long
        self.conductor._wakeup = MagicMock()
        
        self.conductor._convergence_loop()

        # Verify suggestion engine was called
        mock_suggest_engine.suggest_next_tests.assert_called_once()
        
        # Verify _unlock_mission_by_scanner_name was called with the recommended scanner
        self.conductor._unlock_mission_by_scanner_name.assert_called_once_with("path_traversal_scanner")

    def test_unlock_mission_by_scanner_name_mapping(self):
        # Mock _unlock_mission
        self.conductor._unlock_mission = MagicMock()

        # Test research mapping
        self.conductor._unlock_mission_by_scanner_name("sqli_scanner")
        self.conductor._unlock_mission.assert_called_with("research")

        # Test swarm mapping
        self.conductor._unlock_mission_by_scanner_name("multi_account_idor_engine")
        self.conductor._unlock_mission.assert_called_with("swarm")

        # Test default mapping
        self.conductor._unlock_mission_by_scanner_name("unknown_scanner")
        self.conductor._unlock_mission.assert_called_with("research")

if __name__ == "__main__":
    unittest.main()
