import unittest
from unittest.mock import MagicMock, patch
from oneinfinity.orchestration.god_mode_engine import ChainsMission, GodModeSession
import time

class TestChainsMissionUnification(unittest.TestCase):
    def setUp(self):
        self.session = GodModeSession(
            scan_id="test-scan",
            target="https://example.com",
            start_time=time.time()
        )
        self.mission = ChainsMission()

    @patch("oneinfinity.attack.exploit_chain_engine.ExploitChainEngine")
    @patch("oneinfinity.scan.traffic_correlation_engine.TrafficCorrelationEngine")
    @patch("oneinfinity.findings.result_ingestion_engine.get_ingestion_engine")
    def test_run_calls_both_engines(self, mock_get_ingestion, mock_traffic_engine_class, mock_static_engine_class):
        # Setup mocks
        mock_ingestion = MagicMock()
        mock_get_ingestion.return_value = mock_ingestion
        mock_ingestion.get_findings.return_value = [{"id": "f1", "vuln_type": "xss"}]

        mock_static_engine = mock_static_engine_class.return_value
        mock_static_engine.detect_chains.return_value = [MagicMock()] # 1 static chain

        mock_traffic_engine = mock_traffic_engine_class.return_value
        # TrafficCorrelationEngine.correlate_all returns a dict of lists
        mock_traffic_engine.correlate_all.return_value = {
            "same_endpoint": [MagicMock()],
            "param_overlap": [],
            "session_flow": [MagicMock()]
        } # 2 traffic chains total

        # Run mission
        self.mission._run(self.session)

        # Verify static engine called
        mock_static_engine.detect_chains.assert_called_once()
        
        # Verify traffic engine called
        mock_traffic_engine.correlate_all.assert_called_once()

        # Verify results merged in self._result
        res = self.mission.result()
        self.assertEqual(res["static_chains"], 1)
        self.assertEqual(res["traffic_chains"], 2) # same_endpoint(1) + session_flow(1)
        self.assertEqual(res["total_chains"], 3)
        self.assertIn("chains", self.session.phases_complete)


if __name__ == "__main__":
    unittest.main()
