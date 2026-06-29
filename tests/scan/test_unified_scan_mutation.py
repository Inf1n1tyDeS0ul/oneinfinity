import unittest
from unittest.mock import MagicMock, patch
from oneinfinity.scan.unified_scan_engine import UnifiedScanEngine

class TestUnifiedScanMutation(unittest.TestCase):
    def setUp(self):
        self.engine = UnifiedScanEngine()
        self.mock_registry = MagicMock()

    @patch("oneinfinity.core.scope_validator.ScopeValidator")
    @patch("oneinfinity.core.http_payload_mutator.get_http_mutator")
    @patch("oneinfinity.scan.adaptive_mutation_helper.get_mutation_engine")
    @patch("oneinfinity.core.safety.safety_guard")
    def test_run_tool_safe_uses_payload_mutation_engine_on_waf(self, mock_safety, mock_get_mutation_engine, mock_get_mutator, MockScopeValidator):
        # Setup mocks
        mock_scope = MockScopeValidator.return_value
        mock_scope.check.return_value = True
        mock_scope.filter_in_scope.side_effect = lambda x: x
        
        mock_mutation_engine = mock_get_mutation_engine.return_value
        mock_mutation_engine.mutate_payload.return_value = ["mutated_payload"]
        
        mock_mutator = mock_get_mutator.return_value
        mock_mutator.mutate_url.return_value = ["static_mutated_url"]
        
        # First call fails (WAF block), second call succeeds
        mock_result_fail = MagicMock()
        mock_result_fail.success = False
        mock_result_fail.raw = "403 Forbidden - WAF Blocked"
        mock_result_fail.stderr = ""
        
        mock_result_success = MagicMock()
        mock_result_success.success = True
        mock_result_success.count = 1
        mock_result_success.data = {"findings": [{"title": "XSS Found"}]}
        
        self.mock_registry.run.side_effect = [mock_result_fail, mock_result_success]
        
        # Run _run_tool_safe
        target = "http://example.com"
        urls = ["http://example.com/search?q=test"]
        
        results = self.engine._run_tool_safe(
            self.mock_registry, 
            "dalfox", 
            target, 
            urls, 
            waf_retries=1
        )
        
        # Verify PayloadMutationEngine was called
        mock_mutation_engine.mutate_payload.assert_called()
        
        # Verify registry.run was called twice (original + mutation)
        self.assertEqual(self.mock_registry.run.call_count, 2)
        
        # Verify we got the success result
        self.assertEqual(len(results), 1)
        self.assertEqual(results[0]["title"], "XSS Found")

if __name__ == "__main__":
    unittest.main()
