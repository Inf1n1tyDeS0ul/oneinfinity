import json
import os
from pathlib import Path
from unittest.mock import MagicMock, patch
import pytest
from oneinfinity.pipeline.executor import CanonicalExecutor

def test_executor_init_with_target_loads_scope(tmp_path):
    # Setup mock data root and target path
    data_root = tmp_path / "data"
    data_root.mkdir()
    
    findings_dir = data_root / "raw" / "example.com" / "findings"
    findings_dir.mkdir(parents=True)
    
    scope_data = {"include": ["*.example.com"]}
    (findings_dir / "scope.json").write_text(json.dumps(scope_data))
    
    with patch("oneinfinity.infra.path_manager.data_root", return_value=data_root), \
         patch("oneinfinity.infra.path_manager.get_target_path", return_value=findings_dir):
        
        executor = CanonicalExecutor(target="example.com")
        assert executor.target == "example.com"
        assert executor.scope == scope_data

def test_waf_signal_propagation(tmp_path):
    # Test that WAF env vars are set in _run_phase_subprocess
    executor = CanonicalExecutor(
        target="example.com",
        waf_profile={"waf_detected": True, "waf_name": "cloudflare", "rate_limit_rps": 2}
    )
    
    phase = MagicMock()
    phase.name = "test_phase"
    phase.cli_command = "test-cmd"
    phase.cli_extra_args = []
    phase.output_file = "test.json"
    phase.timeout_s = 60
    
    with patch("subprocess.run") as mock_run, \
         patch("oneinfinity.pipeline.executor.CLI_SCRIPT", "run.py"), \
         patch("oneinfinity.pipeline.executor.ROOT", tmp_path), \
         patch("oneinfinity.pipeline.executor.CanonicalExecutor._read_output_file", return_value=[]):
        
        executor._run_phase_subprocess(phase, "example.com", str(tmp_path), MagicMock())
        
        args, kwargs = mock_run.call_args
        env = kwargs.get("env")
        assert env.get("OI_WAF_DETECTED") == "1"
        assert env.get("OI_WAF_TYPE") == "cloudflare"
        assert env.get("OI_WAF_RPS") == "2"
