# tests/test_airt_handover.py
from unittest.mock import MagicMock
from oneinfinity.scan.ai_red_teamer.handover import HandoverProtocol
from oneinfinity.core.scope_validator import ScopeValidator

def test_handover_triggers_scan():
    mock_engine = MagicMock()
    # Mock scope validator to allow everything
    mock_scope = MagicMock(spec=ScopeValidator)
    mock_scope.check.return_value = True
    
    protocol = HandoverProtocol(scan_engine=mock_engine, scope_validator=mock_scope)
    
    leaks = {"urls": ["http://internal.db"]}
    protocol.process_leaks(leaks)
    
    mock_engine.scan.assert_called_once_with("http://internal.db")

def test_handover_blocks_out_of_scope():
    mock_engine = MagicMock()
    # Mock scope validator to block everything
    mock_scope = MagicMock(spec=ScopeValidator)
    mock_scope.check.return_value = False
    
    protocol = HandoverProtocol(scan_engine=mock_engine, scope_validator=mock_scope)
    
    leaks = {"urls": ["http://evil.com"], "ips": ["1.1.1.1"]}
    protocol.process_leaks(leaks)
    
    mock_engine.scan.assert_not_called()
