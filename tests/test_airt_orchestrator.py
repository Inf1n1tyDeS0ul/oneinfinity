# tests/test_airt_orchestrator.py
from oneinfinity.scan.ai_red_teamer.models import AttackGoal, AttackResult

def test_attack_goal_model():
    goal = AttackGoal(target_url="http://test", objective="leak_system_prompt")
    assert goal.objective == "leak_system_prompt"

def test_attack_result_model():
    res = AttackResult(success=True, extracted_data={"url": "http://internal"})
    assert res.success is True

from oneinfinity.scan.ai_red_teamer.orchestrator import AIRTOrchestrator
from unittest.mock import MagicMock
from oneinfinity.scan.ai_red_teamer.models import AttackGoal

def test_orchestrator_initialization():
    orchestrator = AIRTOrchestrator()
    assert orchestrator.state == "INITIALIZED"

def test_orchestrator_full_loop():
    mock_fuzzer = MagicMock()
    mock_fuzzer.mutate.return_value = "mutated_payload"
    
    mock_shadow = MagicMock()
    # First fails, second passes
    mock_shadow.evaluate_payload.side_effect = [
        MagicMock(blocked=True),
        MagicMock(blocked=False, response="OK")
    ]
    
    mock_chainer = MagicMock()
    mock_chainer.analyze_response.return_value = {"urls": ["http://leak"]}
    
    mock_handover = MagicMock()
    
    orchestrator = AIRTOrchestrator(
        fuzzer=mock_fuzzer,
        shadow_boxer=mock_shadow,
        chainer=mock_chainer,
        handover=mock_handover
    )
    
    # Mocking the actual target request
    orchestrator._hit_target = MagicMock(return_value="Leaked: http://leak")
    
    goal = AttackGoal(target_url="http://target", objective="leak_data")
    result = orchestrator.execute_attack(goal)
    
    assert result.success is True
    assert orchestrator.state == "SUCCESS"
    assert mock_fuzzer.mutate.call_count == 2
    mock_handover.process_leaks.assert_called_once_with({"urls": ["http://leak"]})
