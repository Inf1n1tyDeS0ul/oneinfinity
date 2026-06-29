# tests/test_airt_shadow_box.py
from unittest.mock import patch, MagicMock
from oneinfinity.scan.ai_red_teamer.shadow_box import ShadowBoxer

@patch('oneinfinity.scan.ai_red_teamer.shadow_box.safe_request')
def test_shadow_box_evaluation(mock_safe_request):
    # Mocking a successful response from safe_request
    mock_response = MagicMock()
    mock_response.json.return_value = {"response": "I cannot fulfill this request."}
    mock_response.status_code = 200
    mock_safe_request.return_value = mock_response
    
    boxer = ShadowBoxer(ollama_url="http://localhost:11434", model="llama3")
    result = boxer.evaluate_payload("bad payload")
    
    assert result.blocked is True
    assert "cannot fulfill" in result.response
    mock_safe_request.assert_called_once()
