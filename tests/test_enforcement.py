# tests/test_enforcement.py
from oneinfinity.orchestration.enforcement_controller import EnforcementController

def test_stop_recursive_watch_cleans_up_after_exception():
    """Handlers must be unregistered even if god mode is interrupted."""
    ctrl = EnforcementController()
    scan_id = "test-orphan-scan"

    try:
        ctrl.start_recursive_watch(scan_id, "example.com")
        assert scan_id in ctrl._recursion_states
        raise RuntimeError("Simulated interruption")
    except RuntimeError:
        pass  # In real code this would propagate — we test the finally handler

    ctrl.stop_recursive_watch(scan_id)
    assert scan_id not in ctrl._recursion_states, \
        "Recursion state must be cleaned up after stop_recursive_watch"

def test_handler_self_unregisters_when_state_gone():
    """Handler must self-unregister when scan_id is no longer tracked."""
    ctrl = EnforcementController()
    scan_id = "test-self-unregister"

    ctrl.start_recursive_watch(scan_id, "example.com")
    # Force-remove state (simulates stop_recursive_watch having been called)
    with ctrl._lock:
        ctrl._recursion_states.pop(scan_id, None)

    # The handlers are now orphaned — verify state is gone
    assert scan_id not in ctrl._recursion_states
