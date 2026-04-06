"""Test that Redis listener thread reconnects after failure."""
import threading
import time
import pytest

def test_redis_listener_retries_on_disconnect(monkeypatch):
    """Listener must attempt reconnection after an exception, not exit permanently."""
    attempt_count = [0]
    stop_flag = [False]

    def fake_get_redis():
        attempt_count[0] += 1
        if attempt_count[0] < 3:
            raise ConnectionError("Redis gone")
        # Signal test to stop after successful 3rd attempt
        stop_flag[0] = True
        return None  # None stops the listener cleanly

    import sys
    sys.path.insert(0, "/home/devendra-yadav/oneinfinity")
    import event_bus as eb
    from event_bus import EventBus
    import queue
    bus = EventBus.__new__(EventBus)
    bus._running = True
    bus._inbox = queue.PriorityQueue()
    bus._published_ids = {}
    bus._published_ids_lock = threading.Lock()

    # Patch the get_redis import inside the method
    import unittest.mock as mock
    with mock.patch("core.redis_client.get_redis") as mocked:
        mocked.side_effect = fake_get_redis

        def stop_after_attempts():
            deadline = time.time() + 3.0
            while time.time() < deadline:
                if stop_flag[0]:
                    bus._running = False
                    break
                time.sleep(0.05)
            bus._running = False

        t = threading.Thread(target=bus._redis_listener_loop, daemon=True)
        stopper = threading.Thread(target=stop_after_attempts, daemon=True)
        t.start()
        stopper.start()
        t.join(timeout=4.0)

    assert attempt_count[0] >= 2, f"Expected at least 2 attempts, got {attempt_count[0]}"
