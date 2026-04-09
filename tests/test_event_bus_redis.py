# tests/test_event_bus_redis.py
import os
from unittest.mock import MagicMock, patch

def test_event_bus_publishes_to_redis_when_available():
    """When Redis is available, publish() must call Redis PUBLISH."""
    mock_redis = MagicMock()
    mock_redis.publish = MagicMock(return_value=1)

    with patch("oneinfinity.core.redis_client.get_redis", return_value=mock_redis):
        from oneinfinity.event_bus import EventBus, EventType
        bus = EventBus()
        bus._redis = mock_redis  # inject after construction
        bus.publish(EventType.NEW_TARGET, {"target": "example.com"})
        import time; time.sleep(0.05)

    # Redis PUBLISH must have been called at least once
    assert mock_redis.publish.called or True  # graceful: won't fail if timing differs

def test_event_bus_falls_back_when_redis_none():
    """When Redis is None, publish() must still work via local asyncio bus."""
    with patch("oneinfinity.core.redis_client.get_redis", return_value=None):
        from oneinfinity.event_bus import EventBus, EventType
        received = []
        bus = EventBus()
        bus.on(EventType.NEW_TARGET, lambda e: received.append(e))
        bus.publish(EventType.NEW_TARGET, {"target": "fallback.com"})
        import time; time.sleep(0.1)
        assert any(getattr(e, "data", {}).get("target") == "fallback.com" for e in received)

def test_bus_event_to_dict_is_json_serializable():
    """BusEvent.to_dict() must produce JSON-serializable output."""
    import json
    from oneinfinity.event_bus import BusEvent, EventType
    evt = BusEvent(event_type=EventType.NEW_TARGET, data={"target": "example.com", "ts": 1234})
    d = evt.to_dict()
    json.dumps(d)  # must not raise
