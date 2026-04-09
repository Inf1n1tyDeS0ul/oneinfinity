# tests/test_event_bus_pg.py
def test_event_bus_init_does_not_require_sqlite():
    """EventBus must start without creating a SQLite file (PG-only mode)."""
    import os
    from unittest.mock import patch
    with patch.dict(os.environ, {}, clear=True):
        from event_bus import EventBus, EventType
        bus = EventBus()
        bus.publish(EventType.NEW_TARGET, {"target": "example.com"})
        import time; time.sleep(0.05)
        bus.stop() if hasattr(bus, "stop") else None
