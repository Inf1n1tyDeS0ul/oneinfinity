import threading
import sys
sys.path.insert(0, "/home/devendra-yadav/oneinfinity")

from web.backend.graph_api import _get_or_create_graph, _graph_instances


def test_concurrent_same_target_returns_same_instance():
    """Concurrent _get_or_create_graph for the same target must return the same instance.

    Without a lock, two threads can both see the target is missing,
    both create a new instance, and one silently discards the other.
    """
    test_target = "race-condition-test.com"
    # Clean up before test
    _graph_instances.pop(test_target, None)

    results = []
    errors = []

    def get_instance():
        try:
            g = _get_or_create_graph(test_target)
            results.append(id(g) if g is not None else None)
        except Exception as exc:
            errors.append(str(exc))

    threads = [threading.Thread(target=get_instance) for _ in range(20)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()

    assert not errors, f"Concurrent access raised errors: {errors}"

    # All non-None results must be the same object (same id)
    non_none = [r for r in results if r is not None]
    if non_none:
        unique_ids = set(non_none)
        assert len(unique_ids) == 1, (
            f"Race condition: {len(unique_ids)} different graph instances created "
            f"for the same target by concurrent threads. Expected 1."
        )

    # Cleanup
    _graph_instances.pop(test_target, None)


def test_different_targets_get_different_instances():
    """Different targets must get independent graph instances."""
    t1, t2 = "target-a.com", "target-b.com"
    _graph_instances.pop(t1, None)
    _graph_instances.pop(t2, None)

    g1 = _get_or_create_graph(t1)
    g2 = _get_or_create_graph(t2)

    if g1 is not None and g2 is not None:
        assert id(g1) != id(g2), "Different targets should get different instances"

    _graph_instances.pop(t1, None)
    _graph_instances.pop(t2, None)
