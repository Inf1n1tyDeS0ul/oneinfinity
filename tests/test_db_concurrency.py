import threading, os
os.environ["ONEINFINITY_API_KEY"] = ""

from fastapi.testclient import TestClient
from web.backend.main import app, _scan_db

client = TestClient(app)

def test_concurrent_db_writes_do_not_raise_locked():
    """Concurrent writes to ScanDB must not raise 'database is locked'."""
    errors = []

    def write_scan(i):
        try:
            _scan_db.upsert({
                "id": f"concurrent-test-{i}",
                "target": f"target-{i}.com",
                "status": "completed",
                "findings": [],
                "created_at": "2026-01-01T00:00:00",
            })
        except Exception as exc:
            errors.append(str(exc))

    threads = [threading.Thread(target=write_scan, args=(i,)) for i in range(50)]
    for t in threads: t.start()
    for t in threads: t.join()

    locked_errors = [e for e in errors if "locked" in e.lower()]
    assert not locked_errors, f"Database locking errors: {locked_errors}"

    # Cleanup
    for i in range(50):
        try: _scan_db.delete(f"concurrent-test-{i}")
        except: pass
