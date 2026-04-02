
import json
import logging
import time
from unified_scan_engine import get_engine, ScanSession
from pathlib import Path

logging.basicConfig(level=logging.INFO)

TARGET = "https://app.test.12build.com"
AUTH_FILE = "/Users/devendrayadav/.gemini/tmp/oneinfinity/workspaces/12build/auth_sessions.json"

def run_scan():
    with open(AUTH_FILE, "r") as f:
        auth_data = json.load(f)
    
    cookies_a = auth_data["user_a"]["cookies"]
    
    engine = get_engine()
    
    # Manually create and start the scan to inject config
    from unified_scan_engine import _PHASES, PhaseResult, _persist_session
    import uuid
    import threading

    scan_id = str(uuid.uuid4())
    session = ScanSession(
        scan_id=scan_id,
        target=TARGET,
        start_time=time.time(),
        status="running",
        phases={name: PhaseResult(name=name) for name in _PHASES},
    )
    # INJECT CONFIG HERE
    session.scan_config = {
        "cookies": cookies_a,
        "max_threads": 5,
        "depth": "deep",
        "auto_exploit": True,
        "validate_findings": True
    }

    def on_progress(phase, pct, msg):
        print(f"  [{pct}%] {phase}: {msg}")

    stop_event = threading.Event()
    with engine._lock:
        engine._active[scan_id] = stop_event
        engine._sessions[scan_id] = session

    _persist_session(session)
    print(f"[*] Starting authenticated scan for User A ({auth_data['user_a']['email']})...")
    
    # Run synchronously for this script
    engine._execute_scan(session, stop_event, on_progress)
    
    print(f"[+] Scan complete. Session ID: {session.scan_id}")
    print(f"[+] Findings: {len(session.findings)}")
    
    output_path = Path("/Users/devendrayadav/.gemini/tmp/oneinfinity/workspaces/12build/scan_user_a.json")
    with open(output_path, "w") as f:
        # ScanSession is not directly serializable to JSON via json.dump if it has objects
        json.dump(session.to_dict(), f, indent=2)
    
    print(f"[+] Full results saved to {output_path}")

if __name__ == "__main__":
    run_scan()
