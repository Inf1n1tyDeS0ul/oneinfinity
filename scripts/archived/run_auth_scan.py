
import json
import logging
from unified_scan_engine import get_engine
from auth_session_manager import AuthSessionManager
from pathlib import Path

logging.basicConfig(level=logging.INFO)

TARGET = "https://app.test.12build.com"
AUTH_FILE = "/Users/devendrayadav/.gemini/tmp/oneinfinity/workspaces/12build/auth_sessions.json"

def run_scan():
    with open(AUTH_FILE, "r") as f:
        auth_data = json.load(f)
    
    cookies_a = auth_data["user_a"]["cookies"]
    
    engine = get_engine()
    
    # We can pass scan_config to engine.scan
    scan_config = {
        "cookies": cookies_a,
        "max_threads": 5,
        "depth": "deep",
        "auto_exploit": True,
        "validate_findings": True
    }
    
    print(f"[*] Starting authenticated scan for User A ({auth_data['user_a']['email']})...")
    
    session = engine.scan(TARGET, scan_config=scan_config)
    
    print(f"[+] Scan complete. Session ID: {session.scan_id}")
    print(f"[+] Findings: {len(session.findings)}")
    
    output_path = Path("/Users/devendrayadav/.gemini/tmp/oneinfinity/workspaces/12build/scan_user_a.json")
    with open(output_path, "w") as f:
        json.dump(session.to_dict(), f, indent=2)
    
    print(f"[+] Full results saved to {output_path}")

if __name__ == "__main__":
    run_scan()
