
import json
import logging
from auth_session_manager import AuthSessionManager
from pathlib import Path

logging.basicConfig(level=logging.INFO)

TARGET = "https://app.test.12build.com"
LOGIN_URL = "https://app.test.12build.com/login"

CRED_A = ("intigriti-pentest+62a@12build.com", "518FE8195E85E84F")
CRED_B = ("intigriti-pentest+62b@12build.com", "031F785A22EFE0FF")

def setup_auth():
    mgr = AuthSessionManager(target=TARGET)
    
    print(f"[*] Attempting login for User A: {CRED_A[0]}")
    sess_a = mgr.attempt_login(LOGIN_URL, CRED_A[0], CRED_A[1])
    if sess_a:
        print("[+] Login successful for User A")
        cookies_a = sess_a.cookies.get_dict()
    else:
        print("[-] Login failed for User A")
        return

    print(f"[*] Attempting login for User B: {CRED_B[0]}")
    sess_b = mgr.attempt_login(LOGIN_URL, CRED_B[0], CRED_B[1])
    if sess_b:
        print("[+] Login successful for User B")
        cookies_b = sess_b.cookies.get_dict()
    else:
        print("[-] Login failed for User B")
        return

    auth_data = {
        "user_a": {
            "email": CRED_A[0],
            "cookies": cookies_a
        },
        "user_b": {
            "email": CRED_B[0],
            "cookies": cookies_b
        }
    }

    output_path = Path("/Users/devendrayadav/.gemini/tmp/oneinfinity/workspaces/12build/auth_sessions.json")
    with open(output_path, "w") as f:
        json.dump(auth_data, f, indent=2)
    
    print(f"[+] Auth sessions saved to {output_path}")

if __name__ == "__main__":
    setup_auth()
