
import requests
import json
from pathlib import Path

TARGET = "https://app.test.12build.com"
LOGIN_URL = "https://app.test.12build.com/nl_NL/ajax/login"

CRED_A = ("intigriti-pentest+62a@12build.com", "518FE8195E85E84F")
CRED_B = ("intigriti-pentest+62b@12build.com", "031F785A22EFE0FF")

def login(email, password):
    payload = {
        "request": {
            "action": "login",
            "data": {
                "login": email,
                "password": password,
                "keep_login": False,
                "loginSuccesRedirect": ""
            }
        }
    }
    headers = {
        "Content-Type": "application/json",
        "X-Requested-With": "XMLHttpRequest"
    }
    
    sess = requests.Session()
    # First get the page to set some initial cookies (like device if needed)
    sess.get(TARGET)
    
    resp = sess.post(LOGIN_URL, json=payload, headers=headers)
    if resp.status_code == 200:
        data = resp.json()
        # The response doesn't necessarily mean success, check if it has errors or redirect
        print(f"Login response for {email}: {data}")
        return sess
    else:
        print(f"Login failed for {email} with status {resp.status_code}")
        return None

def setup_auth():
    print(f"[*] Logging in User A...")
    sess_a = login(CRED_A[0], CRED_A[1])
    if sess_a:
        cookies_a = sess_a.cookies.get_dict()
        print(f"[+] User A cookies: {cookies_a}")
    else:
        return

    print(f"[*] Logging in User B...")
    sess_b = login(CRED_B[0], CRED_B[1])
    if sess_b:
        cookies_b = sess_b.cookies.get_dict()
        print(f"[+] User B cookies: {cookies_b}")
    else:
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
    output_path.parent.mkdir(parents=True, exist_ok=True)
    with open(output_path, "w") as f:
        json.dump(auth_data, f, indent=2)
    
    print(f"[+] Auth sessions saved to {output_path}")

if __name__ == "__main__":
    setup_auth()
