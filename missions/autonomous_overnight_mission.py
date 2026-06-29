import sys
import os
import requests
import subprocess
import time

SERIAL = "36011FDH20018W"
PKG = "de.telekom.android.customercenter.prod"
LOCAL_APK = f"/tmp/{PKG}.apk"
URL_BASE = "http://localhost:8001/api"

print(f"Step 1: Exfiltrating {PKG} from device...")
try:
    # Get path
    path_info = subprocess.check_output(["adb", "-s", SERIAL, "shell", f"pm path {PKG}"], text=True).strip()
    remote_path = path_info.splitlines()[0].replace("package:", "").strip()
    print(f"Remote path: {remote_path}")
    
    # Pull
    subprocess.check_call(["adb", "-s", SERIAL, "pull", remote_path, LOCAL_APK])
    print(f"Pulled successfully. Size: {os.path.getsize(LOCAL_APK)} bytes")

    print("Step 2: Uploading and Ingesting into OneInfinity...")
    auth_resp = requests.get(f"{URL_BASE}/auth-token")
    token = auth_resp.json().get("token")
    headers = {"X-API-Key": token}

    with open(LOCAL_APK, 'rb') as f:
        files = {'file': (f'{PKG}.apk', f, 'application/vnd.android.package-archive')}
        # Longer timeout for upload
        resp = requests.post(f"{URL_BASE}/mobile/upload", headers=headers, files=files, timeout=600)
        
    print(f"Response: {resp.status_code}")
    print(resp.json())
    
    app_id = resp.json().get("app_id")
    if app_id:
        print(f"Step 3: Triggering Deep Forensic Audit for {app_id}...")
        analyze_params = {
            "run_dynamic": True,
            "device_id": SERIAL,
            "run_ai": True,
            "run_frida_gen": True,
            "run_attack": True
        }
        resp = requests.post(f"{URL_BASE}/mobile/apps/{app_id}/analyze", headers=headers, params=analyze_params)
        print(f"Analysis started: {resp.json()}")

except Exception as e:
    print(f"Critical Failure: {e}")
