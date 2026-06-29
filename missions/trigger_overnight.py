import requests
import time
import sys

URL_BASE = "http://localhost:8001/api"
SERIAL = "36011FDH20018W"
PKG = "de.telekom.android.customercenter.prod"

print("Fetching auth token...")
try:
    auth_resp = requests.get(f"{URL_BASE}/auth-token")
    token = auth_resp.json().get("token")
    if not token:
        print("Failed to get token.")
        sys.exit(1)
    print(f"Token acquired: {token[:10]}...")

    headers = {"X-API-Key": token}
    ingest_url = f"{URL_BASE}/mobile/devices/{SERIAL}/packages/{PKG}/ingest"
    
    print(f"Triggering ingest: {ingest_url}")
    # 10 minute timeout for large APK pull
    response = requests.post(ingest_url, headers=headers, timeout=600)
    print(f"Response: {response.status_code}")
    print(response.json())
except Exception as e:
    print(f"Error: {e}")
