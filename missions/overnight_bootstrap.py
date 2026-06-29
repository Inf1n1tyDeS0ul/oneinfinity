import sys
import os
from pathlib import Path

# Setup path
sys.path.insert(0, str(Path(__file__).parent.parent / "src"))

from oneinfinity.mobile.upload_manager import mobile_upload_manager
from oneinfinity.mobile.security_engine import MobileSecurityEngine, MobileSecurityConfig, MobileSecurityReport

APK_PATH = "/tmp/de.telekom.android.customercenter.prod.apk"
SERIAL = "36011FDH20018W"

print(f"Mission: Aegis Sentinel Direct Bootstrap v3")
print(f"Target: {APK_PATH}")

if not os.path.exists(APK_PATH):
    print("Error: APK not found.")
    sys.exit(1)

try:
    print("1. Ingesting via UploadManager...")
    # This stores the file in the proper internal directory
    app_info = mobile_upload_manager.upload(APK_PATH, "telekom_overnight.apk")
    app_id = app_info.id
    actual_apk_path = app_info.upload_path
    
    print(f"App Ingested. ID: {app_id}")
    print(f"Internal APK Path: {actual_apk_path}")

    print("2. Initializing MobileSecurityEngine...")
    engine = MobileSecurityEngine()
    
    config = MobileSecurityConfig(
        run_static=True,
        run_secrets=True,
        run_dynamic=True,
        device_id=SERIAL,
        run_ai_reverse=True,
        run_frida_gen=True,
        run_api_attack=True
    )

    print("3. Starting Autonomous Audit Pipeline (Overnight)...")
    # Pass the ACTUAL absolute path as the first argument
    engine.analyze(actual_apk_path, config)
    
    print("Mission Complete. Results should be in the Dashboard.")

except Exception as e:
    import traceback
    print(f"Audit Failure: {e}")
    traceback.print_exc()
