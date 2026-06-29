import sys
import os
import shutil
from pathlib import Path
import logging
import time

# Setup logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s %(levelname)s %(message)s',
    handlers=[logging.StreamHandler(sys.stdout)]
)
logger = logging.getLogger("AegisMission")

# Setup path
sys.path.insert(0, str(Path(__file__).parent.parent / "src"))

from oneinfinity.mobile.upload_manager import mobile_upload_manager
from oneinfinity.mobile.security_engine import MobileSecurityEngine, MobileSecurityConfig

# THE TARGET
APK_SOURCE = "/tmp/de.telekom.android.customercenter.prod.apk"
SERIAL = "36011FDH20018W"

logger.info(f"MISSION START: Aegis Sentinel Overnight Audit (Robust v4)")

try:
    if not os.path.exists(APK_SOURCE):
        logger.error(f"APK source {APK_SOURCE} not found. Mission aborted.")
        sys.exit(1)

    # STEP 1: Proper Ingestion (Ensures absolute paths in internal workspace)
    logger.info("1. Registering and storing app in OneInfinity workspace...")
    app_info = mobile_upload_manager.upload(APK_SOURCE, "telekom_production_audit.apk")
    
    app_id = app_info.id
    apk_path = app_info.upload_path
    extract_path = app_info.extract_path
    
    logger.info(f"App Workspace Initialized: ID={app_id}")
    logger.info(f"Workspace APK: {apk_path}")
    logger.info(f"Workspace Extracted: {extract_path}")

    # STEP 2: Engine Initialization
    logger.info("2. Initializing MobileSecurityEngine...")
    engine = MobileSecurityEngine()
    
    # Configure for Maximum Depth Audit
    config = MobileSecurityConfig(
        run_static=True,
        run_secrets=True,
        run_dynamic=True,
        device_id=SERIAL,
        run_ai_reverse=True,
        run_frida_gen=True,
        run_api_attack=True,
        use_mobsf=False # Skipping MobSF to prevent OOM
    )

    # STEP 3: Execution
    logger.info("3. Starting Autonomous Audit Pipeline (Synchronous)...")
    report = engine.analyze(apk_path, config)
    
    logger.info("MISSION COMPLETE.")
    logger.info(f"Findings: {len(report.all_vulnerabilities)}, Risk: {report.risk_score}")

except Exception as e:
    logger.exception(f"CRITICAL MISSION FAILURE: {e}")

sys.stdout.flush()
