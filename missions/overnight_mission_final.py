import sys
import os
from pathlib import Path
import logging
import time

# Setup logging to stdout so it captures everything in redirect
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s %(levelname)s %(message)s',
    handlers=[logging.StreamHandler(sys.stdout)]
)
logger = logging.getLogger("AegisMission")

# Setup path
sys.path.insert(0, str(Path(__file__).parent.parent / "src"))

from oneinfinity.mobile.security_engine import MobileSecurityEngine, MobileSecurityConfig

# THE TARGET
APK_PATH = "/tmp/de.telekom.android.customercenter.prod.apk"
SERIAL = "36011FDH20018W"

logger.info(f"MISSION START: Aegis Sentinel Overnight Audit")
logger.info(f"Target APK: {APK_PATH}")
logger.info(f"Target Device: {SERIAL}")

if not os.path.exists(APK_PATH):
    logger.error("CRITICAL: APK file not found at /tmp. Audit cannot proceed.")
    sys.exit(1)

try:
    logger.info("Initializing MobileSecurityEngine...")
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
        use_mobsf=False # Skipping MobSF to prevent OOM on 400MB Telekom app
    )

    logger.info("Starting Full 12-Phase Security Pipeline...")
    logger.info("This will take significant time for a 400MB / 30-DEX application.")
    
    # We pass the absolute path. The engine will handle upload/extract internally.
    report = engine.analyze(APK_PATH, config)
    
    logger.info("MISSION COMPLETE.")
    logger.info(f"Report Summary: {len(report.all_vulnerabilities)} findings, risk_score={report.risk_score}")
    logger.info(f"App ID: {report.app_id}")

except Exception as e:
    logger.exception(f"MISSION FAILED: {e}")

# Explicitly flush
sys.stdout.flush()
