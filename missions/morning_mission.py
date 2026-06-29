import sys
import os
import logging
import time

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s %(levelname)s %(message)s',
    handlers=[logging.StreamHandler(sys.stdout)]
)
logger = logging.getLogger("AegisMission")

from pathlib import Path
sys.path.insert(0, str(Path(__file__).parent.parent / "src"))

from oneinfinity.mobile.security_engine import MobileSecurityEngine, MobileSecurityConfig

APK_SOURCE = "/tmp/de.telekom.android.customercenter.prod.apk"
SERIAL = "36011FDH20018W"

logger.info(f"MORNING MISSION RESTART: Aegis Sentinel (Fixed Paths)")

if not os.path.exists(APK_SOURCE):
    logger.error("APK not found.")
    sys.exit(1)

try:
    engine = MobileSecurityEngine()
    config = MobileSecurityConfig(
        run_static=True,
        run_secrets=True,
        run_dynamic=True,
        device_id=SERIAL,
        run_ai_reverse=True,
        run_frida_gen=True,
        run_api_attack=True,
        use_mobsf=False
    )

    logger.info("Executing Pipeline...")
    report = engine.analyze(APK_SOURCE, config)
    
    logger.info("MISSION COMPLETE.")
    logger.info(f"Findings: {len(report.all_vulnerabilities)}, Risk: {report.risk_score}")

except Exception as e:
    logger.exception(f"FAILURE: {e}")
