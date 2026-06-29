import sys
import os
import logging
import time

# Setup logging to stdout
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s %(levelname)s %(message)s',
    handlers=[logging.StreamHandler(sys.stdout)]
)
logger = logging.getLogger("AegisLive")

# Setup path
from pathlib import Path
sys.path.insert(0, str(Path(__file__).parent.parent / "src"))

from oneinfinity.mobile.security_engine import MobileSecurityEngine, MobileSecurityConfig, MobileSecurityReport

# THE TARGET
APP_ID = "0bf13c1b-9ed"
PKG = "de.telekom.android.customercenter.prod"
SERIAL = "36011FDH20018W"

logger.info(f"LIVE FORENSIC MISSION START: {PKG}")

try:
    engine = MobileSecurityEngine()
    engine._lazy_load()
    engine._on_finding = lambda f, s: None
    engine._on_progress = lambda p, m: None
    
    # Configure for FORENSIC ONLY audit
    config = MobileSecurityConfig(
        run_static=False,
        run_secrets=False,
        run_dynamic=True,
        device_id=SERIAL,
        run_ai_reverse=False,
        run_frida_gen=False,
        run_api_attack=False,
        use_mobsf=False
    )

    report = MobileSecurityReport(app_id=APP_ID, package_name=PKG)
    
    logger.info("Triggering Live Forensic Sentinel (Active for 5 minutes)...")
    
    # In a separate thread to not block the sentinel? 
    # No, _phase_dynamic is synchronous. 
    # To keep it alive, we can increase the sleep time in run_audit or wrap it.
    
    # We'll just run it. The adb_forensics has a sleep(1).
    # I'll update adb_forensics to sleep longer if it's a live mission?
    # Or just loop it here.
    
    for i in range(10): # 10 * 30s = 5 minutes
        logger.info(f"Sentinel Pulse {i+1}/10...")
        engine._phase_dynamic(report, "/tmp/dummy.apk", "/tmp/extracted", config)
        time.sleep(30)
    
    logger.info("MISSION COMPLETE. Check your dashboard for Live Signals.")

except Exception as e:
    logger.exception(f"LIVE MISSION FAILED: {e}")
