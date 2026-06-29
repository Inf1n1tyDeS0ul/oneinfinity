import sys
import os
import json
import logging
from pathlib import Path

# Setup logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("AegisRecovery")

# Setup path
sys.path.insert(0, str(Path(__file__).parent.parent / "src"))

from oneinfinity.mobile.upload_manager import mobile_upload_manager
from oneinfinity.mobile.security_engine import MobileSecurityEngine, MobileSecurityConfig

# THE PRE-EXISTING DATA
APP_ID = "0bf13c1b-9ed"
APK_PATH = "/tmp/de.telekom.android.customercenter.prod.apk"
SERIAL = "36011FDH20018W"

logger.info(f"MISSION RECOVERY: Saving findings for {APP_ID}")

try:
    engine = MobileSecurityEngine()
    
    # Configure for analysis (will skip extraction as it's already on disk)
    config = MobileSecurityConfig(
        run_static=True,
        run_secrets=True,
        run_dynamic=False, # Skip dynamic to save time, already have static/secrets
        run_ai_reverse=True,
        run_frida_gen=True,
        run_api_attack=False,
        use_mobsf=False
    )

    # Run analysis (Fast because extraction is skipped)
    report = engine.analyze(APK_PATH, config)
    result = report.to_dict()

    # CRITICAL STEP: Explicit Persistence
    logger.info(f"Persisting {len(report.all_vulnerabilities)} findings to DB...")
    
    # Force Postgres URL for recovery
    os.environ["POSTGRES_URL"] = "postgresql://oi:oi_password_123@localhost:5433/oneinfinity"
    os.environ["ONEINFINITY_STORAGE_MODE"] = "distributed"
    
    mobile_upload_manager.save_result(APP_ID, result)
    
    # Also save to disk just in case
    analysis_dir = Path("data_local/raw/mobile/analysis")
    analysis_dir.mkdir(parents=True, exist_ok=True)
    (analysis_dir / f"{APP_ID}.json").write_text(json.dumps(result, indent=2))

    logger.info("RECOVERY COMPLETE. Findings are now in the Dashboard.")

except Exception as e:
    logger.exception(f"RECOVERY FAILED: {e}")
