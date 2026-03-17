
import sys
import os
import time
import logging
import threading

# Add project root to sys.path
sys.path.insert(0, os.getcwd())

from unified_scan_engine import get_engine

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
    handlers=[logging.StreamHandler(sys.stdout)]
)
log = logging.getLogger("reproduce_scan")

def on_progress(phase, pct, msg):
    print(f"[PROGRESS] {phase.upper()} ({pct}%): {msg}")

def main():
    target = "https://telekom.de"
    
    # Clear cache - disabled to test loading from previous successful recon
    import shutil
    from pathlib import Path
    home = Path.home()
    recon_dir = home / ".oneinfinity" / "raw" / "telekom.de"
    # if recon_dir.exists():
    #     log.info(f"Clearing cache at {recon_dir}")
    #     shutil.rmtree(recon_dir)

    log.info(f"Starting scan for {target}")
    
    engine = get_engine()
    
    # We use scan_async to not block if we want to inspect things while it runs,
    # but here we'll just join the thread or wait loop.
    session = engine.scan_async(target, on_progress=on_progress)
    
    log.info(f"Scan started with ID: {session.scan_id}")
    
    # Monitor loop
    while session.status == "running":
        time.sleep(2)
        # We can inspect session.phases here if needed
        # log.info(f"Status: {session.status}")

    log.info(f"Scan finished with status: {session.status}")
    if session.error:
        log.error(f"Scan error: {session.error}")
    
    log.info(f"Findings: {len(session.findings)}")
    for f in session.findings:
        print(f" - [{f.get('severity')}] {f.get('title')} ({f.get('tool')})")

if __name__ == "__main__":
    main()
