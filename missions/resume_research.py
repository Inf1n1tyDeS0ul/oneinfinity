
import json
import logging
import os
import sys
import time
from pathlib import Path

# Setup path and env
sys.path.insert(0, str(Path(__file__).parent.parent / "src"))
os.environ["DB_MODE"] = "postgres"
# If Neo4j is still failing, we might want to disable it for the mission
# os.environ["NEO4J_ENABLED"] = "false"

from oneinfinity.orchestration.god_mode_engine import GodModeSession, GodModeStateFile, GOD_MODE_DIR
from oneinfinity.orchestration.research_mode_controller import ResearchModeController

logging.basicConfig(level=logging.INFO)
log = logging.getLogger("resume_research")

SCAN_ID = "gm-15992a"

def main():
    state_file = GodModeStateFile(SCAN_ID)
    data = state_file.read()
    if not data:
        print(f"Error: State file for {SCAN_ID} not found.")
        return

    # Reconstruct session
    session = GodModeSession(
        scan_id=data["scan_id"],
        target=data["target"],
        start_time=data["start_time"],
        phases_complete=data.get("phases_complete", []),
        finding_count=data.get("finding_count", 0),
        missions=data.get("missions", {}),
        terminated_by=data.get("terminated_by"),
        log_path=data.get("log_path", ""),
        background=data.get("background", False),
        auth_config=data.get("auth_config", {})
    )

    print(f"Resuming Research Mission for {session.scan_id} ({session.target})...")
    
    out_dir = str(GOD_MODE_DIR / session.scan_id / "research")
    Path(out_dir).mkdir(parents=True, exist_ok=True)

    # Update status to running
    session.missions["research"] = "running"
    state_file.write(session)

    try:
        ctrl = ResearchModeController(
            target=session.target,
            output_dir=out_dir,
            max_iterations=2, # Reduced for faster completion since we are resuming
            passive_only=False,
            auth_config=session.auth_config,
        )
        discoveries = ctrl.run_research()

        new_count = len(discoveries) if discoveries else 0
        session.add_findings(new_count)
        if "research" not in session.phases_complete:
            session.phases_complete.append("research")
        
        session.missions["research"] = "done"
        print(f"Research Mission complete. Found {new_count} new discoveries.")
    except Exception as exc:
        log.error("Research Mission failed again: %s", exc, exc_info=True)
        session.missions["research"] = "failed"
    
    # Final write
    state_file.write(session)
    print(f"Updated state for {SCAN_ID} saved.")

if __name__ == "__main__":
    main()
