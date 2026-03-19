import os
from typing import List, Dict, Any
from .storage import RegressionStorage

class RegressionEngine:
    def __init__(self, workspace_root: str):
        self.storage = RegressionStorage(os.path.join(workspace_root, ".doctor_state.json"))
        
    def detect(self, current_audit: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Detect regressions by comparing current audit with previous state."""
        previous = self.storage.load()
        regressions = []
        
        if not previous:
            # First run, just save state
            self.storage.save(current_audit)
            return []
            
        # Create a mapping of feature name -> status for previous run
        prev_details = {
            str(d.get("feature", {}).get("name")): d.get("status") 
            for d in previous.get("details", []) 
            if "feature" in d
        }
        
        for curr in current_audit.get("details", []):
            feat_name = str(curr.get("feature", {}).get("name"))
            curr_status = curr.get("status", "")
            prev_status = prev_details.get(feat_name)
            
            # Detect working -> broken or partial transition
            if prev_status and "working" in prev_status and "working" not in curr_status:
                regressions.append({
                    "feature": curr.get("feature"),
                    "previous": prev_status,
                    "current": curr_status,
                    "type": "degradation"
                })
                
        # Save the current state for the next run
        self.storage.save(current_audit)
        
        return regressions
