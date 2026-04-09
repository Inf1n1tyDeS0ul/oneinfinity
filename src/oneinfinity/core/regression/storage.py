import json
import os
import tempfile
from pathlib import Path
from typing import Dict, Any

class RegressionStorage:
    def __init__(self, path: str):
        self.path = Path(path)
        
    def load(self) -> Dict[str, Any]:
        """Load previous run state."""
        if self.path.exists():
            try:
                with open(self.path, 'r', encoding='utf-8') as f:
                    return json.load(f)
            except Exception:
                return {}
        return {}
        
    def save(self, state: Dict[str, Any]):
        """Save current run state atomically (temp+rename to prevent corruption on crash)."""
        self.path.parent.mkdir(parents=True, exist_ok=True)
        fd, tmp_path = tempfile.mkstemp(dir=self.path.parent, suffix=".tmp")
        try:
            with os.fdopen(fd, 'w', encoding='utf-8') as f:
                json.dump(state, f, indent=2)
            os.replace(tmp_path, self.path)
        except Exception:
            os.unlink(tmp_path)
            raise
