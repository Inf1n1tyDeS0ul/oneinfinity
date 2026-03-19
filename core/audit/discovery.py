import os
import ast
from typing import List, Dict, Any

class FeatureDiscovery:
    def __init__(self, root_dir: str):
        self.root_dir = root_dir
        
    def discover(self) -> List[Dict[str, Any]]:
        """Dynamically discover features (classes/functions) from the codebase."""
        features = []
        for root, _, files in os.walk(self.root_dir):
            # Skip hidden directories, tests, etc.
            if any(part.startswith('.') or part in ('tests', 'venv', 'env', '__pycache__') for part in root.split(os.sep)):
                continue
                
            for file in files:
                if file.endswith('.py') and not file.startswith('__'):
                    path = os.path.join(root, file)
                    rel_path = os.path.relpath(path, self.root_dir)
                    
                    try:
                        with open(path, 'r', encoding='utf-8') as f:
                            tree = ast.parse(f.read(), filename=path)
                            
                            for node in ast.walk(tree):
                                if isinstance(node, ast.ClassDef):
                                    # Very basic heuristic for a 'feature'
                                    if 'Engine' in node.name or 'Agent' in node.name or 'Manager' in node.name:
                                        features.append({
                                            "file": rel_path,
                                            "type": "class",
                                            "name": node.name
                                        })
                    except Exception:
                        pass
                        
        return features
