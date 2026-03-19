import os
import asyncio
from typing import Dict, Any
from .discovery import FeatureDiscovery
from .executor import AuditExecutor
from .reporter import AuditReporter

class AuditEngine:
    def __init__(self, workspace_root: str, mode: str = "simulate"):
        self.workspace_root = workspace_root
        self.discovery = FeatureDiscovery(workspace_root)
        self.executor = AuditExecutor(mode=mode)
        self.reporter = AuditReporter()
        
    async def run(self, quick: bool = False) -> Dict[str, Any]:
        """Run the audit engine process."""
        features = self.discovery.discover()
        
        if quick:
            # In quick mode, only audit a small sample of features
            features = features[:10]
            
        results = []
        
        # Execute features concurrently with a semaphore to limit concurrency
        sem = asyncio.Semaphore(10)
        
        async def execute_with_sem(feat):
            async with sem:
                res = await self.executor.execute(feat)
                return {"feature": feat, **res}
                
        tasks = [execute_with_sem(feat) for feat in features]
        results = await asyncio.gather(*tasks)
            
        return self.reporter.generate(results)
