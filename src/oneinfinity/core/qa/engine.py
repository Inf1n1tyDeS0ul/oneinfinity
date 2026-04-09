import asyncio
from typing import Dict, Any
from .scenarios import SCENARIOS
from .validator import QAValidator

class QAEngine:
    def __init__(self):
        self.validator = QAValidator()
        self.runs = 2  # Run same feature at least twice for consistency
        
    async def run(self, quick: bool = False, deep: bool = False) -> Dict[str, Any]:
        results = {}
        
        runs = self.runs
        if quick:
            runs = 1
        elif deep:
            runs = 5
            
        # Run scenarios in parallel
        async def run_scenario(name, scenario_func):
            try:
                outputs = []
                for _ in range(runs):
                    out = await scenario_func()
                    outputs.append(out)
                
                status = self.validator.validate(outputs)
                return name, {"status": status, "outputs": outputs}
            except Exception as e:
                return name, {"status": "FAIL", "error": str(e)}

        tasks = [run_scenario(name, func) for name, func in SCENARIOS.items()]
        completed = await asyncio.gather(*tasks)
        
        for name, res in completed:
            results[name] = res
            
        return results
