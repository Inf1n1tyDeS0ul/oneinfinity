from typing import List, Dict, Any

class AuditReporter:
    def generate(self, results: List[Dict[str, Any]]) -> Dict[str, Any]:
        summary = {"working": 0, "partial": 0, "broken": 0, "total": len(results)}
        
        for res in results:
            status = res.get("status", "")
            if "working" in status:
                summary["working"] += 1
            elif "partial" in status:
                summary["partial"] += 1
            elif "broken" in status:
                summary["broken"] += 1
                
        # Detect dead code/missing integrations (simulated)
        dead_code = []
        if summary["broken"] > 0:
            dead_code = [r["feature"]["name"] for r in results if "broken" in r.get("status", "")]
            
        return {
            "summary": summary, 
            "details": results,
            "dead_code": dead_code
        }
