import asyncio
import json
import os
from typing import Dict, Any

from .qa.engine import QAEngine
from .audit.engine import AuditEngine
from .regression.engine import RegressionEngine
from .audit.ai_analysis import ai_analysis

class DoctorOrchestrator:
    def __init__(self, workspace_root: str):
        self.workspace_root = workspace_root
        self.qa_engine = QAEngine()
        self.audit_engine = AuditEngine(workspace_root)
        self.regression_engine = RegressionEngine(workspace_root)
        
    def compute_health_score(self, qa_result: Dict[str, Any], audit_result: Dict[str, Any], regressions: list) -> float:
        """Calculate a health score between 0.0 and 10.0."""
        score = 10.0
        
        # Penalize for regressions
        score -= len(regressions) * 2.0
        
        # Penalize for failed QA
        for k, v in qa_result.items():
            status = v.get("status")
            if status == "FAIL":
                score -= 0.5
            elif status in ("UNRELIABLE", "PARTIAL"):
                score -= 0.2
                
        # Penalize for broken/partial features in audit
        summary = audit_result.get("summary", {})
        score -= summary.get("broken", 0) * 0.5
        score -= summary.get("partial", 0) * 0.2
        
        # Ensure score stays within 0-10 range
        return max(0.0, min(10.0, round(score, 1)))

    async def run(self, quick: bool = False, deep: bool = False) -> Dict[str, Any]:
        """Run the full doctor diagnostic suite."""
        
        # 1. Run QA Engine
        qa_result = await self.qa_engine.run(quick=quick, deep=deep)
        
        # 2. Run Audit Engine
        # Audit always runs in simulate mode; import mode is reserved for explicit calls.
        self.audit_engine = AuditEngine(self.workspace_root, mode="simulate")
        audit_result = await self.audit_engine.run(quick=quick)
        
        # 3. Detect Regressions
        regressions = self.regression_engine.detect(audit_result)
        
        # 4. AI Analysis
        insights = ai_analysis({
            "qa": qa_result,
            "audit": audit_result,
            "regressions": regressions
        })
        
        # 5. Compute Score
        score = self.compute_health_score(qa_result, audit_result, regressions)
        
        return {
            "score": score,
            "summary": {
                "quick_mode": quick,
                "deep_mode": deep,
                "total_features_audited": audit_result.get("summary", {}).get("total", 0)
            },
            "qa": qa_result,
            "audit": audit_result,
            "regressions": regressions,
            "insights": insights
        }

    def print_report(self, report: Dict[str, Any], output_json: bool = False):
        """Format and print the diagnostic report."""
        if output_json:
            print(json.dumps(report, indent=2))
            return
            
        print("\n" + "="*50)
        print(" " * 12 + "ONEINFINITY DOCTOR REPORT")
        print("="*50 + "\n")
        
        score = report['score']
        # Color coding standard in CLI tools
        if score >= 9.0:
            score_str = f"🟢 {score} / 10.0 (Healthy)"
        elif score >= 7.0:
            score_str = f"🟡 {score} / 10.0 (Warning)"
        else:
            score_str = f"🔴 {score} / 10.0 (Critical)"
            
        print(f"Health Score: {score_str}\n")
        
        print("--- QA Results ---")
        for k, v in report['qa'].items():
            status = v['status']
            icon = "✅" if status == "PASS" else ("❌" if status == "FAIL" else "⚠️")
            print(f"  {icon} {k}: {status}")

        # Optional QA detail: tool registry availability
        tr = report['qa'].get("tool_registry", {})
        if isinstance(tr, dict) and tr.get("status") == "PASS":
            outputs = tr.get("outputs", [])
            if outputs:
                o0 = outputs[0]
                if isinstance(o0, dict):
                    avail = o0.get("available_count")
                    miss = o0.get("missing_count")
                    if avail is not None and miss is not None:
                        print(f"\n  Tooling: {avail} available, {miss} missing")
            
        print("\n--- Audit Summary ---")
        summary = report['audit'].get('summary', {})
        print(f"  ✅ Working: {summary.get('working', 0)}")
        print(f"  ⚠️ Partial: {summary.get('partial', 0)}")
        print(f"  ❌ Broken:  {summary.get('broken', 0)}")
        
        if report['audit'].get('dead_code'):
            print(f"\n  Dead Code / Missing Integrations Detected: {len(report['audit']['dead_code'])}")
            for dc in report['audit']['dead_code'][:5]:
                print(f"    - {dc}")
            if len(report['audit']['dead_code']) > 5:
                print(f"    ... and {len(report['audit']['dead_code']) - 5} more.")
        
        print("\n--- Regressions ---")
        if not report['regressions']:
            print("  ✅ None detected.")
        else:
            for r in report['regressions']:
                feat_name = r['feature'].get('name', 'Unknown')
                print(f"  📉 {feat_name}: {r['previous']} -> {r['current']}")
                
        print("\n--- AI Insights ---")
        insights = report['insights']
        print(f"  🔍 Root Cause: {insights.get('root_cause_analysis')}")
        
        if insights.get("system_weaknesses"):
            print("  ⚠️ Weaknesses:")
            for w in insights.get("system_weaknesses", []):
                print(f"    - {w}")
                
        print("  💡 Recommendations:")
        for rec in insights.get('fix_recommendations', []):
            print(f"    - {rec}")
            
        print("\n" + "="*50 + "\n")
