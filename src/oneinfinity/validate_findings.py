
import json
import os
import sys

# Add current directory to path
sys.path.insert(0, os.getcwd())

from oneinfinity.core.finding_validator import FindingClassifier

def main():
    report_path = "data/reports/report.json"
    if not os.path.exists(report_path):
        print(f"Error: {report_path} not found.")
        return

    with open(report_path) as f:
        data = json.load(f)
    
    findings = data.get("findings", [])
    if not findings:
        print("No findings found in report.json.")
        return

    print(f"[*] Validating {len(findings)} findings from {report_path}...")
    
    classifier = FindingClassifier()
    classified = classifier.classify(findings)
    
    print(f"[*] Results: {classified.summary()}")
    
    output_path = "data/reports/validated_findings.json"
    with open(output_path, "w") as f:
        json.dump(classified.to_dict(), f, indent=2)
    
    print(f"[*] Validated findings saved to {output_path}")
    
    print("\n--- CONFIRMED FINDINGS CLI REPRODUCIBILITY ---")
    for f in classified.confirmed:
        vt = f.get('vuln_type', 'unknown').upper()
        cmd = f.get('reproduction_cmd', 'N/A')
        print(f"  [+] {vt:15} | {cmd}")
    
    print("\n--- UNVERIFIED / AI THEORIES ---")
    for f in classified.unverified:
        vt = f.get('vuln_type', 'unknown').upper()
        desc = f.get('description', '')[:60] + "..."
        print(f"  [?] {vt:15} | {desc}")

if __name__ == "__main__":
    main()
