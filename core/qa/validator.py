class QAValidator:
    """Validates QA execution outputs."""
    
    def validate(self, outputs: list) -> str:
        if not outputs:
            return "FAIL"
            
        # Check for empty outputs (all outputs are empty/None)
        if all(not out for out in outputs):
            return "FAIL"
            
        # Check for consistency across runs
        first = outputs[0]
        consistent = True
        for out in outputs[1:]:
            # Simple consistency check for demonstration
            if type(out) != type(first):
                consistent = False
                break
            if isinstance(out, dict) and isinstance(first, dict):
                if set(out.keys()) != set(first.keys()):
                    consistent = False
                    break
            elif out != first:
                consistent = False
                break
                
        if not consistent:
            return "UNRELIABLE"
            
        # Check for partial (e.g. dict is missing expected keys or has empty values)
        is_partial = False
        for out in outputs:
            if isinstance(out, dict):
                # If any top-level value is falsey but the dict itself has keys
                if out and any(not v for k, v in out.items() if k != "error"):
                    is_partial = True
                    break
                    
        if is_partial:
            return "PARTIAL"
            
        return "PASS"
