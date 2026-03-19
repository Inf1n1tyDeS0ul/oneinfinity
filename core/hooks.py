class DoctorHooks:
    """Optional hooks to auto-trigger the doctor command."""
    
    @staticmethod
    def on_scan_complete():
        print("[HOOK] Scan complete. Run 'onefinity doctor' to check system health.")
        
    @staticmethod
    def on_agent_error():
        print("[HOOK] Agent error detected. We recommend running 'onefinity doctor' for a full diagnosis.")
