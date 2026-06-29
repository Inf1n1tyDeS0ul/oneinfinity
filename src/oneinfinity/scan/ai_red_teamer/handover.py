# src/oneinfinity/scan/ai_red_teamer/handover.py
import logging
from typing import Dict, List, Any, Optional
from oneinfinity.core.scope_validator import ScopeValidator

logger = logging.getLogger(__name__)

class HandoverProtocol:
    """
    Bridges AI-discovered leaks to infrastructure scanners with strict scope validation.
    """
    def __init__(self, scan_engine: Any, scope_validator: Optional[ScopeValidator] = None):
        """
        Initialize the HandoverProtocol.
        
        Args:
            scan_engine (Any): The UnifiedScanEngine or similar to trigger infra scans.
            scope_validator (Optional[ScopeValidator]): Optional validator. If not provided, 
                                                       a strict one will be created.
        """
        self.scan_engine = scan_engine
        self.scope_validator = scope_validator or ScopeValidator(mode="strict")

    def process_leaks(self, leaks: Dict[str, List[str]]):
        """
        Trigger scans for leaked URLs and IPs only if they are within the allowed scope.
        
        Args:
            leaks (Dict[str, List[str]]): Dictionary of extracted entities (urls, ips, etc.)
        """
        for url in leaks.get("urls", []):
            if not self.scope_validator.check(url):
                logger.warning(f"handover_blocked_out_of_scope_url: {url}")
                continue
                
            logger.info(f"handover_trigger_url_scan: {url}")
            if hasattr(self.scan_engine, 'scan'):
                self.scan_engine.scan(url)
        
        for ip in leaks.get("ips", []):
            if not self.scope_validator.check(ip):
                logger.warning(f"handover_blocked_out_of_scope_ip: {ip}")
                continue
                
            logger.info(f"handover_trigger_ip_scan: {ip}")
            if hasattr(self.scan_engine, 'scan'):
                self.scan_engine.scan(ip)
                
        # API keys and emails are currently reported but not used for secondary scans
        for key in leaks.get("api_keys", []):
            logger.info(f"handover_reporting_api_key_found: {key[:8]}...")
