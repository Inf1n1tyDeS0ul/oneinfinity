# src/oneinfinity/scan/ai_red_teamer/chainer.py
import re
import logging
import ipaddress
from typing import Dict, List, Set

logger = logging.getLogger(__name__)

class ExploitChainer:
    """
    Analyzes LLM responses to extract sensitive data and potential attack targets.
    Implements deduplication and robust validation of extracted entities.
    """
    def __init__(self):
        # Improved URL pattern: handles query params, fragments, and avoids trailing punctuation
        self.url_pattern = re.compile(
            r'https?://[a-zA-Z0-9\-._~:/?#\[\]@!$&\'()*+,;=%]+[a-zA-Z0-9/_~#$=%]'
        )
        # IP pattern (loose match, validated later)
        self.ip_candidate_pattern = re.compile(r'\b(?:\d{1,3}\.){3}\d{1,3}\b')
        self.email_pattern = re.compile(r'\b[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}\b')
        # Expanded API key patterns
        self.api_key_patterns = [
            re.compile(r'\bAKIA[0-9A-Z]{16}\b'),  # AWS Access Key
            re.compile(r'\b[a-f0-9]{32,40}\b', re.IGNORECASE),  # Generic Hex (MD5/SHA1)
            re.compile(r'\bsk_live_[0-9a-zA-Z]{24}\b'),  # Stripe Secret Key
        ]

    def _validate_ip(self, ip_str: str) -> bool:
        """Verify if a string is a valid IPv4 address."""
        try:
            ipaddress.IPv4Address(ip_str)
            return True
        except ValueError:
            return False

    def analyze_response(self, response_text: str) -> Dict[str, List[str]]:
        """
        Extract unique URLs, IPs, emails, and API keys from response text.
        """
        logger.info("exploit_chain_analysis_start", extra={"text_len": len(response_text)})
        
        # Use sets for automatic deduplication
        urls: Set[str] = set(self.url_pattern.findall(response_text))
        
        # Extract and validate IPs
        ip_candidates = self.ip_candidate_pattern.findall(response_text)
        ips: Set[str] = {ip for ip in ip_candidates if self._validate_ip(ip)}
        
        emails: Set[str] = set(self.email_pattern.findall(response_text))
        
        api_keys: Set[str] = set()
        for pattern in self.api_key_patterns:
            api_keys.update(pattern.findall(response_text))

        leaks = {
            "urls": sorted(list(urls)),
            "ips": sorted(list(ips)),
            "emails": sorted(list(emails)),
            "api_keys": sorted(list(api_keys))
        }
        
        logger.info("exploit_chain_analysis_complete", extra={
            "url_count": len(leaks["urls"]),
            "ip_count": len(leaks["ips"]),
            "email_count": len(leaks["emails"]),
            "api_key_count": len(leaks["api_keys"])
        })
        return leaks
