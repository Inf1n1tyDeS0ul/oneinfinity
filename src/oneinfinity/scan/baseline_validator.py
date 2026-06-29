"""
Baseline-Aware Vulnerability Validator
=======================================
False positive reduction via traffic baseline comparison.

Integrates with:
  - finding_validator.py (existing validation)
  - traffic_capture_engine.py (baseline establishment)

Innovation: Traffic pattern learning + contextual SQLi/SSRF validation.
"""
from __future__ import annotations

import logging
import re
from collections import defaultdict
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Set, Tuple
from urllib.parse import urlparse

from oneinfinity.scan.traffic_capture_engine import traffic_capture_engine, CapturedRequest
from oneinfinity.core.finding_validator import FindingValidator

log = logging.getLogger("oneinfinity.baseline_validator")

# ─────────────────────────────────────────────────────────────────────────────
# Real DB error patterns (not templates)
# ─────────────────────────────────────────────────────────────────────────────

_REAL_SQL_ERRORS = [
    # MySQL
    re.compile(r'You have an error in your SQL syntax', re.I),
    re.compile(r"mysql_fetch|mysql_query|mysql_num_rows", re.I),
    re.compile(r'MySQLSyntaxErrorException|MySQLIntegrityConstraintViolationException', re.I),

    # PostgreSQL
    re.compile(r'pg_query|pg_exec|pg_fetch', re.I),
    re.compile(r'PostgreSQL.*ERROR', re.I),
    re.compile(r'PSQLException|PostgresException', re.I),

    # SQLite
    re.compile(r'SQLite3::SQLException|sqlite3\.OperationalError', re.I),
    re.compile(r'SQLITE_ERROR', re.I),

    # Oracle
    re.compile(r'ORA-\d{5}', re.I),
    re.compile(r'Oracle.*Exception', re.I),

    # SQL Server
    re.compile(r'SQLSTATE\[', re.I),
    re.compile(r'SqlException|SQLException', re.I),
    re.compile(r'Unclosed quotation mark after the character string', re.I),

    # Generic SQL
    re.compile(r'quoted string not properly terminated', re.I),
    re.compile(r'unterminated quoted string', re.I),
]

_SQL_TEMPLATE_MARKERS = [
    # Template/generic error page markers (NOT real SQLi)
    'error.html', 'error_page', 'error-template',
    '<title>Error</title>', '<title>500 Error</title>',
    'An error occurred', 'Something went wrong',
]

_REAL_SSRF_INDICATORS = [
    # AWS metadata
    re.compile(r'169\.254\.169\.254', re.I),
    re.compile(r'"AccessKeyId"\s*:\s*"[A-Z0-9]{20}"', re.I),

    # GCP metadata
    re.compile(r'metadata\.google\.internal', re.I),
    re.compile(r'metadata/v1', re.I),

    # Azure metadata
    re.compile(r'169\.254\.169\.254.*azure', re.I),

    # Internal services
    re.compile(r'consul\.service', re.I),
    re.compile(r'kubernetes\.default', re.I),
]

_DESIGNED_REDIRECT_MARKERS = [
    '/login', '/signin', '/authenticate',
    '/oauth', '/callback', '/redirect',
    'Location:', 'Redirecting',
]


# ─────────────────────────────────────────────────────────────────────────────
# Baseline data
# ─────────────────────────────────────────────────────────────────────────────

@dataclass
class Baseline:
    """Baseline for a URL pattern"""
    url_pattern: str
    normal_responses: List[CapturedRequest] = field(default_factory=list)
    normal_status_codes: Set[int] = field(default_factory=set)
    normal_response_signatures: Set[str] = field(default_factory=set)
    invalid_id_response: Optional[str] = None
    string_id_response: Optional[str] = None
    contains_sql_keyword: bool = False  # Normal responses mention "SQL"
    is_public_resource: bool = False
    established: bool = False


# ─────────────────────────────────────────────────────────────────────────────
# Baseline Validator
# ─────────────────────────────────────────────────────────────────────────────

class BaselineValidator:
    """
    Enhanced validator that uses traffic baselines to reduce false positives.

    Features:
    1. Baseline establishment (normal vs attack responses)
    2. Context-aware SQLi validation (real DB errors vs templates)
    3. SSRF vs designed redirect detection
    4. Public resource vs IDOR detection
    5. Response pattern learning
    """

    def __init__(self):
        self.baselines: Dict[str, Baseline] = {}
        self.base_validator = FindingValidator()

    # ── Baseline Establishment ────────────────────────────────────────────────

    def establish_baseline(self, url: str) -> Baseline:
        """
        Establish baseline for a URL by analyzing traffic history.

        Strategy:
        1. Get normal (200) requests to same URL pattern
        2. Get error cases (invalid ID, string ID)
        3. Extract response patterns
        """
        url_pattern = self._normalize_url_pattern(url)

        if url_pattern in self.baselines and self.baselines[url_pattern].established:
            return self.baselines[url_pattern]

        log.info(f"Establishing baseline for {url_pattern}")

        baseline = Baseline(url_pattern=url_pattern)

        # Get historical traffic for this pattern
        domain = urlparse(url).netloc
        historical = traffic_capture_engine.list(
            target=domain,
            status_min=200,
            status_max=299,
            limit=50,
        )

        # Filter for same URL pattern
        matching = [
            req for req in historical
            if self._normalize_url_pattern(req.url) == url_pattern
        ]

        baseline.normal_responses = matching[:10]
        baseline.normal_status_codes = set(req.response_status for req in matching)

        # Create response signatures (hash of key response features)
        for req in baseline.normal_responses:
            signature = self._response_signature(req.response_body)
            baseline.normal_response_signatures.add(signature)

            # Check if normal responses contain SQL keywords
            if 'sql' in req.response_body.lower():
                baseline.contains_sql_keyword = True

            # Check for public resource markers
            if self._is_public_marker(req.response_body):
                baseline.is_public_resource = True

        # Test with invalid ID (if URL has ID parameter)
        if self._has_id_param(url):
            baseline.invalid_id_response = self._get_invalid_id_response(url)
            baseline.string_id_response = self._get_string_id_response(url)

        baseline.established = True
        self.baselines[url_pattern] = baseline

        log.info(f"Baseline established: {len(baseline.normal_responses)} normal responses")
        return baseline

    # ── Enhanced Validation ───────────────────────────────────────────────────

    def validate_sqli(
        self,
        finding: dict,
        attack_response: str,
        attack_status: int,
    ) -> Tuple[bool, str]:
        """
        Validate SQLi finding with baseline comparison.

        Returns:
            (is_real_vuln: bool, reason: str)
        """
        url = finding.get('url', '')
        baseline = self.establish_baseline(url)

        # Check 1: Is "SQL" mention just from error page template?
        if baseline.contains_sql_keyword:
            # Baseline responses also mention SQL - likely template
            if not self._has_real_sql_error(attack_response):
                return False, "SQL keyword found in normal responses - likely error page template"

        # Check 2: Does response have actual DB error?
        if not self._has_real_sql_error(attack_response):
            return False, "No real database error detected - generic error page"

        # Check 3: Is response similar to normal responses?
        attack_signature = self._response_signature(attack_response)
        if attack_signature in baseline.normal_response_signatures:
            return False, "Attack response identical to normal response - not SQLi"

        # Check 4: Check for template markers
        if self._has_template_markers(attack_response):
            return False, "Response contains error template markers"

        return True, "Real SQLi confirmed - actual database error"

    def validate_ssrf(
        self,
        finding: dict,
        attack_response: str,
        attack_status: int,
    ) -> Tuple[bool, str]:
        """
        Validate SSRF finding vs designed redirect.

        Returns:
            (is_real_vuln: bool, reason: str)
        """
        url = finding.get('url', '')
        payload = finding.get('payload', '')

        # Check 1: Is this a designed redirect endpoint?
        if any(marker in url.lower() for marker in _DESIGNED_REDIRECT_MARKERS):
            return False, "Designed redirect endpoint - not SSRF"

        # Check 2: Does response contain real SSRF indicators?
        has_real_ssrf = any(
            pattern.search(attack_response)
            for pattern in _REAL_SSRF_INDICATORS
        )

        if not has_real_ssrf:
            # Check if just a redirect
            if 'location:' in attack_response.lower() or attack_status in (301, 302, 303, 307, 308):
                return False, "Simple redirect - not SSRF"

        # Check 3: Metadata/internal service access
        if has_real_ssrf:
            return True, "Real SSRF - accessed internal metadata/service"

        # Check 4: Response contains external content
        if 'localhost' in payload.lower() or '127.0.0.1' in payload:
            if attack_status == 200 and len(attack_response) > 100:
                return True, "SSRF confirmed - accessed localhost and got content"

        return False, "No SSRF indicators found"

    def validate_idor(
        self,
        finding: dict,
        attack_response: str,
        original_response: str,
        attack_status: int,
    ) -> Tuple[bool, str]:
        """
        Validate IDOR finding vs public resource.

        Returns:
            (is_real_vuln: bool, reason: str)
        """
        url = finding.get('url', '')
        baseline = self.establish_baseline(url)

        # Check 1: Is resource marked as public?
        if baseline.is_public_resource or self._is_public_marker(attack_response):
            return False, "Public resource - not IDOR"

        # Check 2: Compare with invalid ID response
        if baseline.invalid_id_response:
            # If attack response matches invalid ID response, not IDOR
            if self._responses_similar(attack_response, baseline.invalid_id_response, threshold=0.8):
                return False, "Response matches invalid ID response - not IDOR"

        # Check 3: Response similarity to original
        similarity = self._response_similarity(original_response, attack_response)
        if similarity < 0.3:
            return False, "Responses too different - accessing different resource"

        # Check 4: Check for ownership indicators
        if self._has_ownership_mismatch(original_response, attack_response, finding):
            return True, "IDOR confirmed - ownership mismatch detected"

        # Moderate confidence
        if similarity > 0.7 and attack_status == 200:
            return True, "Likely IDOR - high response similarity"

        return False, "Insufficient evidence for IDOR"

    # ── Helper Methods ────────────────────────────────────────────────────────

    def _has_real_sql_error(self, response: str) -> bool:
        """Check if response contains real DB error (not template)"""
        return any(pattern.search(response) for pattern in _REAL_SQL_ERRORS)

    def _has_template_markers(self, response: str) -> bool:
        """Check if response is generic error template"""
        response_lower = response.lower()
        return any(marker in response_lower for marker in _SQL_TEMPLATE_MARKERS)

    def _is_public_marker(self, response: str) -> bool:
        """Check if response indicates public/shared resource"""
        response_lower = response.lower()
        public_markers = [
            '"public":true', '"is_public":true', '"visibility":"public"',
            '"access":"public"', '"shared":true', 'publicly accessible',
        ]
        return any(marker in response_lower for marker in public_markers)

    def _response_signature(self, response: str) -> str:
        """
        Create signature hash of response (for deduplication).

        Uses: status line count, response length bucket, key JSON fields.
        """
        import hashlib

        # Length bucket (not exact)
        length_bucket = len(response) // 100

        # Line count bucket
        line_count = response.count('\n') // 10

        # Extract JSON keys (if JSON response)
        json_keys = ""
        try:
            import json
            data = json.loads(response)
            if isinstance(data, dict):
                json_keys = ",".join(sorted(data.keys()))
        except json.JSONDecodeError:
            pass

        signature_str = f"{length_bucket}|{line_count}|{json_keys}"
        return hashlib.md5(signature_str.encode()).hexdigest()[:8]

    def _response_similarity(self, resp1: str, resp2: str) -> float:
        """Calculate Jaccard similarity between responses"""
        if not resp1 or not resp2:
            return 0.0

        words1 = set(re.findall(r'\w+', resp1.lower()))
        words2 = set(re.findall(r'\w+', resp2.lower()))

        if not words1 and not words2:
            return 1.0

        intersection = len(words1 & words2)
        union = len(words1 | words2)

        return intersection / union if union > 0 else 0.0

    def _responses_similar(self, resp1: str, resp2: str, threshold: float = 0.7) -> bool:
        """Check if two responses are similar above threshold"""
        return self._response_similarity(resp1, resp2) >= threshold

    def _has_ownership_mismatch(
        self,
        original_response: str,
        attack_response: str,
        finding: dict,
    ) -> bool:
        """Detect ownership mismatch in IDOR"""
        # Extract user IDs from responses
        user_id_pattern = re.compile(r'"(?:user_id|owner_id|created_by)"\s*:\s*(\d+)', re.I)

        original_ids = set(user_id_pattern.findall(original_response))
        attack_ids = set(user_id_pattern.findall(attack_response))

        # If attacker response contains original user's ID, strong IDOR indicator
        if original_ids and attack_ids and original_ids == attack_ids:
            return True

        return False

    def _normalize_url_pattern(self, url: str) -> str:
        """Normalize URL to pattern (replace IDs with placeholders)"""
        # Remove protocol and domain
        parsed = urlparse(url)
        path = parsed.path

        # Replace numeric IDs
        normalized = re.sub(r'/\d{1,12}(?=/|$|\?)', '/{id}', path)

        # Remove query params (keep structure only)
        if parsed.query:
            normalized += '?'

        return normalized

    def _has_id_param(self, url: str) -> bool:
        """Check if URL has ID parameter"""
        return bool(re.search(r'/\d{1,12}(?=/|$|\?)', url))

    def _get_invalid_id_response(self, url: str) -> Optional[str]:
        """Get response for invalid ID (99999)"""
        invalid_url = re.sub(r'/(\d{1,12})(?=/|$|\?)', '/99999', url)
        # This would need actual HTTP request - simplified for now
        return None

    def _get_string_id_response(self, url: str) -> Optional[str]:
        """Get response for string ID (abc)"""
        string_url = re.sub(r'/(\d{1,12})(?=/|$|\?)', '/abc', url)
        # This would need actual HTTP request - simplified for now
        return None

    # ── Integrated Validation ─────────────────────────────────────────────────

    def validate_finding_enhanced(
        self,
        finding: dict,
        attack_response: Optional[str] = None,
        original_response: Optional[str] = None,
        attack_status: Optional[int] = None,
    ) -> dict:
        """
        Enhanced validation that combines base validation + baseline checks.

        Returns:
            Updated finding dict with enhanced validation status
        """
        # First run base validation
        base_result = self.base_validator.validate(finding)

        # Apply baseline checks based on vuln type
        vuln_type = finding.get('vuln_type', '').lower()

        if 'sqli' in vuln_type or 'sql_injection' in vuln_type:
            if attack_response and attack_status:
                is_real, reason = self.validate_sqli(finding, attack_response, attack_status)
                if not is_real:
                    finding['validation_status'] = 'false_positive'
                    finding['fp_reason'] = reason
                    finding['confidence'] = 0.2

        elif 'ssrf' in vuln_type:
            if attack_response and attack_status:
                is_real, reason = self.validate_ssrf(finding, attack_response, attack_status)
                if not is_real:
                    finding['validation_status'] = 'false_positive'
                    finding['fp_reason'] = reason
                    finding['confidence'] = 0.2

        elif 'idor' in vuln_type:
            if attack_response and original_response and attack_status:
                is_real, reason = self.validate_idor(
                    finding, attack_response, original_response, attack_status
                )
                if not is_real:
                    finding['validation_status'] = 'false_positive'
                    finding['fp_reason'] = reason
                    finding['confidence'] = 0.2

        # Keep base validation if no baseline override
        if 'validation_status' not in finding or finding['validation_status'] != 'false_positive':
            finding['validation_status'] = base_result.status
            finding['confidence'] = base_result.confidence
            finding['confidence_breakdown'] = base_result.confidence_breakdown

        return finding


# ─────────────────────────────────────────────────────────────────────────────
# Global instance
# ─────────────────────────────────────────────────────────────────────────────

baseline_validator = BaselineValidator()
