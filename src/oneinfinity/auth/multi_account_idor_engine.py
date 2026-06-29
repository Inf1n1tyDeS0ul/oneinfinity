"""
Multi-Account IDOR Testing Engine
==================================
Cross-account access testing with automated ownership validation.

Integrates with:
  - session_manager.py (multi-account tokens)
  - traffic_replay_engine.py (request replay)
  - traffic_capture_engine.py (captured traffic)
  - finding_validator.py (result validation)

Innovation: AI-powered ownership inference from response patterns.
"""
from __future__ import annotations

import asyncio
import hashlib
import json
import logging
import re
import uuid
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Set, Tuple
from urllib.parse import urlparse, parse_qs

import httpx

from oneinfinity.auth.session_manager import SessionManager, LoginSession
from oneinfinity.scan.traffic_capture_engine import traffic_capture_engine, CapturedRequest
from oneinfinity.scan.traffic_replay_engine import traffic_replay_engine, ReplayResult
from oneinfinity.core.finding_validator import get_validator

log = logging.getLogger("oneinfinity.auth.multi_account_idor")

# ─────────────────────────────────────────────────────────────────────────────
# Constants
# ─────────────────────────────────────────────────────────────────────────────

# Patterns that indicate resource ownership in responses
_OWNERSHIP_PATTERNS = [
    re.compile(r'"user_id"\s*:\s*(\d+)', re.I),
    re.compile(r'"owner_id"\s*:\s*(\d+)', re.I),
    re.compile(r'"created_by"\s*:\s*(\d+)', re.I),
    re.compile(r'"author_id"\s*:\s*(\d+)', re.I),
    re.compile(r'"account_id"\s*:\s*(\d+)', re.I),
    re.compile(r'"uid"\s*:\s*"?(\d+)"?', re.I),
    re.compile(r'/user/(\d+)', re.I),
    re.compile(r'/profile/(\d+)', re.I),
]

# Markers indicating public/shared resources (not IDOR)
_PUBLIC_MARKERS = [
    "public", "shared", "everyone", "visibility:public",
    "access:open", "is_public:true", "publicly_accessible",
]

# Resource ID extraction patterns (URL and body)
_RESOURCE_ID_PATTERNS = [
    re.compile(r'/(\d{1,12})(?:/|$|\?)'),  # URL: /api/orders/123
    re.compile(r'"id"\s*:\s*(\d+)', re.I),  # JSON: {"id": 123}
    re.compile(r'[\?&]id=(\d+)', re.I),     # Query: ?id=123
]


# ─────────────────────────────────────────────────────────────────────────────
# Data models
# ─────────────────────────────────────────────────────────────────────────────

@dataclass
class AccountContext:
    """Single test account"""
    role: str                          # "victim", "attacker", "admin", etc.
    session: LoginSession
    user_id: Optional[str] = None      # Extracted from responses
    cookies_str: str = ""
    auth_header: str = ""

    def __post_init__(self):
        self.cookies_str = "; ".join(
            f"{c['name']}={c['value']}" for c in self.session.cookies if c.get('name')
        )
        self.auth_header = self.session.auth_headers.get('Authorization', '')


@dataclass
class IDORFinding:
    """IDOR vulnerability finding"""
    finding_id: str = field(default_factory=lambda: f"IDOR-{uuid.uuid4().hex[:8].upper()}")
    vuln_type: str = "idor"
    severity: str = "high"
    url: str = ""
    resource_id: str = ""
    victim_role: str = ""
    attacker_role: str = ""
    evidence: str = ""
    payload: str = ""
    confidence: float = 0.0
    idor_type: str = ""  # "horizontal", "vertical", "broken_access_control"
    ownership_proof: str = ""
    response_similarity: float = 0.0
    victim_response: str = ""
    attacker_response: str = ""
    tool: str = "multi_account_idor_engine"
    source_type: str = "tool"

    def to_dict(self) -> dict:
        return {k: v for k, v in self.__dict__.items()}


# ─────────────────────────────────────────────────────────────────────────────
# Multi-Account IDOR Engine
# ─────────────────────────────────────────────────────────────────────────────

class MultiAccountIDOREngine:
    """
    Cross-account IDOR testing with AI-powered ownership detection.

    Features:
    1. Automated account matrix testing (N × M accounts × endpoints)
    2. Traffic history replay with account substitution
    3. Ownership inference from response patterns
    4. Horizontal vs vertical privilege escalation detection
    5. Public resource false positive filtering
    """

    def __init__(self, target: str):
        self.target = target.rstrip('/')
        self.session_manager = SessionManager()
        self.accounts: Dict[str, AccountContext] = {}
        self._ownership_cache: Dict[str, Set[str]] = {}  # resource_id → set of owner user_ids

    # ── Account Management ────────────────────────────────────────────────────

    def load_accounts(self, account_configs: List[Dict[str, str]]) -> None:
        """
        Load multiple accounts from saved sessions or config.

        Args:
            account_configs: List of dicts with keys:
                - role: "victim", "attacker", "admin"
                - session_name: saved session name in SessionManager
                OR
                - token: Bearer token
                - cookies: cookie string
                - user_id: (optional) user identifier
        """
        for config in account_configs:
            role = config.get('role', 'user')
            session_name = config.get('session_name')

            if session_name:
                session = self.session_manager.load(name=session_name)
                if not session:
                    log.warning(f"Session '{session_name}' not found for role '{role}'")
                    continue
            else:
                # Build session from config
                session = LoginSession(
                    session_id=str(uuid.uuid4())[:12],
                    target=self.target,
                    login_url=config.get('login_url', f"{self.target}/login"),
                    cookies=[{'name': 'session', 'value': config.get('cookies', '')}],
                    auth_headers={'Authorization': config.get('token', '')},
                    local_storage={},
                    session_storage={},
                    indexeddb_snapshot={},
                    har_path="",
                    recorder="manual",
                )

            account = AccountContext(
                role=role,
                session=session,
                user_id=config.get('user_id'),
            )
            self.accounts[role] = account
            log.info(f"Loaded account: {role} (user_id={account.user_id})")

    def add_account_from_session(self, role: str, session: LoginSession) -> None:
        """Add account directly from LoginSession object"""
        account = AccountContext(role=role, session=session)
        self.accounts[role] = account
        log.info(f"Added account: {role}")

    # ── IDOR Testing ──────────────────────────────────────────────────────────

    async def test_all_captured_traffic(
        self,
        source_filter: Optional[str] = None,
        limit: int = 500,
    ) -> List[IDORFinding]:
        """
        Test all captured traffic for IDOR vulnerabilities.

        Strategy:
        1. Get all requests from victim account (source_filter)
        2. Identify resource-accessing requests (GET /api/user/123)
        3. Replay each request with attacker account credentials
        4. Detect unauthorized access via ownership analysis
        """
        if len(self.accounts) < 2:
            raise ValueError("Need at least 2 accounts (victim + attacker)")

        # Get victim and attacker accounts
        victim = self.accounts.get('victim') or list(self.accounts.values())[0]
        attacker = self.accounts.get('attacker') or list(self.accounts.values())[1]

        log.info(f"Testing IDOR: {victim.role} → {attacker.role}")

        # Get victim's captured requests
        victim_requests = traffic_capture_engine.list(
            source=source_filter or victim.role,
            status_min=200,
            status_max=299,
            limit=limit,
        )

        log.info(f"Found {len(victim_requests)} victim requests to test")

        findings: List[IDORFinding] = []
        tested_urls: Set[str] = set()

        # Test each request
        for req in victim_requests:
            # Skip if already tested (dedup by URL pattern)
            url_pattern = self._normalize_url_pattern(req.url)
            if url_pattern in tested_urls:
                continue
            tested_urls.add(url_pattern)

            # Extract resource ID
            resource_id = self._extract_resource_id(req)
            if not resource_id:
                continue

            # Test cross-account access
            result = await self._test_cross_account_access(req, victim, attacker)
            if result:
                findings.append(result)

        log.info(f"IDOR testing complete: {len(findings)} findings")
        return findings

    async def _test_cross_account_access(
        self,
        original_req: CapturedRequest,
        victim: AccountContext,
        attacker: AccountContext,
    ) -> Optional[IDORFinding]:
        """
        Test if attacker can access victim's resource.

        Returns IDORFinding if vulnerable, None otherwise.
        """
        resource_id = self._extract_resource_id(original_req)

        # Replay request with attacker credentials
        async with httpx.AsyncClient(verify=False, timeout=15) as client:
            headers = dict(original_req.headers)

            # Substitute attacker credentials
            if attacker.auth_header:
                headers['Authorization'] = attacker.auth_header

            cookies = {}
            if attacker.cookies_str:
                for pair in attacker.cookies_str.split('; '):
                    if '=' in pair:
                        k, v = pair.split('=', 1)
                        cookies[k] = v

            try:
                resp = await client.request(
                    method=original_req.method,
                    url=original_req.url,
                    headers=headers,
                    cookies=cookies,
                    content=original_req.body.encode('utf-8') if original_req.body else None,
                )

                attacker_response = resp.text
                attacker_status = resp.status_code

            except Exception as exc:
                log.debug(f"Cross-account request failed: {exc}")
                return None

        # Analyze results
        return self._analyze_idor(
            url=original_req.url,
            resource_id=resource_id,
            victim_status=original_req.response_status,
            victim_response=original_req.response_body,
            attacker_status=attacker_status,
            attacker_response=attacker_response,
            victim=victim,
            attacker=attacker,
        )

    def _analyze_idor(
        self,
        url: str,
        resource_id: str,
        victim_status: int,
        victim_response: str,
        attacker_status: int,
        attacker_response: str,
        victim: AccountContext,
        attacker: AccountContext,
    ) -> Optional[IDORFinding]:
        """
        Analyze if cross-account access indicates IDOR.

        Heuristics:
        1. Both returned 200 → potential IDOR
        2. Response similarity > 70% → likely same resource
        3. Response contains victim user_id → confirmed IDOR
        4. Response contains public markers → false positive
        """

        # Both must be successful
        if attacker_status not in (200, 201):
            return None

        if victim_status not in (200, 201):
            return None

        # Check for public resource markers
        if self._is_public_resource(attacker_response):
            log.debug(f"Resource {resource_id} is public, not IDOR")
            return None

        # Calculate response similarity
        similarity = self._response_similarity(victim_response, attacker_response)

        # Low similarity = different resources = not IDOR
        if similarity < 0.3:
            return None

        # Extract ownership from victim response
        victim_user_id = self._extract_user_id(victim_response)
        if not victim_user_id and victim.user_id:
            victim_user_id = victim.user_id

        # Check if attacker response contains victim's user_id (strong IDOR indicator)
        ownership_proof = ""
        if victim_user_id and victim_user_id in attacker_response:
            ownership_proof = f"Response contains victim user_id: {victim_user_id}"

        # Determine IDOR type
        idor_type = "horizontal"  # Same privilege level
        if victim.role == "user" and attacker.role == "admin":
            idor_type = "vertical_downgrade"  # Admin accessing user (less common)
        elif victim.role == "admin" and attacker.role == "user":
            idor_type = "vertical_escalation"  # User accessing admin (critical)

        # Calculate confidence
        confidence = 0.5  # Base
        confidence += 0.2 if similarity > 0.7 else 0.1
        confidence += 0.2 if ownership_proof else 0.0
        confidence += 0.1 if idor_type == "vertical_escalation" else 0.0

        # Minimum confidence threshold
        if confidence < 0.6:
            return None

        severity = "critical" if idor_type == "vertical_escalation" else "high"

        return IDORFinding(
            url=url,
            resource_id=resource_id,
            victim_role=victim.role,
            attacker_role=attacker.role,
            evidence=f"Attacker ({attacker.role}) accessed resource {resource_id} owned by {victim.role}. "
                     f"Status: {attacker_status}, Similarity: {similarity:.0%}",
            payload=f"Authorization: {attacker.auth_header[:50]}...",
            confidence=confidence,
            idor_type=idor_type,
            ownership_proof=ownership_proof,
            response_similarity=similarity,
            victim_response=victim_response[:500],
            attacker_response=attacker_response[:500],
            severity=severity,
        )

    # ── Analysis Helpers ──────────────────────────────────────────────────────

    def _extract_resource_id(self, req: CapturedRequest) -> Optional[str]:
        """Extract resource ID from URL or body"""
        # Try URL patterns
        for pattern in _RESOURCE_ID_PATTERNS:
            match = pattern.search(req.url)
            if match:
                return match.group(1)

        # Try body (JSON)
        if req.body:
            for pattern in _RESOURCE_ID_PATTERNS:
                match = pattern.search(req.body)
                if match:
                    return match.group(1)

        return None

    def _extract_user_id(self, response: str) -> Optional[str]:
        """Extract user/owner ID from response"""
        for pattern in _OWNERSHIP_PATTERNS:
            match = pattern.search(response)
            if match:
                return match.group(1)
        return None

    def _is_public_resource(self, response: str) -> bool:
        """Check if response indicates public/shared resource"""
        response_lower = response.lower()
        return any(marker in response_lower for marker in _PUBLIC_MARKERS)

    def _response_similarity(self, resp1: str, resp2: str) -> float:
        """
        Calculate response similarity (0-1).
        Uses Jaccard similarity of word sets.
        """
        if not resp1 or not resp2:
            return 0.0

        # Tokenize (simple word split)
        words1 = set(re.findall(r'\w+', resp1.lower()))
        words2 = set(re.findall(r'\w+', resp2.lower()))

        if not words1 and not words2:
            return 1.0

        intersection = len(words1 & words2)
        union = len(words1 | words2)

        return intersection / union if union > 0 else 0.0

    def _normalize_url_pattern(self, url: str) -> str:
        """
        Normalize URL by replacing numeric IDs with placeholders.
        /api/users/123 → /api/users/{id}
        """
        normalized = re.sub(r'/\d{1,12}(?=/|$|\?)', '/{id}', url)
        # Also normalize query params
        normalized = re.sub(r'[?&]id=\d+', '?id={id}', normalized)
        return normalized

    # ── Targeted Testing ──────────────────────────────────────────────────────

    async def test_endpoint_matrix(
        self,
        endpoints: List[str],
        resource_ids: List[str],
    ) -> List[IDORFinding]:
        """
        Test specific endpoints with all account combinations.

        Args:
            endpoints: List of endpoint templates (e.g., "/api/users/{id}")
            resource_ids: List of resource IDs to test

        Returns:
            List of IDOR findings
        """
        findings = []

        for endpoint_template in endpoints:
            for resource_id in resource_ids:
                url = endpoint_template.replace('{id}', resource_id)
                url = self.target + url if not url.startswith('http') else url

                # Test all account pairs
                for victim_role, victim in self.accounts.items():
                    for attacker_role, attacker in self.accounts.items():
                        if victim_role == attacker_role:
                            continue

                        finding = await self._test_endpoint_pair(
                            url, resource_id, victim, attacker
                        )
                        if finding:
                            findings.append(finding)

        return findings

    async def _test_endpoint_pair(
        self,
        url: str,
        resource_id: str,
        victim: AccountContext,
        attacker: AccountContext,
    ) -> Optional[IDORFinding]:
        """Test single endpoint with two accounts"""
        async with httpx.AsyncClient(verify=False, timeout=10) as client:
            # Victim request
            victim_headers = {'Authorization': victim.auth_header} if victim.auth_header else {}
            victim_cookies = {}
            if victim.cookies_str:
                for pair in victim.cookies_str.split('; '):
                    if '=' in pair:
                        k, v = pair.split('=', 1)
                        victim_cookies[k] = v

            try:
                victim_resp = await client.get(url, headers=victim_headers, cookies=victim_cookies)
                victim_status = victim_resp.status_code
                victim_body = victim_resp.text
            except Exception:
                return None

            # Attacker request
            attacker_headers = {'Authorization': attacker.auth_header} if attacker.auth_header else {}
            attacker_cookies = {}
            if attacker.cookies_str:
                for pair in attacker.cookies_str.split('; '):
                    if '=' in pair:
                        k, v = pair.split('=', 1)
                        attacker_cookies[k] = v

            try:
                attacker_resp = await client.get(url, headers=attacker_headers, cookies=attacker_cookies)
                attacker_status = attacker_resp.status_code
                attacker_body = attacker_resp.text
            except Exception:
                return None

        return self._analyze_idor(
            url=url,
            resource_id=resource_id,
            victim_status=victim_status,
            victim_response=victim_body,
            attacker_status=attacker_status,
            attacker_response=attacker_body,
            victim=victim,
            attacker=attacker,
        )

    # ── Export / Integration ──────────────────────────────────────────────────

    def export_findings(self, findings: List[IDORFinding]) -> List[dict]:
        """Convert findings to standard format for reporting"""
        validated_findings = []

        validator = get_validator()

        for finding in findings:
            finding_dict = finding.to_dict()

            # Apply validation
            validation = validator.validate(finding_dict)
            finding_dict['validation_status'] = validation.status
            finding_dict['confidence'] = validation.confidence

            validated_findings.append(finding_dict)

        return validated_findings


# ─────────────────────────────────────────────────────────────────────────────
# Global instance
# ─────────────────────────────────────────────────────────────────────────────

_engine_instances: Dict[str, MultiAccountIDOREngine] = {}

def get_multi_account_idor_engine(target: str) -> MultiAccountIDOREngine:
    """Get or create engine instance for target"""
    if target not in _engine_instances:
        _engine_instances[target] = MultiAccountIDOREngine(target)
    return _engine_instances[target]
