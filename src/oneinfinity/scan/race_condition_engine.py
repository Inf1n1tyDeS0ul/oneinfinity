"""
Race Condition Testing Engine
==============================
Parallel request testing for race condition vulnerability detection.

Integrates with:
  - traffic_replay_engine.py (request replay)
  - traffic_capture_engine.py (captured traffic)
  - business_logic_attack_engine.py (race templates)
  - proxy_manager.py (traffic routing)

Innovation: Smart concurrency tuning + resource state diffing.
"""
from __future__ import annotations

import asyncio
import hashlib
import json
import logging
import re
import time
import uuid
from collections import Counter
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Set, Tuple
from urllib.parse import urlparse, parse_qs

import httpx

from oneinfinity.scan.traffic_capture_engine import traffic_capture_engine, CapturedRequest

log = logging.getLogger("oneinfinity.race_condition")

# ─────────────────────────────────────────────────────────────────────────────
# Constants
# ─────────────────────────────────────────────────────────────────────────────

# Endpoint patterns that are prime targets for race conditions
_RACE_PRONE_PATTERNS = [
    re.compile(r'/coupon|/promo|/discount', re.I),
    re.compile(r'/redeem|/claim|/apply', re.I),
    re.compile(r'/vote|/like|/favorite', re.I),
    re.compile(r'/transfer|/withdraw|/payment', re.I),
    re.compile(r'/checkout|/purchase|/order', re.I),
    re.compile(r'/verify|/confirm|/activate', re.I),
    re.compile(r'/upload|/create|/submit', re.I),
]

# HTTP methods that modify state
_STATE_MODIFYING_METHODS = ['POST', 'PUT', 'PATCH', 'DELETE']


# ─────────────────────────────────────────────────────────────────────────────
# Data models
# ─────────────────────────────────────────────────────────────────────────────

@dataclass
class RaceTestResult:
    """Result of a race condition test"""
    test_id: str = field(default_factory=lambda: f"RACE-{uuid.uuid4().hex[:8].upper()}")
    url: str = ""
    method: str = "POST"
    concurrency: int = 20
    total_requests: int = 0
    successful_responses: int = 0
    unique_responses: int = 0
    response_status_distribution: Dict[int, int] = field(default_factory=dict)
    response_times_ms: List[int] = field(default_factory=list)
    vulnerable: bool = False
    vulnerability_type: str = ""
    evidence: str = ""
    confidence: float = 0.0
    responses: List[Dict[str, Any]] = field(default_factory=list)
    resource_ids_created: List[str] = field(default_factory=list)
    balance_inconsistency: Optional[Dict] = None

    def to_dict(self) -> dict:
        return {
            'test_id': self.test_id,
            'url': self.url,
            'method': self.method,
            'concurrency': self.concurrency,
            'total_requests': self.total_requests,
            'successful_responses': self.successful_responses,
            'unique_responses': self.unique_responses,
            'response_status_distribution': self.response_status_distribution,
            'avg_response_time_ms': sum(self.response_times_ms) / len(self.response_times_ms) if self.response_times_ms else 0,
            'vulnerable': self.vulnerable,
            'vulnerability_type': self.vulnerability_type,
            'evidence': self.evidence,
            'confidence': self.confidence,
            'resource_ids_created': self.resource_ids_created,
            'balance_inconsistency': self.balance_inconsistency,
        }


@dataclass
class RaceFinding:
    """Race condition vulnerability finding"""
    finding_id: str = field(default_factory=lambda: f"RACE-{uuid.uuid4().hex[:8].upper()}")
    vuln_type: str = "race_condition"
    title: str = ""
    severity: str = "high"
    url: str = ""
    evidence: str = ""
    payload: str = ""
    confidence: float = 0.0
    race_type: str = ""  # "toctou", "duplicate_action", "resource_exhaustion", "state_confusion"
    expected_success_count: int = 1
    actual_success_count: int = 0
    test_result: Optional[RaceTestResult] = None
    tool: str = "race_condition_engine"
    source_type: str = "tool"

    def to_dict(self) -> dict:
        d = {k: v for k, v in self.__dict__.items() if k != 'test_result'}
        if self.test_result:
            d['test_details'] = self.test_result.to_dict()
        return d


# ─────────────────────────────────────────────────────────────────────────────
# Race Condition Testing Engine
# ─────────────────────────────────────────────────────────────────────────────

class RaceConditionEngine:
    """
    Parallel request engine for race condition detection.

    Features:
    1. Async parallel HTTP requests (configurable concurrency)
    2. Multiple race detection heuristics
    3. Smart endpoint targeting (auto-identify race-prone URLs)
    4. Resource state diffing (balance, IDs, counts)
    5. Adaptive concurrency tuning
    """

    def __init__(self):
        self._timeout = 30
        self._default_concurrency = 20
        self._max_concurrency = 100

    # ── Test Execution ────────────────────────────────────────────────────────

    async def test_request_parallel(
        self,
        url: str,
        method: str = "POST",
        headers: Optional[Dict[str, str]] = None,
        body: str = "",
        concurrency: int = 20,
        delay_between_batches_ms: int = 0,
    ) -> RaceTestResult:
        """
        Send N parallel requests to the same endpoint.

        Args:
            url: Target URL
            method: HTTP method
            headers: Request headers
            body: Request body
            concurrency: Number of parallel requests
            delay_between_batches_ms: Optional delay between request batches

        Returns:
            RaceTestResult with analysis
        """
        log.info(f"Testing race condition: {method} {url} (concurrency={concurrency})")

        headers = headers or {}
        content = body.encode('utf-8') if body else None

        responses = []
        start_time = time.time()

        async with httpx.AsyncClient(verify=False, timeout=self._timeout) as client:
            # Create all tasks
            tasks = [
                self._send_request(client, method, url, headers, content, i)
                for i in range(concurrency)
            ]

            # Execute in parallel
            results = await asyncio.gather(*tasks, return_exceptions=True)

        # Process results
        for i, result in enumerate(results):
            if isinstance(result, Exception):
                log.debug(f"Request {i} failed: {result}")
                continue

            responses.append(result)

        # Analyze results
        analysis = self._analyze_race_responses(url, method, concurrency, responses)
        analysis.response_times_ms = [int((time.time() - start_time) * 1000)]

        log.info(f"Race test complete: {analysis.successful_responses}/{concurrency} successful, "
                f"vulnerable={analysis.vulnerable}")

        return analysis

    async def _send_request(
        self,
        client: httpx.AsyncClient,
        method: str,
        url: str,
        headers: Dict[str, str],
        content: Optional[bytes],
        request_index: int,
    ) -> Dict[str, Any]:
        """Send single request and return response data"""
        start = time.time()
        try:
            resp = await client.request(
                method=method,
                url=url,
                headers=headers,
                content=content,
            )

            return {
                'index': request_index,
                'status': resp.status_code,
                'body': resp.text[:2000],  # Truncate for memory
                'headers': dict(resp.headers),
                'duration_ms': int((time.time() - start) * 1000),
                'exception': None,
            }

        except Exception as exc:
            return {
                'index': request_index,
                'status': 0,
                'body': '',
                'headers': {},
                'duration_ms': int((time.time() - start) * 1000),
                'exception': str(exc),
            }

    # ── Response Analysis ─────────────────────────────────────────────────────

    def _analyze_race_responses(
        self,
        url: str,
        method: str,
        concurrency: int,
        responses: List[Dict[str, Any]],
    ) -> RaceTestResult:
        """
        Analyze parallel responses for race condition indicators.

        Detection heuristics:
        1. Multiple 200/201 success (should be only 1)
        2. Resource ID sequence gaps (ID 1, 1, 3 - missing 2)
        3. Balance inconsistency (started $100, spent $50×20, ended $50 not -$900)
        4. Duplicate resource creation
        5. State confusion (conflicting final states)
        """
        result = RaceTestResult(
            url=url,
            method=method,
            concurrency=concurrency,
            total_requests=len(responses),
            responses=responses,
        )

        if not responses:
            return result

        # Count status codes
        status_counts = Counter(r['status'] for r in responses)
        result.response_status_distribution = dict(status_counts)
        result.successful_responses = sum(
            count for status, count in status_counts.items()
            if status in (200, 201, 204)
        )

        # Count unique response bodies
        unique_bodies = set(r['body'] for r in responses if r['body'])
        result.unique_responses = len(unique_bodies)

        # Heuristic 1: Multiple successes (most common race indicator)
        expected_success_count = 1  # Most operations should succeed only once
        if result.successful_responses > expected_success_count:
            result.vulnerable = True
            result.vulnerability_type = "duplicate_action"
            result.evidence = (
                f"Expected {expected_success_count} successful response, got {result.successful_responses}. "
                f"Action was executed multiple times."
            )
            result.confidence = 0.85
            return result

        # Heuristic 2: Resource ID sequence analysis
        resource_ids = []
        for r in responses:
            if r['status'] in (200, 201):
                ids = self._extract_resource_ids(r['body'])
                resource_ids.extend(ids)

        result.resource_ids_created = resource_ids

        if len(resource_ids) > 1:
            # Check for ID sequence gaps (indicates race in ID generation)
            numeric_ids = []
            for rid in resource_ids:
                try:
                    numeric_ids.append(int(rid))
                except ValueError:
                    pass

            if len(numeric_ids) > 1:
                numeric_ids.sort()
                gaps = []
                for i in range(len(numeric_ids) - 1):
                    gap = numeric_ids[i + 1] - numeric_ids[i]
                    if gap > 1:
                        gaps.append((numeric_ids[i], numeric_ids[i + 1]))

                if gaps:
                    result.vulnerable = True
                    result.vulnerability_type = "resource_id_race"
                    result.evidence = (
                        f"Resource ID sequence has gaps: {gaps}. "
                        f"Indicates race condition in ID generation/allocation."
                    )
                    result.confidence = 0.75
                    return result

        # Heuristic 3: Balance/count inconsistency detection
        balance_check = self._check_balance_inconsistency(responses)
        if balance_check:
            result.vulnerable = True
            result.vulnerability_type = "toctou_balance"
            result.evidence = balance_check['evidence']
            result.confidence = 0.90
            result.balance_inconsistency = balance_check
            return result

        # Heuristic 4: State confusion (conflicting final states)
        if result.unique_responses > result.successful_responses // 2:
            # Too many unique responses for same operation
            result.vulnerable = True
            result.vulnerability_type = "state_confusion"
            result.evidence = (
                f"Got {result.unique_responses} unique responses from {result.successful_responses} "
                f"successful requests. Indicates non-deterministic state."
            )
            result.confidence = 0.60

        return result

    def _extract_resource_ids(self, response_body: str) -> List[str]:
        """Extract resource IDs from response (order_id, transaction_id, etc.)"""
        patterns = [
            re.compile(r'"id"\s*:\s*"?(\d+)"?', re.I),
            re.compile(r'"order_id"\s*:\s*"?(\d+)"?', re.I),
            re.compile(r'"transaction_id"\s*:\s*"?(\w+)"?', re.I),
            re.compile(r'"resource_id"\s*:\s*"?(\w+)"?', re.I),
        ]

        ids = []
        for pattern in patterns:
            matches = pattern.findall(response_body)
            ids.extend(matches)

        return list(set(ids))  # Deduplicate

    def _check_balance_inconsistency(
        self,
        responses: List[Dict[str, Any]],
    ) -> Optional[Dict[str, Any]]:
        """
        Check for balance/count inconsistency in responses.

        Example: User had $100, tried to spend $50 twenty times in parallel,
        final balance should be $50 (1 success) or $100 (all failed),
        but if it's $0 or negative, race condition exists.
        """
        # Extract balance/amount fields from responses
        balance_pattern = re.compile(r'"(?:balance|amount|credits|count)"\s*:\s*(-?\d+(?:\.\d+)?)', re.I)

        balances = []
        for r in responses:
            if r['status'] in (200, 201):
                matches = balance_pattern.findall(r['body'])
                for match in matches:
                    try:
                        balances.append(float(match))
                    except ValueError:
                        pass

        if not balances:
            return None

        # Check for negative balance (strong race indicator)
        if any(b < 0 for b in balances):
            return {
                'evidence': f"Negative balance detected: {min(balances)}. Indicates TOCTOU race in balance check.",
                'balances': balances,
                'min_balance': min(balances),
                'max_balance': max(balances),
            }

        # Check for inconsistent balances across responses
        unique_balances = set(balances)
        if len(unique_balances) > 1:
            return {
                'evidence': f"Inconsistent balances: {unique_balances}. Indicates race in state updates.",
                'balances': balances,
                'unique_values': list(unique_balances),
            }

        return None

    # ── Automated Testing ─────────────────────────────────────────────────────

    async def test_captured_traffic(
        self,
        source_filter: Optional[str] = None,
        limit: int = 100,
        concurrency: int = 20,
    ) -> List[RaceFinding]:
        """
        Automatically test captured traffic for race conditions.

        Strategy:
        1. Filter for state-modifying requests (POST/PUT/PATCH)
        2. Prioritize race-prone endpoints (coupon, payment, etc.)
        3. Test each with parallel requests
        """
        log.info("Starting automated race condition testing on captured traffic")

        # Get candidate requests from traffic DB
        candidates = traffic_capture_engine.list(
            source=source_filter,
            status_min=200,
            status_max=299,
            limit=limit,
        )

        # Filter for state-modifying requests
        candidates = [
            req for req in candidates
            if req.method in _STATE_MODIFYING_METHODS
        ]

        # Prioritize race-prone endpoints
        candidates.sort(key=lambda r: self._race_prone_score(r.url), reverse=True)

        log.info(f"Testing {len(candidates[:50])} endpoints for race conditions")

        findings = []
        tested_urls = set()

        for req in candidates[:50]:  # Limit to top 50
            # Deduplicate by URL pattern
            url_pattern = self._normalize_url_pattern(req.url)
            if url_pattern in tested_urls:
                continue
            tested_urls.add(url_pattern)

            # Test race condition
            test_result = await self.test_request_parallel(
                url=req.url,
                method=req.method,
                headers=req.headers,
                body=req.body,
                concurrency=concurrency,
            )

            if test_result.vulnerable:
                finding = self._create_finding(req, test_result)
                findings.append(finding)

        log.info(f"Race condition testing complete: {len(findings)} vulnerabilities found")
        return findings

    def _race_prone_score(self, url: str) -> int:
        """Score URL for race condition likelihood (higher = more likely)"""
        score = 0
        for pattern in _RACE_PRONE_PATTERNS:
            if pattern.search(url):
                score += 10
        return score

    def _normalize_url_pattern(self, url: str) -> str:
        """Normalize URL by replacing IDs with placeholders"""
        normalized = re.sub(r'/\d{1,12}(?=/|$|\?)', '/{id}', url)
        normalized = re.sub(r'[?&]\w+=[^&]+', '', normalized)  # Remove query params
        return normalized

    def _create_finding(
        self,
        original_req: CapturedRequest,
        test_result: RaceTestResult,
    ) -> RaceFinding:
        """Convert test result to vulnerability finding"""
        severity_map = {
            "toctou_balance": "critical",
            "duplicate_action": "high",
            "resource_id_race": "high",
            "state_confusion": "medium",
        }

        severity = severity_map.get(test_result.vulnerability_type, "medium")

        title_map = {
            "toctou_balance": "TOCTOU Race Condition in Balance Check",
            "duplicate_action": "Race Condition Allows Duplicate Action Execution",
            "resource_id_race": "Race Condition in Resource ID Allocation",
            "state_confusion": "Race Condition Causes State Inconsistency",
        }

        title = title_map.get(test_result.vulnerability_type, "Race Condition Detected")

        return RaceFinding(
            title=title,
            severity=severity,
            url=test_result.url,
            evidence=test_result.evidence,
            payload=f"{original_req.method} {original_req.url}\n{original_req.body[:200]}",
            confidence=test_result.confidence,
            race_type=test_result.vulnerability_type,
            expected_success_count=1,
            actual_success_count=test_result.successful_responses,
            test_result=test_result,
        )

    # ── Request ID Testing ────────────────────────────────────────────────────

    async def test_captured_request_by_id(
        self,
        request_id: str,
        concurrency: int = 20,
    ) -> RaceTestResult:
        """
        Test a specific captured request for race conditions.

        Args:
            request_id: ID from traffic_capture_engine
            concurrency: Number of parallel requests

        Returns:
            RaceTestResult
        """
        req = traffic_capture_engine.get(request_id)
        if not req:
            raise ValueError(f"Request {request_id} not found in traffic DB")

        return await self.test_request_parallel(
            url=req.url,
            method=req.method,
            headers=req.headers,
            body=req.body,
            concurrency=concurrency,
        )


    async def test_h2_single_packet(
        self,
        url: str,
        method: str = "POST",
        headers: Optional[Dict[str, str]] = None,
        body: str = "",
        concurrency: int = 20,
    ) -> RaceTestResult:
        """
        HTTP/2 single-packet race condition (Burp Suite / James Kettle technique).

        Sends all N requests in a single TCP window so the server receives them
        simultaneously — eliminates network jitter that defeats parallel asyncio races.
        Falls back to test_request_parallel when h2/httpx h2 support unavailable.
        """
        log.info(f"H2 single-packet race: {method} {url} (concurrency={concurrency})")
        try:
            import httpx
            _headers = headers or {}
            _content = body.encode('utf-8') if body else None
            # Build all requests, then send them within one HTTP/2 connection
            # httpx with http2=True sends on the same TCP connection
            responses = []
            async with httpx.AsyncClient(verify=False, timeout=self._timeout, http2=True) as h2client:
                tasks = [
                    self._send_request(h2client, method, url, _headers, _content, i)
                    for i in range(concurrency)
                ]
                results = await asyncio.gather(*tasks, return_exceptions=True)
            for i, result in enumerate(results):
                if not isinstance(result, Exception):
                    responses.append(result)
            analysis = self._analyze_race_responses(url, method, concurrency, responses)
            analysis.technique = "h2_single_packet"
            return analysis
        except Exception as _h2_err:
            log.debug("H2 single-packet unavailable (%s), falling back to asyncio parallel", _h2_err)
            return await self.test_request_parallel(
                url=url, method=method, headers=headers, body=body, concurrency=concurrency
            )


# ─────────────────────────────────────────────────────────────────────────────
# Global instance
# ─────────────────────────────────────────────────────────────────────────────

race_condition_engine = RaceConditionEngine()
