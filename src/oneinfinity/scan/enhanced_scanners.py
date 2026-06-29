"""
Enhanced Scanners (P1-P2)
=========================
Wrapper scanners for existing capabilities + innovation layers.

Wraps:
- Deserialization (tool_wrappers)
- LDAP injection (owasp_gap_checks)
- SAML (owasp_gap_checks)
- Prototype pollution (tool_wrappers)
- gRPC (owasp_gap_checks)

Innovation:
- Traffic-aware endpoint discovery
- Unified finding format
- Async scanning
- Integration with chain validator
"""
from __future__ import annotations

import asyncio
import hashlib
import logging
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional

log = logging.getLogger("oneinfinity.enhanced_scanners")

# ─────────────────────────────────────────────────────────────────────────────
# Unified Finding Model
# ─────────────────────────────────────────────────────────────────────────────

@dataclass
class ScannerFinding:
    """Unified finding model for all scanners."""
    finding_id: str
    vuln_type: str
    title: str
    severity: str
    url: str
    parameter: str = ""
    payload: str = ""
    evidence: str = ""
    confidence: float = 0.0
    tool: str = ""
    source_type: str = "active"

    def to_dict(self) -> dict:
        return {
            "finding_id": self.finding_id,
            "vuln_type": self.vuln_type,
            "title": self.title,
            "severity": self.severity,
            "url": self.url,
            "parameter": self.parameter,
            "payload": self.payload,
            "evidence": self.evidence,
            "confidence": self.confidence,
            "tool": self.tool,
            "source_type": self.source_type,
        }


# ─────────────────────────────────────────────────────────────────────────────
# Deserialization Scanner
# ─────────────────────────────────────────────────────────────────────────────

async def scan_deserialization(target: str) -> List[ScannerFinding]:
    """Scan deserialization vulnerabilities."""
    log.info(f"Scanning deserialization for {target}")

    findings = []

    try:
        from oneinfinity.modules.tool_wrappers import run_deserialization_test
    except ImportError:
        log.warning("Deserialization test not available")
        return []

    # Get POST endpoints from traffic
    try:
        from oneinfinity.scan.traffic_capture_engine import traffic_capture_engine
        requests = traffic_capture_engine.list(target=target, limit=200)
        urls = [
            req.to_json().get("url", "") if hasattr(req, 'to_json') else req.get("url", "")
            for req in requests
            if (req.to_json() if hasattr(req, 'to_json') else req).get("method") in ("POST", "PUT")
        ]
        urls = list(set(urls))[:20]
    except Exception:
        urls = [target]

    # Test each URL
    for url in urls:
        try:
            result = run_deserialization_test(url, timeout=10)
            if result.success and result.data.get("findings"):
                for raw_finding in result.data["findings"]:
                    findings.append(ScannerFinding(
                        finding_id=hashlib.md5(f"deser_{url}_{raw_finding.get('parameter')}".encode()).hexdigest()[:16],
                        vuln_type="insecure_deserialization",
                        title=raw_finding.get("vulnerability", "Deserialization"),
                        severity=raw_finding.get("severity", "critical"),
                        url=url,
                        parameter=raw_finding.get("parameter", "body"),
                        evidence=raw_finding.get("extra", {}).get("error_snippet", ""),
                        confidence=0.90,
                        tool="deserialization_scanner"
                    ))
        except Exception as e:
            log.debug(f"Deserialization test failed for {url}: {e}")

    log.info(f"Deserialization scan complete: {len(findings)} findings")
    return findings


# ─────────────────────────────────────────────────────────────────────────────
# LDAP Scanner
# ─────────────────────────────────────────────────────────────────────────────

async def scan_ldap_injection(target: str) -> List[ScannerFinding]:
    """Scan LDAP injection vulnerabilities."""
    log.info(f"Scanning LDAP injection for {target}")

    findings = []

    try:
        from oneinfinity.modules.owasp_gap_checks import check_ldap_injection
    except ImportError:
        log.warning("LDAP check not available")
        return []

    # Find login/auth endpoints
    try:
        from oneinfinity.scan.traffic_capture_engine import traffic_capture_engine
        requests = traffic_capture_engine.list(target=target, limit=200)
        auth_endpoints = []
        for req in requests:
            req_dict = req.to_json() if hasattr(req, 'to_json') else req
            url = req_dict.get("url", "")
            method = req_dict.get("method", "GET")
            if method in ("POST", "PUT") and any(kw in url.lower() for kw in ["login", "auth", "signin", "ldap"]):
                # Extract parameters
                body = req_dict.get("body", "")
                for part in body.split("&"):
                    if "=" in part:
                        param = part.split("=")[0]
                        if param.lower() in ["username", "user", "email", "uid"]:
                            auth_endpoints.append((url, param, method))
        auth_endpoints = list(set(auth_endpoints))[:10]
    except Exception:
        auth_endpoints = [(target, "username", "POST")]

    # Test each endpoint
    for url, param, method in auth_endpoints:
        try:
            result = check_ldap_injection(url, param, method)
            if result.confidence >= 0.65:
                findings.append(ScannerFinding(
                    finding_id=hashlib.md5(f"ldap_{url}_{param}".encode()).hexdigest()[:16],
                    vuln_type="ldap_injection",
                    title=f"LDAP Injection in {param}",
                    severity="critical" if result.active_confirmed else "high",
                    url=url,
                    parameter=param,
                    evidence=result.evidence,
                    confidence=result.confidence,
                    tool="ldap_scanner"
                ))
        except Exception as e:
            log.debug(f"LDAP test failed: {e}")

    log.info(f"LDAP scan complete: {len(findings)} findings")
    return findings


# ─────────────────────────────────────────────────────────────────────────────
# SAML Scanner
# ─────────────────────────────────────────────────────────────────────────────

async def scan_saml(target: str) -> List[ScannerFinding]:
    """Scan SAML vulnerabilities."""
    log.info(f"Scanning SAML for {target}")

    findings = []

    try:
        from oneinfinity.modules.owasp_gap_checks import check_saml_assertion
    except ImportError:
        log.warning("SAML check not available")
        return []

    # Find SAML responses in traffic
    try:
        from oneinfinity.scan.traffic_capture_engine import traffic_capture_engine
        requests = traffic_capture_engine.list(target=target, limit=500)
        saml_responses = []
        for req in requests:
            req_dict = req.to_json() if hasattr(req, 'to_json') else req
            url = req_dict.get("url", "")
            response = req_dict.get("response", {})
            body = response.get("body", "")
            if "saml" in body.lower() or "assertion" in body.lower():
                saml_responses.append((url, body))
        saml_responses = list(set(saml_responses))[:10]
    except Exception:
        saml_responses = []

    # Test each response
    for url, response_body in saml_responses:
        try:
            result = check_saml_assertion(url, response_body)
            if result.confidence >= 0.70:
                findings.append(ScannerFinding(
                    finding_id=hashlib.md5(f"saml_{url}".encode()).hexdigest()[:16],
                    vuln_type="saml_wrapping",
                    title="SAML Signature Vulnerability",
                    severity="critical",
                    url=url,
                    evidence=result.evidence,
                    confidence=result.confidence,
                    tool="saml_scanner"
                ))
        except Exception as e:
            log.debug(f"SAML test failed: {e}")

    log.info(f"SAML scan complete: {len(findings)} findings")
    return findings


# ─────────────────────────────────────────────────────────────────────────────
# Prototype Pollution Scanner
# ─────────────────────────────────────────────────────────────────────────────

async def scan_prototype_pollution(target: str) -> List[ScannerFinding]:
    """Scan prototype pollution vulnerabilities."""
    log.info(f"Scanning prototype pollution for {target}")

    findings = []

    try:
        from oneinfinity.modules.tool_wrappers import run_prototype_pollution_test
    except ImportError:
        log.warning("Prototype pollution test not available")
        return []

    # Get endpoints from traffic
    try:
        from oneinfinity.scan.traffic_capture_engine import traffic_capture_engine
        requests = traffic_capture_engine.list(target=target, limit=200)
        urls = [
            req.to_json().get("url", "") if hasattr(req, 'to_json') else req.get("url", "")
            for req in requests
        ]
        urls = list(set(urls))[:20]
    except Exception:
        urls = [target]

    # Test each URL
    for url in urls:
        try:
            result = run_prototype_pollution_test(url, timeout=10)
            if result.success and result.data.get("findings"):
                for raw_finding in result.data["findings"]:
                    findings.append(ScannerFinding(
                        finding_id=hashlib.md5(f"proto_{url}_{raw_finding.get('parameter')}".encode()).hexdigest()[:16],
                        vuln_type="prototype_pollution",
                        title=raw_finding.get("vulnerability", "Prototype Pollution"),
                        severity=raw_finding.get("severity", "high"),
                        url=url,
                        parameter=raw_finding.get("parameter", ""),
                        payload=raw_finding.get("extra", {}).get("payload", ""),
                        evidence=f"Reflected: {raw_finding.get('extra', {}).get('reflected', False)}",
                        confidence=0.85,
                        tool="prototype_pollution_scanner"
                    ))
        except Exception as e:
            log.debug(f"Prototype pollution test failed: {e}")

    log.info(f"Prototype pollution scan complete: {len(findings)} findings")
    return findings


# ─────────────────────────────────────────────────────────────────────────────
# gRPC Scanner
# ─────────────────────────────────────────────────────────────────────────────

async def scan_grpc(target: str) -> List[ScannerFinding]:
    """Scan gRPC vulnerabilities."""
    log.info(f"Scanning gRPC for {target}")

    findings = []

    try:
        from oneinfinity.modules.owasp_gap_checks import check_grpc_soap
    except ImportError:
        log.warning("gRPC check not available")
        return []

    # Test base URL
    try:
        from oneinfinity.scan.traffic_capture_engine import traffic_capture_engine
        requests = traffic_capture_engine.list(target=target, limit=100)
        first_req = requests[0] if requests else None
        if first_req:
            req_dict = first_req.to_json() if hasattr(first_req, 'to_json') else first_req
            response = req_dict.get("response", {})
            headers = response.get("headers", {})
            body = response.get("body", "")
            
            result = check_grpc_soap(target, headers, body)
            if result.confidence >= 0.60:
                findings.append(ScannerFinding(
                    finding_id=hashlib.md5(f"grpc_{target}".encode()).hexdigest()[:16],
                    vuln_type="grpc_reflection",
                    title="gRPC Reflection Enabled",
                    severity="high",
                    url=target,
                    evidence=result.evidence,
                    confidence=result.confidence,
                    tool="grpc_scanner"
                ))
    except Exception as e:
        log.debug(f"gRPC test failed: {e}")

    log.info(f"gRPC scan complete: {len(findings)} findings")
    return findings


# ─────────────────────────────────────────────────────────────────────────────
# Unified Scanner Interface
# ─────────────────────────────────────────────────────────────────────────────

async def scan_all_enhanced(target: str) -> Dict[str, List[ScannerFinding]]:
    """
    Run all enhanced scanners.

    Returns:
        Dict mapping scanner name to findings
    """
    log.info(f"Running all enhanced scanners for {target}")

    # Run all scanners in parallel
    results = await asyncio.gather(
        scan_deserialization(target),
        scan_ldap_injection(target),
        scan_saml(target),
        scan_prototype_pollution(target),
        scan_grpc(target),
        return_exceptions=True
    )

    return {
        "deserialization": results[0] if not isinstance(results[0], Exception) else [],
        "ldap": results[1] if not isinstance(results[1], Exception) else [],
        "saml": results[2] if not isinstance(results[2], Exception) else [],
        "prototype_pollution": results[3] if not isinstance(results[3], Exception) else [],
        "grpc": results[4] if not isinstance(results[4], Exception) else [],
    }
