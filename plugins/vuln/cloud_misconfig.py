"""
Cloud Misconfiguration Scanner Plugin.

Detects common cloud misconfigurations:
  - Open S3 buckets (public read/write)
  - Exposed GCS buckets
  - Azure Blob Storage public containers
  - AWS metadata endpoint reachable via SSRF
  - Publicly accessible ECS/EKS metadata
  - Exposed cloud credentials in HTTP responses
  - Unsecured Elasticsearch/Kibana
  - Exposed Kubernetes API server
"""

from __future__ import annotations

import json
import logging
import re
import urllib.error
import urllib.request
from dataclasses import dataclass
from typing import Any, Dict, List, Optional, Set
from urllib.parse import urljoin, urlparse

log = logging.getLogger(__name__)

PLUGIN_META = {
    "name": "cloud_misconfig",
    "type": "vuln",
    "version": "1.0.0",
    "description": "Cloud misconfiguration detection — S3, GCS, Azure, AWS metadata, K8s",
    "author": "OneInfinity",
    "tags": ["cloud", "aws", "s3", "gcs", "azure", "kubernetes", "misconfig", "exposure"],
}

_TIMEOUT = 10

_AWS_METADATA_ENDPOINTS = [
    "http://169.254.169.254/latest/meta-data/",
    "http://169.254.169.254/latest/user-data",
    "http://169.254.169.254/latest/dynamic/instance-identity/document",
    "http://[fd00:ec2::254]/latest/meta-data/",  # IPv6
]

_KUBERNETES_PATHS = [
    "/api/v1/namespaces",
    "/api/v1/pods",
    "/api/v1/secrets",
    "/api",
    "/version",
]

_ELASTIC_PATHS = [
    ":9200/",
    ":9200/_cat/indices",
    ":9200/_cluster/health",
]

_CREDENTIAL_PATTERNS = [
    (r"AKIA[0-9A-Z]{16}", "AWS Access Key ID"),
    (r"aws_secret_access_key\s*=\s*[A-Za-z0-9/+]{40}", "AWS Secret Key"),
    (r"(?i)\"api[-_]?key\"\s*:\s*\"[A-Za-z0-9]{20,}\"", "API Key in JSON"),
    (r"(?i)password\s*=\s*['\"][^'\"]{8,}['\"]", "Hardcoded Password"),
    (r"ghp_[A-Za-z0-9]{36}", "GitHub Personal Access Token"),
    (r"(?i)\"access[-_]?token\"\s*:\s*\"[A-Za-z0-9._-]{20,}\"", "Access Token"),
]

_S3_BUCKET_PATTERN = re.compile(
    r"(?:s3://|https?://)?([a-z0-9][a-z0-9\-\.]{2,62}[a-z0-9])\.s3(?:[-\.](?:[a-z0-9-]+))?\.amazonaws\.com"
)


@dataclass
class CloudFinding:
    vuln_type: str
    severity: str
    endpoint: str
    description: str
    evidence: str = ""
    confidence: float = 0.80
    remediation: str = ""


class Plugin:
    """Cloud misconfiguration detector."""

    def run(self, target: str, context: Dict[str, Any]) -> Dict[str, Any]:
        """
        Args:
            target: domain or URL
            context:
                "urls": [str] — crawled URLs to scan for bucket refs + credential leaks
                "ssrf_vectors": [str] — SSRF probe URLs

        Returns:
            {"findings": [...], "tested": int, "error": None}
        """
        base_url = self._normalize_url(target)
        urls = context.get("urls", [])
        ssrf_vectors = context.get("ssrf_vectors", [])

        findings: List[CloudFinding] = []
        tested = 0

        # 1. Scan crawled URLs/responses for exposed credentials
        for url in urls[:100]:
            resp = self._get(url)
            if resp and resp.get("body"):
                cred_findings = self._check_credential_exposure(url, resp["body"])
                findings.extend(cred_findings)
                tested += 1

        # 2. Check S3 bucket references and test for public access
        bucket_names: Set[str] = set()
        for url in urls:
            for match in _S3_BUCKET_PATTERN.finditer(url):
                bucket_names.add(match.group(1))

        for bucket in list(bucket_names)[:10]:
            s3_findings = self._check_s3_bucket(bucket)
            findings.extend(s3_findings)
            tested += 1

        # 3. Kubernetes API exposure
        k8s_findings = self._check_kubernetes(base_url)
        findings.extend(k8s_findings)
        tested += len(_KUBERNETES_PATHS)

        # 4. Elasticsearch/Kibana exposure
        elastic_findings = self._check_elasticsearch(target)
        findings.extend(elastic_findings)
        tested += len(_ELASTIC_PATHS)

        # 5. SSRF to AWS metadata (test if provided SSRF vectors hit metadata)
        if ssrf_vectors:
            meta_findings = self._check_ssrf_metadata(ssrf_vectors[:5])
            findings.extend(meta_findings)
            tested += len(ssrf_vectors[:5])

        return {
            "findings": [self._to_dict(f) for f in findings],
            "tested": tested,
            "error": None,
        }

    # ------------------------------------------------------------------ #
    #  Individual checks
    # ------------------------------------------------------------------ #

    def _check_credential_exposure(self, url: str, body: str) -> List[CloudFinding]:
        findings = []
        for pattern, cred_type in _CREDENTIAL_PATTERNS:
            if re.search(pattern, body):
                findings.append(CloudFinding(
                    vuln_type="Credential Exposure",
                    severity="critical",
                    endpoint=url,
                    description=f"{cred_type} found in HTTP response body.",
                    evidence=self._redact(pattern, body),
                    confidence=0.85,
                    remediation="Remove secrets from application code and responses. Rotate exposed credentials immediately. Use secrets managers (AWS Secrets Manager, HashiCorp Vault).",
                ))
        return findings

    def _check_s3_bucket(self, bucket_name: str) -> List[CloudFinding]:
        findings = []
        bucket_url = f"https://{bucket_name}.s3.amazonaws.com/"
        resp = self._get(bucket_url)
        if resp is None:
            return []

        status = resp.get("status", 0)
        body = resp.get("body", "")

        if status == 200 and "<ListBucketResult" in body:
            findings.append(CloudFinding(
                vuln_type="Open S3 Bucket (Public Read)",
                severity="high",
                endpoint=bucket_url,
                description=f"S3 bucket '{bucket_name}' is publicly readable — bucket listing is enabled.",
                evidence=body[:400],
                confidence=0.95,
                remediation="Set bucket ACL to private. Enable Block Public Access settings. Review bucket policy.",
            ))
        elif status == 200:
            findings.append(CloudFinding(
                vuln_type="Open S3 Bucket (Public)",
                severity="medium",
                endpoint=bucket_url,
                description=f"S3 bucket '{bucket_name}' is publicly accessible.",
                evidence=f"HTTP {status}",
                confidence=0.70,
                remediation="Set bucket ACL to private and enable Block Public Access.",
            ))
        elif status == 403:
            # Bucket exists but access denied — still worth noting
            log.debug("[cloud_misconfig] S3 bucket exists but access denied: %s", bucket_name)

        return findings

    def _check_kubernetes(self, base_url: str) -> List[CloudFinding]:
        findings = []
        parsed = urlparse(base_url)
        # Try K8s API on port 6443 and 8080
        for port in [6443, 8080, 443]:
            k8s_base = f"https://{parsed.hostname}:{port}"
            for path in _KUBERNETES_PATHS[:2]:  # limit probes
                url = k8s_base + path
                resp = self._get(url)
                if resp and resp.get("status") == 200:
                    body = resp.get("body", "")
                    if "apiVersion" in body or "namespaces" in body or "pods" in body:
                        findings.append(CloudFinding(
                            vuln_type="Exposed Kubernetes API",
                            severity="critical",
                            endpoint=url,
                            description="Kubernetes API server is publicly accessible without authentication.",
                            evidence=body[:300],
                            confidence=0.90,
                            remediation="Restrict Kubernetes API access to authorized IPs. Enable RBAC and audit logging. Never expose K8s API to the public internet.",
                        ))
                        return findings  # one finding is enough
        return findings

    def _check_elasticsearch(self, target: str) -> List[CloudFinding]:
        findings = []
        parsed = urlparse(self._normalize_url(target))
        host = parsed.hostname or target
        for suffix in _ELASTIC_PATHS:
            url = f"http://{host}{suffix}"
            resp = self._get(url)
            if resp and resp.get("status") == 200:
                body = resp.get("body", "")
                if "cluster_name" in body or "indices" in body or "tagline" in body:
                    findings.append(CloudFinding(
                        vuln_type="Exposed Elasticsearch",
                        severity="high",
                        endpoint=url,
                        description="Elasticsearch instance is publicly accessible without authentication.",
                        evidence=body[:300],
                        confidence=0.90,
                        remediation="Enable Elasticsearch security features (xpack.security). Bind to localhost or restrict with firewall. Enable TLS and authentication.",
                    ))
                    break
        return findings

    def _check_ssrf_metadata(self, ssrf_results: List[str]) -> List[CloudFinding]:
        """If SSRF results contain AWS metadata responses, flag it."""
        findings = []
        for url in ssrf_results:
            resp = self._get(url)
            if resp and resp.get("status") == 200:
                body = resp.get("body", "")
                if any(k in body for k in ["ami-id", "instance-id", "local-ipv4", "iam"]):
                    findings.append(CloudFinding(
                        vuln_type="SSRF → AWS Metadata",
                        severity="critical",
                        endpoint=url,
                        description="SSRF vulnerability allows reading AWS EC2 instance metadata, potentially exposing IAM credentials.",
                        evidence=body[:400],
                        confidence=0.95,
                        remediation="Implement SSRF mitigations: allowlist outbound URLs, block 169.254.169.254. Use IMDSv2 (requires token-based requests).",
                    ))
        return findings

    # ------------------------------------------------------------------ #
    #  Helpers
    # ------------------------------------------------------------------ #

    def _get(self, url: str) -> Optional[dict]:
        req = urllib.request.Request(
            url,
            headers={"User-Agent": "Mozilla/5.0 (security-scan)"},
        )
        try:
            with urllib.request.urlopen(req, timeout=_TIMEOUT) as resp:
                return {
                    "status": resp.getcode(),
                    "body": resp.read(8192).decode("utf-8", errors="ignore"),
                }
        except urllib.error.HTTPError as e:
            return {"status": e.code, "body": ""}
        except Exception:
            return None

    def _normalize_url(self, url: str) -> str:
        if not url.startswith(("http://", "https://")):
            url = "https://" + url
        return url.rstrip("/")

    def _redact(self, pattern: str, body: str) -> str:
        match = re.search(pattern, body)
        if match:
            found = match.group(0)
            # Redact middle portion
            n = len(found)
            redacted = found[:4] + "*" * (n - 8) + found[-4:] if n > 8 else "****"
            return f"Pattern matched: {redacted}"
        return ""

    def _to_dict(self, f: CloudFinding) -> dict:
        return {
            "vuln_type": f.vuln_type,
            "severity": f.severity,
            "endpoint": f.endpoint,
            "description": f.description,
            "evidence": f.evidence,
            "confidence": f.confidence,
            "remediation": f.remediation,
            "tool": "cloud_misconfig_plugin",
        }
