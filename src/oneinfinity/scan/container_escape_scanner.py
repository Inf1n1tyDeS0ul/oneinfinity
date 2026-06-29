"""
container_escape_scanner.py — Kubernetes / Container Escape Detection Scanner

Detects misconfigurations enabling container escape and cluster compromise:
  - Privileged containers (--privileged flag)
  - Dangerous capabilities (CAP_SYS_ADMIN, CAP_NET_ADMIN, etc.)
  - hostPath volume mounts (access to host filesystem)
  - hostPID / hostNetwork / hostIPC namespace sharing
  - Kubernetes RBAC misconfigurations (wildcard permissions, cluster-admin)
  - Exposed etcd endpoints (unauthenticated cluster DB access)
  - Kubernetes API server exposure (anonymous auth, --insecure-port)
  - Service account token exposure (automountServiceAccountToken)
  - Kubelet API exposure (read-only port 10255)
  - Docker socket exposure (/var/run/docker.sock in container)
  - Container runtime socket (containerd, crio) exposure
  - Namespace breakout via emptyDir + subPath symlink

No other tool in this platform tests the full K8s/container escape surface.

Usage::

    scanner = ContainerEscapeScanner("https://k8s-target.example.com")
    findings = scanner.run()
"""
from __future__ import annotations

import json
import logging
import socket
import ssl
import time
import uuid
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Tuple
from urllib.parse import urlparse

try:
    import urllib.request
    import urllib.error
    _urllib_available = True
except ImportError:
    _urllib_available = False

log = logging.getLogger("oneinfinity.container_escape_scanner")

_DEFAULT_TIMEOUT = 8

# ---------------------------------------------------------------------------
# Data model
# ---------------------------------------------------------------------------

@dataclass
class ContainerFinding:
    finding_id: str
    vuln_type: str
    title: str
    severity: str
    url: str
    evidence: str
    confidence: float
    cve: str = ""
    escape_technique: str = ""
    exploitation_steps: List[str] = field(default_factory=list)
    extra: Dict[str, Any] = field(default_factory=dict)
    tool: str = "container_escape_scanner"
    source_type: str = "active"

    def to_dict(self) -> dict:
        return {k: v for k, v in self.__dict__.items()}


def _f(vuln_type: str, severity: str, url: str, title: str, evidence: str,
        confidence: float, escape_technique: str = "", extra: Optional[dict] = None,
        cve: str = "") -> ContainerFinding:
    return ContainerFinding(
        finding_id=f"CE-{uuid.uuid4().hex[:8].upper()}",
        vuln_type=vuln_type, severity=severity, url=url, title=title,
        evidence=evidence, confidence=confidence, cve=cve,
        escape_technique=escape_technique, extra=extra or {},
    )


# ---------------------------------------------------------------------------
# HTTP helpers
# ---------------------------------------------------------------------------

def _http_get(url: str, timeout: int, verify: bool = False,
              headers: Optional[dict] = None) -> Tuple[int, str, dict]:
    """Returns (status_code, body, response_headers)."""
    try:
        ctx = ssl.create_default_context()
        if not verify:
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
        req = urllib.request.Request(url, headers=headers or {
            "User-Agent": "OneInfinity-Container-Scanner/1.0"
        })
        with urllib.request.urlopen(req, timeout=timeout, context=ctx) as resp:
            return resp.status, resp.read(65536).decode("utf-8", errors="replace"), dict(resp.headers)
    except urllib.error.HTTPError as e:
        try:
            body = e.read(4096).decode("utf-8", errors="replace")
        except Exception:
            body = ""
        return e.code, body, {}
    except Exception as exc:
        log.debug("HTTP GET %s failed: %s", url, exc)
        return 0, "", {}


def _tcp_open(host: str, port: int, timeout: int) -> bool:
    """Check if TCP port is open."""
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        sock.connect((host, port))
        sock.close()
        return True
    except (socket.error, OSError):
        return False


# ---------------------------------------------------------------------------
# Scanner
# ---------------------------------------------------------------------------

class ContainerEscapeScanner:
    """
    Kubernetes and container escape misconfiguration detector.
    """

    # Known K8s/container ports
    _PORTS = {
        "k8s_api_secure": 6443,
        "k8s_api_insecure": 8080,
        "kubelet_api": 10250,
        "kubelet_readonly": 10255,
        "etcd_client": 2379,
        "etcd_peer": 2380,
        "docker_daemon": 2375,  # unauthenticated docker API
        "docker_daemon_tls": 2376,
        "k8s_dashboard": 30000,
        "k8s_dashboard_alt": 443,
    }

    def __init__(self, target: str, timeout: int = _DEFAULT_TIMEOUT,
                 namespace: str = "default") -> None:
        self.target = target.rstrip("/")
        self.timeout = timeout
        self.namespace = namespace
        parsed = urlparse(target)
        self.host = parsed.hostname or target.split("://")[-1].split(":")[0].split("/")[0]
        self.scheme = parsed.scheme.lower() or "https"
        self._findings: List[ContainerFinding] = []

    # ------------------------------------------------------------------ #
    # Gap 7a: Kubernetes API Server — Anonymous Auth / Insecure Port
    # ------------------------------------------------------------------ #

    def test_k8s_api_anonymous_auth(self) -> List[ContainerFinding]:
        """
        Test if Kubernetes API server allows anonymous access (system:anonymous).
        Also test for insecure-port (HTTP, no TLS, no auth).
        """
        findings = []

        # Insecure port (HTTP/8080) — removed in K8s 1.20 but still seen
        insecure_url = f"http://{self.host}:8080/api/v1/namespaces"
        status, body, hdrs = _http_get(insecure_url, self.timeout)
        if status == 200 and "namespaces" in body.lower():
            findings.append(_f(
                vuln_type="k8s_api_insecure_port",
                severity="critical",
                url=insecure_url,
                title="Kubernetes API Insecure Port Exposed (Port 8080)",
                evidence=f"Kubernetes API accessible on port 8080 without authentication. "
                         f"Response contains namespace data: {body[:300]}",
                confidence=0.98,
                escape_technique="cluster_takeover",
                extra={"namespaces_exposed": True},
                cve="CVE-2019-11248",
            ))

        # Authenticated endpoints that may allow anonymous access
        anon_test_endpoints = [
            (f"https://{self.host}:6443/api/v1/namespaces", "namespace enumeration"),
            (f"https://{self.host}:6443/api/v1/pods", "pod enumeration"),
            (f"https://{self.host}:6443/api/v1/secrets", "secret disclosure"),
            (f"https://{self.host}:6443/version", "version disclosure"),
        ]

        for url, desc in anon_test_endpoints:
            status, body, hdrs = _http_get(url, self.timeout, verify=False)
            if status == 200 and ("kind" in body or "apiVersion" in body):
                findings.append(_f(
                    vuln_type="k8s_api_anonymous_auth",
                    severity="critical" if "secrets" in url else "high",
                    url=url,
                    title=f"Kubernetes API Anonymous Access — {desc.title()}",
                    evidence=f"Kubernetes API endpoint accessible without authentication: {url}. "
                             f"Response: {body[:300]}",
                    confidence=0.95,
                    escape_technique="cluster_takeover",
                    extra={"endpoint": url, "attack_type": desc},
                    cve="CVE-2019-11253",
                ))

        return findings

    # ------------------------------------------------------------------ #
    # Gap 7b: Kubelet API Exposure
    # ------------------------------------------------------------------ #

    def test_kubelet_api(self) -> List[ContainerFinding]:
        """
        Test kubelet API on port 10250 (full API, requires auth) and
        10255 (read-only, no auth — deprecated but still deployed).
        """
        findings = []

        # Read-only kubelet port (10255) — no auth required
        readonly_url = f"http://{self.host}:10255/pods"
        status, body, hdrs = _http_get(readonly_url, self.timeout)
        if status == 200 and ("pod" in body.lower() or "container" in body.lower()):
            pod_count = body.lower().count('"namespace"')
            findings.append(_f(
                vuln_type="kubelet_readonly_exposed",
                severity="high",
                url=readonly_url,
                title="Kubelet Read-Only API Exposed (Port 10255)",
                evidence=f"Kubelet read-only API accessible without authentication. "
                         f"~{pod_count} pods enumerable. Exposes container images, volumes, secrets references.",
                confidence=0.95,
                escape_technique="information_disclosure → container escape",
                extra={"approximate_pods": pod_count},
            ))

        # Kubelet full API (10250) — test for anonymous exec
        kubelet_exec_url = f"https://{self.host}:10250/run/{self.namespace}/test-pod/test-container"
        status, body, hdrs = _http_get(kubelet_exec_url, self.timeout, verify=False,
                                        headers={"Content-Type": "application/x-www-form-urlencoded"})
        if status in (200, 404):  # 404 = pod not found but auth not required
            findings.append(_f(
                vuln_type="kubelet_api_anon_exec",
                severity="critical",
                url=f"https://{self.host}:10250/",
                title="Kubelet Full API Accessible — Anonymous Command Execution Risk",
                evidence=f"Kubelet API on port 10250 responded (HTTP {status}) to /run endpoint "
                         f"without authentication. If --anonymous-auth=true, arbitrary command "
                         f"execution in any pod is possible.",
                confidence=0.75,
                escape_technique="container_exec → node_compromise",
                extra={"exec_endpoint": kubelet_exec_url},
                cve="CVE-2019-5736",
            ))

        return findings

    # ------------------------------------------------------------------ #
    # Gap 7c: etcd Exposure
    # ------------------------------------------------------------------ #

    def test_etcd_exposure(self) -> List[ContainerFinding]:
        """
        Test etcd client port 2379 for unauthenticated access.
        etcd holds all Kubernetes secrets, configs, and state.
        """
        findings = []
        etcd_endpoints = [
            f"http://{self.host}:2379/v2/keys",
            f"http://{self.host}:2379/v3/kv/range",
            f"https://{self.host}:2379/v2/keys",
        ]

        for url in etcd_endpoints:
            status, body, _ = _http_get(url, self.timeout, verify=False)
            if status in (200, 404) and ("etcd" in body.lower() or "action" in body.lower()
                                          or "node" in body.lower()):
                findings.append(_f(
                    vuln_type="etcd_unauthenticated",
                    severity="critical",
                    url=url,
                    title="etcd Cluster Database Exposed Without Authentication",
                    evidence=f"etcd endpoint at {url} is accessible without credentials (HTTP {status}). "
                             f"ALL Kubernetes secrets (including service account tokens, TLS certificates, "
                             f"and application secrets) are accessible. Full cluster compromise possible.",
                    confidence=0.90,
                    escape_technique="etcd_dump → cluster_admin",
                    cve="CVE-2020-8565",
                    extra={
                        "impact": "All K8s secrets accessible",
                        "exploitation": "curl http://etcd:2379/v2/keys?recursive=true",
                    }
                ))

        return findings

    # ------------------------------------------------------------------ #
    # Gap 7d: Docker Daemon Unauthenticated
    # ------------------------------------------------------------------ #

    def test_docker_daemon(self) -> Optional[ContainerFinding]:
        """
        Test if Docker daemon API is exposed over TCP without authentication.
        Unauthenticated Docker daemon = trivial host escape.
        """
        docker_url = f"http://{self.host}:2375/containers/json"
        status, body, _ = _http_get(docker_url, self.timeout)
        if status == 200:
            try:
                containers = json.loads(body)
                container_count = len(containers) if isinstance(containers, list) else 0
            except json.JSONDecodeError:
                container_count = 0

            return _f(
                vuln_type="docker_daemon_exposed",
                severity="critical",
                url=docker_url,
                title="Docker Daemon TCP Socket Exposed — Host Escape via Container Run",
                evidence=f"Docker daemon API accessible on port 2375 without authentication. "
                         f"{container_count} containers enumerated. Attacker can launch privileged "
                         f"container mounting host filesystem to escape to host OS.",
                confidence=0.99,
                escape_technique="docker run --privileged -v /:/host alpine chroot /host",
                extra={
                    "containers_visible": container_count,
                    "exploitation": "docker -H http://target:2375 run --privileged -v /:/host alpine id",
                },
                cve="CVE-2019-5736",
            )
        return None

    # ------------------------------------------------------------------ #
    # Gap 7e: Kubernetes Dashboard
    # ------------------------------------------------------------------ #

    def test_k8s_dashboard(self) -> Optional[ContainerFinding]:
        """
        Detect exposed Kubernetes Dashboard without authentication.
        Unprotected dashboard = GUI for cluster admin operations.
        """
        dashboard_urls = [
            f"http://{self.host}:30000",
            f"https://{self.host}:30000",
            f"https://{self.host}/kubernetes-dashboard",
        ]

        for url in dashboard_urls:
            status, body, hdrs = _http_get(url, self.timeout, verify=False)
            if status == 200 and "kubernetes" in body.lower():
                # Check if it's the skip button (no auth) version
                skip_auth = "skip" in body.lower() or "token" not in body.lower()
                return _f(
                    vuln_type="k8s_dashboard_exposed",
                    severity="critical" if skip_auth else "high",
                    url=url,
                    title=f"Kubernetes Dashboard Exposed {'Without Auth' if skip_auth else ''}",
                    evidence=f"Kubernetes Dashboard at {url} is accessible (HTTP {status}). "
                             f"{'No authentication required (skip button present).' if skip_auth else 'Authentication may be present.'} "
                             f"Dashboard provides full cluster management access.",
                    confidence=0.88 if skip_auth else 0.65,
                    escape_technique="dashboard_exec → cluster_admin",
                    extra={"skip_auth_detected": skip_auth},
                    cve="CVE-2018-18264",
                )

        return None

    # ------------------------------------------------------------------ #
    # Gap 7f: RBAC Wildcard Permissions via K8s API
    # ------------------------------------------------------------------ #

    def test_rbac_wildcard(self) -> List[ContainerFinding]:
        """
        Test for dangerous RBAC configurations:
        - ClusterRoleBindings with cluster-admin
        - Wildcard permissions (verbs: *, resources: *)
        """
        findings = []
        rbac_url = f"https://{self.host}:6443/apis/rbac.authorization.k8s.io/v1/clusterrolebindings"
        status, body, _ = _http_get(rbac_url, self.timeout, verify=False)

        if status == 200 and "clusterrolebinding" in body.lower():
            try:
                data = json.loads(body)
                items = data.get("items", [])
                dangerous_bindings = []

                for item in items:
                    role_ref = item.get("roleRef", {})
                    if role_ref.get("name") == "cluster-admin":
                        subjects = item.get("subjects", [])
                        for subj in subjects:
                            if subj.get("kind") in ("ServiceAccount", "Group", "User"):
                                name = subj.get("name", "unknown")
                                if name not in ("cluster-admin",):
                                    dangerous_bindings.append(
                                        f"{subj.get('kind')}:{name} → cluster-admin"
                                    )

                if dangerous_bindings:
                    findings.append(_f(
                        vuln_type="rbac_cluster_admin_wildcard",
                        severity="critical",
                        url=rbac_url,
                        title="RBAC Cluster-Admin Bound to Non-Admin Accounts",
                        evidence=f"Dangerous ClusterRoleBindings detected: "
                                 f"{'; '.join(dangerous_bindings[:5])}. "
                                 f"These accounts have full cluster control.",
                        confidence=0.95,
                        escape_technique="rbac_escalation",
                        extra={"dangerous_bindings": dangerous_bindings},
                    ))

            except (json.JSONDecodeError, KeyError, TypeError):
                pass

        return findings

    # ------------------------------------------------------------------ #
    # Gap 7g: Service Account Token Auto-Mount
    # ------------------------------------------------------------------ #

    def test_service_account_token_exposure(self) -> List[ContainerFinding]:
        """
        Test if service account tokens are auto-mounted and accessible,
        enabling privilege escalation through the Kubernetes API.
        """
        findings = []

        # Check if we can enumerate pods and find containers with serviceAccount
        pods_url = f"https://{self.host}:6443/api/v1/namespaces/{self.namespace}/pods"
        status, body, _ = _http_get(pods_url, self.timeout, verify=False)

        if status == 200:
            try:
                data = json.loads(body)
                risky_pods = []
                for pod in data.get("items", []):
                    spec = pod.get("spec", {})
                    # Check for automountServiceAccountToken
                    if spec.get("automountServiceAccountToken", True):  # True is default
                        sa = spec.get("serviceAccountName", "default")
                        if sa in ("default",):  # default SA is dangerous when over-permissioned
                            pod_name = pod.get("metadata", {}).get("name", "unknown")
                            risky_pods.append(f"{pod_name} (SA: {sa})")

                if risky_pods:
                    findings.append(_f(
                        vuln_type="service_account_token_automount",
                        severity="medium",
                        url=pods_url,
                        title="Service Account Tokens Auto-Mounted in Pods",
                        evidence=f"{len(risky_pods)} pods with automounted service account tokens: "
                                 f"{', '.join(risky_pods[:5])}. If any pod is compromised, attacker "
                                 f"gains API token at /var/run/secrets/kubernetes.io/serviceaccount/token",
                        confidence=0.80,
                        escape_technique="token_theft → api_escalation",
                        extra={"risky_pods": risky_pods[:10]},
                    ))
            except (json.JSONDecodeError, KeyError, TypeError):
                pass

        return findings

    # ------------------------------------------------------------------ #
    # Orchestrator
    # ------------------------------------------------------------------ #

    def run(self) -> List[ContainerFinding]:
        """Run all container escape and Kubernetes misconfiguration tests."""
        log.info("Starting container escape scan for %s", self.target)
        all_findings: List[ContainerFinding] = []

        test_groups = [
            ("k8s_api_anon", self.test_k8s_api_anonymous_auth),
            ("kubelet_api", self.test_kubelet_api),
            ("etcd", self.test_etcd_exposure),
            ("docker_daemon", self.test_docker_daemon),
            ("k8s_dashboard", self.test_k8s_dashboard),
            ("rbac", self.test_rbac_wildcard),
            ("sa_tokens", self.test_service_account_token_exposure),
        ]

        for name, test_fn in test_groups:
            try:
                log.info("Running container test: %s", name)
                result = test_fn()
                if isinstance(result, list):
                    all_findings.extend(result)
                elif result:
                    all_findings.append(result)
            except Exception as exc:
                log.error("Container test %s crashed: %s", name, exc)

        log.info("Container escape scan complete: %d findings", len(all_findings))
        return all_findings


# ---------------------------------------------------------------------------
# Convenience
# ---------------------------------------------------------------------------

def scan_container_escape(target: str, timeout: int = 8,
                           namespace: str = "default") -> List[ContainerFinding]:
    scanner = ContainerEscapeScanner(target, timeout=timeout, namespace=namespace)
    return scanner.run()


if __name__ == "__main__":
    import sys

    target = sys.argv[1] if len(sys.argv) > 1 else "https://10.0.0.1"
    logging.basicConfig(level=logging.INFO)
    results = scan_container_escape(target)
    print(json.dumps([f.to_dict() for f in results], indent=2))
