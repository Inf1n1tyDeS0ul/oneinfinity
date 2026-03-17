"""
graph_updater.py — Handles all incoming intelligence and translates it into graph updates.
All other engines call this instead of touching the graph directly.
"""

import logging
import time
import uuid
from typing import Optional
from urllib.parse import urlparse

from .graph_engine import AttackGraphEngine, NodeType, EdgeType, get_engine

logger = logging.getLogger(__name__)


class GraphUpdater:
    """
    Single entry point for all engines to write discoveries into the attack graph.
    Each method is idempotent — safe to call multiple times with the same data.
    """

    def __init__(self, engine: AttackGraphEngine = None):
        self._engine = engine  # resolved lazily on first use

    @property
    def engine(self) -> AttackGraphEngine:
        if self._engine is None:
            self._engine = get_engine()
        return self._engine

    # ------------------------------------------------------------------
    # Asset nodes
    # ------------------------------------------------------------------

    def add_target(self, domain: str, program: str = "", platform: str = "") -> object:
        """Register a top-level pentest target."""
        node, _ = self.engine.get_or_create_node(
            NodeType.TARGET,
            domain,
            properties={"program": program, "platform": platform},
            source="target_registration",
        )
        logger.info(f"Target registered: {domain}")
        return node

    def add_subdomain(self, domain: str, parent_domain: str, source: str = "recon") -> object:
        """Create Subdomain node and link it to the parent target via HOSTS edge."""
        parent_key = (NodeType.TARGET, parent_domain)
        # Try target first, then subdomain
        parent_node = None
        for ntype in [NodeType.TARGET, NodeType.SUBDOMAIN]:
            candidate_key = (ntype, parent_domain)
            existing_id = self.engine._label_index.get(candidate_key)
            if existing_id:
                parent_node = self.engine.get_node(existing_id)
                break

        if parent_node is None:
            parent_node = self.add_target(parent_domain)

        sub_node, created = self.engine.get_or_create_node(
            NodeType.SUBDOMAIN,
            domain,
            properties={"parent": parent_domain},
            source=source,
        )

        self.engine.add_edge(
            parent_node.id,
            sub_node.id,
            EdgeType.HOSTS,
            label=f"{parent_domain} hosts {domain}",
            source_engine=source,
        )

        if created:
            logger.debug(f"Subdomain added: {domain} <- {parent_domain}")
        return sub_node

    def add_url(
        self,
        url: str,
        parent_domain: str,
        method: str = "GET",
        status_code: int = 200,
    ) -> object:
        """Create a URL node and connect it to its parent domain/subdomain."""
        parsed = urlparse(url)
        clean_url = url.rstrip("/")

        # Find parent node
        parent_node = None
        for ntype in [NodeType.SUBDOMAIN, NodeType.TARGET]:
            pid = self.engine._label_index.get((ntype, parent_domain))
            if pid:
                parent_node = self.engine.get_node(pid)
                break
        if parent_node is None:
            parent_node = self.add_target(parent_domain)

        url_node, created = self.engine.get_or_create_node(
            NodeType.URL,
            clean_url,
            properties={
                "method": method,
                "status_code": status_code,
                "path": parsed.path,
                "scheme": parsed.scheme,
                "host": parsed.netloc,
            },
            source="crawler",
        )

        self.engine.add_edge(
            parent_node.id,
            url_node.id,
            EdgeType.EXPOSES,
            label="exposes",
            source_engine="crawler",
        )

        return url_node

    def add_parameter(
        self,
        name: str,
        url: str,
        param_type: str = "query",
        value_type: str = "string",
    ) -> object:
        """Create a Parameter node and link it to its URL."""
        label = f"{url}?{name}"
        url_node_id = self.engine._label_index.get((NodeType.URL, url)) or \
                      self.engine._label_index.get((NodeType.URL, url.rstrip("/")))

        param_node, _ = self.engine.get_or_create_node(
            NodeType.PARAMETER,
            label,
            properties={
                "name": name,
                "url": url,
                "param_type": param_type,
                "value_type": value_type,
            },
            source="parameter_discovery",
        )

        if url_node_id:
            self.engine.add_edge(
                url_node_id,
                param_node.id,
                EdgeType.EXPOSES,
                label="has_parameter",
                source_engine="parameter_discovery",
            )

        return param_node

    def add_api_endpoint(
        self,
        path: str,
        method: str,
        base_url: str,
        auth_required: bool = False,
    ) -> object:
        """Create an API endpoint node."""
        label = f"{method} {base_url}{path}"
        api_node, _ = self.engine.get_or_create_node(
            NodeType.API_ENDPOINT,
            label,
            properties={
                "path": path,
                "method": method,
                "base_url": base_url,
                "auth_required": auth_required,
            },
            source="api_discovery",
        )

        # Link to parent URL/subdomain if available
        parsed = urlparse(base_url)
        parent_domain = parsed.netloc
        for ntype in [NodeType.SUBDOMAIN, NodeType.TARGET]:
            pid = self.engine._label_index.get((ntype, parent_domain))
            if pid:
                self.engine.add_edge(
                    pid, api_node.id, EdgeType.EXPOSES,
                    label="exposes_api",
                    source_engine="api_discovery",
                )
                break

        return api_node

    def add_credential(
        self,
        username: str,
        password: str = "",
        cred_type: str = "basic",
        source_url: str = "",
    ) -> object:
        """Create a Credential node (passwords stored as hashes in properties)."""
        import hashlib
        label = f"{cred_type}:{username}"
        pw_hash = hashlib.sha256(password.encode()).hexdigest() if password else ""
        cred_node, _ = self.engine.get_or_create_node(
            NodeType.CREDENTIAL,
            label,
            properties={
                "username": username,
                "password_hash": pw_hash,
                "cred_type": cred_type,
                "source_url": source_url,
                "has_password": bool(password),
            },
            source="secret_scanner",
            severity="high",
        )
        return cred_node

    def add_vulnerability(
        self,
        vuln_type: str,
        url: str,
        parameter: str = "",
        severity: str = "medium",
        tool: str = "",
        evidence: str = "",
        cvss: float = 0.0,
        payload: str = "",
    ) -> object:
        """Create a Vulnerability node and link it to its URL."""
        label = f"{vuln_type}@{url}"
        if parameter:
            label += f"?{parameter}"

        vuln_node, created = self.engine.get_or_create_node(
            NodeType.VULNERABILITY,
            label,
            properties={
                "vuln_type": vuln_type,
                "url": url,
                "parameter": parameter,
                "tool": tool,
                "evidence": evidence[:500] if evidence else "",
                "cvss": cvss,
                "payload": payload,
            },
            severity=severity,
            exploitable=False,
            source=tool or "scanner",
        )

        # Link to URL node
        url_clean = url.rstrip("/")
        for ntype in [NodeType.URL, NodeType.API_ENDPOINT]:
            uid = self.engine._label_index.get((ntype, url_clean))
            if uid is None:
                uid = self.engine._label_index.get((ntype, url))
            if uid:
                self.engine.add_edge(
                    uid, vuln_node.id, EdgeType.HAS_VULNERABILITY,
                    label=f"has {vuln_type}",
                    source_engine=tool or "scanner",
                )
                break
        else:
            # If no URL node exists, create one on the fly
            parent_domain = urlparse(url).netloc
            url_node = self.add_url(url, parent_domain)
            self.engine.add_edge(
                url_node.id, vuln_node.id, EdgeType.HAS_VULNERABILITY,
                label=f"has {vuln_type}",
                source_engine=tool or "scanner",
            )

        return vuln_node

    def add_exploit(
        self,
        vuln_node_id: str,
        payload: str,
        confirmed: bool = True,
        impact: str = "",
        cvss: float = 0.0,
    ) -> object:
        """Create an Exploit node linked to its Vulnerability node."""
        vuln_node = self.engine.get_node(vuln_node_id)
        base_label = vuln_node.label if vuln_node else vuln_node_id
        label = f"exploit:{base_label}"

        exploit_node, _ = self.engine.get_or_create_node(
            NodeType.EXPLOIT,
            label,
            properties={
                "payload": payload[:1000] if payload else "",
                "confirmed": confirmed,
                "impact": impact,
                "cvss": cvss,
                "vuln_node_id": vuln_node_id,
            },
            exploitable=confirmed,
            source="exploit_engine",
        )

        if vuln_node:
            self.engine.add_edge(
                vuln_node_id, exploit_node.id, EdgeType.ENABLES,
                label="enables exploit",
                source_engine="exploit_engine",
            )
            # Mark the vuln as exploitable
            self.engine.update_node(vuln_node_id, exploitable=confirmed)

        return exploit_node

    def add_impact(
        self,
        impact_type: str,
        description: str,
        affected_assets: list = None,
    ) -> object:
        """Create an Impact node."""
        label = f"impact:{impact_type}"
        impact_node, _ = self.engine.get_or_create_node(
            NodeType.IMPACT,
            label,
            properties={
                "impact_type": impact_type,
                "description": description,
                "affected_assets": affected_assets or [],
            },
            source="impact_analysis",
        )
        return impact_node

    def add_technology(
        self,
        name: str,
        version: str = "",
        target_domain: str = "",
    ) -> object:
        """Create a Technology node and link it to the target domain."""
        label = f"{name}:{version}" if version else name
        tech_node, _ = self.engine.get_or_create_node(
            NodeType.TECHNOLOGY,
            label,
            properties={"name": name, "version": version, "target": target_domain},
            source="tech_detection",
        )

        if target_domain:
            for ntype in [NodeType.SUBDOMAIN, NodeType.TARGET]:
                pid = self.engine._label_index.get((ntype, target_domain))
                if pid:
                    self.engine.add_edge(
                        pid, tech_node.id, EdgeType.EXPOSES,
                        label="uses_technology",
                        source_engine="tech_detection",
                    )
                    break

        return tech_node

    def add_auth_flow(
        self,
        url: str,
        mechanism: str,
        target_domain: str = "",
    ) -> object:
        """Create an AuthFlow node."""
        label = f"auth:{mechanism}@{url}"
        auth_node, _ = self.engine.get_or_create_node(
            NodeType.AUTH_FLOW,
            label,
            properties={"url": url, "mechanism": mechanism, "target_domain": target_domain},
            source="app_intelligence",
        )

        if target_domain:
            for ntype in [NodeType.SUBDOMAIN, NodeType.TARGET]:
                pid = self.engine._label_index.get((ntype, target_domain))
                if pid:
                    self.engine.add_edge(
                        auth_node.id, pid, EdgeType.AUTHENTICATED_BY,
                        label="authenticated_by",
                        source_engine="app_intelligence",
                    )
                    break

        return auth_node

    # ------------------------------------------------------------------
    # Relationship helpers
    # ------------------------------------------------------------------

    def link_vuln_to_impact(
        self,
        vuln_node_id: str,
        impact_node_id: str,
        probability: float = 0.8,
    ):
        """Connect a Vulnerability to an Impact node."""
        self.engine.add_edge(
            vuln_node_id, impact_node_id, EdgeType.LEADS_TO,
            label="leads to impact",
            probability=probability,
            source_engine="risk_analyzer",
        )

    def link_credential_to_auth(self, cred_node_id: str, auth_node_id: str):
        """Connect a Credential to an AuthFlow node."""
        self.engine.add_edge(
            cred_node_id, auth_node_id, EdgeType.AUTHENTICATED_BY,
            label="authenticates via",
            source_engine="exploit_engine",
        )

    def mark_exploited(self, vuln_node_id: str, exploit_node_id: str):
        """Mark a vuln as exploited and link to its exploit node."""
        self.engine.update_node(vuln_node_id, exploitable=True)
        self.engine.add_edge(
            vuln_node_id, exploit_node_id, EdgeType.ENABLES,
            label="exploited_by",
            source_engine="exploit_engine",
        )

    def mark_validated(self, node_id: str, evidence: str = ""):
        """Mark any node as validated (confirmed true positive)."""
        props_update = {}
        node = self.engine.get_node(node_id)
        if node:
            props = dict(node.properties)
            if evidence:
                props["validation_evidence"] = evidence[:500]
            self.engine.update_node(node_id, validated=True, properties=props)

    # ------------------------------------------------------------------
    # Bulk update helpers (called by each engine after its run)
    # ------------------------------------------------------------------

    def update_from_recon_result(self, target: str, recon_data: dict):
        """
        Translate recon JSON into graph nodes.
        Expected recon_data keys: subdomains, urls, technologies, auth_flows
        """
        # Ensure target exists
        self.add_target(target)

        for sub in recon_data.get("subdomains", []):
            if isinstance(sub, dict):
                self.add_subdomain(sub.get("domain", sub.get("host", "")), target, source="recon")
            else:
                self.add_subdomain(str(sub), target, source="recon")

        for url_entry in recon_data.get("urls", []):
            if isinstance(url_entry, dict):
                url = url_entry.get("url", "")
                method = url_entry.get("method", "GET")
                status = url_entry.get("status_code", 200)
            else:
                url, method, status = str(url_entry), "GET", 200
            if url:
                parsed = urlparse(url)
                domain = parsed.netloc or target
                self.add_url(url, domain, method=method, status_code=status)

        for tech in recon_data.get("technologies", []):
            if isinstance(tech, dict):
                self.add_technology(
                    tech.get("name", ""),
                    tech.get("version", ""),
                    target,
                )
            else:
                self.add_technology(str(tech), "", target)

        for af in recon_data.get("auth_flows", []):
            if isinstance(af, dict):
                self.add_auth_flow(
                    af.get("url", ""),
                    af.get("mechanism", "unknown"),
                    target,
                )

        logger.info(
            f"Recon update for {target}: "
            f"{len(recon_data.get('subdomains', []))} subs, "
            f"{len(recon_data.get('urls', []))} urls"
        )

    def update_from_scan_result(self, target: str, findings: list):
        """
        Translate scanner findings (list of dicts) into Vulnerability nodes.
        Expected fields: vuln_type/name, url, parameter, severity, tool, evidence, cvss, payload
        """
        self.add_target(target)
        count = 0
        for f in findings:
            if not isinstance(f, dict):
                continue
            vuln_type = f.get("vuln_type") or f.get("name") or f.get("type", "unknown")
            url = f.get("url") or f.get("endpoint", "")
            if not url:
                continue
            self.add_vulnerability(
                vuln_type=vuln_type,
                url=url,
                parameter=f.get("parameter", ""),
                severity=f.get("severity", "medium"),
                tool=f.get("tool", ""),
                evidence=f.get("evidence", "") or f.get("description", ""),
                cvss=float(f.get("cvss", 0.0)),
                payload=f.get("payload", ""),
            )
            count += 1
        logger.info(f"Scan update for {target}: {count} findings added to graph")

    def update_from_exploit_result(self, exploit_result: dict):
        """
        Translate exploit engine output into Exploit + Impact nodes.
        Expected keys: vuln_node_id, payload, confirmed, impact_type, impact_description, cvss
        """
        vuln_node_id = exploit_result.get("vuln_node_id", "")
        payload = exploit_result.get("payload", "")
        confirmed = exploit_result.get("confirmed", False)
        cvss = float(exploit_result.get("cvss", 0.0))
        impact_type = exploit_result.get("impact_type", "unknown")
        impact_desc = exploit_result.get("impact_description", "")

        if not vuln_node_id:
            # Try to find the vuln node by URL + type
            url = exploit_result.get("url", "")
            vuln_type = exploit_result.get("vuln_type", "unknown")
            if url:
                vuln_node = self.add_vulnerability(
                    vuln_type=vuln_type,
                    url=url,
                    severity=exploit_result.get("severity", "medium"),
                    tool=exploit_result.get("tool", "exploit_engine"),
                    cvss=cvss,
                )
                vuln_node_id = vuln_node.id

        if vuln_node_id:
            exploit_node = self.add_exploit(
                vuln_node_id=vuln_node_id,
                payload=payload,
                confirmed=confirmed,
                impact=impact_type,
                cvss=cvss,
            )
            if impact_type and impact_desc:
                impact_node = self.add_impact(impact_type, impact_desc)
                self.link_vuln_to_impact(vuln_node_id, impact_node.id)

    def update_from_mobile_result(self, app_id: str, mobile_result: dict):
        """
        Translate mobile security engine output into graph nodes.
        mobile_result keys: secrets, vulnerabilities, api_endpoints, technologies
        """
        target_label = f"mobile_app:{app_id}"
        target_node = self.add_target(target_label, program=app_id, platform="mobile")

        for secret in mobile_result.get("secrets", []):
            if isinstance(secret, dict):
                self.add_credential(
                    username=secret.get("key", "unknown"),
                    password=secret.get("value", ""),
                    cred_type=secret.get("secret_type", "api_key"),
                    source_url=secret.get("file", ""),
                )

        for vuln in mobile_result.get("vulnerabilities", []):
            if isinstance(vuln, dict):
                vuln_node = self.add_vulnerability(
                    vuln_type=vuln.get("type", "mobile_vuln"),
                    url=vuln.get("location", target_label),
                    severity=vuln.get("severity", "medium"),
                    tool="mobile_analyzer",
                    evidence=vuln.get("description", ""),
                )

        for ep in mobile_result.get("api_endpoints", []):
            if isinstance(ep, dict):
                self.add_api_endpoint(
                    path=ep.get("path", ""),
                    method=ep.get("method", "GET"),
                    base_url=ep.get("base_url", target_label),
                    auth_required=ep.get("auth_required", False),
                )
            else:
                self.add_api_endpoint(str(ep), "GET", target_label)

        for tech in mobile_result.get("technologies", []):
            if isinstance(tech, dict):
                self.add_technology(tech.get("name", ""), tech.get("version", ""), target_label)
            else:
                self.add_technology(str(tech), "", target_label)

        logger.info(f"Mobile update for app {app_id}: graph populated")

    def update_from_ai_result(self, target: str, ai_findings: list):
        """
        Translate AI security engine findings into Vulnerability nodes.
        Expected fields: finding_type, endpoint, severity, description, payload, confirmed
        """
        self.add_target(target)
        count = 0
        for f in ai_findings:
            if not isinstance(f, dict):
                continue
            vuln_type = f.get("finding_type") or f.get("vuln_type", "ai_vuln")
            url = f.get("endpoint") or f.get("url", target)
            self.add_vulnerability(
                vuln_type=vuln_type,
                url=url,
                severity=f.get("severity", "medium"),
                tool="ai_security_engine",
                evidence=f.get("description", ""),
                payload=f.get("payload", ""),
            )
            count += 1
        logger.info(f"AI security update for {target}: {count} findings")


# ---------------------------------------------------------------------------
# Global singleton
# ---------------------------------------------------------------------------

graph_updater = GraphUpdater()
