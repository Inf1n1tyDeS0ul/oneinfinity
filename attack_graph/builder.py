"""
Attack Graph Builder
======================
Populates an AttackGraph from:
  - existing findings.db / ExtendedDB
  - workflow state JSON files (recon output)
  - live tool results (ToolRegistry)
  - manual input dicts
"""

from __future__ import annotations

import json
import os
from pathlib import Path
from typing import Optional

from attack_graph.graph import AttackGraph, Node, Edge, NodeType, EdgeType


class AttackGraphBuilder:
    """Builds and incrementally updates an AttackGraph."""

    def __init__(self, target: str, graph: Optional[AttackGraph] = None):
        self.target = target
        self.g = graph or AttackGraph(target)

    # ── From recon output directory ───────────────────────────────────────────

    def from_recon_dir(self, recon_dir: str) -> "AttackGraphBuilder":
        """
        Load all JSON files produced by the workflow/pipeline into the graph.
        Expects: subdomains.json, alive_hosts.json, ports.json,
                 endpoints.json, findings.json, secrets.json
        """
        d = Path(recon_dir)

        # Subdomains
        subs_file = d / "subdomains.json"
        if subs_file.exists():
            subs = json.loads(subs_file.read_text())
            if isinstance(subs, dict):
                subs = subs.get("subdomains", [])
            for sub in subs:
                self.g.add_subdomain(str(sub))

        # Alive hosts
        hosts_file = d / "alive_hosts.json"
        if hosts_file.exists():
            hosts = json.loads(hosts_file.read_text())
            if isinstance(hosts, dict):
                hosts = hosts.get("hosts", [])
            for h in hosts:
                if not isinstance(h, dict):
                    continue
                url  = h.get("url", "")
                host = h.get("host", url.split("//")[-1].split("/")[0] if "//" in url else url)
                node = self.g.add_host(
                    url=url or f"https://{host}",
                    status=h.get("status-code", h.get("status", 200)),
                    tech=h.get("tech", []),
                    title=h.get("title", ""),
                )
                # Connect subdomain → host
                sub_nid = f"subdomain:{host}"
                if sub_nid in self.g._nodes:
                    self.g.add_edge(Edge(
                        edge_id=f"e:{sub_nid}→{node.node_id}",
                        src=sub_nid, dst=node.node_id,
                        edge_type=EdgeType.RESOLVES_TO,
                        label="http",
                    ))

        # Open ports
        ports_file = d / "ports.json"
        if ports_file.exists():
            ports = json.loads(ports_file.read_text())
            if isinstance(ports, list):
                for p in ports:
                    host = p.get("host", self.target)
                    port = p.get("port", 0)
                    svc = p.get("service", str(port))
                    ver = p.get("version", "")
                    self.g.add_service(host, port, svc, ver)

        # Endpoints (URLs with params)
        ep_file = d / "endpoints.json"
        if ep_file.exists():
            eps = json.loads(ep_file.read_text())
            if isinstance(eps, list):
                for ep in eps[:500]:   # cap to avoid huge graphs
                    if isinstance(ep, str) and ep:
                        node = self.g.add_endpoint(ep)
                        # Connect to closest host
                        if "://" in ep:
                            host_part = ep.split("://")[1].split("/")[0]
                            host_nid = f"host:https://{host_part}"
                            if host_nid in self.g._nodes:
                                self.g.add_edge(Edge(
                                    edge_id=f"e:{host_nid}→{node.node_id}",
                                    src=host_nid, dst=node.node_id,
                                    edge_type=EdgeType.HAS_ENDPOINT,
                                    label="endpoint",
                                ))

        # Findings / vulnerabilities
        findings_file = d / "findings.json"
        if findings_file.exists():
            findings = json.loads(findings_file.read_text())
            if isinstance(findings, dict):
                findings = findings.get("findings", [])
            for i, f in enumerate(findings):
                if not isinstance(f, dict):
                    continue
                self._add_finding(f, vuln_idx=i)

        # Secrets
        secrets_file = d / "secrets.json"
        if secrets_file.exists():
            secrets = json.loads(secrets_file.read_text())
            if isinstance(secrets, list):
                for i, s in enumerate(secrets):
                    if not isinstance(s, dict):
                        continue
                    detector = s.get("detector", s.get("rule", "secret"))
                    source = s.get("source", {})
                    source_node = f"target:{self.target}"
                    self.g.add_credential(
                        cred_id=f"secret:{i}",
                        cred_type=detector,
                        value_hint=s.get("raw", "")[:30],
                        source_node=source_node,
                    )

        return self

    def _add_finding(self, f: dict, vuln_idx: int = 0):
        vuln_type = f.get("vuln_type", f.get("type", f.get("name", "unknown")))
        host = f.get("host", f.get("matched_at", ""))
        endpoint = f.get("matched_at", f.get("endpoint", f.get("url", host)))
        severity = f.get("severity", "info")
        evidence = f.get("evidence", f.get("description", ""))
        param = f.get("parameter", "")
        confidence = f.get("confidence", "medium")
        finding_id = f.get("id", f.get("finding_db_id"))

        # Normalise host
        if "://" in host:
            host = host.split("://")[1].split("/")[0].split(":")[0]

        vuln_id = f"{vuln_type.replace(' ', '_')}_{host}_{vuln_idx}"
        self.g.add_vulnerability(
            vuln_id=vuln_id,
            vuln_type=vuln_type,
            host=host,
            endpoint=endpoint,
            severity=self._normalise_severity(severity),
            evidence=str(evidence),
            parameter=str(param),
            confidence=str(confidence),
            finding_db_id=finding_id,
        )

    @staticmethod
    def _normalise_severity(sev: str) -> str:
        s = str(sev).lower()
        if s in ("critical", "high", "medium", "low", "info"):
            return s
        mapping = {"crit": "critical", "informational": "info", "warn": "low"}
        return mapping.get(s, "info")

    # ── From ExtendedDB ───────────────────────────────────────────────────────

    def from_db(self, db_path: str, session_id: Optional[int] = None
                ) -> "AttackGraphBuilder":
        """Load findings and assets from the existing findings.db."""
        try:
            from oneinfinity_framework.db_ext import ExtendedDB
            db = ExtendedDB(db_path)

            # Load subdomains and hosts from recon_assets
            q = "SELECT * FROM recon_assets WHERE is_in_scope=1"
            params = []
            if session_id:
                q += " AND session_id=?"
                params.append(session_id)
            for row in db.conn.execute(q, params).fetchall():
                row = dict(row)
                atype = row.get("asset_type", "")
                val = row.get("value", "")
                if atype == "subdomain":
                    self.g.add_subdomain(val)
                elif atype == "url":
                    tech = []
                    if row.get("tech_stack"):
                        try:
                            tech = json.loads(row["tech_stack"])
                        except Exception:
                            tech = [row["tech_stack"]]
                    self.g.add_host(val, status=row.get("status_code", 0), tech=tech)

            # Load vuln candidates
            q2 = "SELECT * FROM vuln_candidates WHERE confidence IN ('high','medium')"
            p2 = []
            if session_id:
                q2 += " AND session_id=?"
                p2.append(session_id)
            for i, row in enumerate(db.conn.execute(q2, p2).fetchall()):
                row = dict(row)
                self._add_finding({
                    "vuln_type": row.get("vuln_type", "unknown"),
                    "host": row.get("host", ""),
                    "endpoint": row.get("endpoint", ""),
                    "severity": "high" if row.get("confidence") == "high" else "medium",
                    "evidence": row.get("evidence", ""),
                    "parameter": row.get("parameter", ""),
                    "confidence": row.get("confidence", "medium"),
                    "finding_db_id": row.get("finding_id"),
                }, vuln_idx=i)

            # Load confirmed findings
            for i, row in enumerate(db.conn.execute(
                "SELECT * FROM findings WHERE status NOT IN ('false_positive','duplicate')"
            ).fetchall()):
                row = dict(row)
                ep = row.get("endpoint", "")
                host = ep.split("://")[1].split("/")[0] if "://" in ep else ep
                self.g.add_vulnerability(
                    vuln_id=f"finding_{row['id']}",
                    vuln_type=row.get("vuln_type", "unknown"),
                    host=host,
                    endpoint=ep,
                    severity=row.get("severity", "info"),
                    evidence=row.get("description", "")[:200],
                    finding_db_id=row["id"],
                )

            db.close()
        except Exception as exc:
            import warnings
            warnings.warn(f"AttackGraphBuilder.from_db: {exc}")
        return self

    # ── From ResultIngestionEngine findings.db ────────────────────────────────

    def from_findings_db(self, db_path: str = "") -> "AttackGraphBuilder":
        """Load findings from PostgreSQL into the graph."""
        try:
            from core.db_manager import get_db_manager_sync
            mgr = get_db_manager_sync()
            if mgr is None or mgr.mode not in ("distributed", "postgres"):
                raise RuntimeError("PostgreSQL is required")
            rows = mgr.sync_pg_execute_read(
                "SELECT * FROM findings WHERE status NOT IN ('false_positive') "
                "ORDER BY created_at DESC"
            )
            for i, row in enumerate(rows):
                r = dict(row)
                self._add_finding({
                    "vuln_type":    r.get("vuln_type", "unknown"),
                    "host":         r.get("url") or r.get("target", ""),
                    "matched_at":   r.get("url", ""),
                    "severity":     r.get("severity", "info"),
                    "evidence":     r.get("evidence", ""),
                    "parameter":    "",
                    "confidence":   str(r.get("confidence", "medium")),
                    "finding_db_id": r.get("finding_id"),
                    "name":         r.get("title", ""),
                }, vuln_idx=i)
        except Exception as exc:
            import warnings
            warnings.warn(f"AttackGraphBuilder.from_findings_db: {exc}")
        return self

    # ── From live tool results ────────────────────────────────────────────────

    def from_tool_result(self, tool_name: str, result_data: dict
                         ) -> "AttackGraphBuilder":
        """Ingest a ToolResult.data dict directly."""
        if not isinstance(result_data, dict):
            return self

        if tool_name in ("subfinder", "amass", "assetfinder", "findomain"):
            for sub in result_data.get("subdomains", []):
                self.g.add_subdomain(sub)

        elif tool_name == "httpx":
            for h in result_data.get("hosts", []):
                url = h.get("url", "")
                host = h.get("host", url.split("//")[-1].split("/")[0])
                self.g.add_host(url, h.get("status-code", 0), h.get("tech", []))

        elif tool_name in ("naabu", "nmap", "masscan", "rustscan"):
            for p in result_data.get("open_ports", []):
                host = p.get("host", self.target)
                self.g.add_service(host, p.get("port", 0),
                                   p.get("service", str(p.get("port", ""))),
                                   p.get("version", ""))

        elif tool_name == "nuclei":
            for i, f in enumerate(result_data.get("findings", [])):
                self._add_finding(f, vuln_idx=i)

        elif tool_name in ("dalfox", "sqlmap", "crlfuzz", "commix", "xssstrike"):
            for i, f in enumerate(result_data.get("findings", [])):
                self._add_finding(f, vuln_idx=i)

        elif tool_name in ("trufflehog", "gitleaks"):
            for i, s in enumerate(result_data.get("secrets", [])):
                self.g.add_credential(
                    cred_id=f"{tool_name}_{i}",
                    cred_type=s.get("detector", s.get("rule", "secret")),
                    value_hint=s.get("raw", "")[:30],
                    source_node=f"target:{self.target}",
                )

        elif tool_name in ("katana", "hakrawler", "gauplus", "waybackurls"):
            for url in result_data.get("urls", [])[:500]:
                if "?" in url:
                    self.g.add_endpoint(url)

        elif tool_name in ("s3scanner", "cloudbrute"):
            for bucket in result_data.get("buckets", result_data.get("found", [])):
                nid = f"cloud:{bucket}"
                self.g.add_node(Node(
                    node_id=nid,
                    node_type=NodeType.CLOUD_ASSET,
                    label=str(bucket),
                    severity="high",
                    exploitable=True,
                ))

        return self

    # ── Add exploit chain edges ───────────────────────────────────────────────

    def add_chain_edge(self, src_vuln_id: str, dst_vuln_id: str,
                       label: str = "", confidence: str = "medium"):
        """Connect two vuln nodes to represent an exploit chain."""
        src_nid = f"vuln:{src_vuln_id}"
        dst_nid = f"vuln:{dst_vuln_id}"
        if src_nid in self.g._nodes and dst_nid in self.g._nodes:
            self.g.add_edge(Edge(
                edge_id=f"chain:{src_nid}→{dst_nid}",
                src=src_nid, dst=dst_nid,
                edge_type=EdgeType.ENABLES,
                label=label or "chain",
                weight=0.5,   # chains are high-value paths
                confidence=confidence,
            ))

    def build(self) -> AttackGraph:
        return self.g
