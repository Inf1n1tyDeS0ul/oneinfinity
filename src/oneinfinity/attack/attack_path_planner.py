"""
Attack Path Planner — Analyze attack graph, find exploit chains, prioritize paths
"""
import json
import logging
from dataclasses import dataclass, field
from typing import Optional
from collections import defaultdict, deque

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Data classes
# ---------------------------------------------------------------------------

@dataclass
class AttackNode:
    node_id: str
    node_type: str          # recon / initial_access / lateral / escalation / exfil / impact
    label: str
    severity: str           # critical / high / medium / low / info
    exploitable: bool = False
    asset_value: int = 5    # 1-10

    def to_dict(self):
        return {
            "node_id":    self.node_id,
            "node_type":  self.node_type,
            "label":      self.label,
            "severity":   self.severity,
            "exploitable":self.exploitable,
            "asset_value":self.asset_value,
        }


@dataclass
class AttackEdge:
    source_id: str
    target_id: str
    edge_type: str          # leads_to / enables / requires / chained_with
    probability: float = 0.5   # 0.0-1.0
    requires_auth: bool = False

    def to_dict(self):
        return {
            "source_id":    self.source_id,
            "target_id":    self.target_id,
            "edge_type":    self.edge_type,
            "probability":  self.probability,
            "requires_auth":self.requires_auth,
        }


@dataclass
class AttackPath:
    path_id: str
    nodes: list = field(default_factory=list)          # list[AttackNode]
    edges: list = field(default_factory=list)          # list[AttackEdge]
    total_score: float = 0.0
    entry_point: Optional[str] = None
    impact_node: Optional[str] = None
    chain_description: str = ""
    exploitability_score: float = 0.0
    impact_score: float = 0.0
    difficulty: str = "medium"   # easy / medium / hard

    def to_dict(self):
        return {
            "path_id":             self.path_id,
            "nodes":               [n.to_dict() for n in self.nodes],
            "edges":               [e.to_dict() for e in self.edges],
            "total_score":         round(self.total_score, 3),
            "entry_point":         self.entry_point,
            "impact_node":         self.impact_node,
            "chain_description":   self.chain_description,
            "exploitability_score":round(self.exploitability_score, 3),
            "impact_score":        round(self.impact_score, 3),
            "difficulty":          self.difficulty,
        }


@dataclass
class AttackChain:
    chain_id: str
    name: str
    steps: list = field(default_factory=list)           # list[str]
    findings_used: list = field(default_factory=list)   # list[str] (finding IDs or titles)
    combined_severity: str = "high"
    estimated_bounty: int = 0
    description: str = ""

    def to_dict(self):
        return {
            "chain_id":          self.chain_id,
            "name":              self.name,
            "steps":             self.steps,
            "findings_used":     self.findings_used,
            "combined_severity": self.combined_severity,
            "estimated_bounty":  self.estimated_bounty,
            "description":       self.description,
        }


# ---------------------------------------------------------------------------
# Pre-defined chain patterns
# ---------------------------------------------------------------------------

_CHAIN_DEFINITIONS = [
    {
        "chain_id": "ssrf_idor_ato",
        "name": "SSRF + IDOR → Account Takeover",
        "requires": {"ssrf", "idor"},
        "combined_severity": "critical",
        "estimated_bounty": 5000,
        "description": (
            "SSRF allows reading internal metadata (cloud credentials, tokens); "
            "IDOR lets the attacker use those credentials to impersonate another user."
        ),
        "steps": [
            "Identify SSRF endpoint that fetches attacker-supplied URL",
            "Probe internal metadata service (169.254.169.254 / IMDSv2) for IAM tokens",
            "Use leaked token to authenticate as privileged user",
            "Leverage IDOR to access or modify target account data",
        ],
    },
    {
        "chain_id": "xss_csrf_session",
        "name": "XSS + CSRF → Session Hijack",
        "requires": {"xss", "csrf"},
        "combined_severity": "critical",
        "estimated_bounty": 4000,
        "description": (
            "Stored or reflected XSS is used to steal CSRF tokens or session cookies, "
            "enabling full account takeover via forged requests."
        ),
        "steps": [
            "Inject persistent XSS payload into user-controlled field",
            "Script steals victim's CSRF token and session cookie via document.cookie / fetch",
            "Send forged CSRF request to change account credentials",
            "Attacker gains authenticated session as victim",
        ],
    },
    {
        "chain_id": "sqli_authbypass_compromise",
        "name": "SQLi + Auth Bypass → Full Compromise",
        "requires": {"sql_injection", "auth_bypass"},
        "combined_severity": "critical",
        "estimated_bounty": 8000,
        "description": (
            "SQL injection in login logic allows bypassing authentication, "
            "leading to full database read/write access and admin takeover."
        ),
        "steps": [
            "Exploit SQL injection in login endpoint to bypass password check",
            "Gain admin session or dump users table for credential cracking",
            "Leverage admin access to read/write all application data",
            "Potential for OS-level compromise via stacked queries / file writes",
        ],
    },
    {
        "chain_id": "lfi_path_rce",
        "name": "LFI + Path Traversal → RCE",
        "requires": {"lfi", "path_traversal"},
        "combined_severity": "critical",
        "estimated_bounty": 7500,
        "description": (
            "Local file inclusion combined with path traversal allows reading sensitive "
            "server files (e.g. /proc/self/environ, logs) and may enable code execution "
            "through log poisoning or PHP filter chains."
        ),
        "steps": [
            "Discover LFI parameter via path traversal (../../../etc/passwd)",
            "Include application logs or /proc/self/environ to confirm RCE vector",
            "Poison log file (User-Agent injection) with PHP/template payload",
            "Execute arbitrary code via log inclusion",
        ],
    },
    {
        "chain_id": "open_redirect_xss_phishing",
        "name": "Open Redirect + XSS → Phishing Chain",
        "requires": {"open_redirect", "xss"},
        "combined_severity": "high",
        "estimated_bounty": 2000,
        "description": (
            "An open redirect on a trusted domain is combined with XSS to craft "
            "convincing phishing URLs that execute malicious scripts in the victim's browser."
        ),
        "steps": [
            "Identify open redirect on trusted domain (/redirect?url=attacker.com)",
            "Craft URL that redirects to attacker page hosting reflected XSS payload",
            "Send phishing link to victim — browser executes in context of trusted origin",
            "Steal cookies, tokens, or perform CSRF actions",
        ],
    },
    {
        "chain_id": "infodisclosure_authbypass_privesc",
        "name": "Info Disclosure + Auth Bypass → Privilege Escalation",
        "requires": {"information_disclosure", "auth_bypass"},
        "combined_severity": "high",
        "estimated_bounty": 3000,
        "description": (
            "Sensitive data exposed (API keys, JWT secret, internal tokens) via an "
            "information disclosure vulnerability is used to forge credentials and "
            "escalate privileges."
        ),
        "steps": [
            "Discover information disclosure (debug endpoint, error message, backup file)",
            "Extract JWT secret or admin token from leaked data",
            "Forge authentication token to bypass auth as privileged user",
            "Access restricted admin functions or sensitive data",
        ],
    },
]

# Severity ordering for comparisons
_SEV_ORDER = {"critical": 4, "high": 3, "medium": 2, "low": 1, "info": 0, "unknown": 0}

# Node type → suggested graph layer (for BFS ordering / visual layout)
_NODE_TYPE_LAYER = {
    "recon":          0,
    "initial_access": 1,
    "lateral":        2,
    "escalation":     3,
    "exfil":          4,
    "impact":         5,
}

# Vuln type → attack node type mapping
_VULN_TO_NODE_TYPE = {
    "xss":                  "initial_access",
    "sql_injection":        "initial_access",
    "ssrf":                 "lateral",
    "idor":                 "lateral",
    "csrf":                 "initial_access",
    "lfi":                  "lateral",
    "rfi":                  "lateral",
    "path_traversal":       "lateral",
    "command_injection":    "impact",
    "rce":                  "impact",
    "auth_bypass":          "escalation",
    "privilege_escalation": "escalation",
    "information_disclosure":"recon",
    "open_redirect":        "initial_access",
    "xxe":                  "lateral",
    "insecure_deserialization": "impact",
    "hardcoded_secret":     "recon",
    "default":              "lateral",
}

# Severity → probability heuristic (higher sev = more likely exploitable)
_SEV_PROB = {"critical": 0.9, "high": 0.75, "medium": 0.5, "low": 0.3, "info": 0.1}

# Severity → asset value
_SEV_ASSET = {"critical": 9, "high": 7, "medium": 5, "low": 3, "info": 1}

# Node color for frontend visualization
_NODE_COLOR = {
    "recon":          "#6366f1",
    "initial_access": "#f59e0b",
    "lateral":        "#ef4444",
    "escalation":     "#ec4899",
    "exfil":          "#8b5cf6",
    "impact":         "#dc2626",
}


# ---------------------------------------------------------------------------
# Planner
# ---------------------------------------------------------------------------

class AttackPathPlanner:
    """Convert vulnerability findings into a scored, prioritised attack graph."""

    # ------------------------------------------------------------------
    # Graph construction
    # ------------------------------------------------------------------

    def build_graph(self, findings: list, recon_data: Optional[dict] = None):
        """
        Convert vulnerability findings (and optional recon data) into
        AttackNode / AttackEdge objects.

        Returns (nodes: list[AttackNode], edges: list[AttackEdge])
        """
        nodes: list  = []
        edges: list  = []
        node_map: dict = {}   # node_id → AttackNode

        # Add a synthetic "Internet / Attacker" entry node
        entry_node = AttackNode(
            node_id="entry_internet",
            node_type="recon",
            label="Internet (Attacker)",
            severity="info",
            exploitable=False,
            asset_value=1,
        )
        nodes.append(entry_node)
        node_map["entry_internet"] = entry_node

        # Add recon results as nodes
        if recon_data:
            for i, subdomain in enumerate(recon_data.get("subdomains", [])[:20]):
                nid = f"recon_subdomain_{i}"
                n = AttackNode(
                    node_id=nid,
                    node_type="recon",
                    label=f"Subdomain: {subdomain}",
                    severity="info",
                    exploitable=False,
                    asset_value=2,
                )
                nodes.append(n)
                node_map[nid] = n
                edges.append(AttackEdge(
                    source_id="entry_internet",
                    target_id=nid,
                    edge_type="leads_to",
                    probability=1.0,
                    requires_auth=False,
                ))

            for i, url in enumerate(recon_data.get("urls", [])[:30]):
                nid = f"recon_url_{i}"
                n = AttackNode(
                    node_id=nid,
                    node_type="recon",
                    label=f"Endpoint: {url[:60]}",
                    severity="info",
                    exploitable=False,
                    asset_value=2,
                )
                nodes.append(n)
                node_map[nid] = n
                edges.append(AttackEdge(
                    source_id="entry_internet",
                    target_id=nid,
                    edge_type="leads_to",
                    probability=1.0,
                    requires_auth=False,
                ))

        # Add each finding as a node
        finding_nodes: list = []
        for idx, finding in enumerate(findings):
            raw_type = (
                finding.get("vuln_type") or finding.get("type") or "unknown"
            ).lower().replace(" ", "_").replace("-", "_")
            severity = finding.get("severity", "medium").lower()
            nid = f"vuln_{idx}_{raw_type}"
            node_type = _VULN_TO_NODE_TYPE.get(raw_type, _VULN_TO_NODE_TYPE["default"])
            n = AttackNode(
                node_id=nid,
                node_type=node_type,
                label=finding.get("title") or finding.get("name") or raw_type.replace("_", " ").title(),
                severity=severity,
                exploitable=severity in ("critical", "high"),
                asset_value=_SEV_ASSET.get(severity, 5),
            )
            nodes.append(n)
            node_map[nid] = n
            finding_nodes.append((idx, raw_type, severity, nid, n))

            # Edge from internet (or closest recon node) to this finding
            src = "entry_internet"
            if recon_data and node_map:
                recon_nodes = [k for k in node_map if k.startswith("recon_")]
                if recon_nodes:
                    src = recon_nodes[0]
            edges.append(AttackEdge(
                source_id=src,
                target_id=nid,
                edge_type="leads_to",
                probability=_SEV_PROB.get(severity, 0.5),
                requires_auth=False,
            ))

        # Add impact nodes based on finding types
        self._add_impact_nodes(finding_nodes, nodes, edges, node_map)

        # Cross-edges: lateral movement between vuln nodes of similar type
        self._add_lateral_edges(finding_nodes, edges)

        return nodes, edges

    def _add_impact_nodes(self, finding_nodes, nodes, edges, node_map):
        """Insert high-value impact nodes and connect exploit chains to them."""
        impact_defs = [
            ("impact_data_exfil", "Data Exfiltration", {"sql_injection", "xxe", "ssrf", "path_traversal", "lfi"}),
            ("impact_rce",        "Remote Code Execution", {"command_injection", "rce", "insecure_deserialization", "lfi"}),
            ("impact_account_takeover", "Account Takeover", {"xss", "csrf", "auth_bypass", "idor"}),
            ("impact_privesc",    "Privilege Escalation", {"privilege_escalation", "auth_bypass", "information_disclosure"}),
        ]
        vuln_types_present = {raw_type for _, raw_type, _, _, _ in finding_nodes}

        for impact_id, impact_label, required_types in impact_defs:
            matching = required_types & vuln_types_present
            if not matching:
                continue
            impact_node = AttackNode(
                node_id=impact_id,
                node_type="impact",
                label=impact_label,
                severity="critical",
                exploitable=True,
                asset_value=10,
            )
            nodes.append(impact_node)
            node_map[impact_id] = impact_node

            for _, raw_type, severity, nid, _ in finding_nodes:
                if raw_type in required_types:
                    edges.append(AttackEdge(
                        source_id=nid,
                        target_id=impact_id,
                        edge_type="leads_to",
                        probability=_SEV_PROB.get(severity, 0.5) * 0.8,
                        requires_auth=False,
                    ))

    def _add_lateral_edges(self, finding_nodes, edges):
        """Add chained_with edges between complementary vulnerability types."""
        chain_pairs = [
            ("ssrf",      "idor"),
            ("xss",       "csrf"),
            ("sql_injection", "auth_bypass"),
            ("lfi",       "path_traversal"),
            ("open_redirect", "xss"),
            ("information_disclosure", "auth_bypass"),
        ]
        type_to_nodes: dict = defaultdict(list)
        for _, raw_type, _, nid, _ in finding_nodes:
            type_to_nodes[raw_type].append(nid)

        for type_a, type_b in chain_pairs:
            for nid_a in type_to_nodes.get(type_a, []):
                for nid_b in type_to_nodes.get(type_b, []):
                    edges.append(AttackEdge(
                        source_id=nid_a,
                        target_id=nid_b,
                        edge_type="chained_with",
                        probability=0.7,
                        requires_auth=False,
                    ))

    # ------------------------------------------------------------------
    # Path finding
    # ------------------------------------------------------------------

    def find_paths(self, nodes: list, edges: list, max_paths: int = 10) -> list:
        """BFS/DFS from entry points to impact nodes, score and return paths."""
        node_dict = {n.node_id: n for n in nodes}
        # Build adjacency: edges keyed by source
        edges_by_source: dict = defaultdict(list)
        edges_by_pair: dict   = {}
        for e in edges:
            edges_by_source[e.source_id].append(e)
            edges_by_pair[(e.source_id, e.target_id)] = e

        entry_points = self._find_entry_points(nodes)
        impact_nodes = self._find_impact_nodes(nodes)

        if not entry_points or not impact_nodes:
            logger.debug("No entry points or impact nodes found for path search")
            return []

        all_paths: list = []
        seen_paths: set = set()

        for entry in entry_points:
            for impact in impact_nodes:
                raw_paths = self._bfs_paths(
                    node_dict,
                    edges_by_source,
                    entry.node_id,
                    {n.node_id for n in impact_nodes},
                    max_depth=8,
                )
                for raw_path in raw_paths:
                    path_key = tuple(raw_path)
                    if path_key in seen_paths:
                        continue
                    seen_paths.add(path_key)

                    path_nodes = [node_dict[nid] for nid in raw_path if nid in node_dict]
                    path_edges = []
                    for i in range(len(raw_path) - 1):
                        e = edges_by_pair.get((raw_path[i], raw_path[i + 1]))
                        if e:
                            path_edges.append(e)

                    path_id = f"path_{len(all_paths):03d}"
                    ap = AttackPath(
                        path_id=path_id,
                        nodes=path_nodes,
                        edges=path_edges,
                        entry_point=raw_path[0] if raw_path else None,
                        impact_node=raw_path[-1] if raw_path else None,
                    )
                    ap = self._score_path_obj(ap)
                    ap.chain_description = self._build_chain_description(path_nodes)
                    all_paths.append(ap)

        return self.prioritize_paths(all_paths)[:max_paths]

    def _bfs_paths(
        self,
        nodes_dict: dict,
        edges_by_source: dict,
        start: str,
        ends: set,
        max_depth: int = 6,
    ) -> list:
        """BFS that collects all simple paths from start to any node in ends."""
        results = []
        # queue: (current_node_id, path_so_far, visited_set)
        queue = deque([(start, [start], {start})])
        while queue:
            current, path, visited = queue.popleft()
            if len(path) > max_depth:
                continue
            if current in ends and len(path) > 1:
                results.append(list(path))
                if len(results) >= 50:   # cap to avoid combinatorial explosion
                    break
                continue
            for edge in edges_by_source.get(current, []):
                neighbor = edge.target_id
                if neighbor in visited:
                    continue
                if neighbor not in nodes_dict:
                    continue
                queue.append((neighbor, path + [neighbor], visited | {neighbor}))
        return results

    # ------------------------------------------------------------------
    # Chain detection
    # ------------------------------------------------------------------

    def detect_chains(self, findings: list) -> list:
        """Match vulnerability findings against pre-defined chain patterns."""
        chains: list = []
        vuln_types_present: dict = defaultdict(list)  # normalised_type → [finding]

        for f in findings:
            raw = (f.get("vuln_type") or f.get("type") or "").lower().replace(" ", "_").replace("-", "_")
            vuln_types_present[raw].append(f)

        for defn in _CHAIN_DEFINITIONS:
            required = defn["requires"]
            # Check if ALL required vuln types are present
            matched_types = required & set(vuln_types_present.keys())
            if matched_types != required:
                continue

            # Collect finding titles/IDs used
            findings_used = []
            for rt in required:
                for f in vuln_types_present[rt][:2]:
                    label = f.get("title") or f.get("name") or rt
                    findings_used.append(label)

            chain = AttackChain(
                chain_id=defn["chain_id"],
                name=defn["name"],
                steps=defn["steps"],
                findings_used=findings_used,
                combined_severity=defn["combined_severity"],
                estimated_bounty=defn["estimated_bounty"],
                description=defn["description"],
            )
            chains.append(chain)

        return chains

    # ------------------------------------------------------------------
    # Path scoring & prioritisation
    # ------------------------------------------------------------------

    def prioritize_paths(self, paths: list) -> list:
        """Sort paths by (exploitability × impact × probability), descending."""
        for p in paths:
            if p.total_score == 0.0:
                p = self._score_path_obj(p)
        return sorted(paths, key=lambda p: p.total_score, reverse=True)

    def _score_path(self, path: "AttackPath") -> float:
        """Compute a numeric score for a path."""
        if not path.nodes or not path.edges:
            return 0.0

        # Base: sum of (asset_value × edge_probability) along the path
        base_score = 0.0
        for i, node in enumerate(path.nodes):
            prob = 1.0
            if i < len(path.edges):
                prob = path.edges[i].probability
            base_score += node.asset_value * prob

        # Chain bonus: reward longer exploit chains
        chain_bonus = 1.0 + 0.15 * max(0, len(path.nodes) - 2)

        # Impact multiplier: critical impact nodes worth more
        impact_mult = 1.0
        if path.nodes:
            last_node = path.nodes[-1]
            impact_mult = _SEV_ASSET.get(last_node.severity, 5) / 5.0

        return base_score * chain_bonus * impact_mult

    def _score_path_obj(self, path: "AttackPath") -> "AttackPath":
        """Compute and set all score fields on a path object."""
        path.total_score = self._score_path(path)

        # Exploitability: fraction of exploitable nodes × average probability
        exploitable_count = sum(1 for n in path.nodes if n.exploitable)
        path.exploitability_score = (
            exploitable_count / len(path.nodes) if path.nodes else 0.0
        )
        avg_prob = (
            sum(e.probability for e in path.edges) / len(path.edges)
            if path.edges else 0.5
        )
        path.exploitability_score *= avg_prob

        # Impact: severity of the terminal node, normalised
        if path.nodes:
            terminal_sev = path.nodes[-1].severity
            path.impact_score = _SEV_ORDER.get(terminal_sev, 0) / 4.0

        # Difficulty: based on chain length and average probability
        if avg_prob >= 0.7 and len(path.nodes) <= 3:
            path.difficulty = "easy"
        elif avg_prob >= 0.4 and len(path.nodes) <= 5:
            path.difficulty = "medium"
        else:
            path.difficulty = "hard"

        return path

    # ------------------------------------------------------------------
    # Helper node finders
    # ------------------------------------------------------------------

    def _find_entry_points(self, nodes: list) -> list:
        """Return nodes accessible without auth (recon type, or low-severity initial_access)."""
        entries = [
            n for n in nodes
            if n.node_type == "recon" or n.node_id == "entry_internet"
        ]
        if not entries:
            entries = [n for n in nodes if n.node_type == "initial_access"]
        return entries

    def _find_impact_nodes(self, nodes: list) -> list:
        """Return high-value impact / escalation nodes."""
        impact = [
            n for n in nodes
            if n.node_type == "impact" or (
                n.node_type == "escalation" and n.severity in ("critical", "high")
            )
        ]
        if not impact:
            # Fall back to most severe nodes
            impact = sorted(nodes, key=lambda n: _SEV_ORDER.get(n.severity, 0), reverse=True)[:3]
        return impact

    # ------------------------------------------------------------------
    # Narrative generation
    # ------------------------------------------------------------------

    def get_attack_narrative(self, path: "AttackPath") -> str:
        """Generate a human-readable attack story for the given path."""
        if not path.nodes:
            return "Empty attack path."

        lines = [
            f"## Attack Narrative — {path.path_id}",
            f"**Difficulty**: {path.difficulty.capitalize()}  |  "
            f"**Score**: {path.total_score:.2f}  |  "
            f"**Exploitability**: {path.exploitability_score:.0%}  |  "
            f"**Impact**: {path.impact_score:.0%}",
            "",
            "### Step-by-step",
        ]

        transition_verbs = {
            "leads_to":     "leads to",
            "enables":      "enables",
            "requires":     "requires",
            "chained_with": "is chained with",
        }

        for i, node in enumerate(path.nodes):
            step_num = i + 1
            indent = "  " * (step_num - 1)
            lines.append(
                f"{indent}{step_num}. **[{node.node_type.upper()}]** {node.label} "
                f"_(severity: {node.severity}, asset value: {node.asset_value}/10)_"
            )
            if i < len(path.edges):
                edge = path.edges[i]
                verb = transition_verbs.get(edge.edge_type, "connects to")
                next_node = path.nodes[i + 1] if i + 1 < len(path.nodes) else None
                if next_node:
                    lines.append(
                        f"{indent}   ↓ *{verb}* (probability: {edge.probability:.0%}"
                        f"{', requires auth' if edge.requires_auth else ''})"
                    )

        lines += [
            "",
            "### Summary",
            path.chain_description or (
                f"Attacker starts from **{path.nodes[0].label}** and, through "
                f"{len(path.nodes) - 1} step(s), reaches **{path.nodes[-1].label}**."
            ),
        ]
        return "\n".join(lines)

    def _build_chain_description(self, nodes: list) -> str:
        if not nodes:
            return ""
        labels = [n.label for n in nodes]
        if len(labels) == 1:
            return labels[0]
        return " → ".join(labels[:6]) + (" → ..." if len(labels) > 6 else "")

    # ------------------------------------------------------------------
    # Frontend visualization export
    # ------------------------------------------------------------------

    def to_graph_dict(self, nodes: list, edges: list) -> dict:
        """
        Return a dict suitable for D3 / vis.js / Cytoscape frontend rendering.
        Assigns x/y positions using a layered layout and color-codes by node_type.
        """
        # Group nodes by layer
        layers: dict = defaultdict(list)
        for n in nodes:
            layer = _NODE_TYPE_LAYER.get(n.node_type, 2)
            layers[layer].append(n)

        # Assign x/y
        x_spacing = 250
        y_spacing = 120
        node_positions: dict = {}
        for layer_idx in sorted(layers.keys()):
            layer_nodes = layers[layer_idx]
            total_height = (len(layer_nodes) - 1) * y_spacing
            for i, n in enumerate(layer_nodes):
                x = layer_idx * x_spacing + 50
                y = i * y_spacing - total_height / 2 + 300
                node_positions[n.node_id] = (x, y)

        viz_nodes = []
        for n in nodes:
            x, y = node_positions.get(n.node_id, (0, 0))
            viz_nodes.append({
                "id":         n.node_id,
                "label":      n.label,
                "type":       n.node_type,
                "severity":   n.severity,
                "exploitable":n.exploitable,
                "asset_value":n.asset_value,
                "x":          round(x, 1),
                "y":          round(y, 1),
                "color":      _NODE_COLOR.get(n.node_type, "#64748b"),
                "size":       max(10, n.asset_value * 3),
            })

        viz_edges = []
        for e in edges:
            viz_edges.append({
                "source":       e.source_id,
                "target":       e.target_id,
                "type":         e.edge_type,
                "probability":  round(e.probability, 2),
                "requires_auth":e.requires_auth,
                "label":        f"{e.edge_type} ({e.probability:.0%})",
                "color":        "#94a3b8" if e.probability < 0.5 else "#ef4444",
                "width":        max(1, int(e.probability * 4)),
            })

        return {
            "nodes": viz_nodes,
            "links": viz_edges,
            "meta": {
                "total_nodes": len(nodes),
                "total_edges": len(edges),
                "entry_nodes":  [n.node_id for n in self._find_entry_points(nodes)],
                "impact_nodes": [n.node_id for n in self._find_impact_nodes(nodes)],
            },
        }


    def plan(self, findings: list, target: str, recon_data: Optional[dict] = None,
             max_paths: int = 10) -> list:
        """
        Convenience: build_graph → find_paths → return ranked AttackPath objects.
        Called by the executor after exploit_chains to score and rank attack paths.
        Returns a list of AttackPath ordered by total_score descending.
        """
        nodes, edges = self.build_graph(findings, recon_data=recon_data)
        return self.find_paths(nodes, edges, max_paths=max_paths)


# ---------------------------------------------------------------------------
# Global singleton
# ---------------------------------------------------------------------------

attack_path_planner = AttackPathPlanner()
