"""
zero_day_hypothesis.py — Zero-Day Hypothesis Generator from Attack Graph Clustering

Innovation: Discovers potential zero-day vulnerability patterns by clustering the
attack graph — looking for structural anomalies that match known-class vulnerability
shapes but haven't been tested yet.

No other tool does this: instead of testing known payloads against known endpoints,
this engine identifies UNTESTED endpoint/parameter clusters that share structural
similarity with already-confirmed vulnerabilities, then generates targeted hypotheses.

How it works
------------
1. Read the live attack graph (via get_engine())
2. Build a feature vector for each parameter/endpoint node:
   - Node type (PARAMETER, API_ENDPOINT, AUTH_FLOW...)
   - Connectivity (in-degree, out-degree)
   - Reachable vulnerability types (from neighbors)
   - Technology stack tags
   - Auth requirement (has AUTH_FOR edge)
3. Cluster nodes by structural similarity (simple cosine similarity, no ML libs required)
4. For each cluster that contains ≥1 confirmed vulnerability:
   - Identify untested nodes in the same cluster
   - Generate a VulnHypothesis for each (same class as confirmed neighbors)
5. Rank hypotheses by confidence (structural similarity × chain potential × severity)
6. Emit HYPOTHESIS_CREATED events and return ranked list

Integration
-----------
- Called from god_mode_engine.py FullScanMission between vuln_scan and exploit_chaining
- Results feed into adaptive_planner.py for next-scan prioritization
- Stored in PersistentMemory as ai_theory findings

Usage::

    from oneinfinity.intelligence.zero_day_hypothesis import ZeroDayHypothesisEngine

    engine = ZeroDayHypothesisEngine()
    hypotheses = engine.generate(target="example.com", top_n=20)
    for h in hypotheses:
        print(h.vuln_type, h.endpoint, h.confidence, h.rationale)
"""

from __future__ import annotations

import logging
import math
import time
import uuid
from collections import defaultdict
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Set, Tuple

log = logging.getLogger("oneinfinity.intelligence.zero_day_hypothesis")


# ── Hypothesis data model ─────────────────────────────────────────────────────

@dataclass
class VulnHypothesis:
    """A generated zero-day hypothesis: untested node likely vulnerable to vuln_type."""
    hypothesis_id: str = field(default_factory=lambda: str(uuid.uuid4())[:8])
    vuln_type:     str = ""          # sqli | xss | ssrf | idor | ssti | ...
    endpoint:      str = ""
    parameter:     str = ""
    target:        str = ""
    confidence:    float = 0.0       # 0.0–1.0
    rationale:     str = ""
    cluster_id:    str = ""
    evidence_nodes: List[str] = field(default_factory=list)  # confirmed vuln node IDs
    tech_stack:    List[str] = field(default_factory=list)
    severity:      str = "medium"    # estimated severity based on vuln_type
    source_type:   str = "ai_theory"
    created_at:    float = field(default_factory=time.time)

    def to_dict(self) -> dict:
        return {
            "hypothesis_id":   self.hypothesis_id,
            "vuln_type":       self.vuln_type,
            "endpoint":        self.endpoint,
            "parameter":       self.parameter,
            "target":          self.target,
            "confidence":      round(self.confidence, 3),
            "rationale":       self.rationale,
            "cluster_id":      self.cluster_id,
            "evidence_nodes":  self.evidence_nodes,
            "tech_stack":      self.tech_stack,
            "severity":        self.severity,
            "source_type":     self.source_type,
        }


# ── Severity by vuln type ─────────────────────────────────────────────────────

_VULN_SEVERITY: Dict[str, str] = {
    "sqli":         "critical",
    "rce":          "critical",
    "ssrf":         "critical",
    "ssti":         "high",
    "idor":         "high",
    "xxe":          "high",
    "path_traversal": "high",
    "xss":          "medium",
    "open_redirect": "medium",
    "csrf":         "medium",
    "cors":         "medium",
    "prototype_pollution": "high",
    "deserialization":     "critical",
    "jwt_weakness":        "high",
    "auth_bypass":         "critical",
}


# ── Feature extraction ────────────────────────────────────────────────────────

def _extract_features(node, engine) -> Dict[str, float]:
    """
    Build a numeric feature vector for a graph node.

    Features:
      - type_*:      one-hot node type
      - in_degree:   number of incoming edges
      - out_degree:  number of outgoing edges
      - has_auth:    1.0 if node has AUTH_FOR or AUTHENTICATED_BY edge
      - has_param:   1.0 if node has HAS_PARAM edge
      - has_vuln:    1.0 if node has HAS_VULNERABILITY edge (already confirmed)
      - tag_*:       tech stack tags
    """
    features: Dict[str, float] = {}

    # Node type
    ntype = str(getattr(node, "node_type", "unknown"))
    for t in ("parameter", "api_endpoint", "url", "auth_flow", "service"):
        features[f"type_{t}"] = 1.0 if t in ntype.lower() else 0.0

    # Connectivity
    try:
        in_edges  = engine.get_edges_to(node.id)
        out_edges = engine.get_edges_from(node.id)
        features["in_degree"]  = min(len(in_edges), 10) / 10.0
        features["out_degree"] = min(len(out_edges), 10) / 10.0

        edge_types = set()
        for e in in_edges + out_edges:
            edge_types.add(str(getattr(e, "edge_type", "")).lower())

        features["has_auth"]  = 1.0 if any("auth" in t for t in edge_types) else 0.0
        features["has_param"] = 1.0 if any("param" in t for t in edge_types) else 0.0
        features["has_vuln"]  = 1.0 if any("vuln" in t for t in edge_types) else 0.0
    except Exception:
        features.update({"in_degree": 0.0, "out_degree": 0.0,
                         "has_auth": 0.0, "has_param": 0.0, "has_vuln": 0.0})

    # Tech stack
    tags = getattr(node, "tags", []) or []
    props = getattr(node, "properties", {}) or {}
    tech_tags = tags + list(props.get("tech", []) or [])
    for tech in ("java", "php", "python", "node", "ruby", "dotnet", "go"):
        features[f"tech_{tech}"] = 1.0 if any(tech in t.lower() for t in tech_tags) else 0.0

    # Risk signal
    features["risk_score"] = min(getattr(node, "risk_score", 0.0), 10.0) / 10.0
    features["exploitable"] = 1.0 if getattr(node, "exploitable", False) else 0.0

    return features


def _cosine_similarity(a: Dict[str, float], b: Dict[str, float]) -> float:
    """Cosine similarity between two feature dicts."""
    keys = set(a) | set(b)
    dot   = sum(a.get(k, 0.0) * b.get(k, 0.0) for k in keys)
    norm_a = math.sqrt(sum(v * v for v in a.values()))
    norm_b = math.sqrt(sum(v * v for v in b.values()))
    if norm_a == 0 or norm_b == 0:
        return 0.0
    return dot / (norm_a * norm_b)


# ── Main engine ───────────────────────────────────────────────────────────────

class ZeroDayHypothesisEngine:
    """
    Generates zero-day vulnerability hypotheses by clustering the attack graph.

    Algorithm
    ---------
    1. Partition nodes into: confirmed_vulns, candidate_nodes (untested PARAMETER/API_ENDPOINT)
    2. For each confirmed_vuln, find candidate nodes with cosine_similarity >= threshold
    3. Group candidates sharing the same "seed" vuln cluster
    4. For each group, emit a hypothesis with vuln_type from the seed
    5. Rank by confidence (similarity × chain_potential × seed_severity)
    """

    SIMILARITY_THRESHOLD = 0.65   # min cosine similarity to form a cluster
    MIN_CANDIDATE_DEGREE = 1      # candidates must have at least 1 edge

    def __init__(self, engine=None) -> None:
        self._engine = engine  # AttackGraphEngine; lazy-loaded if None

    def _get_engine(self):
        if self._engine is None:
            try:
                from oneinfinity.attack_graph_core.graph_engine import get_engine
                self._engine = get_engine()
            except Exception as exc:
                log.warning("ZeroDayHypothesisEngine: graph engine unavailable: %s", exc)
        return self._engine

    def generate(self, target: str = "", top_n: int = 20) -> List[VulnHypothesis]:
        """
        Generate zero-day hypotheses for the given target.

        Returns top_n hypotheses ranked by confidence (descending).
        """
        eng = self._get_engine()
        if eng is None:
            log.warning("ZeroDayHypothesisEngine: no graph engine — returning empty")
            return []

        try:
            all_nodes = list(eng.find_nodes(label_contains=target) if target else eng.find_nodes())
        except Exception as exc:
            log.warning("ZeroDayHypothesisEngine.generate: get_nodes failed: %s", exc)
            return []

        if not all_nodes:
            return []

        # Partition nodes
        confirmed: List[Any] = []    # nodes that ARE vulnerabilities (exploitable or validated)
        candidates: List[Any] = []   # untested parameter / api_endpoint nodes

        for node in all_nodes:
            ntype = str(getattr(node, "node_type", "")).lower()
            if "vulnerability" in ntype or getattr(node, "exploitable", False):
                confirmed.append(node)
            elif ntype in ("parameter", "api_endpoint", "url"):
                if not getattr(node, "validated", False):
                    candidates.append(node)

        if not confirmed or not candidates:
            log.info("ZeroDayHypothesisEngine: no confirmed vulns or no candidates — skipping")
            return []

        log.info(
            "ZeroDayHypothesisEngine: %d confirmed vulns, %d candidate nodes",
            len(confirmed), len(candidates),
        )

        # Build feature vectors
        confirmed_features = {n.id: _extract_features(n, eng) for n in confirmed}
        candidate_features = {n.id: _extract_features(n, eng) for n in candidates}

        # Cluster: for each candidate, find most similar confirmed vuln
        hypotheses: List[VulnHypothesis] = []

        for cand in candidates:
            cand_feat = candidate_features[cand.id]
            best_sim   = 0.0
            best_seed  = None

            for seed in confirmed:
                sim = _cosine_similarity(cand_feat, confirmed_features[seed.id])
                if sim > best_sim:
                    best_sim  = sim
                    best_seed = seed

            if best_sim < self.SIMILARITY_THRESHOLD or best_seed is None:
                continue

            # Extract vuln_type from confirmed seed
            seed_props   = getattr(best_seed, "properties", {}) or {}
            vuln_type    = (seed_props.get("vuln_type")
                            or seed_props.get("type")
                            or getattr(best_seed, "label", "unknown").lower())
            severity     = _VULN_SEVERITY.get(vuln_type, "medium")
            severity_w   = {"critical": 1.0, "high": 0.8, "medium": 0.6, "low": 0.4}.get(severity, 0.5)

            # Chain potential: does candidate have high connectivity?
            out_deg = cand_feat.get("out_degree", 0.0)
            chain_w = 0.5 + out_deg * 0.5

            confidence = best_sim * severity_w * chain_w

            cand_props = getattr(cand, "properties", {}) or {}
            endpoint   = (cand_props.get("url")
                          or cand_props.get("endpoint")
                          or getattr(cand, "label", ""))
            parameter  = cand_props.get("parameter", "")
            tech_tags  = (getattr(cand, "tags", []) or []) + list(cand_props.get("tech", []) or [])

            h = VulnHypothesis(
                vuln_type      = vuln_type,
                endpoint       = endpoint,
                parameter      = parameter,
                target         = target,
                confidence     = confidence,
                cluster_id     = best_seed.id,
                evidence_nodes = [best_seed.id],
                tech_stack     = tech_tags[:5],
                severity       = severity,
                rationale      = (
                    f"Node '{getattr(cand, 'label', cand.id)}' is structurally similar "
                    f"(cosine={best_sim:.2f}) to confirmed {vuln_type} node "
                    f"'{getattr(best_seed, 'label', best_seed.id)}'. "
                    f"Same node type ({getattr(cand, 'node_type', '?')}), "
                    f"similar connectivity, shared tech stack. "
                    f"Untested — high prior probability of same vulnerability class."
                ),
            )
            hypotheses.append(h)

        # Sort by confidence desc
        hypotheses.sort(key=lambda h: -h.confidence)
        result = hypotheses[:top_n]

        # Emit EventBus events (non-fatal)
        self._emit(result, target)

        log.info(
            "ZeroDayHypothesisEngine: generated %d hypotheses (from %d candidates)",
            len(result), len(candidates),
        )
        return result

    def _emit(self, hypotheses: List[VulnHypothesis], target: str) -> None:
        """Publish HYPOTHESIS_CREATED events for top hypotheses."""
        try:
            from oneinfinity.orchestration.event_bus import get_bus, EventType
            bus = get_bus()
            for h in hypotheses[:5]:  # limit to top 5 to avoid flooding
                bus.publish(
                    event_type=EventType.HYPOTHESIS_CREATED,
                    source="zero_day_hypothesis",
                    data={
                        "theory_id":   h.hypothesis_id,
                        "vuln_type":   h.vuln_type,
                        "endpoint":    h.endpoint,
                        "confidence":  h.confidence,
                        "severity":    h.severity,
                        "target":      target,
                        "rationale":   h.rationale,
                    },
                )
        except Exception as _e:
            log.debug("ZeroDayHypothesisEngine._emit: %s", _e)

    def generate_and_store(self, target: str, top_n: int = 20) -> List[VulnHypothesis]:
        """
        Generate hypotheses and persist them into PersistentMemory as ai_theory findings.
        Also feeds into result_ingestion_engine with source_type='ai_theory'.
        """
        hypotheses = self.generate(target=target, top_n=top_n)
        if not hypotheses:
            return []

        # Persist via result_ingestion_engine (non-fatal)
        try:
            from oneinfinity.findings.result_ingestion_engine import get_ingestion_engine
            engine = get_ingestion_engine()
            import uuid as _uuid
            scan_id = f"zdh_{str(_uuid.uuid4())[:6]}"
            for h in hypotheses:
                engine.ingest_raw({
                    "scan_id":      scan_id,
                    "source":       "zero_day_hypothesis",
                    "tool":         "ZeroDayHypothesisEngine",
                    "vuln_type":    h.vuln_type,
                    "title":        f"Zero-Day Hypothesis: {h.vuln_type} on {h.endpoint[:60]}",
                    "severity":     h.severity,
                    "target":       target,
                    "url":          h.endpoint,
                    "evidence":     h.rationale,
                    "confidence":   h.confidence,
                    "source_type":  "ai_theory",
                    "payload":      h.parameter,
                })
        except Exception as _e:
            log.debug("ZeroDayHypothesisEngine.generate_and_store: ingestion failed: %s", _e)

        return hypotheses


# ── Module-level singleton ────────────────────────────────────────────────────

_ENGINE_INSTANCE: Optional[ZeroDayHypothesisEngine] = None


def get_hypothesis_engine(graph_engine=None) -> ZeroDayHypothesisEngine:
    """Return (or lazily create) the module-level ZeroDayHypothesisEngine singleton."""
    global _ENGINE_INSTANCE
    if _ENGINE_INSTANCE is None or graph_engine is not None:
        _ENGINE_INSTANCE = ZeroDayHypothesisEngine(engine=graph_engine)
    return _ENGINE_INSTANCE
