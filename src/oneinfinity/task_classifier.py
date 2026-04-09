"""
task_classifier.py — Task Classification Engine

Classifies incoming tasks into structured TaskClassification objects
that drive model selection in the orchestrator.

Classification dimensions:
  category     — what kind of work (RECON, VULN_ANALYSIS, EXPLOIT_GEN …)
  complexity   — how hard the task is (LOW → CRITICAL)
  importance   — how impactful the result is (BACKGROUND → CRITICAL)
  latency      — how fast we need an answer (REAL_TIME / INTERACTIVE / BATCH)

All classification is rule-based + keyword signals — no model call needed here.
The classifier is deliberately fast (pure Python, < 2ms per call).

Signal sources (in priority order):
  1. Explicit fields in the task dict (task["importance"] = "critical")
  2. Graph context: node_type, priority_score, severity
  3. Keyword matching on task["prompt"] / task["description"]
  4. Category-specific heuristics
"""

from __future__ import annotations

import re
import time
from dataclasses import dataclass, field
from enum import IntEnum
from typing import Any, Dict, List, Optional, Set


# ── Enums ──────────────────────────────────────────────────────────────────────

class TaskCategory(str):
    RECON            = "RECON"
    VULN_ANALYSIS    = "VULN_ANALYSIS"
    EXPLOIT_GEN      = "EXPLOIT_GEN"
    HYPOTHESIS       = "HYPOTHESIS"
    CHAIN_DETECTION  = "CHAIN_DETECTION"
    PAYLOAD_MUTATION = "PAYLOAD_MUTATION"
    CODE_ANALYSIS    = "CODE_ANALYSIS"
    REPORT_WRITING   = "REPORT_WRITING"
    OSINT            = "OSINT"
    BIZ_LOGIC        = "BIZ_LOGIC"
    GENERAL          = "GENERAL"

    ALL = [
        RECON, VULN_ANALYSIS, EXPLOIT_GEN, HYPOTHESIS, CHAIN_DETECTION,
        PAYLOAD_MUTATION, CODE_ANALYSIS, REPORT_WRITING, OSINT, BIZ_LOGIC, GENERAL,
    ]


class ComplexityLevel(IntEnum):
    LOW      = 1  # simple lookup, format conversion
    MEDIUM   = 2  # multi-step reasoning, pattern matching
    HIGH     = 3  # deep analysis, chaining, code synthesis
    CRITICAL = 4  # novel exploit development, complex chain reasoning


class ImportanceLevel(IntEnum):
    BACKGROUND = 1  # informational, can be wrong
    NORMAL     = 2  # standard analysis
    HIGH       = 3  # finding affects report quality
    CRITICAL   = 4  # finding affects critical vulnerability or chain


class LatencyClass(str):
    REAL_TIME   = "REAL_TIME"    # < 1s expected
    INTERACTIVE = "INTERACTIVE"  # < 10s acceptable
    BATCH       = "BATCH"        # no time constraint


# ── Keyword signal tables ──────────────────────────────────────────────────────

# (regex_pattern, category, complexity_boost, importance_boost)
_KEYWORD_SIGNALS: List[tuple] = [
    # Category signals
    (r"\b(subfinder|subdomain|enumerate|dns|asn|crt\.sh|amass)\b",
     TaskCategory.RECON, 0, 0),
    (r"\b(osint|shodan|github dork|wayback|urlscan|dnsdumpster)\b",
     TaskCategory.OSINT, 0, 0),
    (r"\b(vulnerability|vuln|cve|cvss|severity|patch|disclosure)\b",
     TaskCategory.VULN_ANALYSIS, 1, 1),
    (r"\b(exploit|payload|injection|bypass|escalat|privilege)\b",
     TaskCategory.EXPLOIT_GEN, 2, 2),
    (r"\b(hypothesis|theory|attack surface|possible vulnerability|may be vulnerable)\b",
     TaskCategory.HYPOTHESIS, 1, 1),
    (r"\b(chain|pivot|escalate|combine|leverage.*vuln|rce chain|ato chain)\b",
     TaskCategory.CHAIN_DETECTION, 2, 2),
    (r"\b(mutate|variant|obfuscat|encode|bypass waf|evad)\b",
     TaskCategory.PAYLOAD_MUTATION, 1, 0),
    (r"\b(code review|source code|static analysis|taint|sink|decompile)\b",
     TaskCategory.CODE_ANALYSIS, 2, 1),
    (r"\b(report|write up|poc|proof of concept|remediation|markdown)\b",
     TaskCategory.REPORT_WRITING, 0, 0),
    (r"\b(business logic|price|coupon|race condition|workflow|transaction|cart)\b",
     TaskCategory.BIZ_LOGIC, 2, 2),

    # Complexity boosters (no category override)
    (r"\b(rce|remote code execution|code execution|shell)\b",          None, 3, 3),
    (r"\b(ssrf.*cloud|metadata.*169|aws.*iam|gcp.*metadata)\b",        None, 2, 3),
    (r"\b(sql injection|sqli|blind sqli|time.based|error.based)\b",    None, 1, 2),
    (r"\b(xss.*csp|csp bypass|dom.*xss|stored xss)\b",                 None, 2, 2),
    (r"\b(jwt.*none|alg.*none|jwt.*secret|jwt.*brute)\b",              None, 2, 2),
    (r"\b(idor.*admin|idor.*privilege|horizontal.*priv)\b",             None, 2, 2),
    (r"\b(multi.*step|chained|complex.*flow|deep.*analysis)\b",        None, 2, 0),
    (r"\b(0day|zero.day|novel|unknown|undisclosed)\b",                  None, 3, 3),

    # Importance boosters
    (r"\b(critical|p1|p0|bounty|high.value|impactful)\b",              None, 0, 2),
    (r"\b(admin|root|rce|takeover|exfil|data breach)\b",               None, 1, 2),
    (r"\b(background|informational|low.priority|fyi)\b",               None, 0, -2),
]

# Category by node_type (from attack graph integration)
_NODE_TYPE_CATEGORY: Dict[str, str] = {
    "VULNERABILITY":  TaskCategory.VULN_ANALYSIS,
    "EXPLOIT":        TaskCategory.EXPLOIT_GEN,
    "PARAMETER":      TaskCategory.HYPOTHESIS,
    "API_ENDPOINT":   TaskCategory.HYPOTHESIS,
    "AUTH_FLOW":      TaskCategory.BIZ_LOGIC,
    "SUBDOMAIN":      TaskCategory.RECON,
    "TARGET":         TaskCategory.RECON,
    "SERVICE":        TaskCategory.RECON,
    "TECHNOLOGY":     TaskCategory.RECON,
    "CREDENTIAL":     TaskCategory.EXPLOIT_GEN,
}

# Agent-type to category mapping (for fabric task classification)
_AGENT_TYPE_CATEGORY: Dict[str, str] = {
    "recon":          TaskCategory.RECON,
    "xss":            TaskCategory.EXPLOIT_GEN,
    "sqli":           TaskCategory.EXPLOIT_GEN,
    "idor":           TaskCategory.VULN_ANALYSIS,
    "ssrf":           TaskCategory.EXPLOIT_GEN,
    "ssti":           TaskCategory.EXPLOIT_GEN,
    "auth":           TaskCategory.BIZ_LOGIC,
    "biz_logic":      TaskCategory.BIZ_LOGIC,
    "exploit":        TaskCategory.EXPLOIT_GEN,
    "mobile":         TaskCategory.CODE_ANALYSIS,
    "ai_security":    TaskCategory.VULN_ANALYSIS,
    "open_redirect":  TaskCategory.VULN_ANALYSIS,
}


# ── Data model ─────────────────────────────────────────────────────────────────

@dataclass
class TaskClassification:
    category:               str            # TaskCategory value
    complexity:             ComplexityLevel
    importance:             ImportanceLevel
    latency_class:          str            # LatencyClass value
    estimated_tokens:       int            # rough prompt size estimate
    reasoning_depth:        int            # 1-5, how much chain-of-thought needed
    tags:                   List[str]      # matched signal tags
    classifier_confidence:  float          # 0-1, how sure we are about this classification
    raw_text_length:        int = 0
    classified_at:          float = field(default_factory=time.time)

    def to_dict(self) -> dict:
        return {
            "category":              self.category,
            "complexity":            self.complexity.name,
            "importance":            self.importance.name,
            "latency_class":         self.latency_class,
            "estimated_tokens":      self.estimated_tokens,
            "reasoning_depth":       self.reasoning_depth,
            "tags":                  self.tags,
            "classifier_confidence": round(self.classifier_confidence, 3),
        }

    @property
    def tier_hint(self) -> str:
        """Suggest initial model tier without knowing the registry."""
        if self.importance == ImportanceLevel.CRITICAL:
            return "STANDARD"  # never start FAST for CRITICAL
        if self.complexity >= ComplexityLevel.HIGH or self.importance >= ImportanceLevel.HIGH:
            return "STANDARD"
        return "FAST"


# ── Classifier ────────────────────────────────────────────────────────────────

class TaskClassifier:
    """
    Classifies task dicts into structured TaskClassification objects.
    Pure rule-based — fast, deterministic, no external calls.
    """

    def __init__(self) -> None:
        self._compiled = [
            (re.compile(pat, re.IGNORECASE), cat, cb, ib)
            for pat, cat, cb, ib in _KEYWORD_SIGNALS
        ]

    def classify(self, task: Dict[str, Any]) -> TaskClassification:
        """
        Main entry point. task dict may contain:
          prompt / description / text — the actual content to analyze
          agent_type   — e.g. "xss", "sqli" (from fabric)
          node_type    — e.g. "PARAMETER", "AUTH_FLOW" (from graph)
          node_label   — the node's label (URL, param name, etc.)
          severity     — "critical", "high", "medium", "low", "info"
          graph_priority — float 0-20 from brain scoring
          importance   — explicit override: "critical", "high", etc.
          complexity   — explicit override
          latency      — explicit override
          context      — dict of extra metadata
        """
        text = self._extract_text(task)
        tags: List[str] = []

        # ── Step 1: keyword scan ─────────────────────────────────────────────
        category_votes: Dict[str, int] = {}
        complexity_raw = 0
        importance_raw = 0

        for regex, cat, cb, ib in self._compiled:
            if regex.search(text):
                if cat:
                    category_votes[cat] = category_votes.get(cat, 0) + 1
                complexity_raw  += cb
                importance_raw  += ib
                tags.append(regex.pattern[:40])

        # ── Step 2: structural signals ───────────────────────────────────────
        agent_type = task.get("agent_type", "")
        node_type  = task.get("node_type", "")
        severity   = str(task.get("severity", "")).lower()

        # Agent type → category
        if agent_type in _AGENT_TYPE_CATEGORY:
            cat = _AGENT_TYPE_CATEGORY[agent_type]
            category_votes[cat] = category_votes.get(cat, 0) + 2

        # Node type → category
        if node_type in _NODE_TYPE_CATEGORY:
            cat = _NODE_TYPE_CATEGORY[node_type]
            category_votes[cat] = category_votes.get(cat, 0) + 2

        # Severity → importance
        sev_importance = {
            "critical": 3, "high": 2, "medium": 1, "low": 0, "info": -1
        }.get(severity, 0)
        importance_raw += sev_importance

        # Graph priority → complexity + importance
        graph_priority = float(task.get("graph_priority", 0))
        if graph_priority >= 9:
            complexity_raw  += 2
            importance_raw  += 2
        elif graph_priority >= 7:
            complexity_raw  += 1
            importance_raw  += 1

        # Context window estimate
        context = task.get("context", {})
        if isinstance(context, dict):
            context_size = sum(len(str(v)) for v in context.values())
            if context_size > 10000:
                complexity_raw += 1

        # ── Step 3: explicit overrides ───────────────────────────────────────
        if "importance" in task:
            importance_raw = {"critical": 4, "high": 3, "normal": 2,
                              "background": 1}.get(
                str(task["importance"]).lower(), importance_raw)

        if "complexity" in task:
            complexity_raw = {"critical": 4, "high": 3, "medium": 2,
                              "low": 1}.get(
                str(task["complexity"]).lower(), complexity_raw)

        # ── Step 4: derive enums ─────────────────────────────────────────────
        # Complexity
        if complexity_raw >= 4:
            complexity = ComplexityLevel.CRITICAL
        elif complexity_raw >= 2:
            complexity = ComplexityLevel.HIGH
        elif complexity_raw >= 1:
            complexity = ComplexityLevel.MEDIUM
        else:
            complexity = ComplexityLevel.LOW

        # Importance
        if importance_raw >= 4:
            importance = ImportanceLevel.CRITICAL
        elif importance_raw >= 2:
            importance = ImportanceLevel.HIGH
        elif importance_raw >= 1:
            importance = ImportanceLevel.NORMAL
        else:
            importance = ImportanceLevel.BACKGROUND

        # Category
        if category_votes:
            category = max(category_votes, key=category_votes.get)
        else:
            category = TaskCategory.GENERAL

        # Latency
        if "latency" in task:
            latency_class = str(task["latency"]).upper()
        elif complexity >= ComplexityLevel.HIGH:
            latency_class = LatencyClass.BATCH
        elif importance >= ImportanceLevel.HIGH:
            latency_class = LatencyClass.INTERACTIVE
        else:
            latency_class = LatencyClass.INTERACTIVE

        # Reasoning depth (1-5)
        reasoning_depth = min(5, max(1,
            int(complexity) + (1 if importance >= ImportanceLevel.HIGH else 0)
        ))

        # Token estimate
        estimated_tokens = max(100, len(text) // 4)
        if complexity >= ComplexityLevel.HIGH:
            estimated_tokens = int(estimated_tokens * 1.5)

        # Classifier confidence — higher when we have strong signals
        n_votes = sum(category_votes.values())
        classifier_confidence = min(1.0, 0.5 + n_votes * 0.1 + (0.1 if severity else 0))

        return TaskClassification(
            category=category,
            complexity=complexity,
            importance=importance,
            latency_class=latency_class,
            estimated_tokens=estimated_tokens,
            reasoning_depth=reasoning_depth,
            tags=list(set(tags))[:10],
            classifier_confidence=classifier_confidence,
            raw_text_length=len(text),
        )

    def classify_for_brain_action(self, action) -> TaskClassification:
        """Convenience wrapper for BrainAction objects."""
        return self.classify({
            "description":    action.reasoning,
            "agent_type":     action.agent_type,
            "node_type":      action.node_type,
            "graph_priority": action.priority,
        })

    def classify_for_trigger(self, trigger_firing) -> TaskClassification:
        """Convenience wrapper for TriggerFiring objects."""
        return self.classify({
            "description": f"trigger:{trigger_firing.trigger_name} node:{trigger_firing.node_label}",
            "agent_type":  trigger_firing.agents[0] if trigger_firing.agents else "",
            "importance":  "high" if trigger_firing.priority >= 9.0 else "normal",
        })

    def classify_for_daemon_event(self, worker_name: str, event: dict) -> TaskClassification:
        """Convenience wrapper for daemon bus events."""
        event_type = event.get("event_type", "")
        data       = event.get("data", {})
        return self.classify({
            "description": f"daemon:{worker_name} event:{event_type} target:{data.get('target','')}",
            "severity":    data.get("severity", ""),
            "importance":  "critical" if event_type in
                           ("NEW_VULNERABILITY", "CHAIN_DETECTED", "EXPLOIT_ATTEMPTED") else "normal",
        })

    # ── Internal helpers ──────────────────────────────────────────────────────

    @staticmethod
    def _extract_text(task: dict) -> str:
        """Concatenate all textual fields for keyword scanning."""
        parts = []
        for key in ("prompt", "description", "text", "node_label", "context_text",
                    "vuln_type", "agent_type", "node_type", "reasoning"):
            val = task.get(key)
            if val:
                parts.append(str(val))
        # Include context dict values
        ctx = task.get("context", {})
        if isinstance(ctx, dict):
            for v in list(ctx.values())[:5]:
                if isinstance(v, str):
                    parts.append(v[:200])
        return " ".join(parts)


# ── Singleton ──────────────────────────────────────────────────────────────────

_classifier: Optional[TaskClassifier] = None


def get_classifier() -> TaskClassifier:
    global _classifier
    if _classifier is None:
        _classifier = TaskClassifier()
    return _classifier
