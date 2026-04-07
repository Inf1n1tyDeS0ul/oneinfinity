"""
Pattern Miner — mines historical findings to extract actionable scan patterns.

Identifies correlations between technology stacks and vulnerability types,
enabling predictive tool selection for future scans.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from learning.neo4j_knowledge_base import Neo4jKnowledgeBase as KnowledgeBase


@dataclass
class VulnPattern:
    tech_stack: list[str]
    vuln_type: str
    probability: float      # 0.0–1.0  (occurrences / scans_with_this_stack)
    avg_cvss: float
    best_tool: str
    occurrence_count: int


@dataclass
class TargetInsight:
    domain: str
    predicted_vulns: list[VulnPattern]
    suggested_tools: list[str]       # ordered by expected yield
    scan_priority: str               # "fast", "thorough", "targeted"
    notes: list[str] = field(default_factory=list)


class PatternMiner:
    """
    Extracts reusable patterns from KnowledgeBase findings.

    Patterns are both read from the DB (previously mined) and written back
    after each new scan via ``record_findings()``.
    """

    # Tech stack keywords to extract from httpx/whatweb output
    TECH_KEYWORDS = [
        "wordpress", "drupal", "joomla", "laravel", "django", "rails",
        "express", "spring", "tomcat", "nginx", "apache", "iis",
        "php", "java", "python", "ruby", "node",
        "mysql", "postgresql", "mssql", "mongodb", "redis",
        "react", "angular", "vue", "jquery",
        "aws", "azure", "gcp", "cloudflare",
        "graphql", "rest", "soap",
    ]

    # Known high-probability vuln-tech associations (seed data)
    SEED_PATTERNS: list[tuple[list[str], str, str]] = [
        (["wordpress"],         "SQL Injection",      "sqlmap"),
        (["wordpress"],         "XSS",                "dalfox"),
        (["wordpress"],         "Security Misconfiguration", "nuclei"),
        (["drupal"],            "SQL Injection",      "sqlmap"),
        (["drupal"],            "OS Command Injection", "nuclei"),
        (["php"],               "SQL Injection",      "sqlmap"),
        (["php"],               "SSRF",               "nuclei"),
        (["java", "spring"],    "SSRF",               "nuclei"),
        (["java", "tomcat"],    "Security Misconfiguration", "nuclei"),
        (["graphql"],           "IDOR",               "kiterunner"),
        (["aws"],               "SSRF",               "nuclei"),
        (["aws"],               "Secret Exposure",    "trufflehog"),
        (["nginx"],             "CRLF Injection",     "crlfuzz"),
        (["iis"],               "CRLF Injection",     "crlfuzz"),
        (["express", "node"],   "XSS",                "dalfox"),
        (["rails"],             "IDOR",               "kiterunner"),
        (["django"],            "SSRF",               "nuclei"),
    ]

    def __init__(self, kb: "KnowledgeBase"):
        self.kb = kb
        self._seed_patterns()

    def _seed_patterns(self):
        """Insert seed patterns into the KB if they don't exist yet."""
        for tech_stack, vuln_type, tool in self.SEED_PATTERNS:
            try:
                self.kb.upsert_pattern_sync(tech_stack, vuln_type, cvss=5.0, best_tool=tool)
            except Exception:
                pass

    # ── Mining from scan results ──────────────────────────────────────────────

    def record_findings(self, target: str, findings: list[dict],
                        tech_stack: list[str] | None = None,
                        tool_results: dict | None = None):
        """
        After a scan, mine its findings and update the KB patterns.

        Parameters
        ----------
        target      : scanned domain
        findings    : list of confirmed finding dicts
        tech_stack  : detected technologies for the target
        tool_results: {tool_name: {"duration": float, "findings": int, "success": bool}}
        """
        tech = tech_stack or []

        # Record tool performance
        if tool_results:
            for tool_name, perf in tool_results.items():
                self.kb.record_tool_run_sync(
                    tool_name=tool_name,
                    vuln_type=perf.get("vuln_type", ""),
                    target_type=self._classify_target(tech),
                    success=perf.get("success", True),
                    findings_count=perf.get("findings", 0),
                    duration_s=perf.get("duration", 0.0),
                )

        # Upsert tech-vuln patterns
        for f in findings:
            vuln_type = f.get("vuln_type", "")
            cvss = f.get("cvss_score", 0.0) or 0.0
            source = f.get("source_tool", "")
            if vuln_type and tech:
                self.kb.upsert_pattern_sync(tech, vuln_type, cvss=cvss, best_tool=source)

        # Update target profile
        self.kb.upsert_target_profile_sync(target, tech_stack=tech)

    def extract_tech_stack(self, raw_tech_data: str | list | dict) -> list[str]:
        """
        Extract normalised technology keywords from httpx/whatweb output.
        Accepts a string, list of strings, or dict.
        """
        if isinstance(raw_tech_data, dict):
            raw_tech_data = " ".join(str(v) for v in raw_tech_data.values())
        elif isinstance(raw_tech_data, list):
            raw_tech_data = " ".join(str(x) for x in raw_tech_data)
        text = raw_tech_data.lower()
        return [kw for kw in self.TECH_KEYWORDS if kw in text]

    # ── Pattern lookup ────────────────────────────────────────────────────────

    def predict_for_target(self, target: str,
                            tech_stack: list[str] | None = None) -> TargetInsight:
        """
        Predict likely vulnerabilities and suggest tools for a new target.
        """
        profile = self.kb.get_target_profile_sync(target)
        tech = tech_stack or (profile.get("tech_stack") if profile else None) or []

        patterns_raw = self.kb.patterns_for_tech_stack_sync(tech)
        patterns: list[VulnPattern] = []
        for p in patterns_raw:
            prob = min(p["occurrence_count"] / max(1, p["occurrence_count"] + 2), 0.95)
            patterns.append(VulnPattern(
                tech_stack=tech,
                vuln_type=p["vuln_type"],
                probability=prob,
                avg_cvss=p.get("avg_cvss") or 5.0,
                best_tool=p.get("best_tool") or "",
                occurrence_count=p["occurrence_count"],
            ))

        # Sort by probability × avg_cvss
        patterns.sort(key=lambda p: p.probability * p.avg_cvss, reverse=True)

        suggested_tools = self._suggest_tools(patterns, tech)
        priority = self._scan_priority(profile, patterns)
        notes = self._generate_notes(profile, tech, patterns)

        return TargetInsight(
            domain=target,
            predicted_vulns=patterns,
            suggested_tools=suggested_tools,
            scan_priority=priority,
            notes=notes,
        )

    # ── Helpers ───────────────────────────────────────────────────────────────

    @staticmethod
    def _classify_target(tech: list[str]) -> str:
        if any(t in tech for t in ["graphql", "rest", "kiterunner"]):
            return "api"
        if any(t in tech for t in ["aws", "azure", "gcp"]):
            return "cloud"
        return "web"

    @staticmethod
    def _suggest_tools(patterns: list[VulnPattern], tech: list[str]) -> list[str]:
        seen: set[str] = set()
        tools: list[str] = []
        for p in patterns:
            if p.best_tool and p.best_tool not in seen:
                tools.append(p.best_tool)
                seen.add(p.best_tool)
        # Always include broad scanner
        for t in ["nuclei", "dalfox", "sqlmap"]:
            if t not in seen:
                tools.append(t)
                seen.add(t)
        return tools[:8]

    @staticmethod
    def _scan_priority(profile: dict | None, patterns: list[VulnPattern]) -> str:
        if not profile:
            return "thorough"
        if profile.get("scan_count", 0) > 3:
            return "targeted"  # We know this target well
        high_prob = sum(1 for p in patterns if p.probability > 0.5)
        if high_prob >= 3:
            return "fast"   # High-confidence leads — go straight to vulns
        return "thorough"

    @staticmethod
    def _generate_notes(profile: dict | None,
                         tech: list[str],
                         patterns: list[VulnPattern]) -> list[str]:
        notes = []
        if profile and profile.get("scan_count", 0) > 0:
            notes.append(f"Target scanned {profile['scan_count']} time(s) previously")
        if profile and profile.get("waf_detected"):
            notes.append(f"WAF detected: {profile['waf_detected']} — use evasion payloads")
        if "wordpress" in tech:
            notes.append("WordPress target: run WPScan or nuclei:wordpress template set")
        if "aws" in tech:
            notes.append("AWS environment: check for SSRF to IMDS and exposed S3 buckets")
        if patterns:
            top = patterns[0]
            notes.append(
                f"Highest predicted risk: {top.vuln_type} "
                f"(p={top.probability:.0%}, avg CVSS={top.avg_cvss:.1f})"
            )
        return notes
