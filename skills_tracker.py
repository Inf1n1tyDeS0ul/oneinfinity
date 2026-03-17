"""
skills_tracker.py — Platform Capability & Skills Tracker

Tracks the set of active capabilities, categorizes them into the 7 skill
domains, and rewrites SKILLS.md whenever the registry changes.  The registry
persists to the evolution.db (via MemoryManager.snapshot_capabilities) so the
UI can query growth over time.
"""

from __future__ import annotations

import json
import re
import threading
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional

ROOT = Path(__file__).parent

# 7 canonical categories (must match SKILLS.md headings)
CATEGORIES = [
    "web_security",
    "mobile_security",
    "ai_security",
    "exploit_development",
    "attack_graph_intelligence",
    "swarm_intelligence",
    "reverse_engineering",
]

CATEGORY_LABELS = {
    "web_security":              "Web Security",
    "mobile_security":           "Mobile Security",
    "ai_security":               "AI Security",
    "exploit_development":       "Exploit Development",
    "attack_graph_intelligence": "Attack Graph Intelligence",
    "swarm_intelligence":        "Swarm Intelligence",
    "reverse_engineering":       "Reverse Engineering",
}


@dataclass
class Skill:
    name: str
    category: str
    command: str = ""
    engine: str = ""
    description: str = ""
    tools: list[str] = field(default_factory=list)
    added_at: float = field(default_factory=time.time)
    source_event: str = ""

    def to_dict(self) -> dict:
        return {
            "name": self.name,
            "category": self.category,
            "command": self.command,
            "engine": self.engine,
            "description": self.description,
            "tools": self.tools,
            "added_at": self.added_at,
            "source_event": self.source_event,
        }

    def to_md_row(self) -> str:
        tools_str = ", ".join(self.tools) if self.tools else "—"
        cmd = f"`{self.command}`" if self.command else "—"
        eng = f"`{self.engine}`" if self.engine else "—"
        return f"| {self.name} | {cmd} | {eng} | {self.description} | {tools_str} |"


class SkillsTracker:
    """
    In-memory skill registry backed by SKILLS.md on disk.

    On init, parses any existing SKILLS.md to bootstrap the registry.
    The `register()` method adds/updates skills and optionally rewrites
    SKILLS.md (throttled to at most one rewrite per 5 s to avoid thrashing).
    """

    _HEADER = "| Skill | Command | Engine | Description | Tools |\n|-------|---------|--------|-------------|-------|\n"

    def __init__(self, skills_path: Path | None = None):
        self._path = skills_path or (ROOT / "SKILLS.md")
        self._lock = threading.Lock()
        self._skills: dict[str, Skill] = {}      # name → Skill
        self._last_write: float = 0.0
        self._dirty = False
        self._parse_existing()

    # ── Registry operations ───────────────────────────────────────────────────

    def register(self, skill: Skill, rewrite: bool = True) -> bool:
        """Add or update a skill.  Returns True if this was a genuinely new skill."""
        with self._lock:
            is_new = skill.name not in self._skills
            self._skills[skill.name] = skill
            self._dirty = True
        if rewrite:
            self._maybe_rewrite()
        return is_new

    def register_many(self, skills: list[Skill]):
        with self._lock:
            for s in skills:
                self._skills[s.name] = s
            self._dirty = True
        self._maybe_rewrite()

    def all_skills(self) -> list[dict]:
        with self._lock:
            return [s.to_dict() for s in self._skills.values()]

    def by_category(self, category: str) -> list[Skill]:
        with self._lock:
            return [s for s in self._skills.values() if s.category == category]

    def categories_summary(self) -> dict[str, int]:
        with self._lock:
            summary: dict[str, int] = {c: 0 for c in CATEGORIES}
            for s in self._skills.values():
                if s.category in summary:
                    summary[s.category] += 1
                else:
                    summary[s.category] = 1
            return summary

    def total_count(self) -> int:
        with self._lock:
            return len(self._skills)

    def capability_names(self) -> list[str]:
        with self._lock:
            return sorted(self._skills.keys())

    # ── SKILLS.md I/O ─────────────────────────────────────────────────────────

    def _parse_existing(self):
        """Bootstrap the registry by parsing existing SKILLS.md."""
        if not self._path.exists():
            return
        text = self._path.read_text(encoding="utf-8")
        current_cat = "web_security"
        # Detect category from heading
        cat_re = re.compile(r"^##\s+\d+\.\s+(.*)", re.MULTILINE)
        row_re = re.compile(r"^\|\s*([^|]+)\|\s*([^|]+)\|\s*([^|]+)\|\s*([^|]+)\|")

        cat_label_to_key = {v.lower(): k for k, v in CATEGORY_LABELS.items()}
        for m in re.finditer(r"^##.*$", text, re.MULTILINE):
            heading = m.group(0).lower()
            for label_lower, key in cat_label_to_key.items():
                if label_lower in heading:
                    current_cat = key
                    break

        # Parse table rows  (name | command | engine | tools)
        for line in text.splitlines():
            m = row_re.match(line)
            if m and not line.startswith("| Skill") and not line.startswith("|---"):
                name = m.group(1).strip().strip("`")
                cmd  = m.group(2).strip().strip("`")
                eng  = m.group(3).strip().strip("`")
                if name and name not in ("-", "Skill"):
                    skill = Skill(
                        name=name,
                        category=current_cat,
                        command=cmd if cmd != "—" else "",
                        engine=eng if eng != "—" else "",
                    )
                    self._skills[name] = skill

    def _maybe_rewrite(self):
        now = time.time()
        if now - self._last_write < 5.0:
            return
        self._rewrite()

    def force_rewrite(self):
        """Public: always rewrite now."""
        self._rewrite()

    def _rewrite(self):
        """Atomically rewrite SKILLS.md with current registry."""
        with self._lock:
            if not self._dirty:
                return
            sections: dict[str, list[Skill]] = {c: [] for c in CATEGORIES}
            uncategorized: list[Skill] = []
            for s in sorted(self._skills.values(), key=lambda x: x.name.lower()):
                if s.category in sections:
                    sections[s.category].append(s)
                else:
                    uncategorized.append(s)

            lines = ["# One&Infinity — Skills Reference\n",
                     "A complete reference of all platform capabilities, organized by domain.\n",
                     "_Auto-generated by `skills_tracker.py`. Last updated: "
                     f"{time.strftime('%Y-%m-%d %H:%M UTC', time.gmtime())}._\n\n---\n"]

            idx = 1
            for cat in CATEGORIES:
                label = CATEGORY_LABELS[cat]
                skills = sections[cat]
                lines.append(f"\n## {idx}. {label}\n")
                lines.append("\n" + self._HEADER)
                if skills:
                    for s in skills:
                        lines.append(s.to_md_row() + "\n")
                else:
                    lines.append("| _(none registered yet)_ | — | — | — | — |\n")
                lines.append("\n---\n")
                idx += 1

            if uncategorized:
                lines.append(f"\n## {idx}. Other Capabilities\n")
                lines.append("\n" + self._HEADER)
                for s in uncategorized:
                    lines.append(s.to_md_row() + "\n")
                lines.append("\n---\n")

            # Tool inventory footer (preserved from original)
            lines.append("\n## Tool Inventory\n")
            lines.append("See README.md for the complete tool installation list.\n")

            tmp = self._path.with_suffix(".md.tmp")
            tmp.write_text("".join(lines), encoding="utf-8")
            tmp.replace(self._path)
            self._last_write = time.time()
            self._dirty = False


# ── Skill catalogue loaded from existing SKILLS.md ───────────────────────────

# Pre-defined skill definitions that cover the full platform
BUILTIN_SKILLS: list[Skill] = [
    # ── Web Security ──────────────────────────────────────────────────────────
    Skill("Subdomain enumeration",      "web_security", "oneinfinity scan <target>",       "agents/recon_agent.py",       "subfinder + amass + assetfinder + dnsx", ["subfinder","amass","assetfinder","dnsx"]),
    Skill("HTTP probing",               "web_security", "oneinfinity scan <target>",       "modules/tool_wrappers.py",    "httpx v1.8.1 status + tech fingerprint", ["httpx","naabu","whatweb"]),
    Skill("Technology detection",       "web_security", "oneinfinity adaptive-recon",      "adaptive_recon_engine.py",    "Wappalyzer heuristics + httpx headers", ["httpx"]),
    Skill("JS endpoint extraction",     "web_security", "oneinfinity adaptive-recon",      "adaptive_recon_engine.py",    "katana + regex crawl", ["katana"]),
    Skill("Cloud asset discovery",      "web_security", "oneinfinity adaptive-recon",      "adaptive_recon_engine.py",    "DNS patterns + CIDR matching", []),
    Skill("Web crawling",               "web_security", "oneinfinity scan <target>",       "autonomous_scan_pipeline.py", "katana + hakrawler + waybackurls + gauplus", ["katana","hakrawler","waybackurls","gauplus"]),
    Skill("XSS detection",              "web_security", "oneinfinity scan <target>",       "agents/scan_agent.py",        "dalfox + kxss + XSStrike", ["dalfox","kxss","xssstrike"]),
    Skill("SQL injection",              "web_security", "oneinfinity scan <target>",       "modules/tool_wrappers.py",    "sqlmap + commix", ["sqlmap","commix"]),
    Skill("Template vuln scan",         "web_security", "oneinfinity scan <target>",       "agents/scan_agent.py",        "nuclei v3 175k+ templates", ["nuclei"]),
    Skill("Secret scanning",            "web_security", "oneinfinity scan <target>",       "modules/tool_wrappers.py",    "trufflehog + gitleaks + jwt_tool", ["trufflehog","gitleaks","jwt_tool"]),
    Skill("Directory fuzzing",          "web_security", "oneinfinity scan <target>",       "modules/tool_wrappers.py",    "ffuf + gobuster + dirsearch", ["ffuf","gobuster","dirsearch"]),
    Skill("Parameter discovery",        "web_security", "oneinfinity scan <target>",       "modules/tool_wrappers.py",    "arjun + gf", ["arjun","gf"]),
    Skill("API security testing",       "web_security", "oneinfinity plugins run api_security", "plugins/vuln/api_security.py", "GraphQL + BOLA + mass assign + rate limit", []),
    Skill("Cloud misconfiguration",     "web_security", "oneinfinity plugins run cloud_misconfig", "plugins/vuln/cloud_misconfig.py", "S3 + Elasticsearch + K8s", []),
    Skill("OSINT collection",           "web_security", "oneinfinity attack-graph",        "osint_collector.py",          "HackerTarget + Shodan + URLScan + GitHub dorks", []),
    # ── Mobile Security ───────────────────────────────────────────────────────
    Skill("APK static analysis",        "mobile_security", "oneinfinity mobile-analyze",   "mobile_static_analysis.py",   "APKTool + JADX + MobSF — 24 dangerous permissions", ["apktool","jadx","mobsf"]),
    Skill("AI-driven reverse engineering","mobile_security","oneinfinity mobile-analyze",  "mobile_ai_reverse_engineer.py","Claude/GPT + 14 rule patterns", []),
    Skill("Frida script generation",    "mobile_security", "oneinfinity mobile-analyze",   "frida_script_generator.py",   "Auto-generate Frida JS: SSL/root/auth/crypto hooks", ["frida"]),
    Skill("Runtime analysis",           "mobile_security", "oneinfinity mobile-analyze",   "mobile_dynamic_analysis.py",  "Frida + Objection + RMS", ["frida","objection"]),
    Skill("Mobile secret detection",    "mobile_security", "oneinfinity mobile-secrets",   "mobile_secret_detection.py",  "Binary DEX string scan + assets/gradle patterns", []),
    Skill("Android component testing",  "mobile_security", "oneinfinity mobile-analyze",   "android_component_testing.py","Exported components via Drozer", ["drozer"]),
    Skill("Mobile network analysis",    "mobile_security", "oneinfinity mobile-analyze",   "mobile_network_analysis.py",  "Burp proxy + token-in-URL + WS detection", ["burp"]),
    Skill("Mobile API attack",          "mobile_security", "oneinfinity mobile-analyze",   "mobile_api_attack_engine.py", "IDOR + auth bypass + mass assign + rate limit", []),
    # ── AI Security ───────────────────────────────────────────────────────────
    Skill("AI vulnerability scanning",  "ai_security", "oneinfinity ai-test --all",        "ai_security_engine.py",       "Garak + PyRIT automated scanners", ["garak","pyrit"]),
    Skill("Prompt injection testing",   "ai_security", "oneinfinity ai-test",              "ai_security_engine.py",       "Prompt injection + jailbreak detection", []),
    Skill("AI Red Team campaign",       "ai_security", "oneinfinity ai-redteam",           "ai_red_team_engine.py",       "Jailbreak / RAG / tool abuse / model extraction", []),
    Skill("RAG poisoning",              "ai_security", "oneinfinity ai-redteam --campaign rag_attack", "ai_red_team_engine.py", "RAG corpus poisoning attacks", []),
    Skill("Model extraction",           "ai_security", "oneinfinity ai-redteam",           "ai_red_team_engine.py",       "API-based model extraction probing", []),
    # ── Exploit Development ───────────────────────────────────────────────────
    Skill("Exploit payload generator",  "exploit_development", "oneinfinity exploit",      "exploit_generator.py",        "130+ payloads for 12 vuln types", []),
    Skill("Finding validation",         "exploit_development", "oneinfinity exploit",      "finding_validation_engine.py","Canary XSS + time-based blind SQLi confirmation", []),
    Skill("Autonomous exploit engine",  "exploit_development", "oneinfinity exploit",      "autonomous_exploit_engine.py","Severity-sorted exploitation + CVSS scoring", []),
    Skill("Attack path planning",       "exploit_development", "oneinfinity exploit",      "attack_path_planner.py",      "BFS chain planning (SSRF+IDOR, XSS+CSRF, SQLi+RCE)", []),
    Skill("Browser attack engine",      "exploit_development", "oneinfinity exploit",      "browser_attack_engine.py",    "Playwright/Selenium XSS + login bypass + form testing", ["playwright"]),
    Skill("Autonomous scan pipeline",   "exploit_development", "oneinfinity scan",         "autonomous_scan_pipeline.py", "7-phase discover→recon→crawl→scan→exploit→validate→report", []),
    # ── Attack Graph Intelligence ─────────────────────────────────────────────
    Skill("Attack graph construction",  "attack_graph_intelligence", "oneinfinity attack-graph", "attack_graph_core/graph_engine.py", "Real-time node/edge graph of all discovered assets+vulns", []),
    Skill("BFS attack path enumeration","attack_graph_intelligence", "oneinfinity attack-graph", "attack_graph_core/graph_query_engine.py", "BFS from target root to exploit nodes", []),
    Skill("Exploit chain detection",    "attack_graph_intelligence", "oneinfinity attack-graph", "attack_graph_core/exploit_chain_engine.py", "12 multi-step chain patterns", []),
    Skill("Risk scoring",               "attack_graph_intelligence", "oneinfinity attack-graph", "attack_graph_core/risk_analyzer.py", "CVSS + exploitability + chain bonus × impact", []),
    Skill("Target discovery",           "attack_graph_intelligence", "oneinfinity attack-graph", "target_discovery_engine.py", "crt.sh + ASN + DNS + GitHub + Shodan", []),
    Skill("Attack planner",             "attack_graph_intelligence", "oneinfinity attack-graph", "attack_graph_core/attack_planner.py", "Prioritized AttackAction list from graph state", []),
    # ── Swarm Intelligence ────────────────────────────────────────────────────
    Skill("Multi-agent parallel scan",  "swarm_intelligence", "oneinfinity swarm-scan",    "swarm_intelligence_engine.py","8 specialized agents — XSS/SQLi/SSRF/IDOR/Auth/BizLogic/Mobile/API", []),
    Skill("Agent competition & collaboration","swarm_intelligence","oneinfinity swarm-scan","agent_swarm_coordinator.py",  "Event bus: SQLi→IDOR, SSRF→IDOR, XSS→Auth triggers", []),
    Skill("Monte Carlo attack simulation","swarm_intelligence","oneinfinity simulate-attacks","attack_simulation_engine.py","N=200 Bernoulli trials, 23-path catalog, 6 factors", []),
    Skill("Business logic simulation",  "swarm_intelligence", "oneinfinity simulate-workflow","workflow_simulation_engine.py","4 workflow factories, 9 attack categories", []),
    Skill("EMA pattern learning",       "swarm_intelligence", "(automatic)",               "swarm_intelligence_engine.py","α=0.30 EMA per-agent success rates across sessions", []),
    Skill("Swarm exploit chain detection","swarm_intelligence","(automatic)",              "agent_swarm_coordinator.py",  "Cross-references 10 multi-step chain patterns", []),
    # ── Reverse Engineering ───────────────────────────────────────────────────
    Skill("Static source analysis",     "reverse_engineering", "oneinfinity scan",         "source_analysis_engine.py",   "Python/JS/Java/Go: route extraction + taint tracking (AST)", []),
    Skill("HTML form/link crawling",    "reverse_engineering", "oneinfinity scan",         "application_crawler.py",      "HTML forms, links, API call detection (fetch/axios/XHR)", []),
    Skill("AppModel builder",           "reverse_engineering", "oneinfinity analyze-app",  "application_intelligence.py", "Auth flows, API structure, roles, sensitive endpoints", []),
    Skill("Vulnerability theory engine","reverse_engineering", "oneinfinity generate-theories","vulnerability_theory_engine.py","23 rule-based vuln theories from AppModel", []),
    Skill("Zero-day anomaly detection", "reverse_engineering", "oneinfinity zero-day",     "zero_day_engine.py",          "Status changes + leakage + timing + reflection detection", []),
    Skill("Custom attack test designer","reverse_engineering", "oneinfinity run-custom-tests","custom_test_engine.py",    "Attack test designer + executor (http/dalfox/sqlmap)", []),
    Skill("CI/CD pipeline generation",  "reverse_engineering", "(utility)",                "cicd_integration_engine.py",  "GitHub Actions + GitLab CI + Jenkinsfile generators", []),
    # ── Self-Evolving Architecture (new) ──────────────────────────────────────
    Skill("Self-evolving architecture", "attack_graph_intelligence", "oneinfinity arch-status", "auto_architecture_engine.py", "Event-driven doc + memory auto-update on system activity", []),
    Skill("Architecture auto-updater",  "attack_graph_intelligence", "(automatic)",         "architecture_updater.py",     "Rewrites ARCHITECTURE.md on feature_added / component events", []),
    Skill("Skills auto-tracker",        "attack_graph_intelligence", "(automatic)",         "skills_tracker.py",           "Rewrites SKILLS.md when capabilities change", []),
    Skill("README auto-generator",      "attack_graph_intelligence", "(automatic)",         "readme_generator.py",         "Rewrites README.md on feature_added events", []),
    Skill("Evolution memory store",     "attack_graph_intelligence", "oneinfinity arch-status", "memory_manager.py",      "SQLite evolution.db: patterns, chains, insights, snapshots", []),
]


# ── Singleton ─────────────────────────────────────────────────────────────────

_instance: SkillsTracker | None = None
_instance_lock = threading.Lock()


def get_skills_tracker() -> SkillsTracker:
    global _instance
    if _instance is None:
        with _instance_lock:
            if _instance is None:
                _instance = SkillsTracker()
                # Bootstrap with builtin skills (don't overwrite existing entries
                # that may have been parsed from the file)
                for s in BUILTIN_SKILLS:
                    if s.name not in _instance._skills:
                        _instance._skills[s.name] = s
                _instance._dirty = True
    return _instance
