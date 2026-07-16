"""
readme_generator.py — README.md Auto-Generator

Maintains a structured internal model of the platform's README.  Any engine
can call add_feature(), add_cli_command(), or update_architecture_tree() and
the README will be regenerated automatically (throttled to 10-second bursts).
"""

from __future__ import annotations

import re
import threading
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional

ROOT = Path(__file__).parent
README_PATH = ROOT / "README.md"


# ── Data models ───────────────────────────────────────────────────────────────

@dataclass
class FeatureEntry:
    title: str
    description: str
    category: str = "General"
    sub_items: list[str] = field(default_factory=list)
    added_at: float = field(default_factory=time.time)

    def to_md(self) -> str:
        lines = [f"- **{self.title}** — {self.description}"]
        for item in self.sub_items:
            lines.append(f"  - {item}")
        return "\n".join(lines)


@dataclass
class CLICommand:
    command: str
    description: str
    category: str = "General"
    example: str = ""

    def to_md(self) -> str:
        line = f"oneinfinity {self.command}"
        if len(line) < 52:
            line = line.ljust(52)
        return f"{line} # {self.description}"


@dataclass
class UIPage:
    label: str
    route: str
    description: str

    def to_md_row(self) -> str:
        return f"| **{self.label}** | `{self.route}` | {self.description} |"


# ── Generator ─────────────────────────────────────────────────────────────────

class ReadmeGenerator:
    """
    Maintains structured sections of README.md and rewrites the file when
    any section changes.  Parsing on init bootstraps from existing README.

    Sections managed:
      - Features  (grouped by category)
      - CLI       (grouped by category)
      - Web UI pages
      - Architecture tree
      - Data directory note
      - Tool requirements
    """

    def __init__(self, readme_path: Path = README_PATH):
        self._path = readme_path
        self._lock = threading.Lock()
        self._last_write: float = 0.0
        self._dirty: bool = False

        # Feature registry: category → list[FeatureEntry]
        self._features: dict[str, list[FeatureEntry]] = {}
        # CLI registry: category → list[CLICommand]
        self._cli: dict[str, list[CLICommand]] = {}
        # UI pages
        self._pages: list[UIPage] = []
        # Architecture tree lines
        self._arch_lines: list[str] = []
        # Freeform extras appended at bottom (tool requirements, data dir, etc.)
        self._extras: dict[str, str] = {}

        self._bootstrap_defaults()
        self._parse_existing()

    # ── Bootstrap ─────────────────────────────────────────────────────────────

    def _bootstrap_defaults(self):
        """Populate with the platform's known features/commands."""
        categories_order = [
            "Web Security", "Mobile Security", "AI Security",
            "Swarm Intelligence", "Attack Graph Intelligence",
            "Autonomous Bug Bounty Hunter", "Exploit Development",
            "Self-Evolving Architecture",
        ]
        features = {
            "Web Security": [
                FeatureEntry("Reconnaissance", "Subdomain enum, HTTP probing, JS endpoint extraction, cloud asset discovery",
                             sub_items=["subfinder, amass, assetfinder, dnsx, httpx"]),
                FeatureEntry("Vulnerability Scanning", "nuclei v3 (175k+ templates), XSS, SQLi, SSRF, IDOR, CORS, CRLF, Open Redirect",
                             sub_items=["dalfox, kxss, XSStrike, sqlmap, commix, crlfuzz"]),
                FeatureEntry("Secret Detection", "trufflehog, gitleaks, jwt_tool across repos and endpoints"),
                FeatureEntry("API Security", "GraphQL injection, BOLA, mass assignment, rate limit bypass"),
                FeatureEntry("Cloud Misconfiguration", "S3, Elasticsearch, K8s, credential leakage checks"),
            ],
            "Mobile Security": [
                FeatureEntry("12-Phase Pipeline", "APK static → AI reverse → Frida gen → secrets → API → components → dynamic → network → API attack → aggregate"),
                FeatureEntry("Static Analysis", "APKTool + JADX + MobSF, 24 dangerous permissions, 14 vuln patterns"),
                FeatureEntry("Runtime Analysis", "Frida auto-scripts, Objection, RMS — SSL bypass, root bypass, crypto hooks"),
                FeatureEntry("Secret Detection", "Binary DEX string scanning, assets/gradle patterns, FP filtering"),
            ],
            "AI Security": [
                FeatureEntry("AI Vulnerability Scanners", "Garak + PyRIT integration"),
                FeatureEntry("Red Team Campaigns", "Jailbreak (5000+ prompts), RAG poisoning, tool abuse, model extraction"),
                FeatureEntry("Prompt Injection", "Detection + exploitation across LLM endpoints"),
            ],
            "Swarm Intelligence": [
                FeatureEntry("8 Specialized Agents", "XSS, SQLi, SSRF, IDOR, Auth Bypass, Business Logic, Mobile, API Security — parallel execution"),
                FeatureEntry("Agent Collaboration", "Event bus: SQLi→IDOR, SSRF→IDOR, XSS→Auth triggers on finding confirmation"),
                FeatureEntry("Monte Carlo Simulation", "N=200 Bernoulli trials, 23-path catalog, 6 probability factors, EV ranking"),
                FeatureEntry("Workflow Simulation", "4 workflow factories (checkout/login/reset/transfer), 9 business logic attack categories"),
                FeatureEntry("EMA Learning", "α=0.30 per-agent success rate persistence across sessions"),
            ],
            "Attack Graph Intelligence": [
                FeatureEntry("Real-time Attack Graph", "Nodes: host/service/vuln/chain; edges: exploits/leads-to/chained-with"),
                FeatureEntry("BFS Path Enumeration", "Attack path finding from target root to exploit nodes"),
                FeatureEntry("Exploit Chain Detection", "12 multi-step patterns: XSS→ATO, SQLi→RCE, SSRF→Cloud, etc."),
                FeatureEntry("Risk Scoring", "CVSS + exploitability + chain bonus × impact multiplier"),
                FeatureEntry("OSINT Collection", "crt.sh, ASN, Wayback, GitHub dorks, Shodan, URLScan"),
            ],
            "Autonomous Bug Bounty Hunter": [
                FeatureEntry("Program Discovery", "HackerOne, Bugcrowd, Intigriti APIs"),
                FeatureEntry("Target Prioritization", "6-dimension weighted scoring (tech risk, cloud, sensitive paths)"),
                FeatureEntry("Full Pipeline", "discover → recon → crawl → vuln_scan → exploit → validate → report"),
                FeatureEntry("Report Templates", "HackerOne/Bugcrowd markdown with CVSS + bounty estimates"),
            ],
            "Self-Evolving Architecture": [
                FeatureEntry("Event-Driven Updates", "feature_added / scan_completed / vulnerability_discovered / exploit_chain_detected / tool_integrated events"),
                FeatureEntry("Auto Doc Rewrite", "ARCHITECTURE.md, SKILLS.md, README.md updated automatically on activity"),
                FeatureEntry("Persistent Memory", "evolution.db: attack patterns, exploit chains, learning insights, capability snapshots"),
                FeatureEntry("System Evolution Dashboard", "React UI: recent updates, new capabilities, architecture changes, learning insights"),
            ],
        }

        for cat, entries in features.items():
            self._features[cat] = entries

        cli_commands = {
            "Core Scanning": [
                CLICommand("scan <target>",           "Full autonomous pentest (7-phase)"),
                CLICommand("adaptive-recon <target>", "Tech detect + JS endpoints + cloud assets"),
                CLICommand("research <target> --yes", "Autonomous research loop"),
            ],
            "Swarm Intelligence": [
                CLICommand("swarm-scan <target>",         "8-agent parallel swarm scan"),
                CLICommand("simulate-attacks <target>",   "Monte Carlo attack path simulation (N=200)"),
                CLICommand("simulate-workflow <target>",  "Business logic workflow simulation"),
            ],
            "Mobile": [
                CLICommand("mobile-analyze app.apk",  "Full 12-phase mobile security pipeline"),
                CLICommand("mobile-static app.apk",   "Static analysis only"),
                CLICommand("mobile-secrets app.apk",  "Secret/credential scanning"),
            ],
            "AI Security": [
                CLICommand("ai-test <target> --all",                              "All AI security tools"),
                CLICommand("ai-redteam <target> --campaign jailbreak --prompts 5000", "AI red team campaign"),
            ],
            "Autonomous Hunter": [
                CLICommand("hunter-start",        "Discover programs + auto-scan"),
                CLICommand("hunter-scan <target>","Single-target pipeline"),
            ],
            "Attack Graph": [
                CLICommand("attack-graph <target>", "Build + view attack graph"),
                CLICommand("agents run <target> --yes", "Multi-agent pentest"),
            ],
            "Self-Evolving Architecture": [
                CLICommand("arch-status",     "Show evolution engine status + recent changes"),
                CLICommand("arch-events",     "List recent architecture events"),
                CLICommand("arch-insights",   "Show latest learning insights"),
            ],
            "Utilities": [
                CLICommand("toolcheck",     "Check tool availability"),
                CLICommand("learn stats",   "Learning system statistics"),
                CLICommand("profile list",  "List scan profiles"),
                CLICommand("cache stats",   "Recon cache statistics"),
            ],
        }
        for cat, cmds in cli_commands.items():
            self._cli[cat] = cmds

        self._pages = [
            UIPage("Dashboard",             "/dashboard",           "Overview metrics, recent findings"),
            UIPage("Targets",               "/targets",             "Target management"),
            UIPage("Scans",                 "/scans",               "Scan history and live progress"),
            UIPage("Vulnerabilities",       "/vulnerabilities",     "Finding browser with filters"),
            UIPage("Attack Graph",          "/attack-graph",        "Graph visualization"),
            UIPage("Graph Explorer",        "/graph-explorer",      "ForceGraph2D, attack paths, risk report"),
            UIPage("AI Red Team",           "/ai-redteam",          "Campaign builder and results"),
            UIPage("AI Security",           "/ai-security",         "AI test console"),
            UIPage("AI Agent Pentest",      "/ai-agent-pentest",    "Agentic system tester"),
            UIPage("Mobile Security",       "/mobile",              "14-tab mobile analysis UI"),
            UIPage("Bounty Hunter",         "/hunter",              "Autonomous hunter (5-tab)"),
            UIPage("Swarm Intelligence",    "/swarm-intelligence",  "Swarm scan, Monte Carlo sim, workflow sim, history"),
            UIPage("System Evolution",      "/evolution",           "Architecture changes, new capabilities, insights"),
            UIPage("Traffic Explorer",      "/traffic",             "HTTP capture and replay"),
            UIPage("Attack Replay",         "/attack-replay",       "Attack replay builder"),
            UIPage("Reports",               "/reports",             "Report viewer"),
            UIPage("Settings",              "/settings",            "Platform configuration"),
        ]

        self._arch_lines = [
            "oneinfinity.py (CLI, 58 commands)",
            "    │",
            "    ├── Self-Evolving Architecture (NEW)",
            "    │   ├── auto_architecture_engine.py  — event bus, dispatcher, integration hooks",
            "    │   ├── architecture_updater.py       — ARCHITECTURE.md section patcher",
            "    │   ├── memory_manager.py             — evolution.db: patterns/chains/insights",
            "    │   ├── skills_tracker.py             — SKILLS.md capability registry",
            "    │   └── readme_generator.py           — README.md auto-generator",
            "    │",
            "    ├── Swarm Intelligence",
            "    │   ├── swarm_intelligence_engine.py  — 8 specialized agents + EMA learning",
            "    │   ├── agent_swarm_coordinator.py    — parallel orchestration + event bus",
            "    │   ├── attack_simulation_engine.py   — Monte Carlo N=200 simulations",
            "    │   └── workflow_simulation_engine.py — business logic attack simulation",
            "    │",
            "    ├── Core Agents",
            "    │   ├── agents/coordinator.py         — orchestrator, sequential phases",
            "    │   ├── agents/recon_agent.py         — subfinder/httpx/katana/waybackurls",
            "    │   ├── agents/scan_agent.py          — nuclei/dalfox/sqlmap/trufflehog",
            "    │   └── agents/report_agent.py        — HackerOne/Bugcrowd reports",
            "    │",
            "    ├── Intelligence Engines",
            "    │   ├── adaptive_recon_engine.py      — tech detect, JS endpoints, cloud",
            "    │   ├── application_intelligence.py   — AppModel: auth flows, API structure",
            "    │   ├── vulnerability_theory_engine.py — 23 rule-based vuln theories",
            "    │   └── attack_graph_core/            — graph engine, risk analyzer, planner",
            "    │",
            "    ├── Mobile Security",
            "    │   ├── mobile_security_engine.py     — 12-phase pipeline",
            "    │   ├── mobile_static_analysis.py     — APKTool + JADX + MobSF",
            "    │   ├── frida_script_generator.py     — auto-generate Frida JS",
            "    │   └── mobile_dynamic_analysis.py    — Frida + Objection runtime",
            "    │",
            "    ├── AI Security",
            "    │   └── ai_security/                  — Garak, PyRIT, prompt injection, campaigns",
            "    │",
            "    └── Web Layer",
            "        ├── web/backend/main.py           — FastAPI, 60+ routes, WebSocket",
            "        └── web/frontend/src/             — React 18, Tailwind, Recharts, Zustand",
        ]

        self._extras["data_dir"] = (
            "## Data Directory\n\n"
            "Default: `~/.oneinfinity`\n\n"
            "Override: `ONEINFINITY_HOME` or `ONEINFINITY_DATA_DIR` environment variables.\n"
        )

        self._extras["tools"] = (
            "## Tool Requirements\n\n"
            "**Go tools** (`~/go/bin/`): dalfox, crlfuzz, kxss, dnsx, naabu, gobuster, ffuf, anew, "
            "gf, qsreplace, httpx, waybackurls, gauplus, katana, hakrawler, subfinder, assetfinder, "
            "amass, nuclei\n\n"
            "**Binaries** (`~/.local/bin/`): trufflehog, gitleaks, findomain\n\n"
            "**Git clones** (`~/.local/`): sqlmap, xssstrike, jwt_tool, commix, paramspider, dirsearch\n\n"
            "**Python packages**: arjun, s3scanner, sublist3r, whatweb, nikto, garak, pyrit\n"
        )

    def _parse_existing(self):
        """No-op for now — we own the full content model."""
        pass

    # ── Public API ────────────────────────────────────────────────────────────

    def add_feature(self, feature: FeatureEntry):
        with self._lock:
            cat = feature.category
            if cat not in self._features:
                self._features[cat] = []
            # Avoid duplicate titles
            existing = [f.title for f in self._features[cat]]
            if feature.title not in existing:
                self._features[cat].append(feature)
                self._dirty = True
        self._maybe_write()

    def add_cli_command(self, cmd: CLICommand):
        with self._lock:
            cat = cmd.category
            if cat not in self._cli:
                self._cli[cat] = []
            existing = [c.command for c in self._cli[cat]]
            if cmd.command not in existing:
                self._cli[cat].append(cmd)
                self._dirty = True
        self._maybe_write()

    def add_ui_page(self, page: UIPage):
        with self._lock:
            routes = [p.route for p in self._pages]
            if page.route not in routes:
                self._pages.append(page)
                self._dirty = True
        self._maybe_write()

    def update_architecture_tree(self, lines: list[str]):
        with self._lock:
            self._arch_lines = lines
            self._dirty = True
        self._maybe_write()

    def set_extra(self, key: str, markdown: str):
        with self._lock:
            self._extras[key] = markdown
            self._dirty = True
        self._maybe_write()

    # ── Render + write ────────────────────────────────────────────────────────

    def _maybe_write(self):
        if time.time() - self._last_write >= 10.0 and self._dirty:
            self._write()

    def force_write(self):
        with self._lock:
            self._write()

    def _write(self):
        content = self._render()
        tmp = self._path.with_suffix(".md.tmp")
        tmp.write_text(content, encoding="utf-8")
        tmp.replace(self._path)
        self._last_write = time.time()
        self._dirty = False

    def _render(self) -> str:
        ts = time.strftime("%Y-%m-%d", time.gmtime())
        lines: list[str] = [
            "# AI-Powered Offensive Security Research Framework : One&Infinity\n\n",
            "An autonomous, AI-driven platform for offensive security research, bug bounty automation, "
            "mobile security testing, AI security testing, swarm-intelligence–driven vulnerability discovery, "
            "attack graph analysis, and **self-evolving architecture**.\n\n",
            f"_Auto-generated by `readme_generator.py`. Last updated: {ts}._\n\n---\n\n",
            "## Features\n\n",
        ]

        for cat, features in self._features.items():
            if not features:
                continue
            lines.append(f"### {cat}\n")
            for f in features:
                lines.append(f.to_md() + "\n")
            lines.append("\n")

        lines.append("---\n\n## CLI\n\nPrimary command: `oneinfinity`\n\n")

        for cat, cmds in self._cli.items():
            if not cmds:
                continue
            lines.append(f"```bash\n# {cat}\n")
            for c in cmds:
                lines.append(c.to_md() + "\n")
            lines.append("```\n\n")

        lines.append("---\n\n")

        lines.append("## Web UI\n\nStart backend + frontend:\n\n```bash\n./web/start.sh\n```\n\n")
        lines.append("| Service | URL |\n|---------|-----|\n")
        lines.append("| React dashboard | `http://localhost:47292` |\n")
        lines.append("| FastAPI REST    | `http://localhost:47291` |\n")
        lines.append("| OpenAPI docs    | `http://localhost:47291/docs` |\n\n")

        lines.append("### Pages\n\n| Page | Route | Description |\n|------|-------|-------------|\n")
        for p in self._pages:
            lines.append(p.to_md_row() + "\n")
        lines.append("\n---\n\n")

        lines.append("## Architecture\n\n```\n")
        for al in self._arch_lines:
            lines.append(al + "\n")
        lines.append("```\n\n---\n\n")

        for extra_md in self._extras.values():
            lines.append(extra_md + "\n\n")

        return "".join(lines)


# ── Singleton ─────────────────────────────────────────────────────────────────

_instance: ReadmeGenerator | None = None
_instance_lock = threading.Lock()


def get_readme_generator() -> ReadmeGenerator:
    global _instance
    if _instance is None:
        with _instance_lock:
            if _instance is None:
                _instance = ReadmeGenerator()
    return _instance
