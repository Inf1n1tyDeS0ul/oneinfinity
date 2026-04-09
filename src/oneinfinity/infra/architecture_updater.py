"""
architecture_updater.py — Architecture Document Auto-Updater

Rewrites / patches ARCHITECTURE.md based on platform events.  Maintains a
structured in-memory representation of the document so individual sections
can be updated without touching the rest of the file.
"""

from __future__ import annotations

import re
import threading
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional

ROOT = Path(__file__).parent
ARCH_PATH = ROOT / "ARCHITECTURE.md"


# ── Data models ───────────────────────────────────────────────────────────────

@dataclass
class ComponentEntry:
    """Represents a single row in a module table inside ARCHITECTURE.md."""
    name: str
    file: str
    description: str
    category: str = "Core"
    added_at: float = field(default_factory=time.time)

    def to_md_row(self) -> str:
        return f"| `{self.file}` | {self.description} |"


@dataclass
class DataFlowStep:
    """One step in a data-flow diagram."""
    from_component: str
    to_component: str
    label: str = ""
    edge_type: str = "→"   # → / ⇒ / ─►


@dataclass
class ArchSection:
    """A top-level section of ARCHITECTURE.md."""
    number: int
    title: str
    content: str = ""       # raw markdown body


# ── Updater ───────────────────────────────────────────────────────────────────

class ArchitectureUpdater:
    """
    Manages ARCHITECTURE.md:

    - Parses the existing file into sections on first access.
    - Provides targeted update methods that patch individual sections.
    - Writes the file atomically via a .tmp → replace pattern.
    - Throttled: at most one write per 10 s to avoid IO thrashing.
    """

    def __init__(self, arch_path: Path = ARCH_PATH):
        self._path = arch_path
        self._lock = threading.Lock()
        self._sections: list[ArchSection] = []
        self._header: str = ""          # everything before first ##
        self._last_write: float = 0.0
        self._dirty: bool = False
        self._load()

    # ── Load / save ───────────────────────────────────────────────────────────

    def _load(self):
        if not self._path.exists():
            self._header = "# One&Infinity — Platform Architecture\n\n"
            self._sections = []
            return
        text = self._path.read_text(encoding="utf-8")
        self._parse(text)

    def _parse(self, text: str):
        """Split the file into header + list[ArchSection]."""
        # Find all ## headings (we don't touch # title)
        pattern = re.compile(r"^(## .+)$", re.MULTILINE)
        positions = [(m.start(), m.group(1)) for m in pattern.finditer(text)]

        if not positions:
            self._header = text
            self._sections = []
            return

        self._header = text[: positions[0][0]]
        self._sections = []

        num_re = re.compile(r"^## (\d+)\.\s+(.*)")
        for i, (start, heading) in enumerate(positions):
            end = positions[i + 1][0] if i + 1 < len(positions) else len(text)
            body = text[start + len(heading) : end].rstrip()
            m = num_re.match(heading)
            if m:
                self._sections.append(ArchSection(int(m.group(1)), m.group(2).strip(), body))
            else:
                # Unnumbered section — use 0 + title
                title = heading[3:].strip()
                self._sections.append(ArchSection(0, title, body))

    def _render(self) -> str:
        lines = [self._header]
        for sec in self._sections:
            num = f"{sec.number}. " if sec.number else ""
            lines.append(f"## {num}{sec.title}{sec.content}\n")
        return "".join(lines)

    def _write(self):
        content = self._render()
        tmp = self._path.with_suffix(".md.tmp")
        tmp.write_text(content, encoding="utf-8")
        tmp.replace(self._path)
        self._last_write = time.time()
        self._dirty = False

    def _maybe_write(self):
        if time.time() - self._last_write >= 10.0 and self._dirty:
            self._write()

    def force_write(self):
        with self._lock:
            self._write()

    # ── Section operations ────────────────────────────────────────────────────

    def _get_section(self, title_fragment: str) -> Optional[ArchSection]:
        for sec in self._sections:
            if title_fragment.lower() in sec.title.lower():
                return sec
        return None

    def _upsert_section(self, number: int, title: str, content: str):
        for sec in self._sections:
            if sec.title.lower() == title.lower():
                sec.content = content
                return
        # Append new section with correct number
        if number == 0:
            # Auto-assign: max + 1
            number = max((s.number for s in self._sections if s.number), default=0) + 1
        self._sections.append(ArchSection(number, title, content))
        # Keep sorted by number
        self._sections.sort(key=lambda s: (s.number, s.title))

    # ── Public update methods ─────────────────────────────────────────────────

    def add_component(self, component: ComponentEntry, section_title: str = "Project Directory Structure"):
        """
        Append a new module entry to the named section's component table.
        If the section doesn't exist, creates a minimal new section.
        """
        with self._lock:
            sec = self._get_section(section_title)
            row = component.to_md_row()
            if sec:
                # Avoid duplicates
                if component.file in sec.content:
                    return
                # Append before the closing ``` or before the next blank line after a table
                if "```" in sec.content:
                    # Append to last code block
                    idx = sec.content.rfind("```")
                    sec.content = sec.content[:idx] + f"├── {component.file:<42} # {component.description}\n" + sec.content[idx:]
                else:
                    sec.content = sec.content.rstrip() + f"\n{row}\n"
            else:
                content = f"\n\nNew components added at {time.strftime('%Y-%m-%d %H:%M UTC', time.gmtime())}:\n\n"
                content += "| File | Description |\n|------|-------------|\n"
                content += row + "\n"
                self._upsert_section(0, section_title, content)
            self._dirty = True
            self._maybe_write()

    def update_metrics(self, *, total_files: int | None = None,
                       total_loc: int | None = None,
                       api_routes: int | None = None,
                       cli_commands: int | None = None,
                       vuln_types: int | None = None):
        """Patch the metrics table that appears at the end of ARCHITECTURE.md."""
        with self._lock:
            sec = self._get_section("Codebase Statistics") or self._get_section("Code Statistics")
            if not sec:
                return
            def _patch(text: str, key: str, value: str) -> str:
                return re.sub(
                    rf"(\|\s*\*\*{re.escape(key)}\*\*\s*\|.*?\|)(.*?)(\|)",
                    lambda m: f"{m.group(1)} {value} {m.group(3)}",
                    text
                )
            if total_files is not None:
                sec.content = re.sub(r"(\| \*\*Total\*\* \| )\d+", rf"\g<1>{total_files}", sec.content)
            if api_routes is not None:
                sec.content = re.sub(r"\*\*API routes:\*\* \d+", f"**API routes:** {api_routes}", sec.content)
            if cli_commands is not None:
                sec.content = re.sub(r"\*\*CLI commands:\*\* \d+", f"**CLI commands:** {cli_commands}", sec.content)
            self._dirty = True
            self._maybe_write()

    def add_section(self, title: str, content: str, number: int = 0):
        """Add or replace an entire section."""
        with self._lock:
            self._upsert_section(number, title, "\n\n" + content.strip() + "\n")
            self._dirty = True
            self._maybe_write()

    def append_to_section(self, title_fragment: str, markdown: str):
        """Append markdown text to an existing section."""
        with self._lock:
            sec = self._get_section(title_fragment)
            if sec:
                sec.content = sec.content.rstrip() + "\n\n" + markdown.strip() + "\n"
                self._dirty = True
                self._maybe_write()

    def update_data_flow(self, steps: list[DataFlowStep], section_title: str = "Architecture Diagrams"):
        """
        Append or replace the data-flow ASCII diagram in the named section.
        Generates a simple linear diagram from the steps list.
        """
        lines = ["```", "Data Flow:"]
        for s in steps:
            lines.append(f"  {s.from_component}  {s.edge_type}  [{s.label}]  {s.to_component}")
        lines.append("```")
        diagram = "\n".join(lines)
        with self._lock:
            sec = self._get_section(section_title)
            if sec:
                # Replace existing auto-generated block if present
                marker = "<!-- auto-flow -->"
                if marker in sec.content:
                    pattern = re.compile(
                        r"<!-- auto-flow -->.*?<!-- /auto-flow -->", re.DOTALL
                    )
                    replacement = f"{marker}\n{diagram}\n<!-- /auto-flow -->"
                    sec.content = pattern.sub(replacement, sec.content)
                else:
                    block = f"\n\n{marker}\n{diagram}\n<!-- /auto-flow -->\n"
                    sec.content = sec.content.rstrip() + block
                self._dirty = True
                self._maybe_write()

    def record_integration(self, engine_name: str, connected_to: list[str],
                            description: str = ""):
        """
        Record a new engine integration point in the Inter-Module Communication
        or Integration section.
        """
        entry = (
            f"\n#### {engine_name}\n"
            f"- **Connected to:** {', '.join(connected_to)}\n"
        )
        if description:
            entry += f"- **Description:** {description}\n"
        self.append_to_section("Inter-Module Communication", entry)

    def get_section_titles(self) -> list[str]:
        with self._lock:
            return [f"{s.number}. {s.title}" for s in self._sections]

    def section_count(self) -> int:
        with self._lock:
            return len(self._sections)


# ── Singleton ─────────────────────────────────────────────────────────────────

_instance: ArchitectureUpdater | None = None
_instance_lock = threading.Lock()


def get_architecture_updater() -> ArchitectureUpdater:
    global _instance
    if _instance is None:
        with _instance_lock:
            if _instance is None:
                _instance = ArchitectureUpdater()
    return _instance
