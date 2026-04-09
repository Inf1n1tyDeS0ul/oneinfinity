"""Scope management: load, validate, save scope.yaml, enforce in-scope checks."""

import os
import re
import sys
from pathlib import Path
from oneinfinity.modules.utils import ok, info, warn, err, ask, banner, section

# ── YAML helpers (no external dep) ───────────────────────────────────────────

def _yaml_load(path: str) -> dict:
    """Minimal YAML loader for our known schema (no PyYAML required)."""
    try:
        import yaml
        with open(path) as f:
            return yaml.safe_load(f) or {}
    except ImportError:
        pass
    # Fallback: parse simple key: value YAML
    data = {}
    with open(path) as f:
        content = f.read()
    # Delegate to json if it's actually JSON
    if content.strip().startswith("{"):
        import json
        return json.loads(content)
    # Very simple YAML parser for our template structure
    try:
        return _simple_yaml_parse(content)
    except Exception:
        err(f"Cannot parse {path}. Install PyYAML: pip3 install pyyaml")
        sys.exit(1)

def _simple_yaml_parse(text: str) -> dict:
    """Parse the specific scope.yaml structure without PyYAML."""
    result = {}
    stack = [(result, -1)]

    for raw_line in text.splitlines():
        if not raw_line.strip() or raw_line.strip().startswith("#"):
            continue
        indent = len(raw_line) - len(raw_line.lstrip())
        line = raw_line.strip()

        # Pop stack to correct level
        while len(stack) > 1 and stack[-1][1] >= indent:
            stack.pop()

        parent, _ = stack[-1]

        if line.startswith("- "):
            # List item
            val = line[2:].strip().strip('"').strip("'")
            key = list(parent.keys())[-1] if parent else None
            if key and isinstance(parent.get(key), list):
                parent[key].append(val)
        elif ": " in line:
            key, _, val = line.partition(": ")
            val = val.strip().strip('"').strip("'")
            if val == "" or val is None:
                parent[key] = {}
                stack.append((parent[key], indent))
            elif val.lower() == "true":
                parent[key] = True
            elif val.lower() == "false":
                parent[key] = False
            elif val.lstrip("-").isdigit():
                parent[key] = int(val)
            else:
                parent[key] = val
        elif line.endswith(":"):
            key = line[:-1]
            parent[key] = {}
            stack.append((parent[key], indent))

    return result

def _yaml_dump(data: dict, indent: int = 0) -> str:
    """Minimal YAML serializer."""
    try:
        import yaml
        return yaml.dump(data, default_flow_style=False, allow_unicode=True)
    except ImportError:
        pass
    lines = []
    pad = "  " * indent
    for k, v in data.items():
        if isinstance(v, dict):
            lines.append(f"{pad}{k}:")
            lines.append(_yaml_dump(v, indent + 1))
        elif isinstance(v, list):
            lines.append(f"{pad}{k}:")
            for item in v:
                lines.append(f"{pad}  - \"{item}\"")
        elif isinstance(v, bool):
            lines.append(f"{pad}{k}: {'true' if v else 'false'}")
        elif v is None or v == "":
            lines.append(f"{pad}{k}: \"\"")
        else:
            lines.append(f"{pad}{k}: \"{v}\"")
    return "\n".join(lines)

# ── ScopeManager ─────────────────────────────────────────────────────────────

SCOPE_TEMPLATE = """\
program:
  name: "{name}"
  platform: ""          # HackerOne / Bugcrowd / Intigriti / Private
  url: ""               # Link to program page
  registered: false     # Set to true once you confirm registration

scope:
  in_scope:
    - "*.example.com"
  out_of_scope:
    - "status.example.com"

rules:
  automated_scanning: false
  rate_limit: "30/minute"
  auth_brute_force: false
  dos_testing: false
  physical: false
  restrictions_notes: ""

researcher:
  platform_username: ""
  registered_date: ""
"""

PENTEST_SCOPE_TEMPLATE = """\
engagement:
  type: "pentest"
  client: "{name}"
  authorized: false     # Set true only after confirming written authorization
  auth_document: ""     # Path or ref to signed auth doc / statement of work
  start_date: "{date}"
  tester: ""

scope:
  targets:
{targets}
  out_of_scope: []

rules:
  automated_scanning: true
  port_scanning: true
  auth_brute_force: false   # Set true only if explicitly permitted
  dos_testing: false        # Set true only if explicitly permitted
  rate_limit: "none"
  notes: ""
"""


class ScopeManager:
    def __init__(self, program_dir: str):
        self.program_dir = Path(program_dir)
        self.scope_file  = self.program_dir / "scope.yaml"
        self._data: dict = {}

    # ── Loading ──────────────────────────────────────────────────────────────

    def load(self) -> "ScopeManager":
        if not self.scope_file.exists():
            err(f"scope.yaml not found at {self.scope_file}")
            err("Run: oneinfinity setup <program-name>")
            sys.exit(1)
        self._data = _yaml_load(str(self.scope_file))
        return self

    def exists(self) -> bool:
        return self.scope_file.exists()

    # ── Validation ────────────────────────────────────────────────────────────

    def is_pentest(self) -> bool:
        return self._data.get("engagement", {}).get("type") == "pentest"

    def validate(self) -> bool:
        """Return True if scope.yaml is complete enough to work with."""
        if self.is_pentest():
            eng = self._data.get("engagement", {})
            if not eng.get("authorized"):
                warn("scope.yaml: 'authorized' is false — set to true after confirming written authorization.")
                return False
            if not self._data.get("scope", {}).get("targets"):
                warn("scope.yaml: no targets defined.")
                return False
            return True
        # Bug bounty mode
        prog = self._data.get("program", {})
        if not prog.get("registered"):
            warn("scope.yaml: 'registered' is false — update it once you join the program.")
            return False
        if not self._data.get("scope", {}).get("in_scope"):
            warn("scope.yaml: no in_scope targets defined.")
            return False
        return True

    def require_valid(self):
        self.load()
        if not self.validate():
            err("Fix scope.yaml before running target-specific commands.")
            sys.exit(1)

    # ── Scope checking ────────────────────────────────────────────────────────

    def _pattern_match(self, pattern: str, target: str) -> bool:
        """Wildcard match: *.example.com matches sub.example.com."""
        regex = re.escape(pattern).replace(r"\*", "[^.]+")
        return bool(re.fullmatch(regex, target, re.IGNORECASE))

    def is_in_scope(self, target: str) -> bool:
        """Out-of-scope blocklist wins over in-scope allowlist."""
        scope = self._data.get("scope", {})
        for pat in scope.get("out_of_scope", []):
            if self._pattern_match(pat, target):
                return False
        for pat in scope.get("in_scope", []):
            if self._pattern_match(pat, target):
                return True
        return False

    def filter_in_scope(self, targets: list[str]) -> tuple[list[str], list[str]]:
        """Returns (in_scope, out_of_scope) partition."""
        ins, outs = [], []
        for t in targets:
            # Strip scheme for matching
            host = re.sub(r"^https?://", "", t).split("/")[0].split(":")[0]
            if self.is_in_scope(host):
                ins.append(t)
            else:
                outs.append(t)
        return ins, outs

    # ── Getters ───────────────────────────────────────────────────────────────

    @property
    def program_name(self) -> str:
        return self._data.get("program", {}).get("name", "unknown")

    @property
    def platform(self) -> str:
        return self._data.get("program", {}).get("platform", "")

    @property
    def in_scope_patterns(self) -> list[str]:
        if self.is_pentest():
            return self._data.get("scope", {}).get("targets", [])
        return self._data.get("scope", {}).get("in_scope", [])

    @property
    def rules(self) -> dict:
        return self._data.get("rules", {})

    @property
    def rate_limit(self) -> str:
        return self.rules.get("rate_limit", "30/minute")

    @property
    def allows_automated_scanning(self) -> bool:
        return bool(self.rules.get("automated_scanning", False))

    def show_scope(self):
        if self.is_pentest():
            eng = self._data.get("engagement", {})
            banner(f"Engagement Scope — {eng.get('client', '—')}")
            section("Engagement")
            print(f"  Client     : {eng.get('client', '—')}")
            print(f"  Authorized : {'Yes' if eng.get('authorized') else 'NO — update scope.yaml'}")
            print(f"  Auth Doc   : {eng.get('auth_document') or '—'}")
            print(f"  Start Date : {eng.get('start_date', '—')}")
            print(f"  Tester     : {eng.get('tester') or '—'}")
            section("Targets (In Scope)")
            for t in self._data.get("scope", {}).get("targets", []):
                print(f"  + {t}")
            section("Out of Scope")
            for t in self._data.get("scope", {}).get("out_of_scope", []):
                print(f"  - {t}")
        else:
            banner(f"Scope — {self.program_name}")
            prog = self._data.get("program", {})
            section("Program")
            print(f"  Platform  : {prog.get('platform', '—')}")
            print(f"  URL       : {prog.get('url', '—')}")
            print(f"  Registered: {'Yes' if prog.get('registered') else 'No'}")
            section("In Scope")
            for p in self.in_scope_patterns:
                print(f"  + {p}")
            section("Out of Scope")
            for p in self._data.get("scope", {}).get("out_of_scope", []):
                print(f"  - {p}")
        section("Rules")
        for k, v in self.rules.items():
            print(f"  {k}: {v}")
        print()

    # ── Creation ──────────────────────────────────────────────────────────────

    @classmethod
    def create_template(cls, program_dir: str, name: str):
        path = Path(program_dir) / "scope.yaml"
        path.write_text(SCOPE_TEMPLATE.format(name=name))
        ok(f"Created {path}")
        warn("Edit scope.yaml: add program URL, scope patterns, and set registered: true")

    @classmethod
    def create_pentest_template(cls, program_dir: str, name: str, targets: list[str]):
        from datetime import datetime
        path = Path(program_dir) / "scope.yaml"
        target_lines = "\n".join(f'    - "{t}"' for t in targets)
        path.write_text(PENTEST_SCOPE_TEMPLATE.format(
            name=name,
            date=datetime.utcnow().strftime("%Y-%m-%d"),
            targets=target_lines,
        ))
        ok(f"Created {path}")
        warn("Set authorized: true in scope.yaml after confirming written authorization from the client.")
