"""Shared utilities: colors, formatting, output helpers."""

import os
import sys
import json
from datetime import datetime

# ── ANSI colors ───────────────────────────────────────────────────────────────

NO_COLOR = os.environ.get("NO_COLOR") or not sys.stdout.isatty()

def _c(code: str, text: str) -> str:
    return text if NO_COLOR else f"\033[{code}m{text}\033[0m"

def red(t):     return _c("31", t)
def green(t):   return _c("32", t)
def yellow(t):  return _c("33", t)
def blue(t):    return _c("34", t)
def magenta(t): return _c("35", t)
def cyan(t):    return _c("36", t)
def bold(t):    return _c("1",  t)
def dim(t):     return _c("2",  t)

SEV_COLOR = {
    "critical": lambda t: _c("1;31", t),
    "high":     lambda t: _c("31",   t),
    "medium":   lambda t: _c("33",   t),
    "low":      lambda t: _c("34",   t),
    "info":     lambda t: _c("36",   t),
}

def sev(severity: str, text: str = None) -> str:
    s = severity.lower()
    label = text or severity.upper()
    fn = SEV_COLOR.get(s, lambda t: t)
    return fn(label)

# ── Pretty printing ───────────────────────────────────────────────────────────

def banner(title: str, width: int = 60):
    line = "═" * width
    print(f"\n{cyan(line)}")
    print(f"  {bold(title)}")
    print(f"{cyan(line)}\n")

def section(title: str):
    print(f"\n{bold(blue('─── ' + title + ' ───'))}")

def ok(msg):   print(f"  {green('[+]')} {msg}")
def info(msg): print(f"  {blue('[*]')} {msg}")
def warn(msg): print(f"  {yellow('[!]')} {msg}")
def err(msg):  print(f"  {red('[✗]')} {msg}", file=sys.stderr)
def ask(msg):  return input(f"  {cyan('[?]')} {msg}")

def table(rows: list[dict], cols: list[str]):
    """Simple ASCII table."""
    widths = {c: len(c) for c in cols}
    for row in rows:
        for c in cols:
            widths[c] = max(widths[c], len(str(row.get(c, ""))))
    header = "  " + "  ".join(bold(c.upper().ljust(widths[c])) for c in cols)
    sep    = "  " + "  ".join("─" * widths[c] for c in cols)
    print(header)
    print(sep)
    for row in rows:
        line = "  " + "  ".join(str(row.get(c, "")).ljust(widths[c]) for c in cols)
        print(line)

# ── File helpers ──────────────────────────────────────────────────────────────

def read_lines(path: str) -> list[str]:
    with open(path) as f:
        return [l.strip() for l in f if l.strip()]

def read_json(path: str):
    with open(path) as f:
        return json.load(f)

def read_jsonl(path: str) -> list[dict]:
    """Read newline-delimited JSON (nuclei / httpx output format)."""
    results = []
    with open(path) as f:
        for line in f:
            line = line.strip()
            if line:
                try:
                    results.append(json.loads(line))
                except json.JSONDecodeError:
                    pass
    return results

def write_json(path: str, data):
    os.makedirs(os.path.dirname(path) or ".", exist_ok=True)
    with open(path, "w") as f:
        json.dump(data, f, indent=2, default=str)

def write_text(path: str, text: str):
    os.makedirs(os.path.dirname(path) or ".", exist_ok=True)
    with open(path, "w") as f:
        f.write(text)

def now_str() -> str:
    return datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%SZ")

def slugify(text: str) -> str:
    import re
    return re.sub(r"[^a-z0-9]+", "-", text.lower()).strip("-")
