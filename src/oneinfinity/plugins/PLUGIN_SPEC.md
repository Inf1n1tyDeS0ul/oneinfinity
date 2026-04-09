# OneInfinity Plugin Specification

Plugins extend OneInfinity with custom recon, vulnerability, or report capabilities.
They are auto-discovered from the `plugins/` directory tree and hot-reloaded
when the plugin volume is updated.

## Plugin Types

| Type | Description | Called by |
|------|-------------|-----------|
| `recon` | Discover subdomains, URLs, endpoints | `recon` phase |
| `vuln` | Detect vulnerabilities | `vuln_scan` phase |
| `report` | Format and export findings | `report` command |

## Required Structure

Every plugin must have a `plugin.py` file (or `__init__.py`) containing:

```python
# PLUGIN_META — metadata dict (required)
PLUGIN_META = {
    "name":        "my-plugin",        # unique identifier, kebab-case
    "type":        "vuln",             # recon | vuln | report
    "version":     "1.0.0",            # semver
    "description": "Detects X vuln",
    "author":      "Your Name",
    "tags":        ["graphql", "api"], # for capability map routing
}

# Plugin class — must be named exactly `Plugin`
class Plugin:
    def run(self, target: str, context: dict) -> dict:
        """
        Execute the plugin against `target`.

        Args:
            target:  The scan target (URL, domain, file path, etc.)
            context: Dict with keys:
                       output_dir    str  — where to write output files
                       config        dict — user-supplied config
                       findings_db   str  — path to SQLite findings DB
                       app_model     dict — AppModel if available
                       urls          list — discovered URLs
                       alive_hosts   list — live hosts

        Returns:
            dict with keys:
              findings     list[dict]  — list of finding dicts (see below)
              metadata     dict        — any extra data
              error        str | None  — error message if failed
        """
        raise NotImplementedError
```

## Finding Schema

Each finding in `result["findings"]` must follow this schema:

```python
{
    "title":       str,   # Short description, e.g. "GraphQL Introspection Enabled"
    "severity":    str,   # critical | high | medium | low | info
    "vuln_type":   str,   # e.g. "graphql-introspection", "ssrf", "idor"
    "url":         str,   # Affected endpoint
    "parameter":   str,   # Vulnerable parameter (optional)
    "evidence":    str,   # Proof — response excerpt, payload, etc.
    "payload":     str,   # The payload that triggered the issue (optional)
    "description": str,   # Detailed explanation
    "remediation": str,   # How to fix it
    "cvss":        float, # CVSS 3.1 score (0.0–10.0)
    "confidence":  float, # 0.0–1.0 certainty the finding is real
    "tool":        str,   # Plugin name
}
```

## Example — Minimal Recon Plugin

```python
# plugins/community/my_recon_plugin/plugin.py
import requests

PLUGIN_META = {
    "name":        "crtsh-monitor",
    "type":        "recon",
    "version":     "1.0.0",
    "description": "Certificate transparency subdomain enumeration",
    "author":      "Security Team",
    "tags":        ["subdomains", "recon", "passive"],
}

class Plugin:
    def run(self, target: str, context: dict) -> dict:
        domain = target.replace("https://", "").replace("http://", "").split("/")[0]
        try:
            resp = requests.get(
                f"https://crt.sh/?q=%.{domain}&output=json",
                timeout=30,
            )
            resp.raise_for_status()
            subdomains = list({entry["name_value"]
                               for entry in resp.json()
                               if entry.get("name_value")})
            return {
                "findings": [],          # recon plugins return metadata, not findings
                "metadata": {
                    "subdomains":  subdomains,
                    "subdomain_count": len(subdomains),
                },
                "error": None,
            }
        except Exception as exc:
            return {"findings": [], "metadata": {}, "error": str(exc)}
```

## Example — Vulnerability Plugin

```python
# plugins/community/graphql-audit/plugin.py
import requests

PLUGIN_META = {
    "name":        "graphql-audit",
    "type":        "vuln",
    "version":     "1.2.0",
    "description": "GraphQL introspection, BOLA, and injection testing",
    "author":      "Security Team",
    "tags":        ["graphql", "api", "introspection", "injection"],
}

INTROSPECTION_QUERY = {"query": "{ __schema { types { name } } }"}

class Plugin:
    def run(self, target: str, context: dict) -> dict:
        findings = []
        urls = context.get("urls", [target])

        for url in urls:
            if "/graphql" not in url.lower():
                continue
            try:
                r = requests.post(url, json=INTROSPECTION_QUERY, timeout=10)
                if r.ok and "__schema" in r.text:
                    findings.append({
                        "title":       "GraphQL Introspection Enabled",
                        "severity":    "medium",
                        "vuln_type":   "graphql-introspection",
                        "url":         url,
                        "parameter":   "query",
                        "evidence":    r.text[:500],
                        "payload":     str(INTROSPECTION_QUERY),
                        "description": "GraphQL introspection is enabled, exposing the full schema.",
                        "remediation": "Disable introspection in production via server configuration.",
                        "cvss":        5.3,
                        "confidence":  0.95,
                        "tool":        "graphql-audit",
                    })
            except Exception:
                pass

        return {"findings": findings, "metadata": {}, "error": None}
```

## Installing Plugins

```bash
# From GitHub
oneinfinity-plugin install github.com/org/oi-plugin-graphql

# Or via the Docker plugin installer
docker exec oneinfinity-orchestrator \
    /app/scripts/plugin-install.sh install github.com/org/oi-plugin-graphql

# From PyPI
docker exec oneinfinity-orchestrator \
    /app/scripts/plugin-install.sh install pypi:oi-plugin-graphql

# List installed
docker exec oneinfinity-orchestrator \
    /app/scripts/plugin-install.sh list
```

## Plugin Hot-Reload (Docker)

When using the distributed docker-compose setup, mount a local plugin
directory as a volume. Any `.py` files added/changed trigger automatic
reload via the plugin-watcher service:

```yaml
volumes:
  - ./my-plugins:/app/plugins/community
```

The `plugin-watcher` service (see `docker-compose.distributed.yml`) monitors
this volume for changes and signals the orchestrator to reload the registry.

## Plugin Directory Layout

```
plugins/
├── community/              ← community / third-party plugins
│   ├── __init__.py
│   ├── registry.yaml       ← auto-generated plugin manifest
│   ├── graphql-audit/
│   │   ├── plugin.py
│   │   ├── requirements.txt
│   │   └── README.md
│   └── crtsh-monitor/
│       ├── plugin.py
│       └── README.md
├── recon/                  ← built-in recon plugins
│   ├── crtsh_monitor.py
│   └── asn_enum.py
└── vuln/                   ← built-in vulnerability plugins
    ├── api_security.py
    └── cloud_misconfig.py
```
