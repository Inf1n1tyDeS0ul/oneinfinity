"""
MCP Server for OneInfinity
===========================
Exposes OneInfinity as tools for Claude CLI, Gemini CLI, or Ollama.

Architecture:
  AI Orchestrator (Claude/Gemini/Ollama)
    ↓ calls MCP tools
  OneInfinity MCP Server (this file)
    ↓ executes
  OneInfinity Core (with internal AI still active)

Usage:
  # Claude CLI
  claude "pentest oauth-app.com using oneinfinity tools"

  # Gemini CLI
  gemini "security scan example.com with oneinfinity"

  # Ollama (via mcp-server protocol)
  ollama run deepseek-r1 --mcp oneinfinity
"""

import json
import logging
import subprocess
import sys
import uuid
from pathlib import Path
from typing import Any, Dict, List, Optional

log = logging.getLogger("oneinfinity.mcp")


# ── MCP Tool Definitions ──────────────────────────────────────────────────────

def oneinfinity_recon(
    domain: str,
    subdomain_limit: int = 500,
    crawl_depth: int = 3
) -> Dict[str, Any]:
    """
    Run reconnaissance on domain.

    Discovers:
    - Subdomains (subfinder, amass, assetfinder)
    - Live endpoints (httpx, katana)
    - Technologies (whatweb)
    - Attack surface map

    Args:
        domain: Target domain (e.g., "example.com")
        subdomain_limit: Max subdomains to return (default 500)
        crawl_depth: URL crawl depth (default 3)

    Returns:
        {
            "subdomains": ["sub1.example.com", ...],
            "live_endpoints": ["https://example.com/api/v1", ...],
            "technologies": ["Node.js", "PostgreSQL", ...],
            "asset_count": 1248,
            "graph_nodes": 1489
        }
    """
    log.info(f"[MCP] oneinfinity_recon({domain})")

    cmd = [
        sys.executable, "-m", "oneinfinity.cli.main",
        "scan", domain,
        "--recon-only",
        "--subdomain-limit", str(subdomain_limit),
        "--crawl-depth", str(crawl_depth),
        "--json"
    ]

    result = subprocess.run(
        cmd,
        capture_output=True,
        text=True,
        timeout=600,
        cwd=Path(__file__).parent.parent.parent.parent
    )

    if result.returncode != 0:
        return {
            "error": "Recon failed",
            "stderr": result.stderr,
            "returncode": result.returncode
        }

    # Parse JSON output
    try:
        data = json.loads(result.stdout)
        return {
            "subdomains": data.get("subdomains", []),
            "live_endpoints": data.get("endpoints", []),
            "technologies": data.get("technologies", []),
            "asset_count": len(data.get("endpoints", [])),
            "graph_nodes": data.get("graph_node_count", 0),
            "scan_id": data.get("scan_id", "")
        }
    except json.JSONDecodeError:
        # Fallback: parse text output
        lines = result.stdout.strip().split('\n')
        return {
            "raw_output": lines,
            "note": "Recon complete - check raw_output for results"
        }


def oneinfinity_scan(
    target: str,
    vuln_types: List[str],
    payloads: Optional[List[str]] = None,
    use_internal_ai: bool = True,
    timeout: int = 1800
) -> Dict[str, Any]:
    """
    Scan target for vulnerabilities.

    Vuln types: xss, sqli, ssrf, idor, auth-bypass, cors, jwt, oauth,
                api, graphql, xxe, lfi, ssti, rce, open-redirect

    Args:
        target: URL or IP to scan
        vuln_types: List of vulnerability types to test
        payloads: Optional custom payloads (skips AI generation if provided)
        use_internal_ai: Use OneInfinity's AI for payload generation (default True)
        timeout: Scan timeout in seconds (default 1800)

    Returns:
        {
            "findings": [
                {
                    "vuln_type": "xss",
                    "severity": "high",
                    "url": "https://example.com/search?q=test",
                    "parameter": "q",
                    "payload": "<img src=x onerror=alert(1)>",
                    "validated": true,
                    "confidence": 0.89,
                    "cvss": 7.5
                }
            ],
            "finding_count": 8,
            "scan_duration_seconds": 342
        }
    """
    log.info(f"[MCP] oneinfinity_scan({target}, vuln_types={vuln_types})")

    cmd = [
        sys.executable, "-m", "oneinfinity.cli.main",
        "scan", target,
        "--vuln", ",".join(vuln_types),
        "--json"
    ]

    if payloads:
        # Write custom payloads to temp file
        payload_file = Path(f"/tmp/oneinfinity_payloads_{uuid.uuid4().hex[:8]}.json")
        payload_file.write_text(json.dumps({"payloads": payloads}))
        cmd.extend(["--payload-file", str(payload_file)])

    if not use_internal_ai:
        cmd.append("--no-ai-payloads")

    result = subprocess.run(
        cmd,
        capture_output=True,
        text=True,
        timeout=timeout,
        cwd=Path(__file__).parent.parent.parent.parent
    )

    if result.returncode != 0:
        return {
            "error": "Scan failed",
            "stderr": result.stderr,
            "returncode": result.returncode
        }

    try:
        data = json.loads(result.stdout)
        return {
            "findings": data.get("findings", []),
            "finding_count": len(data.get("findings", [])),
            "scan_duration_seconds": data.get("duration_seconds", 0),
            "scan_id": data.get("scan_id", "")
        }
    except json.JSONDecodeError:
        return {
            "raw_output": result.stdout,
            "note": "Scan complete - check raw_output"
        }


def oneinfinity_exploit(
    finding_id: Optional[str] = None,
    chain_type: Optional[str] = None,
    generate_poc: bool = True
) -> Dict[str, Any]:
    """
    Generate exploit or detect exploit chains.

    Chain types: ssrf_to_cloud, xss_to_ato, sqli_to_rce,
                 idor_to_priv_esc, cors_to_cred_theft,
                 open_redirect_to_oauth_hijack

    Args:
        finding_id: Specific finding to exploit (optional)
        chain_type: Specific chain pattern to detect (optional)
        generate_poc: Generate proof-of-concept script (default True)

    Returns:
        {
            "chains": [
                {
                    "pattern": "xss_to_ato",
                    "steps": ["XSS injection", "Session hijack", "Account takeover"],
                    "confidence": 0.91,
                    "severity": "critical",
                    "poc_script": "#!/bin/bash\n..."
                }
            ],
            "chain_count": 2
        }
    """
    log.info(f"[MCP] oneinfinity_exploit(finding_id={finding_id}, chain={chain_type})")

    cmd = [
        sys.executable, "-m", "oneinfinity.cli.main",
        "exploit",
        "--json"
    ]

    if finding_id:
        cmd.extend(["--finding", finding_id])

    if chain_type:
        cmd.extend(["--chain-type", chain_type])

    if generate_poc:
        cmd.append("--generate-poc")

    result = subprocess.run(
        cmd,
        capture_output=True,
        text=True,
        timeout=300,
        cwd=Path(__file__).parent.parent.parent.parent
    )

    if result.returncode != 0:
        return {
            "error": "Exploit generation failed",
            "stderr": result.stderr
        }

    try:
        data = json.loads(result.stdout)
        return {
            "chains": data.get("chains", []),
            "chain_count": len(data.get("chains", [])),
            "exploits": data.get("exploits", [])
        }
    except json.JSONDecodeError:
        return {"raw_output": result.stdout}


def oneinfinity_validate(
    finding_id: Optional[str] = None,
    exploit_id: Optional[str] = None
) -> Dict[str, Any]:
    """
    Validate finding or exploit (false positive check).

    Performs active re-testing:
    - XSS: Canary token reflection check
    - SQLi: Time-based or error-based validation
    - SSRF: Out-of-band callback verification

    Args:
        finding_id: Finding to validate (optional)
        exploit_id: Exploit to validate (optional)

    Returns:
        {
            "status": "confirmed" | "false_positive" | "unverified",
            "confidence": 0.91,
            "validation_method": "canary_reflection",
            "evidence": {...}
        }
    """
    log.info(f"[MCP] oneinfinity_validate(finding={finding_id}, exploit={exploit_id})")

    cmd = [
        sys.executable, "-m", "oneinfinity.cli.main",
        "validate",
        "--json"
    ]

    if finding_id:
        cmd.extend(["--finding", finding_id])

    if exploit_id:
        cmd.extend(["--exploit", exploit_id])

    result = subprocess.run(
        cmd,
        capture_output=True,
        text=True,
        timeout=120,
        cwd=Path(__file__).parent.parent.parent.parent
    )

    if result.returncode != 0:
        return {
            "error": "Validation failed",
            "stderr": result.stderr
        }

    try:
        data = json.loads(result.stdout)
        return {
            "status": data.get("status", "unverified"),
            "confidence": data.get("confidence", 0.0),
            "validation_method": data.get("method", ""),
            "evidence": data.get("evidence", {})
        }
    except json.JSONDecodeError:
        return {"raw_output": result.stdout}


def oneinfinity_report(
    scan_id: Optional[str] = None,
    finding_ids: Optional[List[str]] = None,
    format: str = "hackerone",
    include_poc: bool = True
) -> Dict[str, Any]:
    """
    Generate security report.

    Formats: hackerone, bugcrowd, intigriti, markdown, json

    Args:
        scan_id: Scan to report on (optional, uses latest if not provided)
        finding_ids: Specific findings to include (optional)
        format: Report format (default "hackerone")
        include_poc: Include proof-of-concept scripts (default True)

    Returns:
        {
            "report_markdown": "## Vulnerability: ...",
            "finding_count": 8,
            "critical_count": 2,
            "bounty_estimate": "$3,000 - $8,000"
        }
    """
    log.info(f"[MCP] oneinfinity_report(scan_id={scan_id}, format={format})")

    cmd = [
        sys.executable, "-m", "oneinfinity.cli.main",
        "report",
        "--format", format,
        "--json"
    ]

    if scan_id:
        cmd.extend(["--scan-id", scan_id])

    if finding_ids:
        cmd.extend(["--findings", ",".join(finding_ids)])

    if include_poc:
        cmd.append("--include-poc")

    result = subprocess.run(
        cmd,
        capture_output=True,
        text=True,
        timeout=180,
        cwd=Path(__file__).parent.parent.parent.parent
    )

    if result.returncode != 0:
        return {
            "error": "Report generation failed",
            "stderr": result.stderr
        }

    try:
        data = json.loads(result.stdout)
        return {
            "report_markdown": data.get("report", ""),
            "finding_count": data.get("finding_count", 0),
            "critical_count": data.get("critical_count", 0),
            "high_count": data.get("high_count", 0),
            "bounty_estimate": data.get("bounty_estimate", "Unknown")
        }
    except json.JSONDecodeError:
        return {"raw_output": result.stdout}


def oneinfinity_graph_query(
    query: str,
    target: Optional[str] = None
) -> Dict[str, Any]:
    """
    Query attack graph for paths/chains.

    Example queries:
    - "paths from XSS to admin access"
    - "all nodes connected to /api/users endpoint"
    - "chains with confidence > 0.8"

    Args:
        query: Natural language graph query
        target: Optional target filter

    Returns:
        {
            "paths": [
                {
                    "nodes": ["xss_node", "auth_endpoint", "admin_panel"],
                    "confidence": 0.87,
                    "steps": [...]
                }
            ],
            "path_count": 3
        }
    """
    log.info(f"[MCP] oneinfinity_graph_query(query={query})")

    cmd = [
        sys.executable, "-m", "oneinfinity.cli.main",
        "graph-query",
        "--query", query,
        "--json"
    ]

    if target:
        cmd.extend(["--target", target])

    result = subprocess.run(
        cmd,
        capture_output=True,
        text=True,
        timeout=60,
        cwd=Path(__file__).parent.parent.parent.parent
    )

    if result.returncode != 0:
        return {
            "error": "Graph query failed",
            "stderr": result.stderr
        }

    try:
        data = json.loads(result.stdout)
        return {
            "paths": data.get("paths", []),
            "path_count": len(data.get("paths", [])),
            "nodes": data.get("nodes", [])
        }
    except json.JSONDecodeError:
        return {"raw_output": result.stdout}


def oneinfinity_mobile_analyze(
    apk_path: str,
    deep_analysis: bool = True
) -> Dict[str, Any]:
    """
    Analyze Android APK for security issues.

    Performs:
    - Static analysis (MobSF, APKTool, JADX)
    - AI reverse engineering (hidden endpoints, business logic)
    - Secret scanning (TruffleHog, Gitleaks)
    - Component testing (exported activities, providers)

    Args:
        apk_path: Path to APK file
        deep_analysis: Enable AI-powered deep analysis (default True)

    Returns:
        {
            "package_name": "com.example.app",
            "vulnerabilities": [...],
            "hidden_endpoints": [...],
            "secrets_found": [...],
            "attack_surface_score": 67.5
        }
    """
    log.info(f"[MCP] oneinfinity_mobile_analyze({apk_path})")

    cmd = [
        sys.executable, "-m", "oneinfinity.cli.main",
        "mobile-upload", apk_path
    ]

    # Upload APK first
    upload_result = subprocess.run(
        cmd,
        capture_output=True,
        text=True,
        timeout=120,
        cwd=Path(__file__).parent.parent.parent.parent
    )

    if upload_result.returncode != 0:
        return {
            "error": "APK upload failed",
            "stderr": upload_result.stderr
        }

    # Extract apk_id from upload response
    apk_id = upload_result.stdout.strip().split()[-1]

    # Run analysis
    cmd = [
        sys.executable, "-m", "oneinfinity.cli.main",
        "mobile-analyze", apk_id,
        "--json"
    ]

    if not deep_analysis:
        cmd.append("--no-ai")

    result = subprocess.run(
        cmd,
        capture_output=True,
        text=True,
        timeout=1800,
        cwd=Path(__file__).parent.parent.parent.parent
    )

    if result.returncode != 0:
        return {
            "error": "Mobile analysis failed",
            "stderr": result.stderr
        }

    try:
        data = json.loads(result.stdout)
        return {
            "package_name": data.get("package_name", ""),
            "vulnerabilities": data.get("vulnerabilities", []),
            "hidden_endpoints": data.get("hidden_endpoints", []),
            "secrets_found": data.get("secrets", []),
            "attack_surface_score": data.get("attack_surface_score", 0.0),
            "apk_id": apk_id
        }
    except json.JSONDecodeError:
        return {"raw_output": result.stdout}


# ── MCP Server Registration ───────────────────────────────────────────────────

TOOLS = {
    "oneinfinity_recon": {
        "function": oneinfinity_recon,
        "description": "Run reconnaissance on domain (subdomains, endpoints, tech stack)",
        "parameters": {
            "domain": {"type": "string", "required": True},
            "subdomain_limit": {"type": "integer", "default": 500},
            "crawl_depth": {"type": "integer", "default": 3}
        }
    },
    "oneinfinity_scan": {
        "function": oneinfinity_scan,
        "description": "Scan target for vulnerabilities (xss, sqli, ssrf, etc.)",
        "parameters": {
            "target": {"type": "string", "required": True},
            "vuln_types": {"type": "array", "required": True},
            "payloads": {"type": "array", "default": None},
            "use_internal_ai": {"type": "boolean", "default": True},
            "timeout": {"type": "integer", "default": 1800}
        }
    },
    "oneinfinity_exploit": {
        "function": oneinfinity_exploit,
        "description": "Generate exploits or detect exploit chains",
        "parameters": {
            "finding_id": {"type": "string", "default": None},
            "chain_type": {"type": "string", "default": None},
            "generate_poc": {"type": "boolean", "default": True}
        }
    },
    "oneinfinity_validate": {
        "function": oneinfinity_validate,
        "description": "Validate finding (false positive check with active re-testing)",
        "parameters": {
            "finding_id": {"type": "string", "default": None},
            "exploit_id": {"type": "string", "default": None}
        }
    },
    "oneinfinity_report": {
        "function": oneinfinity_report,
        "description": "Generate HackerOne/Bugcrowd security report",
        "parameters": {
            "scan_id": {"type": "string", "default": None},
            "finding_ids": {"type": "array", "default": None},
            "format": {"type": "string", "default": "hackerone"},
            "include_poc": {"type": "boolean", "default": True}
        }
    },
    "oneinfinity_graph_query": {
        "function": oneinfinity_graph_query,
        "description": "Query attack graph for paths/chains (Neo4j-backed)",
        "parameters": {
            "query": {"type": "string", "required": True},
            "target": {"type": "string", "default": None}
        }
    },
    "oneinfinity_mobile_analyze": {
        "function": oneinfinity_mobile_analyze,
        "description": "Analyze Android APK for security issues",
        "parameters": {
            "apk_path": {"type": "string", "required": True},
            "deep_analysis": {"type": "boolean", "default": True}
        }
    }
}


def _register_platform_tools() -> None:
    """Register HackerOne/Bugcrowd MCP tools into the TOOLS dict."""
    try:
        from oneinfinity.mcp.hackerone_mcp_tool import MCP_TOOLS
        for spec in MCP_TOOLS:
            TOOLS[spec["name"]] = {
                "function": spec["fn"],
                "description": spec["description"],
                "parameters": spec["parameters"],
            }
        log.debug("Registered %d platform API tools", len(MCP_TOOLS))
    except Exception as exc:
        log.warning("Platform API tools unavailable: %s", exc)


_register_platform_tools()


def get_tool_manifest() -> Dict[str, Any]:
    """Return MCP tool manifest for registration."""
    return {
        "name": "oneinfinity",
        "version": "1.0.0",
        "description": "Autonomous offensive security research platform",
        "tools": [
            {
                "name": name,
                "description": meta["description"],
                "parameters": meta["parameters"]
            }
            for name, meta in TOOLS.items()
        ]
    }


def call_tool(tool_name: str, parameters: Dict[str, Any]) -> Dict[str, Any]:
    """Execute MCP tool call."""
    if tool_name not in TOOLS:
        return {"error": f"Unknown tool: {tool_name}"}

    tool_func = TOOLS[tool_name]["function"]

    try:
        result = tool_func(**parameters)
        return result
    except Exception as e:
        log.exception(f"Tool {tool_name} failed")
        return {
            "error": str(e),
            "tool": tool_name,
            "parameters": parameters
        }


# ── CLI Entry Point ───────────────────────────────────────────────────────────

def main():
    """MCP server main entry point (direct invocation)."""
    import argparse

    parser = argparse.ArgumentParser(description="OneInfinity MCP Server")
    parser.add_argument("--manifest", action="store_true", help="Print tool manifest")
    parser.add_argument("--tool", help="Tool name to execute")
    parser.add_argument("--params", help="Tool parameters (JSON)")
    parser.add_argument("--serve", action="store_true", help="Start HTTP server (deprecated, use CLI)")

    args = parser.parse_args()

    if args.manifest:
        print(json.dumps(get_tool_manifest(), indent=2))
    elif args.tool:
        params = json.loads(args.params) if args.params else {}
        result = call_tool(args.tool, params)
        print(json.dumps(result, indent=2))
    elif args.serve:
        print("  [!] Use 'oneinfinity mcp-server --serve' instead", file=sys.stderr)
        sys.exit(1)
    else:
        parser.print_help()


if __name__ == "__main__":
    main()
