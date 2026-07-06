"""
mcp_surface_scanner.py — MCP Protocol Attack Surface Scanner

Discovers MCP endpoints, enumerates tools/resources, and tests for:
  - Tool parameter injection (command, SQL, template, XSS)
  - Resource content poisoning (prompt injection indicators)
  - Prompt injection via resources (IGNORE PREVIOUS INSTRUCTIONS, etc.)
"""
from __future__ import annotations

import json
import logging
import os
import time
import urllib.error
import urllib.request
import uuid
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional

log = logging.getLogger("oneinfinity.mcp_scanner")


# ─────────────────────────────────────────────────────────────────────────────
#  Data Models
# ─────────────────────────────────────────────────────────────────────────────

@dataclass
class MCPTool:
    name: str
    description: str
    input_schema: dict
    injectable: bool = False


@dataclass
class MCPResource:
    uri: str
    name: str
    mime_type: str
    content_preview: str = ""
    injectable: bool = False


@dataclass
class MCPVulnFinding:
    endpoint: str
    vuln_type: str
    tool_name: str
    payload: str
    evidence: str
    severity: str


@dataclass
class MCPScanResult:
    target: str
    endpoints_found: List[str] = field(default_factory=list)
    tools: List[MCPTool] = field(default_factory=list)
    resources: List[MCPResource] = field(default_factory=list)
    vulnerabilities: List[MCPVulnFinding] = field(default_factory=list)
    scan_id: str = field(default_factory=lambda: uuid.uuid4().hex[:12])

    def to_dict(self) -> Dict[str, Any]:
        return {
            "target": self.target,
            "scan_id": self.scan_id,
            "endpoints_found": self.endpoints_found,
            "tools": [
                {
                    "name": t.name,
                    "description": t.description,
                    "input_schema": t.input_schema,
                    "injectable": t.injectable,
                }
                for t in self.tools
            ],
            "resources": [
                {
                    "uri": r.uri,
                    "name": r.name,
                    "mime_type": r.mime_type,
                    "content_preview": r.content_preview,
                    "injectable": r.injectable,
                }
                for r in self.resources
            ],
            "vulnerabilities": [
                {
                    "endpoint": v.endpoint,
                    "vuln_type": v.vuln_type,
                    "tool_name": v.tool_name,
                    "payload": v.payload,
                    "evidence": v.evidence,
                    "severity": v.severity,
                }
                for v in self.vulnerabilities
            ],
        }


# ─────────────────────────────────────────────────────────────────────────────
#  Injection payloads and poison indicators
# ─────────────────────────────────────────────────────────────────────────────

_INJECTION_PAYLOADS = [
    "; ls -la",
    "' OR '1'='1",
    "{{7*7}}",
    "<script>alert(1)</script>",
    '__import__("os").system("id")',
]

# Evidence strings that indicate successful command/template injection
_INJECTION_EVIDENCE = [
    "49",           # 7*7 evaluated
    "uid=",         # id command output
    "root:",        # /etc/passwd
    "<script>",     # reflected XSS
    "drwx",         # ls -la output
    "total ",       # ls -la header
    "syntax error",
    "traceback",
    "exception",
    "sql",
    "mysql",
    "postgres",
    "sqlite",
    "ora-",         # Oracle errors
]

_PROMPT_INJECTION_INDICATORS = [
    "IGNORE PREVIOUS INSTRUCTIONS",
    "ignore previous instructions",
    "You are now",
    "you are now",
    "SYSTEM PROMPT",
    "system prompt",
    "Forget everything",
    "forget everything",
    "DAN mode",
    "jailbreak",
    "JAILBREAK",
    "new instructions",
    "NEW INSTRUCTIONS",
    "override",
    "OVERRIDE",
    "act as",
    "ACT AS",
    "pretend you",
    "PRETEND YOU",
    "disregard",
    "DISREGARD",
]


# ─────────────────────────────────────────────────────────────────────────────
#  Scanner
# ─────────────────────────────────────────────────────────────────────────────

class MCPSurfaceScanner:
    """
    Discovers and attacks the MCP HTTP attack surface of a target host.

    Usage:
        scanner = MCPSurfaceScanner(timeout=10)
        result = scanner.scan("http://target:8080")
    """

    MCP_PATHS: List[str] = [
        "/mcp",
        "/api/mcp",
        "/v1/mcp",
        "/mcp/v1",
    ]

    MCP_PATH_TEMPLATES: List[str] = [f"/level/{n}/mcp" for n in range(1, 20)]

    def __init__(
        self,
        model_orchestrator: Optional[Any] = None,
        timeout: int = 10,
    ) -> None:
        self.model_orchestrator = model_orchestrator
        self.timeout = timeout

    # ── Public entry point ────────────────────────────────────────────────────

    def scan(self, target: str, scan_id: str = "") -> MCPScanResult:
        """Full MCP surface scan against *target* (e.g. 'http://host:port')."""
        if not scan_id:
            scan_id = uuid.uuid4().hex[:12]

        result = MCPScanResult(target=target, scan_id=scan_id)

        # 1. Discover endpoints
        endpoints = self._discover_mcp_endpoints(target)
        result.endpoints_found = endpoints
        log.info("[mcp_scanner] %d endpoints found on %s", len(endpoints), target)

        for ep in endpoints:
            try:
                session = self._init_mcp_session(ep)
                if not session:
                    continue

                tools = self._list_tools(session)
                resources = self._list_resources(session)

                result.tools.extend(tools)
                result.resources.extend(resources)

                vulns: List[MCPVulnFinding] = []
                vulns.extend(self._test_tool_injection(session, tools))
                vulns.extend(self._test_resource_poisoning(session, resources))
                vulns.extend(
                    self._test_prompt_injection_via_resources(session, resources)
                )
                result.vulnerabilities.extend(vulns)

                log.info(
                    "[mcp_scanner] ep=%s tools=%d resources=%d vulns=%d",
                    ep,
                    len(tools),
                    len(resources),
                    len(vulns),
                )
            except Exception as exc:
                log.debug("[mcp_scanner] error processing %s: %s", ep, exc)

        return result

    # ── Discovery ─────────────────────────────────────────────────────────────

    def _discover_mcp_endpoints(self, target: str) -> List[str]:
        """Probe well-known MCP paths; return those that respond with a valid
        MCP initialize result (result.protocolVersion present)."""
        candidates = self.MCP_PATHS + self.MCP_PATH_TEMPLATES
        target = target.rstrip("/")
        found: List[str] = []

        init_payload = {
            "jsonrpc": "2.0",
            "method": "initialize",
            "params": {
                "protocolVersion": "2024-11-05",
                "capabilities": {},
                "clientInfo": {"name": "probe", "version": "1.0"},
            },
            "id": 1,
        }

        for path in candidates:
            ep = target + path
            try:
                resp = self._send_mcp_request(ep, init_payload)
                if (
                    isinstance(resp, dict)
                    and "result" in resp
                    and isinstance(resp["result"], dict)
                    and "protocolVersion" in resp["result"]
                ):
                    found.append(ep)
                    log.debug("[mcp_scanner] valid MCP endpoint: %s", ep)
            except Exception:
                pass  # connection refused, timeout, non-JSON — all expected

        return found

    # ── Session ───────────────────────────────────────────────────────────────

    def _init_mcp_session(self, endpoint: str) -> Dict[str, Any]:
        """Send initialize and return session metadata dict."""
        payload = {
            "jsonrpc": "2.0",
            "method": "initialize",
            "params": {
                "protocolVersion": "2024-11-05",
                "capabilities": {},
                "clientInfo": {"name": "probe", "version": "1.0"},
            },
            "id": 1,
        }
        try:
            resp = self._send_mcp_request(endpoint, payload)
            result = resp.get("result", {})
            return {
                "endpoint": endpoint,
                "protocolVersion": result.get("protocolVersion", ""),
                "serverInfo": result.get("serverInfo", {}),
                "capabilities": result.get("capabilities", {}),
            }
        except Exception as exc:
            log.debug("[mcp_scanner] init_session failed for %s: %s", endpoint, exc)
            return {}

    # ── Tool/resource enumeration ─────────────────────────────────────────────

    def _list_tools(self, session: dict) -> List[MCPTool]:
        ep = session.get("endpoint", "")
        if not ep:
            return []
        payload = {"jsonrpc": "2.0", "method": "tools/list", "params": {}, "id": 2}
        try:
            resp = self._send_mcp_request(ep, payload)
            raw_tools = resp.get("result", {}).get("tools", [])
            tools: List[MCPTool] = []
            for t in raw_tools:
                tools.append(
                    MCPTool(
                        name=t.get("name", ""),
                        description=t.get("description", ""),
                        input_schema=t.get("inputSchema", t.get("input_schema", {})),
                    )
                )
            return tools
        except Exception as exc:
            log.debug("[mcp_scanner] list_tools failed for %s: %s", ep, exc)
            return []

    def _list_resources(self, session: dict) -> List[MCPResource]:
        ep = session.get("endpoint", "")
        if not ep:
            return []
        payload = {
            "jsonrpc": "2.0",
            "method": "resources/list",
            "params": {},
            "id": 3,
        }
        try:
            resp = self._send_mcp_request(ep, payload)
            raw = resp.get("result", {}).get("resources", [])
            resources: List[MCPResource] = []
            for r in raw:
                resources.append(
                    MCPResource(
                        uri=r.get("uri", ""),
                        name=r.get("name", ""),
                        mime_type=r.get("mimeType", r.get("mime_type", "")),
                    )
                )
            return resources
        except Exception as exc:
            log.debug("[mcp_scanner] list_resources failed for %s: %s", ep, exc)
            return []

    # ── Vulnerability tests ───────────────────────────────────────────────────

    def _test_tool_injection(
        self, session: dict, tools: List[MCPTool]
    ) -> List[MCPVulnFinding]:
        """Inject payloads into every string parameter of every tool."""
        ep = session.get("endpoint", "")
        findings: List[MCPVulnFinding] = []

        for tool in tools:
            schema = tool.input_schema or {}
            properties = schema.get("properties", {})
            if not properties:
                # Try a single generic string arg named 'input'
                properties = {"input": {"type": "string"}}

            # Collect string-type parameter names
            str_params = [
                name
                for name, defn in properties.items()
                if isinstance(defn, dict) and defn.get("type") == "string"
            ] or list(properties.keys())[:1]  # fall back to first key

            for param in str_params:
                for payload in _INJECTION_PAYLOADS:
                    args = {param: payload}
                    try:
                        call_payload = {
                            "jsonrpc": "2.0",
                            "method": "tools/call",
                            "params": {"name": tool.name, "arguments": args},
                            "id": 10,
                        }
                        resp = self._send_mcp_request(ep, call_payload)
                        resp_str = json.dumps(resp).lower()

                        evidence = self._detect_injection_evidence(resp_str, payload)
                        if evidence:
                            tool.injectable = True
                            severity = self._injection_severity(payload)
                            findings.append(
                                MCPVulnFinding(
                                    endpoint=ep,
                                    vuln_type="tool_injection",
                                    tool_name=tool.name,
                                    payload=payload,
                                    evidence=evidence,
                                    severity=severity,
                                )
                            )
                            log.warning(
                                "[mcp_scanner] INJECTION tool=%s param=%s payload=%r",
                                tool.name,
                                param,
                                payload[:40],
                            )
                    except Exception:
                        pass

        return findings

    def _test_resource_poisoning(
        self, session: dict, resources: List[MCPResource]
    ) -> List[MCPVulnFinding]:
        """Read each resource and check for embedded prompt injection strings."""
        findings: List[MCPVulnFinding] = []

        for resource in resources:
            content = self._read_resource(session, resource.uri)
            if not content:
                continue
            resource.content_preview = content[:300]
            for indicator in _PROMPT_INJECTION_INDICATORS:
                if indicator in content:
                    resource.injectable = True
                    findings.append(
                        MCPVulnFinding(
                            endpoint=session.get("endpoint", ""),
                            vuln_type="resource_poisoning",
                            tool_name=f"resource:{resource.uri}",
                            payload=indicator,
                            evidence=f"Resource content contains prompt injection indicator: {indicator!r}",
                            severity="high",
                        )
                    )
                    log.warning(
                        "[mcp_scanner] RESOURCE POISONING uri=%s indicator=%r",
                        resource.uri,
                        indicator,
                    )
                    break  # one finding per resource is enough

        return findings

    def _test_prompt_injection_via_resources(
        self, session: dict, resources: List[MCPResource]
    ) -> List[MCPVulnFinding]:
        """
        Deep scan: look for instruction-override strings buried deeper in content
        (case-insensitive, multi-line).  Returns findings not already caught by
        _test_resource_poisoning (which does exact-case matching).
        """
        findings: List[MCPVulnFinding] = []
        ep = session.get("endpoint", "")

        soft_indicators = [
            "ignore all previous",
            "ignore prior instructions",
            "new persona",
            "your new role",
            "do not follow",
            "bypass your",
            "you must now",
            "your real instructions",
            "secret instructions",
        ]

        for resource in resources:
            content = self._read_resource(session, resource.uri)
            if not content:
                continue
            lower = content.lower()
            for indicator in soft_indicators:
                if indicator in lower:
                    resource.injectable = True
                    idx = lower.find(indicator)
                    snippet = content[max(0, idx - 20) : idx + len(indicator) + 60]
                    findings.append(
                        MCPVulnFinding(
                            endpoint=ep,
                            vuln_type="prompt_injection_via_resource",
                            tool_name=f"resource:{resource.uri}",
                            payload=indicator,
                            evidence=f"Prompt injection string found in resource: ...{snippet!r}...",
                            severity="critical",
                        )
                    )
                    log.warning(
                        "[mcp_scanner] PROMPT INJECTION VIA RESOURCE uri=%s indicator=%r",
                        resource.uri,
                        indicator,
                    )
                    break

        return findings

    # ── Low-level helpers ─────────────────────────────────────────────────────

    def _read_resource(self, session: dict, uri: str) -> str:
        """Send resources/read and return text content."""
        ep = session.get("endpoint", "")
        if not ep or not uri:
            return ""
        payload = {
            "jsonrpc": "2.0",
            "method": "resources/read",
            "params": {"uri": uri},
            "id": 4,
        }
        try:
            resp = self._send_mcp_request(ep, payload)
            contents = resp.get("result", {}).get("contents", [])
            if isinstance(contents, list) and contents:
                item = contents[0]
                return item.get("text", item.get("blob", ""))
            # Some servers nest differently
            return resp.get("result", {}).get("text", "")
        except Exception as exc:
            log.debug("[mcp_scanner] read_resource %s failed: %s", uri, exc)
            return ""

    def _send_mcp_request(self, endpoint: str, payload: dict) -> dict:
        """Raw JSON-RPC POST helper.  Returns parsed response dict or raises."""
        body = json.dumps(payload).encode()
        req = urllib.request.Request(
            endpoint,
            data=body,
            headers={
                "Content-Type": "application/json",
                "Accept": "application/json",
                "User-Agent": "oneinfinity-mcp-scanner/1.0",
            },
            method="POST",
        )
        try:
            with urllib.request.urlopen(req, timeout=self.timeout) as resp:
                raw = resp.read()
                return json.loads(raw.decode("utf-8", errors="replace"))
        except urllib.error.HTTPError as exc:
            # Still parse the body — MCP errors come as 400/500 with JSON
            try:
                raw = exc.read()
                return json.loads(raw.decode("utf-8", errors="replace"))
            except Exception:
                raise exc
        # urllib.error.URLError (connection refused, timeout) propagates up

    # ── Evidence / severity helpers ───────────────────────────────────────────

    @staticmethod
    def _detect_injection_evidence(resp_lower: str, payload: str) -> str:
        """Return non-empty evidence string if *resp_lower* shows injection success."""
        for indicator in _INJECTION_EVIDENCE:
            if indicator in resp_lower:
                return f"Response contains {indicator!r} after payload {payload[:60]!r}"
        return ""

    @staticmethod
    def _injection_severity(payload: str) -> str:
        if "os" in payload or "system" in payload or "ls -la" in payload:
            return "critical"
        if "OR '1'='1" in payload or "sql" in payload.lower():
            return "high"
        if "{{" in payload:
            return "high"
        if "<script>" in payload:
            return "medium"
        return "medium"

    # ── Persistence ───────────────────────────────────────────────────────────

    def save_result(self, result: MCPScanResult, scan_id: str) -> str:
        """Persist scan result to ~/.oneinfinity/<scan_id>/mcp/scan.json."""
        out_dir = os.path.join(
            os.path.expanduser("~"), ".oneinfinity", scan_id, "mcp"
        )
        os.makedirs(out_dir, exist_ok=True)
        out_path = os.path.join(out_dir, "scan.json")
        with open(out_path, "w") as fh:
            json.dump(result.to_dict(), fh, indent=2)
        log.info("[mcp_scanner] result saved to %s", out_path)
        return out_path
