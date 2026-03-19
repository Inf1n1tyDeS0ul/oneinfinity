"""
Scan Agent — Vulnerability discovery: nuclei, dalfox, sqlmap, crlfuzz, nikto, etc.
Uses gf patterns to triage candidates before expensive tools.
"""

from __future__ import annotations

import json
from pathlib import Path

from path_manager import resolve_output_dir

from agents.base import BaseAgent, Task, TaskResult


class ScanAgent(BaseAgent):
    AGENT_ID = "scan_agent"
    DESCRIPTION = "Vulnerability scanning: nuclei, dalfox, sqlmap, crlfuzz, nikto, kxss"
    SPECIALIZATIONS = [
        "scan", "scan_xss", "scan_sqli", "scan_ssrf",
        "scan_nuclei", "scan_headers", "scan_cors", "scan_secrets",
        "triage",
    ]

    def execute_task(self, task: Task) -> TaskResult:
        handler = {
            "scan":         self._full_scan,
            "scan_nuclei":  self._scan_nuclei,
            "scan_xss":     self._scan_xss,
            "scan_sqli":    self._scan_sqli,
            "scan_ssrf":    self._scan_ssrf,
            "scan_secrets": self._scan_secrets,
            "triage":       self._triage,
        }.get(task.task_type, self._full_scan)

        data, findings, tools = handler(task)
        return TaskResult(
            task_id=task.task_id,
            agent_id=self.agent_id,
            task_type=task.task_type,
            target=task.target,
            success=True,
            data=data,
            findings=findings,
            tools_used=tools,
        )

    def _load_urls(self, out_dir: Path, task: Task) -> tuple[list, list]:
        """Load urls + endpoints from disk or task context."""
        urls = task.context.get("urls", [])
        endpoints = task.context.get("endpoints", [])
        if not urls:
            f = out_dir / "urls.json"
            if f.exists():
                try:
                    urls = json.loads(f.read_text())
                except (json.JSONDecodeError, OSError):
                    urls = []
        if not endpoints:
            f = out_dir / "endpoints.json"
            if f.exists():
                try:
                    endpoints = json.loads(f.read_text())
                except (json.JSONDecodeError, OSError):
                    endpoints = []
        # Fallback: derive endpoints from urls
        if not endpoints and urls:
            endpoints = [u for u in urls if "?" in u]
        return urls, endpoints

    def _load_alive_hosts(self, out_dir: Path, task: Task) -> list[str]:
        hosts = task.context.get("alive_hosts", [])
        if not hosts:
            f = out_dir / "alive_hosts.json"
            if f.exists():
                data = json.loads(f.read_text())
                if isinstance(data, dict):
                    hosts = [h.get("url", "") for h in data.get("hosts", [])]
                elif isinstance(data, list):
                    hosts = [h.get("url", h) if isinstance(h, dict) else h for h in data]
        return [h for h in hosts if h]

    # ── GF triage ─────────────────────────────────────────────────────────────

    def _triage(self, task: Task):
        out_dir = resolve_output_dir(task.context.get("output_dir"), task.target)
        urls, endpoints = self._load_urls(out_dir, task)
        all_urls = list(set(urls + endpoints))

        if not self.tool_available("gf"):
            self.log("gf not available — returning all endpoints as candidates", "warn")
            return {
                "sqli_candidates": [u for u in endpoints if "id=" in u.lower()],
                "xss_candidates": endpoints,
                "ssrf_candidates": [u for u in endpoints if any(
                    p in u.lower() for p in ["url=", "redirect=", "uri="])],
            }, [], []

        patterns = ["sqli", "xss", "ssrf", "redirect", "rce", "idor", "lfi", "ssti", "debug"]
        candidates = {}
        tools_used = ["gf"]

        for pattern in patterns:
            if self.is_aborted():
                break
            d = self.run_tool("gf", urls=all_urls, pattern=pattern, timeout=15)
            matches = d.get("matches", []) if isinstance(d, dict) else []
            candidates[f"{pattern}_candidates"] = matches
            if matches:
                self.log(f"gf {pattern}: {len(matches)} candidates", "ok")

        # kxss for reflected XSS detection
        if self.tool_available("kxss") and candidates.get("xss_candidates"):
            self.log("kxss reflected-char check...")
            d = self.run_tool("kxss", urls=candidates["xss_candidates"][:200], timeout=90)
            reflected = d.get("reflected", []) if isinstance(d, dict) else []
            candidates["xss_reflected"] = reflected
            if reflected:
                self.log(f"kxss: {len(reflected)} reflected", "ok")
                tools_used.append("kxss")

        # Save triage results
        (out_dir / "triage.json").write_text(json.dumps(candidates, indent=2))
        return candidates, [], tools_used

    # ── Full scan ─────────────────────────────────────────────────────────────

    def _full_scan(self, task: Task):
        target = task.target
        out_dir = resolve_output_dir(task.context.get("output_dir"), target)
        all_findings = []
        tools_used = []

        # First triage
        triage_data, _, t = self._triage(task)
        tools_used.extend(t)
        task.context.update(triage_data)

        for scan_type in ["scan_nuclei", "scan_xss", "scan_sqli", "scan_secrets"]:
            if self.is_aborted():
                break
            sub_task = Task(
                task_id=f"{task.task_id}:{scan_type}",
                task_type=scan_type,
                target=target,
                context=task.context,
            )
            _, findings, t = getattr(self, f"_{scan_type.replace('-', '_')}")(sub_task)
            all_findings.extend(findings)
            tools_used.extend(t)

        (out_dir / "findings.json").write_text(json.dumps(all_findings, indent=2))
        self.log(f"Total findings: {len(all_findings)}", "ok")
        return {"findings": all_findings}, all_findings, list(set(tools_used))

    # ── Nuclei ────────────────────────────────────────────────────────────────

    def _scan_nuclei(self, task: Task):
        out_dir = resolve_output_dir(task.context.get("output_dir"), task.target)
        alive = self._load_alive_hosts(out_dir, task)
        target_url = alive[0] if alive else f"https://{task.target}"
        tools_used = []

        if not self.tool_available("nuclei"):
            self.log("nuclei not available", "warn")
            return {}, [], []

        severity = task.context.get("nuclei_severity", "info,low,medium,high,critical")
        # Scan ALL alive hosts, not just the first one
        scan_targets = [h.get("url", h) if isinstance(h, dict) else h
                        for h in alive[:10]] or [f"https://{task.target}"]
        self.log(f"nuclei scan on {len(scan_targets)} host(s) ({severity})...")

        all_findings: list[dict] = []
        for scan_target in scan_targets:
            if self.is_aborted():
                break
            d = self.run_tool("nuclei", target=scan_target, severity=severity, timeout=600)
            host_findings = d.get("findings", []) if isinstance(d, dict) else []
            for f in host_findings:
                f["source_tool"] = "nuclei"
                f["agent"] = self.agent_id
            all_findings.extend(host_findings)
        findings = all_findings
        tools_used.append("nuclei")

        # Single combined tag pass — run all tags together for efficiency
        nuclei_tags = task.context.get("nuclei_tags", [
            "xss", "ssrf", "cors", "lfi", "ssti",
            "sqli", "rce", "open-redirect", "xxe", "crlf",
            "auth-bypass", "exposed-panel", "misconfig",
            "takeover", "exposure", "cloud", "jwt", "oauth",
        ])
        combined_tags = ",".join(nuclei_tags)
        primary_target = scan_targets[0] if scan_targets else f"https://{task.target}"
        if not self.is_aborted():
            self.log(f"nuclei combined tags scan ({len(nuclei_tags)} tags)...")
            d2 = self.run_tool("nuclei", target=primary_target,
                                templates=combined_tags, severity=severity,
                                timeout=600)
            tag_findings = d2.get("findings", []) if isinstance(d2, dict) else []
            for f in tag_findings:
                f["source_tool"] = "nuclei:tags"
                f["agent"] = self.agent_id
            findings.extend(tag_findings)

        self.log(f"nuclei: {len(findings)} findings", "ok")
        if self.attack_graph:
            for f in findings:
                self.attack_graph.add_vulnerability(
                    vuln_id=f.get("template_id", f"nuclei_{id(f)}"),
                    vuln_type=f.get("name", f.get("template_id", "unknown")),
                    host=f.get("host", task.target),
                    endpoint=f.get("matched_at", ""),
                    severity=f.get("severity", "info"),
                    evidence=f.get("description", ""),
                    confidence="medium",
                )

        return {"findings": findings}, findings, tools_used

    # ── XSS ──────────────────────────────────────────────────────────────────

    def _scan_xss(self, task: Task):
        out_dir = resolve_output_dir(task.context.get("output_dir"), task.target)
        candidates = task.context.get("xss_candidates", []) or \
                     task.context.get("xss_reflected", [])
        tools_used = []
        findings = []

        if not candidates:
            urls, endpoints = self._load_urls(out_dir, task)
            candidates = [u for u in endpoints if "?" in u][:20]

        if not candidates:
            return {}, [], []

        # dalfox — best XSS tool
        xss_limit = task.context.get("xss_candidate_limit", 15)
        if self.tool_available("dalfox") and not self.is_aborted():
            self.log(f"dalfox on {min(len(candidates), xss_limit)} XSS candidates...")
            for url in candidates[:xss_limit]:
                d = self.run_tool("dalfox", url=url, timeout=120)
                for f in d.get("findings", []) if isinstance(d, dict) else []:
                    f.update({"source_tool": "dalfox", "agent": self.agent_id,
                               "vuln_type": "XSS", "severity": "high"})
                    findings.append(f)
            tools_used.append("dalfox")

        # xssstrike as backup
        if self.tool_available("xssstrike") and not findings and not self.is_aborted():
            self.log("xssstrike XSS scan...")
            for url in candidates[:3]:
                d = self.run_tool("xssstrike", url=url, timeout=120)
                for f in d.get("findings", []) if isinstance(d, dict) else []:
                    f.update({"source_tool": "xssstrike", "agent": self.agent_id,
                               "vuln_type": "XSS", "severity": "high"})
                    findings.append(f)
            tools_used.append("xssstrike")

        self.log(f"XSS scan: {len(findings)} findings", "ok" if findings else "info")
        return {"xss_findings": findings}, findings, tools_used

    # ── SQLi ──────────────────────────────────────────────────────────────────

    def _scan_sqli(self, task: Task):
        candidates = task.context.get("sqli_candidates", [])
        out_dir = resolve_output_dir(task.context.get("output_dir"), task.target)
        tools_used = []
        findings = []

        if not candidates:
            _, endpoints = self._load_urls(out_dir, task)
            # Heuristic: URLs with id=, user=, query= etc.
            candidates = [u for u in endpoints if any(
                p in u.lower() for p in ["id=", "user=", "query=", "search=", "name=", "cat="]
            )][:5]

        sqli_limit = task.context.get("sqli_candidate_limit", 10)
        if not candidates or not self.tool_available("sqlmap"):
            return {}, [], []

        self.log(f"sqlmap on {min(len(candidates), sqli_limit)} SQLi candidates...")
        for url in candidates[:sqli_limit]:
            if self.is_aborted():
                break
            d = self.run_tool("sqlmap", url=url, level=1, risk=1, timeout=300)
            if isinstance(d, dict) and d.get("is_vulnerable"):
                f = {
                    "source_tool": "sqlmap",
                    "agent": self.agent_id,
                    "vuln_type": "SQL Injection",
                    "severity": "high",
                    "url": url,
                    "parameters": d.get("vulnerable_parameters", []),
                    "injection_types": d.get("injection_types", []),
                    "matched_at": url,
                }
                findings.append(f)
                if self.attack_graph:
                    host = url.split("//")[1].split("/")[0] if "//" in url else task.target
                    self.attack_graph.add_vulnerability(
                        vuln_id=f"sqli_{url[:30]}",
                        vuln_type="SQL Injection",
                        host=host, endpoint=url, severity="high",
                        evidence=f"SQLMap: parameters={d.get('vulnerable_parameters', [])}",
                    )
        tools_used.append("sqlmap")
        self.log(f"SQLi scan: {len(findings)} findings", "ok" if findings else "info")
        return {"sqli_findings": findings}, findings, tools_used

    # ── SSRF ──────────────────────────────────────────────────────────────────

    def _scan_ssrf(self, task: Task):
        candidates = task.context.get("ssrf_candidates", [])
        if not candidates or not self.tool_available("nuclei"):
            return {}, [], []
        self.log(f"SSRF-focused nuclei on {len(candidates[:3])} candidates...")
        findings = []
        for url in candidates[:3]:
            if self.is_aborted():
                break
            d = self.run_tool("nuclei", target=url, templates="ssrf",
                               severity="medium,high,critical", timeout=120)
            for f in d.get("findings", []) if isinstance(d, dict) else []:
                f.update({"source_tool": "nuclei:ssrf", "agent": self.agent_id})
                findings.append(f)
        return {"ssrf_findings": findings}, findings, ["nuclei"]

    # ── Secrets ───────────────────────────────────────────────────────────────

    def _scan_secrets(self, task: Task):
        out_dir = resolve_output_dir(task.context.get("output_dir"), task.target)
        findings = []
        tools_used = []

        if self.tool_available("trufflehog"):
            self.log("TruffleHog secrets scan...")
            d = self.run_tool("trufflehog", target=str(out_dir),
                               target_type="filesystem", timeout=180)
            secrets = d.get("secrets", []) if isinstance(d, dict) else []
            for s in secrets:
                f = {
                    "source_tool": "trufflehog",
                    "agent": self.agent_id,
                    "vuln_type": "Secret Exposure",
                    "severity": "critical" if s.get("verified") else "high",
                    "detector": s.get("detector", ""),
                    "verified": s.get("verified", False),
                    "raw": s.get("raw", "")[:50],
                }
                findings.append(f)
                if self.attack_graph:
                    self.attack_graph.add_credential(
                        cred_id=f"th_{id(s)}",
                        cred_type=s.get("detector", "secret"),
                        value_hint=s.get("raw", "")[:20],
                        source_node=f"target:{task.target}",
                    )
            tools_used.append("trufflehog")

        if self.tool_available("gitleaks"):
            self.log("gitleaks scan...")
            d = self.run_tool("gitleaks", target=str(out_dir), timeout=90)
            secrets = d.get("secrets", []) if isinstance(d, dict) else []
            for s in secrets:
                f = {
                    "source_tool": "gitleaks",
                    "agent": self.agent_id,
                    "vuln_type": "Secret Exposure",
                    "severity": "critical",
                    "rule": s.get("rule", ""),
                    "file": s.get("file", ""),
                    "line": s.get("line", 0),
                }
                findings.append(f)
            tools_used.append("gitleaks")

        self.log(f"Secrets scan: {len(findings)} secrets found",
                 "ok" if findings else "info")
        return {"secrets": findings}, findings, tools_used
