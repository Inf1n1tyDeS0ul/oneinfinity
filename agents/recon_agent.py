"""
Recon Agent — subdomain enumeration, HTTP probing, URL discovery, port scanning.
"""

from __future__ import annotations

import json
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path

from path_manager import resolve_output_dir

from agents.base import BaseAgent, Task, TaskResult


class ReconAgent(BaseAgent):
    AGENT_ID = "recon_agent"
    DESCRIPTION = "Subdomain enumeration, HTTP probing, URL discovery, port scanning"
    SPECIALIZATIONS = [
        "recon", "subdomain_enum", "http_probe",
        "port_scan", "url_discovery", "dns_resolve",
    ]

    def execute_task(self, task: Task) -> TaskResult:
        handler = {
            "recon":           self._full_recon,
            "subdomain_enum":  self._subdomain_enum,
            "http_probe":      self._http_probe,
            "port_scan":       self._port_scan,
            "url_discovery":   self._url_discovery,
            "dns_resolve":     self._dns_resolve,
        }.get(task.task_type, self._full_recon)

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

    # ── Full recon (orchestrates all sub-tasks) ───────────────────────────────

    def _full_recon(self, task: Task):
        target = task.target
        out_dir = resolve_output_dir(task.context.get("output_dir"), target)
        out_dir.mkdir(parents=True, exist_ok=True)
        all_data = {}
        tools_used = []

        # Step 1: Subdomain enum (must complete before HTTP probe)
        _, _, t = self._subdomain_enum(task)
        tools_used.extend(t)
        if self.is_aborted():
            return all_data, [], tools_used

        # Step 2 & 3: HTTP probe + URL discovery run in parallel
        # URL discovery (waybackurls/gauplus) is network-bound and independent of httpx
        with ThreadPoolExecutor(max_workers=2) as pool:
            futures = {
                pool.submit(self._http_probe, task):    "http_probe",
                pool.submit(self._url_discovery, task): "url_discovery",
            }
            for future in as_completed(futures):
                if self.is_aborted():
                    break
                try:
                    _, _, t = future.result()
                    tools_used.extend(t)
                except Exception as exc:
                    self.log(f"{futures[future]} failed: {exc}", "warn")

        return all_data, [], list(set(tools_used))

    # ── Subdomain enumeration ─────────────────────────────────────────────────

    def _subdomain_enum(self, task: Task):
        target = task.target
        found: set[str] = set()
        tools_used = []
        out_dir = resolve_output_dir(task.context.get("output_dir"), target)
        out_dir.mkdir(parents=True, exist_ok=True)

        tool_order = ["subfinder", "assetfinder", "findomain", "amass", "sublist3r", "chaos"]
        for tool in tool_order:
            if self.is_aborted():
                break
            if not self.tool_available(tool):
                continue
            self.log(f"Subdomain enum via {tool}...")
            d = self.run_tool(tool, domain=target, timeout=120)
            subs = d.get("subdomains", []) if isinstance(d, dict) else []
            before = len(found)
            found.update(subs)
            self.log(f"{tool}: +{len(found)-before} subdomains", "ok")
            tools_used.append(tool)

        # crt.sh fallback (no tool needed)
        if not self.is_aborted():
            try:
                crt_subs = self._crtsh_lookup(target)
                before = len(found)
                found.update(crt_subs)
                self.log(f"crt.sh: +{len(found)-before} subdomains", "ok")
            except Exception as e:
                self.log(f"crt.sh failed: {e}", "warn")

        found.add(target)
        subs_list = sorted(found)
        out_file = out_dir / "subdomains.json"
        out_file.write_text(json.dumps(subs_list, indent=2))
        self.log(f"Total subdomains: {len(subs_list)}", "ok")

        # Update attack graph
        if self.attack_graph:
            for sub in subs_list:
                self.attack_graph.add_subdomain(sub)

        return {"subdomains": subs_list}, [], tools_used

    def _crtsh_lookup(self, domain: str) -> list[str]:
        import urllib.request, urllib.parse
        url = f"https://crt.sh/?q=%.{urllib.parse.quote(domain)}&output=json"
        req = urllib.request.Request(url, headers={"User-Agent": "OneInfinity/1.0"})
        with urllib.request.urlopen(req, timeout=20) as resp:
            data = json.loads(resp.read())
        subs = set()
        for entry in data:
            for name in entry.get("name_value", "").splitlines():
                name = name.strip().lstrip("*.")
                if name.endswith(f".{domain}"):
                    subs.add(name.lower())
        return list(subs)

    # ── HTTP probing ──────────────────────────────────────────────────────────

    def _http_probe(self, task: Task):
        target = task.target
        out_dir = resolve_output_dir(task.context.get("output_dir"), target)

        # Load subdomains
        subs_file = out_dir / "subdomains.json"
        subs = [target]
        if subs_file.exists():
            try:
                subs = json.loads(subs_file.read_text())
            except Exception:
                pass

        if not self.tool_available("httpx"):
            self.log("httpx not available — skipping HTTP probe", "warn")
            return {}, [], []

        self.log(f"Probing {len(subs)} hosts with httpx...")
        d = self.run_tool("httpx", targets=subs, timeout=180)
        hosts = d.get("hosts", []) if isinstance(d, dict) else []

        out_file = out_dir / "alive_hosts.json"
        out_file.write_text(json.dumps({"hosts": hosts}, indent=2))
        self.log(f"Alive hosts: {len(hosts)}", "ok")

        if self.attack_graph:
            for h in hosts:
                url = h.get("url", "")
                tech = h.get("tech", [])
                self.attack_graph.add_host(url, h.get("status-code", 0), tech)

        return {"hosts": hosts}, [], ["httpx"]

    # ── Port scanning ─────────────────────────────────────────────────────────

    def _port_scan(self, task: Task):
        target = task.target
        out_dir = resolve_output_dir(task.context.get("output_dir"), target)
        tool = self.best_tool("naabu", "rustscan", "nmap")
        if not tool:
            self.log("No port scanner available", "warn")
            return {}, [], []

        self.log(f"Port scanning {target} via {tool}...")
        d = self.run_tool(tool, target=target, timeout=180)
        ports = d.get("open_ports", []) if isinstance(d, dict) else []

        out_file = out_dir / "ports.json"
        out_file.write_text(json.dumps(ports, indent=2))
        self.log(f"Open ports: {len(ports)}", "ok")

        if self.attack_graph:
            for p in ports:
                self.attack_graph.add_service(
                    target, p.get("port", 0),
                    p.get("service", ""), p.get("version", "")
                )

        return {"open_ports": ports}, [], [tool]

    # ── URL discovery ─────────────────────────────────────────────────────────

    def _url_discovery(self, task: Task):
        target = task.target
        out_dir = resolve_output_dir(task.context.get("output_dir"), target)
        all_urls: set[str] = set()
        tools_used = []

        # Historical
        for tool in ["gauplus", "waybackurls"]:
            if self.is_aborted() or not self.tool_available(tool):
                continue
            self.log(f"Historical URLs via {tool}...")
            d = self.run_tool(tool, domain=target, timeout=90)
            urls = d.get("urls", []) if isinstance(d, dict) else []
            all_urls.update(urls)
            tools_used.append(tool)
            self.log(f"{tool}: +{len(urls)} URLs", "ok")

        # Active crawl
        crawl_tool = self.best_tool("katana", "hakrawler")
        if crawl_tool and not self.is_aborted():
            self.log(f"Active crawling via {crawl_tool}...")
            if crawl_tool == "katana":
                d = self.run_tool("katana", target=f"https://{target}", timeout=200)
            else:
                d = self.run_tool("hakrawler", url=f"https://{target}", timeout=120)
            urls = d.get("urls", []) if isinstance(d, dict) else []
            all_urls.update(urls)
            tools_used.append(crawl_tool)
            self.log(f"{crawl_tool}: +{len(urls)} URLs", "ok")

        urls_list = sorted(all_urls)
        endpoints = [u for u in urls_list if "?" in u]
        (out_dir / "urls.json").write_text(json.dumps(urls_list, indent=2))
        (out_dir / "endpoints.json").write_text(json.dumps(endpoints, indent=2))
        self.log(f"Total URLs: {len(urls_list)}, endpoints: {len(endpoints)}", "ok")

        return {"urls": urls_list, "endpoints": endpoints}, [], tools_used

    # ── DNS resolution ────────────────────────────────────────────────────────

    def _dns_resolve(self, task: Task):
        target = task.target
        out_dir = resolve_output_dir(task.context.get("output_dir"), target)

        if not self.tool_available("dnsx"):
            self.log("dnsx not available — skipping DNS resolve", "warn")
            return {}, [], []

        subs_file = out_dir / "subdomains.json"
        domains = [target]
        if subs_file.exists():
            try:
                domains = json.loads(subs_file.read_text())
            except Exception:
                pass

        self.log(f"Resolving {len(domains)} domains via dnsx...")
        d = self.run_tool("dnsx", domains=domains[:500], timeout=60)
        records = d.get("records", []) if isinstance(d, dict) else []

        self.log(f"DNS records: {len(records)}", "ok")
        return {"dns_records": records}, [], ["dnsx"]
