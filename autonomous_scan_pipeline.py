"""
Autonomous Scan Pipeline — Full discover→recon→endpoints→vuln test→exploit→report
===================================================================================
Chains all engines together into a single autonomous pipeline that runs from
subdomain discovery through vulnerability exploitation and final report generation.

Usage:
    from autonomous_scan_pipeline import autonomous_scan_pipeline
    result = autonomous_scan_pipeline.run("example.com")
    print(result.to_dict())
"""

import asyncio
import json
import time
import logging
import uuid
import urllib.request
import urllib.parse
import urllib.error
import ssl
from dataclasses import dataclass, field, asdict
from enum import Enum
from pathlib import Path
from typing import Optional

from path_manager import raw_dir

logger = logging.getLogger(__name__)


# ── Phase Enum ────────────────────────────────────────────────────────────────

class PipelinePhase(str, Enum):
    DISCOVERY  = "discovery"
    RECON      = "recon"
    CRAWL      = "crawl"
    VULN_SCAN  = "vuln_scan"
    EXPLOIT    = "exploit"
    VALIDATE   = "validate"
    REPORT     = "report"


# ── Data Models ───────────────────────────────────────────────────────────────

@dataclass
class PhaseResult:
    phase: str
    status: str = "pending"          # pending / running / complete / failed / skipped
    duration_s: float = 0.0
    finding_count: int = 0
    error: str = ""
    data: dict = field(default_factory=dict)

    def to_dict(self) -> dict:
        return asdict(self)


@dataclass
class PipelineConfig:
    target: str
    phases: list = field(default_factory=lambda: list(PipelinePhase))
    max_duration_s: int = 3600
    auto_exploit: bool = False
    validate_findings: bool = True
    generate_report: bool = True
    output_dir: str = ""

    def __post_init__(self):
        if not self.output_dir:
            self.output_dir = str(raw_dir() / "pipelines")
        if not self.phases:
            self.phases = list(PipelinePhase)


@dataclass
class ScanPipelineResult:
    target: str
    session_id: str
    phases: dict = field(default_factory=dict)          # phase name → PhaseResult
    findings: list = field(default_factory=list)
    report_path: str = ""
    total_duration_s: float = 0.0
    started_at: str = ""
    completed_at: str = ""

    def to_dict(self) -> dict:
        import datetime
        return {
            "target": self.target,
            "session_id": self.session_id,
            "phases": {k: v.to_dict() for k, v in self.phases.items()},
            "findings": self.findings,
            "report_path": self.report_path,
            "total_duration_s": self.total_duration_s,
            "started_at": self.started_at,
            "completed_at": self.completed_at,
        }

    def save(self, path: str = "") -> str:
        """Persist result as JSON. Returns the path written."""
        if not path:
            out_dir = raw_dir() / "pipelines"
            out_dir.mkdir(parents=True, exist_ok=True)
            path = str(out_dir / f"{self.session_id}.json")
        try:
            Path(path).write_text(json.dumps(self.to_dict(), indent=2, default=str))
            logger.info("Pipeline result saved to %s", path)
        except Exception as exc:
            logger.error("Failed to save pipeline result: %s", exc)
        return path


# ── Helper to build a failed/skipped PhaseResult quickly ─────────────────────

def _make_phase(phase: PipelinePhase, status: str = "skipped",
                duration_s: float = 0.0, finding_count: int = 0,
                error: str = "", data: dict = None) -> PhaseResult:
    return PhaseResult(
        phase=phase.value,
        status=status,
        duration_s=duration_s,
        finding_count=finding_count,
        error=error,
        data=data or {},
    )


# ══════════════════════════════════════════════════════════════════════════════
# MAIN PIPELINE CLASS
# ══════════════════════════════════════════════════════════════════════════════

class AutonomousScanPipeline:
    """
    Full-chain autonomous scan pipeline.

    Chains:
        DISCOVERY → RECON → CRAWL → VULN_SCAN → EXPLOIT → VALIDATE → REPORT

    Every phase is independently guarded — a failure or missing module causes
    that phase to be marked 'failed'/'skipped' but the pipeline continues.
    """

    def __init__(self):
        # Lazily loaded module references
        self._tool_registry = None
        self._adaptive_recon = None
        self._app_crawler = None
        self._validation_engine = None
        self._exploit_engine = None
        self._report_generator = None
        self._ssl_ctx = ssl.create_default_context()
        self._ssl_ctx.check_hostname = False
        self._ssl_ctx.verify_mode = ssl.CERT_NONE
        # In-memory progress log for this run (reset per run)
        self._progress_log: list[dict] = []

    # ── Public Entry Points ───────────────────────────────────────────────────

    def run(self, target: str, config: Optional[PipelineConfig] = None) -> ScanPipelineResult:
        """Synchronous pipeline run. Blocks until complete."""
        import datetime
        if config is None:
            config = PipelineConfig(target=target)

        session_id = str(uuid.uuid4())[:12]
        self._progress_log = []
        pipeline_start = time.time()

        result = ScanPipelineResult(
            target=target,
            session_id=session_id,
            started_at=datetime.datetime.utcnow().isoformat() + "Z",
        )

        self._lazy_load()
        phases_to_run = [p for p in PipelinePhase if p in config.phases]

        logger.info("[pipeline] Starting scan for %s  session=%s", target, session_id)
        self._emit_progress(PipelinePhase.DISCOVERY, "running", f"Pipeline started for {target}")

        # ── Phase data passed between stages ──
        discovery_data: dict = {}
        recon_data: dict = {}
        crawl_data: dict = {}
        all_findings: list = []

        # ── DISCOVERY ─────────────────────────────────────────────────────────
        if PipelinePhase.DISCOVERY in phases_to_run:
            pr = self._run_phase(PipelinePhase.DISCOVERY, self._phase_discovery, target, config)
            result.phases[PipelinePhase.DISCOVERY.value] = pr
            discovery_data = pr.data

        # ── RECON ─────────────────────────────────────────────────────────────
        if PipelinePhase.RECON in phases_to_run:
            pr = self._run_phase(PipelinePhase.RECON, self._phase_recon,
                                 target, config, discovery_data)
            result.phases[PipelinePhase.RECON.value] = pr
            recon_data = pr.data

        # ── CRAWL ─────────────────────────────────────────────────────────────
        if PipelinePhase.CRAWL in phases_to_run:
            pr = self._run_phase(PipelinePhase.CRAWL, self._phase_crawl,
                                 target, config, recon_data)
            result.phases[PipelinePhase.CRAWL.value] = pr
            crawl_data = pr.data

        # ── VULN SCAN ─────────────────────────────────────────────────────────
        if PipelinePhase.VULN_SCAN in phases_to_run:
            pr = self._run_phase(PipelinePhase.VULN_SCAN, self._phase_vuln_scan,
                                 target, config, crawl_data)
            result.phases[PipelinePhase.VULN_SCAN.value] = pr
            raw_findings = pr.data.get("findings", [])
            all_findings.extend(self._normalize_findings(raw_findings))

        # ── EXPLOIT ───────────────────────────────────────────────────────────
        if PipelinePhase.EXPLOIT in phases_to_run and config.auto_exploit:
            pr = self._run_phase(PipelinePhase.EXPLOIT, self._phase_exploit,
                                 target, config, all_findings)
            result.phases[PipelinePhase.EXPLOIT.value] = pr
            exploit_findings = pr.data.get("findings", [])
            all_findings.extend(self._normalize_findings(exploit_findings))
        elif PipelinePhase.EXPLOIT in phases_to_run:
            result.phases[PipelinePhase.EXPLOIT.value] = _make_phase(
                PipelinePhase.EXPLOIT, status="skipped",
                error="auto_exploit=False in config"
            )

        # ── VALIDATE ──────────────────────────────────────────────────────────
        if PipelinePhase.VALIDATE in phases_to_run and config.validate_findings:
            pr = self._run_phase(PipelinePhase.VALIDATE, self._phase_validate,
                                 target, config, all_findings)
            result.phases[PipelinePhase.VALIDATE.value] = pr
            validated = pr.data.get("validated_findings", [])
            if validated:
                all_findings = validated
        elif PipelinePhase.VALIDATE in phases_to_run:
            result.phases[PipelinePhase.VALIDATE.value] = _make_phase(
                PipelinePhase.VALIDATE, status="skipped",
                error="validate_findings=False in config"
            )

        # ── REPORT ────────────────────────────────────────────────────────────
        result.findings = all_findings
        if PipelinePhase.REPORT in phases_to_run and config.generate_report:
            pr = self._run_phase(PipelinePhase.REPORT, self._phase_report,
                                 target, config, result)
            result.phases[PipelinePhase.REPORT.value] = pr
            result.report_path = pr.data.get("report_path", "")
        elif PipelinePhase.REPORT in phases_to_run:
            result.phases[PipelinePhase.REPORT.value] = _make_phase(
                PipelinePhase.REPORT, status="skipped",
                error="generate_report=False in config"
            )

        result.total_duration_s = round(time.time() - pipeline_start, 2)
        import datetime as dt
        result.completed_at = dt.datetime.utcnow().isoformat() + "Z"

        # Auto-save result
        try:
            out_dir = Path(config.output_dir)
            out_dir.mkdir(parents=True, exist_ok=True)
            result.save(str(out_dir / f"{session_id}.json"))
        except Exception as exc:
            logger.warning("Could not auto-save pipeline result: %s", exc)

        logger.info(
            "[pipeline] Completed %s in %.1fs — %d findings",
            target, result.total_duration_s, len(all_findings)
        )
        return result

    async def run_async(self, target: str,
                        config: Optional[PipelineConfig] = None) -> ScanPipelineResult:
        """Async wrapper — offloads synchronous pipeline to a thread pool."""
        loop = asyncio.get_event_loop()
        return await loop.run_in_executor(None, self.run, target, config)

    # ── Lazy Loading ──────────────────────────────────────────────────────────

    def _lazy_load(self):
        """Import optional modules on first use. Never raises."""
        if self._tool_registry is None:
            try:
                from modules.tool_wrappers import ToolRegistry
                self._tool_registry = ToolRegistry()
                logger.debug("tool_wrappers loaded")
            except ImportError as exc:
                logger.warning("tool_wrappers not available: %s", exc)

        if self._adaptive_recon is None:
            try:
                from adaptive_recon_engine import AdaptiveReconEngine
                self._adaptive_recon = AdaptiveReconEngine
                logger.debug("adaptive_recon_engine loaded")
            except ImportError as exc:
                logger.warning("adaptive_recon_engine not available: %s", exc)

        if self._app_crawler is None:
            try:
                # Optional module that may not exist yet
                import importlib
                mod = importlib.import_module("application_crawler")
                self._app_crawler = getattr(mod, "ApplicationCrawler", None)
                logger.debug("application_crawler loaded")
            except (ImportError, AttributeError) as exc:
                logger.debug("application_crawler not available: %s", exc)

        if self._validation_engine is None:
            try:
                from finding_validation_engine import FindingValidationEngine
                self._validation_engine = FindingValidationEngine()
                logger.debug("finding_validation_engine loaded")
            except ImportError as exc:
                logger.warning("finding_validation_engine not available: %s", exc)

        if self._exploit_engine is None:
            try:
                from autonomous_exploit_engine import AutonomousExploitEngine
                self._exploit_engine = AutonomousExploitEngine()
                logger.debug("autonomous_exploit_engine loaded")
            except ImportError as exc:
                logger.warning("autonomous_exploit_engine not available: %s", exc)

        if self._report_generator is None:
            try:
                import importlib
                mod = importlib.import_module("bounty_report_generator")
                self._report_generator = getattr(mod, "BountyReportGenerator", None)
                if self._report_generator:
                    self._report_generator = self._report_generator()
                logger.debug("bounty_report_generator loaded")
            except (ImportError, AttributeError) as exc:
                logger.debug("bounty_report_generator not available: %s", exc)

    # ── Phase Runner Wrapper ──────────────────────────────────────────────────

    def _run_phase(self, phase: PipelinePhase, fn, *args) -> PhaseResult:
        """Execute a phase function, tracking timing and catching all errors."""
        self._emit_progress(phase, "running", f"Starting {phase.value}")
        t0 = time.time()
        try:
            pr = fn(*args)
            pr.duration_s = round(time.time() - t0, 2)
            if pr.status == "running":
                pr.status = "complete"
            self._emit_progress(phase, pr.status,
                                f"{phase.value} done — {pr.finding_count} findings in {pr.duration_s}s")
            return pr
        except Exception as exc:
            duration = round(time.time() - t0, 2)
            logger.error("[pipeline] Phase %s crashed: %s", phase.value, exc, exc_info=True)
            self._emit_progress(phase, "failed", f"{phase.value} failed: {exc}")
            return _make_phase(phase, status="failed", duration_s=duration, error=str(exc))

    # ── DISCOVERY ─────────────────────────────────────────────────────────────

    def _phase_discovery(self, target: str, config: PipelineConfig) -> PhaseResult:
        """
        Enumerate subdomains using subfinder/assetfinder/dnsx, falling back to
        a basic DNS probe when tools are unavailable.
        """
        subdomains: set[str] = {target}
        hosts: list[dict] = []
        errors: list[str] = []

        if self._tool_registry:
            # subfinder
            try:
                res = self._tool_registry.run("subfinder", domain=target)
                if res.success and isinstance(res.data, dict):
                    for sd in res.data.get("subdomains", []):
                        subdomains.add(sd.strip())
                    logger.info("[discovery] subfinder: %d subdomains", len(subdomains))
            except Exception as exc:
                errors.append(f"subfinder: {exc}")
                logger.warning("[discovery] subfinder error: %s", exc)

            # assetfinder fallback
            try:
                res = self._tool_registry.run("assetfinder", domain=target)
                if res.success and isinstance(res.data, dict):
                    for sd in res.data.get("subdomains", []):
                        subdomains.add(sd.strip())
            except Exception as exc:
                errors.append(f"assetfinder: {exc}")
                logger.debug("[discovery] assetfinder: %s", exc)

            # httpx probe to find live hosts
            subdomain_list = list(subdomains)
            if subdomain_list:
                try:
                    res = self._tool_registry.run("httpx", targets=subdomain_list, timeout=120)
                    if res.success and isinstance(res.data, dict):
                        hosts = res.data.get("hosts", [])
                        logger.info("[discovery] httpx: %d live hosts", len(hosts))
                except Exception as exc:
                    errors.append(f"httpx: {exc}")
                    logger.warning("[discovery] httpx error: %s", exc)
        else:
            # Basic DNS fallback
            import socket
            logger.info("[discovery] tool_wrappers unavailable, using DNS fallback")
            common_prefixes = ["www", "api", "admin", "dev", "staging", "app", "mail", "cdn"]
            for prefix in common_prefixes:
                fqdn = f"{prefix}.{target}"
                try:
                    socket.gethostbyname(fqdn)
                    subdomains.add(fqdn)
                except socket.gaierror:
                    pass

        live_urls = [h.get("url", h.get("input", "")) for h in hosts if isinstance(h, dict)]
        live_urls = [u for u in live_urls if u]

        return PhaseResult(
            phase=PipelinePhase.DISCOVERY.value,
            status="complete",
            finding_count=len(subdomains),
            data={
                "subdomains": sorted(subdomains),
                "subdomain_count": len(subdomains),
                "live_hosts": hosts,
                "live_host_count": len(hosts),
                "live_urls": live_urls,
                "errors": errors,
            },
        )

    # ── RECON ─────────────────────────────────────────────────────────────────

    def _phase_recon(self, target: str, config: PipelineConfig,
                     discovery_data: dict) -> PhaseResult:
        """
        Harvest historical URLs from Wayback Machine and crawl with katana/gauplus.
        """
        all_urls: set[str] = set()
        endpoints: set[str] = set()
        errors: list[str] = []

        live_urls = discovery_data.get("live_urls", [])
        subdomains = discovery_data.get("subdomains", [target])
        probe_targets = live_urls if live_urls else [f"https://{s}" for s in subdomains[:5]]

        if self._tool_registry:
            # waybackurls
            try:
                res = self._tool_registry.run("waybackurls", domain=target)
                if res.success and isinstance(res.data, dict):
                    for u in res.data.get("urls", []):
                        all_urls.add(u)
                    logger.info("[recon] waybackurls: %d URLs", len(all_urls))
            except Exception as exc:
                errors.append(f"waybackurls: {exc}")
                logger.warning("[recon] waybackurls: %s", exc)

            # gauplus
            try:
                res = self._tool_registry.run("gauplus", domain=target)
                if res.success and isinstance(res.data, dict):
                    for u in res.data.get("urls", []):
                        all_urls.add(u)
                    logger.info("[recon] gauplus: %d total URLs", len(all_urls))
            except Exception as exc:
                errors.append(f"gauplus: {exc}")
                logger.debug("[recon] gauplus: %s", exc)

            # katana — active crawl of live hosts
            for url in probe_targets[:3]:
                try:
                    res = self._tool_registry.run("katana", target=url, depth=2, timeout=120)
                    if res.success and isinstance(res.data, dict):
                        for u in res.data.get("urls", []):
                            all_urls.add(u)
                    logger.info("[recon] katana crawled %s", url)
                except Exception as exc:
                    errors.append(f"katana({url}): {exc}")
                    logger.debug("[recon] katana(%s): %s", url, exc)

            # gf patterns to extract interesting endpoints
            if all_urls:
                url_list = list(all_urls)
                for pattern in ["xss", "sqli", "redirect", "ssrf", "lfi"]:
                    try:
                        res = self._tool_registry.run("gf", urls=url_list, pattern=pattern)
                        if res.success and isinstance(res.data, list):
                            for u in res.data:
                                endpoints.add(u)
                    except Exception:
                        pass
        else:
            logger.warning("[recon] tool_wrappers unavailable — skipping URL harvesting")

        return PhaseResult(
            phase=PipelinePhase.RECON.value,
            status="complete",
            finding_count=len(all_urls),
            data={
                "urls": list(all_urls),
                "url_count": len(all_urls),
                "endpoints": list(endpoints),
                "endpoint_count": len(endpoints),
                "probe_targets": probe_targets,
                "errors": errors,
            },
        )

    # ── CRAWL ─────────────────────────────────────────────────────────────────

    def _phase_crawl(self, target: str, config: PipelineConfig,
                     recon_data: dict) -> PhaseResult:
        """
        Deep crawl to discover pages, forms, and inputs.
        Uses application_crawler if available, else basic urllib HTTP crawl.
        """
        pages: list[dict] = []
        forms: list[dict] = []
        inputs: list[dict] = []
        errors: list[str] = []

        probe_targets = recon_data.get("probe_targets", [f"https://{target}"])
        seed_url = probe_targets[0] if probe_targets else f"https://{target}"

        if self._app_crawler:
            try:
                crawler = self._app_crawler(seed_url)
                crawl_result = crawler.crawl()
                pages = getattr(crawl_result, "pages", [])
                forms = getattr(crawl_result, "forms", [])
                inputs = getattr(crawl_result, "inputs", [])
                logger.info("[crawl] application_crawler: %d pages", len(pages))
            except Exception as exc:
                errors.append(f"application_crawler: {exc}")
                logger.warning("[crawl] application_crawler: %s", exc)

        # Always supplement with basic urllib crawl
        try:
            basic = self._basic_http_crawl(seed_url, max_pages=30)
            for p in basic["pages"]:
                if p not in pages:
                    pages.append(p)
            for f in basic["forms"]:
                forms.append(f)
            for i in basic["inputs"]:
                inputs.append(i)
            logger.info("[crawl] basic crawl: %d pages", len(basic["pages"]))
        except Exception as exc:
            errors.append(f"basic_crawl: {exc}")
            logger.warning("[crawl] basic_crawl: %s", exc)

        return PhaseResult(
            phase=PipelinePhase.CRAWL.value,
            status="complete",
            finding_count=len(pages),
            data={
                "pages": pages,
                "page_count": len(pages),
                "forms": forms,
                "form_count": len(forms),
                "inputs": inputs,
                "input_count": len(inputs),
                "errors": errors,
            },
        )

    def _basic_http_crawl(self, seed_url: str, max_pages: int = 30) -> dict:
        """Simple urllib-based BFS crawler. Returns pages/forms/inputs."""
        import re as _re
        from html.parser import HTMLParser

        class _LinkParser(HTMLParser):
            def __init__(self):
                super().__init__()
                self.links: list[str] = []
                self.forms: list[dict] = []
                self.inputs: list[dict] = []
                self._cur_form: Optional[dict] = None

            def handle_starttag(self, tag, attrs):
                attrs_d = dict(attrs)
                if tag == "a" and attrs_d.get("href"):
                    self.links.append(attrs_d["href"])
                elif tag == "form":
                    self._cur_form = {
                        "action": attrs_d.get("action", ""),
                        "method": attrs_d.get("method", "GET").upper(),
                        "inputs": [],
                    }
                    self.forms.append(self._cur_form)
                elif tag == "input" and self._cur_form is not None:
                    inp = {
                        "name": attrs_d.get("name", ""),
                        "type": attrs_d.get("type", "text"),
                        "id": attrs_d.get("id", ""),
                    }
                    self._cur_form["inputs"].append(inp)
                    self.inputs.append(inp)

        visited: set[str] = set()
        queue: list[str] = [seed_url]
        pages: list[dict] = []
        all_forms: list[dict] = []
        all_inputs: list[dict] = []
        parsed_base = urllib.parse.urlparse(seed_url)
        base_domain = parsed_base.netloc

        while queue and len(visited) < max_pages:
            url = queue.pop(0)
            if url in visited:
                continue
            visited.add(url)
            try:
                req = urllib.request.Request(
                    url,
                    headers={"User-Agent": "OneInfinity/1.0"},
                )
                with urllib.request.urlopen(req, timeout=10, context=self._ssl_ctx) as resp:
                    ct = resp.headers.get_content_type() or ""
                    if "html" not in ct:
                        continue
                    html = resp.read(65536).decode("utf-8", errors="replace")
                    status = resp.status
            except Exception:
                continue

            parser = _LinkParser()
            try:
                parser.parse(html)
            except Exception:
                try:
                    parser.feed(html)
                except Exception:
                    pass

            pages.append({"url": url, "status": status,
                          "form_count": len(parser.forms)})
            all_forms.extend(parser.forms)
            all_inputs.extend(parser.inputs)

            # Enqueue same-domain links
            for href in parser.links:
                absolute = urllib.parse.urljoin(url, href)
                parsed = urllib.parse.urlparse(absolute)
                if parsed.netloc == base_domain and absolute not in visited:
                    queue.append(absolute)

        return {"pages": pages, "forms": all_forms, "inputs": all_inputs}

    # ── VULN SCAN ─────────────────────────────────────────────────────────────

    def _phase_vuln_scan(self, target: str, config: PipelineConfig,
                         crawl_data: dict) -> PhaseResult:
        """
        Run nuclei templates against discovered endpoints, supplement with
        common manual vuln checks where tools are unavailable.
        """
        findings: list[dict] = []
        errors: list[str] = []

        if self._tool_registry:
            # nuclei — template-based scan
            try:
                res = self._tool_registry.run(
                    "nuclei",
                    target=target,
                    severity="info,low,medium,high,critical",
                    timeout=600,
                )
                if res.success and isinstance(res.data, list):
                    for item in res.data:
                        if isinstance(item, dict):
                            findings.append(item)
                    logger.info("[vuln_scan] nuclei: %d findings", len(findings))
                elif res.error:
                    errors.append(f"nuclei: {res.error}")
            except Exception as exc:
                errors.append(f"nuclei: {exc}")
                logger.warning("[vuln_scan] nuclei: %s", exc)

            # dalfox — XSS
            pages = crawl_data.get("pages", [])
            for page in pages[:20]:
                url = page.get("url", "") if isinstance(page, dict) else str(page)
                if not url or "?" not in url:
                    continue
                try:
                    res = self._tool_registry.run("dalfox", url=url)
                    if res.success and isinstance(res.data, list):
                        for item in res.data:
                            if isinstance(item, dict):
                                item.setdefault("vuln_type", "xss")
                                findings.append(item)
                except Exception as exc:
                    logger.debug("[vuln_scan] dalfox(%s): %s", url, exc)

            # crlfuzz — CRLF injection
            try:
                res = self._tool_registry.run("crlfuzz", target=f"https://{target}")
                if res.success and res.data:
                    raw = res.data if isinstance(res.data, list) else []
                    for item in raw:
                        findings.append({
                            "vuln_type": "crlf_injection",
                            "title": "CRLF Injection",
                            "severity": "medium",
                            "url": item if isinstance(item, str) else str(item),
                            "evidence": str(item),
                        })
            except Exception as exc:
                logger.debug("[vuln_scan] crlfuzz: %s", exc)

            # trufflehog — secret scanning on the domain
            try:
                res = self._tool_registry.run("trufflehog",
                                              target=f"https://{target}",
                                              target_type="url")
                if res.success and isinstance(res.data, list):
                    for item in res.data:
                        if isinstance(item, dict):
                            item.setdefault("vuln_type", "secret_exposure")
                            item.setdefault("severity", "high")
                            findings.append(item)
                    logger.info("[vuln_scan] trufflehog: %d secrets", len(res.data))
            except Exception as exc:
                logger.debug("[vuln_scan] trufflehog: %s", exc)
        else:
            logger.warning("[vuln_scan] tool_wrappers unavailable — running header checks only")
            findings.extend(self._check_security_headers(target))

        # Always run header checks as a lightweight supplement
        try:
            header_findings = self._check_security_headers(target)
            findings.extend(header_findings)
        except Exception as exc:
            logger.debug("[vuln_scan] header_check: %s", exc)

        return PhaseResult(
            phase=PipelinePhase.VULN_SCAN.value,
            status="complete",
            finding_count=len(findings),
            data={"findings": findings, "errors": errors},
        )

    def _check_security_headers(self, target: str) -> list[dict]:
        """Lightweight security header check over HTTP."""
        findings: list[dict] = []
        url = f"https://{target}" if not target.startswith("http") else target
        required_headers = {
            "strict-transport-security": ("Missing HSTS", "medium"),
            "x-frame-options": ("Missing X-Frame-Options", "low"),
            "x-content-type-options": ("Missing X-Content-Type-Options", "low"),
            "content-security-policy": ("Missing CSP", "medium"),
            "referrer-policy": ("Missing Referrer-Policy", "info"),
            "permissions-policy": ("Missing Permissions-Policy", "info"),
        }
        try:
            req = urllib.request.Request(
                url,
                headers={"User-Agent": "OneInfinity/1.0"},
            )
            with urllib.request.urlopen(req, timeout=10, context=self._ssl_ctx) as resp:
                headers_present = {k.lower() for k in dict(resp.headers).keys()}
            for header, (title, severity) in required_headers.items():
                if header not in headers_present:
                    findings.append({
                        "vuln_type": "missing_security_header",
                        "title": title,
                        "severity": severity,
                        "url": url,
                        "evidence": f"Header '{header}' not found in response",
                        "header": header,
                    })
        except Exception as exc:
            logger.debug("[header_check] %s: %s", url, exc)
        return findings

    # ── EXPLOIT ───────────────────────────────────────────────────────────────

    def _phase_exploit(self, target: str, config: PipelineConfig,
                       vuln_findings: list) -> PhaseResult:
        """
        Attempt exploitation of discovered vulnerabilities using the
        AutonomousExploitEngine.
        """
        if not vuln_findings:
            return _make_phase(PipelinePhase.EXPLOIT, status="skipped",
                               error="No findings to exploit")

        if not self._exploit_engine:
            return _make_phase(PipelinePhase.EXPLOIT, status="skipped",
                               error="autonomous_exploit_engine not available")

        try:
            session = self._exploit_engine.exploit_target(
                target=target,
                findings=vuln_findings,
                max_findings=50,
            )
            exploit_findings = []
            for r in session.results:
                if hasattr(r, "to_dict"):
                    d = r.to_dict()
                else:
                    d = r if isinstance(r, dict) else {}
                if d.get("exploited"):
                    exploit_findings.append(d)

            logger.info("[exploit] %d/%d findings exploited",
                        session.exploited_count, session.total_findings)
            return PhaseResult(
                phase=PipelinePhase.EXPLOIT.value,
                status="complete",
                finding_count=len(exploit_findings),
                data={
                    "session": session.to_dict(),
                    "findings": exploit_findings,
                    "exploited_count": session.exploited_count,
                    "total_attempted": session.total_findings,
                },
            )
        except Exception as exc:
            logger.error("[exploit] engine error: %s", exc, exc_info=True)
            return _make_phase(PipelinePhase.EXPLOIT, status="failed", error=str(exc))

    # ── VALIDATE ──────────────────────────────────────────────────────────────

    def _phase_validate(self, target: str, config: PipelineConfig,
                        all_findings: list) -> PhaseResult:
        """
        Run each finding through FindingValidationEngine to reduce false positives.
        """
        if not all_findings:
            return _make_phase(PipelinePhase.VALIDATE, status="skipped",
                               error="No findings to validate")

        if not self._validation_engine:
            logger.warning("[validate] FindingValidationEngine not available — returning all findings unvalidated")
            return PhaseResult(
                phase=PipelinePhase.VALIDATE.value,
                status="complete",
                finding_count=len(all_findings),
                data={"validated_findings": all_findings, "skipped": True},
            )

        validated: list[dict] = []
        rejected: list[dict] = []

        for finding in all_findings:
            try:
                vr = self._validation_engine.validate(finding)
                if hasattr(vr, "to_dict"):
                    vr_dict = vr.to_dict()
                else:
                    vr_dict = vr if isinstance(vr, dict) else {}

                if vr_dict.get("validated", False):
                    enriched = dict(finding)
                    enriched["validation"] = vr_dict
                    enriched["confidence"] = vr_dict.get("confidence", 0.5)
                    validated.append(enriched)
                else:
                    rejected.append(finding)
            except Exception as exc:
                logger.debug("[validate] finding validation error: %s", exc)
                # When validation itself errors, keep the finding
                validated.append(finding)

        logger.info("[validate] %d validated, %d rejected from %d total",
                    len(validated), len(rejected), len(all_findings))

        return PhaseResult(
            phase=PipelinePhase.VALIDATE.value,
            status="complete",
            finding_count=len(validated),
            data={
                "validated_findings": validated,
                "rejected_findings": rejected,
                "validated_count": len(validated),
                "rejected_count": len(rejected),
            },
        )

    # ── REPORT ────────────────────────────────────────────────────────────────

    def _phase_report(self, target: str, config: PipelineConfig,
                      pipeline_result: "ScanPipelineResult") -> PhaseResult:
        """
        Generate a final report. Uses bounty_report_generator if available,
        otherwise writes a structured JSON + Markdown summary.
        """
        report_path = ""
        errors: list[str] = []
        out_dir = Path(config.output_dir)
        out_dir.mkdir(parents=True, exist_ok=True)

        if self._report_generator:
            try:
                rpt = self._report_generator.generate(
                    target=target,
                    findings=pipeline_result.findings,
                    session_id=pipeline_result.session_id,
                    output_dir=str(out_dir),
                )
                report_path = getattr(rpt, "path", str(rpt)) if rpt else ""
                logger.info("[report] bounty_report_generator: %s", report_path)
            except Exception as exc:
                errors.append(f"bounty_report_generator: {exc}")
                logger.warning("[report] report generator error: %s", exc)

        # Always write a basic JSON + Markdown regardless
        json_path = out_dir / f"{pipeline_result.session_id}_report.json"
        md_path   = out_dir / f"{pipeline_result.session_id}_report.md"

        try:
            json_path.write_text(
                json.dumps(pipeline_result.to_dict(), indent=2, default=str)
            )
            if not report_path:
                report_path = str(json_path)
        except Exception as exc:
            errors.append(f"json_write: {exc}")

        try:
            md_path.write_text(self._render_markdown(target, pipeline_result))
        except Exception as exc:
            errors.append(f"md_write: {exc}")

        return PhaseResult(
            phase=PipelinePhase.REPORT.value,
            status="complete",
            finding_count=len(pipeline_result.findings),
            data={
                "report_path": report_path or str(json_path),
                "json_path": str(json_path),
                "markdown_path": str(md_path),
                "finding_count": len(pipeline_result.findings),
                "errors": errors,
            },
        )

    def _render_markdown(self, target: str,
                         result: "ScanPipelineResult") -> str:
        """Render a readable Markdown report from the pipeline result."""
        import datetime
        lines = [
            f"# One&Infinity Scan Report",
            f"",
            f"**Target:** `{target}`  ",
            f"**Session:** `{result.session_id}`  ",
            f"**Date:** {datetime.datetime.utcnow().strftime('%Y-%m-%d %H:%M UTC')}  ",
            f"**Duration:** {result.total_duration_s:.1f}s  ",
            f"**Total Findings:** {len(result.findings)}",
            f"",
            f"---",
            f"",
            f"## Phase Summary",
            f"",
            f"| Phase | Status | Duration | Findings |",
            f"|-------|--------|----------|----------|",
        ]
        for phase_name, pr in result.phases.items():
            lines.append(
                f"| {phase_name} | {pr.status} | {pr.duration_s:.1f}s | {pr.finding_count} |"
            )

        lines += ["", "---", "", "## Findings", ""]

        # Group by severity
        severity_order = ["critical", "high", "medium", "low", "info", "unknown"]
        grouped: dict[str, list] = {s: [] for s in severity_order}
        for f in result.findings:
            sev = str(f.get("severity", "unknown")).lower()
            grouped.setdefault(sev, []).append(f)

        for sev in severity_order:
            bucket = grouped.get(sev, [])
            if not bucket:
                continue
            lines.append(f"### {sev.upper()} ({len(bucket)})")
            lines.append("")
            for f in bucket:
                title = f.get("title", f.get("name", f.get("vuln_type", "Finding")))
                url   = f.get("url", "")
                vtype = f.get("vuln_type", f.get("type", ""))
                evidence = str(f.get("evidence", ""))[:200]
                lines.append(f"#### {title}")
                if url:
                    lines.append(f"- **URL:** `{url}`")
                if vtype:
                    lines.append(f"- **Type:** {vtype}")
                if evidence:
                    lines.append(f"- **Evidence:** {evidence}")
                lines.append("")

        return "\n".join(lines)

    # ── Finding Normalizer ────────────────────────────────────────────────────

    def _normalize_findings(self, raw: list) -> list[dict]:
        """
        Normalize raw tool output into a consistent finding dict schema:
            id, title, severity, vuln_type, url, evidence
        """
        normalized: list[dict] = []
        for i, item in enumerate(raw):
            if not item:
                continue
            if not isinstance(item, dict):
                try:
                    item = json.loads(str(item))
                except Exception:
                    item = {"raw": str(item)}

            # Nuclei output uses "info.name", "info.severity", "matched-at"
            title = (
                item.get("title")
                or item.get("name")
                or (item.get("info") or {}).get("name")
                or item.get("template-id")
                or "Finding"
            )
            severity = (
                item.get("severity")
                or (item.get("info") or {}).get("severity")
                or "info"
            ).lower()
            vuln_type = (
                item.get("vuln_type")
                or item.get("type")
                or item.get("template-id")
                or "unknown"
            )
            url = (
                item.get("url")
                or item.get("matched-at")
                or item.get("matched_at")
                or item.get("endpoint")
                or ""
            )
            evidence = (
                item.get("evidence")
                or item.get("extracted-results")
                or item.get("description")
                or ""
            )
            if isinstance(evidence, list):
                evidence = "; ".join(str(e) for e in evidence)

            finding_id = item.get("id") or f"{vuln_type}-{i:04d}-{uuid.uuid4().hex[:6]}"

            normalized.append({
                "id": finding_id,
                "title": str(title),
                "severity": severity,
                "vuln_type": str(vuln_type),
                "url": str(url),
                "evidence": str(evidence)[:500],
                "_raw": item,
            })
        return normalized

    # ── Progress Emitter ──────────────────────────────────────────────────────

    def _emit_progress(self, phase: PipelinePhase, status: str, msg: str):
        """Log pipeline progress and append to in-memory log."""
        entry = {
            "phase": phase.value,
            "status": status,
            "message": msg,
            "ts": time.time(),
        }
        self._progress_log.append(entry)
        log_fn = logger.info if status not in ("failed",) else logger.error
        log_fn("[pipeline][%s][%s] %s", phase.value, status, msg)


# ── Global Singleton ──────────────────────────────────────────────────────────

autonomous_scan_pipeline = AutonomousScanPipeline()
