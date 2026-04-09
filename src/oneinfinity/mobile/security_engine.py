"""
Mobile Security Engine — Comprehensive Orchestrator
=====================================================
Full mobile penetration testing pipeline:
  1. Upload & Extract
  2. Tool Registry Check
  3. Static Analysis (APKTool + JADX + MobSF)
  4. AI Reverse Engineering
  5. Frida Script Generation
  6. Secret Detection (TruffleHog + Gitleaks + Regex + Binary)
  7. API Discovery
  8. Android Component Testing (Drozer + Static)
  9. Dynamic Analysis (Frida + Objection + RMS)
  10. Network Traffic Analysis
  11. API Attack & Fuzzing
  12. Vulnerability Aggregation + Risk Scoring + Reporting
"""

from __future__ import annotations

import importlib
import json
import dataclasses
import logging
import os
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional

logger = logging.getLogger(__name__)


# ─────────────────────────────────────────────────────────────────────────────
#  Configuration
# ─────────────────────────────────────────────────────────────────────────────

@dataclass
class MobileSecurityConfig:
    # Phase toggles
    run_static: bool = True
    run_ai_reverse: bool = True
    run_frida_gen: bool = True
    run_secrets: bool = True
    run_api_discovery: bool = True
    run_component_testing: bool = True
    run_dynamic: bool = False          # requires connected device
    run_network_analysis: bool = True
    run_api_attack: bool = False       # active testing — off by default
    run_api_fuzzing: bool = False

    # Tool config
    use_mobsf: bool = False            # requires MobSF server
    use_jadx: bool = True
    use_apktool: bool = True
    use_drozer: bool = False           # requires connected device + drozer agent

    # Device / proxy
    device_id: str = ""
    proxy_host: str = ""
    proxy_port: int = 8080

    # AI analysis
    use_ai_analysis: bool = True
    ai_provider: str = "anthropic"

    # Limits
    timeout: int = 300
    output_dir: str = ""


# ─────────────────────────────────────────────────────────────────────────────
#  Report
# ─────────────────────────────────────────────────────────────────────────────

@dataclass
class MobileSecurityReport:
    app_id: str
    app_name: str = ""
    package_name: str = ""
    platform: str = ""
    file_path: str = ""

    # Phase results (dicts for JSON serialisation)
    upload: dict = field(default_factory=dict)
    tool_registry: dict = field(default_factory=dict)
    static_analysis: dict = field(default_factory=dict)
    advanced_static: dict = field(default_factory=dict)   # APKTool + JADX
    ai_reverse_engineering: dict = field(default_factory=dict)
    frida_scripts: dict = field(default_factory=dict)
    secrets: dict = field(default_factory=dict)
    api_discovery: dict = field(default_factory=dict)
    component_testing: dict = field(default_factory=dict)
    dynamic_analysis: dict = field(default_factory=dict)
    network_analysis: dict = field(default_factory=dict)
    api_attack: dict = field(default_factory=dict)
    api_fuzzing: dict = field(default_factory=dict)

    # Aggregated
    all_vulnerabilities: list = field(default_factory=list)
    severity_counts: dict = field(default_factory=lambda: {
        "critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0
    })
    risk_score: float = 0.0
    recommendations: list = field(default_factory=list)
    errors: list = field(default_factory=list)
    phase_timings: dict = field(default_factory=dict)

    def to_dict(self) -> dict:
        return {
            "app_id": self.app_id,
            "app_name": self.app_name,
            "package_name": self.package_name,
            "platform": self.platform,
            "file_path": self.file_path,
            "upload": self.upload,
            "tool_registry": self.tool_registry,
            "static_analysis": self.static_analysis,
            "advanced_static": self.advanced_static,
            "ai_reverse_engineering": self.ai_reverse_engineering,
            "frida_scripts": self.frida_scripts,
            "secrets": self.secrets,
            "api_discovery": self.api_discovery,
            "component_testing": self.component_testing,
            "dynamic_analysis": self.dynamic_analysis,
            "network_analysis": self.network_analysis,
            "api_attack": self.api_attack,
            "api_fuzzing": self.api_fuzzing,
            "all_vulnerabilities": self.all_vulnerabilities,
            "severity_counts": self.severity_counts,
            "risk_score": self.risk_score,
            "recommendations": self.recommendations,
            "errors": self.errors,
            "phase_timings": self.phase_timings,
        }

    def save(self, path: str):
        def _json_default(obj: Any):
            # Best-effort conversion for non-JSON types produced by some phases.
            if hasattr(obj, "to_dict") and callable(getattr(obj, "to_dict")):
                try:
                    return obj.to_dict()
                except Exception:
                    pass
            if dataclasses.is_dataclass(obj):
                try:
                    return dataclasses.asdict(obj)
                except Exception:
                    pass
            return str(obj)

        Path(path).write_text(json.dumps(self.to_dict(), indent=2, default=_json_default))


# ─────────────────────────────────────────────────────────────────────────────
#  Engine
# ─────────────────────────────────────────────────────────────────────────────

class MobileSecurityEngine:
    """
    Orchestrates the full mobile security testing pipeline.
    All component modules are lazily imported so the engine starts even if
    individual tools or libraries are missing.
    """

    def __init__(self):
        # Lazily-loaded component references
        self._upload_mgr = None
        self._tool_registry = None
        self._static_analyzer = None        # original mobile_static_analyzer
        self._advanced_static = None        # new mobile_static_analysis
        self._ai_reverser = None
        self._frida_gen = None
        self._secret_scanner = None         # original mobile_secret_scanner
        self._secret_detector = None        # new mobile_secret_detection
        self._api_discovery = None
        self._component_tester = None
        self._dynamic_analyzer = None
        self._network_analyzer = None
        self._api_attacker = None
        self._android_studio = None
        self._attack_graph = None
        self._learning = None

    # ─── Lazy loader ──────────────────────────────────────────────────────────

    def _lazy_load(self):
        def _try(attr: str, module: str, symbol: str):
            if getattr(self, attr) is None:
                try:
                    mod = importlib.import_module(module)
                    setattr(self, attr, getattr(mod, symbol))
                except Exception as exc:
                    logger.debug(f"{module}.{symbol} unavailable: {exc}")

        _try("_upload_mgr",       "oneinfinity.mobile.upload_manager",    "mobile_upload_manager")
        _try("_tool_registry",    "oneinfinity.mobile.tool_registry",     "tool_registry")
        _try("_static_analyzer",  "oneinfinity.mobile.static_analysis",   "mobile_static_analyzer")
        _try("_advanced_static",  "oneinfinity.mobile.static_analysis",   "mobile_static_analyzer")
        _try("_ai_reverser",      "oneinfinity.mobile.ai_reverse_engineer","mobile_ai_reverse_engineer")
        _try("_frida_gen",        "oneinfinity.frida_script_generator",   "frida_script_generator")
        _try("_secret_scanner",   "oneinfinity.mobile.secret_scanner",    "mobile_secret_scanner")
        _try("_secret_detector",  "oneinfinity.mobile.secret_detection",  "mobile_secret_detector")
        _try("_api_discovery",    "oneinfinity.mobile.api_discovery",     "mobile_api_discovery")
        _try("_component_tester", "oneinfinity.android_component_testing","android_component_tester")
        _try("_dynamic_analyzer", "oneinfinity.mobile.dynamic_analysis",  "mobile_dynamic_analyzer")
        _try("_network_analyzer", "oneinfinity.mobile.network_analysis",  "mobile_network_analyzer")
        _try("_api_attacker",     "oneinfinity.mobile.api_attack",        "mobile_api_attack_engine")
        _try("_android_studio",   "android_studio_integration",           "android_studio_integration")

    # ─── Main entry ───────────────────────────────────────────────────────────

    def analyze(self, file_path: str,
                config: Optional[MobileSecurityConfig] = None,
                attack_graph=None,
                learning_system=None) -> MobileSecurityReport:
        """Run the complete mobile security pipeline. Returns a MobileSecurityReport."""
        self._lazy_load()
        if config is None:
            config = MobileSecurityConfig()
        self._attack_graph = attack_graph
        self._learning = learning_system

        report = MobileSecurityReport(app_id="")
        report.file_path = file_path
        pipeline_start = time.time()

        # ── Phase 0: Tool Registry ─────────────────────────────────────────────
        self._phase_tool_registry(report)

        # ── Phase 1: Upload & Extract ──────────────────────────────────────────
        t0 = time.time()
        logger.info("[mobile] Phase 1: Upload & Extract — %s", file_path)
        app = self._phase_upload(file_path, report)
        report.phase_timings["upload"] = round(time.time() - t0, 2)
        if not app:
            return report

        report.app_id        = app.get("app_id", "unknown")
        report.app_name      = app.get("app_name", "")
        report.package_name  = app.get("package_name", "")
        report.platform      = app.get("platform", "")
        extracted_dir        = app.get("extracted_dir", "")

        # ── Phase 2: Static Analysis (original + advanced) ─────────────────────
        if config.run_static:
            t0 = time.time()
            logger.info("[mobile] Phase 2: Static Analysis")
            self._phase_static(report, file_path, extracted_dir, config)
            report.phase_timings["static_analysis"] = round(time.time() - t0, 2)
            # Sync package_name if discovered by static analysis
            if not report.package_name:
                report.package_name = (
                    report.static_analysis.get("package_name") or
                    report.advanced_static.get("package_name") or ""
                )

        # ── Phase 3: AI Reverse Engineering ────────────────────────────────────
        if config.run_ai_reverse:
            t0 = time.time()
            logger.info("[mobile] Phase 3: AI Reverse Engineering")
            self._phase_ai_reverse(report, extracted_dir, config)
            report.phase_timings["ai_reverse"] = round(time.time() - t0, 2)

        # ── Phase 4: Frida Script Generation ───────────────────────────────────
        if config.run_frida_gen:
            t0 = time.time()
            logger.info("[mobile] Phase 4: Frida Script Generation")
            self._phase_frida_scripts(report, extracted_dir, config)
            report.phase_timings["frida_scripts"] = round(time.time() - t0, 2)

        # ── Phase 5: Secret Detection ──────────────────────────────────────────
        if config.run_secrets:
            t0 = time.time()
            logger.info("[mobile] Phase 5: Secret Detection")
            self._phase_secrets(report, extracted_dir)
            report.phase_timings["secrets"] = round(time.time() - t0, 2)

        # ── Phase 6: API Discovery ─────────────────────────────────────────────
        if config.run_api_discovery:
            t0 = time.time()
            logger.info("[mobile] Phase 6: API Discovery")
            self._phase_api_discovery(report, extracted_dir)
            report.phase_timings["api_discovery"] = round(time.time() - t0, 2)

        # ── Phase 7: Android Component Testing ────────────────────────────────
        if config.run_component_testing:
            t0 = time.time()
            logger.info("[mobile] Phase 7: Android Component Testing")
            self._phase_component_testing(report, extracted_dir, config)
            report.phase_timings["component_testing"] = round(time.time() - t0, 2)

        # ── Phase 8: Dynamic Analysis ─────────────────────────────────────────
        if config.run_dynamic:
            t0 = time.time()
            logger.info("[mobile] Phase 8: Dynamic Analysis")
            self._phase_dynamic(report, file_path, extracted_dir, config)
            report.phase_timings["dynamic_analysis"] = round(time.time() - t0, 2)

        # ── Phase 9: Network Traffic Analysis ────────────────────────────────
        if config.run_network_analysis:
            t0 = time.time()
            logger.info("[mobile] Phase 9: Network Analysis")
            self._phase_network_analysis(report)
            report.phase_timings["network_analysis"] = round(time.time() - t0, 2)

        # ── Phase 10: API Attack / Fuzzing ────────────────────────────────────
        if config.run_api_attack or config.run_api_fuzzing:
            t0 = time.time()
            logger.info("[mobile] Phase 10: API Attack & Fuzzing")
            self._phase_api_attack(report, config)
            report.phase_timings["api_attack"] = round(time.time() - t0, 2)

        # ── Aggregate, Score, Recommend ───────────────────────────────────────
        self._aggregate_vulnerabilities(report)
        self._calculate_risk_score(report)
        self._generate_recommendations(report)

        report.phase_timings["total"] = round(time.time() - pipeline_start, 2)
        logger.info("[mobile] Pipeline complete: %d vulns, risk=%.1f in %.1fs",
                    len(report.all_vulnerabilities), report.risk_score,
                    report.phase_timings["total"])

        # ── Save report ───────────────────────────────────────────────────────
        if config.output_dir:
            out_path = os.path.join(config.output_dir, f"mobile_{report.app_id}.json")
            try:
                report.save(out_path)
                logger.info("[mobile] Report saved: %s", out_path)
            except Exception as exc:
                report.errors.append(f"Report save error: {exc}")

        # ── Update attack graph ───────────────────────────────────────────────
        if self._attack_graph and report.all_vulnerabilities:
            self._update_attack_graph(report)

        return report

    # ─── Phase implementations ────────────────────────────────────────────────

    def _phase_tool_registry(self, report: MobileSecurityReport):
        if not self._tool_registry:
            return
        try:
            summary = self._tool_registry.tool_summary()
            report.tool_registry = {
                "tools": summary,
                "available": [n for n, s in summary.items() if s.get("status") == "available"],
                "missing": [n for n, s in summary.items() if s.get("status") == "missing"],
            }
        except Exception as exc:
            logger.debug("Tool registry summary error: %s", exc)

    def _phase_upload(self, file_path: str, report: MobileSecurityReport) -> Optional[dict]:
        ext = Path(file_path).suffix.lower()
        platform = "android" if ext == ".apk" else "ios" if ext == ".ipa" else "unknown"

        if not self._upload_mgr:
            app = {
                "app_id": Path(file_path).stem[:16],
                "app_name": Path(file_path).stem,
                "package_name": "",
                "platform": platform,
                "extracted_dir": str(Path(file_path).parent / f"{Path(file_path).stem}_extracted"),
            }
            report.upload = app
            return app

        try:
            app = self._upload_mgr.upload(file_path, os.path.basename(file_path))
            if hasattr(app, "to_dict"):
                app = app.to_dict()
            app.setdefault("app_id",       app.get("id", Path(file_path).stem[:16]))
            app.setdefault("file_path",    app.get("upload_path", file_path))
            app.setdefault("extracted_dir",app.get("extract_path", ""))
            app.setdefault("app_name",     app.get("filename", Path(file_path).name))
            report.upload = app
            return app
        except Exception as exc:
            report.errors.append(f"Upload error: {exc}")
            logger.exception("Upload phase failed")
            return None

    def _phase_static(self, report: MobileSecurityReport,
                      file_path: str, extracted_dir: str,
                      config: MobileSecurityConfig):
        # Original static analyzer (AndroidManifest / aapt / androguard)
        if self._static_analyzer:
            try:
                result = self._static_analyzer.analyze(report.app_id, file_path, extracted_dir)
                report.static_analysis = result.to_dict() if hasattr(result, "to_dict") else result
                if hasattr(result, "package_name") and result.package_name:
                    report.package_name = result.package_name
            except Exception as exc:
                report.errors.append(f"Static analysis error: {exc}")
                logger.exception("Static analysis failed")

        # Advanced static analysis (APKTool + JADX + MobSF)
        if self._advanced_static:
            try:
                adv = self._advanced_static.analyze(report.app_id, file_path, extracted_dir)
                report.advanced_static = adv.to_dict() if hasattr(adv, "to_dict") else (adv if isinstance(adv, dict) else {})
            except Exception as exc:
                report.errors.append(f"Advanced static analysis error: {exc}")
                logger.debug("Advanced static analysis failed: %s", exc)

    def _phase_ai_reverse(self, report: MobileSecurityReport,
                          extracted_dir: str, config: MobileSecurityConfig):
        if not self._ai_reverser:
            report.ai_reverse_engineering = {"status": "unavailable", "findings": []}
            return
        try:
            # Look for decompiled Java source
            source_dir = _find_source_dir(extracted_dir)
            if not source_dir:
                report.ai_reverse_engineering = {
                    "status": "no_source",
                    "message": "No decompiled source found. Run with APKTool/JADX.",
                    "findings": [],
                }
                return
            app_model, findings = self._ai_reverser.analyze(
                source_dir, report.package_name, report.platform or "android"
            )
            finding_dicts = [
                f.to_dict() if hasattr(f, "to_dict") else (f if isinstance(f, dict) else vars(f))
                for f in findings
            ]
            report.ai_reverse_engineering = {
                "status": "complete",
                "app_model": vars(app_model) if hasattr(app_model, "__dict__") else {},
                "findings": finding_dicts,
                "total": len(findings),
                "attack_surface_score": getattr(app_model, "attack_surface_score", 0.0),
                "hidden_endpoints": getattr(app_model, "hidden_endpoints", []),
                "admin_functions": getattr(app_model, "admin_functions", []),
                "business_logic_flaws": getattr(app_model, "business_logic_flaws", []),
            }
            # Store app_model for Frida script generation
            report.ai_reverse_engineering["_app_model"] = app_model
        except Exception as exc:
            report.errors.append(f"AI reverse engineering error: {exc}")
            report.ai_reverse_engineering = {"status": "error", "error": str(exc), "findings": []}
            logger.exception("AI reverse engineering failed")

    def _phase_frida_scripts(self, report: MobileSecurityReport,
                             extracted_dir: str, config: MobileSecurityConfig):
        if not self._frida_gen:
            report.frida_scripts = {"status": "unavailable", "scripts": []}
            return
        try:
            app_model = report.ai_reverse_engineering.get("_app_model")
            scripts = self._frida_gen.generate_from_app_model(
                app_model, extracted_dir, report.platform or "android"
            )
            # Save scripts to extracted_dir/frida_scripts/
            scripts_dir = os.path.join(extracted_dir, "frida_scripts")
            os.makedirs(scripts_dir, exist_ok=True)
            saved = []
            for s in scripts:
                fname = f"{s.name.replace(' ', '_').lower()}.js"
                fpath = os.path.join(scripts_dir, fname)
                try:
                    Path(fpath).write_text(s.script_content)
                    saved.append({"name": s.name, "path": fpath,
                                  "description": s.description,
                                  "hook_type": getattr(s.targets[0], "hook_type", "") if s.targets else "",
                                  "auto_run": s.auto_run})
                except Exception:
                    pass
            report.frida_scripts = {
                "status": "complete",
                "scripts": saved,
                "total": len(scripts),
                "scripts_dir": scripts_dir,
            }
        except Exception as exc:
            report.errors.append(f"Frida script generation error: {exc}")
            report.frida_scripts = {"status": "error", "error": str(exc), "scripts": []}
            logger.debug("Frida script generation failed: %s", exc)

    def _phase_secrets(self, report: MobileSecurityReport, extracted_dir: str):
        findings_raw = []
        total = 0

        # Preferred: new mobile_secret_detection
        if self._secret_detector:
            try:
                sec_report = self._secret_detector.scan_app(extracted_dir, report.app_id)
                total = sec_report.total_findings
                findings_raw = sec_report.top_findings
                # Also get all findings if available
                if hasattr(sec_report, "findings_by_type"):
                    all_f = []
                    for lst in sec_report.findings_by_type.values():
                        all_f.extend(lst)
                    if all_f:
                        findings_raw = [
                            f.to_dict() if hasattr(f, "to_dict") else f
                            for f in all_f
                        ]
                report.secrets = {
                    "total_findings": total,
                    "findings": findings_raw,
                    "critical": sec_report.critical,
                    "high": sec_report.high,
                    "medium": sec_report.medium,
                    "low": sec_report.low,
                    "scan_duration": sec_report.scan_duration,
                }
                return
            except Exception as exc:
                logger.debug("New secret detector failed, falling back: %s", exc)

        # Fallback: original mobile_secret_scanner
        if self._secret_scanner:
            try:
                findings = self._secret_scanner.scan(extracted_dir, report.app_id)
                report.secrets = {
                    "total_findings": len(findings),
                    "findings": [f.to_dict() if hasattr(f, "to_dict") else f for f in findings],
                }
            except Exception as exc:
                report.errors.append(f"Secret scan error: {exc}")
                logger.exception("Secret scan failed")
        else:
            report.errors.append("Secret scanner not available")

    def _phase_api_discovery(self, report: MobileSecurityReport, extracted_dir: str):
        if not self._api_discovery:
            report.errors.append("API discovery not available")
            return
        try:
            result = self._api_discovery.discover(report.app_id, extracted_dir)
            report.api_discovery = result.to_dict() if hasattr(result, "to_dict") else (
                result if isinstance(result, dict) else {}
            )
        except Exception as exc:
            report.errors.append(f"API discovery error: {exc}")
            logger.exception("API discovery failed")

    def _phase_component_testing(self, report: MobileSecurityReport,
                                 extracted_dir: str, config: MobileSecurityConfig):
        if report.platform and report.platform != "android":
            return  # Component testing is Android-specific
        if not self._component_tester:
            report.component_testing = {"status": "unavailable", "findings": []}
            return
        try:
            result = self._component_tester.test_app(
                report.package_name or report.app_id,
                extracted_dir,
                config.device_id,
            )
            finding_dicts = []
            for f in getattr(result, "findings", []):
                finding_dicts.append(
                    f.to_dict() if hasattr(f, "to_dict") else (f if isinstance(f, dict) else vars(f))
                )
            report.component_testing = {
                "status": "complete",
                "activities_tested": getattr(result, "activities_tested", []),
                "services_tested": getattr(result, "services_tested", []),
                "receivers_tested": getattr(result, "receivers_tested", []),
                "providers_tested": getattr(result, "providers_tested", []),
                "drozer_available": getattr(result, "drozer_available", False),
                "static_only": getattr(result, "static_only", True),
                "findings": finding_dicts,
                "total": len(finding_dicts),
            }
        except Exception as exc:
            report.errors.append(f"Component testing error: {exc}")
            report.component_testing = {"status": "error", "error": str(exc), "findings": []}
            logger.debug("Component testing failed: %s", exc)

    def _phase_dynamic(self, report: MobileSecurityReport,
                       file_path: str, extracted_dir: str,
                       config: MobileSecurityConfig):
        if not self._dynamic_analyzer:
            report.dynamic_analysis = {
                "status": "unavailable",
                "message": "Dynamic analyzer not loaded",
                "findings": [],
            }
            return
        try:
            device_id = config.device_id
            if not device_id and self._android_studio:
                try:
                    session = self._android_studio.launch_emulator(wait=True, timeout=60)
                    if session:
                        device_id = session.device_id
                except Exception:
                    pass

            app_model = report.ai_reverse_engineering.get("_app_model")
            result = self._dynamic_analyzer.analyze(
                report.app_id,
                report.package_name,
                extracted_dir,
                device_id,
                app_model,
            )
            finding_dicts = []
            for f in getattr(result, "all_findings", []):
                finding_dicts.append(
                    f.to_dict() if hasattr(f, "to_dict") else (f if isinstance(f, dict) else vars(f))
                )
            report.dynamic_analysis = {
                "status": "complete",
                "ssl_bypassed": getattr(result, "ssl_bypassed", False),
                "root_bypassed": getattr(result, "root_bypassed", False),
                "network_traffic": getattr(result, "network_traffic", []),
                "crypto_operations": getattr(result, "crypto_operations", []),
                "storage_operations": getattr(result, "storage_operations", []),
                "frida_script_results": getattr(result, "frida_script_results", []),
                "duration": getattr(result, "duration", 0.0),
                "findings": finding_dicts,
                "total": len(finding_dicts),
            }
        except Exception as exc:
            report.errors.append(f"Dynamic analysis error: {exc}")
            report.dynamic_analysis = {"status": "error", "error": str(exc), "findings": []}
            logger.exception("Dynamic analysis failed")

    def _phase_network_analysis(self, report: MobileSecurityReport):
        if not self._network_analyzer:
            report.network_analysis = {"status": "unavailable", "findings": []}
            return
        try:
            # Static URL analysis using discovered endpoints
            urls = report.api_discovery.get("base_urls", [])
            endpoints = report.api_discovery.get("endpoints", [])
            findings = self._network_analyzer.analyze_static_urls(urls, endpoints)
            finding_dicts = [
                f.to_dict() if hasattr(f, "to_dict") else (f if isinstance(f, dict) else vars(f))
                for f in findings
            ]
            report.network_analysis = {
                "status": "complete",
                "findings": finding_dicts,
                "total": len(finding_dicts),
                "urls_analyzed": len(urls),
            }
        except Exception as exc:
            report.errors.append(f"Network analysis error: {exc}")
            report.network_analysis = {"status": "error", "error": str(exc), "findings": []}
            logger.debug("Network analysis failed: %s", exc)

    def _phase_api_attack(self, report: MobileSecurityReport, config: MobileSecurityConfig):
        endpoints = report.api_discovery.get("endpoints", [])
        if not endpoints:
            report.api_attack = {"status": "skipped", "reason": "no endpoints discovered"}
            return

        if self._api_attacker and config.run_api_attack:
            try:
                findings = self._api_attacker.test_endpoints(endpoints)
                finding_dicts = [
                    f.to_dict() if hasattr(f, "to_dict") else (f if isinstance(f, dict) else vars(f))
                    for f in findings
                ]
                report.api_attack = {
                    "status": "complete",
                    "endpoints_tested": len(endpoints[:20]),
                    "findings": finding_dicts,
                    "total": len(finding_dicts),
                }
            except Exception as exc:
                report.errors.append(f"API attack error: {exc}")
                report.api_attack = {"status": "error", "error": str(exc)}
        elif config.run_api_fuzzing:
            # Legacy fuzzing via TrafficReplayEngine
            results = []
            try:
                from oneinfinity.traffic_replay_engine import TrafficReplayEngine
                engine = TrafficReplayEngine()
                for ep in endpoints[:20]:
                    url = ep.get("full_url") or ep.get("url") or ep.get("path", "")
                    if not url or not url.startswith("http"):
                        continue
                    try:
                        r = engine.replay(url=url, method=ep.get("method", "GET"),
                                          headers={}, body="", modifications={},
                                          follow_redirects=True)
                        if r.get("suspicious") or r.get("flags"):
                            results.append({"url": url, "flags": r.get("flags", []),
                                            "status": r.get("status_code")})
                    except Exception:
                        pass
            except ImportError:
                pass
            report.api_fuzzing = {
                "endpoints_tested": min(len(endpoints), 20),
                "suspicious_results": len(results),
                "results": results,
            }

    # ─── Aggregation & Scoring ────────────────────────────────────────────────

    def _aggregate_vulnerabilities(self, report: MobileSecurityReport):
        all_vulns: List[dict] = []
        seen: set = set()

        def _add(v: dict):
            key = f"{v.get('type','')}:{v.get('file','')}:{v.get('detail','')[:40]}"
            if key not in seen:
                seen.add(key)
                all_vulns.append(v)

        def _from_unified(findings: list, source: str):
            for f in findings:
                if isinstance(f, dict):
                    _add({
                        "type": f.get("vulnerability", f.get("attack_type", f.get("type", "unknown"))),
                        "severity": f.get("severity", "medium"),
                        "detail": f.get("evidence", f.get("detail", f.get("description", ""))),
                        "source": source,
                        "file": f.get("file_path", f.get("file", "")),
                        "tool": f.get("tool", source),
                        "confidence": f.get("confidence", 0.8),
                        "cvss": f.get("cvss", 0.0),
                        "remediation": f.get("remediation", ""),
                    })

        # Original static analysis vulnerabilities
        for v in report.static_analysis.get("vulnerabilities", []):
            if isinstance(v, dict):
                _add({**v, "source": v.get("source", "static"), "tool": "mobile_static_analyzer"})

        # Advanced static analysis findings
        _from_unified(report.advanced_static.get("all_findings", []), "advanced_static")
        _from_unified(report.advanced_static.get("manifest_findings", []), "static_manifest")
        _from_unified(report.advanced_static.get("code_findings", []), "static_code")
        _from_unified(report.advanced_static.get("permission_findings", []), "static_permissions")

        # AI reverse engineering findings
        _from_unified(report.ai_reverse_engineering.get("findings", []), "ai_reverse")

        # Secrets
        for f in report.secrets.get("findings", []):
            if isinstance(f, dict):
                stype = f.get("secret_type", f.get("type", "secret"))
                fpath = f.get("file_path", f.get("file", ""))
                line  = f.get("line_number", 0)
                matched = f.get("matched_text", "")
                detail = (f"Found {stype} in {fpath}:{line} — {matched[:50]}"
                          if matched else f"Found {stype} in {fpath}")
                _add({
                    "type": stype, "severity": f.get("severity", "high"),
                    "detail": detail, "source": "secret_scanner",
                    "file": fpath, "tool": f.get("tool", "secret_scanner"),
                    "confidence": f.get("confidence", 0.8),
                })

        # Component testing findings
        _from_unified(report.component_testing.get("findings", []), "component_testing")

        # Dynamic analysis findings
        _from_unified(report.dynamic_analysis.get("findings", []), "dynamic")

        # Network analysis findings
        _from_unified(report.network_analysis.get("findings", []), "network_analysis")

        # API attack findings
        _from_unified(report.api_attack.get("findings", []), "api_attack")

        # Legacy API fuzzing
        for r in report.api_fuzzing.get("results", []):
            _add({
                "type": "api_anomaly", "severity": "medium",
                "detail": f"Suspicious API: {r.get('url','')} flags={r.get('flags',[])}",
                "source": "api_fuzzing", "tool": "traffic_replay",
            })

        report.all_vulnerabilities = all_vulns

        # Severity counts
        for v in all_vulns:
            sev = v.get("severity", "info").lower()
            if sev in report.severity_counts:
                report.severity_counts[sev] += 1

    def _calculate_risk_score(self, report: MobileSecurityReport):
        weights = {"critical": 10, "high": 7, "medium": 4, "low": 1, "info": 0}
        raw = sum(weights.get(sev, 0) * count
                  for sev, count in report.severity_counts.items())
        # Bonus for AI attack surface score
        ai_score = report.ai_reverse_engineering.get("attack_surface_score", 0.0)
        report.risk_score = min(100.0, raw + ai_score * 2)

    def _generate_recommendations(self, report: MobileSecurityReport):
        recs = set()
        sa = report.static_analysis
        dyn = report.dynamic_analysis

        if sa.get("debuggable"):
            recs.add("Remove android:debuggable=true before production release")
        if sa.get("backup_allowed"):
            recs.add("Set android:allowBackup=false to prevent ADB data extraction")
        if (sa.get("cleartext_traffic") or
                dyn.get("ssl_bypassed") or
                report.network_analysis.get("findings")):
            recs.add("Enforce HTTPS-only traffic and implement certificate pinning")
        if sa.get("dangerous_permissions"):
            perms = sa["dangerous_permissions"][:5]
            recs.add(f"Review dangerous permissions: {', '.join(perms)}")
        if sa.get("exported_components") or report.component_testing.get("findings"):
            recs.add("Add explicit android:permission to all exported components")
        if report.secrets.get("total_findings", 0) > 0:
            recs.add("Remove hardcoded secrets; use Android Keystore / iOS Keychain")
        if report.api_discovery.get("base_urls"):
            recs.add("Audit all discovered API endpoints for authentication and authorization")
        if report.ai_reverse_engineering.get("hidden_endpoints"):
            recs.add("Review AI-discovered hidden endpoints for unauthorized access paths")
        if report.ai_reverse_engineering.get("business_logic_flaws"):
            recs.add("Address business logic flaws identified by AI reverse engineering")
        if dyn.get("ssl_bypassed"):
            recs.add("Strengthen SSL/TLS pinning (consider OkHttp CertificatePinner + custom TrustManager)")
        if report.severity_counts.get("critical", 0) > 0:
            recs.add("CRITICAL: Address all critical severity findings before publishing")
        if report.severity_counts.get("high", 0) > 3:
            recs.add("Conduct a manual penetration test — high number of high-severity findings")

        report.recommendations = sorted(recs)

    def _update_attack_graph(self, report: MobileSecurityReport):
        try:
            ag = self._attack_graph
            if not ag:
                return
            # Add MobileApp node
            if hasattr(ag, "add_node"):
                app_node = ag.add_node(
                    node_type="mobile_app",
                    label=report.app_name or report.package_name or report.app_id,
                    metadata={
                        "platform": report.platform,
                        "risk_score": report.risk_score,
                        "severity_counts": report.severity_counts,
                    },
                )
                # Add API endpoint nodes
                for ep in report.api_discovery.get("endpoints", [])[:20]:
                    url = ep.get("url") or ep.get("full_url") or ep.get("path", "")
                    ep_node = ag.add_node(
                        node_type="api_endpoint",
                        label=url[:80],
                        metadata={"method": ep.get("method", "GET"), "risk": ep.get("risk_level", "low")},
                    )
                    ag.add_edge(app_node, ep_node, "uses_api")
                # Add vulnerability nodes
                for v in report.all_vulnerabilities[:30]:
                    vuln_node = ag.add_node(
                        node_type="vulnerability",
                        label=v.get("type", "unknown")[:60],
                        metadata={"severity": v.get("severity", "medium")},
                    )
                    ag.add_edge(app_node, vuln_node, "contains_vulnerability")
        except Exception as exc:
            logger.debug("Attack graph update error: %s", exc)


# ─── Helpers ──────────────────────────────────────────────────────────────────

def _find_source_dir(extracted_dir: str) -> Optional[str]:
    """Find decompiled Java/Kotlin source directory in extracted APK."""
    candidates = [
        os.path.join(extracted_dir, "jadx_src"),
        os.path.join(extracted_dir, "sources"),
        os.path.join(extracted_dir, "src"),
        extracted_dir,
    ]
    for c in candidates:
        if os.path.isdir(c):
            # Check for .java files
            p = Path(c)
            if any(p.rglob("*.java")) or any(p.rglob("*.kt")):
                return c
    return None


# ─── CLI entry ────────────────────────────────────────────────────────────────

def analyze_cli(args):
    """Entry point for `oneinfinity mobile-analyze <file>`."""
    engine = MobileSecurityEngine()
    config = MobileSecurityConfig(
        run_static=not getattr(args, "no_static", False),
        run_ai_reverse=not getattr(args, "no_ai", False),
        run_frida_gen=not getattr(args, "no_frida", False),
        run_secrets=not getattr(args, "no_secrets", False),
        run_api_discovery=not getattr(args, "no_api", False),
        run_component_testing=not getattr(args, "no_components", False),
        run_dynamic=getattr(args, "dynamic", False),
        run_network_analysis=not getattr(args, "no_network", False),
        run_api_attack=getattr(args, "attack", False),
        run_api_fuzzing=getattr(args, "fuzz", False),
        device_id=getattr(args, "device", ""),
        proxy_host=getattr(args, "proxy_host", ""),
        proxy_port=getattr(args, "proxy_port", 8080),
        output_dir=getattr(args, "output", ""),
    )

    file_path = args.file
    if not os.path.exists(file_path):
        print(f"[!] File not found: {file_path}")
        return

    print(f"[*] Starting mobile security analysis: {file_path}")
    report = engine.analyze(file_path, config)

    _print_report(report)


def _print_report(report: MobileSecurityReport):
    SEV_ICON = {"critical": "💀", "high": "🔴", "medium": "🟡", "low": "🔵", "info": "⚪"}
    print(f"\n{'='*65}")
    print(f"  Mobile Security Report — {report.app_name or report.app_id}")
    print(f"{'='*65}")
    print(f"  Platform:     {report.platform}")
    print(f"  Package:      {report.package_name}")
    print(f"  Risk Score:   {report.risk_score:.1f}/100")
    print(f"\n  Severity Breakdown:")
    for sev, count in report.severity_counts.items():
        if count:
            icon = SEV_ICON.get(sev, "•")
            bar = "█" * min(count, 20)
            print(f"    {sev.upper():10s} {count:3d}  {bar}")

    # Tool availability
    avail = report.tool_registry.get("available", [])
    missing = report.tool_registry.get("missing", [])
    if avail or missing:
        print(f"\n  Tools Available: {', '.join(avail) or 'none'}")
        if missing:
            print(f"  Tools Missing:   {', '.join(missing)}")

    # Frida scripts generated
    scripts = report.frida_scripts.get("scripts", [])
    if scripts:
        print(f"\n  Frida Scripts Generated ({len(scripts)}):")
        for s in scripts:
            print(f"    • {s.get('name','')} — {s.get('description','')[:60]}")

    # AI findings
    ai = report.ai_reverse_engineering
    if ai.get("hidden_endpoints"):
        print(f"\n  AI-Discovered Hidden Endpoints ({len(ai['hidden_endpoints'])}):")
        for ep in ai["hidden_endpoints"][:5]:
            print(f"    • {ep}")
    if ai.get("business_logic_flaws"):
        print(f"\n  Business Logic Flaws ({len(ai['business_logic_flaws'])}):")
        for f in ai["business_logic_flaws"][:3]:
            print(f"    • {f[:80]}")

    # Findings
    print(f"\n  Findings ({len(report.all_vulnerabilities)}):")
    for v in report.all_vulnerabilities[:25]:
        sev = v.get("severity", "info").lower()
        icon = SEV_ICON.get(sev, "•")
        vtype = v.get("type", "?")
        detail = v.get("detail", "")[:70]
        print(f"  {icon} [{sev.upper():<8}] {vtype}: {detail}")
    if len(report.all_vulnerabilities) > 25:
        print(f"  ... and {len(report.all_vulnerabilities) - 25} more findings")

    # Timing
    timing = report.phase_timings
    if timing:
        print(f"\n  Phase Timings:")
        for phase, t in timing.items():
            if phase != "total":
                print(f"    {phase:<25} {t:.1f}s")
        print(f"    {'TOTAL':<25} {timing.get('total', 0):.1f}s")

    # Recommendations
    if report.recommendations:
        print(f"\n  Recommendations:")
        for r in report.recommendations:
            print(f"  • {r}")

    # Errors
    if report.errors:
        print(f"\n  Errors ({len(report.errors)}):")
        for e in report.errors[:5]:
            print(f"  ! {e}")


# ─── Singleton ────────────────────────────────────────────────────────────────

mobile_security_engine = MobileSecurityEngine()
