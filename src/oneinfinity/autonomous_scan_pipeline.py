"""
autonomous_scan_pipeline.py — LEGACY SHIM

This module is deprecated. Please use unified_scan_engine.py directly.
It now acts as a wrapper around UnifiedScanEngine for backward compatibility.
"""
import logging
import uuid
import time
from dataclasses import dataclass, field
from oneinfinity.unified_scan_engine import get_engine

logger = logging.getLogger(__name__)

class PipelinePhase:
    DISCOVERY  = "discovery"
    RECON      = "recon"
    CRAWL      = "crawl"
    VULN_SCAN  = "vuln_scan"
    EXPLOIT    = "exploit"
    VALIDATE   = "validate"
    REPORT     = "report"

@dataclass
class PipelineConfig:
    target: str = ""
    phases: list = field(default_factory=list)
    auto_exploit: bool = False
    validate_findings: bool = True
    generate_report: bool = True

class AutonomousScanPipeline:
    def run(self, target: str, config=None):
        logger.info("Legacy autonomous_scan_pipeline.run() called for %s", target)
        engine = get_engine()
        
        # Mapping callback
        def on_progress(phase, pct, msg):
            logger.info("[%d%%] %s: %s", pct, phase, msg)

        session = engine.scan(target, on_progress=on_progress)
        
        # Convert UnifiedScanSession to legacy dict format
        return {
            "target": target,
            "session_id": session.scan_id,
            "findings": session.findings,
            "vulnerabilities": session.findings, # compatibility alias
            "status": session.status,
            "to_dict": lambda: {
                "target": target,
                "session_id": session.scan_id,
                "findings": session.findings,
                "vulnerabilities": session.findings,
            }
        }

    async def run_async(self, target: str, config=None):
        return self.run(target, config)

autonomous_scan_pipeline = AutonomousScanPipeline()
