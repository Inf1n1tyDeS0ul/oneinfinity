"""
confirmed_pipeline.py — Actions triggered when a finding is confirmed or dismissed.

Feature set
-----------
1. Neo4j graph weighting   — boost confirmed node confidence, mark verified=true
2. AI ground truth          — write to learning KB as labelled true/false positive
3. Re-test scheduling       — queue a targeted re-scan of the confirmed finding
4. God Mode seeding         — expose confirmed findings as anchors for attack chains
5. Bounty report            — generate markdown report from confirmed findings
6. Nuclei template          — auto-generate Nuclei YAML template for confirmed findings
"""
from __future__ import annotations

import hashlib
import json
import logging
import threading
import time
from datetime import datetime
from typing import Any, Dict, List, Optional

log = logging.getLogger("oneinfinity.findings.confirmed_pipeline")


# ── 1. Neo4j graph weighting ───────────────────────────────────────────────────

def _neo4j_boost_confirmed(finding: dict) -> None:
    """Raise confidence to 1.0 and set verified=true on the Neo4j vuln node."""
    try:
        from oneinfinity.attack_graph_core.graph_store import get_attack_graph
        g = get_attack_graph()
        if not g or not getattr(g, "_driver", None):
            return
        vuln_id  = finding.get("finding_id") or finding.get("id", "")
        url      = finding.get("url", "")
        vuln_type = finding.get("vuln_type", finding.get("title", ""))
        with g._driver.session() as sess:
            sess.run(
                """
                MERGE (v:Vulnerability {id: $vid})
                SET v.confidence  = 1.0,
                    v.verified    = true,
                    v.verified_at = $ts,
                    v.url         = $url,
                    v.vuln_type   = $vtype
                """,
                vid=vuln_id, ts=datetime.utcnow().isoformat(), url=url, vtype=vuln_type,
            )
        log.info("Neo4j: boosted confirmed finding %s", vuln_id)
    except Exception as exc:
        log.debug("Neo4j boost failed: %s", exc)


def _neo4j_mark_false_positive(finding: dict) -> None:
    """Lower confidence to 0.0 and set false_positive=true on the Neo4j vuln node."""
    try:
        from oneinfinity.attack_graph_core.graph_store import get_attack_graph
        g = get_attack_graph()
        if not g or not getattr(g, "_driver", None):
            return
        vuln_id = finding.get("finding_id") or finding.get("id", "")
        with g._driver.session() as sess:
            sess.run(
                """
                MERGE (v:Vulnerability {id: $vid})
                SET v.confidence     = 0.0,
                    v.false_positive = true,
                    v.verified_at    = $ts
                """,
                vid=vuln_id, ts=datetime.utcnow().isoformat(),
            )
    except Exception as exc:
        log.debug("Neo4j FP mark failed: %s", exc)


# ── 2. AI ground truth ─────────────────────────────────────────────────────────

def _write_ground_truth(finding: dict, label: bool) -> None:
    """
    Write confirmed (label=True) or false-positive (label=False) to the
    learning knowledge base so future confidence scoring improves.
    """
    try:
        from oneinfinity.learning.graph_learning_writer import get_graph_learning_writer
        glw = get_graph_learning_writer()
        enriched = {**finding, "confirmed": label, "ground_truth_at": datetime.utcnow().isoformat()}
        if label:
            glw.write_finding_async(enriched)
        else:
            # False positives: write with confirmed=False so the KB learns to avoid
            t = threading.Thread(
                target=glw.write_finding,
                args=({**enriched, "confidence": 0.0},),
                daemon=True,
            )
            t.start()
    except Exception as exc:
        log.debug("Ground truth write failed: %s", exc)

    # Also persist to learning_findings table in PostgreSQL
    try:
        from oneinfinity.core.db_manager import get_db_manager_sync
        mgr = get_db_manager_sync()
        mgr._run_sync(_pg_upsert_learning_finding(mgr, finding, label))
    except Exception as exc:
        log.debug("learning_findings DB write failed: %s", exc)


async def _pg_upsert_learning_finding(mgr, finding: dict, confirmed: bool) -> None:
    """Upsert into learning_findings table with ground-truth label."""
    try:
        if not hasattr(mgr, "_pg_pool") or mgr._pg_pool is None:
            return
        fid       = finding.get("finding_id") or finding.get("id", "")
        target    = finding.get("target", "")
        vuln_type = finding.get("vuln_type", finding.get("title", ""))
        tool      = finding.get("tool", "")
        severity  = finding.get("severity", "medium")
        cvss      = float(finding.get("cvss") or 0.0)
        async with mgr._pg_pool.connection() as conn:
            await conn.execute(
                """
                INSERT INTO learning_findings
                    (scan_id, target, endpoint, parameter, source_tool, confirmed,
                     evidence, tested_at, chain_id)
                VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9)
                ON CONFLICT DO NOTHING
                """,
                finding.get("scan_id", "manual"),
                target,
                finding.get("url", target),
                vuln_type,
                tool,
                1 if confirmed else 0,
                json.dumps({"severity": severity, "cvss": cvss, "finding_id": fid}),
                datetime.utcnow().isoformat(),
                None,
            )
    except Exception as exc:
        log.debug("_pg_upsert_learning_finding: %s", exc)


# ── 3. Re-test scheduling ──────────────────────────────────────────────────────

_RETEST_QUEUE: List[dict] = []
_RETEST_LOCK = threading.Lock()


def schedule_retest(finding: dict) -> str:
    """
    Queue a targeted re-scan for a confirmed finding.
    Returns a retest_id that the caller can use to poll status.
    """
    retest_id = hashlib.sha1(
        f"{finding.get('finding_id','')}{time.time()}".encode()
    ).hexdigest()[:12]

    entry = {
        "retest_id":  retest_id,
        "finding_id": finding.get("finding_id") or finding.get("id"),
        "target":     finding.get("target", ""),
        "url":        finding.get("url", ""),
        "vuln_type":  finding.get("vuln_type", finding.get("title", "")),
        "tool":       finding.get("tool", ""),
        "scan_id":    finding.get("scan_id", ""),
        "source_type": finding.get("source_type", "tool"),
        "status":     "queued",
        "queued_at":  datetime.utcnow().isoformat(),
        "result":     None,
    }
    with _RETEST_LOCK:
        _RETEST_QUEUE.append(entry)

    threading.Thread(
        target=_run_retest,
        args=(entry,),
        daemon=True,
        name=f"retest-{retest_id}",
    ).start()

    log.info("Retest queued: %s for finding %s", retest_id, entry["finding_id"])
    return retest_id


def get_retest_status(retest_id: str) -> Optional[dict]:
    with _RETEST_LOCK:
        return next((e for e in _RETEST_QUEUE if e["retest_id"] == retest_id), None)


def get_all_retests() -> List[dict]:
    with _RETEST_LOCK:
        return list(_RETEST_QUEUE)


def _run_retest(entry: dict) -> None:
    """Run the actual re-scan in a background thread."""
    entry["status"] = "running"
    entry["started_at"] = datetime.utcnow().isoformat()
    try:
        source_type = entry.get("source_type", "tool")
        result = _retest_mobile(entry) if source_type == "mobile" else _retest_web(entry)
        entry["status"] = "completed"
        entry["result"] = result
        entry["completed_at"] = datetime.utcnow().isoformat()

        # Write retest result back to learning KB
        _write_ground_truth({**entry, **result}, confirmed=result.get("still_vulnerable", False))
    except Exception as exc:
        log.warning("Retest %s failed: %s", entry["retest_id"], exc)
        entry["status"] = "error"
        entry["result"] = {"error": str(exc)}
        entry["completed_at"] = datetime.utcnow().isoformat()


def _retest_web(entry: dict) -> dict:
    """Re-probe a web finding using nuclei against the specific URL."""
    import shutil, subprocess, tempfile, json as _json
    url      = entry.get("url") or entry.get("target", "")
    vuln_type = entry.get("vuln_type", "")
    nuclei = shutil.which("nuclei")
    if not nuclei or not url:
        return {"still_vulnerable": None, "note": "nuclei unavailable or no URL"}
    with tempfile.NamedTemporaryFile(suffix=".json", delete=False) as f:
        out = f.name
    try:
        subprocess.run(
            [nuclei, "-u", url, "-severity", "medium,high,critical",
             "-jsonl", "-o", out, "-silent", "-no-interactsh"],
            timeout=120, capture_output=True,
        )
        from pathlib import Path
        lines = [_json.loads(l) for l in Path(out).read_text().splitlines() if l.strip()]
        still = any(vuln_type.lower() in _json.dumps(l).lower() for l in lines)
        return {"still_vulnerable": still, "findings_count": len(lines), "raw": lines[:5]}
    except Exception as exc:
        return {"still_vulnerable": None, "error": str(exc)}
    finally:
        from pathlib import Path
        Path(out).unlink(missing_ok=True)


def _retest_mobile(entry: dict) -> dict:
    """For mobile findings, re-run static analysis on the same APK if available."""
    scan_id = entry.get("scan_id", "")
    app_id  = scan_id.replace("mobile_", "") if scan_id.startswith("mobile_") else scan_id
    note    = f"Mobile retest queued for app_id={app_id}. Re-run analysis from the Mobile Security page."
    return {"still_vulnerable": None, "note": note, "app_id": app_id}


# ── 4. God Mode seeding — expose confirmed findings as anchors ─────────────────

def get_confirmed_anchors(target: Optional[str] = None) -> List[dict]:
    """
    Return confirmed findings suitable as God Mode attack anchors.
    Optionally filtered by target.
    """
    try:
        from oneinfinity.findings.result_ingestion_engine import get_ingestion_engine
        findings = get_ingestion_engine().get_findings()
        anchors = []
        for f in findings:
            if f.get("status") != "confirmed":
                continue
            if target and target not in (f.get("target", "") + f.get("url", "")):
                continue
            anchors.append({
                "finding_id": f.get("finding_id", f.get("id")),
                "title":      f.get("title", ""),
                "vuln_type":  f.get("vuln_type", ""),
                "url":        f.get("url", ""),
                "target":     f.get("target", ""),
                "severity":   f.get("severity", "medium"),
                "cvss":       float(f.get("cvss") or 0.0),
                "evidence":   f.get("evidence", ""),
                "tool":       f.get("tool", ""),
            })
        # Sort by CVSS desc — highest impact anchors first
        return sorted(anchors, key=lambda x: x["cvss"], reverse=True)
    except Exception as exc:
        log.warning("get_confirmed_anchors failed: %s", exc)
        return []


# ── 5. Bounty report generation ────────────────────────────────────────────────

def generate_bounty_report(target: Optional[str] = None, fmt: str = "markdown") -> str:
    """
    Generate a structured bounty report from all confirmed findings.
    fmt: "markdown" | "json"
    """
    try:
        from oneinfinity.findings.result_ingestion_engine import get_ingestion_engine
        all_findings = get_ingestion_engine().get_findings()
    except Exception as exc:
        return f"# Error\nCould not load findings: {exc}"

    confirmed = [
        f for f in all_findings
        if f.get("status") == "confirmed"
        and (not target or target in (f.get("target", "") + f.get("url", "")))
    ]
    confirmed.sort(
        key=lambda f: {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}.get(f.get("severity", "info"), 5)
    )

    if fmt == "json":
        return json.dumps({"generated_at": datetime.utcnow().isoformat(), "findings": confirmed}, indent=2)

    return _render_markdown_report(confirmed, target)


def _render_markdown_report(findings: List[dict], target: Optional[str]) -> str:
    sev_emoji = {"critical": "🔴", "high": "🟠", "medium": "🟡", "low": "🔵", "info": "⚪"}
    counts: Dict[str, int] = {}
    for f in findings:
        counts[f.get("severity", "info")] = counts.get(f.get("severity", "info"), 0) + 1

    lines = [
        "# Security Vulnerability Report",
        "",
        f"**Generated:** {datetime.utcnow().strftime('%Y-%m-%d %H:%M UTC')}",
        f"**Target:** {target or 'All Targets'}",
        f"**Total Confirmed Findings:** {len(findings)}",
        "",
        "## Executive Summary",
        "",
        "| Severity | Count |",
        "|----------|-------|",
    ]
    for sev in ["critical", "high", "medium", "low", "info"]:
        if counts.get(sev):
            lines.append(f"| {sev_emoji.get(sev,'')} {sev.capitalize()} | {counts[sev]} |")
    lines += ["", "---", "", "## Findings", ""]

    for i, f in enumerate(findings, 1):
        sev  = f.get("severity", "info")
        cvss = f.get("cvss")
        lines += [
            f"### {i}. {f.get('title', f.get('vuln_type', 'Finding'))}",
            "",
            f"**Severity:** {sev_emoji.get(sev,'')} `{sev.upper()}`" +
            (f"  **CVSS:** `{float(cvss):.1f}`" if cvss else ""),
            f"**Type:** `{f.get('vuln_type', '')}`",
            f"**Target:** `{f.get('target', '')}`",
            f"**URL / File:** `{f.get('url', '')}`",
            f"**Tool:** `{f.get('tool', '')}`",
            f"**Confidence:** `{int(float(f.get('confidence', 0.8)) * 100)}%`",
            "",
        ]
        if f.get("evidence"):
            lines += ["**Evidence:**", "```", f.get("evidence", ""), "```", ""]
        if f.get("payload") and f.get("payload") != f.get("evidence"):
            lines += ["**Payload / Value:**", "```", f.get("payload", ""), "```", ""]
        if f.get("remediation") or f.get("raw", {}).get("payload"):
            rem = f.get("remediation") or f.get("raw", {}).get("payload", "")
            lines += [f"**Remediation:** {rem}", ""]
        lines += ["---", ""]

    if not findings:
        lines += ["*No confirmed findings found. Confirm findings from the Intelligence Vault.*", ""]

    lines += [
        "## Disclosure",
        "",
        "This report was generated by OneInfinity automated security analysis.",
        "All findings listed have been manually confirmed as true positives.",
        "",
    ]
    return "\n".join(lines)


# ── 6. SSRF cloud-credential lateral chain ────────────────────────────────────

import re as _re

def _trigger_lateral_cve_chain(finding: dict) -> None:
    """On cloud_credential_via_ssrf confirmation, run GoServiceCveMapper on all
    lateral IPs stored in finding['evidence'] and ingest the CVE findings."""
    try:
        evidence = str(finding.get("evidence", ""))
        # Parse IPs appended by ssrf_scanner._add_lateral_movement_targets:
        #   "\nLateral movement targets: ['10.0.1.5', '10.0.1.6']"
        ip_list_match = _re.search(r'Lateral movement targets:\s*(\[[^\]]*\])', evidence)
        if not ip_list_match:
            log.debug("_trigger_lateral_cve_chain: no lateral IPs in evidence")
            return
        import ast as _ast
        lateral_ips = _ast.literal_eval(ip_list_match.group(1))
        if not lateral_ips:
            return

        from oneinfinity.scan.go_service_cve_mapper import GoServiceCveMapper
        import asyncio as _asyncio

        mapper = GoServiceCveMapper()
        if not mapper.is_available():
            log.debug("_trigger_lateral_cve_chain: GoServiceCveMapper binary unavailable")
            return

        _HIGH_VALUE_PORTS = [
            (6379,  "redis"),
            (9200,  "elasticsearch"),
            (27017, "mongodb"),
            (5432,  "postgresql"),
            (3306,  "mysql"),
            (2181,  "zookeeper"),
            (8500,  "consul"),
            (8200,  "vault"),
        ]
        services = [
            {"host": ip, "port": port, "service": svc, "banner": ""}
            for ip in lateral_ips
            for port, svc in _HIGH_VALUE_PORTS
        ]

        loop = _asyncio.new_event_loop()
        try:
            cve_findings = loop.run_until_complete(mapper.map_services(services))
        finally:
            loop.close()

        if not cve_findings:
            log.info("_trigger_lateral_cve_chain: no CVE findings on %d lateral IPs", len(lateral_ips))
            return

        log.warning(
            "[CHAIN] cloud_credential_via_ssrf confirmed → %d CVEs on lateral IPs %s",
            len(cve_findings), lateral_ips,
        )
        try:
            from oneinfinity.findings.result_ingestion_engine import get_ingestion_engine, RawResult
            scan_id = finding.get("scan_id", "lateral_cve_chain")
            eng = get_ingestion_engine()
            for cf in cve_findings:
                cf.setdefault("source_chain", "cloud_credential_via_ssrf")
                cf.setdefault("parent_finding_id", finding.get("finding_id") or finding.get("id"))
                eng.ingest(RawResult(scan_id=scan_id, source="oi-service-cve-mapper", raw=cf))
        except Exception as _ie:
            log.debug("_trigger_lateral_cve_chain: ingestion error: %s", _ie)
    except Exception as exc:
        log.debug("_trigger_lateral_cve_chain: %s", exc)


def _generate_nuclei_template(finding: dict) -> None:
    """Save a Nuclei YAML template for a confirmed high-confidence finding."""
    try:
        from oneinfinity.attack.nuclei_template_generator import get_generator
        path = get_generator().save(finding)
        finding.setdefault("metadata", {})["template_path"] = path
        log.info("[confirmed_pipeline] Nuclei template: %s", path)
    except Exception as exc:
        log.warning("[confirmed_pipeline] Nuclei template generation failed: %s", exc)


# ── Public dispatcher ──────────────────────────────────────────────────────────

def on_status_change(finding: dict, new_status: str) -> None:
    """
    Call this whenever a finding's status changes.
    Dispatches to all relevant pipeline features asynchronously.
    """
    if new_status == "confirmed":
        threading.Thread(target=_neo4j_boost_confirmed, args=(finding,), daemon=True).start()
        threading.Thread(target=_write_ground_truth,    args=(finding, True), daemon=True).start()
        if str(finding.get("vuln_type", "")).lower() == "cloud_credential_via_ssrf":
            threading.Thread(target=_trigger_lateral_cve_chain, args=(finding,), daemon=True).start()
        # Auto-generate Nuclei template for high-confidence confirmed findings
        confidence = float(finding.get("confidence") or 0.0)
        if confidence >= 0.85:
            threading.Thread(target=_generate_nuclei_template, args=(finding,), daemon=True).start()

    elif new_status == "false_positive":
        threading.Thread(target=_neo4j_mark_false_positive, args=(finding,), daemon=True).start()
        threading.Thread(target=_write_ground_truth,         args=(finding, False), daemon=True).start()
