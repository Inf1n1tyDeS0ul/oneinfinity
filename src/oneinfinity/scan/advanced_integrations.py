"""
Advanced Integrations
======================
Integration helpers for zero-day detection, autonomous validation, and intelligent features.

Designed to plug into unified_advanced_scanner.run_full_scan().
"""
from __future__ import annotations

import logging
from typing import List, Dict, Any

log = logging.getLogger("oneinfinity.advanced_integrations")


# ── Zero-Day Detection Integration ───────────────────────────────────────────

def integrate_zero_day_detection(target: str, all_findings: List[Dict]) -> List[Dict]:
    """
    Run zero-day detection on all captured traffic.

    Returns:
        List of anomaly findings (potential zero-days)
    """
    anomalies = []

    try:
        from oneinfinity.attack.zero_day_engine import ZeroDayEngine, ResponseProfile
        from oneinfinity.scan.traffic_capture_engine import traffic_capture_engine

        # Get all traffic for target
        all_traffic = traffic_capture_engine.list(target=target, limit=10000)

        if not all_traffic:
            log.info("No traffic captured for zero-day detection")
            return anomalies

        # Convert to ResponseProfile
        profiles = []
        for req in all_traffic:
            profile = ResponseProfile(
                url=req.url,
                method=req.method,
                status_code=req.response_status,
                content_length=len(req.response_body) if req.response_body else 0,
                content_type=req.response_headers.get('content-type', '') if req.response_headers else '',
                response_time_ms=req.duration_ms,
                headers=req.response_headers or {},
                body_snippet=req.response_body[:2048] if req.response_body else '',
                body_hash="",  # Could compute if needed
                redirect_location=req.response_headers.get('location', '') if req.response_headers else '',
                server=req.response_headers.get('server', '') if req.response_headers else '',
                error_present=req.response_status >= 400,
            )
            profiles.append(profile)

        # Run zero-day detection
        zero_day_engine = ZeroDayEngine()
        detected_anomalies = zero_day_engine.detect_anomalies(profiles)

        # Convert to finding format
        for anomaly in detected_anomalies:
            if anomaly.confidence >= 0.70:  # High-confidence anomalies only
                finding = {
                    "finding_id": anomaly.anomaly_id,
                    "vuln_type": "zero_day_candidate",
                    "anomaly_type": anomaly.anomaly_type,
                    "title": f"Zero-day candidate: {anomaly.anomaly_type}",
                    "severity": anomaly.severity,
                    "url": anomaly.endpoint,
                    "parameter": anomaly.parameter,
                    "evidence": anomaly.evidence,
                    "confidence": anomaly.confidence,
                    "baseline_value": anomaly.baseline_value,
                    "observed_value": anomaly.observed_value,
                    "payload_used": anomaly.payload_used,
                    "recommended_follow_up": anomaly.recommended_follow_up,
                    "tool": "zero_day_engine",
                    "source_type": "passive",
                }
                anomalies.append(finding)

        log.info(f"Zero-day detection found {len(anomalies)} high-confidence anomalies")

    except Exception as e:
        log.error(f"Zero-day detection failed: {e}")

    return anomalies


# ── Autonomous Validation Integration ────────────────────────────────────────

def integrate_autonomous_validation(all_findings: List[Dict]) -> Dict[str, Any]:
    """
    Validate all findings via re-exploitation.

    Returns:
        Dict with validated findings and false positives
    """
    result = {
        "validated_findings": [],
        "false_positives": [],
        "validation_stats": {},
    }

    try:
        from oneinfinity.attack.autonomous_exploit_engine import AutonomousExploitEngine

        exploit_engine = AutonomousExploitEngine()

        for finding in all_findings:
            validation = exploit_engine.validate_finding(finding)

            if validation['status'] == 'confirmed':
                # Finding confirmed
                finding['validated'] = True
                finding['confidence'] = validation.get('confidence', finding.get('confidence', 0.5))
                finding['validation_evidence'] = validation.get('evidence', '')
                result['validated_findings'].append(finding)

            elif validation['status'] == 'false_positive':
                # False positive detected
                result['false_positives'].append(finding)

            else:
                # Skipped (no validator available)
                result['validated_findings'].append(finding)  # Keep as-is

        result['validation_stats'] = {
            "total_tested": len(all_findings),
            "confirmed": len(result['validated_findings']),
            "false_positives": len(result['false_positives']),
            "false_positive_rate": len(result['false_positives']) / len(all_findings) if all_findings else 0,
        }

        log.info(f"Validation: {len(result['validated_findings'])} confirmed, {len(result['false_positives'])} false positives")

    except Exception as e:
        log.error(f"Autonomous validation failed: {e}")
        # Return all findings unvalidated
        result['validated_findings'] = all_findings

    return result


# ── Traffic Correlation Integration ──────────────────────────────────────────

def integrate_traffic_correlation(all_findings: List[Dict], target: str) -> Dict[str, Any]:
    """
    Correlate findings via traffic patterns.

    Returns:
        Dict with correlated chains by type
    """
    result = {
        "correlated_chains": [],
        "correlation_stats": {},
    }

    try:
        from oneinfinity.scan.traffic_correlation_engine import TrafficCorrelationEngine

        engine = TrafficCorrelationEngine()
        correlation_results = engine.correlate_all(all_findings, target)

        # Flatten chains
        for correlation_type, chains in correlation_results.items():
            for chain in chains:
                result['correlated_chains'].append({
                    "chain_id": chain.chain_id,
                    "name": chain.name,
                    "severity": chain.severity,
                    "description": chain.description,
                    "correlation_type": chain.correlation_type,
                    "endpoint": chain.endpoint,
                    "shared_params": list(chain.shared_params),
                    "confidence": chain.confidence,
                    "exploitation_steps": chain.exploitation_steps,
                    "evidence": chain.evidence,
                    "findings_count": len(chain.findings),
                })

        result['correlation_stats'] = {
            "total_chains": len(result['correlated_chains']),
            "by_type": {k: len(v) for k, v in correlation_results.items()},
        }

        log.info(f"Traffic correlation found {len(result['correlated_chains'])} chains")

    except Exception as e:
        log.error(f"Traffic correlation failed: {e}")

    return result


# ── Chain Suggestion Integration ─────────────────────────────────────────────

def integrate_chain_suggestions(all_findings: List[Dict]) -> Dict[str, Any]:
    """
    Generate chain completion suggestions.

    Returns:
        Dict with suggestions and priority scanners
    """
    result = {
        "suggestions": [],
        "priority_scanners": [],
        "report": "",
    }

    try:
        from oneinfinity.scan.chain_suggestion_engine import ChainSuggestionEngine

        engine = ChainSuggestionEngine()
        suggestions = engine.suggest_next_tests(all_findings)

        result['suggestions'] = [
            {
                "chain_name": s.chain_name,
                "severity": s.chain_severity,
                "completion_percentage": s.completion_percentage,
                "missing_vuln_types": s.missing_vuln_types,
                "present_vuln_types": s.present_vuln_types,
                "recommended_scanner": s.recommended_scanner,
                "confidence": s.confidence,
                "priority_score": s.priority_score,
                "exploitation_impact": s.exploitation_impact,
            }
            for s in suggestions
        ]

        result['priority_scanners'] = engine.get_priority_scanners(suggestions)
        result['report'] = engine.format_suggestions(suggestions)

        log.info(f"Generated {len(suggestions)} chain suggestions")

    except Exception as e:
        log.error(f"Chain suggestion failed: {e}")

    return result


# ── Payload Mutation Integration ─────────────────────────────────────────────

async def integrate_payload_mutation(target: str) -> Dict[str, Any]:
    """
    Learn and mutate payloads.

    Returns:
        Dict with payload library and mutation results
    """
    result = {
        "payload_library": {},
        "mutations_tested": 0,
        "mutation_findings": [],
    }

    try:
        from oneinfinity.scan.payload_mutation_engine import PayloadMutationEngine

        engine = PayloadMutationEngine()

        # Extract learned payloads
        library = engine.extract_successful_payloads(target)
        result['payload_library'] = {k: len(v) for k, v in library.items()}

        # Apply mutations
        mutation_findings = await engine.apply_learned_payloads(target)
        result['mutation_findings'] = mutation_findings
        result['mutations_tested'] = len(mutation_findings)

        log.info(f"Payload mutation: {len(library)} payload types, {len(mutation_findings)} mutations tested")

    except Exception as e:
        log.error(f"Payload mutation failed: {e}")

    return result
