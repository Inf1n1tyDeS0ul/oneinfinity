"""
core/target_prioritizer.py — Smart Target Prioritization (Phase 6 Fix 1)

Scores and ranks targets/URLs by expected vulnerability density and bounty value.
High-value endpoints are promoted to the front of the scan queue so the most
impactful findings arrive first — maximising bounty ROI per unit of scan time.

Scoring model:
    URL pattern signals     (path keywords, parameters, API depth)
    Historical signals      (previously confirmed vulns on this host)
    Program signals         (bounty table — higher payout → higher priority)
    Technology signals      (tech stack hints from recon)
    Context signals         (findings already in pipeline ctx)

All scores are additive integers — higher = higher priority.
"""
from __future__ import annotations

import logging
import re
from typing import Dict, List, Optional, Tuple
from urllib.parse import urlparse, parse_qs

log = logging.getLogger("oneinfinity.core.target_prioritizer")

# ---------------------------------------------------------------------------
# URL-pattern scoring table
# ---------------------------------------------------------------------------

# (regex_pattern, score, label)
_URL_RULES: List[Tuple[re.Pattern, int, str]] = [
    # Authentication / session management — highest bounty surface
    (re.compile(r"/(login|signin|sign-in|auth|oauth|sso|saml|token|session)", re.I), 5, "auth"),
    (re.compile(r"/(logout|signout|sign-out)", re.I), 2, "auth-logout"),
    (re.compile(r"/(password|passwd|reset|forgot|recovery)", re.I), 4, "password-reset"),
    (re.compile(r"/(register|signup|sign-up|onboard)", re.I), 3, "registration"),
    # Administrative / privileged
    (re.compile(r"/(admin|administrator|management|manage|console|panel|dashboard)", re.I), 5, "admin"),
    (re.compile(r"/(superuser|root|staff|internal|backoffice)", re.I), 5, "privileged"),
    # API endpoints — always high value
    (re.compile(r"/api/", re.I), 4, "api"),
    (re.compile(r"/(v\d+|v\d+\.\d+)/", re.I), 3, "api-versioned"),
    (re.compile(r"/graphql|/gql|/query", re.I), 4, "graphql"),
    (re.compile(r"/(rest|rpc|grpc|soap|wsdl)", re.I), 3, "rpc"),
    (re.compile(r"/webhook|/callback|/hook", re.I), 3, "webhook"),
    # File / upload operations
    (re.compile(r"/(upload|file|attachment|document|media|image|avatar|photo)", re.I), 4, "file-upload"),
    (re.compile(r"/(download|export|import|backup|archive)", re.I), 3, "file-ops"),
    # Payment / financial
    (re.compile(r"/(payment|billing|checkout|order|invoice|subscription|cart|purchase)", re.I), 4, "payment"),
    (re.compile(r"/(transfer|withdraw|deposit|wallet|balance|refund)", re.I), 4, "financial"),
    # User / profile data
    (re.compile(r"/(user|profile|account|me|whoami|settings|preferences)", re.I), 3, "user-data"),
    (re.compile(r"/(email|phone|address|contact|notification)", re.I), 2, "pii"),
    # Search / query (injection surface)
    (re.compile(r"/(search|find|query|lookup|filter)", re.I), 3, "search"),
    # SSRF / redirect targets
    (re.compile(r"/(proxy|fetch|redirect|forward|open|url|link|href|goto|next|return)", re.I), 3, "ssrf-candidate"),
    # Debug / dev endpoints
    (re.compile(r"/(debug|test|dev|staging|preview|beta)", re.I), 3, "debug"),
    (re.compile(r"/(swagger|openapi|docs|redoc|api-docs|apidoc)", re.I), 2, "api-docs"),
    # Cloud / infra
    (re.compile(r"/(health|status|metrics|monitor|actuator|info|env)", re.I), 2, "health"),
]

# Parameter presence bonus
_PARAM_BONUS = 3

# Previously vulnerable host bonus (applied if ctx has findings for this host)
_PREV_VULN_BONUS = 6

# API path depth bonus — deep API paths tend to have richer vuln surface
_API_DEPTH_BONUS_PER_SEGMENT = 1
_API_DEPTH_MAX_BONUS = 4

# ---------------------------------------------------------------------------
# Severity weights for "previously confirmed" scoring
# ---------------------------------------------------------------------------

_PREV_SEVERITY_BONUS: Dict[str, int] = {
    "critical": 8,
    "high":     6,
    "medium":   4,
    "low":      2,
    "info":     1,
}

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _extract_host(target: str) -> str:
    """Return bare hostname from URL or domain string."""
    target = target.strip()
    if "://" in target:
        return urlparse(target).hostname or target
    return target.split("/")[0].split(":")[0]


def _has_parameters(target: str) -> bool:
    """Return True if URL has query parameters."""
    return "?" in target


def _path_depth(target: str) -> int:
    """Return the number of path segments."""
    if "://" in target:
        path = urlparse(target).path or ""
    else:
        path = target.split("?")[0]
    return len([s for s in path.split("/") if s])


# ---------------------------------------------------------------------------
# Scorer
# ---------------------------------------------------------------------------


class TargetScore:
    """Score for a single target/URL."""

    __slots__ = ("target", "score", "signals")

    def __init__(self, target: str, score: int, signals: List[str]) -> None:
        self.target = target
        self.score = score
        self.signals = signals

    def to_dict(self) -> dict:
        return {"target": self.target, "score": self.score, "signals": self.signals}


def score_target(
    target: str,
    ctx: Optional[dict] = None,
    vuln_history: Optional[Dict[str, int]] = None,
) -> TargetScore:
    """
    Score a single target URL/domain.

    Parameters
    ----------
    target       : URL or domain string
    ctx          : pipeline context dict (provides scan_findings for host history)
    vuln_history : {host: max_severity_bonus} from a previous session — optional
    """
    score = 0
    signals: List[str] = []

    target_lower = target.lower()

    # ── URL-pattern rules ─────────────────────────────────────────────────────
    for pattern, pts, label in _URL_RULES:
        if pattern.search(target_lower):
            score += pts
            signals.append(f"+{pts}:{label}")

    # ── Parameter presence ────────────────────────────────────────────────────
    if _has_parameters(target):
        score += _PARAM_BONUS
        signals.append(f"+{_PARAM_BONUS}:has-params")

    # ── API path depth ────────────────────────────────────────────────────────
    if "/api/" in target_lower or "/v1/" in target_lower or "/v2/" in target_lower:
        depth_bonus = min(_path_depth(target) * _API_DEPTH_BONUS_PER_SEGMENT, _API_DEPTH_MAX_BONUS)
        if depth_bonus > 0:
            score += depth_bonus
            signals.append(f"+{depth_bonus}:api-depth")

    # ── Historical vuln on this host (from ctx scan_findings) ────────────────
    host = _extract_host(target)
    if ctx:
        prior_findings = ctx.get("scan_findings", []) or []
        host_findings = [
            f for f in prior_findings
            if host in str(f.get("url", "")) or host in str(f.get("target", ""))
        ]
        if host_findings:
            # Give max severity bonus across all prior findings for this host
            max_sev = max(
                _PREV_SEVERITY_BONUS.get((f.get("severity") or "info").lower(), 1)
                for f in host_findings
            )
            score += max_sev
            signals.append(f"+{max_sev}:prior-vuln-host")

    # ── Explicit vuln history dict ────────────────────────────────────────────
    if vuln_history and host in vuln_history:
        bonus = vuln_history[host]
        score += bonus
        signals.append(f"+{bonus}:vuln-history")

    return TargetScore(target=target, score=score, signals=signals)


# ---------------------------------------------------------------------------
# Prioritizer
# ---------------------------------------------------------------------------


class TargetPrioritizer:
    """
    Ranks a list of targets/URLs by expected vulnerability density.

    Usage::
        prioritizer = TargetPrioritizer()
        ranked = prioritizer.rank(targets, ctx=ctx)
        # ranked is sorted highest-score first
    """

    def __init__(self) -> None:
        # Persistent vuln history: {host: max_severity_bonus} — updated after each scan
        self._vuln_history: Dict[str, int] = {}

    def rank(
        self,
        targets: List[str],
        ctx: Optional[dict] = None,
    ) -> List[str]:
        """
        Score and sort targets by priority.

        Returns a new list sorted highest-priority first.
        Targets with equal scores preserve their original relative order.
        """
        scored = [
            score_target(t, ctx=ctx, vuln_history=self._vuln_history)
            for t in targets
        ]
        scored.sort(key=lambda s: s.score, reverse=True)

        if scored:
            top = scored[0]
            log.info(
                "[prioritizer] Top target: %s (score=%d signals=%s)",
                top.target[:80], top.score, top.signals[:3],
            )
            log.debug(
                "[prioritizer] Full ranking:\n%s",
                "\n".join(f"  {s.score:3d}  {s.target[:80]}" for s in scored[:10]),
            )

        return [s.target for s in scored]

    def rank_with_scores(
        self,
        targets: List[str],
        ctx: Optional[dict] = None,
    ) -> List[TargetScore]:
        """Like rank() but returns TargetScore objects with score details."""
        scored = [
            score_target(t, ctx=ctx, vuln_history=self._vuln_history)
            for t in targets
        ]
        scored.sort(key=lambda s: s.score, reverse=True)
        return scored

    def record_finding(self, host: str, severity: str) -> None:
        """
        Record a confirmed finding for a host so it gets a higher priority
        in future scans (Fix 6 — priority-based execution order).
        """
        bonus = _PREV_SEVERITY_BONUS.get(severity.lower(), 1)
        current = self._vuln_history.get(host, 0)
        self._vuln_history[host] = max(current, bonus)
        log.debug("[prioritizer] Recorded %s finding for %s (bonus=%d)", severity, host, bonus)

    def record_findings_batch(self, findings: List[dict]) -> None:
        """Record multiple findings from a scan session."""
        for f in findings:
            url = f.get("url") or f.get("target") or ""
            severity = (f.get("severity") or "info").lower()
            if url:
                host = _extract_host(url)
                self.record_finding(host, severity)

    def top_n_signals(self, targets: List[str], n: int = 5) -> List[dict]:
        """Return top-N targets with their score breakdown for debugging."""
        scored = self.rank_with_scores(targets)
        return [s.to_dict() for s in scored[:n]]


# ---------------------------------------------------------------------------
# Singleton
# ---------------------------------------------------------------------------

_instance: Optional[TargetPrioritizer] = None


def get_target_prioritizer() -> TargetPrioritizer:
    global _instance
    if _instance is None:
        _instance = TargetPrioritizer()
    return _instance
