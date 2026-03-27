"""
core/bounty_strategy_engine.py — Bug Bounty Strategy Engine

Scores and ranks targets based on real-world payout likelihood (ROI),
platform intelligence, and persistent memory of past findings.

Scoring model
─────────────
  auth-related endpoint       +5   (login/oauth/sso/token/session)
  API-heavy target            +4   (/api/, /v1/, /graphql, /rest/)
  previous confirmed finding  +6   (from persistent memory)
  complex app (many endpoints)+3   (inferred from URL depth + param count)
  admin / management panel    +4
  payment / billing surface   +5
  static site or CDN asset    -5
  no parameters               -2

Program-category multipliers (applied to base score)
──────────────────────────────────────────────────────
  fintech        1.4
  SaaS platform  1.3
  auth-heavy     1.3
  healthcare     1.2
  government     1.1
  e-commerce     1.1
  default        1.0

Usage::
    from core.bounty_strategy_engine import get_strategy_engine

    engine = get_strategy_engine()
    ranked = engine.rank(targets, ctx)          # returns sorted list[str]
    scored = engine.rank_with_scores(targets, ctx)  # list[StrategyScore]
"""
from __future__ import annotations

import logging
import re
from dataclasses import dataclass, field
from typing import Dict, List, Optional
from urllib.parse import urlparse

log = logging.getLogger("oneinfinity.core.bounty_strategy")

# ---------------------------------------------------------------------------
# URL scoring rules
# ---------------------------------------------------------------------------

@dataclass
class _Rule:
    pattern: re.Pattern
    delta:   int
    label:   str


_URL_RULES: List[_Rule] = [
    # High value
    _Rule(re.compile(r"/(login|signin|auth|oauth|sso|saml|token|session|logout)", re.I), +5, "auth"),
    _Rule(re.compile(r"/(admin|administrator|management|console|panel|dashboard)", re.I), +4, "admin"),
    _Rule(re.compile(r"/api/|/v\d+/|/graphql|/gql|/rest/|/query", re.I),              +4, "api"),
    _Rule(re.compile(r"/(payment|billing|checkout|invoice|subscription|wallet)", re.I),+5, "payment"),
    _Rule(re.compile(r"/(upload|file|attachment|document|import|export)", re.I),       +3, "file-ops"),
    _Rule(re.compile(r"/(password|reset|forgot|verify|confirm|2fa|mfa)", re.I),        +4, "creds"),
    _Rule(re.compile(r"/(user|account|profile|settings|preferences)", re.I),           +2, "user"),
    _Rule(re.compile(r"/(internal|private|secret|hidden|debug|test|dev)", re.I),       +3, "internal"),
    _Rule(re.compile(r"/(webhook|callback|redirect|forward|proxy)", re.I),             +3, "redirect"),
    _Rule(re.compile(r"/(report|analytics|metrics|logs|audit)", re.I),                 +2, "data"),
    # Negative signals
    _Rule(re.compile(r"\.(jpg|jpeg|png|gif|svg|ico|css|js|woff|ttf|eot)$", re.I),    -5, "static-asset"),
    _Rule(re.compile(r"/(cdn|static|assets|images|fonts|media)/", re.I),              -5, "cdn"),
]

# Bonus for URL parameters
_PARAM_BONUS = +3

# Bonus for URL path depth (each segment after 2)
def _depth_bonus(path: str) -> int:
    segments = [s for s in path.split("/") if s]
    return min(3, max(0, len(segments) - 2))


# ---------------------------------------------------------------------------
# Program-category multipliers
# ---------------------------------------------------------------------------

_CATEGORY_MULTIPLIERS: Dict[str, float] = {
    "fintech":     1.4,
    "banking":     1.4,
    "crypto":      1.4,
    "saas":        1.3,
    "auth":        1.3,
    "healthcare":  1.2,
    "medical":     1.2,
    "government":  1.1,
    "ecommerce":   1.1,
    "retail":      1.1,
    "default":     1.0,
}

# Keywords that hint at category — checked against the target host+path
_CATEGORY_HINTS: List[tuple] = [
    ("fintech",    re.compile(r"(bank|pay|finance|fintech|invest|trade|wallet|crypto|coin)", re.I)),
    ("saas",       re.compile(r"(dashboard|workspace|tenant|team|org|enterprise|saas)", re.I)),
    ("auth",       re.compile(r"(auth|sso|login|identity|iam|okta|idp)", re.I)),
    ("healthcare", re.compile(r"(health|medical|patient|clinical|pharma|hospital)", re.I)),
    ("government", re.compile(r"(\.gov|government|federal|state\.)", re.I)),
    ("ecommerce",  re.compile(r"(shop|store|cart|order|product|ecomm)", re.I)),
]


def _detect_category(url: str) -> str:
    for cat, rx in _CATEGORY_HINTS:
        if rx.search(url):
            return cat
    return "default"


# ---------------------------------------------------------------------------
# Score model
# ---------------------------------------------------------------------------

@dataclass
class StrategyScore:
    target:     str
    score:      float
    raw_score:  int
    multiplier: float
    category:   str
    labels:     List[str] = field(default_factory=list)
    from_memory: bool = False   # True if boosted by persistent memory


# ---------------------------------------------------------------------------
# Engine
# ---------------------------------------------------------------------------

class BountyStrategyEngine:
    """
    Ranks targets by estimated bug bounty ROI.

    Parameters
    ----------
    memory : PersistentMemory | None
        If provided, applies previous-finding bonuses and category hints.
    """

    def __init__(self, memory=None) -> None:
        self._memory = memory or self._load_memory()

    @staticmethod
    def _load_memory():
        try:
            from learning.persistent_memory import get_memory
            return get_memory()
        except Exception:
            return None

    # ── Public API ────────────────────────────────────────────────────────────

    def score_target(self, target: str, ctx: Optional[dict] = None) -> StrategyScore:
        """Score a single target URL/host."""
        ctx = ctx or {}
        raw = 0
        labels: List[str] = []

        parsed = urlparse(target if "://" in target else f"https://{target}")
        full   = target
        path   = parsed.path or "/"
        host   = parsed.netloc or parsed.path.split("/")[0]

        # Apply URL rules
        for rule in _URL_RULES:
            if rule.pattern.search(full):
                raw += rule.delta
                if rule.delta > 0:
                    labels.append(rule.label)

        # Param bonus
        if "?" in target or "&" in target:
            raw += _PARAM_BONUS
            labels.append("has-params")

        # Depth bonus (complex app)
        db = _depth_bonus(path)
        if db > 0:
            raw += db
            labels.append(f"depth+{db}")

        # Persistent memory: previous confirmed finding on this host
        if self._memory:
            try:
                if self._memory.was_vulnerable(host):
                    raw += 6
                    labels.append("prev-vuln")
            except Exception:
                pass

        # ctx-injected high-value hosts (from TargetPrioritizer history)
        hv_hosts = ctx.get("high_value_hosts") or (
            self._memory.high_value_hosts() if self._memory else []
        )
        if host in hv_hosts:
            raw += 4
            labels.append("memory-high-value")

        # Category detection + multiplier
        category   = _detect_category(full)
        multiplier = _CATEGORY_MULTIPLIERS.get(category, 1.0)
        score      = raw * multiplier

        return StrategyScore(
            target=target,
            score=round(score, 2),
            raw_score=raw,
            multiplier=multiplier,
            category=category,
            labels=labels,
            from_memory=("prev-vuln" in labels or "memory-high-value" in labels),
        )

    def rank(self, targets: List[str], ctx: Optional[dict] = None) -> List[str]:
        """Return targets sorted by ROI score (highest first)."""
        scored = self.rank_with_scores(targets, ctx)
        return [s.target for s in scored]

    def rank_with_scores(
        self, targets: List[str], ctx: Optional[dict] = None
    ) -> List[StrategyScore]:
        """Return StrategyScore objects sorted by score descending."""
        scored = [self.score_target(t, ctx) for t in targets]
        scored.sort(key=lambda s: (-s.score, s.target))
        if scored:
            top = scored[0]
            log.info(
                "[strategy] Ranked %d targets — top: %s (score=%.1f, cat=%s, labels=%s)",
                len(scored), top.target, top.score, top.category, top.labels,
            )
        return scored

    def apply_to_ctx(self, targets: List[str], ctx: dict) -> List[str]:
        """
        Rank targets and inject strategy metadata into ctx.

        Sets ctx["strategy_scores"], ctx["top_strategy_target"].
        Returns ranked target list.
        """
        scored = self.rank_with_scores(targets, ctx)
        ctx["strategy_scores"] = [
            {"target": s.target, "score": s.score, "category": s.category, "labels": s.labels}
            for s in scored
        ]
        if scored:
            ctx["top_strategy_target"] = scored[0].target
        return [s.target for s in scored]

    def program_intel(self, targets: List[str]) -> dict:
        """
        Return high-level program intelligence — categories + recommended focus.

        Used by cmd_hunter to display a strategy summary before scanning.
        """
        categories: Dict[str, int] = {}
        for t in targets:
            cat = _detect_category(t if "://" in t else f"https://{t}")
            categories[cat] = categories.get(cat, 0) + 1

        dominant = max(categories, key=lambda k: categories[k]) if categories else "default"
        multiplier = _CATEGORY_MULTIPLIERS.get(dominant, 1.0)

        focus = []
        if dominant in ("fintech", "banking", "crypto"):
            focus = ["auth", "payment", "api", "idor"]
        elif dominant == "saas":
            focus = ["idor", "api", "auth", "business_logic"]
        elif dominant == "auth":
            focus = ["auth_bypass", "session", "sso", "token"]
        elif dominant == "healthcare":
            focus = ["idor", "auth", "data_exposure", "api"]
        else:
            focus = ["xss", "sqli", "idor", "ssrf"]

        return {
            "categories":    categories,
            "dominant":      dominant,
            "roi_multiplier": multiplier,
            "recommended_focus": focus,
        }


# ---------------------------------------------------------------------------
# Singleton
# ---------------------------------------------------------------------------

_instance: Optional[BountyStrategyEngine] = None


def get_strategy_engine() -> BountyStrategyEngine:
    global _instance
    if _instance is None:
        _instance = BountyStrategyEngine()
    return _instance
