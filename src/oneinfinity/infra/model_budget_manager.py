"""
model_budget_manager.py — Model Usage Tracking & Budget Enforcement

Tracks every model API call, enforces daily/monthly/per-model limits,
and exposes cost projections so the orchestrator can make cost-aware decisions.

Storage: PostgreSQL model_usage table (hard requirement).

Budget hierarchy:
  1. Global daily limit            — hard stop
  2. Global monthly limit          — hard stop
  3. Per-model daily limit         — skip this model if exceeded (fallback to cheaper)
  4. Per-category daily limit      — skip if exceeded

Alert system:
  - Emits WARNING log when > alert_threshold% consumed
  - Publishes AGENT_STATUS event to EventBus when 90% consumed
  - Raises BudgetExhaustedError on hard limit
"""

from __future__ import annotations

import logging
import time
from dataclasses import dataclass, field
from typing import Dict, List, Optional

log = logging.getLogger("model_budget_manager")


# ── Exceptions ─────────────────────────────────────────────────────────────────

class BudgetExhaustedError(Exception):
    """Raised when a hard budget limit is hit."""


# ── Data models ───────────────────────────────────────────────────────────────

@dataclass
class BudgetConfig:
    daily_limit_usd:        float = 5.00
    monthly_limit_usd:      float = 50.00
    alert_threshold:        float = 0.80
    per_model_daily_limit:  Dict[str, float] = field(default_factory=dict)
    per_category_daily_limit: Dict[str, float] = field(default_factory=dict)

    @classmethod
    def from_dict(cls, d: dict) -> "BudgetConfig":
        return cls(
            daily_limit_usd=float(d.get("daily_limit_usd", 5.00)),
            monthly_limit_usd=float(d.get("monthly_limit_usd", 50.00)),
            alert_threshold=float(d.get("alert_threshold", 0.80)),
            per_model_daily_limit={k: float(v)
                                   for k, v in d.get("per_model_daily_limit", {}).items()},
            per_category_daily_limit={k: float(v)
                                      for k, v in d.get("per_category_daily_limit", {}).items()},
        )


@dataclass
class UsageRecord:
    record_id:      int
    model_id:       str
    provider:       str
    task_id:        str
    task_category:  str
    input_tokens:   int
    output_tokens:  int
    cost_usd:       float
    duration_ms:    float
    escalation:     bool
    timestamp:      float

    def to_dict(self) -> dict:
        return self.__dict__.copy()


@dataclass
class UsageSummary:
    period:               str
    total_calls:          int
    total_input_tokens:   int
    total_output_tokens:  int
    total_cost_usd:       float
    cost_by_model:        Dict[str, float]
    cost_by_category:     Dict[str, float]
    calls_by_model:       Dict[str, int]
    escalation_rate:      float
    daily_budget_used:    float
    monthly_budget_used:  float

    def to_dict(self) -> dict:
        return {
            "period":               self.period,
            "total_calls":          self.total_calls,
            "total_tokens":         self.total_input_tokens + self.total_output_tokens,
            "total_cost_usd":       round(self.total_cost_usd, 6),
            "cost_by_model":        {k: round(v, 6) for k, v in self.cost_by_model.items()},
            "cost_by_category":     {k: round(v, 6) for k, v in self.cost_by_category.items()},
            "calls_by_model":       self.calls_by_model,
            "escalation_rate":      round(self.escalation_rate, 3),
            "daily_budget_used":    round(self.daily_budget_used, 3),
            "monthly_budget_used":  round(self.monthly_budget_used, 3),
        }


def _require_pg():
    """Return DBManager in PG mode, or raise if unavailable."""
    try:
        from oneinfinity.core.db_manager import get_db_manager_sync
        mgr = get_db_manager_sync()
        if mgr is not None and mgr.mode in ("distributed", "postgres"):
            return mgr
    except Exception as exc:
        raise RuntimeError(f"PostgreSQL is required but DBManager unavailable: {exc}") from exc
    raise RuntimeError(
        "PostgreSQL is required. Set DB_MODE=postgres or DB_MODE=distributed."
    )


# ── Budget Manager ─────────────────────────────────────────────────────────────

class ModelBudgetManager:
    """Budget tracker backed by PostgreSQL. Used by the orchestrator before every model call."""

    def __init__(self, config: Optional[BudgetConfig] = None) -> None:
        self._config = config or BudgetConfig()

        # In-memory cache to avoid DB round-trips on every check
        self._today_total:    float = 0.0
        self._month_total:    float = 0.0
        self._model_today:    Dict[str, float] = {}
        self._cat_today:      Dict[str, float] = {}
        self._cache_date:     str = ""
        self._refresh_cache()

    # ── Cache refresh ──────────────────────────────────────────────────────────

    def _refresh_cache(self) -> None:
        """Reload today/month totals from PG."""
        import datetime
        today    = datetime.date.today()
        today_s  = today.isoformat()
        month_s  = today.replace(day=1).isoformat()
        self._cache_date = today_s

        today_ts = time.mktime(today.timetuple())
        month_ts = time.mktime(
            __import__("datetime").datetime.strptime(month_s, "%Y-%m-%d").timetuple()
        )

        pg = _require_pg()
        rows = pg.sync_pg_execute_read(
            "SELECT model_id, task_category, SUM(cost_usd) AS cost "
            "FROM model_usage WHERE timestamp >= %s GROUP BY model_id, task_category",
            (today_ts,)
        )
        month_rows = pg.sync_pg_execute_read(
            "SELECT SUM(cost_usd) AS total FROM model_usage WHERE timestamp >= %s",
            (month_ts,)
        )
        month_total = (month_rows[0].get("total") or 0.0) if month_rows else 0.0

        today_total = 0.0
        model_today: Dict[str, float] = {}
        cat_today:   Dict[str, float] = {}
        for row in rows:
            mid  = row.get("model_id", "")
            cat  = row.get("task_category", "")
            cost = row.get("cost") or 0.0
            today_total         += cost
            model_today[mid]     = model_today.get(mid, 0.0) + cost
            cat_today[cat]       = cat_today.get(cat, 0.0) + cost

        self._today_total = today_total
        self._month_total = month_total
        self._model_today = model_today
        self._cat_today   = cat_today

    def _ensure_cache_fresh(self) -> None:
        import datetime
        if datetime.date.today().isoformat() != self._cache_date:
            self._refresh_cache()

    # ── Budget checks ─────────────────────────────────────────────────────────

    def can_use_model(self, model_id: str, category: str = "GENERAL",
                       raise_on_exhausted: bool = False) -> tuple[bool, str]:
        """Check whether this model can be used right now. Returns (allowed, reason)."""
        self._ensure_cache_fresh()

        if self._today_total >= self._config.daily_limit_usd:
            reason = (f"Global daily budget exhausted "
                      f"(${self._today_total:.4f} ≥ ${self._config.daily_limit_usd})")
            if raise_on_exhausted:
                raise BudgetExhaustedError(reason)
            return False, reason

        if self._month_total >= self._config.monthly_limit_usd:
            reason = (f"Monthly budget exhausted "
                      f"(${self._month_total:.4f} ≥ ${self._config.monthly_limit_usd})")
            if raise_on_exhausted:
                raise BudgetExhaustedError(reason)
            return False, reason

        model_limit = self._config.per_model_daily_limit.get(model_id)
        if model_limit is not None:
            used = self._model_today.get(model_id, 0.0)
            if used >= model_limit:
                return False, (f"Per-model daily limit for {model_id} exhausted "
                               f"(${used:.4f} ≥ ${model_limit})")

        cat_limit = self._config.per_category_daily_limit.get(category)
        if cat_limit is not None:
            used = self._cat_today.get(category, 0.0)
            if used >= cat_limit:
                return False, (f"Category daily limit for {category} exhausted "
                               f"(${used:.4f} ≥ ${cat_limit})")

        daily_frac = self._today_total / max(self._config.daily_limit_usd, 0.001)
        if daily_frac >= self._config.alert_threshold:
            log.warning("Daily budget %.0f%% consumed (%.4f / %.2f USD)",
                        daily_frac * 100, self._today_total, self._config.daily_limit_usd)
            if daily_frac >= 0.90:
                self._publish_budget_alert(daily_frac)

        return True, "ok"

    def cheapest_available_model(self, models: Dict[str, "ModelConfig"],
                                  category: str = "GENERAL") -> Optional[str]:
        candidates = []
        for model_id, cfg in models.items():
            if not cfg.enabled:
                continue
            allowed, _ = self.can_use_model(model_id, category)
            if allowed:
                cost = cfg.cost_per_1k_input + cfg.cost_per_1k_output
                candidates.append((cost, model_id))
        if not candidates:
            return None
        candidates.sort()
        return candidates[0][1]

    # ── Usage recording ───────────────────────────────────────────────────────

    def record(self, model_id: str, provider: str, task_id: str,
               task_category: str, input_tokens: int, output_tokens: int,
               cost_usd: float, duration_ms: float = 0.0,
               escalation: bool = False) -> None:
        """Persist a usage record and update in-memory cache."""
        ts = time.time()
        _require_pg().sync_pg_execute_write(
            "INSERT INTO model_usage "
            "(model_id, provider, task_id, task_category, input_tokens, "
            "output_tokens, cost_usd, duration_ms, escalation, timestamp) "
            "VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s)",
            (model_id, provider, task_id, task_category,
             input_tokens, output_tokens, cost_usd, duration_ms,
             bool(escalation), ts)
        )
        self._today_total              += cost_usd
        self._month_total              += cost_usd
        self._model_today[model_id]     = self._model_today.get(model_id, 0.0) + cost_usd
        self._cat_today[task_category]  = self._cat_today.get(task_category, 0.0) + cost_usd
        log.debug("Usage recorded: model=%s tokens=%d+%d cost=$%.6f",
                  model_id, input_tokens, output_tokens, cost_usd)

    # ── Summaries ─────────────────────────────────────────────────────────────

    def get_summary(self, period: str = "today") -> UsageSummary:
        """period: "today" | "this_month" | "all_time" """
        import datetime
        if period == "today":
            since = time.mktime(datetime.date.today().timetuple())
        elif period == "this_month":
            today = datetime.date.today()
            since = time.mktime(today.replace(day=1).timetuple())
        else:
            since = 0.0

        rows = _require_pg().sync_pg_execute_read(
            "SELECT model_id, provider, task_category, input_tokens, "
            "output_tokens, cost_usd, escalation "
            "FROM model_usage WHERE timestamp >= %s",
            (since,)
        )

        total_calls    = len(rows)
        total_in       = sum(r["input_tokens"] for r in rows)
        total_out      = sum(r["output_tokens"] for r in rows)
        total_cost     = sum(r["cost_usd"] for r in rows)
        escalations    = sum(1 for r in rows if r["escalation"])
        cost_by_model: Dict[str, float] = {}
        cost_by_cat:   Dict[str, float] = {}
        calls_by_model: Dict[str, int]  = {}

        for r in rows:
            mid = r["model_id"]
            cat = r["task_category"]
            cost_by_model[mid]  = cost_by_model.get(mid, 0.0) + r["cost_usd"]
            cost_by_cat[cat]    = cost_by_cat.get(cat, 0.0) + r["cost_usd"]
            calls_by_model[mid] = calls_by_model.get(mid, 0) + 1

        self._ensure_cache_fresh()
        return UsageSummary(
            period=period,
            total_calls=total_calls,
            total_input_tokens=total_in,
            total_output_tokens=total_out,
            total_cost_usd=total_cost,
            cost_by_model=cost_by_model,
            cost_by_category=cost_by_cat,
            calls_by_model=calls_by_model,
            escalation_rate=escalations / max(total_calls, 1),
            daily_budget_used=self._today_total / max(self._config.daily_limit_usd, 0.001),
            monthly_budget_used=self._month_total / max(self._config.monthly_limit_usd, 0.001),
        )

    def project_monthly_cost(self) -> float:
        import datetime
        day_of_month = datetime.date.today().day
        if day_of_month < 1:
            return self._month_total
        return round(self._month_total / day_of_month * 30, 4)

    def recent_records(self, limit: int = 50) -> List[dict]:
        rows = _require_pg().sync_pg_execute_read(
            "SELECT id, model_id, provider, task_id, task_category, "
            "input_tokens, output_tokens, cost_usd, duration_ms, escalation, timestamp "
            "FROM model_usage ORDER BY timestamp DESC LIMIT %s",
            (limit,)
        )
        return [
            {
                "record_id":    r["id"],
                "model_id":     r["model_id"],
                "provider":     r["provider"],
                "task_id":      r["task_id"],
                "task_category": r["task_category"],
                "input_tokens": r["input_tokens"],
                "output_tokens": r["output_tokens"],
                "cost_usd":     round(r["cost_usd"], 6),
                "duration_ms":  round(r["duration_ms"], 1),
                "escalation":   bool(r["escalation"]),
                "timestamp":    r["timestamp"],
            }
            for r in rows
        ]

    # ── Helpers ───────────────────────────────────────────────────────────────

    def _publish_budget_alert(self, fraction: float) -> None:
        try:
            from oneinfinity.event_bus import get_bus, EventType
            get_bus().publish(
                event_type=EventType.AGENT_STATUS,
                source="model_budget_manager",
                data={
                    "alert": "budget_threshold",
                    "daily_fraction": round(fraction, 3),
                    "today_usd": round(self._today_total, 4),
                    "daily_limit": self._config.daily_limit_usd,
                },
            )
        except Exception:
            pass

    def update_config(self, config: BudgetConfig) -> None:
        self._config = config

    def status(self) -> dict:
        self._ensure_cache_fresh()
        return {
            "today_usd":         round(self._today_total, 4),
            "month_usd":         round(self._month_total, 4),
            "daily_limit":       self._config.daily_limit_usd,
            "monthly_limit":     self._config.monthly_limit_usd,
            "daily_pct":         round(self._today_total / max(self._config.daily_limit_usd, 0.001) * 100, 1),
            "monthly_pct":       round(self._month_total / max(self._config.monthly_limit_usd, 0.001) * 100, 1),
            "projected_monthly": self.project_monthly_cost(),
            "model_today":       {k: round(v, 4) for k, v in self._model_today.items()},
        }


# ── Singleton ──────────────────────────────────────────────────────────────────

import threading as _threading
_budget_manager: Optional[ModelBudgetManager] = None
_bm_lock = _threading.Lock()


def get_budget_manager() -> ModelBudgetManager:
    global _budget_manager
    if _budget_manager is None:
        with _bm_lock:
            if _budget_manager is None:
                _budget_manager = ModelBudgetManager()
    return _budget_manager
