"""
infra/log_config.py — Structured JSON Logging for OneInfinity

Provides a JSONFormatter that emits one JSON object per log line.
Compatible with Loki, ELK (Elasticsearch/Logstash), Splunk, and Datadog.

Required fields per record:
    timestamp       ISO-8601 UTC with millisecond precision
    level           DEBUG / INFO / WARNING / ERROR / CRITICAL
    logger          logger name (dotted path)
    message         formatted log message

Optional context fields (populated when present on the LogRecord):
    scan_id         active scan identifier
    correlation_id  event bus / trace correlation
    worker_id       distributed worker identifier
    phase           current scan phase name
    target          scan target domain/URL
    exc_info        exception class + message (when an exception is attached)

Usage::

    from oneinfinity.infra.log_config import configure_json_logging
    configure_json_logging()

    # Or just the formatter:
    from oneinfinity.infra.log_config import JSONFormatter
    handler.setFormatter(JSONFormatter())

Environment controls:
    ONEINFINITY_LOG_FORMAT   = "json" | "text"  (default "json")
    ONEINFINITY_LOG_LEVEL    = DEBUG | INFO | WARNING | ERROR | CRITICAL
                               (default INFO)
    ONEINFINITY_LOG_FILE     = path to append log file (optional; stdout always active)
"""
from __future__ import annotations

import json
import logging
import os
import sys
import time
from datetime import datetime, timezone
from typing import Optional

# ---------------------------------------------------------------------------
# Context fields recognised on LogRecord
# ---------------------------------------------------------------------------

_CONTEXT_FIELDS = (
    "scan_id",
    "correlation_id",
    "worker_id",
    "phase",
    "target",
)

_STDLIB_ATTRS = frozenset((
    "args", "created", "exc_info", "exc_text", "filename", "funcName",
    "levelname", "levelno", "lineno", "message", "module", "msecs", "msg",
    "name", "pathname", "process", "processName", "relativeCreated",
    "stack_info", "taskName", "thread", "threadName",
))


class JSONFormatter(logging.Formatter):
    """
    Formatter that serialises every LogRecord as a single-line JSON object.

    Guaranteed fields:
        timestamp, level, logger, message

    Optional fields added when non-empty:
        scan_id, correlation_id, worker_id, phase, target

    Exception info added as ``exc_info`` when present.

    Any extra keyword args passed via ``logger.info("msg", extra={...})``
    that are not standard logging attrs are forwarded into the JSON object.
    """

    def format(self, record: logging.LogRecord) -> str:
        # Ensure the message string is fully formatted
        record.message = record.getMessage()

        ts = datetime.fromtimestamp(record.created, tz=timezone.utc).strftime(
            "%Y-%m-%dT%H:%M:%S.%f"
        )[:-3] + "Z"   # millisecond precision: drop last 3 µs digits

        obj: dict = {
            "timestamp":     ts,
            "level":         record.levelname,
            "logger":        record.name,
            "message":       record.message,
        }

        # Structured context fields
        for field in _CONTEXT_FIELDS:
            val = getattr(record, field, None)
            if val:
                obj[field] = str(val)

        # Exception info
        if record.exc_info:
            exc_type, exc_val, _ = record.exc_info
            if exc_type is not None:
                obj["exc_info"] = f"{exc_type.__name__}: {exc_val}"

        # Forward any non-standard extras from ``extra={}``
        for key, val in record.__dict__.items():
            if key not in _STDLIB_ATTRS and not key.startswith("_") and key not in obj:
                try:
                    json.dumps(val)   # only include JSON-serialisable extras
                    obj[key] = val
                except (TypeError, ValueError):
                    obj[key] = str(val)

        try:
            return json.dumps(obj, ensure_ascii=False)
        except Exception:
            # Fallback: safe ASCII serialisation
            return json.dumps({
                "timestamp": ts,
                "level": record.levelname,
                "logger": record.name,
                "message": repr(record.message),
                "serialisation_error": True,
            })


class _ContextFilter(logging.Filter):
    """
    No-op filter that exists so callers can attach scan-level context to a
    handler rather than passing ``extra`` on every call::

        with logging.get_logger(...).addFilter(
            _ContextFilter(scan_id="abc", phase="recon")
        ):
            ...
    """

    def __init__(self, **context):
        super().__init__()
        self._context = context

    def filter(self, record: logging.LogRecord) -> bool:
        for key, val in self._context.items():
            if not hasattr(record, key):
                setattr(record, key, val)
        return True


def configure_json_logging(
    level: Optional[str] = None,
    log_file: Optional[str] = None,
    force_format: Optional[str] = None,
) -> None:
    """
    Configure the root logger for JSON output.

    Call once at application startup (e.g. FastAPI lifespan start).

    Args:
        level:        Override log level (default: ONEINFINITY_LOG_LEVEL env, then INFO).
        log_file:     Append to this file in addition to stdout.
                      Default: ONEINFINITY_LOG_FILE env var.
        force_format: "json" or "text".  Default: ONEINFINITY_LOG_FORMAT env, then "json".

    Behaviour:
        - Idempotent: calling twice does not duplicate handlers.
        - Existing handlers on the root logger are replaced.
        - Does NOT suppress third-party library logs; only formats them.
    """
    fmt = (force_format or os.environ.get("ONEINFINITY_LOG_FORMAT", "json")).lower()
    lvl = (level or os.environ.get("ONEINFINITY_LOG_LEVEL", "INFO")).upper()
    fpath = log_file or os.environ.get("ONEINFINITY_LOG_FILE", "")

    numeric_level = getattr(logging, lvl, logging.INFO)

    root = logging.getLogger()
    root.setLevel(numeric_level)

    # Remove existing handlers to avoid duplicates on re-call
    for h in list(root.handlers):
        root.removeHandler(h)

    if fmt == "json":
        formatter: logging.Formatter = JSONFormatter()
    else:
        formatter = logging.Formatter(
            "%(asctime)s %(levelname)s %(name)s — %(message)s",
            datefmt="%Y-%m-%dT%H:%M:%S",
        )

    # stdout handler
    stdout_handler = logging.StreamHandler(sys.stdout)
    stdout_handler.setFormatter(formatter)
    stdout_handler.setLevel(numeric_level)
    root.addHandler(stdout_handler)

    # Optional file handler
    if fpath:
        try:
            file_handler = logging.FileHandler(fpath, encoding="utf-8")
            file_handler.setFormatter(formatter)
            file_handler.setLevel(numeric_level)
            root.addHandler(file_handler)
        except Exception as exc:
            root.warning("log_config: could not open log file %s: %s", fpath, exc)

    root.info(
        "Logging configured",
        extra={
            "format": fmt,
            "level": lvl,
            "log_file": fpath or None,
        },
    )
