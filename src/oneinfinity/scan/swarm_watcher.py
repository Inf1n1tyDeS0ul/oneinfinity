"""
Swarm Watcher — One&Infinity
=============================
Automated traffic monitoring engine. Monitors incoming requests from the 
TrafficCaptureEngine and automatically dispatches background fuzzing tasks
for high-value targets (tokens, IDs, sensitive parameters).
"""

import json
import logging
import re
import time
import uuid
from typing import List
from oneinfinity.scan.traffic_capture_engine import traffic_capture_engine, CapturedRequest
from oneinfinity.infra.task_dispatcher import TaskRouter

log = logging.getLogger("oneinfinity.scan.swarm_watcher")

# Parameters that trigger automated fuzzing
INTERESTING_PARAMS = [
    r"token", r"auth", r"jwt", r"session", r"user_id", r"customer_id",
    r"account", r"order_id", r"uuid", r"guid", r"id", r"email", r"phone",
    r"search", r"query", r"limit", r"offset", r"page"
]

_router = TaskRouter()


class SwarmWatcher:
    def __init__(self):
        self._enabled = False
        self._patterns = [re.compile(p, re.I) for p in INTERESTING_PARAMS]

    def start(self):
        if self._enabled:
            return
        log.info("Swarm Watcher: ACTIVATED")
        traffic_capture_engine.add_listener(self._on_request_captured)
        self._enabled = True

    def stop(self):
        if not self._enabled:
            return
        traffic_capture_engine.remove_listener(self._on_request_captured)
        self._enabled = False
        log.info("Swarm Watcher: DEACTIVATED")

    def _on_request_captured(self, req: CapturedRequest):
        """Analyze request and dispatch to Swarm if interesting."""
        if req.source != "mobile_live_proxy":
            return

        # Check URL and body for interesting patterns
        target_str = f"{req.url} {req.body}"
        if any(p.search(target_str) for p in self._patterns):
            log.info(f"Swarm Watcher: Interest detected in {req.id}. Dispatching fuzz task...")
            
            # Dispatch to background swarm queue via TaskRouter
            task_payload = json.dumps({
                "task_id": str(uuid.uuid4()),
                "target": req.url,
                "module": "traffic_fuzzer",
                "priority": 2,
                "status": "queued",
                "worker_id": None,
                "created_at": time.time(),
                "started_at": None,
                "completed_at": None,
                "retry_count": 0,
                "max_retries": 3,
                "result": None,
                "error": None,
                "config": {
                    "action": "auto_fuzz",
                    "request_id": req.id,
                    "reason": "sensitive_params_detected",
                },
            })
            _router._inmemory_push("swarm:tasks:traffic_fuzzer", task_payload)

# Singleton
swarm_watcher = SwarmWatcher()
