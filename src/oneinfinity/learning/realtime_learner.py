"""
Real-Time Learning Engine
==========================
Event-driven learning system that updates immediately from scan feedback.

Features:
- Subscribes to validation, exploitation, tool failure events
- Updates attack graph edge weights in real-time
- Adjusts tool confidence scores based on success/failure
- Persists learned patterns to knowledge base
- Tracks improvement metrics across scans

Architecture:
- Event subscribers → learning handlers → persistence
- Neo4j for graph weight updates
- PostgreSQL for pattern/confidence storage
- Metrics: scan improvement rate, tool reliability, pattern growth
"""

from __future__ import annotations

import logging
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional

log = logging.getLogger(__name__)


@dataclass
class LearningEvent:
    """Learning event record."""
    event_id: str
    event_type: str  # finding_validated, chain_exploited, tool_failed
    timestamp: float
    data: Dict[str, Any]
    impact: str = "neutral"  # positive, negative, neutral


@dataclass
class ToolConfidence:
    """Tool reliability metrics."""
    tool_name: str
    success_count: int = 0
    failure_count: int = 0
    false_positive_count: int = 0
    confidence: float = 0.8  # 0-1 score

    @property
    def success_rate(self) -> float:
        total = self.success_count + self.failure_count
        return self.success_count / total if total > 0 else 0.5


class RealtimeLearner:
    """
    Real-time learning engine that adapts from scan feedback.

    Subscribes to:
    - NEW_VULNERABILITY: Update graph weights, tool confidence
    - EXPLOIT_ATTEMPTED: Learn from exploitation success/failure
    - CHAIN_DETECTED: Add successful chain patterns
    - AGENT_STATUS: Track tool performance

    Updates:
    - Neo4j graph edge weights (more successful paths = higher weight)
    - Tool confidence scores (PostgreSQL)
    - Pattern library (successful exploit patterns)
    - Improvement metrics (scan N+1 vs scan N)
    """

    def __init__(self):
        """Initialize learner and subscribe to events."""
        self.tool_confidence: Dict[str, ToolConfidence] = {}
        self.learning_events: List[LearningEvent] = []
        self.scan_count = 0
        self.adaptation_count = 0
        self.pattern_count = 0

        self._subscribe_to_events()
        log.info("RealtimeLearner initialized")

    def _subscribe_to_events(self):
        """Subscribe to platform events."""
        try:
            from oneinfinity.orchestration.event_bus import get_bus, EventType

            bus = get_bus()
            bus.on(EventType.NEW_VULNERABILITY, self._on_finding_validated)
            bus.on(EventType.EXPLOIT_ATTEMPTED, self._on_exploit_attempted)
            bus.on(EventType.CHAIN_DETECTED, self._on_chain_detected)
            # Note: tool_failed not in EventType enum - would need to be added

            log.info("Subscribed to learning events")
        except Exception as e:
            log.warning(f"Event subscription failed: {e}")

    # ── Event Handlers ────────────────────────────────────────────────────────

    async def _on_finding_validated(self, event):
        """Handle finding validation event."""
        try:
            data = event.data if hasattr(event, 'data') else event

            finding_id = data.get("finding_id")
            vuln_type = data.get("vuln_type", "unknown")
            confidence = data.get("confidence", 0.5)
            tool = data.get("tool", "unknown")
            status = data.get("status", "confirmed")

            log.debug(f"Learning from finding: {finding_id} ({vuln_type})")

            # Update tool confidence
            if status == "confirmed":
                self._update_tool_confidence(tool, success=True)
                self.adaptation_count += 1
            elif status == "false_positive":
                self._update_tool_confidence(tool, false_positive=True)

            # Update graph weights if graph node exists
            await self._update_graph_weights(vuln_type, confidence, success=True)

            # Record learning event
            self.learning_events.append(LearningEvent(
                event_id=f"learn_{int(time.time())}",
                event_type="finding_validated",
                timestamp=time.time(),
                data={"vuln_type": vuln_type, "tool": tool, "confidence": confidence},
                impact="positive" if status == "confirmed" else "negative"
            ))

            # Persist to KB
            await self._persist_learning()

        except Exception as e:
            log.error(f"Error in _on_finding_validated: {e}")

    async def _on_exploit_attempted(self, event):
        """Handle exploit attempt event."""
        try:
            data = event.data if hasattr(event, 'data') else event

            vuln_type = data.get("vuln_type", "unknown")
            payload = data.get("payload", "")
            success = data.get("success", False)
            tool = data.get("tool", "custom")

            log.debug(f"Learning from exploit: {vuln_type} success={success}")

            if success:
                # Add successful payload to pattern library
                await self._add_pattern(vuln_type, payload, tool)
                self._update_tool_confidence(tool, success=True)
                self.pattern_count += 1
            else:
                self._update_tool_confidence(tool, success=False)

            # Update graph weights
            await self._update_graph_weights(vuln_type, confidence=0.8, success=success)

            self.learning_events.append(LearningEvent(
                event_id=f"exploit_{int(time.time())}",
                event_type="exploit_attempted",
                timestamp=time.time(),
                data={"vuln_type": vuln_type, "success": success},
                impact="positive" if success else "neutral"
            ))

        except Exception as e:
            log.error(f"Error in _on_exploit_attempted: {e}")

    async def _on_chain_detected(self, event):
        """Handle attack chain detection event."""
        try:
            data = event.data if hasattr(event, 'data') else event

            chain_name = data.get("chain_name", "unnamed")
            steps = data.get("steps", [])
            exploitability = data.get("exploitability_score", 0.5)

            log.info(f"Learning from chain: {chain_name} ({len(steps)} steps)")

            # Update graph edges for chain path
            for i in range(len(steps) - 1):
                src = steps[i]
                dst = steps[i + 1]
                await self._strengthen_edge(src, dst, weight_delta=0.2)

            # Add chain pattern to library
            await self._add_chain_pattern(chain_name, steps, exploitability)

            self.pattern_count += 1
            self.adaptation_count += 1

            self.learning_events.append(LearningEvent(
                event_id=f"chain_{int(time.time())}",
                event_type="chain_detected",
                timestamp=time.time(),
                data={"chain": chain_name, "steps": len(steps)},
                impact="positive"
            ))

        except Exception as e:
            log.error(f"Error in _on_chain_detected: {e}")

    async def _on_tool_failed(self, event):
        """Handle tool failure event."""
        try:
            data = event.data if hasattr(event, 'data') else event

            tool = data.get("tool", "unknown")
            reason = data.get("reason", "")

            log.debug(f"Tool failed: {tool} - {reason}")

            self._update_tool_confidence(tool, success=False)

            self.learning_events.append(LearningEvent(
                event_id=f"fail_{int(time.time())}",
                event_type="tool_failed",
                timestamp=time.time(),
                data={"tool": tool, "reason": reason},
                impact="negative"
            ))

        except Exception as e:
            log.error(f"Error in _on_tool_failed: {e}")

    # ── Learning Operations ───────────────────────────────────────────────────

    def _update_tool_confidence(self, tool: str, success: bool = None, false_positive: bool = False):
        """Update tool reliability scores."""
        if tool not in self.tool_confidence:
            self.tool_confidence[tool] = ToolConfidence(tool_name=tool)

        tc = self.tool_confidence[tool]

        if success is True:
            tc.success_count += 1
        elif success is False:
            tc.failure_count += 1

        if false_positive:
            tc.false_positive_count += 1

        # Recalculate confidence using exponential moving average
        alpha = 0.3  # Learning rate
        new_confidence = tc.success_rate
        tc.confidence = alpha * new_confidence + (1 - alpha) * tc.confidence

        log.debug(f"Tool {tool}: confidence={tc.confidence:.2f}, success_rate={tc.success_rate:.2f}")

    async def _update_graph_weights(self, vuln_type: str, confidence: float, success: bool):
        """Update Neo4j graph edge weights based on finding success."""
        try:
            from oneinfinity.learning.neo4j_knowledge_base import Neo4jKnowledgeBase

            kb = Neo4jKnowledgeBase()

            # Weight adjustment based on confidence and success
            weight_delta = confidence * 0.1 if success else -confidence * 0.05

            # Query for nodes with this vuln_type
            query = """
            MATCH (n {vuln_type: $vuln_type})
            SET n.weight = COALESCE(n.weight, 1.0) + $delta
            RETURN count(n) as updated
            """

            result = await kb.execute_query(query, {
                "vuln_type": vuln_type,
                "delta": weight_delta
            })

            log.debug(f"Updated graph weights for {vuln_type}: delta={weight_delta:.3f}")

        except Exception as e:
            log.debug(f"Graph weight update skipped: {e}")

    async def _strengthen_edge(self, src_node: str, dst_node: str, weight_delta: float):
        """Increase weight of attack graph edge (successful chain path)."""
        try:
            from oneinfinity.learning.neo4j_knowledge_base import Neo4jKnowledgeBase

            kb = Neo4jKnowledgeBase()

            query = """
            MATCH (a)-[r:ENABLES]->(b)
            WHERE a.node_id = $src AND b.node_id = $dst
            SET r.weight = COALESCE(r.weight, 1.0) + $delta
            RETURN r.weight as new_weight
            """

            result = await kb.execute_query(query, {
                "src": src_node,
                "dst": dst_node,
                "delta": weight_delta
            })

            log.debug(f"Strengthened edge {src_node} → {dst_node}: +{weight_delta:.2f}")

        except Exception as e:
            log.debug(f"Edge strengthen skipped: {e}")

    async def _add_pattern(self, vuln_type: str, payload: str, tool: str):
        """Add successful payload pattern to KB."""
        try:
            from oneinfinity.core.db_manager import get_db_manager

            mgr = await get_db_manager()
            if not mgr:
                return

            await mgr.pg_execute_write(
                """
                INSERT INTO knowledge_base (category, key, value, source, created_at)
                VALUES ('successful_payload', $1, $2, $3, NOW())
                ON CONFLICT DO NOTHING
                """,
                (f"{vuln_type}_{tool}", payload, tool)
            )

            log.debug(f"Added pattern: {vuln_type} from {tool}")

        except Exception as e:
            log.debug(f"Pattern addition skipped: {e}")

    async def _add_chain_pattern(self, chain_name: str, steps: List[str], exploitability: float):
        """Add successful chain pattern to KB."""
        try:
            from oneinfinity.core.db_manager import get_db_manager
            import json

            mgr = await get_db_manager()
            if not mgr:
                return

            await mgr.pg_execute_write(
                """
                INSERT INTO knowledge_base (category, key, value, source, created_at)
                VALUES ('attack_chain', $1, $2, 'realtime_learner', NOW())
                ON CONFLICT DO NOTHING
                """,
                (chain_name, json.dumps({
                    "steps": steps,
                    "exploitability": exploitability,
                    "discovered_at": time.time()
                }))
            )

            log.info(f"Added chain pattern: {chain_name}")

        except Exception as e:
            log.debug(f"Chain pattern addition skipped: {e}")

    async def _persist_learning(self):
        """Persist tool confidence scores to PostgreSQL."""
        try:
            from oneinfinity.core.db_manager import get_db_manager
            import json

            mgr = await get_db_manager()
            if not mgr:
                return

            for tool, tc in self.tool_confidence.items():
                await mgr.pg_execute_write(
                    """
                    INSERT INTO knowledge_base (category, key, value, source, created_at)
                    VALUES ('tool_confidence', $1, $2, 'realtime_learner', NOW())
                    ON CONFLICT (category, key) DO UPDATE
                    SET value = EXCLUDED.value, source = EXCLUDED.source
                    """,
                    (tool, json.dumps({
                        "confidence": tc.confidence,
                        "success_count": tc.success_count,
                        "failure_count": tc.failure_count,
                        "false_positive_count": tc.false_positive_count,
                        "success_rate": tc.success_rate
                    }))
                )

        except Exception as e:
            log.debug(f"Learning persistence skipped: {e}")

    # ── Metrics & Analytics ───────────────────────────────────────────────────

    def get_scan_count(self) -> int:
        """Get total number of scans processed."""
        return self.scan_count

    def get_adaptation_count(self) -> int:
        """Get number of successful adaptations."""
        return self.adaptation_count

    def get_tool_confidence_map(self) -> Dict[str, float]:
        """Get confidence scores for all tools."""
        return {
            tool: tc.confidence
            for tool, tc in self.tool_confidence.items()
        }

    def get_pattern_count(self) -> int:
        """Get number of learned patterns."""
        return self.pattern_count

    def compute_improvement_rate(self) -> float:
        """Calculate scan improvement rate (scan N+1 vs N)."""
        if self.scan_count < 2:
            return 0.0

        # Improvement = adaptations / scans
        return self.adaptation_count / self.scan_count if self.scan_count > 0 else 0.0

    def get_learning_velocity(self) -> float:
        """Get learning velocity (patterns/hour)."""
        if not self.learning_events:
            return 0.0

        first_event = self.learning_events[0]
        last_event = self.learning_events[-1]

        time_elapsed = last_event.timestamp - first_event.timestamp
        hours = time_elapsed / 3600

        return len(self.learning_events) / hours if hours > 0 else 0.0

    def get_learning_events(self, limit: int = 100) -> List[Dict]:
        """Get recent learning events."""
        events = self.learning_events[-limit:]
        return [
            {
                "event_id": e.event_id,
                "event_type": e.event_type,
                "timestamp": e.timestamp,
                "data": e.data,
                "impact": e.impact
            }
            for e in events
        ]

    def start_scan(self, scan_id: str = "", target: str = "") -> None:
        """Called when a new scan starts. Records scan context for metrics."""
        log.info("RealtimeLearner: scan started scan_id=%s target=%s", scan_id, target)

    def on_scan_complete(self, scan_id: str = "", finding_count: int = 0) -> None:
        """Called when scan completes to update metrics."""
        self.scan_count += 1
        log.info(
            "Scan %s complete (scan_id=%s): %d findings, %d adaptations, %d patterns",
            self.scan_count, scan_id, finding_count, self.adaptation_count, self.pattern_count,
        )


# ── Singleton ─────────────────────────────────────────────────────────────────

_learner_instance: Optional[RealtimeLearner] = None


def get_learner() -> RealtimeLearner:
    """Get singleton learner instance."""
    global _learner_instance
    if _learner_instance is None:
        _learner_instance = RealtimeLearner()
    return _learner_instance
