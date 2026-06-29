"""
Learning System API
===================
Endpoints for real-time learning statistics and insights.
"""

from fastapi import APIRouter, Depends, HTTPException
from typing import Dict, List
import logging

log = logging.getLogger(__name__)

router = APIRouter(prefix="/api/learning", tags=["learning"])


def register_routes(app, require_auth=None):
    """Register learning routes with optional auth dependency."""
    deps = [Depends(require_auth)] if require_auth else []
    app.include_router(router, dependencies=deps)


@router.get("/stats")
async def get_learning_stats():
    """
    Get learning system statistics.

    Returns:
        - total_scans: Number of scans processed
        - successful_adaptations: Count of learning updates
        - tool_confidence: Tool reliability scores
        - pattern_library_size: Number of learned patterns
        - improvement_rate: Adaptation rate across scans
        - learning_velocity: Patterns learned per hour
    """
    try:
        from oneinfinity.learning.realtime_learner import get_learner

        learner = get_learner()

        return {
            "total_scans": learner.get_scan_count(),
            "successful_adaptations": learner.get_adaptation_count(),
            "tool_confidence": learner.get_tool_confidence_map(),
            "pattern_library_size": learner.get_pattern_count(),
            "improvement_rate": learner.compute_improvement_rate(),
            "learning_velocity": learner.get_learning_velocity(),
        }
    except Exception as e:
        log.error(f"Error fetching learning stats: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/timeline")
async def get_learning_timeline(limit: int = 100):
    """
    Get timeline of learning events.

    Args:
        limit: Maximum events to return (default: 100)

    Returns:
        List of learning events with timestamps and impact
    """
    try:
        from oneinfinity.learning.realtime_learner import get_learner

        learner = get_learner()
        events = learner.get_learning_events(limit=limit)

        return {"events": events}
    except Exception as e:
        log.error(f"Error fetching learning timeline: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/tool-confidence")
async def get_tool_confidence():
    """
    Get detailed tool confidence metrics.

    Returns tool success rates, failure counts, false positives.
    """
    try:
        from oneinfinity.learning.realtime_learner import get_learner

        learner = get_learner()

        # Build detailed confidence data
        detailed = []
        for tool_name, tc in learner.tool_confidence.items():
            detailed.append({
                "tool": tool_name,
                "confidence": tc.confidence,
                "success_rate": tc.success_rate,
                "success_count": tc.success_count,
                "failure_count": tc.failure_count,
                "false_positive_count": tc.false_positive_count,
            })

        return {"tools": detailed}
    except Exception as e:
        log.error(f"Error fetching tool confidence: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@router.post("/reset")
async def reset_learning():
    """
    Reset learning system (clear all learned patterns and confidence scores).

    WARNING: This cannot be undone.
    """
    try:
        from oneinfinity.learning.realtime_learner import get_learner

        learner = get_learner()

        # Clear learning data
        learner.tool_confidence.clear()
        learner.learning_events.clear()
        learner.successful_mutations.clear()
        learner.scan_count = 0
        learner.adaptation_count = 0
        learner.pattern_count = 0

        log.warning("Learning system reset by user request")

        return {"status": "ok", "message": "Learning system reset"}
    except Exception as e:
        log.error(f"Error resetting learning: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/mutation-stats")
async def get_mutation_stats():
    """
    Get payload mutation engine statistics.

    Returns mutation counts, strategy distribution, success rates.
    """
    try:
        from oneinfinity.arsenal.mutation_engine import get_mutation_engine

        engine = get_mutation_engine()
        stats = engine.get_stats()

        return stats
    except Exception as e:
        log.error(f"Error fetching mutation stats: {e}")
        raise HTTPException(status_code=500, detail=str(e))
