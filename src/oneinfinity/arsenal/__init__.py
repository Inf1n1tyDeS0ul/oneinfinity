"""
Offensive Arsenal Package

Embedded payload libraries and context-aware selection for exploitation.
"""
from oneinfinity.arsenal.context_matcher import (
    ContextMatcher,
    Payload,
    TargetContext,
    get_context_matcher,
)

__all__ = [
    "ContextMatcher",
    "Payload",
    "TargetContext",
    "get_context_matcher",
]
