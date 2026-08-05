"""
ai_target_classifier.py — Shared AI Target Detection Module
============================================================
Single source of truth for "_is_ai_target()" detection.
Previously duplicated in god_mode_engine.py and various scan modules.

Usage:
    from oneinfinity.ai_security.ai_target_classifier import AITargetClassifier

    clf = AITargetClassifier()
    result = clf.classify(url="http://localhost:9090", body_sample="ask the chatbot")
    if result.is_ai_target:
        print(result.reason, result.confidence)
"""
from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Optional, List


# ── URL / path keyword signals ────────────────────────────────────────────────
_URL_KEYWORDS = frozenset([
    "/v1/chat", "/api/chat", "completions", "llm", "chatbot",
    "openai", "anthropic", "ollama", "gemini", "/inference",
    "/generate", "/ai/", "gpt", "claude", "/predict", "/text",
    "/completion", "/assistant", "/bot", "/nlp", "/ml",
])

# ── Body / title / page content signals ──────────────────────────────────────
_BODY_KEYWORDS = frozenset([
    "llm", "language model", "chatbot", "chat with", "ai assistant",
    "prompt injection", "ai goat", "damn vulnerable llm", "streamlit",
    "ollama", "gpt", "claude", "gemini", "openai", "anthropic",
    "large language", "text generation", "neural network", "transformer",
    "embedding", "semantic search", "vector store", "rag", "langchain",
    "autogpt", "agent", "copilot",
])

# ── HTTP response header signals ─────────────────────────────────────────────
_HEADER_SIGNALS = frozenset([
    "x-openai", "x-anthropic", "x-model", "x-llm", "openai-processing-ms",
    "x-request-id",  # openai-style
])

# ── JSON response body signals ────────────────────────────────────────────────
_JSON_RESPONSE_SIGNALS = frozenset([
    "choices", "message", "content", "role", "finish_reason",
    "model", "usage", "prompt_tokens", "completion_tokens",
])


@dataclass
class ClassificationResult:
    is_ai_target: bool
    confidence: float                           # 0.0–1.0
    reason: str
    signals: List[str] = field(default_factory=list)
    url_match: bool = False
    body_match: bool = False
    header_match: bool = False
    json_response_match: bool = False


class AITargetClassifier:
    """
    Classifies whether a URL / endpoint is an AI/LLM target.

    Confidence scoring:
      Each matched signal category adds to the confidence score:
        URL keywords          → +0.4
        Body keywords         → +0.3
        Response headers      → +0.2
        JSON response shape   → +0.2
        All four              → capped at 1.0

    A target is classified as AI if confidence >= threshold (default 0.3).
    """

    def __init__(self, threshold: float = 0.3) -> None:
        self.threshold = threshold

    def classify(
        self,
        url: str,
        body_sample: str = "",
        response_headers: Optional[dict] = None,
        response_body: str = "",
    ) -> ClassificationResult:
        signals: List[str] = []
        score = 0.0

        # URL match
        url_lower = url.lower()
        url_hits = [kw for kw in _URL_KEYWORDS if kw in url_lower]
        if url_hits:
            score += 0.4
            signals.extend([f"url:{h}" for h in url_hits[:3]])

        # Body match (page text / request body)
        body_lower = (body_sample or "").lower()
        body_hits = [kw for kw in _BODY_KEYWORDS if kw in body_lower]
        if body_hits:
            score += 0.3
            signals.extend([f"body:{h}" for h in body_hits[:3]])

        # Response header match
        header_match = False
        if response_headers:
            headers_lower = {k.lower(): v for k, v in response_headers.items()}
            header_hits = [s for s in _HEADER_SIGNALS if any(s in hk for hk in headers_lower)]
            if header_hits:
                score += 0.2
                header_match = True
                signals.extend([f"header:{h}" for h in header_hits[:2]])

        # JSON response shape (OpenAI-compat check)
        json_match = False
        resp_lower = response_body.lower()
        json_hits = [s for s in _JSON_RESPONSE_SIGNALS if f'"{s}"' in resp_lower]
        if len(json_hits) >= 2:
            score += 0.2
            json_match = True
            signals.extend([f"json:{h}" for h in json_hits[:2]])

        confidence = min(1.0, round(score, 2))
        is_ai = confidence >= self.threshold

        reason = (
            f"AI target: {', '.join(signals[:4])}"
            if is_ai
            else f"Not AI target (confidence={confidence:.2f})"
        )

        return ClassificationResult(
            is_ai_target=is_ai,
            confidence=confidence,
            reason=reason,
            signals=signals,
            url_match=bool(url_hits),
            body_match=bool(body_hits),
            header_match=header_match,
            json_response_match=json_match,
        )

    def is_ai_target(self, url: str, body_sample: str = "") -> bool:
        """Convenience boolean wrapper."""
        return self.classify(url=url, body_sample=body_sample).is_ai_target


# Module-level singleton convenience
_default_classifier = AITargetClassifier()


def is_ai_target(url: str, body_sample: str = "") -> bool:
    """Drop-in replacement for god_mode_engine._is_ai_target()."""
    return _default_classifier.is_ai_target(url, body_sample)
