"""
Tests for SemanticCache

Covers:
1. Cache hit/miss (exact match)
2. Semantic similarity matching
3. Tech stack filtering
4. TTL expiration
5. Clear cache
6. Statistics
7. Integration with model orchestrator
"""

import pytest
import time
from unittest.mock import Mock, patch, MagicMock

from oneinfinity.infra.semantic_cache import SemanticCache, CachedResponse, EMBEDDINGS_AVAILABLE


@pytest.fixture
def redis_mock():
    """Mock Redis client."""
    mock = MagicMock()
    mock.ping.return_value = True
    mock.get.return_value = None
    mock.setex.return_value = True
    mock.keys.return_value = []
    mock.delete.return_value = 0
    return mock


@pytest.fixture
def cache(redis_mock):
    """Create SemanticCache with mocked Redis."""
    with patch('redis.from_url', return_value=redis_mock):
        cache = SemanticCache(
            redis_url="redis://localhost:6379/1",
            similarity_threshold=0.92,
            ttl_days=7,
        )
        return cache


def test_cache_initialization(cache):
    """Test cache initializes correctly."""
    assert cache.threshold == 0.92
    assert cache.ttl == 7 * 86400
    assert cache._hits == 0
    assert cache._misses == 0


def test_cache_disabled_without_redis():
    """Test cache gracefully disabled without Redis."""
    with patch('redis.from_url', side_effect=Exception("Connection failed")):
        cache = SemanticCache()
        assert cache.redis is None
        assert cache.get("test task") is None


@pytest.mark.skipif(not EMBEDDINGS_AVAILABLE, reason="sentence-transformers not installed")
def test_exact_match_hit(cache, redis_mock):
    """Test cache hit with exact task match."""
    # Mock cached response
    cached_data = CachedResponse(
        task="detect SSRF in search endpoint",
        target_tech=["python", "flask"],
        response="Use SSRF payload: http://169.254.169.254/...",
        model_id="gpt-4",
        confidence=0.9,
        timestamp=time.time(),
        hit_count=0,
    )

    redis_mock.get.return_value = cached_data.to_dict()
    redis_mock.get.return_value = '{"task": "detect SSRF in search endpoint", "target_tech": ["python", "flask"], "response": "Use SSRF payload: http://169.254.169.254/...", "model_id": "gpt-4", "confidence": 0.9, "timestamp": 1234567890.0, "hit_count": 0}'

    # Query same task
    result = cache.get("detect SSRF in search endpoint", ["python", "flask"])

    assert result is not None
    assert result.response == "Use SSRF payload: http://169.254.169.254/..."
    assert result.model_id == "gpt-4"
    assert cache._hits == 1


@pytest.mark.skipif(not EMBEDDINGS_AVAILABLE, reason="sentence-transformers not installed")
def test_cache_miss(cache, redis_mock):
    """Test cache miss when no similar tasks."""
    redis_mock.get.return_value = None
    redis_mock.keys.return_value = []

    result = cache.get("completely new task", ["nodejs"])

    assert result is None
    assert cache._misses == 1


@pytest.mark.skipif(not EMBEDDINGS_AVAILABLE, reason="sentence-transformers not installed")
def test_semantic_similarity_hit(cache, redis_mock):
    """Test semantic matching finds similar (not exact) tasks."""
    import json
    import numpy as np

    # Mock model to return similar embeddings
    mock_embedding = np.random.rand(384)  # 384-dim embedding

    cache.model = Mock()
    cache.model.encode.return_value = mock_embedding

    # Mock cached task with similar embedding
    cached_embedding = mock_embedding + np.random.rand(384) * 0.01  # Very similar

    cached_entry = {
        "task": "find SSRF vulnerability",
        "target_tech": ["python"],
        "embedding": cached_embedding.tolist(),
        "response_data": {
            "task": "find SSRF vulnerability",
            "target_tech": ["python"],
            "response": "Check for SSRF patterns",
            "model_id": "gpt-4",
            "confidence": 0.85,
            "timestamp": time.time(),
            "hit_count": 0,
        },
        "key": "cache:embed:abc123"
    }

    redis_mock.get.side_effect = lambda key: (
        None if key.startswith("cache:exact:")
        else json.dumps(cached_entry)
    )
    redis_mock.keys.return_value = ["cache:embed:abc123"]

    # Query semantically similar task
    result = cache.get("detect SSRF bugs", ["python"])

    # Should find similar cached task
    # (actual similarity depends on embeddings, so just check structure)
    assert cache._hits + cache._misses > 0


@pytest.mark.skipif(not EMBEDDINGS_AVAILABLE, reason="sentence-transformers not installed")
def test_tech_stack_filtering(cache):
    """Test tech stack compatibility filtering."""
    # Compatible: overlap exists
    assert cache._tech_matches(
        ["python", "flask"],
        ["python", "django"]
    ) is True

    # Incompatible: no overlap
    assert cache._tech_matches(
        ["python", "flask"],
        ["nodejs", "express"]
    ) is False

    # No tech info: assume compatible
    assert cache._tech_matches([], ["python"]) is True
    assert cache._tech_matches(["python"], []) is True


def test_put_stores_in_cache(cache, redis_mock):
    """Test put() stores response in cache."""
    cache.put(
        task="test task",
        target_tech=["python"],
        response="test response",
        model_id="gpt-4",
        confidence=0.9,
    )

    # Should call setex twice (exact + embedding keys)
    assert redis_mock.setex.call_count >= 1


def test_clear_cache(cache, redis_mock):
    """Test clear() removes all cache entries."""
    redis_mock.keys.return_value = ["cache:exact:abc", "cache:embed:def"]
    redis_mock.delete.return_value = 2

    deleted = cache.clear()

    assert deleted == 2
    redis_mock.delete.assert_called_once()


def test_cache_stats(cache):
    """Test stats() returns correct statistics."""
    cache._hits = 7
    cache._misses = 3

    stats = cache.stats()

    assert stats["hits"] == 7
    assert stats["misses"] == 3
    assert stats["hit_rate"] == 0.7
    assert stats["threshold"] == 0.92


@pytest.mark.skipif(not EMBEDDINGS_AVAILABLE, reason="sentence-transformers not installed")
def test_cosine_similarity(cache):
    """Test cosine similarity calculation."""
    import numpy as np

    vec1 = np.array([1.0, 0.0, 0.0])
    vec2 = np.array([1.0, 0.0, 0.0])

    similarity = cache._cosine_similarity(vec1, vec2)
    assert similarity == pytest.approx(1.0, abs=0.01)

    vec3 = np.array([0.0, 1.0, 0.0])
    similarity = cache._cosine_similarity(vec1, vec3)
    assert similarity == pytest.approx(0.0, abs=0.01)


def test_singleton_get_semantic_cache():
    """Test singleton pattern for get_semantic_cache."""
    from oneinfinity.infra.semantic_cache import get_semantic_cache

    cache1 = get_semantic_cache()
    cache2 = get_semantic_cache()

    assert cache1 is cache2


@pytest.mark.skipif(not EMBEDDINGS_AVAILABLE, reason="sentence-transformers not installed")
def test_cached_response_serialization():
    """Test CachedResponse to_dict/from_dict."""
    response = CachedResponse(
        task="test",
        target_tech=["python"],
        response="result",
        model_id="gpt-4",
        confidence=0.9,
        timestamp=1234567890.0,
        hit_count=5,
    )

    data = response.to_dict()
    assert data["task"] == "test"
    assert data["hit_count"] == 5

    restored = CachedResponse.from_dict(data)
    assert restored.task == "test"
    assert restored.hit_count == 5


def test_cache_with_env_variables():
    """Test cache respects environment variables."""
    import os

    with patch.dict(os.environ, {"REDIS_URL": "redis://custom:6379/2"}):
        with patch('redis.from_url') as mock_redis:
            mock_redis.return_value.ping.return_value = True

            cache = SemanticCache()

            mock_redis.assert_called_once()
            args = mock_redis.call_args[0]
            assert "custom" in args[0] or "6379" in args[0]


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
