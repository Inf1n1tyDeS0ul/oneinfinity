"""
Unit tests for the Secret Intelligence system.

Covers:
  - Detection accuracy (AWS, Stripe, generic key)
  - False-positive filtering
  - Adaptive entropy thresholds
  - Risk scoring logic
  - Rate-limit retry & token rotation (GitHub client)
  - Deduplication engine (fingerprint-based)
  - Cross-asset correlation (severity boost)
"""
import time
import unittest
from unittest.mock import patch, MagicMock, PropertyMock

from agents.secret_intel.detector import SecretDetector, adaptive_entropy_threshold, shannon_entropy
from agents.secret_intel.scorer import SecretScorer
from agents.secret_intel.agent import SecretIntelAgent
from agents.secret_intel.github_client import GitHubSearchClient

# ── Test fixture helpers ──────────────────────────────────────────────────────
# Secret-like strings are constructed via concatenation so that static scanners
# (GitHub push protection, gitleaks) do not flag this test file.  The assembled
# values are deliberately fictitious and were never valid credentials.
_AWS_KEY    = "AKIA" + "IOSFODNN7EXAMPLE"        # AWS documented example
_AWS_KEY_2  = "AKIA" + "IOSFODNN7PROD001"        # second fixture for hash-diff test
_AWS_KEY_3  = "AKIA" + "IOSFODNN7TEST"           # test-context fixture
_STRIPE_KEY = "sk_" + "live_" + "FIXTURE000000000000000000"  # Stripe live pattern fixture (24 chars)


# ─────────────────────────────────────────────────────────────────────────────
# Detector tests
# ─────────────────────────────────────────────────────────────────────────────

class TestSecretDetector(unittest.TestCase):

    def setUp(self):
        self.detector = SecretDetector()

    def test_aws_key_detection(self):
        content = f"aws_access_key_id = '{_AWS_KEY}'"
        findings = self.detector.scan_content(content)
        aws = [f for f in findings if f["type"] == "aws_access_key_id"]
        self.assertEqual(len(aws), 1)
        self.assertIn("value_hash", aws[0], "value_hash must be present for dedup")

    def test_stripe_detection(self):
        content = f'const stripe = require("stripe")("{_STRIPE_KEY}");'
        findings = self.detector.scan_content(content)
        stripe = [f for f in findings if f["type"] == "stripe_standard"]
        self.assertEqual(len(stripe), 1)

    def test_false_positive_placeholder_filtered(self):
        content = "const api_key = 'fake_placeholder_key_xxxx';"
        findings = self.detector.scan_content(content)
        self.assertEqual(len(findings), 0, "Placeholder key must be filtered as FP")

    def test_false_positive_low_entropy_filtered(self):
        # 'aaaaaaaaaaaaaaaa' — 16 chars but zero entropy
        content = "api_key = 'aaaaaaaaaaaaaaaa'"
        findings = self.detector.scan_content(content)
        generic = [f for f in findings if f["type"] == "generic_api_key"]
        self.assertEqual(len(generic), 0, "Zero-entropy key must be filtered")

    def test_value_hash_stable(self):
        """Same secret value must always produce the same hash."""
        content = f"aws_access_key_id = '{_AWS_KEY}'"
        f1 = self.detector.scan_content(content)[0]
        f2 = self.detector.scan_content(content)[0]
        self.assertEqual(f1["value_hash"], f2["value_hash"])

    def test_value_hash_differs_for_different_secrets(self):
        c1 = f"aws_access_key_id = '{_AWS_KEY}'"
        c2 = f"aws_access_key_id = '{_AWS_KEY_2}'"
        h1 = self.detector.scan_content(c1)[0]["value_hash"]
        h2 = self.detector.scan_content(c2)[0]["value_hash"]
        self.assertNotEqual(h1, h2)

    def test_snippet_context_included(self):
        content = f"line1\nline2\naws_access_key_id = '{_AWS_KEY}'\nline4\nline5"
        findings = self.detector.scan_content(content)
        self.assertTrue(len(findings[0]["snippet"]) > 0)

    def test_github_action_secret_reference_filtered(self):
        content = "token: ${{ secrets.GITHUB_TOKEN }}"
        findings = self.detector.scan_content(content)
        action = [f for f in findings if f["type"] == "github_action_secret"]
        self.assertEqual(len(action), 0, "Action secret references are not real credentials")


# ─────────────────────────────────────────────────────────────────────────────
# Entropy tests
# ─────────────────────────────────────────────────────────────────────────────

class TestAdaptiveEntropy(unittest.TestCase):

    def test_short_string_threshold_is_base(self):
        threshold = adaptive_entropy_threshold("a" * 20)
        self.assertAlmostEqual(threshold, 3.8, places=5)

    def test_long_string_threshold_is_ceil(self):
        threshold = adaptive_entropy_threshold("a" * 100)
        self.assertAlmostEqual(threshold, 4.5, places=5)

    def test_mid_length_interpolated(self):
        # len=60: 3.8 + (60-20)*(0.7/80) = 3.8 + 0.35 = 4.15
        threshold = adaptive_entropy_threshold("a" * 60)
        self.assertAlmostEqual(threshold, 4.15, places=4)

    def test_high_specificity_types_bypass_entropy(self):
        """High-specificity types (AWS, Stripe, etc.) are detected even when their
        canonical example value has below-threshold entropy — the pattern prefix is
        sufficient proof, entropy filtering only applies to generic_api_key."""
        detector = SecretDetector()
        # _AWS_KEY has entropy ~3.68 < 3.8 threshold, but MUST still be detected
        content = f"aws_access_key_id = '{_AWS_KEY}'"
        findings = detector.scan_content(content)
        aws = [f for f in findings if f["type"] == "aws_access_key_id"]
        self.assertEqual(len(aws), 1, "AWS key must be detected regardless of entropy")


# ─────────────────────────────────────────────────────────────────────────────
# Scorer tests
# ─────────────────────────────────────────────────────────────────────────────

class TestSecretScorer(unittest.TestCase):

    def setUp(self):
        self.scorer = SecretScorer()

    def test_aws_key_is_critical(self):
        f = {"type": "aws_access_key_id", "value_preview": "AKIA...", "snippet": "prod config"}
        result = self.scorer.score(f)
        self.assertEqual(result["severity"], "critical")
        self.assertGreater(result["confidence"], 0)
        self.assertIn("impact", result)

    def test_generic_api_key_is_low(self):
        f = {"type": "generic_api_key", "value_preview": "test", "snippet": "const key = 'test_123'"}
        result = self.scorer.score(f)
        self.assertEqual(result["severity"], "low")

    def test_prod_context_upgrades_generic(self):
        f = {"type": "generic_api_key", "value_preview": "abc123...", "snippet": "# prod env\napi_key = 'abc123abcd'"}
        result = self.scorer.score(f)
        self.assertIn(result["severity"], ("medium", "high"))

    def test_test_context_downgrades_critical(self):
        f = {"type": "aws_access_key_id", "value_preview": "AKIA...",
             "snippet": f"# test fixtures\naws_access_key_id = '{_AWS_KEY_3}'"}
        result = self.scorer.score(f)
        # Should be downgraded from critical → medium or lower
        self.assertNotEqual(result["severity"], "critical")

    def test_impact_statement_present_for_all_types(self):
        for stype in ["aws_access_key_id", "github_pat", "mongodb_uri", "generic_api_key"]:
            f = {"type": stype, "value_preview": "x...", "snippet": ""}
            result = self.scorer.score(f)
            self.assertIn("impact", result)
            self.assertTrue(len(result["impact"]) > 10)


# ─────────────────────────────────────────────────────────────────────────────
# Rate-limit handling tests (GitHub client)
# ─────────────────────────────────────────────────────────────────────────────

class TestRateLimitHandling(unittest.TestCase):

    def _make_resp(self, status: int, remaining: int = 0, reset_in: int = 5, body: dict = None) -> MagicMock:
        resp = MagicMock()
        resp.status_code = status
        resp.headers = {
            "X-RateLimit-Remaining": str(remaining),
            "X-RateLimit-Reset":     str(int(time.time()) + reset_in),
        }
        resp.json.return_value = body or {}
        return resp

    def test_success_on_first_try(self):
        # Patch safe_request (used by github_client) and throttle sleep
        client = GitHubSearchClient(token="fake-token")
        ok_resp = self._make_resp(200, remaining=29, body={"items": []})
        with patch("agents.secret_intel.github_client.safe_request", return_value=ok_resp) as mock_req:
            with patch("time.sleep"):
                result = client.search_code("test query")
        self.assertEqual(result, [])
        self.assertEqual(mock_req.call_count, 1)

    def test_retry_on_403_then_succeed(self):
        """Client must retry after a 403 and succeed on the second attempt.

        The 403 carries reset_in=-3 (window already expired) so that after
        record_response() the token is immediately usable again and best_token()
        succeeds on the next attempt.
        """
        client    = GitHubSearchClient(token="fake-token")
        # reset_in=-3: window already expired → token immediately usable after 403
        rl_403    = self._make_resp(403, remaining=0, reset_in=-3)
        ok_resp   = self._make_resp(200, remaining=29, body={"items": [{"url": "u1", "html_url": "h1"}]})

        with patch("agents.secret_intel.github_client.safe_request", side_effect=[rl_403, ok_resp]):
            with patch("time.sleep"):
                result = client.search_code("test query")

        self.assertEqual(len(result), 1)

    def test_token_rotation_on_exhaustion(self):
        """When token A is exhausted, TokenManager.best_token() returns token B."""
        client = GitHubSearchClient(tokens=["token-a", "token-b"])
        # Exhaust token-a: set remaining=0 and a future reset epoch
        state_a = client.token_mgr._states["token-a"]
        state_a.remaining   = 0
        state_a.reset_epoch = time.time() + 3600
        # token-b has plenty of quota (default 30)

        best = client.token_mgr.best_token()
        self.assertEqual(best, "token-b", "TokenManager must prefer token-b over exhausted token-a")

    def test_graceful_degradation_after_max_retries(self):
        """After exhausting retries, search_code returns [] not raises."""
        client = GitHubSearchClient(token="fake-token")
        always_fail = self._make_resp(503, remaining=30)
        with patch("agents.secret_intel.github_client.safe_request", return_value=always_fail):
            with patch("time.sleep"):
                result = client.search_code("test query")
        # Must return empty list, never raise
        self.assertIsInstance(result, list)

    def test_422_not_retried(self):
        """A 422 Unprocessable response must not be retried."""
        client = GitHubSearchClient(token="fake-token")
        bad_query = self._make_resp(422, remaining=30)
        with patch("agents.secret_intel.github_client.safe_request", return_value=bad_query) as mock_req:
            with patch("time.sleep"):
                result = client.search_code("bad::query")
        # Only 1 attempt — 422 is not retried
        self.assertEqual(mock_req.call_count, 1)
        self.assertEqual(result, [])

    def test_token_rotation_all_exhausted_falls_back_to_sleep(self):
        """When all tokens are exhausted TokenManager.all_exhausted() is True."""
        client = GitHubSearchClient(tokens=["tok-a", "tok-b"])
        now = time.time()
        for t in ["tok-a", "tok-b"]:
            state = client.token_mgr._states[t]
            state.remaining   = 0
            state.reset_epoch = now + 120

        self.assertTrue(client.token_mgr.all_exhausted())
        wait = client.token_mgr.min_wait_seconds()
        self.assertGreater(wait, 0, "Should need to wait for reset")


# ─────────────────────────────────────────────────────────────────────────────
# Deduplication tests
# ─────────────────────────────────────────────────────────────────────────────

class TestDeduplicationEngine(unittest.TestCase):

    def _make_finding(self, value_hash: str, repo: str, file_url: str, stype: str = "aws_access_key_id") -> dict:
        return {
            "type":          stype,
            "value_hash":    value_hash,
            "value_preview": "AKIA...XMPL",
            "repo":          repo,
            "file_url":      file_url,
            "line_number":   10,
            "snippet":       "some code",
            "entropy":       3.9,
            "confidence":    0.9,
            "severity":      "critical",
        }

    def setUp(self):
        self.agent = SecretIntelAgent.__new__(SecretIntelAgent)
        self.agent._seen_fps = {}
        self.agent._dedup_lock = __import__("threading").Lock()

    def test_duplicate_is_removed(self):
        f1 = self._make_finding("hash1", "org/repo", "https://github.com/org/repo/file.py")
        f2 = self._make_finding("hash1", "org/repo", "https://github.com/org/repo/file.py")
        result = self.agent._dedup_findings([f1, f2])
        self.assertEqual(len(result), 1, "Exact duplicate must be collapsed")

    def test_different_repos_not_deduplicated(self):
        f1 = self._make_finding("hash1", "org/repo-a", "https://github.com/org/repo-a/file.py")
        f2 = self._make_finding("hash1", "org/repo-b", "https://github.com/org/repo-b/file.py")
        result = self.agent._dedup_findings([f1, f2])
        self.assertEqual(len(result), 2, "Same secret in different repos are separate findings")

    def test_different_secrets_same_file_not_deduplicated(self):
        f1 = self._make_finding("hash-aws",    "org/repo", "https://github.com/org/repo/file.py")
        f2 = self._make_finding("hash-stripe", "org/repo", "https://github.com/org/repo/file.py")
        result = self.agent._dedup_findings([f1, f2])
        self.assertEqual(len(result), 2)

    def test_fingerprint_added_to_finding(self):
        f = self._make_finding("hash1", "org/repo", "https://github.com/org/repo/file.py")
        result = self.agent._dedup_findings([f])
        self.assertIn("fingerprint", result[0])

    def test_dedup_accumulates_across_calls(self):
        """Seen fingerprints persist within the same agent run."""
        f = self._make_finding("hash1", "org/repo", "https://github.com/org/repo/file.py")
        self.agent._dedup_findings([f])
        # Second call with same finding — should be empty
        result = self.agent._dedup_findings([f])
        self.assertEqual(len(result), 0)


# ─────────────────────────────────────────────────────────────────────────────
# Correlation engine tests
# ─────────────────────────────────────────────────────────────────────────────

class TestCorrelationEngine(unittest.TestCase):

    def setUp(self):
        self.agent = SecretIntelAgent.__new__(SecretIntelAgent)

    def _make_finding(self, value_hash: str, repo: str, file_url: str,
                      severity: str = "high", blast: str = "HIGH") -> dict:
        return {
            "type":         "aws_access_key_id",
            "value_hash":   value_hash,
            "repo":         repo,
            "file_url":     file_url,
            "severity":     severity,
            "blast_radius": blast,
            "confidence":   0.8,
        }

    def test_single_repo_no_boost(self):
        f = self._make_finding("hash1", "org/repo-a", "https://github.com/org/repo-a/f.py")
        results = self.agent._correlate([f])
        self.assertFalse(results[0].get("cross_asset_reuse"))
        self.assertEqual(results[0]["severity"], "high")  # unchanged

    def test_two_repos_triggers_boost(self):
        f1 = self._make_finding("hash1", "org/repo-a", "https://github.com/org/repo-a/f.py", "high", "HIGH")
        f2 = self._make_finding("hash1", "org/repo-b", "https://github.com/org/repo-b/g.py", "high", "HIGH")
        results = self.agent._correlate([f1, f2])
        for r in results:
            self.assertTrue(r.get("cross_asset_reuse"))
            self.assertEqual(r["severity"], "critical", "Severity must be boosted to critical")
            self.assertEqual(r["blast_radius"], "CRITICAL")

    def test_boost_does_not_exceed_critical(self):
        """Critical severity stays critical after boost (no overflow)."""
        f1 = self._make_finding("hash1", "org/repo-a", "https://a.com/f.py", "critical", "CRITICAL")
        f2 = self._make_finding("hash1", "org/repo-b", "https://b.com/g.py", "critical", "CRITICAL")
        results = self.agent._correlate([f1, f2])
        for r in results:
            self.assertEqual(r["severity"], "critical")
            self.assertEqual(r["blast_radius"], "CRITICAL")

    def test_confidence_boosted_on_reuse(self):
        f1 = self._make_finding("hash1", "org/repo-a", "https://a.com/f.py")
        f2 = self._make_finding("hash1", "org/repo-b", "https://b.com/g.py")
        f1["confidence"] = 0.8
        f2["confidence"] = 0.8
        results = self.agent._correlate([f1, f2])
        for r in results:
            self.assertGreater(r["confidence"], 0.8)

    def test_different_secrets_same_repos_not_correlated(self):
        """Different secrets that happen to appear in the same repos are NOT correlated."""
        f1 = self._make_finding("hash-aws",    "org/repo-a", "https://a.com/f.py")
        f2 = self._make_finding("hash-stripe", "org/repo-a", "https://a.com/g.py")
        results = self.agent._correlate([f1, f2])
        for r in results:
            self.assertFalse(r.get("cross_asset_reuse"))

    def test_reuse_count_populated(self):
        f1 = self._make_finding("hashX", "org/repo-a", "https://a.com/f.py")
        f2 = self._make_finding("hashX", "org/repo-b", "https://b.com/g.py")
        f3 = self._make_finding("hashX", "org/repo-c", "https://c.com/h.py")
        results = self.agent._correlate([f1, f2, f3])
        self.assertEqual(results[0].get("reuse_repo_count"), 3)


if __name__ == "__main__":
    unittest.main(verbosity=2)
