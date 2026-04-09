"""
SecretIntelAgent — ownership-aware, validation-backed secret intelligence pipeline.

Pipeline phases
---------------
  Phase 0   Scope resolution
  Phase 1   Priority-queue dork execution (high-signal first, early exit on critical)
  Phase 2   File URL deduplication
  Phase 2.5 Org Graph construction (domain → verified GitHub orgs)
  Phase 3   Parallel file fetch + secret detection + ownership classification
  Phase 4   Finding-level deduplication (SHA-256 fingerprint)
  Phase 5   Live validation + ownership-aware risk scoring  [_raw_value stripped here]
  Phase 6   AI validation + enrichment
  Phase 7   Cross-asset correlation engine (severity boost)
  Phase 8   Impact simulation + report field normalisation
  Phase 9   Ingestion + summary

False-attribution elimination
------------------------------
  Findings are NEVER attributed to a target based on keyword presence.
  Ownership is determined exclusively by verifying the repo owner against the
  target domain's confirmed GitHub org set (OrgGraph + OwnershipEngine).

  Every finding carries:
    ownership_party       first_party | third_party
    ownership_confidence  HIGH | MEDIUM | LOW
    ownership_reason      short label explaining the classification
    referenced_domain     the search domain used to discover this finding
    repo_owner            GitHub login of the repository owner
    repo_url              HTML URL of the repository

GitHub efficiency features
---------------------------
  - Queries executed in priority order (score 10 → 1); low-signal skipped on budget
  - Early exit: _critical_found event stops dork workers on first confirmed critical
  - File content LRU cache shared across all workers (same URL fetched once)
  - No blind sleep loops: all inter-request delays are header-driven
"""

import hashlib
import logging
import os
import threading
import time
import uuid
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime
from typing import Any, Dict, List, Optional, Tuple

from oneinfinity.agents.secret_intel.github_client import GitHubSearchClient, LRUContentCache
from oneinfinity.agents.secret_intel.detector      import SecretDetector
from oneinfinity.agents.secret_intel.scorer        import SecretScorer
from oneinfinity.agents.secret_intel.ai_validator  import AIValidationEngine
from oneinfinity.agents.secret_intel.validation_engine import ValidationEngine
from oneinfinity.agents.secret_intel.ownership_engine  import determine_ownership
from oneinfinity.agents.secret_intel.org_graph         import OrgGraph
from oneinfinity.agents.secret_intel.dork_engine       import DorkGenerator

logger = logging.getLogger(__name__)

# ── Tunables ───────────────────────────────────────────────────────────────────
_DORK_WORKERS      = 3    # concurrent GitHub search queries (≤3 avoids secondary RL)
_FETCH_WORKERS     = 8    # concurrent file-content fetches
_MAX_DORKS_PER_RUN = 20   # top-N scored dorks per scan
_MIN_DORK_SCORE    = 2    # skip dorks below this signal score
_AI_CONFIDENCE_MIN = 0.3  # below this skip AI validation (fast path)
_KEEP_CONFIDENCE   = 0.4  # below this discard finding entirely

# ── Impact scenario templates ──────────────────────────────────────────────────
_IMPACT_SCENARIOS: Dict[str, List[str]] = {
    "aws_access_key_id": [
        "Potential read/write access to all S3 buckets in the account",
        "Possible enumeration of EC2 instances, RDS databases, and Lambda functions",
        "Risk of IAM privilege escalation if the key has iam:* permissions",
    ],
    "aws_secret_access_key": [
        "Same blast radius as the paired access key — full AWS API access",
        "Potential data exfiltration from all services accessible to the IAM principal",
    ],
    "gcp_service_account": [
        "Potential read/write access to GCS buckets bound to this service account",
        "Possible access to BigQuery datasets, Pub/Sub topics, and Firestore collections",
        "Risk of lateral movement within the GCP project",
    ],
    "azure_key": [
        "Potential read/write access to Azure Blob Storage containers",
        "Possible enumeration of Azure Queues and Tables in the storage account",
    ],
    "github_pat": [
        "Potential read access to all private repositories the token owner can access",
        "Possible write/delete of repository content, branches, or secrets",
        "Risk of supply-chain attack via code modification or CI secret exfiltration",
    ],
    "stripe_standard": [
        "Possible unauthorized charges, refunds, or subscription manipulation",
        "Potential exposure of customer payment metadata (last 4 digits, email, address)",
        "Risk of financial fraud at scale via the Stripe API",
    ],
    "mongodb_uri": [
        "Potential direct read/write access to all collections in the database",
        "Possible full data exfiltration or ransomware-style database wipe",
    ],
    "postgres_uri": [
        "Potential read access to all tables visible to the connection user",
        "Possible data manipulation or schema alteration if user has DDL privileges",
    ],
    "mysql_uri": [
        "Potential read/write access to the database with the supplied credentials",
        "Possible data exfiltration of all rows accessible to the DB user",
    ],
    "redis_uri": [
        "Potential access to in-memory session tokens, cached PII, or job queues",
        "Possible server-side code execution via Redis CONFIG SET + module load in some versions",
    ],
    "openai_api_key": [
        "Possible unauthorized API usage leading to significant billing charges",
        "Potential access to fine-tuned models or Files API data if present",
    ],
    "twilio_api_key": [
        "Possible bulk SMS/voice call abuse for phishing or fraud",
        "Potential exposure of call logs and message history",
    ],
    "ssh_private_key": [
        "Potential unauthorized SSH access to any server that trusts the public key",
        "Risk of persistent backdoor installation or lateral movement within infrastructure",
    ],
    "rsa_private_key": [
        "Potential decryption of data encrypted with the paired public key",
        "Risk of impersonation if the key is used for TLS/mTLS or JWT signing",
    ],
    "sendgrid_api_key": [
        "Possible bulk email abuse for phishing campaigns using a trusted sending domain",
        "Potential suppression list access or unsubscribe manipulation",
    ],
    "slack_token": [
        "Potential read access to all channels the token has access to",
        "Possible exfiltration of messages, files, and user directories",
    ],
}

_DEFAULT_IMPACT_SCENARIOS = [
    "Potential unauthorized access to the associated service",
    "Possible data exposure depending on the permissions granted to this credential",
]


class SecretIntelAgent:
    """
    Orchestrates the end-to-end secret intelligence pipeline with
    ownership determination, live validation, deduplication, correlation,
    parallelism, and full observability.
    """

    def __init__(
        self,
        token:             Optional[str]       = None,
        tokens:            Optional[List[str]] = None,
        max_requests:      int                 = 5000,
        delay:             float               = 0.0,
        debug_rate_limit:  bool                = False,
        adaptive_throttle: bool                = True,
        live_validate:     bool                = True,
    ):
        # Shared LRU cache — all dork workers benefit from each other's fetches
        self._content_cache = LRUContentCache()
        self.github         = GitHubSearchClient(
            token=token, tokens=tokens, cache=self._content_cache,
            max_requests=max_requests, delay=delay,
            debug_rate_limit=debug_rate_limit,
            adaptive_throttle=adaptive_throttle,
        )

        # Resolve a GitHub token for ownership + org-graph API calls
        self._github_token: Optional[str] = (
            token
            or (tokens[0] if tokens else None)
            or os.environ.get("GITHUB_TOKEN")
            or os.environ.get("GITHUB_TOKENS", "").split(",")[0].strip()
            or None
        )

        self.detector          = SecretDetector()
        self.scorer            = SecretScorer()
        self.validation_engine = ValidationEngine(enabled=live_validate)
        self.org_graph         = OrgGraph(github_token=self._github_token)
        self.dork_engine       = DorkGenerator()

        orchestrator = None
        try:
            from oneinfinity.model_orchestrator import get_orchestrator
            orchestrator = get_orchestrator()
        except Exception:
            logger.warning("Model orchestrator unavailable — AI validation disabled.")

        self.validator = AIValidationEngine(model_orchestrator=orchestrator)

        # Deduplication store {fingerprint: True}
        self._seen_fps: dict = {}
        self._dedup_lock     = threading.Lock()

        # Early-exit signal
        self._critical_found = threading.Event()

        # Per-run observability
        self._timings: Dict[str, float]    = {}
        self._errors:  List[Dict[str, Any]] = []

    # ── Public entry point ─────────────────────────────────────────────────────

    def run(
        self,
        target:            str,
        scope_file:        Optional[str]  = None,
        stop_on_critical:  bool           = False,
        min_dork_score:    int            = _MIN_DORK_SCORE,
        max_dorks:         int            = _MAX_DORKS_PER_RUN,
        concurrency:       int            = _DORK_WORKERS,
        max_requests:      Optional[int]  = None,
        delay:             Optional[float]= None,
        debug_rate_limit:  Optional[bool] = None,
        adaptive_throttle: Optional[bool] = None,
    ) -> Dict[str, Any]:
        """
        Execute the full secret intelligence pipeline for *target*.

        Parameters
        ----------
        target            Domain or org name to scan.
        scope_file        Optional path to a scope file (one target per line).
        stop_on_critical  Cancel remaining dork workers on first CRITICAL finding.
        min_dork_score    Skip dorks below this signal score (2=all, 7=fast).
        max_dorks         Maximum dork queries to execute.
        concurrency       Max concurrent dork workers.
        max_requests      Override total request budget for this run.
        delay             Override per-request delay for this run.
        debug_rate_limit  Verbose rate-limit logging.
        adaptive_throttle Enable/disable header-driven pacing.
        """
        run_id    = str(uuid.uuid4())[:8]
        run_start = time.monotonic()

        if max_requests      is not None: self.github.max_requests      = max_requests
        if delay             is not None: self.github.base_delay         = delay
        if debug_rate_limit  is not None: self.github.debug_rate_limit   = debug_rate_limit
        if adaptive_throttle is not None: self.github.adaptive_throttle  = adaptive_throttle

        # Loose budget guard
        est_reqs = max_dorks * 2
        if est_reqs > self.github.max_requests:
            max_dorks = self.github.max_requests // 2
            logger.warning(
                "[%s] Budget cap: reducing max_dorks to %d", run_id, max_dorks
            )

        logger.info(
            "[%s] SecretIntelAgent starting — target=%s concurrency=%d max_dorks=%d",
            run_id, target, concurrency, max_dorks,
        )

        # Reset per-run state
        self._seen_fps.clear()
        self._timings.clear()
        self._errors.clear()
        self._critical_found.clear()
        self.github.request_count = 0

        # ── Phase 0: Scope ────────────────────────────────────────────────────
        scope_targets = self._timed_phase(
            "phase_0_scope", self._load_scope, scope_file
        )

        # ── Phase 1: Priority-queue dork execution ────────────────────────────
        scored_queries = self.dork_engine.generate_above_score(
            target, min_score=min_dork_score
        )
        top_scored = scored_queries[:max_dorks]
        logger.info(
            "[%s] Phase 1: executing %d/%d dorks (min_score≥%d, "
            "stop_on_critical=%s, concurrency=%d).",
            run_id, len(top_scored), len(scored_queries),
            min_dork_score, stop_on_critical, concurrency,
        )
        raw_results = self._timed_phase(
            "phase_1_dork", self._run_dorks_priority,
            top_scored, stop_on_critical, concurrency,
        )
        logger.info("[%s] Phase 1: %d raw results.", run_id, len(raw_results))

        # ── Phase 2: File-URL deduplication ──────────────────────────────────
        unique_items = self._timed_phase(
            "phase_2_url_dedup", self._dedup_by_url, raw_results
        )
        logger.info(
            "[%s] Phase 2: %d unique files after URL dedup.", run_id, len(unique_items)
        )

        # ── Phase 2.5: Org Graph construction ─────────────────────────────────
        # Build the verified org list BEFORE parallel fetch so all workers share
        # the cached graph without duplicate API calls.
        self._timed_phase(
            "phase_2_5_org_graph", self.org_graph.build_for_domain, target
        )
        logger.info(
            "[%s] Phase 2.5: org graph built for %s → %s",
            run_id, target,
            self.org_graph.summary().get(target, {}).get("orgs", []),
        )

        # ── Phase 3: Parallel fetch + detection + ownership ───────────────────
        raw_findings = self._timed_phase(
            "phase_3_detect", self._fetch_and_detect_parallel,
            unique_items, target, scope_targets, concurrency * 2,
        )
        logger.info(
            "[%s] Phase 3: %d raw findings detected.", run_id, len(raw_findings)
        )

        # ── Phase 4: Finding-level deduplication ──────────────────────────────
        deduped   = self._timed_phase("phase_4_dedup", self._dedup_findings, raw_findings)
        dup_count = len(raw_findings) - len(deduped)
        logger.info(
            "[%s] Phase 4: %d unique findings (%d duplicates removed).",
            run_id, len(deduped), dup_count,
        )

        # ── Phase 5: Live validation + ownership-aware risk scoring ───────────
        scored = self._timed_phase("phase_5_score", self._score_all, deduped)
        # _raw_value stripped here — never leaves Phase 5
        for f in scored:
            f.pop("_raw_value", None)

        # ── Phase 6: AI validation ────────────────────────────────────────────
        validated = self._timed_phase("phase_6_ai", self._validate_all, scored)
        kept      = [f for f in validated if f.get("confidence", 0) > _KEEP_CONFIDENCE]
        logger.info(
            "[%s] Phase 6: %d findings kept after AI + confidence filter.",
            run_id, len(kept),
        )

        # ── Phase 7: Cross-asset correlation ──────────────────────────────────
        correlated = self._timed_phase("phase_7_correlate", self._correlate, kept)

        # ── Phase 8: Impact simulation + field normalisation ──────────────────
        enriched = self._timed_phase(
            "phase_8_impact", self._add_impact_scenarios, correlated
        )
        for f in enriched:
            f["finding_id"] = str(uuid.uuid4())[:12]
            f["timestamp"]  = datetime.utcnow().isoformat()
            # Ensure all report fields are present (Phase 3 sets most; guarantee here)
            f.setdefault("ownership_party",      "unknown")
            f.setdefault("ownership_confidence", "LOW")
            f.setdefault("ownership_reason",     "not_determined")
            f.setdefault("referenced_domain",    target)
            f.setdefault("repo_owner",           "")
            f.setdefault("repo_url",             f.get("file_url", ""))
            f.setdefault("live_verified",        False)
            f.setdefault("validation_type",      "not_attempted")

        # ── Phase 9: Ingestion ────────────────────────────────────────────────
        self._timed_phase("phase_9_ingest", self._ingest_findings, enriched, target)

        total_ms = int((time.monotonic() - run_start) * 1000)
        logger.info(
            "[%s] Pipeline complete in %dms — %d findings.",
            run_id, total_ms, len(enriched),
        )
        return self._generate_summary(enriched, run_id, total_ms)

    # ── Phase implementations ──────────────────────────────────────────────────

    def _load_scope(self, scope_file: Optional[str]) -> List[str]:
        if not scope_file:
            return []
        try:
            targets = []
            with open(scope_file) as fh:
                for line in fh:
                    line = line.strip()
                    if line and not line.startswith("#"):
                        clean = (
                            line.replace("*.", "")
                                .replace("https://", "")
                                .replace("http://", "")
                                .strip("/")
                        )
                        if clean:
                            targets.append(clean)
            logger.info("Scope: %d targets loaded from %s.", len(targets), scope_file)
            return targets
        except Exception as exc:
            self._record_error("scope_load", str(exc))
            logger.warning("Scope load failed (%s) — continuing without scope filter.", exc)
            return []

    def _run_dorks_priority(
        self,
        scored_queries: List[Tuple[int, str]],
        stop_on_critical: bool,
        concurrency: int = _DORK_WORKERS,
    ) -> List[Dict[str, Any]]:
        """
        Execute dork queries in priority order (highest score first).
        Early exit fires when _critical_found is set and stop_on_critical=True.
        """
        results: List[Dict[str, Any]] = []
        lock    = threading.Lock()
        queries = [q for _, q in scored_queries]

        def _run_one(query: str) -> List[Dict[str, Any]]:
            if stop_on_critical and self._critical_found.is_set():
                logger.info("Early exit: skipping low-priority query '%.40s'.", query)
                return []
            try:
                items = self.github.search_code(query, per_page=100)
                logger.debug("Dork '%s...': %d results.", query[:50], len(items))
                return items
            except Exception as exc:
                self._record_error("dork_query", f"{query[:40]}: {exc}")
                return []

        with ThreadPoolExecutor(max_workers=concurrency) as pool:
            futures = {pool.submit(_run_one, q): q for q in queries}
            for fut in as_completed(futures):
                try:
                    items = fut.result()
                    with lock:
                        results.extend(items)
                    if stop_on_critical and not self._critical_found.is_set():
                        self._check_early_exit(items)
                except Exception as exc:
                    self._record_error("dork_future", str(exc))

        if stop_on_critical and self._critical_found.is_set():
            logger.info(
                "Early exit triggered — collected %d raw results before stopping.",
                len(results),
            )
        return results

    def _check_early_exit(self, items: List[Dict[str, Any]]) -> None:
        """Heuristic metadata-only check for critical path indicators."""
        _CRITICAL_PATHS = {
            "id_rsa", "id_dsa", "id_ecdsa", ".env", "aws_credentials",
            "credentials.json", "secrets.json", "gcp_credentials.json",
        }
        for item in items:
            path = item.get("path", "").lower()
            if any(cp in path for cp in _CRITICAL_PATHS):
                logger.warning(
                    "Early-exit heuristic triggered: critical path '%s' in %s.",
                    path, item.get("repository", {}).get("full_name", "?"),
                )
                self._critical_found.set()
                return

    def _dedup_by_url(self, items: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        seen: set = set()
        out = []
        for item in items:
            url = item.get("html_url") or item.get("url")
            if url and url not in seen:
                seen.add(url)
                out.append(item)
        return out

    def _fetch_and_detect_parallel(
        self,
        items:         List[Dict[str, Any]],
        target:        str,
        scope_targets: List[str],
        concurrency:   int = _FETCH_WORKERS,
    ) -> List[Dict[str, Any]]:
        """
        Fetch file contents, run detection, and classify ownership — in parallel.

        Key change vs. legacy: `target` is stored as `referenced_domain` (the
        search keyword that led to this file).  Actual target classification
        (first_party vs. third_party) is determined by OwnershipEngine, never
        by keyword presence.
        """
        findings: List[Dict[str, Any]] = []
        lock = threading.Lock()

        def _process_item(item: Dict[str, Any]) -> List[Dict[str, Any]]:
            file_url  = item.get("url")
            html_url  = item.get("html_url", "")
            repo      = item.get("repository", {})
            repo_name = repo.get("full_name", "unknown")
            repo_owner = repo_name.split("/")[0] if "/" in repo_name else repo_name

            # Scope filter (if scope file was provided)
            if scope_targets:
                hit = any(
                    s.lower() in repo_name.lower()
                    or s.lower() in item.get("path", "").lower()
                    for s in scope_targets
                )
                if not hit:
                    return []

            content = self.github.get_file_content(file_url)
            if not content:
                return []

            # Detect secrets — include raw value for live validation (Phase 5)
            local_findings = self.detector.scan_content(
                content, file_path=html_url, include_raw_value=True
            )

            # Determine ownership for every finding in this file
            party, confidence, reason = determine_ownership(
                repo_owner   = repo_owner,
                repo_full_name = repo_name,
                content      = content,
                target_domain= target,
                github_token = self._github_token,
            )

            # html_url is the file view URL; derive repo URL from it
            # e.g. https://github.com/owner/repo/blob/branch/path → https://github.com/owner/repo
            repo_url = html_url
            if html_url.startswith("https://github.com/"):
                parts = html_url.split("/")
                if len(parts) >= 5:
                    repo_url = "/".join(parts[:5])

            for f in local_findings:
                f["repo"]                 = repo_name
                f["repo_owner"]           = repo_owner
                f["repo_url"]             = repo_url
                f["file_url"]             = html_url
                f["referenced_domain"]    = target          # keyword that found this
                f["ownership_party"]      = party           # first_party | third_party
                f["ownership_confidence"] = confidence      # HIGH | MEDIUM | LOW
                f["ownership_reason"]     = reason          # human-readable label

            return local_findings

        with ThreadPoolExecutor(max_workers=concurrency) as pool:
            futures = {pool.submit(_process_item, item): item for item in items}
            for fut in as_completed(futures):
                try:
                    batch = fut.result()
                    with lock:
                        findings.extend(batch)
                except Exception as exc:
                    self._record_error("fetch_detect", str(exc))

        return findings

    def _fingerprint(self, finding: Dict[str, Any]) -> str:
        key = ":".join([
            finding.get("value_hash", ""),
            finding.get("repo", ""),
            finding.get("file_url", ""),
        ])
        return hashlib.sha256(key.encode()).hexdigest()

    def _dedup_findings(self, findings: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        unique = []
        with self._dedup_lock:
            for f in findings:
                fp = self._fingerprint(f)
                if fp not in self._seen_fps:
                    self._seen_fps[fp] = True
                    f["fingerprint"] = fp
                    unique.append(f)
        return unique

    def _score_all(self, findings: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """
        Live-validate then score each finding.
        _raw_value is consumed here; caller strips it immediately after this returns.
        """
        out = []
        for f in findings:
            try:
                f = self.validation_engine.validate(f)   # live validation
                f = self.scorer.score(f)                 # ownership-aware severity
            except Exception as exc:
                self._record_error("scoring", f"{f.get('type')}: {exc}")
            out.append(f)
        return out

    def _validate_all(self, findings: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        out = []
        for f in findings:
            try:
                if f.get("confidence", 0) > _AI_CONFIDENCE_MIN:
                    f = self.validator.validate(f)
                else:
                    f = self.validator._heuristic_enrich(
                        f, reason="Confidence below AI threshold"
                    )
            except Exception as exc:
                self._record_error("ai_validation", f"{f.get('type')}: {exc}")
                f.setdefault("ai_validated", False)
            out.append(f)
        return out

    # ── Correlation engine ─────────────────────────────────────────────────────

    def _correlate(self, findings: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """
        Detect secrets reused across multiple repos or assets.
        Boost severity and blast_radius when cross-asset reuse is detected.
        Correlation key: (secret_type, value_hash) — same actual credential.
        """
        repos_map:  Dict[str, set] = {}
        assets_map: Dict[str, set] = {}

        for f in findings:
            key = f"{f.get('type','?')}::{f.get('value_hash','')}"
            repos_map.setdefault(key, set()).add(f.get("repo", ""))
            repo_owner = f.get("repo_owner", "")
            assets_map.setdefault(key, set()).add(repo_owner or f.get("repo", "").split("/")[0])

        _SEV_ORDER = ["low", "medium", "high", "critical"]
        for f in findings:
            key         = f"{f.get('type','?')}::{f.get('value_hash','')}"
            repo_count  = len(repos_map.get(key, set()))
            asset_count = len(assets_map.get(key, set()))

            if repo_count >= 2 or asset_count >= 2:
                f["cross_asset_reuse"]  = True
                f["reuse_repo_count"]   = repo_count
                f["reuse_asset_count"]  = asset_count

                cur_sev = f.get("severity", "low").lower()
                idx     = _SEV_ORDER.index(cur_sev) if cur_sev in _SEV_ORDER else 0
                f["severity"] = _SEV_ORDER[min(idx + 1, len(_SEV_ORDER) - 1)]

                br_order = ["LOW", "MEDIUM", "HIGH", "CRITICAL"]
                cur_br   = f.get("blast_radius", "LOW").upper()
                br_idx   = br_order.index(cur_br) if cur_br in br_order else 0
                f["blast_radius"] = br_order[min(br_idx + 1, len(br_order) - 1)]

                f["confidence"] = min(1.0, f.get("confidence", 0.5) + 0.1)
                logger.info(
                    "Correlation boost: %s reused in %d repos / %d assets → severity=%s",
                    key[:40], repo_count, asset_count, f["severity"],
                )
            else:
                f.setdefault("cross_asset_reuse", False)

        return findings

    # ── Impact simulation ──────────────────────────────────────────────────────

    def _add_impact_scenarios(
        self, findings: List[Dict[str, Any]]
    ) -> List[Dict[str, Any]]:
        for f in findings:
            stype     = f.get("type", "generic_api_key")
            scenarios = list(_IMPACT_SCENARIOS.get(stype, _DEFAULT_IMPACT_SCENARIOS))
            if f.get("cross_asset_reuse"):
                scenarios.append(
                    f"ESCALATED: Same credential found in "
                    f"{f.get('reuse_repo_count', '?')} repositories — potential "
                    f"widespread breach if rotated credential was not invalidated everywhere."
                )
            # Ownership-specific escalation note
            if f.get("ownership_party") == "first_party":
                scenarios.append(
                    "FIRST-PARTY: This credential was found in a repository directly "
                    "owned by the target organisation."
                )
            f["impact_scenarios"] = scenarios
        return findings

    # ── Ingestion ──────────────────────────────────────────────────────────────

    def _ingest_findings(self, findings: List[Dict[str, Any]], target: str) -> None:
        """
        Persist findings to the ingestion engine.
        _raw_value is guaranteed to have been stripped before this call.
        """
        try:
            from oneinfinity.findings.result_ingestion_engine import get_ingestion_engine
            engine  = get_ingestion_engine()
            scan_id = str(uuid.uuid4())[:8]
            for f in findings:
                # Safety assertion — _raw_value must NEVER reach persistence
                assert "_raw_value" not in f, (
                    "BUG: _raw_value present in finding during ingestion. "
                    "Strip it in Phase 5."
                )
                normalized = {
                    "finding_id":            f["finding_id"],
                    "scan_id":               scan_id,
                    "target":                target,           # scan domain
                    "referenced_domain":     f.get("referenced_domain", target),
                    "ownership_party":       f.get("ownership_party", "unknown"),
                    "ownership_confidence":  f.get("ownership_confidence", "LOW"),
                    "ownership_reason":      f.get("ownership_reason", ""),
                    "repo_owner":            f.get("repo_owner", ""),
                    "repo_url":              f.get("repo_url", ""),
                    "live_verified":         f.get("live_verified", False),
                    "validation_type":       f.get("validation_type", ""),
                    "title":                 (
                        f"Exposed {f['type']} in "
                        f"{f.get('repo', 'unknown')} "
                        f"[{f.get('ownership_party','unknown')}]"
                    ),
                    "severity":              f["severity"],
                    "vuln_type":             "exposed_secret",
                    "evidence":              (
                        f"File: {f.get('file_url','?')}\n"
                        f"Line: {f.get('line_number','?')}\n"
                        f"Entropy: {f.get('entropy',0):.2f}\n"
                        f"Ownership: {f.get('ownership_party')} "
                        f"[{f.get('ownership_confidence')}] "
                        f"({f.get('ownership_reason')})\n"
                        f"Live verified: {f.get('live_verified')}\n"
                        f"Cross-asset reuse: {f.get('cross_asset_reuse', False)}\n\n"
                        f"Snippet:\n{f.get('snippet','')}"
                    ),
                    "payload":   f.get("value_preview", ""),
                    "url":       f.get("file_url", ""),
                    "tool":      "SecretIntelAgent",
                    "confidence": f.get("confidence", 0.5),
                    "status":    "new",
                    "created_at": f.get("timestamp", ""),
                    "raw":       f,
                }
                engine.persist_finding(normalized)
            logger.info("Ingested %d findings.", len(findings))
        except Exception as exc:
            self._record_error("ingestion", str(exc))
            logger.error("Ingestion failed: %s", exc)

    # ── Summary ────────────────────────────────────────────────────────────────

    def _generate_summary(
        self,
        findings:   List[Dict[str, Any]],
        run_id:     str,
        elapsed_ms: int,
    ) -> Dict[str, Any]:
        sev_counts = {"critical": 0, "high": 0, "medium": 0, "low": 0}
        for f in findings:
            sev = f.get("severity", "low").lower()
            if sev in sev_counts:
                sev_counts[sev] += 1

        first_party_count = sum(
            1 for f in findings if f.get("ownership_party") == "first_party"
        )
        third_party_count = sum(
            1 for f in findings if f.get("ownership_party") == "third_party"
        )
        live_verified_count = sum(1 for f in findings if f.get("live_verified"))

        return {
            "status":              "completed",
            "run_id":              run_id,
            "elapsed_ms":          elapsed_ms,
            "early_exit":          self._critical_found.is_set(),
            "total_findings":      len(findings),
            "severity_breakdown":  sev_counts,
            "ownership_breakdown": {
                "first_party": first_party_count,
                "third_party": third_party_count,
            },
            "live_verified_count": live_verified_count,
            "high_severity_secrets": [
                f for f in findings if f.get("severity") in ("critical", "high")
            ],
            "cross_asset_reuse_count": sum(
                1 for f in findings if f.get("cross_asset_reuse")
            ),
            "ai_validation_summary": {
                "total_validated": sum(
                    1 for f in findings if f.get("ai_validated")
                ),
                "false_positives_filtered": sum(
                    1 for f in findings
                    if f.get("ai_validated") and not f.get("ai_is_real", True)
                ),
            },
            "org_graph_summary":    self.org_graph.summary(),
            "github_client_status": self.github.status(),
            "phase_timings_ms":     {
                k: round(v * 1000, 1) for k, v in self._timings.items()
            },
            "errors":   self._errors,
            "findings": findings,
        }

    # ── Observability helpers ──────────────────────────────────────────────────

    def _timed_phase(self, phase_name: str, fn, *args, **kwargs):
        t0 = time.monotonic()
        try:
            result  = fn(*args, **kwargs)
            elapsed = time.monotonic() - t0
            self._timings[phase_name] = elapsed
            logger.debug("[timing] %s=%.3fs", phase_name, elapsed)
            return result
        except Exception as exc:
            elapsed = time.monotonic() - t0
            self._timings[phase_name] = elapsed
            self._record_error(phase_name, str(exc))
            logger.error("[%s] FAILED after %.3fs: %s", phase_name, elapsed, exc)
            raise

    def _record_error(self, phase: str, detail: str) -> None:
        self._errors.append({
            "phase":     phase,
            "detail":    detail,
            "timestamp": datetime.utcnow().isoformat(),
        })

    def _parse_scope(self, scope_file: str) -> List[str]:
        return self._load_scope(scope_file)
