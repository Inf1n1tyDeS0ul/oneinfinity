"""
DorkEngine — prioritised GitHub search query generator.

Each dork has a signal score (1–10) reflecting the expected severity and
probability of finding a real, exploitable secret.  The engine returns queries
sorted highest-signal-first so that the most valuable dorks are executed within
any API-budget constraint.

Score scale:
  10  Direct cloud/infra access: AWS keys, private keys
   9  Code repo compromise: GitHub PATs, GCP creds, env files
   8  DB connection strings, payment keys, secret files
   7  High-value SaaS: Stripe restricted, Twilio, SendGrid, OpenAI
   6  Communication/identity: Slack, Firebase server keys
   5  General database passwords, JDBC URLs
   4  Broad config files: docker-compose, kubeconfig
   3  Generic analytics/monitoring API keys
   2  Generic keyword matches (password=, token=)
   1  Low-signal broad matches (very noisy)
"""

import logging
from dataclasses import dataclass
from typing import Dict, List, Tuple

logger = logging.getLogger(__name__)


@dataclass(frozen=True)
class Dork:
    keyword:  str
    score:    int       # 1–10, higher = more likely to find exploitable secret
    category: str       # label for observability / filtering


# ── Dork registry (keyword, signal score, category) ──────────────────────────
_REGISTRY: List[Dork] = [

    # ── Score 10: Direct cloud / infra compromise ─────────────────────────────
    Dork("aws_access_key_id",              10, "cloud"),
    Dork("aws_secret_access_key",          10, "cloud"),
    Dork("BEGIN RSA PRIVATE KEY",          10, "private_key"),
    Dork("BEGIN OPENSSH PRIVATE KEY",      10, "private_key"),
    Dork("BEGIN EC PRIVATE KEY",           10, "private_key"),
    Dork("BEGIN DSA PRIVATE KEY",          10, "private_key"),
    Dork("BEGIN PGP PRIVATE KEY BLOCK",    10, "private_key"),
    Dork("BEGIN ENCRYPTED PRIVATE KEY",    10, "private_key"),
    Dork("BEGIN PRIVATE KEY",              10, "private_key"),
    Dork("filename:id_rsa",                10, "private_key"),
    Dork("filename:id_dsa",                10, "private_key"),
    Dork("filename:id_ecdsa",              10, "private_key"),

    # ── Score 9: Repo / pipeline compromise ───────────────────────────────────
    Dork("github_pat",                      9, "vcs"),
    Dork("personal_access_token",           9, "vcs"),
    Dork("github_token",                    9, "vcs"),
    Dork("gitlab_token",                    9, "vcs"),
    Dork("gcp_credentials",                 9, "cloud"),
    Dork("google_application_credentials",  9, "cloud"),
    Dork("filename:.env",                   9, "config_file"),
    Dork("filename:.env.production",        9, "config_file"),
    Dork("filename:.env.staging",           9, "config_file"),
    Dork("filename:credentials.json",       9, "config_file"),
    Dork("filename:aws_credentials",        9, "config_file"),
    Dork("filename:gcp_credentials.json",   9, "config_file"),

    # ── Score 8: DB connection strings + payment keys ─────────────────────────
    Dork("stripe_api_key",                  8, "payment"),
    Dork("mongodb_uri",                     8, "database"),
    Dork("postgres_uri",                    8, "database"),
    Dork("mysql_uri",                       8, "database"),
    Dork("redis_uri",                       8, "database"),
    Dork("database_url",                    8, "database"),
    Dork("connection_string",               8, "database"),
    Dork("filename:secrets.json",           8, "config_file"),
    Dork("filename:secrets.yml",            8, "config_file"),
    Dork("filename:secrets.yaml",           8, "config_file"),
    Dork("filename:.env.development",       8, "config_file"),
    Dork("filename:.env.local",             8, "config_file"),

    # ── Score 7: High-value SaaS keys ─────────────────────────────────────────
    Dork("stripe_restricted",               7, "payment"),
    Dork("twilio_api_key",                  7, "communication"),
    Dork("sendgrid_api_key",                7, "communication"),
    Dork("openai_api_key",                  7, "ai"),
    Dork("azure_storage_key",               7, "cloud"),
    Dork("azure_storage_account",           7, "cloud"),
    Dork("firebase_api_key",                7, "cloud"),
    Dork("heroku_api_key",                  7, "devops"),
    Dork("filename:credentials.yml",        7, "config_file"),
    Dork("filename:credentials.yaml",       7, "config_file"),
    Dork("filename:database.yml",           7, "config_file"),
    Dork("filename:database.yaml",          7, "config_file"),

    # ── Score 6: Communication / identity ─────────────────────────────────────
    Dork("slack_token",                     6, "communication"),
    Dork("discord_token",                   6, "communication"),
    Dork("bot_token",                       6, "communication"),
    Dork("firebase_server_key",             6, "cloud"),
    Dork("mailgun_api_key",                 6, "communication"),
    Dork("private_token",                   6, "auth"),
    Dork("auth_token",                      6, "auth"),
    Dork("access_token",                    6, "auth"),
    Dork("client_secret",                   6, "auth"),

    # ── Score 5: General database passwords ───────────────────────────────────
    Dork("db_password",                     5, "database"),
    Dork("database_password",               5, "database"),
    Dork("postgres_password",               5, "database"),
    Dork("redis_password",                  5, "database"),
    Dork("mongo_password",                  5, "database"),
    Dork("mysql_pwd",                       5, "database"),
    Dork("jdbc_url",                        5, "database"),
    Dork("db_connection",                   5, "database"),
    Dork("sql_password",                    5, "database"),

    # ── Score 4: Broad config files / infra ───────────────────────────────────
    Dork("filename:docker-compose.yml",     4, "devops"),
    Dork("filename:docker-compose.yaml",    4, "devops"),
    Dork("filename:kubeconfig",             4, "devops"),
    Dork("filename:config.json",            4, "config_file"),
    Dork("filename:config.yml",             4, "config_file"),
    Dork("filename:appsettings.json",       4, "config_file"),
    Dork("filename:wp-config.php",          4, "config_file"),
    Dork("filename:configuration.php",      4, "config_file"),
    Dork("filename:settings.json",          4, "config_file"),
    Dork("filename:settings.yml",           4, "config_file"),
    Dork("filename:keystore",               4, "private_key"),
    Dork("filename:client.ovpn",            4, "private_key"),
    Dork("filename:ca.crt",                 4, "private_key"),
    Dork("filename:client.crt",             4, "private_key"),

    # ── Score 3: Monitoring / analytics API keys ──────────────────────────────
    Dork("datadog_api_key",                 3, "monitoring"),
    Dork("newrelic_api_key",                3, "monitoring"),
    Dork("sentry_api_key",                  3, "monitoring"),
    Dork("algolia_api_key",                 3, "analytics"),
    Dork("mapbox_api_key",                  3, "analytics"),
    Dork("pagerduty_api_key",               3, "monitoring"),
    Dork("rollbar_api_key",                 3, "monitoring"),
    Dork("splunk_api_key",                  3, "monitoring"),
    Dork("segment_api_key",                 3, "analytics"),
    Dork("amplitude_api_key",               3, "analytics"),
    Dork("intercom_api_key",                3, "analytics"),
    Dork("launchdarkly_api_key",            3, "analytics"),
    Dork("posthog_api_key",                 3, "analytics"),
    Dork("mixpanel_api_key",                3, "analytics"),

    # ── Score 2: Generic keyword assignments ──────────────────────────────────
    Dork("\"api_key=\"",                    2, "generic"),
    Dork("\"apikey=\"",                     2, "generic"),
    Dork("\"secret_key=\"",                 2, "generic"),
    Dork("\"client_secret=\"",              2, "generic"),
    Dork("\"access_token=\"",               2, "generic"),
    Dork("\"password=\"",                   2, "generic"),
    Dork("\"passwd=\"",                     2, "generic"),
    Dork("\"token=\"",                      2, "generic"),
    Dork("\"auth=\"",                       2, "generic"),
    Dork("\"credentials=\"",               2, "generic"),
    Dork("api_key",                         2, "generic"),
    Dork("apikey",                          2, "generic"),
    Dork("secret_key",                      2, "generic"),

    # ── Score 1: Very broad / high-noise terms ────────────────────────────────
    Dork("password",                        1, "generic"),
    Dork("passwd",                          1, "generic"),
    Dork("pwd",                             1, "generic"),
    Dork("db_user",                         1, "generic"),
    Dork("db_username",                     1, "generic"),
    Dork("oracle_password",                 1, "database"),
    Dork("cassandra_password",              1, "database"),
    Dork("mariadb_password",                1, "database"),
    Dork("hotjar_api_key",                  1, "analytics"),
    Dork("crazyegg_api_key",                1, "analytics"),
    Dork("vwo_api_key",                     1, "analytics"),
    Dork("fullstory_api_key",               1, "analytics"),
    Dork("heap_api_key",                    1, "analytics"),
    Dork("kissmetrics_api_key",             1, "analytics"),
    Dork("clevertap_api_key",               1, "analytics"),
    Dork("split_api_key",                   1, "analytics"),
    Dork("appdynamics_api_key",             1, "monitoring"),
    Dork("sumologic_api_key",               1, "monitoring"),
    Dork("logdna_api_key",                  1, "monitoring"),
    Dork("papertrail_api_key",              1, "monitoring"),
    Dork("optimizely_api_key",              1, "analytics"),
    Dork("filename:truststore",             1, "private_key"),
    Dork("filename:server.ovpn",            1, "private_key"),
    Dork("BEGIN CERTIFICATE",               1, "private_key"),
]

# Sort descending by score at module load time — O(n log n) once
_REGISTRY_SORTED: List[Dork] = sorted(_REGISTRY, key=lambda d: d.score, reverse=True)


class DorkGenerator:
    """
    Generates GitHub code-search queries for a target, ordered by signal score.

    All public methods return lists ordered highest-priority first so callers
    can slice to any budget (top-5, top-20, etc.) and still get the best value.
    """

    def __init__(self):
        logger.debug("DorkGenerator: %d dorks in registry.", len(_REGISTRY_SORTED))

    # ── Primary API ───────────────────────────────────────────────────────────

    def generate(self, target: str) -> List[str]:
        """
        Return all queries sorted by signal score (highest first).

        Equivalent to generate_prioritized() without the scores — drop-in
        replacement for callers that just need a flat list.
        """
        return [q for _, q in self.generate_prioritized(target)]

    def generate_prioritized(self, target: str) -> List[Tuple[int, str]]:
        """
        Return ``(score, query)`` tuples, sorted by score descending.

        The caller can:
          - Take the top N: ``pairs[:10]``
          - Filter by minimum score: ``[(s,q) for s,q in pairs if s >= 7]``
          - Filter by category: use ``generate_by_category()``
        """
        target_str = f'"{target}"'
        pairs: List[Tuple[int, str]] = []

        for dork in _REGISTRY_SORTED:
            query = f"{target_str} {dork.keyword}"
            pairs.append((dork.score, query))

        return pairs

    def generate_by_category(
        self, target: str, categories: List[str]
    ) -> List[Tuple[int, str]]:
        """
        Return prioritised queries for the specified categories only.

        Example: generate_by_category("acme.com", ["cloud", "database"])
        """
        cats = {c.lower() for c in categories}
        target_str = f'"{target}"'
        pairs = []
        for dork in _REGISTRY_SORTED:
            if dork.category.lower() in cats:
                pairs.append((dork.score, f"{target_str} {dork.keyword}"))
        return pairs

    def generate_above_score(
        self, target: str, min_score: int
    ) -> List[Tuple[int, str]]:
        """
        Return only queries with signal score >= *min_score*.
        Useful for quick high-confidence-only scans.
        """
        target_str = f'"{target}"'
        return [
            (dork.score, f"{target_str} {dork.keyword}")
            for dork in _REGISTRY_SORTED
            if dork.score >= min_score
        ]

    # ── Diagnostics ───────────────────────────────────────────────────────────

    def score_distribution(self) -> Dict[int, int]:
        """Return {score: count} histogram for the dork registry."""
        dist: Dict[int, int] = {}
        for dork in _REGISTRY_SORTED:
            dist[dork.score] = dist.get(dork.score, 0) + 1
        return dict(sorted(dist.items(), reverse=True))

    def __len__(self) -> int:
        return len(_REGISTRY_SORTED)
