"""
Advanced GitHub Dorks for Bug Bounty
====================================
Based on InfoSec Writeups article: GitHub Recon techniques
https://infosecwriteups.com/github-recon-the-underrated-technique-to-discover-high-impact-leaks-in-bug-bounty-c4069894389a

Provides comprehensive GitHub search dorks for finding leaks.
"""

from typing import List, Dict, Tuple

# High-value keywords for secrets
KEYWORDS = {
    "authentication": [
        "api_key", "apikey", "api-key", "api key",
        "access_token", "accessToken", "access-token",
        "client_secret", "clientSecret", "client-secret",
        "auth_token", "authToken", "auth-token",
        "SECRET_KEY", "secret_key", "secret key",
        "credentials", "credential",
        "bearer_token", "bearer token",
    ],

    "cloud_providers": [
        "AWS_SECRET_ACCESS_KEY", "aws_secret_access_key",
        "AWS_ACCESS_KEY_ID", "aws_access_key_id",
        "GCP_SECRET", "gcp_secret",
        "AZURE_CLIENT_SECRET", "azure_client_secret",
        "firebase_url", "firebase_api_key",
        "shodan_api_key",
        "digitalocean_token",
    ],

    "database": [
        "DB_PASSWORD", "db_password", "database_password",
        "DATABASE_URL", "database_url",
        "MYSQL_PASSWORD", "mysql_password",
        "POSTGRES_PASSWORD", "postgres_password",
        "MONGODB_URI", "mongo_uri", "mongodb_uri",
        "REDIS_PASSWORD", "redis_password",
    ],

    "private_keys": [
        "BEGIN RSA PRIVATE KEY",
        "BEGIN OPENSSH PRIVATE KEY",
        "BEGIN EC PRIVATE KEY",
        "BEGIN PGP PRIVATE KEY",
        "id_rsa",
        "private_key",
        "privateKey",
    ],

    "service_tokens": [
        "slack_token", "slack_webhook",
        "discord_token", "discord_webhook",
        "github_token", "github_pat",
        "twilio_auth_token", "twilio_account_sid",
        "stripe_secret", "stripe_api_key",
        "sendgrid_api_key",
        "mailgun_api_key",
        "openai_api_key",
        "anthropic_api_key",
    ],
}


def generate_basic_dorks(domain: str) -> List[str]:
    """Generate basic GitHub dorks for domain."""
    return [
        f'"{domain}" password',
        f'"{domain}" api_key',
        f'"{domain}" secret',
        f'"{domain}" token',
        f'"{domain}" credentials',
        f'"{domain}" aws_access_key',
        f'"{domain}" private_key',
    ]


def generate_json_format_dorks(domain: str) -> List[str]:
    """Generate JSON-formatted key-value dorks."""
    return [
        f'"{domain}" "password":',
        f'"{domain}" "api_key":',
        f'"{domain}" "secret":',
        f'"{domain}" "token":',
        f'"{domain}" "access_token":',
        f'"{domain}" "client_secret":',
        f'"{domain}" "private_key":',
    ]


def generate_org_dorks(org: str) -> List[str]:
    """Generate organization-specific dorks."""
    return [
        f'org:{org} "password":',
        f'org:{org} "api_key":',
        f'org:{org} "secret":',
        f'org:{org} "access_token":',
        f'org:{org} "AWS_SECRET_ACCESS_KEY"',
        f'org:{org} "BEGIN RSA PRIVATE KEY"',
    ]


def generate_advanced_combined_dorks(domain: str) -> List[str]:
    """Generate advanced combined dorks with operators."""
    return [
        f'"{domain}" AND ("api_key" OR "secret" OR "password" OR "access_token" OR "client_secret")',
        f'"{domain}" AND ("AWS_SECRET_ACCESS_KEY" OR "AWS_ACCESS_KEY_ID")',
        f'"{domain}" AND ("BEGIN RSA PRIVATE KEY" OR "BEGIN OPENSSH PRIVATE KEY")',
        f'"{domain}" AND ("DB_PASSWORD" OR "DATABASE_URL" OR "MYSQL_PASSWORD")',
        f'"{domain}" AND ("stripe_secret" OR "stripe_api_key")',
        f'"{domain}" AND ("slack_token" OR "slack_webhook")',
        f'"{domain}" AND ("firebase_url" OR "firebase_api_key")',
    ]


def generate_filtered_dorks(domain: str) -> List[str]:
    """Generate dorks with GitHub search filters."""
    return [
        # .env files
        f'filename:.env "{domain}"',
        f'filename:.env "DB_PASSWORD"',
        f'path:**/.env "{domain}"',

        # Config files
        f'extension:json "{domain}" "access_token"',
        f'extension:yaml "{domain}" "secret"',
        f'extension:yml "{domain}" "password"',
        f'path:/config filename:database.php "{domain}"',
        f'path:/config "{domain}" password',

        # Language-specific
        f'"{domain}" language:PHP password',
        f'"{domain}" language:Python "api_key"',
        f'"{domain}" language:JavaScript "token"',
        f'"{domain}" language:Ruby "secret"',

        # Private keys
        f'filename:id_rsa "{domain}"',
        f'extension:pem "{domain}"',
        f'filename:private_key "{domain}"',

        # Cloud configs
        f'filename:credentials "{domain}"',
        f'filename:.aws/credentials',
        f'filename:.boto',
        f'filename:client_secret.json "{domain}"',
    ]


def generate_all_dorks(domain: str, org: str = None) -> Dict[str, List[str]]:
    """Generate all types of dorks for comprehensive search."""
    dorks = {
        "basic": generate_basic_dorks(domain),
        "json_format": generate_json_format_dorks(domain),
        "advanced_combined": generate_advanced_combined_dorks(domain),
        "filtered": generate_filtered_dorks(domain),
    }

    if org:
        dorks["org_specific"] = generate_org_dorks(org)

    return dorks


def get_high_priority_dorks(domain: str, org: str = None) -> List[Tuple[str, int]]:
    """
    Get prioritized list of dorks with confidence scores.
    Returns: List[(dork, priority_score)] where higher score = higher priority
    """
    dorks = []

    # High priority: Combined filters + high-value keywords (score: 10)
    dorks.extend([
        (f'filename:.env "{domain}" "DB_PASSWORD"', 10),
        (f'extension:json "{domain}" "access_token"', 10),
        (f'"{domain}" AND ("AWS_SECRET_ACCESS_KEY" OR "AWS_ACCESS_KEY_ID")', 10),
        (f'filename:id_rsa "{domain}"', 10),
        (f'org:{org} "BEGIN RSA PRIVATE KEY"', 10) if org else None,
    ])

    # Medium priority: Specific patterns (score: 7-8)
    dorks.extend([
        (f'"{domain}" "password":', 8),
        (f'"{domain}" "api_key":', 8),
        (f'path:/config "{domain}" password', 7),
        (f'filename:.aws/credentials "{domain}"', 7),
        (f'extension:pem "{domain}"', 7),
    ])

    # Lower priority: Broad searches (score: 5)
    dorks.extend([
        (f'"{domain}" password', 5),
        (f'"{domain}" secret', 5),
        (f'"{domain}" api_key', 5),
    ])

    # Remove None entries
    dorks = [d for d in dorks if d is not None]

    # Sort by priority (descending)
    dorks.sort(key=lambda x: x[1], reverse=True)

    return dorks


# Exposed .git directory check patterns
GIT_EXPOSURE_PATTERNS = [
    "/.git/",
    "/.git/config",
    "/.git/HEAD",
    "/.git/index",
    "/.git/logs/",
]


# File extensions to prioritize in scans
HIGH_VALUE_EXTENSIONS = [
    ".env",
    ".json",
    ".yaml", ".yml",
    ".xml",
    ".conf", ".config",
    ".properties",
    ".ini",
    ".pem",
    ".key",
    ".p12", ".pfx",
    ".sql",
    ".backup",
]


# Paths commonly containing secrets
HIGH_VALUE_PATHS = [
    "/config/",
    "/.aws/",
    "/.ssh/",
    "/credentials/",
    "/secrets/",
    "/keys/",
    "/backup/",
    "/old/",
    "/test/",
    "/dev/",
]
