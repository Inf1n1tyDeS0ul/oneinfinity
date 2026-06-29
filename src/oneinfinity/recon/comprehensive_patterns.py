"""
Comprehensive patterns for GitHub OSINT
========================================
All sensitive patterns for bug bounty reconnaissance.
"""

import re
from typing import List, Tuple

# Format: (pattern, name, severity, category)
COMPREHENSIVE_PATTERNS: List[Tuple[str, str, str, str]] = [
    # ============= AWS =============
    (r'(?:A3T[A-Z0-9]|AKIA|AGPA|AIDA|AROA|AIPA|ANPA|ANVA|ASIA)[A-Z0-9]{16}', "aws_access_key_id", "critical", "cloud"),
    (r'(?i)aws.{0,20}?["\']([0-9a-zA-Z/+]{40})["\']', "aws_secret_key", "critical", "cloud"),
    (r'amzn\.mws\.[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}', "aws_mws_key", "critical", "cloud"),

    # ============= GCP =============
    (r'AIza[0-9A-Za-z_\-]{35}', "gcp_api_key", "high", "cloud"),
    (r'"type":\s*"service_account"', "gcp_service_account", "critical", "cloud"),
    (r'"project_id":\s*"([a-z0-9-]+)"', "gcp_project_id", "medium", "cloud"),
    (r'"private_key":\s*"-----BEGIN PRIVATE KEY-----', "gcp_private_key", "critical", "cloud"),

    # ============= Azure =============
    (r'[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}', "azure_subscription_id", "medium", "cloud"),
    (r'(?i)(?:azure|az).{0,20}?["\']([a-zA-Z0-9+/=]{44})["\']', "azure_storage_key", "critical", "cloud"),

    # ============= GitHub =============
    (r'ghp_[A-Za-z0-9]{36,}', "github_personal_token", "critical", "vcs"),
    (r'gho_[A-Za-z0-9]{36,}', "github_oauth_token", "critical", "vcs"),
    (r'ghu_[A-Za-z0-9]{36,}', "github_user_token", "critical", "vcs"),
    (r'ghs_[A-Za-z0-9]{36,}', "github_server_token", "critical", "vcs"),
    (r'ghr_[A-Za-z0-9]{36,}', "github_refresh_token", "critical", "vcs"),
    (r'github_pat_[A-Za-z0-9_]{82}', "github_fine_grained_pat", "critical", "vcs"),

    # ============= GitLab =============
    (r'glpat-[0-9a-zA-Z_\-]{20}', "gitlab_pat", "critical", "vcs"),

    # ============= OpenAI =============
    (r'sk-[A-Za-z0-9]{48}', "openai_api_key", "critical", "api"),
    (r'sk-proj-[A-Za-z0-9_-]{48,}', "openai_project_key", "critical", "api"),

    # ============= Anthropic =============
    (r'sk-ant-[A-Za-z0-9_\-]{95,}', "anthropic_api_key", "critical", "api"),

    # ============= Stripe =============
    (r'sk_live_[0-9a-zA-Z]{24,}', "stripe_live_secret", "critical", "payment"),
    (r'sk_test_[0-9a-zA-Z]{24,}', "stripe_test_secret", "high", "payment"),
    (r'rk_live_[0-9a-zA-Z]{24,}', "stripe_live_restricted", "critical", "payment"),
    (r'pk_live_[0-9a-zA-Z]{24,}', "stripe_live_public", "medium", "payment"),

    # ============= PayPal =============
    (r'(?i)paypal.{0,30}?["\'][A-Za-z0-9_\-]{80,}["\']', "paypal_client_secret", "critical", "payment"),

    # ============= Square =============
    (r'sq0csp-[0-9A-Za-z_\-]{43}', "square_access_token", "critical", "payment"),
    (r'sq0atp-[0-9A-Za-z_\-]{22}', "square_oauth_secret", "critical", "payment"),

    # ============= SendGrid =============
    (r'SG\.[a-zA-Z0-9_\-]{22}\.[a-zA-Z0-9_\-]{43}', "sendgrid_api_key", "critical", "api"),

    # ============= Twilio =============
    (r'SK[0-9a-fA-F]{32}', "twilio_api_key", "critical", "api"),
    (r'AC[0-9a-fA-F]{32}', "twilio_account_sid", "high", "api"),

    # ============= Slack =============
    (r'xox[baprs]-[0-9]{10,13}-[0-9]{10,13}-[a-zA-Z0-9]{24,}', "slack_token", "critical", "api"),
    (r'https://hooks\.slack\.com/services/T[a-zA-Z0-9_]{8,}/B[a-zA-Z0-9_]{8,}/[a-zA-Z0-9_]{24}', "slack_webhook", "high", "api"),

    # ============= Mailgun =============
    (r'key-[0-9a-zA-Z]{32}', "mailgun_api_key", "high", "api"),

    # ============= MailChimp =============
    (r'[0-9a-f]{32}-us[0-9]{1,2}', "mailchimp_api_key", "high", "api"),

    # ============= NPM =============
    (r'npm_[a-zA-Z0-9]{36}', "npm_token", "critical", "registry"),

    # ============= PyPI =============
    (r'pypi-[A-Za-z0-9_-]{90,}', "pypi_token", "critical", "registry"),

    # ============= Docker Hub =============
    (r'dckr_pat_[a-zA-Z0-9_-]{36,}', "docker_pat", "high", "registry"),

    # ============= DigitalOcean =============
    (r'dop_v1_[a-f0-9]{64}', "digitalocean_token", "critical", "cloud"),

    # ============= Heroku =============
    (r'[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}', "heroku_api_key", "medium", "cloud"),

    # ============= Firebase =============
    (r'"apiKey":\s*"(AIza[0-9A-Za-z_\-]{35})"', "firebase_api_key", "high", "api"),
    (r'AAAA[A-Za-z0-9_\-]{100,}', "firebase_fcm", "high", "api"),

    # ============= JWT Tokens =============
    (r'eyJ[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}', "jwt_token", "high", "token"),

    # ============= Private Keys =============
    (r'-----BEGIN RSA PRIVATE KEY-----', "rsa_private_key", "critical", "crypto"),
    (r'-----BEGIN EC PRIVATE KEY-----', "ec_private_key", "critical", "crypto"),
    (r'-----BEGIN OPENSSH PRIVATE KEY-----', "openssh_private_key", "critical", "crypto"),
    (r'-----BEGIN PGP PRIVATE KEY BLOCK-----', "pgp_private_key", "critical", "crypto"),
    (r'-----BEGIN DSA PRIVATE KEY-----', "dsa_private_key", "critical", "crypto"),

    # ============= Database URIs =============
    (r'mongodb(?:\+srv)?://[^\s"\'<>]+', "mongodb_uri", "critical", "database"),
    (r'postgres(?:ql)?://[^\s"\'<>]+', "postgresql_uri", "critical", "database"),
    (r'mysql://[^\s"\'<>]+', "mysql_uri", "critical", "database"),
    (r'redis://[^\s"\'<>]+', "redis_uri", "high", "database"),
    (r'amqp://[^\s"\'<>]+', "rabbitmq_uri", "high", "database"),

    # ============= Hardcoded Credentials =============
    (r'(?i)password\s*=\s*["\']([^"\']{6,})["\']', "hardcoded_password", "critical", "credential"),
    (r'(?i)passwd\s*=\s*["\']([^"\']{6,})["\']', "hardcoded_passwd", "critical", "credential"),
    (r'(?i)pwd\s*=\s*["\']([^"\']{6,})["\']', "hardcoded_pwd", "critical", "credential"),
    (r'(?i)api[_-]?key\s*=\s*["\']([A-Za-z0-9_\-]{16,})["\']', "api_key", "high", "credential"),
    (r'(?i)api[_-]?secret\s*=\s*["\']([A-Za-z0-9_\-]{16,})["\']', "api_secret", "high", "credential"),

    # ============= S3 Buckets =============
    (r's3://[a-z0-9.-]+', "s3_bucket_url", "medium", "infra"),
    (r'[a-z0-9.-]+\.s3\.amazonaws\.com', "s3_bucket_domain", "medium", "infra"),
    (r'[a-z0-9.-]+\.s3-[a-z0-9-]+\.amazonaws\.com', "s3_regional_bucket", "medium", "infra"),

    # ============= Internal/Staging Domains =============
    (r'(?:https?://)?(?:dev|staging|test|internal|admin|api|backend)[.-][a-z0-9.-]+\.[a-z]{2,}', "internal_domain", "medium", "infra"),
    (r'(?:https?://)?[a-z0-9.-]+\.(?:local|internal|corp|dev|staging)[:\s]', "internal_tld", "medium", "infra"),

    # ============= Private IPs =============
    (r'10\.\d{1,3}\.\d{1,3}\.\d{1,3}', "private_ip_10", "low", "infra"),
    (r'172\.(?:1[6-9]|2[0-9]|3[01])\.\d{1,3}\.\d{1,3}', "private_ip_172", "low", "infra"),
    (r'192\.168\.\d{1,3}\.\d{1,3}', "private_ip_192", "low", "infra"),

    # ============= API Endpoints =============
    (r'(?:https?://)?[a-z0-9.-]+(?:/api/v[0-9]|/api)[a-z0-9/_-]+', "api_endpoint", "low", "infra"),

    # ============= Database Hosts =============
    (r'(?:db|database|postgres|mysql|mongo|redis)[.-][a-z0-9.-]+\.[a-z]{2,}', "database_host", "medium", "infra"),

    # ============= Google OAuth =============
    (r'ya29\.[0-9A-Za-z_\-]{60,}', "google_oauth_token", "critical", "token"),

    # ============= Auth Headers =============
    (r'(?i)authorization:\s*Bearer\s+([A-Za-z0-9_\-\.]{20,})', "bearer_token", "high", "token"),
    (r'(?i)authorization:\s*Basic\s+([A-Za-z0-9+/=]{20,})', "basic_auth", "high", "token"),

    # ============= Credit Cards (for testing) =============
    (r'\b(?:4[0-9]{12}(?:[0-9]{3})?|5[1-5][0-9]{14}|3[47][0-9]{13})\b', "potential_credit_card", "high", "pii"),

    # ============= SSN (US) =============
    (r'\b[0-9]{3}-[0-9]{2}-[0-9]{4}\b', "potential_ssn", "critical", "pii"),

    # ============= Generic Secrets =============
    (r'(?i)(?:secret|token)\s*=\s*["\']([A-Za-z0-9_\-]{16,})["\']', "generic_secret", "medium", "credential"),

    # ============= DATABASE_URL assignment =============
    (r'DATABASE_URL[\s]*=[\s]*["\']?(postgres|mysql|mongodb|redis)[a-zA-Z0-9+\-.]*://[^\s"\' ]+', "database_url", "critical", "database"),

    # ============= Terraform secrets =============
    (r'(?i)(secret|password|token|key)\s*=\s*"[^"]{8,}"', "terraform_secret", "high", "credential"),

    # ============= GitHub PAT (fine-grained, exact 36-char classic) =============
    (r'ghp_[a-zA-Z0-9]{36}', "github_pat", "critical", "vcs"),

    # ============= OpenAI key (exact 48-char) =============
    (r'sk-[a-zA-Z0-9]{48}', "openai_key", "critical", "api"),
]


def compile_patterns():
    """Compile all patterns."""
    return [
        (re.compile(pattern, re.MULTILINE | re.IGNORECASE), name, severity, category)
        for pattern, name, severity, category in COMPREHENSIVE_PATTERNS
    ]


COMPILED_PATTERNS = compile_patterns()
