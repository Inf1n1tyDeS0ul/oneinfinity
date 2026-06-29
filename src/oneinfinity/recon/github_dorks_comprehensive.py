"""
Comprehensive GitHub Dorks Collection
======================================
Combined from:
- TheBinitGhimire/GitHub-Recon
- techgaun/github-dorks
- random-robbie/keywords
- InfoSec Writeups article

Complete collection for bug bounty GitHub reconnaissance.
"""

from typing import List, Dict, Tuple

# File-based dorks (high priority)
FILE_DORKS = [
    # Authentication & Config Files
    ("filename:.npmrc _auth", "npm_registry_auth", 10),
    ("filename:.dockercfg auth", "docker_registry_auth", 10),
    ("filename:id_rsa OR filename:id_dsa", "ssh_private_keys", 10),
    ("filename:.git-credentials", "git_credentials", 10),
    ("filename:.netrc password", "netrc_credentials", 9),
    ("filename:_netrc password", "netrc_alt_credentials", 9),
    ("filename:hub oauth_token", "github_hub_token", 10),

    # Cloud Provider Configs
    ("filename:credentials aws_access_key_id", "aws_credentials_file", 10),
    ("filename:.s3cfg", "s3_config", 9),
    ("filename:.boto", "boto_config", 9),
    ("filename:.aws/credentials", "aws_creds_path", 10),

    # Environment Files
    ('filename:.env DB_USERNAME NOT homestead', "env_db_creds", 10),
    ('filename:.env MAIL_HOST=smtp.gmail.com', "env_smtp_config", 8),
    ('filename:.env "DB_PASSWORD"', "env_db_password", 10),
    ('filename:.env "API_KEY"', "env_api_key", 9),
    ('filename:.env "SECRET"', "env_secret", 9),

    # Shell History & RC Files
    ("filename:.bashrc password", "bashrc_password", 8),
    ("filename:.bashrc mailchimp", "bashrc_api_keys", 7),
    ("filename:.bash_profile aws", "bash_profile_aws", 8),
    ("filename:.bash_history", "bash_history", 7),
    ("filename:.zsh_history", "zsh_history", 7),
    ("filename:.sh_history", "sh_history", 7),

    # Database Configs
    ("filename:wp-config.php", "wordpress_config", 9),
    ("filename:config.php dbpasswd", "php_db_config", 9),
    ("filename:configuration.php JConfig password", "joomla_config", 9),
    ("path:sites databases password", "drupal_db_creds", 9),
    ("filename:.pgpass", "postgres_password_file", 9),
    ("filename:proftpdpasswd", "proftpd_passwords", 8),
    ("filename:robomongo.json", "mongodb_robomongo_creds", 9),

    # FTP/Network Configs
    ("filename:filezilla.xml Pass", "filezilla_passwords", 9),
    ("filename:recentservers.xml Pass", "filezilla_recent_servers", 9),
    ("filename:.tugboat NOT _tugboat", "digitalocean_tugboat", 8),
    ("filename:sshd_config", "openssh_server_config", 7),
    ("filename:dhcpd.conf", "dhcp_config", 6),

    # IDE & Development Tools
    ("filename:idea14.key", "intellij_license_key", 7),
    ("filename:WebServers.xml", "jetbrains_servers", 8),
    ("filename:config irc_pass", "irc_password", 7),

    # Server Configs
    ("filename:ventrilo_srv.ini", "ventrilo_config", 6),
    ("filename:server.cfg rcon password", "counterstrike_rcon", 7),
    ("filename:connections.xml", "db_connections_xml", 8),

    # Framework-Specific
    ("filename:prod.exs NOT prod.secret.exs", "phoenix_prod_config", 8),
    ("filename:prod.secret.exs", "phoenix_secrets", 9),
    ("filename:express.conf path:.openshift", "openshift_config", 7),

    # Docker
    ("filename:config.json auths", "docker_auths", 9),
    ("filename:docker-compose.yml", "docker_compose", 6),

    # System Files (Unix/Linux)
    ("filename:shadow path:etc", "unix_shadow_file", 10),
    ("filename:passwd path:etc", "unix_passwd_file", 9),
    ("filename:.htpasswd", "htpasswd_file", 8),
]

# Extension-based dorks
EXTENSION_DORKS = [
    ("extension:pem private", "pem_private_keys", 10),
    ("extension:ppk private", "putty_private_keys", 10),
    ("extension:key private", "generic_private_keys", 9),
    ("extension:pkcs12", "pkcs12_certificates", 9),
    ("extension:pfx", "pfx_certificates", 9),
    ("extension:p12", "p12_certificates", 9),
    ("extension:sql mysql dump", "mysql_dump", 8),
    ("extension:sql mysql dump password", "mysql_dump_passwords", 9),
    ("extension:json api.forecast.io", "forecast_api_keys", 7),
    ("extension:json mongolab.com", "mongolab_creds_json", 8),
    ("extension:yaml mongolab.com", "mongolab_creds_yaml", 8),
    ("extension:avastlic", "avast_license", 6),
]

# Keyword-based dorks (to combine with domain)
KEYWORD_DORKS = [
    "password",
    "api_key",
    "secret",
    "token",
    "access_token",
    "client_secret",
    "private_key",
    "aws_access_key_id",
    "aws_secret_access_key",
    "db_password",
    "database_password",
    "mysql_password",
    "postgres_password",
    "mongodb_uri",
    "redis_password",
    "jwt_secret",
    "session_secret",
    "encryption_key",
    "slack_token",
    "slack_webhook",
    "github_token",
    "stripe_secret",
    "stripe_api_key",
    "twilio_auth_token",
    "sendgrid_api_key",
    "mailgun_api_key",
    "firebase_api_key",
    "openai_api_key",
]

# High-value private key patterns
PRIVATE_KEY_PATTERNS = [
    ("-----BEGIN RSA PRIVATE KEY-----", "rsa_private_key", 10),
    ("-----BEGIN DSA PRIVATE KEY-----", "dsa_private_key", 10),
    ("-----BEGIN EC PRIVATE KEY-----", "ec_private_key", 10),
    ("-----BEGIN OPENSSH PRIVATE KEY-----", "openssh_private_key", 10),
    ("-----BEGIN PGP PRIVATE KEY BLOCK-----", "pgp_private_key", 10),
]

# Cloud provider specific patterns
CLOUD_SPECIFIC_DORKS = [
    ("AKIA[0-9A-Z]{16}", "aws_access_key_pattern", 10),
    ("rds.amazonaws.com password", "aws_rds_password", 9),
    ("s3.amazonaws.com", "s3_references", 7),
]


def generate_domain_specific_dorks(domain: str) -> List[Tuple[str, str, int]]:
    """Generate domain-specific dorks with keywords."""
    dorks = []

    for keyword in KEYWORD_DORKS[:15]:  # Top 15 keywords
        # Basic pattern
        dorks.append((f'"{domain}" {keyword}', f"domain_{keyword}", 7))

        # JSON format pattern
        dorks.append((f'"{domain}" "{keyword}:"', f"domain_{keyword}_json", 8))

    return dorks


def generate_org_specific_dorks(org: str) -> List[Tuple[str, str, int]]:
    """Generate organization-specific dorks."""
    dorks = []

    # Org with high-value patterns
    patterns = [
        ("password", 8),
        ("api_key", 9),
        ("secret", 8),
        ("token", 8),
        ("AWS_SECRET_ACCESS_KEY", 10),
        ("BEGIN RSA PRIVATE KEY", 10),
        ("BEGIN OPENSSH PRIVATE KEY", 10),
        ("credentials", 8),
        (".env", 9),
    ]

    for pattern, priority in patterns:
        dorks.append((f'org:{org} "{pattern}"', f"org_{pattern}", priority))

    return dorks


def generate_combined_filter_dorks(domain: str) -> List[Tuple[str, str, int]]:
    """Generate dorks with combined filters."""
    dorks = []

    # High-value file combinations
    file_combos = [
        (f'filename:.env "{domain}"', "env_file_domain", 10),
        (f'filename:config.json "{domain}"', "config_json_domain", 9),
        (f'filename:credentials "{domain}"', "credentials_file_domain", 10),
        (f'extension:pem "{domain}"', "pem_file_domain", 10),
        (f'path:config "{domain}" password', "config_path_password", 9),
    ]

    dorks.extend([(dork, name, prio) for dork, name, prio in file_combos])

    return dorks


def get_all_dorks() -> Dict[str, List[Tuple[str, str, int]]]:
    """Get all categorized dorks."""
    return {
        "file_based": FILE_DORKS,
        "extension_based": EXTENSION_DORKS,
        "private_keys": PRIVATE_KEY_PATTERNS,
        "cloud_specific": CLOUD_SPECIFIC_DORKS,
    }


def get_top_priority_dorks(limit: int = 50) -> List[Tuple[str, str, int]]:
    """Get highest priority dorks across all categories."""
    all_dorks = []

    # Collect all dorks
    all_dorks.extend(FILE_DORKS)
    all_dorks.extend(EXTENSION_DORKS)
    all_dorks.extend(PRIVATE_KEY_PATTERNS)
    all_dorks.extend(CLOUD_SPECIFIC_DORKS)

    # Sort by priority (descending)
    all_dorks.sort(key=lambda x: x[2], reverse=True)

    return all_dorks[:limit]


def get_domain_dork_set(domain: str, org: str = None, limit: int = 30) -> List[Tuple[str, str, int]]:
    """
    Get complete dork set for a domain/org.
    Combines generic high-priority dorks with domain-specific ones.
    """
    dorks = []

    # Top generic dorks (always include)
    dorks.extend(get_top_priority_dorks(10))

    # Domain-specific
    dorks.extend(generate_domain_specific_dorks(domain)[:10])

    # Combined filter dorks
    dorks.extend(generate_combined_filter_dorks(domain)[:5])

    # Org-specific if provided
    if org:
        dorks.extend(generate_org_specific_dorks(org)[:5])

    # Deduplicate and sort by priority
    seen = set()
    unique_dorks = []
    for dork, name, priority in dorks:
        if dork not in seen:
            seen.add(dork)
            unique_dorks.append((dork, name, priority))

    unique_dorks.sort(key=lambda x: x[2], reverse=True)

    return unique_dorks[:limit]
