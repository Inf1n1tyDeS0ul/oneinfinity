"""
Enhanced GitHub Dorks Collection
Comprehensive patterns for secrets detection across GitHub.
"""

from typing import List, Tuple

# Keyword-based dorks (513 patterns)
KEYWORD_DORKS = [
    "access_key", "access_token", "admin_pass", "admin_user",
    "algolia_admin_key", "algolia_api_key", "alias_pass",
    "alicloud_access_key", "amazon_secret_access_key", "amazonaws",
    "ansible_vault_password", "aos_key", "api_key", "api_key_secret",
    "api_key_sid", "api_secret", "apikey", "apiSecret",
    "app_debug", "app_id", "app_key", "app_log_level", "app_secret",
    "appkey", "appkeysecret", "application_key", "appsecret", "appspot",
    "auth_token", "authorizationToken", "authsecret",
    "aws_access", "aws_access_key_id", "aws_bucket", "aws_key",
    "aws_secret", "aws_secret_key", "aws_token", "AWSSecretKey",
    "b2_app_key", "bashrc password", "bintray_apikey",
    "bintray_gpg_password", "bintray_key", "bintraykey",
    "bluemix_api_key", "bluemix_pass", "browserstack_access_key",
    "bucket_password", "bucketeer_aws_access_key_id",
    "bucketeer_aws_secret_access_key", "built_branch_deploy_key",
    "bx_password", "cache_driver", "cache_s3_secret_key",
    "cattle_access_key", "cattle_secret_key", "certificate_password",
    "ci_deploy_password", "client_secret", "client_zpk_secret_key",
    "clojars_password", "cloud_api_key", "cloud_watch_aws_access_key",
    "cloudant_password", "cloudflare_api_key", "cloudflare_auth_key",
    "cloudinary_api_secret", "cloudinary_name", "codecov_token",
    "conn.login", "connectionstring", "consumer_key", "consumer_secret",
    "credentials", "cypress_record_key", "database_password",
    "database_schema_test", "datadog_api_key", "datadog_app_key",
    "db_password", "db_server", "db_username", "dbpasswd", "dbpassword",
    "dbuser", "deploy_password", "docker_hub_password", "docker_key",
    "docker_pass", "docker_passwd", "docker_password",
    "dockerhub_password", "encryption_key", "encryption_password",
    "env_key", "env_secret", "eureka_awssecretkey",
    "fabricApiSecret", "fb_secret", "firebase", "fossa_api_key",
    "ftp_host", "ftp_password", "ftp_user", "gateway_pass",
    "gcloud_api_key", "gcr_password", "gh_api_key", "gh_next_oauth_client_secret",
    "gh_next_unstable_oauth_client_secret", "gh_oauth_client_secret",
    "gh_oauth_token", "gh_token", "git_token",
    "github_api_key", "github_api_token", "github_key", "github_token",
    "gitlab", "gmail_password", "gmail_username", "google_application_credentials",
    "google_private_key", "gpg_key", "gpg_passphrase", "gpg_private_key",
    "gradle_signing_key_id", "gradle_signing_password",
    "gradle_signing_secret_key_ring_file", "herokuapp",
    "heroku_api_key", "heroku_api_user", "heroku_email",
    "iam_user_secret", "irc_pass", "jdbc", "JEKYLL_GITHUB_TOKEN",
    "jira_pass", "jwt_secret", "jwt_token", "kafka_admin_pass",
    "kafka_instance_name", "kafka_rest_url", "key", "keyPassword",
    "keyStore", "keyStorePassword", "ldap_password", "ldap_username",
    "lighthouse_api_hash", "linux_signing_key", "login",
    "mailchimp", "mailchimp_api_key", "mailgun", "mailgun_api_key",
    "mailgun_pub_key", "mailgun_secret_api_key", "master_key",
    "meetup_oauth", "mega_pass", "mh_apikey", "mh_password",
    "mile_zero_key", "minio_access_key", "minio_secret_key",
    "mysql", "mysql_password", "mysql_username", "natural_language_classifier_password",
    "node_env", "npm_api_key", "npm_auth_token", "npmrc _auth",
    "nuget_api_key", "nuget_key", "oauth_token", "objectstore_password",
    "octest_app_password", "okta_client_token", "openai_api_key",
    "openwhisk_key", "pass", "passwd", "password", "passwords",
    "paypal_client_id", "paypal_client_secret", "paypal_secret",
    "pem private", "personal_key", "personal_secret", "preprod",
    "private_key", "prod", "production_key", "project_id",
    "publish_key", "pword", "pwd", "pwds", "quay_password",
    "queue_driver", "rabbitmq_password", "rancher_access_key",
    "rancher_secret_key", "redis_password", "refresh_token",
    "rest_api_key", "root_password", "route53_access_key_id",
    "rtd_key_pass", "s3_access_key", "s3_access_key_id",
    "s3_bucket_name_app_logs", "s3_key", "s3_key_app_logs",
    "s3_secret", "s3_secret_app_logs", "s3_secret_key",
    "salesforce_bulk_test_security_token", "salt", "sauce_access_key",
    "sauce_secret_key", "secret", "secret.password",
    "secret_access_key", "secret_key", "secret_token", "secrets",
    "secure", "security_credentials", "segment_api_key",
    "send.keys", "send_keys", "sendgrid", "sendgrid_api_key",
    "sendgrid_key", "sendgrid_password", "sendkeys",
    "sentry_default_org", "sentry_endpoint", "ses_access_key",
    "ses_secret_key", "setdsapublickey", "setsecretkey",
    "SF_USERNAME salesforce", "shodan_api_key", "slack_api",
    "slack_token", "slack_webhook", "slate_user_email",
    "snoowrap_client_secret", "sonar_organization_key",
    "sonar_token", "sonatype_password", "sqladmin_password",
    "sql_password", "square_access_token", "square_application_id",
    "square_application_secret", "ssh", "ssh2_auth_password",
    "sshpass", "staging", "stg", "storePassword",
    "stormpath_api_key_id", "stormpath_api_key_secret",
    "strip_key", "strip_secret_key", "stripe", "stripe_key",
    "stripe_secret", "stripToken", "svn_pass", "swagger",
    "tesco_api_key", "tester_keys_password", "testuser",
    "thera_oss_access_key", "token", "twilio_account_sid",
    "twilio_accountsid", "twilio_api_key", "twilio_api_secret",
    "twilio_secret", "twilio_secret_token", "twilio_token",
    "twilioapiauth", "twiliosecret", "twine_password",
    "twitter_secret", "twitterKey", "x-api-key",
    "xoxb", "xoxp", "zen_tkn", "zen_token", "zendesk_url",
    "zendesk_api_token", "zendesk_key", "zendesk_token",
    "zendesk_username",
    # Added: database URLs, cloud key prefixes, token prefixes
    "DATABASE_URL postgres", "DATABASE_URL mysql",
    "redis:// password", "mongodb+srv://",
    "AKIA", "ghp_", "gho_", "sk-",
]

# Language-specific patterns
LANGUAGE_SPECIFIC_DORKS = [
    ("HEROKU_API_KEY", "language:json", 9),
    ("HEROKU_API_KEY", "language:shell", 9),
    ("HOMEBREW_GITHUB_API_TOKEN", "language:shell", 8),
    ("PT_TOKEN", "language:bash", 9),
    ("JEKYLL_GITHUB_TOKEN", "language:yaml", 9),
    ("shodan_api_key", "language:python", 9),
    ("jsforce", "extension:js conn.login", 8),
    ('"api_hash" "api_id"', "language:python", 9),  # Telegram API
    ("xoxp-", "language:json", 10),  # Slack user tokens
    ("xoxb-", "language:json", 10),  # Slack bot tokens
]

# Filename-based dorks
FILENAME_DORKS = [
    ("filename:.bash_history", "bash_history", 9),
    ("filename:.bash_profile aws", "bash_aws_config", 9),
    ("filename:.bashrc mailchimp", "bashrc_mailchimp", 8),
    ("filename:.bashrc password", "bashrc_password", 9),
    ("filename:.cshrc", "cshrc", 7),
    ("filename:.dockercfg auth", "dockercfg_auth", 10),
    ("filename:.env DB_USERNAME NOT homestead", "env_db_not_homestead", 10),
    ("filename:.env MAIL_HOST=smtp.gmail.com", "env_gmail", 9),
    ("filename:.esmtprc password", "esmtprc_password", 9),
    ("filename:.ftpconfig", "ftpconfig", 8),
    ("filename:.git-credentials", "git_credentials", 10),
    ("filename:.history", "shell_history", 8),
    ("filename:.htpasswd", "htpasswd", 9),
    ("filename:.netrc password", "netrc_password", 9),
    ("filename:.npmrc _auth", "npmrc_auth", 10),
    ("filename:.pgpass", "pgpass", 9),
    ("filename:.remote-sync.json", "remote_sync", 8),
    ("filename:.s3cfg", "s3cfg", 9),
    ("filename:.sh_history", "sh_history", 8),
    ("filename:.tugboat NOT _tugboat", "tugboat_config", 8),
    ("filename:CCCam.cfg", "cccam", 6),
    ("filename:WebServers.xml", "webservers_xml", 8),
    ("filename:_netrc password", "netrc_alt_password", 9),
    ("filename:beanstalkd.yml", "beanstalk_config", 7),
    ("filename:composer.json", "composer", 6),
    ("filename:config irc_pass", "irc_config_pass", 8),
    ("filename:config.json auths", "config_json_auths", 9),
    ("filename:config.php dbpasswd", "php_db_config", 9),
    ("filename:configuration.php JConfig password", "joomla_config", 9),
    ("filename:connections.xml", "connections_xml", 8),
    ("filename:credentials aws_access_key_id", "credentials_aws", 10),
    ("filename:dbeaver-data-sources.xml", "dbeaver_datasources", 9),
    ("filename:deploy.rake", "deploy_rake", 7),
    ("filename:deployment-config.json", "deployment_config", 7),
    ("filename:dhcpd.conf", "dhcpd_config", 6),
    ("filename:express.conf path:.openshift", "openshift_express", 8),
    ("filename:filezilla.xml Pass", "filezilla_passwords", 9),
    ("filename:hub oauth_token", "github_hub_oauth", 10),
    ("filename:id_dsa", "id_dsa_key", 10),
    ("filename:id_rsa", "id_rsa_key", 10),
    ("filename:id_rsa or filename:id_dsa", "ssh_private_keys", 10),
    ("filename:idea14.key", "intellij_key", 7),
    ("filename:known_hosts", "known_hosts", 6),
    ("filename:logins.json", "logins_json", 9),
    ("filename:master.key path:config", "rails_master_key", 10),
    ("filename:passwd path:etc", "unix_passwd", 9),
    ("filename:prod.exs NOT prod.secret.exs", "phoenix_prod_not_secret", 8),
    ("filename:prod.secret.exs", "phoenix_prod_secret", 9),
    ("filename:proftpdpasswd", "proftpd_passwords", 8),
    ("filename:recentservers.xml Pass", "filezilla_recent", 9),
    ("filename:robomongo.json", "robomongo_creds", 9),
    ("filename:secrets.yml password", "secrets_yml_password", 9),
    ("filename:server.cfg rcon password", "game_rcon", 7),
    ("filename:settings.py SECRET_KEY", "django_secret_key", 9),
    ("filename:sftp-config.json", "sftp_config", 8),
    ("filename:sftp.json path:.vscode", "vscode_sftp", 8),
    ("filename:shadow path:etc", "unix_shadow", 10),
    ("filename:sshd_config", "sshd_config", 7),
    ("filename:ventrilo_srv.ini", "ventrilo", 6),
    ("filename:wp-config.php", "wordpress_config", 9),
    # Added: SSH keys, cloud config, secrets files
    ("filename:id_ecdsa", "id_ecdsa_key", 10),
    ("filename:.pypirc", "pypirc_config", 9),
    ("filename:terraform.tfvars password", "terraform_tfvars_password", 9),
    ("filename:.env DATABASE_URL", "env_database_url", 10),
    ("filename:docker-compose.yml password", "docker_compose_password", 9),
    ("filename:credentials.json", "credentials_json", 9),
    ("filename:secrets.yml", "secrets_yml", 9),
]

# Extension-based dorks
EXTENSION_DORKS = [
    ("extension:avastlic", "support.avast.com", "avast_license", 6),
    ("extension:bat", "", "batch_scripts", 5),
    ("extension:cfg", "", "config_files", 6),
    ("extension:env", "", "env_files", 9),
    ("extension:exs", "", "elixir_config", 7),
    ("extension:ini", "", "ini_files", 7),
    ("extension:json", "api.forecast.io", "forecast_api", 8),
    ("extension:json", "googleusercontent client_secret", "google_client_secret", 10),
    ("extension:json", "mongolab.com", "mongolab_json", 8),
    ("extension:pem", "", "pem_certificates", 9),
    ("extension:pem", "private", "pem_private_keys", 10),
    ("extension:ppk", "", "putty_keys", 9),
    ("extension:ppk", "private", "putty_private_keys", 10),
    ("extension:properties", "", "properties_files", 7),
    ("extension:sh", "", "shell_scripts", 6),
    ("extension:sls", "", "serverless_config", 7),
    ("extension:sql", "", "sql_files", 7),
    ("extension:sql", "mysql dump", "mysql_dumps", 8),
    ("extension:sql", "mysql dump password", "mysql_dump_passwords", 9),
    ("extension:yaml", "mongolab.com", "mongolab_yaml", 8),
    ("extension:zsh", "", "zsh_config", 6),
    # Added: Terraform state files
    ("extension:tfstate", "", "terraform_state", 10),
]

# Path-based searches
PATH_DORKS = [
    ("path:sites databases password", "drupal_sites_db", 9),
    ("msg nickserv identify filename:config", "irc_nickserv", 8),
    # Added: SSH private key in .ssh paths
    ("path:/.ssh/ id_rsa", "ssh_path_id_rsa", 10),
]

# Advanced combined patterns
ADVANCED_DORKS = [
    ("[WFClient] Password=", "extension:ica", "citrix_passwords", 9),
    ("private", "-language:java", "private_no_java", 7),
    ("", "language:yaml -filename:travis", "yaml_no_travis", 6),
]


def generate_quoted_keyword_dorks(domain: str, limit: int = 50) -> List[Tuple[str, str, int]]:
    """Generate quoted keyword searches for exact matching."""
    dorks = []
    high_priority_keywords = [
        "password", "api_key", "secret", "token", "access_token",
        "client_secret", "aws_access_key_id", "aws_secret",
        "private_key", "database_password", "db_password",
        "api_secret", "stripe", "firebase", "credentials",
        "oauth_token", "github_token", "slack_token",
    ]

    for kw in high_priority_keywords[:limit]:
        dorks.append((f'"{domain}" "{kw}"', f"quoted_{kw}", 8))

    return dorks


def generate_language_filtered_dorks(domain: str) -> List[Tuple[str, str, int]]:
    """Generate language-specific searches."""
    dorks = []
    languages = ["python", "javascript", "java", "shell", "json", "yaml", "php", "ruby"]
    keywords = ["password", "api_key", "secret", "token"]

    for lang in languages:
        for kw in keywords:
            dorks.append((f'"{domain}" "{kw}" language:{lang}', f"{kw}_lang_{lang}", 7))

    return dorks


def generate_extension_combined_dorks(domain: str) -> List[Tuple[str, str, int]]:
    """Generate extension + keyword combinations."""
    dorks = []
    combos = [
        ("extension:json", "client_secret", 10),
        ("extension:json", "api_key", 9),
        ("extension:yaml", "password", 9),
        ("extension:env", "DATABASE_URL", 10),
        ("extension:env", "AWS_", 10),
        ("extension:sql", "password", 8),
        ("extension:pem", "PRIVATE", 10),
        ("extension:ppk", "PRIVATE", 10),
    ]

    for ext, kw, priority in combos:
        dorks.append((f'"{domain}" {ext} {kw}', f"{ext.split(':')[1]}_{kw}", priority))

    return dorks


def generate_path_based_dorks(domain: str) -> List[Tuple[str, str, int]]:
    """Generate path-specific searches."""
    dorks = []
    paths = [
        ("path:config", "password", 9),
        ("path:.aws", "", 10),
        ("path:.ssh", "", 10),
        ("path:etc", "password", 8),
        ("path:.openshift", "", 7),
        ("path:.vscode", "sftp", 8),
    ]

    for path, kw, priority in paths:
        if kw:
            dorks.append((f'"{domain}" {path} {kw}', f"{path.split(':')[1]}_{kw}", priority))
        else:
            dorks.append((f'"{domain}" {path}', f"{path.split(':')[1]}", priority))

    return dorks


def generate_not_operator_dorks(domain: str) -> List[Tuple[str, str, int]]:
    """Generate dorks with NOT operators to filter false positives."""
    dorks = [
        (f'"{domain}" filename:.env DB_USERNAME NOT homestead', "env_db_not_test", 10),
        (f'"{domain}" filename:prod.exs NOT prod.secret.exs', "phoenix_prod_not_secret", 8),
        (f'"{domain}" TWILIO_SID NOT env', "twilio_not_env", 9),
        (f'"{domain}" filename:.tugboat NOT _tugboat', "tugboat_not_underscore", 8),
        (f'"{domain}" private -language:java', "private_not_java", 7),
    ]

    return dorks


def generate_temporal_dorks(domain: str, years_back: int = 3) -> List[Tuple[str, str, int]]:
    """Generate date-based dorks to find recent commits/changes."""
    import datetime
    dorks = []
    current_year = datetime.datetime.now().year

    # Recent commits with secrets (higher priority for newer commits)
    for i in range(years_back):
        year = current_year - i
        priority = 8 - i  # Newer = higher priority
        dorks.append((f'"{domain}" "password" created:>={year}-01-01', f"password_{year}", priority))
        dorks.append((f'"{domain}" "api_key" created:>={year}-01-01', f"apikey_{year}", priority))

    return dorks


def get_comprehensive_dork_set(
    domain: str,
    org: str = None,
    include_keywords: bool = True,
    include_filenames: bool = True,
    include_extensions: bool = True,
    include_languages: bool = False,
    include_temporal: bool = False,
    limit: int = 50
) -> List[Tuple[str, str, int]]:
    """
    Get comprehensive dork set combining all techniques.
    Returns prioritized list limited to specified count.
    """
    dorks = []

    if include_keywords:
        dorks.extend(generate_quoted_keyword_dorks(domain, limit=20))

    if include_filenames:
        for dork, name, priority in FILENAME_DORKS[:15]:
            dorks.append((f'"{domain}" {dork}', f"domain_{name}", priority))

    if include_extensions:
        for ext_dork, extra, name, priority in EXTENSION_DORKS[:10]:
            if extra:
                dorks.append((f'"{domain}" {ext_dork} {extra}', f"domain_{name}", priority))
            else:
                dorks.append((f'"{domain}" {ext_dork}', f"domain_{name}", priority))

    if include_languages:
        dorks.extend(generate_language_filtered_dorks(domain)[:10])

    if include_temporal:
        dorks.extend(generate_temporal_dorks(domain, years_back=2))

    # NOT operator dorks
    dorks.extend(generate_not_operator_dorks(domain))

    # Path-based
    dorks.extend(generate_path_based_dorks(domain))

    # Org-specific if provided
    if org:
        for kw in ["password", "api_key", "secret", "AWS_SECRET", "private key"]:
            dorks.append((f'org:{org} "{kw}"', f"org_{kw}", 9))

    # Deduplicate and sort by priority
    seen = set()
    unique_dorks = []
    for dork, name, priority in dorks:
        if dork not in seen:
            seen.add(dork)
            unique_dorks.append((dork, name, priority))

    unique_dorks.sort(key=lambda x: x[2], reverse=True)

    return unique_dorks[:limit]
