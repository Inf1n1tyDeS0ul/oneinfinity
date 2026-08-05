"""
scan_profiles.py — Pre-configured scan profiles for known vulnerable applications.
Auto-detection triggers on page title, response headers, or URL patterns.
"""
from __future__ import annotations
import re
from dataclasses import dataclass, field
from typing import Optional


@dataclass
class ScanProfile:
    name: str
    known_paths: list = field(default_factory=list)   # paths to add to URL discovery
    tech_stack: list = field(default_factory=list)    # expected technologies
    default_auth: dict = field(default_factory=dict)  # default form_auth config
    vuln_hints: list = field(default_factory=list)    # likely vuln types to prioritize
    description: str = ""


# ── Known app profiles ──────────────────────────────────────────────────────
PROFILES = {
    "dvwa": ScanProfile(
        name="DVWA",
        description="Damn Vulnerable Web Application",
        known_paths=[
            "/login.php", "/setup.php", "/vulnerabilities/",
            "/vulnerabilities/sqli/", "/vulnerabilities/sqli_blind/",
            "/vulnerabilities/xss_r/", "/vulnerabilities/xss_s/",
            "/vulnerabilities/csrf/", "/vulnerabilities/upload/",
            "/vulnerabilities/exec/", "/vulnerabilities/idor/",
            "/vulnerabilities/fi/", "/vulnerabilities/brute/",
            "/vulnerabilities/open_redirect/", "/vulnerabilities/weak_id/",
            "/vulnerabilities/javascript/", "/security.php",
            "/instructions.php", "/about.php",
        ],
        tech_stack=["php", "mysql", "apache"],
        default_auth={
            "form_auth_url": "/login.php",
            "form_auth_username": "admin",
            "form_auth_password": "password",
            "form_auth_username_field": "username",
            "form_auth_password_field": "password",
            "form_auth_type": "form",
        },
        vuln_hints=["sqli", "xss", "csrf", "file_upload", "cmd_injection", "lfi"],
    ),
    "juice_shop": ScanProfile(
        name="OWASP Juice Shop",
        description="OWASP Juice Shop",
        known_paths=[
            "/", "/rest/user/login", "/rest/user/register",
            "/rest/Products", "/rest/BasketItems",
            "/api/Users", "/api/Products", "/api/Challenges",
            "/api/SecurityQuestions", "/api/Feedbacks",
            "/rest/basket", "/rest/admin/application-version",
            "/rest/admin/application-configuration",
            "/ftp", "/ftp/acquisitions.md", "/ftp/package.json.bak",
        ],
        tech_stack=["nodejs", "express", "angular", "sqlite"],
        default_auth={
            "form_auth_url": "/rest/user/login",
            "form_auth_username": "admin@juice-sh.op",
            "form_auth_password": "admin123",
            "form_auth_username_field": "email",
            "form_auth_password_field": "password",
            "form_auth_type": "json",
            "form_auth_token_field": "token",
        },
        vuln_hints=["sqli", "xss", "idor", "broken_auth", "sensitive_data", "xxe"],
    ),
    "webgoat": ScanProfile(
        name="WebGoat",
        description="OWASP WebGoat",
        known_paths=[
            "/WebGoat/login", "/WebGoat/register.mvc",
            "/WebGoat/welcome.mvc", "/WebGoat/service/lessonmenu.mvc",
        ],
        tech_stack=["java", "spring"],
        default_auth={
            "form_auth_url": "/WebGoat/login",
            "form_auth_username": "guest",
            "form_auth_password": "guest",
            "form_auth_type": "form",
        },
        vuln_hints=["sqli", "xss", "idor", "broken_auth"],
    ),
    "ai_goat": ScanProfile(
        name="AI Goat CTFd",
        description="AI Goat CTF platform",
        known_paths=[
            "/", "/login", "/register", "/challenges",
            "/api/v1/users", "/api/v1/challenges", "/api/v1/flags",
            "/api/v1/statistics", "/api/v1/config", "/api/v1/notifications",
            "/api/v1/scoreboard", "/scoreboard",
        ],
        tech_stack=["python", "flask"],
        default_auth={},
        vuln_hints=["xss", "idor", "missing_csp", "broken_auth"],
    ),
    "wordpress": ScanProfile(
        name="WordPress",
        description="WordPress CMS",
        known_paths=[
            "/wp-login.php", "/wp-admin", "/wp-json/wp/v2/users",
            "/wp-json/wp/v2/posts", "/xmlrpc.php", "/wp-config.php.bak",
            "/.wp-config.php", "/wp-includes/",
        ],
        tech_stack=["php", "wordpress", "mysql"],
        default_auth={},
        vuln_hints=["sqli", "xss", "lfi", "broken_auth"],
    ),
    "generic_api": ScanProfile(
        name="Generic REST API",
        description="Generic REST API",
        known_paths=[
            "/api", "/api/v1", "/api/v2", "/graphql",
            "/swagger.json", "/openapi.json", "/api-docs",
            "/health", "/status", "/version",
        ],
        tech_stack=[],
        default_auth={},
        vuln_hints=["idor", "broken_auth", "ssrf", "sqli"],
    ),
}


def detect_profile(title: str = "", server_header: str = "", body_snippet: str = "",
                  target_url: str = "") -> Optional[ScanProfile]:
    """
    Auto-detect the scan profile from HTTP response characteristics.
    Returns the matching ScanProfile or None.
    """
    title_l = title.lower()
    body_l  = body_snippet.lower()[:2000]
    url_l   = target_url.lower()

    # DVWA detection
    if "damn vulnerable web application" in title_l or "dvwa" in title_l:
        return PROFILES["dvwa"]
    if "dvwa" in body_l or "dvwa" in url_l:
        return PROFILES["dvwa"]

    # Juice Shop detection
    if "owasp juice shop" in title_l or "juice shop" in title_l:
        return PROFILES["juice_shop"]
    if "juiceshop" in body_l or "juice-shop" in url_l or "juice_shop" in url_l:
        return PROFILES["juice_shop"]

    # WebGoat detection
    if "webgoat" in title_l or "webgoat" in body_l:
        return PROFILES["webgoat"]

    # AI Goat / CTFd detection
    if "ctfd" in title_l or "ai goat" in title_l or "ctfd" in body_l:
        return PROFILES["ai_goat"]

    # WordPress detection
    if "wordpress" in body_l or "/wp-content/" in body_l or "wp-login" in url_l:
        return PROFILES["wordpress"]

    # Generic API detection
    if any(p in url_l for p in ("/api/", "/graphql", "/rest/", "/swagger")):
        return PROFILES["generic_api"]

    return None
