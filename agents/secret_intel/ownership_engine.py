"""
OwnershipEngine — determines whether a secret finding belongs to a target
organisation (first_party) or merely references it (third_party).

Attribution model
-----------------
Domain → GitHub Org mapping uses three heuristics in priority order:
  1. Root domain extraction  (google.com → "google")
  2. Known static mapping config  (amazon.com → ["aws", "amazon"])
  3. Live GitHub org search  (keyword match against /search/users?type=org)

Ownership tiers
---------------
  first_party   repo owner is a confirmed org for the target domain
  third_party   domain appears in content, but repo is unrelated
  unknown       insufficient signals

Confidence levels
-----------------
  HIGH    repo_owner_match — owner login is in the org set
  MEDIUM  api_usage_in_code — domain found in actual runtime code (not comments)
  LOW     keyword_in_content — domain appears anywhere in file text
  LOW     no_ownership_signal — no evidence linking repo to domain
"""

import json
import logging
import os
import re
import urllib.request
import urllib.error
from typing import Dict, List, Optional, Tuple

logger = logging.getLogger(__name__)

# ── Static domain → org mapping ───────────────────────────────────────────────
_KNOWN_MAPPINGS: Dict[str, List[str]] = {
    "google.com":       ["google", "googleapis", "googlecloudplatform",
                         "googlechrome", "google-deepmind"],
    "amazon.com":       ["aws", "amazon", "amzn", "awslabs"],
    "microsoft.com":    ["microsoft", "azure", "microsoftdocs"],
    "apple.com":        ["apple"],
    "meta.com":         ["facebook", "facebookresearch", "meta-llama"],
    "facebook.com":     ["facebook", "facebookresearch"],
    "twitter.com":      ["twitter", "twitterdev"],
    "x.com":            ["twitter", "twitterdev"],
    "netflix.com":      ["netflix"],
    "stripe.com":       ["stripe"],
    "github.com":       ["github", "githubtraining"],
    "shopify.com":      ["shopify"],
    "airbnb.com":       ["airbnb"],
    "uber.com":         ["uber", "ubereats"],
    "lyft.com":         ["lyft"],
    "slack.com":        ["slackhq"],
    "atlassian.com":    ["atlassian"],
    "hashicorp.com":    ["hashicorp"],
    "cloudflare.com":   ["cloudflare"],
    "elastic.co":       ["elastic"],
    "mongodb.com":      ["mongodb"],
    "twilio.com":       ["twilio"],
    "sendgrid.com":     ["sendgrid"],
    "datadog.com":      ["datadog"],
    "splunk.com":       ["splunk"],
    "pagerduty.com":    ["pagerduty"],
    "okta.com":         ["okta"],
    "auth0.com":        ["auth0"],
    "docker.com":       ["docker"],
    "digitalocean.com": ["digitalocean"],
    "linode.com":       ["linode"],
    "heroku.com":       ["heroku"],
    "vercel.com":       ["vercel"],
    "netlify.com":      ["netlify"],
    "openai.com":       ["openai"],
    "anthropic.com":    ["anthropic"],
    "huggingface.co":   ["huggingface"],
    "gitlab.com":       ["gitlab-org"],
    "grafana.com":      ["grafana"],
    "redis.com":        ["redis"],
}

# Optional user-defined config file to extend mappings
_CONFIG_PATH = os.path.expanduser("~/.oneinfinity/org_mappings.json")

# Matches URLs in non-comment lines (scheme:// or @hostname patterns)
_URL_RE = re.compile(
    r"""(?x)
    (?:https?://|@)          # scheme or git-style @ prefix
    (                        # capture the host+path
      [\w\-]+(?:\.[\w\-]+)+  # hostname (e.g. api.stripe.com)
      (?:[:/][\w\-./=?&%#]*)? # optional path / query
    )
    """,
)

# Subdomain prefixes that are not useful as org identifiers
_SKIP_LABELS = frozenset(["www", "api", "app", "portal", "mail", "smtp", "cdn"])


# ── Config helpers ─────────────────────────────────────────────────────────────

def _load_org_mapping_config(domain: str) -> List[str]:
    """Return orgs from static table + optional user config file."""
    orgs: List[str] = list(_KNOWN_MAPPINGS.get(domain, []))
    try:
        if os.path.exists(_CONFIG_PATH):
            with open(_CONFIG_PATH) as fh:
                data = json.load(fh)
            orgs.extend(data.get(domain, []))
    except Exception as exc:
        logger.debug("org_mapping_config read error: %s", exc)
    return orgs


def _search_github_orgs(domain: str, github_token: Optional[str] = None) -> List[str]:
    """
    Query GitHub /search/users for orgs matching the domain keyword.
    Only returns logins that contain the keyword (avoids unrelated results).
    Falls back to [] on any error.
    """
    keyword = domain.split(".")[0].lower()
    url = (
        f"https://api.github.com/search/users"
        f"?q={keyword}+type:org&per_page=5"
    )
    headers = {
        "Accept": "application/vnd.github.v3+json",
        "User-Agent": "OneInfinity-OwnershipEngine/1.0",
    }
    if github_token:
        headers["Authorization"] = f"token {github_token}"
    try:
        req = urllib.request.Request(url, headers=headers)
        with urllib.request.urlopen(req, timeout=5) as resp:
            data = json.loads(resp.read().decode())
        return [
            item["login"].lower()
            for item in data.get("items", [])
            if keyword in item.get("login", "").lower()
        ]
    except Exception as exc:
        logger.debug("GitHub org search failed for '%s': %s", domain, exc)
        return []


# ── Public API ─────────────────────────────────────────────────────────────────

def map_domain_to_orgs(
    domain: str,
    github_token: Optional[str] = None,
) -> List[str]:
    """
    Return a deduplicated list of likely GitHub org/user names for *domain*.

    Heuristic stack (all results merged):
      1. Root domain label          (stripe.com → "stripe")
      2. Known static mapping       (amazon.com → ["aws", "amazon", "amzn", "awslabs"])
      3. GitHub org search API      (live call; only executed when token provided)
    """
    orgs: set = set()

    # Heuristic 1 — root label
    root = domain.split(".")[0].lower()
    if root and root not in _SKIP_LABELS:
        orgs.add(root)

    # Heuristic 2 — static + user config
    orgs.update(_load_org_mapping_config(domain))

    # Heuristic 3 — live GitHub search (only when token available to avoid anon rate-limit)
    if github_token:
        orgs.update(_search_github_orgs(domain, github_token))

    return [o.lower() for o in orgs if o]


def extract_runtime_domains(content: str) -> List[str]:
    """
    Extract hostnames referenced in actual runtime code (non-comment lines).
    Comment lines (starting with #, //, *) are skipped to reduce noise.
    """
    domains: set = set()
    for line in content.split("\n"):
        stripped = line.strip()
        if stripped.startswith(("#", "//", "*", "<!--", "--")):
            continue
        for match in _URL_RE.finditer(line):
            host_path = match.group(1)
            host = host_path.split("/")[0].split(":")[0].lower()
            if "." in host and len(host) > 4:
                domains.add(host)
    return list(domains)


def determine_ownership(
    repo_owner: str,
    repo_full_name: str,
    content: str,
    target_domain: str,
    github_token: Optional[str] = None,
) -> Tuple[str, str, str]:
    """
    Classify a finding's relationship to *target_domain*.

    Returns
    -------
    (party, confidence, reason)
      party      : "first_party" | "third_party"
      confidence : "HIGH" | "MEDIUM" | "LOW"
      reason     : short human-readable label for the report
    """
    orgs = map_domain_to_orgs(target_domain, github_token=github_token)
    owner_lower = repo_owner.lower() if repo_owner else ""

    # ── Strong signal: repo owner is a known org for this domain ──────────────
    if owner_lower and owner_lower in orgs:
        return ("first_party", "HIGH", f"repo_owner_match:{owner_lower}")

    # ── Medium signal: domain used in runtime code (not comments) ─────────────
    runtime_domains = extract_runtime_domains(content or "")
    if any(
        d == target_domain or d.endswith("." + target_domain)
        for d in runtime_domains
    ):
        return ("third_party", "MEDIUM", "api_usage_in_code")

    # ── Weak signal: domain keyword anywhere in content ────────────────────────
    if content and target_domain.lower() in content.lower():
        return ("third_party", "LOW", "keyword_in_content")

    return ("third_party", "LOW", "no_ownership_signal")
