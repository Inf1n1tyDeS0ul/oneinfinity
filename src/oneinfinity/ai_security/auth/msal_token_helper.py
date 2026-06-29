"""
Microsoft SSO Token Helper for AI Red Team campaigns.

Three auth flows supported:
  1. device_code  — opens a browser URL, you log in, token returned (best for MFA)
  2. username_password — direct creds (works if MFA not enforced per-app)
  3. client_credentials — service principal / app-only (for non-interactive CI)

Usage:
  python msal_token_helper.py --flow device_code --tenant <tenant_id> --client-id <app_id> --scope <scope>

Output: prints token to stdout as JSON for piping into campaign config.
"""

from __future__ import annotations

import argparse
import json
import logging
import os
import sys
import time
from typing import Optional

log = logging.getLogger(__name__)


def get_token_device_code(
    tenant_id: str,
    client_id: str,
    scopes: list[str],
) -> dict:
    """Interactive device-code flow — works with MFA, no stored creds needed."""
    import msal

    app = msal.PublicClientApplication(
        client_id,
        authority=f"https://login.microsoftonline.com/{tenant_id}",
    )

    # Check cache first
    accounts = app.get_accounts()
    if accounts:
        result = app.acquire_token_silent(scopes, account=accounts[0])
        if result and "access_token" in result:
            log.info("Token served from cache")
            return result

    flow = app.initiate_device_flow(scopes=scopes)
    if "user_code" not in flow:
        raise RuntimeError(f"Device flow failed: {flow.get('error_description', flow)}")

    print(f"\n[*] Open this URL in your browser: {flow['verification_uri']}", file=sys.stderr)
    print(f"[*] Enter this code:               {flow['user_code']}", file=sys.stderr)
    print(f"[*] Waiting for authentication...\n", file=sys.stderr)

    result = app.acquire_token_by_device_flow(flow)
    if "access_token" not in result:
        raise RuntimeError(f"Auth failed: {result.get('error_description', result)}")

    return result


def get_token_username_password(
    tenant_id: str,
    client_id: str,
    scopes: list[str],
    username: str,
    password: str,
) -> dict:
    """Username/password flow — only works if MFA is not enforced for this app."""
    import msal

    app = msal.PublicClientApplication(
        client_id,
        authority=f"https://login.microsoftonline.com/{tenant_id}",
    )

    accounts = app.get_accounts(username=username)
    if accounts:
        result = app.acquire_token_silent(scopes, account=accounts[0])
        if result and "access_token" in result:
            return result

    result = app.acquire_token_by_username_password(
        username=username, password=password, scopes=scopes
    )
    if "access_token" not in result:
        raise RuntimeError(f"Auth failed: {result.get('error_description', result)}")
    return result


def get_token_client_credentials(
    tenant_id: str,
    client_id: str,
    client_secret: str,
    scopes: list[str],
) -> dict:
    """Service-principal / app-only flow — for non-interactive/CI use."""
    import msal

    app = msal.ConfidentialClientApplication(
        client_id,
        authority=f"https://login.microsoftonline.com/{tenant_id}",
        client_credential=client_secret,
    )
    result = app.acquire_token_for_client(scopes=scopes)
    if "access_token" not in result:
        raise RuntimeError(f"Auth failed: {result.get('error_description', result)}")
    return result


def get_token(
    flow: str,
    tenant_id: str,
    client_id: str,
    scopes: list[str],
    username: str = "",
    password: str = "",
    client_secret: str = "",
) -> str:
    """Returns a ready-to-use 'Bearer <token>' string."""
    if flow == "device_code":
        result = get_token_device_code(tenant_id, client_id, scopes)
    elif flow == "username_password":
        result = get_token_username_password(tenant_id, client_id, scopes, username, password)
    elif flow == "client_credentials":
        result = get_token_client_credentials(tenant_id, client_id, client_secret, scopes)
    else:
        raise ValueError(f"Unknown flow: {flow}. Use: device_code | username_password | client_credentials")

    token = result["access_token"]
    expires_in = result.get("expires_in", 3600)
    token_type = result.get("token_type", "Bearer")
    print(f"[+] Token acquired. Expires in {expires_in}s ({expires_in // 60} min)", file=sys.stderr)
    return f"{token_type} {token}"


def _cli():
    p = argparse.ArgumentParser(description="Get Microsoft SSO Bearer token for AI Red Team")
    p.add_argument("--flow", choices=["device_code", "username_password", "client_credentials"],
                   default="device_code")
    p.add_argument("--tenant", required=True, help="Azure AD tenant ID or domain (e.g. contoso.onmicrosoft.com)")
    p.add_argument("--client-id", required=True, dest="client_id",
                   help="Application (client) ID of the chatbot app in Azure AD")
    p.add_argument("--scope", default=".default",
                   help="OAuth2 scope (e.g. api://<app-id>/.default or https://graph.microsoft.com/.default)")
    p.add_argument("--username", default=os.environ.get("MSAL_USER", ""))
    p.add_argument("--password", default=os.environ.get("MSAL_PASS", ""))
    p.add_argument("--client-secret", default=os.environ.get("MSAL_SECRET", ""), dest="client_secret")
    p.add_argument("--json", action="store_true", help="Output full token response as JSON")
    args = p.parse_args()

    scope_str = args.scope if args.scope.startswith("http") or args.scope.endswith("/.default") \
        else f"api://{args.client_id}/{args.scope}"
    scopes = [scope_str]

    try:
        if args.json:
            if args.flow == "device_code":
                result = get_token_device_code(args.tenant, args.client_id, scopes)
            elif args.flow == "username_password":
                result = get_token_username_password(args.tenant, args.client_id, scopes, args.username, args.password)
            else:
                result = get_token_client_credentials(args.tenant, args.client_id, args.client_secret, scopes)
            # Mask the token in output — only print what's needed
            print(json.dumps({
                "auth_header": f"{result.get('token_type','Bearer')} {result['access_token']}",
                "expires_in": result.get("expires_in"),
                "scope": result.get("scope"),
            }))
        else:
            bearer = get_token(
                args.flow, args.tenant, args.client_id, scopes,
                args.username, args.password, args.client_secret,
            )
            print(bearer)  # stdout: usable directly as auth_header
    except Exception as exc:
        print(f"[-] Error: {exc}", file=sys.stderr)
        sys.exit(1)


if __name__ == "__main__":
    _cli()
