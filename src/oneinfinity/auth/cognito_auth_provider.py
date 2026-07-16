"""
CognitoAuthProvider — AWS Cognito SRP authentication for OneInfinity scanner.

Performs the full Cognito USER_SRP_AUTH flow to obtain idToken/accessToken/refreshToken,
then constructs a LoginSession with:
  - auth_headers: {"Authorization": "Bearer {idToken}"}
  - local_storage: {"idToken": ..., "accessToken": ..., "refreshToken": ...}

This allows HeadlessBrowserEngine.inject_localstorage() to inject tokens into
a Playwright browser context so the scanner can access Cognito-protected SPAs.

Usage:
    provider = CognitoAuthProvider(
        user_pool_id="ap-southeast-2_XXXXXXX",
        client_id="XXXXXXXXXXXXXXXX",
        region="ap-southeast-2",
    )
    session = provider.authenticate("user@example.com", "Password123!")
    # session.auth_headers == {"Authorization": "Bearer eyJ..."}
    # session.local_storage == {"idToken": "eyJ...", "accessToken": "eyJ...", "refreshToken": "..."}
"""
from __future__ import annotations

import base64
import hashlib
import hmac
import json
import logging
import os
import struct
import time
import uuid
from typing import Optional

import boto3
from botocore.exceptions import ClientError

log = logging.getLogger("oneinfinity.auth.cognito_auth_provider")

# Default Cognito config for SpendAble sandbox (extracted from JS bundle)
_DEFAULT_REGION = "ap-southeast-2"
_DEFAULT_USER_POOL_ID = os.environ.get("COGNITO_USER_POOL_ID", "ap-southeast-2_3mIi5VFTb")
_DEFAULT_CLIENT_ID = os.environ.get("COGNITO_CLIENT_ID", "6ka6ijc9gv6d2f4v34cu31pn8i")
_DEFAULT_IDENTITY_POOL_ID = os.environ.get(
    "COGNITO_IDENTITY_POOL_ID", "ap-southeast-2:ccc3e1b9-6ca1-4218-9c40-d1b6b14aae4e"
)


class CognitoAuthError(Exception):
    """Raised when Cognito authentication fails."""


class CognitoAuthProvider:
    """
    AWS Cognito SRP/USER_PASSWORD_AUTH flow.

    Tries USER_PASSWORD_AUTH first (simpler, works when not blocked).
    Falls back to USER_SRP_AUTH if needed.
    """

    def __init__(
        self,
        user_pool_id: str = _DEFAULT_USER_POOL_ID,
        client_id: str = _DEFAULT_CLIENT_ID,
        identity_pool_id: str = _DEFAULT_IDENTITY_POOL_ID,
        region: str = _DEFAULT_REGION,
    ):
        self.user_pool_id = user_pool_id
        self.client_id = client_id
        self.identity_pool_id = identity_pool_id
        self.region = region
        self._client = boto3.client(
            "cognito-idp",
            region_name=region,
            # Anonymous credentials — no AWS account needed for Cognito user auth
            aws_access_key_id="dummy",
            aws_secret_access_key="dummy",
        )

    # ── Public API ─────────────────────────────────────────────────────────────

    def authenticate(self, email: str, password: str) -> "LoginSession":
        """
        Authenticate with Cognito and return a LoginSession.
        Tries USER_PASSWORD_AUTH first, then USER_SRP_AUTH as fallback.
        """
        from oneinfinity.auth.session_manager import LoginSession

        tokens = self._auth_user_password(email, password)
        if not tokens:
            tokens = self._auth_srp(email, password)
        if not tokens:
            raise CognitoAuthError(f"Cognito authentication failed for {email}")

        id_token = tokens.get("IdToken", "")
        access_token = tokens.get("AccessToken", "")
        refresh_token = tokens.get("RefreshToken", "")

        session = LoginSession(
            session_id=uuid.uuid4().hex[:12],
            target="",
            login_url="",
            cookies=[],
            auth_headers={"Authorization": f"Bearer {id_token}"},
            local_storage={
                "idToken": id_token,
                "accessToken": access_token,
                "refreshToken": refresh_token,
            },
            session_storage={},
            indexeddb_snapshot={},
            har_path="",
            recorder="cognito_auth_provider",
            recorded_at=time.time(),
        )
        log.info(
            "CognitoAuthProvider: authenticated %s — idToken length=%d",
            email, len(id_token),
        )
        return session

    def refresh_session(self, refresh_token: str) -> Optional[dict]:
        """Use refresh token to get new idToken/accessToken."""
        try:
            resp = self._client.initiate_auth(
                AuthFlow="REFRESH_TOKEN_AUTH",
                AuthParameters={"REFRESH_TOKEN": refresh_token},
                ClientId=self.client_id,
            )
            return resp.get("AuthenticationResult")
        except ClientError as exc:
            log.warning("CognitoAuthProvider.refresh_session failed: %s", exc)
            return None

    # ── Internal ───────────────────────────────────────────────────────────────

    def _auth_user_password(self, email: str, password: str) -> Optional[dict]:
        """Simple USER_PASSWORD_AUTH flow."""
        try:
            resp = self._client.initiate_auth(
                AuthFlow="USER_PASSWORD_AUTH",
                AuthParameters={
                    "USERNAME": email,
                    "PASSWORD": password,
                },
                ClientId=self.client_id,
            )
            return resp.get("AuthenticationResult")
        except ClientError as exc:
            code = exc.response.get("Error", {}).get("Code", "")
            if code in ("NotAuthorizedException", "UserNotFoundException"):
                raise CognitoAuthError(f"Invalid credentials for {email}: {exc}") from exc
            log.debug("USER_PASSWORD_AUTH failed (will try SRP): %s", exc)
            return None

    def _auth_srp(self, email: str, password: str) -> Optional[dict]:
        """SRP-based authentication flow as fallback."""
        try:
            import warrant  # pip install warrant
            w = warrant.Cognito(
                self.user_pool_id, self.client_id,
                username=email,
            )
            w.authenticate(password=password)
            return {
                "IdToken": w.id_token,
                "AccessToken": w.access_token,
                "RefreshToken": w.refresh_token,
            }
        except ImportError:
            log.debug("warrant not installed — SRP fallback unavailable")
        except Exception as exc:
            log.debug("SRP auth failed: %s", exc)
        return None
