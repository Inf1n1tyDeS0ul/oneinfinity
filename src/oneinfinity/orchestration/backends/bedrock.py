# src/oneinfinity/orchestration/backends/bedrock.py
"""
orchestration/backends/bedrock.py — Amazon Bedrock AI backend.

Uses the AWS Bedrock Converse API for unified support across Claude, Llama, etc.
Auth: standard AWS credentials (env, ~/.aws/credentials, or IAM role).
"""
from __future__ import annotations

import logging
import time
import os
from typing import Optional, Dict

from oneinfinity.orchestration.backends import BackendResult, BaseBackend, register_backend

log = logging.getLogger(__name__)


class BedrockBackend(BaseBackend):
    """Amazon Bedrock backend using the modern Converse API."""

    provider = "bedrock"

    # Map friendly names to full Bedrock IDs
    _MODEL_MAP: Dict[str, str] = {
        "sonnet-3.5":   "anthropic.claude-3-5-sonnet-20241022-v2:0",
        "sonnet-3.5-v1":"anthropic.claude-3-5-sonnet-20240620-v1:0",
        "haiku-3.5":    "anthropic.claude-3-5-haiku-20241022-v1:0",
        "opus-3":       "anthropic.claude-3-opus-20240229-v1:0",
        "llama-3.3":    "us.meta.llama3-3-70b-instruct-v1:0",
        "nova-pro":     "us.amazon.nova-pro-v1:0",
        "nova-lite":    "us.amazon.nova-lite-v1:0",
    }

    def __init__(self) -> None:
        self._client = None
        self._boto3_installed = False
        try:
            import boto3  # noqa: F401
            self._boto3_installed = True
        except ImportError:
            log.debug("[bedrock] boto3 not installed")

    def is_available(self) -> bool:
        """Available if boto3 is installed and credentials exist."""
        if not self._boto3_installed:
            return False
        try:
            import boto3
            session = boto3.Session()
            # Validating credentials exist without making a network call
            creds = session.get_credentials()
            return creds is not None and (creds.access_key is not None)
        except Exception:
            return False

    def _get_client(self):
        """Lazy-init the bedrock-runtime client."""
        if self._client is None:
            import boto3
            # Region resolution: env > boto3 default > us-east-1
            region = (
                os.environ.get("AWS_REGION") 
                or os.environ.get("AWS_DEFAULT_REGION")
                or boto3.Session().region_name 
                or "us-east-1"
            )
            self._client = boto3.client("bedrock-runtime", region_name=region)
            log.debug("[bedrock] client initialized in region: %s", region)
        return self._client

    def call(
        self,
        model_id: str,
        prompt: str,
        system: str,
        temperature: float,
        max_tokens: int,
    ) -> BackendResult:
        t0 = time.monotonic()
        
        # Map friendly name to ID
        effective_id = self._MODEL_MAP.get(model_id, model_id)
        
        try:
            client = self._get_client()

            # Bedrock Converse API format
            messages = [{"role": "user", "content": [{"text": prompt}]}]
            system_config = [{"text": system}] if system else []

            # Invoke model
            response = client.converse(
                modelId=effective_id,
                messages=messages,
                system=system_config,
                inferenceConfig={
                    "maxTokens": max_tokens,
                    "temperature": temperature,
                    # "stopSequences": ["\n\nHuman:", "\n\nAssistant:"] # Optional: Bedrock handles Claude well
                }
            )

            duration_ms = (time.monotonic() - t0) * 1000
            
            # Extract content and usage
            content = response["output"]["message"]["content"][0]["text"]
            usage = response["usage"]
            in_tok = usage.get("inputTokens", 0)
            out_tok = usage.get("outputTokens", 0)

            return BackendResult(
                content=content,
                input_tokens=in_tok,
                output_tokens=out_tok,
                duration_ms=duration_ms,
            )

        except Exception as e:
            err_msg = str(e)
            # Specialized error categorization for security audit
            if "ResourceNotFoundException" in err_msg:
                if "reached the end of its life" in err_msg:
                    err_msg = f"Model ID '{effective_id}' is legacy/unavailable. Try a newer ID or region-prefixed ID (us.)."
                else:
                    err_msg = f"Model ID '{effective_id}' not found. Verify it is enabled in your AWS console for this region."
            elif "AccessDeniedException" in err_msg:
                err_msg = f"Access denied for '{effective_id}'. Check IAM policies and Model Access in AWS console."
            elif "ThrottlingException" in err_msg:
                err_msg = f"Bedrock API throttled. Rate limit reached for '{effective_id}'."
            
            log.error("[bedrock] call failed: %s", err_msg)
            return BackendResult(
                content="",
                input_tokens=0,
                output_tokens=0,
                duration_ms=(time.monotonic() - t0) * 1000,
                error=f"Bedrock error: {err_msg}",
            )


# Register singleton at import time
register_backend(BedrockBackend())
