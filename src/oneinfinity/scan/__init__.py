"""
scan — Offensive scanning engine for OneInfinity.

TLS verification policy
-----------------------
Security scanners test external targets that may have self-signed certs or
misconfigured TLS. The default for active scan clients is therefore
``verify=False``.  To enforce strict TLS (e.g. in CI/CD pipelines that should
not hit production targets), set:

    ONEINFINITY_STRICT_TLS=1

When that env var is set, all calls to ``scan_verify()`` return ``True``.
When running through a proxy (Burp / mitmproxy), ``verify=False`` is always
returned regardless of the env flag — the proxy handles cert validation.
"""
import os as _os


def scan_verify() -> bool:
    """
    Return the TLS ``verify`` flag appropriate for active security scanners.

    - Strict mode (ONEINFINITY_STRICT_TLS=1) → True
    - Proxy mode active (ONEINFINITY_PROXY_ACTIVE=1) → False (proxy handles TLS)
    - Default → False (scan targets may have self-signed certs)
    """
    if _os.environ.get("ONEINFINITY_STRICT_TLS", "").strip() in ("1", "true", "yes"):
        return True
    return False
