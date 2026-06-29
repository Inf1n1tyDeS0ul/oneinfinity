"""card_api_tester.py — Banking card API vulnerability scanner.

Tests card and transaction endpoints for business logic flaws unique to financial apps:
- Negative amount bypass (transfer negative → balance increases)
- Over-limit purchases (no cap enforcement)
- IDOR via card_id / account_id
- Concurrent duplicate transaction (race condition)
- Cross-account card access

No other open-source scanner tests these banking-specific logic flows.
"""
from __future__ import annotations

import asyncio
import hashlib
import json
import logging
import time
import urllib.error
import urllib.parse
import urllib.request
from typing import List, Dict, Optional

log = logging.getLogger("oneinfinity.card_api_tester")


def _make_fid(prefix: str, url: str) -> str:
    return hashlib.md5(f"{prefix}:{url}".encode()).hexdigest()[:16]


def _request(
    url: str,
    method: str = "POST",
    data: Optional[dict] = None,
    headers: Optional[dict] = None,
    timeout: int = 8,
) -> tuple[int, bytes, dict]:
    """HTTP request helper. Returns (status, body_bytes, response_headers)."""
    base_headers = {"Content-Type": "application/json", "User-Agent": "Mozilla/5.0"}
    if headers:
        base_headers.update(headers)
    try:
        body = json.dumps(data or {}).encode() if method != "GET" else None
        req = urllib.request.Request(url, data=body, headers=base_headers, method=method)
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            return resp.status, resp.read(), dict(resp.headers)
    except urllib.error.HTTPError as e:
        try:
            return e.code, e.read(), dict(e.headers)
        except Exception:
            return e.code, b"", {}
    except Exception:
        return 0, b"", {}


def _get_auth_token(base: str) -> Optional[str]:
    """Authenticate with known default credentials; return JWT token or None."""
    auth_endpoints = [
        "/api/v1/merchants/login", "/api/v1/auth/login",
        "/api/login", "/api/v1/login",
    ]
    creds = [
        {"username": "admin", "password": "admin123"},
        {"email": "admin", "password": "admin123"},
    ]
    for path in auth_endpoints:
        url = f"{base}{path}"
        for cred in creds:
            code, body, _ = _request(url, method="POST", data=cred)
            if code == 200 and body:
                try:
                    d = json.loads(body.decode("utf-8", errors="ignore"))
                    token = (d.get("token") or d.get("access_token") or
                             d.get("jwt") or d.get("auth_token") or "")
                    if token:
                        log.debug("card_api_tester: auth token obtained")
                        return token
                except Exception:
                    pass
    return None


def scan_card_api(target: str, auth_token: Optional[str] = None) -> List[Dict]:
    """Test card API endpoints for banking business logic vulnerabilities."""
    findings: List[Dict] = []
    base = target.rstrip("/")

    # Obtain auth token if not provided
    token = auth_token or _get_auth_token(base)
    auth_headers = {"Authorization": f"Bearer {token}"} if token else {}

    # ── Test 1: Negative amount purchase (V9 from vulnbank article) ────────────
    for ep in ["/api/v1/transactions", "/api/transactions", "/api/v1/card/purchase", "/api/card/purchase"]:
        url = f"{base}{ep}"
        payload = {"from_account": 1, "to_account": 2, "amount": -500}
        code, body, _ = _request(url, method="POST", data=payload, headers=auth_headers)
        if code in (200, 201) and body:
            body_str = body.decode("utf-8", errors="ignore")
            if any(kw in body_str.lower() for kw in ["success", "transfer", "transaction", "balance"]):
                log.info("NEGATIVE TRANSFER accepted at %s", url)
                findings.append({
                    "vuln_type": "negative_transfer", "type": "negative_transfer",
                    "severity": "critical", "confidence": 0.95, "source_type": "active",
                    "url": url,
                    "title": "Negative transfer amount accepted — balance inflation attack",
                    "evidence": f"HTTP {code} for amount=-500: {body_str[:300]}",
                    "payload": json.dumps(payload),
                    "finding_id": _make_fid("neg_transfer", url),
                })
                break

    # ── Test 2: Zero-amount transfer ────────────────────────────────────────────
    for ep in ["/api/v1/transactions", "/api/transactions"]:
        url = f"{base}{ep}"
        payload = {"from_account": 1, "to_account": 2, "amount": 0}
        code, body, _ = _request(url, method="POST", data=payload, headers=auth_headers)
        if code in (200, 201) and body:
            body_str = body.decode("utf-8", errors="ignore")
            if any(kw in body_str.lower() for kw in ["success", "transfer", "transaction"]):
                log.info("ZERO-VALUE TRANSFER accepted at %s", url)
                findings.append({
                    "vuln_type": "zero_value_transfer", "type": "zero_value_transfer",
                    "severity": "medium", "confidence": 0.80, "source_type": "active",
                    "url": url,
                    "title": "Zero-amount transfer accepted — no minimum value enforcement",
                    "evidence": f"HTTP {code} for amount=0: {body_str[:200]}",
                    "payload": json.dumps(payload),
                    "finding_id": _make_fid("zero_transfer", url),
                })
                break

    # ── Test 3: Over-limit purchase (V10 — no transaction limit check) ─────────
    for ep in ["/api/v1/card/purchase", "/api/card/purchase", "/api/v1/transactions"]:
        url = f"{base}{ep}"
        payload = {"card_id": 1, "amount": 999999999, "merchant": "test"}
        code, body, _ = _request(url, method="POST", data=payload, headers=auth_headers)
        if code in (200, 201) and body:
            body_str = body.decode("utf-8", errors="ignore")
            if any(kw in body_str.lower() for kw in ["success", "approved", "purchase"]):
                log.info("OVERLIMIT PURCHASE accepted at %s", url)
                findings.append({
                    "vuln_type": "card_limit_bypass", "type": "card_limit_bypass",
                    "severity": "high", "confidence": 0.90, "source_type": "active",
                    "url": url,
                    "title": "No transaction limit enforcement — $999,999,999 purchase accepted",
                    "evidence": f"HTTP {code}: {body_str[:300]}",
                    "payload": json.dumps(payload),
                    "finding_id": _make_fid("overlimit", url),
                })
                break

    # ── Test 4: Cross-account IDOR via card_id ──────────────────────────────────
    for ep in ["/api/v1/card", "/api/card", "/api/v1/cards"]:
        for card_id in [1, 2, 3]:
            url = f"{base}{ep}/{card_id}"
            code, body, _ = _request(url, method="GET", headers=auth_headers)
            if code == 200 and body:
                body_str = body.decode("utf-8", errors="ignore")
                if len(body_str) > 20 and any(kw in body_str.lower() for kw in
                                               ["card", "number", "account", "cvv", "pan", "balance"]):
                    log.info("CARD IDOR at %s (card_id=%d)", url, card_id)
                    findings.append({
                        "vuln_type": "idor", "type": "idor",
                        "severity": "high", "confidence": 0.85, "source_type": "active",
                        "url": url,
                        "title": f"Card IDOR — /card/{card_id} accessible without owner check",
                        "evidence": f"HTTP {code}: {body_str[:200]}",
                        "payload": f"card_id={card_id}",
                        "finding_id": _make_fid("card_idor", url),
                    })
                    break
        if any(f["vuln_type"] == "idor" and "card_idor" in f["finding_id"] for f in findings):
            break

    # ── Test 5: No rate limiting (login + token-refresh + password-reset) ────────
    _rate_limit_endpoints = [
        ("/api/v1/merchants/login",   "POST", {"username": "admin", "password": "wrongpass"}),
        ("/api/login",                "POST", {"username": "admin", "password": "wrongpass"}),
        ("/api/v1/auth/login",        "POST", {"username": "admin", "password": "wrongpass"}),
        ("/api/v1/forgot-password",   "POST", {"email": "probe@test.com"}),
        ("/api/v1/password-reset",    "POST", {"email": "probe@test.com"}),
        ("/api/v1/auth/refresh",      "POST", {"token": "dummy"}),
        ("/api/v1/auth/token/refresh","POST", {"refresh_token": "dummy"}),
    ]
    for ep, method, payload in _rate_limit_endpoints:
        url = f"{base}{ep}"
        codes = []
        for _ in range(15):
            code, _, _ = _request(url, method=method, data=payload, timeout=3)
            codes.append(code)
        reachable = [c for c in codes if c > 0]
        if reachable and not any(c in (429, 403, 423, 503) for c in reachable):
            log.info("NO RATE LIMITING on %s (15 requests, no 429/403)", url)
            findings.append({
                "vuln_type": "no_rate_limiting", "type": "no_rate_limiting",
                "severity": "high", "confidence": 0.85, "source_type": "active",
                "url": url,
                "title": f"No rate limiting on {ep}",
                "evidence": f"15 requests returned codes: {reachable[:15]}",
                "payload": "15 rapid requests",
                "finding_id": _make_fid("no_rate", url),
            })
            break

    # ── Test 6: Duplicate transaction race condition ──────────────────────────────
    # Send two identical transfers concurrently — if both succeed, double-spend is possible.
    if token:
        import threading as _thr
        _race_results: list = []
        _race_payload = {"from_account": 1, "to_account": 2, "amount": 1}
        def _send_transfer():
            code, body, _ = _request(
                f"{base}/api/v1/transactions",
                method="POST", data=_race_payload, headers=auth_headers, timeout=8,
            )
            _race_results.append((code, body[:50] if body else b""))
        threads = [_thr.Thread(target=_send_transfer) for _ in range(3)]
        for t in threads:
            t.start()
        for t in threads:
            t.join(timeout=10)
        successes = [r for r in _race_results if r[0] in (200, 201)]
        if len(successes) >= 2:
            log.info("DUPLICATE TRANSACTION: %d/%d concurrent requests succeeded", len(successes), len(threads))
            findings.append({
                "vuln_type": "duplicate_transaction", "type": "duplicate_transaction",
                "severity": "high", "confidence": 0.80, "source_type": "active",
                "url": f"{base}/api/v1/transactions",
                "title": f"Race condition: {len(successes)} concurrent identical transfers all accepted",
                "evidence": f"{len(successes)}/{len(threads)} concurrent POST /api/v1/transactions returned 200",
                "payload": json.dumps(_race_payload),
                "finding_id": _make_fid("race_txn", f"{base}/api/v1/transactions"),
            })

    # ── Test 7: Mutation IDOR sweep — numeric ID variants on discovered endpoints ─
    _idor_templates = [
        "/api/v1/accounts/{id}",
        "/api/v1/users/{id}",
        "/api/v1/transactions/{id}",
        "/api/v1/merchants/{id}",
        "/api/users/{id}",
        "/api/accounts/{id}",
    ]
    _tested_idor = 0
    for tpl in _idor_templates:
        if _tested_idor >= 20:  # cap at 20 probes total
            break
        for _id in [0, 1, 2, 3, 100, 999, "00000000-0000-0000-0000-000000000001"]:
            if _tested_idor >= 20:
                break
            url = f"{base}{tpl.replace('{id}', str(_id))}"
            # Test WITHOUT auth first (unauthenticated IDOR)
            code, body, _ = _request(url, method="GET", timeout=5)
            _tested_idor += 1
            if code == 200 and body:
                body_str = body.decode("utf-8", errors="ignore").strip()
                if body_str not in ("[]", "{}", "null", "") and len(body_str) > 15:
                    if any(kw in body_str.lower() for kw in
                           ["id", "account", "user", "balance", "email", "amount"]):
                        log.info("MUTATION IDOR at %s (unauthenticated)", url)
                        findings.append({
                            "vuln_type": "idor", "type": "idor",
                            "severity": "high", "confidence": 0.88, "source_type": "active",
                            "url": url,
                            "title": f"Unauthenticated IDOR at {tpl.replace('{id}', str(_id))}",
                            "evidence": f"HTTP 200 without auth: {body_str[:200]}",
                            "payload": f"id={_id}",
                            "finding_id": _make_fid("mut_idor", url),
                        })

    log.info("card_api_tester: %d findings", len(findings))
    return findings
